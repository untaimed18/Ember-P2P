//! ed2k web sources: the `s=<url>` HTTP(S) sources eMule links can carry
//! (eMule's `CUrlClient`).
//!
//! A web source is a mirror of the whole file on an ordinary web server. The
//! download fetches byte ranges from it with HTTP `Range` requests into the
//! same part file eD2K peers write to, and every part it fills is checked
//! against the file's MD4 part hashes (and AICH, when known) exactly like a
//! peer's — so a mirror cannot get a wrong byte past verification, which is why
//! plain `http://` is accepted here and nowhere else.
//!
//! This module only remembers which URLs belong to which file and how each
//! has fared; the transfer itself is `multi_source::web_worker`. The URLs are
//! persisted by the caller (`transfer_web_sources`), keyed by file hash so a
//! download keeps them across restarts and re-queues.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Web sources kept per file. eMule links rarely name more than two or three
/// mirrors; past a handful they are as likely to be padding as help.
pub const MAX_WEB_SOURCES_PER_FILE: usize = 5;

/// Failures in a row after which a URL is left alone for the rest of the
/// session. A server that answers with errors this often is not coming back
/// on its own between two retries.
const MAX_CONSECUTIVE_FAILURES: u32 = 4;

/// Corrupt parts a source may be charged for before it is retired. One can be
/// bad luck; two from the same mirror is the mirror.
pub const MAX_BAD_PARTS: u32 = 2;

/// Whole parts a mirror may fail while sharing them with a peer before it is
/// retired anyway. Below this a poisoning peer cannot cost an honest mirror its
/// place; without a ceiling, a bad mirror on a file with no AICH data whose
/// parts a peer always shares had the same part fail for ever.
pub const MAX_SHARED_BAD_PARTS: u32 = 4;

/// The narrowest range a failed check can name: one AICH block. A failed range
/// no wider is block-granular evidence, from AICH narrowing or a part that
/// small; a wider one is a whole part that only says some byte in it is wrong.
const BLOCK_EVIDENCE: u64 = super::aich::AICH_BLOCK_SIZE as u64;

/// Written ranges kept per source, merged. Past this a source stops being
/// recorded rather than grow without bound, and goes unblamed for what it
/// writes after.
const MAX_WRITTEN_RANGES: usize = 1024;

/// Whether web sources are used at all; the `web_sources_enabled` setting.
static ENABLED: AtomicBool = AtomicBool::new(true);

#[derive(Debug, Clone)]
struct WebSource {
    url: String,
    failures: u32,
    retry_at: Option<Instant>,
    /// Refused for good this session: the server does not have the file, does
    /// not serve ranges, or keeps sending bytes that fail verification.
    retired: bool,
    /// Byte ranges this source wrote that no verdict has judged yet, merged.
    /// Kept here rather than in a worker, so a part judged after the worker
    /// moved on, or finished by a peer, is still held against the mirror.
    written: Vec<(u64, u64)>,
    /// Corrupt parts this source was charged for, over the session.
    bad_parts: u32,
    /// Corrupt parts it wrote most of with another source writing into them
    /// too. Only suspicion: never retires it.
    shared_bad_parts: u32,
}

impl WebSource {
    fn new(url: String) -> Self {
        Self {
            url,
            failures: 0,
            retry_at: None,
            retired: false,
            written: Vec::new(),
            bad_parts: 0,
            shared_bad_parts: 0,
        }
    }
}

/// Add `[start, end)` to sorted, disjoint `ranges`, merging what it touches.
fn insert_range(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) {
    if start >= end {
        return;
    }
    let at = ranges.partition_point(|&(_, e)| e < start);
    let mut merged = (start, end);
    let mut until = at;
    while until < ranges.len() && ranges[until].0 <= merged.1 {
        merged.0 = merged.0.min(ranges[until].0);
        merged.1 = merged.1.max(ranges[until].1);
        until += 1;
    }
    ranges.splice(at..until, std::iter::once(merged));
}

/// Bytes of sorted, disjoint `ranges` inside `[start, end)`.
fn overlap(ranges: &[(u64, u64)], start: u64, end: u64) -> u64 {
    ranges
        .iter()
        .map(|&(s, e)| e.min(end).saturating_sub(s.max(start)))
        .sum()
}

/// Take `[start, end)` out of sorted, disjoint `ranges`.
fn remove_range(ranges: &mut Vec<(u64, u64)>, start: u64, end: u64) {
    let mut kept = Vec::with_capacity(ranges.len() + 1);
    for &(s, e) in ranges.iter() {
        if e <= start || s >= end {
            kept.push((s, e));
            continue;
        }
        if s < start {
            kept.push((s, start));
        }
        if e > end {
            kept.push((end, e));
        }
    }
    *ranges = kept;
}

fn registry() -> &'static parking_lot::RwLock<HashMap<[u8; 16], Vec<WebSource>>> {
    static REGISTRY: OnceLock<parking_lot::RwLock<HashMap<[u8; 16], Vec<WebSource>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| parking_lot::RwLock::new(HashMap::new()))
}

/// The client name a web source's rows carry in the source list: its protocol.
pub fn source_label(url: &str) -> &'static str {
    if url.starts_with("https:") {
        "HTTPS"
    } else {
        "HTTP"
    }
}

/// Whether a source row's client name is a web source's ([`source_label`]).
pub fn is_web_source_label(client_software: &str) -> bool {
    matches!(client_software, "HTTP" | "HTTPS")
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// A web source URL as it is stored and fetched, or `None` when it can never
/// be one: not http/https, too long, carrying credentials, or naming a host
/// that is plainly local. A host that only resolves to a private address is
/// refused when it is fetched, where the answer is pinned.
pub fn normalize_web_source_url(raw: &str) -> Option<String> {
    let (normalized, host, _port) = crate::security::parse_fetch_url_with(raw, true).ok()?;
    if host.eq_ignore_ascii_case("localhost") {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if crate::security::is_private_ip(ip) {
            return None;
        }
    }
    let mut url = reqwest::Url::parse(&normalized).ok()?;
    // Never sent to the server, and two spellings of one mirror would count twice.
    url.set_fragment(None);
    Some(url.to_string())
}

/// Remember `urls` as web sources for `file_hash`, keeping any it already has
/// first. Returns the ones that were new, normalized, for the caller to persist.
pub fn register(file_hash: [u8; 16], urls: impl IntoIterator<Item = String>) -> Vec<String> {
    register_inner(file_hash, urls, false).added
}

/// What asking for web sources by hand or by link did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Registered {
    /// New to the file, normalized, for the caller to persist.
    pub added: Vec<String>,
    /// Held already, and given up on or resting after failures: asked for
    /// again, they are tried again now.
    pub revived: Vec<String>,
    /// Retired ones that gave their place to the new, for the caller to forget.
    pub replaced: Vec<String>,
    /// Held already, and working or retired for bad data.
    pub already: usize,
    /// New, but left out: the file has as many working ones as it keeps.
    pub over_limit: usize,
}

/// [`register`] for a source asked for again, by hand or in a pasted link:
///
/// - A retired source gives up its place to a new one once the file has as
///   many as it keeps. Without that a mirror that turned out dead held its
///   place for good: the cap counted it, and every restart loaded it again,
///   ahead of any added since.
/// - One already held that was given up on, or is resting, after failures is
///   tried again: asking for it again is the user saying it works now. One
///   retired for sending bad data stays retired.
pub fn register_replacing_retired(file_hash: [u8; 16], urls: impl IntoIterator<Item = String>) -> Registered {
    register_inner(file_hash, urls, true)
}

fn register_inner(file_hash: [u8; 16], urls: impl IntoIterator<Item = String>, asked_again: bool) -> Registered {
    let mut result = Registered::default();
    let mut map = registry().write();
    let known = map.entry(file_hash).or_default();
    for raw in urls {
        let Some(url) = normalize_web_source_url(&raw) else {
            continue;
        };
        if let Some(held) = known.iter_mut().find(|s| s.url == url) {
            let failed = held.retired || held.retry_at.is_some();
            if asked_again && failed && held.bad_parts < MAX_BAD_PARTS {
                held.retired = false;
                held.failures = 0;
                held.retry_at = None;
                result.revived.push(url);
            } else {
                result.already += 1;
            }
            continue;
        }
        if known.len() >= MAX_WEB_SOURCES_PER_FILE {
            match known.iter().position(|s| s.retired).filter(|_| asked_again) {
                Some(at) => result.replaced.push(known.remove(at).url),
                None => {
                    result.over_limit += 1;
                    continue;
                }
            }
        }
        known.push(WebSource::new(url.clone()));
        result.added.push(url);
    }
    if known.is_empty() {
        map.remove(&file_hash);
    }
    result
}

/// Drop every web source of `file_hash`: the download finished or went.
pub fn forget(file_hash: &[u8; 16]) {
    registry().write().remove(file_hash);
}

/// Every web source `file_hash` has, whatever their state.
pub fn urls(file_hash: &[u8; 16]) -> Vec<String> {
    registry()
        .read()
        .get(file_hash)
        .map(|sources| sources.iter().map(|s| s.url.clone()).collect())
        .unwrap_or_default()
}

/// The web sources worth trying for `file_hash` now: the feature is on, and
/// the source is neither retired nor resting after a failure.
pub fn ready(file_hash: &[u8; 16]) -> Vec<String> {
    if !enabled() {
        return Vec::new();
    }
    let now = Instant::now();
    registry()
        .read()
        .get(file_hash)
        .map(|sources| {
            sources
                .iter()
                .filter(|s| !s.retired && s.retry_at.is_none_or(|at| now >= at))
                .map(|s| s.url.clone())
                .collect()
        })
        .unwrap_or_default()
}

pub fn has_ready(file_hash: &[u8; 16]) -> bool {
    !ready(file_hash).is_empty()
}

/// Whether `url` has been given up on for `file_hash` this session: retired,
/// or no longer held at all because a new mirror took its place
/// ([`register_replacing_retired`]) or the download let its sources go. Its
/// worker stops on either. Read as "not retired", a replaced mirror retired
/// for bad data kept fetching with its writes no longer recorded, so nothing
/// it spoiled was ever charged to it.
pub fn is_retired(file_hash: &[u8; 16], url: &str) -> bool {
    registry()
        .read()
        .get(file_hash)
        .and_then(|sources| sources.iter().find(|s| s.url == url))
        .is_none_or(|s| s.retired)
}

/// How long a source rests after its `failures`-th failure in a row.
fn backoff(failures: u32) -> Duration {
    match failures {
        0 | 1 => Duration::from_secs(60),
        2 => Duration::from_secs(5 * 60),
        _ => Duration::from_secs(30 * 60),
    }
}

/// A transfer from `url` failed. A `permanent` failure — the server does not
/// have the file or will not serve parts of it — retires the source for the
/// session; anything else rests it, longer each time, and enough of those in a
/// row retire it too.
pub fn note_failure(file_hash: &[u8; 16], url: &str, permanent: bool) {
    let mut map = registry().write();
    let Some(source) = map
        .get_mut(file_hash)
        .and_then(|sources| sources.iter_mut().find(|s| s.url == url))
    else {
        return;
    };
    source.failures = source.failures.saturating_add(1);
    if permanent || source.failures >= MAX_CONSECUTIVE_FAILURES {
        source.retired = true;
    } else {
        source.retry_at = Some(Instant::now() + backoff(source.failures));
    }
}

/// `url` delivered data, so its run of failures is over.
pub fn note_success(file_hash: &[u8; 16], url: &str) {
    let mut map = registry().write();
    if let Some(source) = map
        .get_mut(file_hash)
        .and_then(|sources| sources.iter_mut().find(|s| s.url == url))
    {
        source.failures = 0;
        source.retry_at = None;
    }
}

/// `url` wrote `ranges` into `file_hash`'s part file.
pub fn note_written(file_hash: &[u8; 16], url: &str, ranges: &[(u64, u64)]) {
    if ranges.is_empty() {
        return;
    }
    let mut map = registry().write();
    let Some(source) = map
        .get_mut(file_hash)
        .and_then(|sources| sources.iter_mut().find(|s| s.url == url))
    else {
        return;
    };
    for &(start, end) in ranges {
        if source.written.len() >= MAX_WRITTEN_RANGES {
            break;
        }
        insert_range(&mut source.written, start, end);
    }
}

/// What a failed part check did to the web sources of the file.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CorruptVerdict {
    /// Retired by it, for the caller to stop keeping with the download, so a
    /// restart does not bring them back.
    pub retired: Vec<String>,
    /// Wrote most of a whole part another source wrote into too, so only
    /// suspected, with how many such parts they have now been suspected of.
    pub suspected: Vec<(String, u32)>,
}

/// A part check failed over `[start, end)`, whoever finished the part.
/// `peers_wrote`: a peer is on record for bytes there. What any source wrote
/// there is forgotten, since it is downloaded again.
///
/// - A range of at most one AICH block (narrowed by AICH, or a part that
///   small) charges a bad part to every mirror that wrote at least half of it.
/// - A wider range is a whole part, and only says some byte in it is wrong.
///   - With no peer on record there and mirrors having written most of it
///     between them, every mirror that wrote into it is charged: nobody else
///     can have sent the bad bytes, and sparing mirrors that split a part let
///     a bad one fail the same part for ever.
///   - With a peer there, a mirror that wrote all of it is charged, and one
///     that wrote at least half is only suspected: the mirror is usually the
///     faster one and writes most of a part it shares, so one poisoning peer
///     could otherwise get an honest mirror retired and deleted, as a peer is
///     blamed only for a part it wrote whole. Suspicion retires it at
///     [`MAX_SHARED_BAD_PARTS`], so a bad mirror cannot fail parts for ever.
///
/// A source is retired at [`MAX_BAD_PARTS`].
pub fn note_corrupt_range(file_hash: &[u8; 16], start: u64, end: u64, peers_wrote: bool) -> CorruptVerdict {
    let mut verdict = CorruptVerdict::default();
    let len = end.saturating_sub(start);
    if len == 0 {
        return verdict;
    }
    let mut map = registry().write();
    let Some(sources) = map.get_mut(file_hash) else {
        return verdict;
    };
    let whole_part = len > BLOCK_EVIDENCE;
    let mirrors_wrote = sources
        .iter()
        .fold(0u64, |total, s| total.saturating_add(overlap(&s.written, start, end)));
    // With no peer on record, the part is the mirrors' if they wrote most of
    // it between them; otherwise most of it came from where nothing is on
    // record (a resumed `.part`), which says nothing about them.
    let mirrors_part = !peers_wrote && mirrors_wrote.saturating_mul(2) >= len;
    for source in sources.iter_mut() {
        let wrote = overlap(&source.written, start, end);
        remove_range(&mut source.written, start, end);
        let most = wrote.saturating_mul(2) >= len;
        let charged = if wrote == 0 {
            false
        } else if !whole_part {
            most
        } else if wrote == len || mirrors_part {
            true
        } else if !peers_wrote {
            false
        } else if most {
            source.shared_bad_parts = source.shared_bad_parts.saturating_add(1);
            verdict.suspected.push((source.url.clone(), source.shared_bad_parts));
            if source.shared_bad_parts >= MAX_SHARED_BAD_PARTS && !source.retired {
                source.retired = true;
                verdict.retired.push(source.url.clone());
            }
            false
        } else {
            false
        };
        if !charged {
            continue;
        }
        source.bad_parts = source.bad_parts.saturating_add(1);
        if source.bad_parts >= MAX_BAD_PARTS && !source.retired {
            source.retired = true;
            verdict.retired.push(source.url.clone());
        }
    }
    verdict
}

/// A part check passed over `[start, end)`: what any source wrote there has its
/// verdict, good, and is forgotten. Kept, those ranges filled
/// [`MAX_WRITTEN_RANGES`] on a long download, after which a source's writes
/// went unrecorded and a mirror sending bad data could no longer be blamed.
pub fn note_verified_range(file_hash: &[u8; 16], start: u64, end: u64) {
    let mut map = registry().write();
    let Some(sources) = map.get_mut(file_hash) else {
        return;
    };
    for source in sources.iter_mut() {
        remove_range(&mut source.written, start, end);
    }
}

/// Corrupt parts `url` has been charged for `file_hash` this session.
#[cfg(test)]
pub fn bad_parts(file_hash: &[u8; 16], url: &str) -> u32 {
    registry()
        .read()
        .get(file_hash)
        .and_then(|sources| sources.iter().find(|s| s.url == url))
        .map_or(0, |s| s.bad_parts)
}

#[cfg(test)]
pub(crate) fn clear_for_tests(file_hash: &[u8; 16]) {
    forget(file_hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_http_and_https_urls_are_kept() {
        assert_eq!(
            normalize_web_source_url("https://mirror.example/files/a.bin#part").as_deref(),
            Some("https://mirror.example/files/a.bin")
        );
        assert!(normalize_web_source_url("http://mirror.example/a.bin").is_some());
        for bad in [
            "ftp://mirror.example/a.bin",
            "https://user:pass@mirror.example/a.bin",
            "http://localhost/a.bin",
            "http://127.0.0.1/a.bin",
            "http://192.168.1.10/a.bin",
            "http://[::1]/a.bin",
            "file:///C:/a.bin",
            "not a url",
        ] {
            assert!(normalize_web_source_url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn registration_dedupes_caps_and_backs_off() {
        let hash = [0xAB; 16];
        clear_for_tests(&hash);
        let added = register(
            hash,
            [
                "https://a.example/f".to_string(),
                "https://a.example/f#x".to_string(),
                "ftp://nope/f".to_string(),
            ],
        );
        assert_eq!(added, vec!["https://a.example/f"]);
        assert!(register(hash, ["https://a.example/f".to_string()]).is_empty());
        let many: Vec<String> = (0..10).map(|i| format!("https://m{i}.example/f")).collect();
        register(hash, many);
        assert_eq!(urls(&hash).len(), MAX_WEB_SOURCES_PER_FILE);

        assert!(ready(&hash).contains(&"https://a.example/f".to_string()));
        note_failure(&hash, "https://a.example/f", false);
        assert!(!ready(&hash).contains(&"https://a.example/f".to_string()), "resting");
        note_success(&hash, "https://a.example/f");
        assert!(ready(&hash).contains(&"https://a.example/f".to_string()));
        note_failure(&hash, "https://a.example/f", true);
        assert!(!ready(&hash).contains(&"https://a.example/f".to_string()), "retired");
        assert_eq!(urls(&hash).len(), MAX_WEB_SOURCES_PER_FILE, "still remembered");
        assert!(register(hash, ["https://late.example/f".to_string()]).is_empty(), "the cap holds");

        // A new mirror takes a retired one's place, never a working one's.
        let registered =
            register_replacing_retired(hash, ["https://new.example/f".to_string(), "https://more.example/f".to_string()]);
        assert_eq!(registered.added, vec!["https://new.example/f"]);
        assert_eq!(registered.replaced, vec!["https://a.example/f"]);
        assert_eq!(registered.over_limit, 1, "no retired one is left to give way");
        assert_eq!(urls(&hash).len(), MAX_WEB_SOURCES_PER_FILE);
        assert!(!urls(&hash).contains(&"https://a.example/f".to_string()));

        forget(&hash);
        assert!(urls(&hash).is_empty());
    }

    /// Asked for again, a mirror given up on after failures is tried again,
    /// and one retired for bad data is not.
    #[test]
    fn a_mirror_asked_for_again_is_tried_again_unless_it_sent_bad_data() {
        let hash = [0xAC; 16];
        clear_for_tests(&hash);
        let dead = "https://dead.example/f".to_string();
        let bad = "https://bad.example/f".to_string();
        let fine = "https://fine.example/f".to_string();
        register(hash, [dead.clone(), bad.clone(), fine.clone()]);
        note_failure(&hash, &dead, true);
        let part = 9_728_000u64;
        for _ in 0..MAX_BAD_PARTS {
            note_written(&hash, &bad, &[(0, part)]);
            note_corrupt_range(&hash, 0, part, false);
        }
        assert!(is_retired(&hash, &dead) && is_retired(&hash, &bad));

        let registered = register_replacing_retired(hash, [dead.clone(), bad.clone(), fine.clone()]);
        assert_eq!(registered.revived, vec![dead.clone()]);
        assert_eq!(registered.already, 2, "the working one and the bad one");
        assert!(registered.added.is_empty());
        assert!(ready(&hash).contains(&dead));
        assert!(!ready(&hash).contains(&bad));
        assert!(register(hash, [dead.clone()]).is_empty(), "loading them again revives nothing");
        forget(&hash);
    }

    #[test]
    fn written_ranges_merge_and_split() {
        let mut ranges = Vec::new();
        insert_range(&mut ranges, 10, 20);
        insert_range(&mut ranges, 30, 40);
        insert_range(&mut ranges, 20, 30);
        assert_eq!(ranges, vec![(10, 40)]);
        insert_range(&mut ranges, 50, 60);
        assert_eq!(overlap(&ranges, 15, 55), 25 + 5);
        remove_range(&mut ranges, 20, 52);
        assert_eq!(ranges, vec![(10, 20), (52, 60)]);
    }

    /// A mirror is held to the parts it mostly wrote, whoever finished them,
    /// across worker runs, and is retired at the second.
    #[test]
    fn a_mirror_is_charged_for_corrupt_parts_it_mostly_wrote() {
        let hash = [0xCD; 16];
        clear_for_tests(&hash);
        let bad = "https://bad.example/f".to_string();
        let good = "https://good.example/f".to_string();
        register(hash, [bad.clone(), good.clone()]);
        let part = 9_728_000u64;

        note_written(&hash, &bad, &[(0, part / 2), (part / 2, part)]);
        note_written(&hash, &good, &[(part, part + 1000)]);
        assert_eq!(note_corrupt_range(&hash, 0, part, true), CorruptVerdict::default(), "one bad part rests nothing");
        assert_eq!(bad_parts(&hash, &bad), 1, "it wrote all of it, so a peer on record does not matter");
        assert_eq!(bad_parts(&hash, &good), 0, "it wrote nothing there");

        note_written(&hash, &bad, &[(part, part + part / 4)]);
        assert_eq!(
            note_corrupt_range(&hash, part, 2 * part, false),
            CorruptVerdict::default(),
            "a quarter of a part says little about the mirror"
        );
        note_written(&hash, &bad, &[(0, part)]);
        assert_eq!(note_corrupt_range(&hash, 0, part, false).retired, vec![bad.clone()]);
        assert!(is_retired(&hash, &bad));
        assert!(!ready(&hash).contains(&bad));
        assert!(note_corrupt_range(&hash, 0, part, false).retired.is_empty(), "retired once");
        forget(&hash);
    }

    /// The report this exists for: a mirror writes 90% of a part a poisoning
    /// peer wrote the other 10% of, and the part fails with no AICH narrowing.
    /// The mirror is only suspected, and outlasts more such parts than an
    /// outright charge allows, but not for ever: a bad mirror that always
    /// shares its parts with a peer must not fail them indefinitely.
    #[test]
    fn a_mirror_sharing_failed_parts_with_a_peer_is_retired_only_after_many() {
        let hash = [0xCF; 16];
        clear_for_tests(&hash);
        let mirror = "https://mirror.example/f".to_string();
        register(hash, [mirror.clone()]);
        let part = 9_728_000u64;
        let peer_share = part / 10;
        for round in 1..MAX_SHARED_BAD_PARTS {
            note_written(&hash, &mirror, &[(peer_share, part)]);
            let verdict = note_corrupt_range(&hash, 0, part, true);
            assert!(verdict.retired.is_empty(), "round {round}");
            assert_eq!(verdict.suspected, vec![(mirror.clone(), round)]);
        }
        const { assert!(MAX_SHARED_BAD_PARTS > MAX_BAD_PARTS) };
        assert_eq!(bad_parts(&hash, &mirror), 0);
        assert!(!is_retired(&hash, &mirror));
        assert!(ready(&hash).contains(&mirror));

        note_written(&hash, &mirror, &[(peer_share, part)]);
        let verdict = note_corrupt_range(&hash, 0, part, true);
        assert_eq!(verdict.retired, vec![mirror.clone()], "the ceiling ends the loop");
        assert!(is_retired(&hash, &mirror));
        forget(&hash);
    }

    /// With no peer in a failed part, only mirrors can have sent the bad
    /// bytes, so each that wrote into it is charged, however the part was
    /// split. Sparing them let a bad mirror splitting a one-part file with a
    /// good one fail that part for ever.
    #[test]
    fn mirrors_splitting_a_failed_part_without_a_peer_are_all_charged() {
        let hash = [0xD0; 16];
        clear_for_tests(&hash);
        let a = "https://a.example/f".to_string();
        let b = "https://b.example/f".to_string();
        register(hash, [a.clone(), b.clone()]);
        let part = 9_728_000u64;
        // Uneven: the one that wrote less is charged too.
        note_written(&hash, &a, &[(0, part * 3 / 5)]);
        note_written(&hash, &b, &[(part * 3 / 5, part)]);
        let verdict = note_corrupt_range(&hash, 0, part, false);
        assert!(verdict.suspected.is_empty());
        assert_eq!((bad_parts(&hash, &a), bad_parts(&hash, &b)), (1, 1));

        note_written(&hash, &a, &[(0, part / 2)]);
        note_written(&hash, &b, &[(part / 2, part)]);
        let mut retired = note_corrupt_range(&hash, 0, part, false).retired;
        retired.sort();
        assert_eq!(retired, vec![a.clone(), b.clone()], "the download stops looping");
        forget(&hash);
    }

    /// A peer's share keeps a mirror that wrote only part of a failed whole
    /// part to suspicion, while a mirror that wrote the whole part is charged.
    #[test]
    fn a_mirror_that_wrote_a_whole_failed_part_is_charged_even_beside_a_peer() {
        let hash = [0xD3; 16];
        clear_for_tests(&hash);
        let mirror = "https://mirror.example/f".to_string();
        register(hash, [mirror.clone()]);
        let part = 9_728_000u64;
        note_written(&hash, &mirror, &[(0, part)]);
        assert!(note_corrupt_range(&hash, 0, part, true).suspected.is_empty());
        assert_eq!(bad_parts(&hash, &mirror), 1);
        forget(&hash);
    }

    /// AICH narrowing names one block, so the mirror that wrote most of a
    /// block it names is charged as before, a peer beside it or not.
    #[test]
    fn an_aich_narrowed_block_charges_the_mirror_that_wrote_most_of_it() {
        let hash = [0xD1; 16];
        clear_for_tests(&hash);
        let mirror = "https://mirror.example/f".to_string();
        register(hash, [mirror.clone()]);
        let block = BLOCK_EVIDENCE;
        let start = 5 * block;
        note_written(&hash, &mirror, &[(start, start + block * 3 / 5)]);
        assert_eq!(note_corrupt_range(&hash, start, start + block, true), CorruptVerdict::default());
        assert_eq!(bad_parts(&hash, &mirror), 1);
        note_written(&hash, &mirror, &[(start, start + block * 3 / 5)]);
        assert_eq!(note_corrupt_range(&hash, start, start + block, true).retired, vec![mirror.clone()]);
        forget(&hash);
    }

    /// A mirror that gave its place to a new one is as good as retired, so its
    /// worker stops rather than fetch on with nothing it writes recorded.
    #[test]
    fn a_replaced_mirror_reads_as_retired() {
        let hash = [0xD2; 16];
        clear_for_tests(&hash);
        let held: Vec<String> = (0..MAX_WEB_SOURCES_PER_FILE).map(|i| format!("https://m{i}.example/f")).collect();
        register(hash, held.clone());
        let part = 9_728_000u64;
        for _ in 0..MAX_BAD_PARTS {
            note_written(&hash, &held[0], &[(0, part)]);
            note_corrupt_range(&hash, 0, part, true);
        }
        assert!(is_retired(&hash, &held[0]));
        let registered = register_replacing_retired(hash, ["https://new.example/f".to_string()]);
        assert_eq!(registered.replaced, vec![held[0].clone()]);
        assert!(is_retired(&hash, &held[0]), "no longer held");
        assert!(!is_retired(&hash, &held[1]));
        assert!(!is_retired(&hash, "https://new.example/f"));
        forget(&hash);
        assert!(is_retired(&hash, &held[1]), "the download let its sources go");
    }

    /// A verified part's writes have their verdict, so they no longer count
    /// toward the ranges a source may keep.
    #[test]
    fn a_verified_part_forgets_what_was_written_there() {
        let hash = [0xCE; 16];
        clear_for_tests(&hash);
        let url = "https://m.example/f".to_string();
        register(hash, [url.clone()]);
        let part = 9_728_000u64;
        note_written(&hash, &url, &[(0, 100), (200, 300), (part, part + 100)]);
        note_verified_range(&hash, 0, part);
        let written = registry().read().get(&hash).map(|s| s[0].written.clone()).unwrap_or_default();
        assert_eq!(written, vec![(part, part + 100)]);
        forget(&hash);
    }
}
