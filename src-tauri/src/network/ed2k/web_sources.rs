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

/// Corrupt parts a source may have mostly written before it is retired. One
/// can be bad luck shared with a peer; two from the same mirror is the mirror.
pub const MAX_BAD_PARTS: u32 = 2;

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
    /// Corrupt parts this source wrote most of, over the session.
    bad_parts: u32,
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
    let mut added = Vec::new();
    let mut map = registry().write();
    let known = map.entry(file_hash).or_default();
    for raw in urls {
        if known.len() >= MAX_WEB_SOURCES_PER_FILE {
            break;
        }
        let Some(url) = normalize_web_source_url(&raw) else {
            continue;
        };
        if known.iter().any(|s| s.url == url) {
            continue;
        }
        known.push(WebSource::new(url.clone()));
        added.push(url);
    }
    if known.is_empty() {
        map.remove(&file_hash);
    }
    added
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

/// Whether `url` has been given up on for `file_hash` this session.
pub fn is_retired(file_hash: &[u8; 16], url: &str) -> bool {
    registry()
        .read()
        .get(file_hash)
        .and_then(|sources| sources.iter().find(|s| s.url == url))
        .is_some_and(|s| s.retired)
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

/// A part check failed over `[start, end)`, whoever finished the part. Every
/// source that wrote at least half of it is charged a bad part, and retired
/// at [`MAX_BAD_PARTS`]; what any source wrote there is forgotten, since it is
/// downloaded again. Returns the URLs this retired, for the caller to stop
/// keeping with the download, so a restart does not bring them back.
pub fn note_corrupt_range(file_hash: &[u8; 16], start: u64, end: u64) -> Vec<String> {
    let mut retired = Vec::new();
    let mut map = registry().write();
    let Some(sources) = map.get_mut(file_hash) else {
        return retired;
    };
    for source in sources.iter_mut() {
        let wrote = overlap(&source.written, start, end);
        remove_range(&mut source.written, start, end);
        if wrote == 0 || wrote.saturating_mul(2) < end.saturating_sub(start) {
            continue;
        }
        source.bad_parts = source.bad_parts.saturating_add(1);
        if source.bad_parts >= MAX_BAD_PARTS && !source.retired {
            source.retired = true;
            retired.push(source.url.clone());
        }
    }
    retired
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

        forget(&hash);
        assert!(urls(&hash).is_empty());
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
        assert!(note_corrupt_range(&hash, 0, part).is_empty(), "one bad part rests nothing");
        assert_eq!(bad_parts(&hash, &bad), 1);
        assert_eq!(bad_parts(&hash, &good), 0, "it wrote nothing there");

        note_written(&hash, &bad, &[(part, part + part / 4)]);
        assert!(
            note_corrupt_range(&hash, part, 2 * part).is_empty(),
            "a quarter of a part says little about the mirror"
        );
        note_written(&hash, &bad, &[(0, part)]);
        assert_eq!(note_corrupt_range(&hash, 0, part), vec![bad.clone()]);
        assert!(is_retired(&hash, &bad));
        assert!(!ready(&hash).contains(&bad));
        assert!(note_corrupt_range(&hash, 0, part).is_empty(), "retired once");
        forget(&hash);
    }
}
