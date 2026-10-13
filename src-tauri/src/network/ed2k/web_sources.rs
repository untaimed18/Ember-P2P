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
        known.push(WebSource {
            url: url.clone(),
            failures: 0,
            retry_at: None,
            retired: false,
        });
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
}
