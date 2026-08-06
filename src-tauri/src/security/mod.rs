#[cfg(target_os = "windows")]
pub mod firewall;

pub mod antileech;
pub mod filesystem;
pub mod policy;

pub mod logging {
    use std::io::{self, Write};
    use std::sync::OnceLock;

    use rand::{rngs::OsRng, RngCore};
    use regex::{Captures, Regex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    pub struct PrivacyMakeWriter<M> {
        inner: M,
        verbose: bool,
    }

    impl<M> PrivacyMakeWriter<M> {
        pub fn new(inner: M, verbose: bool) -> Self {
            Self { inner, verbose }
        }
    }

    pub struct PrivacyWriter<W: Write> {
        inner: Option<W>,
        buffer: Vec<u8>,
        verbose: bool,
    }

    impl<W: Write> Write for PrivacyWriter<W> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buffer.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<W: Write> Drop for PrivacyWriter<W> {
        fn drop(&mut self) {
            let Some(mut inner) = self.inner.take() else {
                return;
            };
            let raw = String::from_utf8_lossy(&self.buffer);
            let rendered = if self.verbose {
                raw.into_owned()
            } else {
                redact_normal_log(&raw)
            };
            let _ = inner.write_all(rendered.as_bytes());
            let _ = inner.flush();
        }
    }

    impl<'a, M> MakeWriter<'a> for PrivacyMakeWriter<M>
    where
        M: MakeWriter<'a>,
        M::Writer: Write,
    {
        type Writer = PrivacyWriter<M::Writer>;

        fn make_writer(&'a self) -> Self::Writer {
            PrivacyWriter {
                inner: Some(self.inner.make_writer()),
                buffer: Vec::with_capacity(512),
                verbose: self.verbose,
            }
        }
    }

    fn pseudonym(value: &str) -> String {
        static KEY: OnceLock<[u8; 32]> = OnceLock::new();
        let key = KEY.get_or_init(|| {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            key
        });
        let digest = blake3::keyed_hash(key, value.as_bytes());
        hex::encode(&digest.as_bytes()[..6])
    }

    fn replace_regex(
        input: String,
        regex: &'static OnceLock<Regex>,
        pattern: &str,
        kind: &'static str,
    ) -> String {
        regex
            .get_or_init(|| Regex::new(pattern).expect("static log redaction regex"))
            .replace_all(&input, |caps: &Captures<'_>| {
                format!("<{kind}:{}>", pseudonym(&caps[0]))
            })
            .into_owned()
    }

    pub fn redact_normal_log(input: &str) -> String {
        static WINDOWS_PATH: OnceLock<Regex> = OnceLock::new();
        static HEX_ID: OnceLock<Regex> = OnceLock::new();
        static IPV4: OnceLock<Regex> = OnceLock::new();
        static IPV6: OnceLock<Regex> = OnceLock::new();
        static PEER_TEXT: OnceLock<Regex> = OnceLock::new();

        let had_newline = input.ends_with('\n');
        let mut value = input
            .trim_end_matches(['\r', '\n'])
            .replace(['\r', '\n'], "\\n");
        value = PEER_TEXT
            .get_or_init(|| {
                Regex::new(
                    r#"(?i)(?:\b(?:nick(?:name)?|query|search(?:_term)?)\s*=\s*|\b(?:search|query)[^'"\r\n]{0,48})['"][^'"\r\n]*['"]"#,
                )
                .expect("static peer-text regex")
            })
            .replace_all(&value, |caps: &Captures<'_>| {
                format!("<text:{}>", pseudonym(&caps[0]))
            })
            .into_owned();
        value = replace_regex(
            value,
            &WINDOWS_PATH,
            r#"(?i)\b[A-Z]:\\[^\r\n\t,;)"']+"#,
            "path",
        );
        value = replace_regex(value, &HEX_ID, r"(?i)\b[0-9a-f]{32,128}\b", "id");
        value = IPV6
            .get_or_init(|| {
                Regex::new(r"(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}").expect("static IPv6 regex")
            })
            .replace_all(&value, |caps: &Captures<'_>| {
                let candidate = &caps[0];
                if candidate.parse::<std::net::Ipv6Addr>().is_ok() {
                    format!("<ip:{}>", pseudonym(candidate))
                } else {
                    candidate.to_string()
                }
            })
            .into_owned();
        value = IPV4
            .get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap())
            .replace_all(&value, |caps: &Captures<'_>| {
                let candidate = &caps[0];
                if candidate.parse::<std::net::Ipv4Addr>().is_ok() {
                    format!("<ip:{}>", pseudonym(candidate))
                } else {
                    candidate.to_string()
                }
            })
            .into_owned();
        if had_newline {
            value.push('\n');
        }
        value
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn normal_log_snapshot_contains_no_raw_privacy_canaries() {
            let ip = "198.51.100.77";
            let hash = "0123456789abcdef0123456789abcdef";
            let path = r"C:\Users\Canary Name\private\secret-file.bin";
            let line = format!(
                "peer={ip}:4662 hash={hash} path={path}, nick='Canary Nick' query=\"rare term\"\n"
            );
            let redacted = redact_normal_log(&line);
            assert!(!redacted.contains(ip));
            assert!(!redacted.contains(hash));
            assert!(!redacted.contains(path));
            assert!(!redacted.contains("Canary Nick"));
            assert!(!redacted.contains("rare term"));
            assert!(redacted.contains("<ip:"));
            assert!(redacted.contains("<id:"));
            assert!(redacted.contains("<path:"));
        }

        #[test]
        fn peer_newlines_cannot_inject_log_records() {
            let redacted = redact_normal_log("nick='bad\nforged WARN record'\n");
            assert_eq!(redacted.matches('\n').count(), 1);
            assert!(!redacted.contains("forged WARN record"));
        }
    }
}

use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Non-queuing resource guard for expensive IPC operations. A compromised
/// renderer cannot build an unbounded waiter backlog: concurrent attempts fail
/// immediately and the flag is released on every return/panic unwind.
pub struct SingleFlightGuard<'a>(&'a AtomicBool);

impl Drop for SingleFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub fn try_begin_single_flight(flag: &AtomicBool) -> Option<SingleFlightGuard<'_>> {
    flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| SingleFlightGuard(flag))
}

pub(crate) fn unique_tmp_path(final_path: &Path) -> PathBuf {
    use rand::RngCore;
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let pid = std::process::id();
    let parent = final_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = final_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    parent.join(format!(".{stem}.{pid}.{}.tmp", hex::encode(random)))
}

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe",
    "bat",
    "cmd",
    "com",
    "scr",
    "pif",
    "msi",
    "msp",
    "mst",
    "cpl",
    "hta",
    "inf",
    "ins",
    "isp",
    "jse",
    "lnk",
    "reg",
    "rgs",
    "sct",
    "shb",
    "shs",
    "vbe",
    "vbs",
    "wsc",
    "wsf",
    "wsh",
    "ws",
    "ps1",
    "ps1xml",
    "ps2",
    "ps2xml",
    "psc1",
    "psc2",
    "psm1",
    "application",
    "gadget",
    "msh",
    "msh1",
    "msh2",
    "mshxml",
    "msh1xml",
    "msh2xml",
    "dll",
    "sys",
    "drv",
];

/// Render a fatal network error for display in the UI without leaking IP
/// addresses, file paths, or deep error-chain diagnostics. The full error is
/// still written to the tracing log for operators.
///
/// Kept conservative: a single short phrase plus the root-cause kind.
pub fn redact_fatal_error(err: &anyhow::Error) -> String {
    // Walk the chain to find a recognisable category; fall back to a generic
    // message if nothing matches.
    let mut category: Option<&'static str> = None;
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            use std::io::ErrorKind::*;
            category = Some(match io.kind() {
                PermissionDenied => "permission denied",
                AddrInUse => "port already in use",
                AddrNotAvailable => "address not available",
                ConnectionRefused | ConnectionReset | ConnectionAborted => {
                    "network connection lost"
                }
                NotFound => "required file missing",
                TimedOut => "network timeout",
                _ => "I/O error",
            });
            break;
        }
    }
    let tag = category.unwrap_or("unexpected error");
    format!("The network service stopped ({tag}). See logs for details.")
}

/// Returns true if the file extension is potentially dangerous (executable).
pub fn is_dangerous_extension(filename: &str) -> bool {
    let path = Path::new(filename);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if DANGEROUS_EXTENSIONS.contains(&ext.as_str()) {
        return true;
    }
    if let Some(inner_ext) = path.file_stem().and_then(|s| Path::new(s).extension()) {
        if DANGEROUS_EXTENSIONS.contains(&inner_ext.to_string_lossy().to_lowercase().as_str()) {
            return true;
        }
    }
    false
}

/// True for every IPv4 address that can never be a legitimate, globally
/// routable peer: loopback, RFC1918 private space, link-local, the
/// unspecified and limited-broadcast addresses, multicast, RFC1122 "this
/// network" (`0.0.0.0/8`), reserved class-E (`240.0.0.0/4`), RFC6598 CGNAT,
/// the RFC5737 documentation ranges, RFC2544 benchmarking, the RFC6890 IETF
/// protocol-assignment block (`192.0.0.0/24`) and the deprecated 6to4 relay
/// anycast prefix (`192.88.99.0/24`).
///
/// This is the single source of truth for "special-use" v4 classification;
/// `ip_filter` builds its `block_private` / always-reject split on top of it
/// (see [`is_lan_or_cgnat_v4`] and [`is_bogus_v4`]).
pub(crate) fn is_special_use_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || is_this_network_v4(v4)
        || is_reserved_future_v4(v4)
        || is_shared_address(v4)
        || is_documentation_v4(v4)
        || is_benchmarking_v4(v4)
        || is_protocol_assignment_v4(v4)
        || is_6to4_relay_anycast_v4(v4)
}

/// RFC1918 private space, RFC3927 link-local, and RFC6598 CGNAT — the
/// "LAN-ish" addresses a user on a local/segmented network might legitimately
/// want to reach. These are the *only* special-use ranges gated behind the
/// `block_private_ips` setting; everything else in [`is_special_use_v4`] is
/// always unroutable (see [`is_bogus_v4`]).
pub(crate) fn is_lan_or_cgnat_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_private() || v4.is_link_local() || is_shared_address(v4)
}

/// Special-use addresses that are *never* a valid public peer regardless of
/// any user setting (loopback, broadcast, multicast, `0.0.0.0/8`,
/// `240.0.0.0/4`, documentation / benchmarking / protocol / 6to4 blocks).
/// This is exactly [`is_special_use_v4`] minus the LAN ranges in
/// [`is_lan_or_cgnat_v4`], so it stays correct automatically as the
/// special-use set grows.
pub(crate) fn is_bogus_v4(v4: std::net::Ipv4Addr) -> bool {
    is_special_use_v4(v4) && !is_lan_or_cgnat_v4(v4)
}

/// RFC 1122 "this network" (0.0.0.0/8)
fn is_this_network_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.octets()[0] == 0
}

/// Reserved for future use / class E (240.0.0.0/4, includes 255.255.255.255)
fn is_reserved_future_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.octets()[0] >= 240
}

/// RFC 6598 Carrier-Grade NAT shared address space (100.64.0.0/10)
fn is_shared_address(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// RFC 5737 documentation ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
fn is_documentation_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
}

/// RFC 2544 benchmarking (198.18.0.0/15)
fn is_benchmarking_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 198 && (o[1] & 0xFE) == 18
}

/// RFC 6890 IETF protocol assignments (192.0.0.0/24)
fn is_protocol_assignment_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 192 && o[1] == 0 && o[2] == 0
}

/// RFC 7526 deprecated 6to4 relay anycast (192.88.99.0/24)
fn is_6to4_relay_anycast_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 192 && o[1] == 88 && o[2] == 99
}

pub(crate) fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_special_use_v4(v4),
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let segs = v6.segments();
            let is_ula = (segs[0] & 0xFE00) == 0xFC00;
            let is_link_local = (segs[0] & 0xFFC0) == 0xFE80;
            // RFC 3849: 2001:db8::/32 documentation prefix
            let is_doc_v6 = segs[0] == 0x2001 && segs[1] == 0x0DB8;
            if is_ula || is_link_local || is_doc_v6 {
                return true;
            }
            let is_v4_mapped = segs[0..5] == [0, 0, 0, 0, 0] && segs[5] == 0xFFFF;
            if is_v4_mapped {
                let mapped = std::net::Ipv4Addr::new(
                    (segs[6] >> 8) as u8,
                    segs[6] as u8,
                    (segs[7] >> 8) as u8,
                    segs[7] as u8,
                );
                return is_special_use_v4(mapped);
            }
            false
        }
    }
}

/// Maximum URL length accepted by [`validate_fetch_url`]. RFC 7230 doesn't
/// pin a hard limit, but mainstream HTTP servers and clients struggle past
/// ~8 KB; 2048 fits every documented bootstrap / ipfilter source comfortably
/// while rejecting pathological inputs early before the DNS / TLS round trip.
pub const MAX_FETCH_URL_LEN: usize = 2048;

/// Validate a URL for safe fetching. Blocks non-HTTP schemes and private IPs.
/// Also resolves hostnames and returns the validated (host, resolved_addrs) pair
/// so callers can pin DNS with `reqwest::Client::builder().resolve()`,
/// preventing TOCTOU DNS rebinding attacks.
///
/// HTTPS-only by design: every default URL we ship (nodes.dat, ipfilter)
/// is already https, and accepting plaintext http would expose the
/// downloaded payload to trivial network tampering even with DNS pinning
/// (the pin only proves *which* host you reached, not that the bytes
/// weren't modified in flight). Users who paste a custom http:// URL
/// into the IP filter import field get a clear "https only" error.
fn parse_fetch_url(url: &str) -> Result<(String, String, u16), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("URL is empty".into());
    }
    if url.len() > MAX_FETCH_URL_LEN {
        return Err(format!("URL exceeds {MAX_FETCH_URL_LEN} bytes",));
    }
    // Reject anything that even looks like userinfo, before parsing. Splitting
    // on a literal "://" misses the forms the url crate still accepts for
    // special schemes — `https:user:pass@host/` and `https:/\/\user@host/` both
    // resolve to `host` — which would let `https:trusted.example@attacker.tld/`
    // read as the trusted host while fetching from the attacker. Skip the
    // scheme, then any run of slashes or backslashes, and inspect what is left
    // up to the path/query/fragment.
    let raw_authority = url
        .split_once(':')
        .map(|(_, rest)| rest.trim_start_matches(['/', '\\']))
        .unwrap_or(url)
        .split(['/', '\\', '?', '#'])
        .next()
        .unwrap_or_default();
    if raw_authority.contains('@') {
        return Err("URLs with userinfo (user:pass@host) are not allowed".into());
    }
    let parsed = reqwest::Url::parse(url).map_err(|error| format!("Invalid URL: {error}"))?;
    if parsed.scheme() != "https" {
        return Err("Only https:// URLs are allowed".into());
    }
    // Belt and braces against any encoding the raw scan above does not model.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URLs with userinfo (user:pass@host) are not allowed".into());
    }
    // `host_str()` keeps the brackets on an IPv6 literal, which would defeat the
    // `Ipv6Addr` parses the private-address checks depend on. Take the parsed
    // host so those checks see a bare address.
    let host = match parsed.host() {
        Some(url::Host::Ipv6(addr)) => addr.to_string(),
        _ => parsed
            .host_str()
            .ok_or_else(|| "URL has no host".to_string())?
            .to_string(),
    };
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "URL has no usable port".to_string())?;
    Ok((parsed.to_string(), host, port))
}

pub async fn validate_fetch_url(
    url: &str,
) -> Result<(String, String, Vec<std::net::SocketAddr>), String> {
    // Parse once through `Url` so the normalized/punycode host is the exact
    // value used for DNS lookup, reqwest's resolver pin, and the final request.
    // Raw Unicode hostnames otherwise validate one key and connect under a
    // different IDNA key, bypassing DNS pinning.
    let (normalized_url, host, url_port) = parse_fetch_url(url)?;
    if host == "localhost" {
        return Err("URLs pointing to private/loopback addresses are blocked".into());
    }

    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        if is_special_use_v4(ipv4) {
            return Err("URLs pointing to private/loopback addresses are blocked".into());
        }
    }

    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        if is_private_ip(std::net::IpAddr::V6(ipv6)) {
            return Err("URLs pointing to private/loopback addresses are blocked".into());
        }
    }

    let mut resolved_addrs = Vec::new();

    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        resolved_addrs.push(std::net::SocketAddr::new(
            std::net::IpAddr::V4(ipv4),
            url_port,
        ));
    } else if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        resolved_addrs.push(std::net::SocketAddr::new(
            std::net::IpAddr::V6(ipv6),
            url_port,
        ));
    } else {
        // `spawn_blocking(ToSocketAddrs)` cannot be cancelled: a resolver
        // that accepts queries but never answers leaves a blocking worker
        // occupied after every caller timeout. Use Tokio's cancellable lookup
        // future with an explicit deadline instead.
        const DNS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let addrs = tokio::time::timeout(
            DNS_LOOKUP_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), url_port)),
        )
        .await
        .map_err(|_| "DNS lookup timed out".to_string())?
        .map_err(|e| format!("DNS lookup failed: {e}"))?
        .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err("URL hostname could not be resolved".into());
        }
        for addr in &addrs {
            if is_private_ip(addr.ip()) {
                return Err("URL hostname resolves to a private/loopback address".into());
            }
        }
        resolved_addrs = addrs
            .iter()
            .map(|a| std::net::SocketAddr::new(a.ip(), url_port))
            .collect();
    }

    Ok((normalized_url, host, resolved_addrs))
}

/// Build a reqwest client that pins DNS to pre-validated addresses,
/// preventing TOCTOU DNS rebinding attacks.
///
/// Auto-redirects are DISABLED on purpose. reqwest's `resolve` map only
/// pins the *original* host, so its built-in redirect follower would
/// resolve any redirect target host through normal DNS — letting a
/// malicious `Location: https://169.254.169.254/…` (or an internal
/// hostname) sail straight past the private-IP checks in
/// [`validate_fetch_url`]. Callers must follow redirects via
/// [`fetch_pinned_get`], which re-validates every hop.
pub fn build_pinned_client(
    host: &str,
    addrs: &[std::net::SocketAddr],
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        // Keep these guarantees on the client itself, not just in
        // `validate_fetch_url`: callers can reuse this client for more than
        // the originally validated request, and reqwest otherwise accepts
        // plaintext URLs and environment/system proxy configuration.
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        // Hard per-request ceiling. Bootstrap downloads should be small
        // and fast; anything over a minute is already failing.
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(15));
    for addr in addrs {
        builder = builder.resolve(host, *addr);
    }
    builder
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))
}

/// Maximum number of HTTP redirects [`fetch_pinned_get`] will follow before
/// giving up. Generous enough for real hosting platforms (e.g. a
/// `releases/download` → CDN hop) without enabling redirect loops.
const MAX_FETCH_REDIRECTS: usize = 5;

/// GET a URL with full SSRF protection across redirects.
///
/// Every hop — the initial URL and each `Location` target — is run through
/// [`validate_fetch_url`] (https-only, no userinfo, DNS resolved, private/
/// loopback/link-local addresses rejected) and fetched through a freshly
/// DNS-pinned client. This closes the redirect-bypass hole that a single
/// up-front validation + auto-following client would leave open.
///
/// Returns the final non-redirect [`reqwest::Response`]; the caller is
/// responsible for status checks (`error_for_status`) and body/size limits.
pub async fn fetch_pinned_get(initial_url: &str) -> Result<reqwest::Response, String> {
    let mut current = initial_url.to_string();
    for _ in 0..=MAX_FETCH_REDIRECTS {
        let (validated_url, host, resolved_addrs) = validate_fetch_url(&current).await?;
        let client = build_pinned_client(&host, &resolved_addrs)?;
        let resp = client
            .get(&validated_url)
            .send()
            .await
            .map_err(|e| format!("HTTP request failed: {e}"))?;

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| "Redirect response had no usable Location header".to_string())?;
            // Resolve relative redirects against the URL we just fetched.
            let base = reqwest::Url::parse(&validated_url)
                .map_err(|e| format!("Could not parse request URL: {e}"))?;
            let next = base
                .join(location)
                .map_err(|e| format!("Invalid redirect target: {e}"))?;
            current = next.to_string();
            continue;
        }

        return Ok(resp);
    }
    Err(format!(
        "Too many redirects (more than {MAX_FETCH_REDIRECTS})"
    ))
}

/// Check whether a canonical path is within one of the allowed directories.
pub fn is_path_within_dirs(canonical: &Path, allowed_dirs: &[String]) -> bool {
    allowed_dirs
        .iter()
        .any(|dir| match std::fs::canonicalize(dir) {
            Ok(canon_dir) => {
                // Refuse a containment match against a filesystem root (e.g.
                // "C:\" or "/"): every path on the volume `starts_with` it, so
                // a root entry in `allowed_dirs` would authorise the entire
                // disk for open/delete/collection operations. This mirrors the
                // bare-drive guard in `path_matches_dir`. A concrete shared
                // folder always has a parent component.
                if canon_dir.parent().is_none() {
                    tracing::warn!(
                        "Ignoring filesystem-root allowed dir {dir:?} in containment check"
                    );
                    return false;
                }
                canonical.starts_with(&canon_dir)
            }
            Err(e) => {
                tracing::debug!("Skipping non-canonicalizable allowed dir {dir:?}: {e}");
                false
            }
        })
}

fn normalize_match_path(path: &str) -> String {
    // Strip Windows' extended-length prefix first. Folders chosen through the
    // picker are stored `canonicalize`d and so always carry it, while the keys
    // these paths are matched against come from `normalize_path_key`, which
    // strips it — so `\\?\C:\Media` normalized to `?/c:/media` and matched
    // nothing at all. Per-file share and priority intents for any
    // picker-added folder therefore survived that folder's removal, and were
    // silently re-applied if it was ever added back: most visibly, a file the
    // user had since re-shared got unshared again.
    let path = match path.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => path.strip_prefix(r"\\?\").unwrap_or(path).to_string(),
    };
    let replaced = path.replace('\\', "/");
    let parts: Vec<&str> = replaced.split('/').filter(|s| !s.is_empty()).collect();
    let mut resolved = Vec::new();
    for part in parts {
        if part == "." {
            continue;
        } else if part == ".." {
            resolved.pop();
        } else {
            resolved.push(part);
        }
    }
    let joined = resolved.join("/");
    if cfg!(target_os = "windows") {
        joined.to_lowercase()
    } else {
        joined
    }
}

/// Returns true when `path` is the same as `dir` or is nested beneath it,
/// using path-segment boundaries instead of raw string prefix matching.
///
/// Refuses match when `dir` resolves to a filesystem root (POSIX `/` →
/// empty string; Windows `C:\` → bare drive letter like `"c:"`).  A
/// bare-drive-letter prefix would otherwise match every path on the
/// volume — for example `unshare_folder("C:\\")` would flip
/// `shared = false` on every indexed file. Callers should pass concrete
/// folder paths; matching against a root is almost certainly a bug or a
/// malicious request and is rejected here as defense in depth.
pub fn path_matches_dir(path: &str, dir: &str) -> bool {
    let normalized_path = normalize_match_path(path);
    let normalized_dir = normalize_match_path(dir);
    if normalized_dir.is_empty() {
        return false;
    }
    if is_bare_drive_letter(&normalized_dir) {
        return false;
    }
    normalized_path == normalized_dir
        || normalized_path.starts_with(&(normalized_dir.clone() + "/"))
}

/// `true` when the normalized path is a single segment ending in `:`
/// (e.g. `"c:"`), i.e. a Windows drive root with no path components.
fn is_bare_drive_letter(normalized: &str) -> bool {
    if normalized.contains('/') {
        return false;
    }
    let bytes = normalized.as_bytes();
    bytes.len() == 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

/// Restrict file permissions to the current user only (platform-specific).
/// The checked form is used for security state so ACL failures are surfaced
/// rather than silently publishing sensitive bytes with inherited access.
pub fn restrict_file_permissions_checked(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if std::fs::metadata(path)?.is_dir() {
            0o700
        } else {
            0o600
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(target_os = "windows")]
    {
        restrict_windows_acl_atomic(path)?;
    }
    Ok(())
}

/// Restrict an already-opened object, avoiding a second pathname lookup after
/// filesystem policy has validated the handle.
pub fn restrict_open_file_permissions_checked(
    file: &std::fs::File,
    is_dir: bool,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(if is_dir {
            0o700
        } else {
            0o600
        }))?;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        };
        let acl = current_user_only_acl(is_dir)?;
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle().cast(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                acl.as_ptr().cast(),
                std::ptr::null(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn current_user_only_acl(is_dir: bool) -> std::io::Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_ALL};
    use windows_sys::Win32::Security::{
        AddAccessAllowedAceEx, GetLengthSid, GetTokenInformation, InitializeAcl, TokenUser, ACL,
        ACL_REVISION, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            let err = std::io::Error::last_os_error();
            let _ = CloseHandle(token);
            return Err(err);
        }
        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            let err = std::io::Error::last_os_error();
            let _ = CloseHandle(token);
            return Err(err);
        }
        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;
        let sid_len = GetLengthSid(sid);
        let acl_bytes = std::mem::size_of::<ACL>()
            .saturating_add(8)
            .saturating_add(sid_len as usize)
            .saturating_add(64);
        let mut acl_buf = vec![0u8; acl_bytes];
        if InitializeAcl(acl_buf.as_mut_ptr().cast(), acl_bytes as u32, ACL_REVISION) == 0 {
            let err = std::io::Error::last_os_error();
            let _ = CloseHandle(token);
            return Err(err);
        }
        let ace_flags = if is_dir {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            0
        };
        if AddAccessAllowedAceEx(
            acl_buf.as_mut_ptr().cast(),
            ACL_REVISION,
            ace_flags,
            GENERIC_ALL,
            sid,
        ) == 0
        {
            let err = std::io::Error::last_os_error();
            let _ = CloseHandle(token);
            return Err(err);
        }
        let _ = CloseHandle(token);
        Ok(acl_buf)
    }
}

/// Apply a protected, current-user-only DACL in a single `SetNamedSecurityInfo`
/// call so inheritance removal and the explicit grant cannot leave an empty
/// DACL if the process dies mid-update.
#[cfg(target_os = "windows")]
fn restrict_windows_acl_atomic(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    let is_dir = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.is_dir(),
        // Empty DACLs make ordinary metadata fail; still attempt ACL repair.
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(error) => return Err(error),
    };

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let acl_buf = current_user_only_acl(is_dir)?;

    unsafe {
        let status = SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            acl_buf.as_ptr().cast(),
            std::ptr::null(),
        );
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

pub fn restrict_file_permissions(path: &Path) {
    if let Err(error) = restrict_file_permissions_checked(path) {
        tracing::warn!(
            "Failed to restrict permissions on {}: {error}",
            path.display()
        );
    }
}

/// Write data to `final_path` atomically: a unique temp file in the same
/// directory is created, fsynced, then renamed to the destination. On Unix
/// the parent directory is also fsynced so the rename survives crashes.
/// When `restrict` is true the temp file is created with 0600 on Unix or
/// has `restrict_file_permissions` applied on Windows before the rename,
/// so the final file is never world-readable between creation and chmod.
pub fn atomic_write(final_path: &Path, data: &[u8], restrict: bool) -> std::io::Result<()> {
    use std::io::Write;

    let (tmp, mut f) = {
        let mut opened = None;
        for _ in 0..32 {
            let candidate = unique_tmp_path(final_path);
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(if restrict { 0o600 } else { 0o644 })
                    .custom_flags(libc::O_NOFOLLOW);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            match options.open(&candidate) {
                Ok(file) => {
                    opened = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        opened.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate random atomic-write temp file",
            )
        })?
    };
    if restrict {
        if let Err(error) = restrict_file_permissions_checked(&tmp) {
            drop(f);
            let _ = std::fs::remove_file(&tmp);
            return Err(error);
        }
    }
    if let Err(e) = f.write_all(data) {
        drop(f);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = f.sync_all() {
        drop(f);
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    drop(f);

    if let Err(e) = std::fs::rename(&tmp, final_path) {
        #[cfg(target_os = "windows")]
        {
            // Windows rejects rename-over-existing in some cases. The old
            // fallback deleted the destination outright and then retried the
            // rename — but if that retry also failed (AV lock, open handle),
            // the user's original file was already gone AND the temp was
            // removed, destroying data (identity.json, cryptkey.dat, etc.).
            //
            // Instead, move the existing destination aside first, publish the
            // replacement, and only then drop the backup. On any failure we
            // restore the original, so the destination is never lost.
            let _ = e;
            let backup = unique_tmp_path(final_path).with_extension("ember-replace-bak");
            match std::fs::rename(final_path, &backup) {
                Ok(()) => {
                    if let Err(retry_err) = std::fs::rename(&tmp, final_path) {
                        // Publish failed — put the original back exactly where
                        // it was and report the error. The temp is cleaned up.
                        let _ = std::fs::rename(&backup, final_path);
                        let _ = std::fs::remove_file(&tmp);
                        return Err(retry_err);
                    }
                    let _ = std::fs::remove_file(&backup);
                }
                Err(_) => {
                    // Couldn't move the destination aside (locked, or it no
                    // longer exists). Retry the rename directly WITHOUT
                    // deleting anything: if it fails, the original is left
                    // intact rather than destroyed.
                    if let Err(retry_err) = std::fs::rename(&tmp, final_path) {
                        let _ = std::fs::remove_file(&tmp);
                        return Err(retry_err);
                    }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }

    // Best-effort durability for the rename itself by flushing the parent
    // directory's metadata. On Unix this is a plain directory fsync. On Windows
    // a directory handle must be opened with FILE_FLAG_BACKUP_SEMANTICS
    // (0x0200_0000) before `FlushFileBuffers` (std's `sync_all`) will accept it
    // — previously this step was skipped entirely on Windows, so a crash right
    // after the rename could lose the directory entry even though the file
    // contents were synced. Failures are non-fatal: the file data is already
    // durable from the `sync_all` above.
    if let Some(parent) = final_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        #[cfg(unix)]
        {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
            if let Ok(dir) = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(parent)
            {
                let _ = dir.sync_all();
            }
        }
    }

    Ok(())
}

/// Back-compat: write a file with restricted perms atomically.
pub fn write_file_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    atomic_write(path, data, true)
}

/// Normalize and validate a trusted AICH master (40 hex chars). Empty input
/// yields `None`; malformed non-empty input is an error so callers fail closed.
pub fn parse_expected_aich(value: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let normalized = raw.to_ascii_lowercase();
    if normalized.len() == 40 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(Some(normalized))
    } else {
        Err("Expected AICH must be a 40-character hexadecimal SHA-1 root")
    }
}

/// Clean up log files older than the given number of days.
pub fn cleanup_old_logs(log_dir: &Path, max_age_days: u64) {
    let Ok(entries) = std::fs::read_dir(log_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("ember.log.") {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if let Ok(age) = modified.elapsed() {
                    if age.as_secs() > max_age_days * 86400 {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
    }
}

/// Sanitize a filename received from the network to prevent path traversal attacks.
/// Removes directory separators, parent references (..), and null bytes.
/// Returns a safe filename that can be used for file creation.
pub fn sanitize_filename(name: &str) -> String {
    // Normalize: strip null bytes and convert Windows separators to Unix
    let name = name.replace('\0', "").replace('\\', "/");

    let path = Path::new(&name);
    let safe_name = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .last()
        .unwrap_or("unnamed_file");

    let safe = safe_name
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() || is_invisible_or_bidi_control(c) => '_',
            c => c,
        })
        .collect::<String>();

    if safe.is_empty() || safe == "." || safe == ".." {
        return "unnamed_file".to_string();
    }

    // Prevent Windows reserved names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    let upper = safe.to_uppercase();
    let base = upper.split('.').next().unwrap_or("");
    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if reserved.contains(&base) {
        return format!("_{safe}");
    }

    let safe = if safe.len() > 255 {
        let mut end = 255;
        while end > 0 && !safe.is_char_boundary(end) {
            end -= 1;
        }
        safe[..end].to_string()
    } else {
        safe
    };

    let safe = safe
        .trim_end_matches(|c: char| c == '.' || c == ' ')
        .to_string();
    if safe.is_empty() {
        return "unnamed_file".to_string();
    }

    safe
}

/// Render a peer hash for logs without leaking the full identifier. Returns
/// the first 8 hex chars (4 bytes) plus an ellipsis — enough to correlate log
/// lines across a session, not enough to deanonymize a peer from a leaked log.
pub fn short_hash(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    let n = hex.len().min(8);
    format!("{}…", &hex[..n])
}

/// Validate that a path stays within the given base directory.
/// Returns the safe path, or None if it escapes the base.
pub fn validate_path_within(base: &Path, relative: &str) -> Option<PathBuf> {
    let sanitized = sanitize_filename(relative);
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        return None;
    }
    if sanitized.contains('/') || sanitized.contains('\\') {
        return None;
    }
    let full = base.join(&sanitized);

    let canonical_base = std::fs::canonicalize(base).ok()?;
    if let Ok(canonical_full) = std::fs::canonicalize(&full) {
        if !canonical_full.starts_with(&canonical_base) {
            return None;
        }
    } else if let Some(parent) = full.parent() {
        let canonical_parent = std::fs::canonicalize(parent).ok()?;
        if !canonical_parent.starts_with(&canonical_base) {
            return None;
        }
    }

    Some(full)
}

/// Returns `true` for code points that are visually invisible or
/// reorder neighbouring text — bidi controls, zero-width spaces,
/// the BOM, and other Cf-category formatters that don't render.
///
/// L20: even with `<bdi>` wrapping (M14) the underlying text still
/// contains the override characters, so they roundtrip through chat,
/// copy-paste, and the friends list. Stripping at sanitise time
/// removes the spoofing primitive entirely instead of just hiding
/// its rendering effects.
/// Public re-export of `is_invisible_or_bidi_control` for callers
/// (e.g. the settings update path) that need the same predicate
/// but a different empty-input fallback than `sanitize_display_name`.
pub fn is_invisible_or_bidi_control_pub(c: char) -> bool {
    is_invisible_or_bidi_control(c)
}

fn is_invisible_or_bidi_control(c: char) -> bool {
    matches!(c,
        // Arabic letter mark (bidi control).
        '\u{061C}'
        // Mongolian vowel separator: invisible, used in some
        // historical spoofing payloads.
        | '\u{180E}'
        // Zero-width spaces, joiners, LTR/RTL marks.
        | '\u{200B}'..='\u{200F}'
        // LTR/RTL embedding, pop, override.
        | '\u{202A}'..='\u{202E}'
        // Unicode line/paragraph separators can visually split a one-line
        // filename or display name without being caught by `is_control`.
        | '\u{2028}' | '\u{2029}'
        // Word joiner, function application, invisible separator
        // / times / plus.
        | '\u{2060}'..='\u{2064}'
        // LTR/RTL/first-strong isolate, pop directional isolate.
        | '\u{2066}'..='\u{2069}'
        // BOM / zero-width no-break space.
        | '\u{FEFF}'
        // Variation selectors (rarely legitimate in user input,
        // sometimes used to alter visual identity of preceding
        // characters).
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{E0100}'..='\u{E01EF}'
    )
}

/// Sanitize a nickname/display name from a peer. Removes control
/// characters, bidi-override / zero-width formatters, and limits
/// length to prevent UI injection.
pub fn sanitize_display_name(name: &str) -> String {
    const MAX_DISPLAY_NAME_LEN: usize = 128;

    let sanitized: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '\0' && !is_invisible_or_bidi_control(*c))
        .take(MAX_DISPLAY_NAME_LEN)
        .collect();

    if sanitized.trim().is_empty() {
        "Anonymous".to_string()
    } else {
        sanitized.trim().to_string()
    }
}

/// Strip non-printing/reordering characters from network-originated UI text
/// while preserving ordinary RTL letters and punctuation. Call this before
/// deriving a filename extension or media type so invisible suffix tricks
/// cannot influence security- or behavior-relevant classification.
pub fn sanitize_remote_text(text: &str, max_chars: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control() && *c != '\0' && !is_invisible_or_bidi_control(*c))
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Maximum bytes inspected from an untrusted friend-request payload. The
/// packet reader has a much larger framing limit for other message types, so
/// friend-request handling must impose its own narrow bound before creating a
/// display string, emitting an event, or writing a log/DB row.
pub const MAX_INBOUND_FRIEND_NICKNAME_BYTES: usize = 256;
pub const MAX_INBOUND_FRIEND_NICKNAME_CHARS: usize = 64;

/// Normalize a friend-request nickname supplied as decoded text.
///
/// This keeps the request UI compatible with peers that send decorative
/// Unicode while guaranteeing a compact, single-line display value.
pub fn sanitize_inbound_friend_nickname(name: &str) -> String {
    let cleaned = sanitize_remote_text(name, MAX_INBOUND_FRIEND_NICKNAME_CHARS);
    if cleaned.is_empty() {
        "Anonymous".to_string()
    } else {
        cleaned
    }
}

/// Normalize a wire-format friend-request nickname without scanning or
/// allocating from an arbitrarily large payload.
pub fn normalize_inbound_friend_nickname(payload: &[u8]) -> String {
    let bounded = &payload[..payload.len().min(MAX_INBOUND_FRIEND_NICKNAME_BYTES)];
    // A byte cap can land in the middle of a multibyte character. Preserve
    // the valid prefix instead of discarding an otherwise legitimate name.
    let name = match std::str::from_utf8(bounded) {
        Ok(name) => name,
        Err(error) => std::str::from_utf8(&bounded[..error.valid_up_to()]).unwrap_or(""),
    };
    sanitize_inbound_friend_nickname(name)
}

/// Sanitize free-form chat text from the local user before
/// sending. Mirrors `sanitize_display_name` but preserves newlines
/// (the chat textarea allows Shift+Enter), and does NOT default to
/// "Anonymous" on empty input — an empty chat string just means
/// "don't send".
///
/// L20: applied to outbound chat so a malicious paste of
/// `"\u202EnoitPircsed eht"` doesn't ship to friends as a
/// legitimate-looking but bidi-flipped message. Inbound chat is
/// rendered through `<bdi>` (M14) which neutralises the visual
/// effect; stripping on the way out closes the storage and
/// roundtrip vector.
pub fn sanitize_chat_text(text: &str) -> String {
    const MAX_CHAT_LEN: usize = 4096;

    text.chars()
        .filter(|c| {
            // Drop ASCII control chars except newline (\n) and
            // carriage return (\r) — the textarea normalises CRLF
            // to LF on submit, and a lone CR is rare but harmless.
            // Tab (\t) is also kept; users sometimes paste tab-
            // delimited fragments.
            if *c == '\n' || *c == '\r' || *c == '\t' {
                return true;
            }
            !c.is_control() && *c != '\0' && !is_invisible_or_bidi_control(*c)
        })
        .take(MAX_CHAT_LEN)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal.txt"), "normal.txt");
        assert_eq!(sanitize_filename("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_filename("..\\..\\Windows\\System32\\file"), "file");
        assert_eq!(sanitize_filename("/root/secret"), "secret");
        assert_eq!(sanitize_filename("file\0name.txt"), "filename.txt");
        assert_eq!(sanitize_filename(""), "unnamed_file");
        assert_eq!(sanitize_filename(".."), "unnamed_file");
        assert_eq!(sanitize_filename("CON.txt"), "_CON.txt");
        assert_eq!(sanitize_filename("file:name"), "file_name");
    }

    #[test]
    fn test_sanitize_display_name() {
        assert_eq!(sanitize_display_name("Alice"), "Alice");
        assert_eq!(sanitize_display_name(""), "Anonymous");
        assert_eq!(sanitize_display_name("Bob\x00Evil"), "BobEvil");
        assert_eq!(sanitize_display_name("\n\r\t"), "Anonymous");
        let long_name = "A".repeat(200);
        assert_eq!(sanitize_display_name(&long_name).len(), 128);
    }

    #[test]
    fn sanitize_display_name_strips_bidi_and_zero_width() {
        // L20: invisible / reordering code points must not survive.
        assert_eq!(sanitize_display_name("Al\u{202E}ice"), "Alice");
        assert_eq!(sanitize_display_name("Bo\u{200B}b"), "Bob");
        assert_eq!(sanitize_display_name("Carol\u{2066}\u{2069}"), "Carol");
        assert_eq!(sanitize_display_name("Dave\u{FEFF}"), "Dave");
        assert_eq!(sanitize_display_name("E\u{202A}v\u{202C}e"), "Eve");
        assert_eq!(sanitize_display_name("A\u{061C}rabic"), "Arabic");
        assert_eq!(sanitize_display_name("Line\u{2028}Break"), "LineBreak");
        assert_eq!(sanitize_display_name("Para\u{2029}Break"), "ParaBreak");
        // Variation selectors are also dropped.
        assert_eq!(sanitize_display_name("Frank\u{FE0F}"), "Frank");
        // A nickname that's purely invisible chars falls back like
        // an empty input would.
        assert_eq!(
            sanitize_display_name("\u{202E}\u{200B}\u{FEFF}"),
            "Anonymous"
        );
    }

    #[test]
    fn remote_text_strips_bidi_controls_but_preserves_real_rtl() {
        assert_eq!(
            sanitize_remote_text("report\u{202E}fdp.exe\u{200B}", 128),
            "reportfdp.exe"
        );
        assert_eq!(
            sanitize_remote_text("ملف عربي — קובץ עברי", 128),
            "ملف عربي — קובץ עברי"
        );
        assert_eq!(sanitize_remote_text("a\u{0000}\nb\tc", 128), "abc");
    }

    #[test]
    fn inbound_friend_nickname_is_bounded_before_storage_or_logging() {
        let payload = vec![b'A'; MAX_INBOUND_FRIEND_NICKNAME_BYTES * 64];
        let nickname = normalize_inbound_friend_nickname(&payload);
        assert_eq!(nickname.chars().count(), MAX_INBOUND_FRIEND_NICKNAME_CHARS);
        assert_eq!(
            normalize_inbound_friend_nickname(b"Al\xE2\x80\xAEice"),
            "Alice"
        );
        assert_eq!(normalize_inbound_friend_nickname(&[0xFF; 32]), "Anonymous");

        let mut split_multibyte = vec![b'A'; MAX_INBOUND_FRIEND_NICKNAME_BYTES - 3];
        split_multibyte.extend_from_slice("💬".as_bytes());
        let normalized = normalize_inbound_friend_nickname(&split_multibyte);
        assert_ne!(normalized, "Anonymous");
        assert_eq!(
            normalized.chars().count(),
            MAX_INBOUND_FRIEND_NICKNAME_CHARS
        );
    }

    #[test]
    fn fetch_url_parser_uses_one_idna_host_for_validation_and_pinning() {
        let (normalized, host, port) =
            parse_fetch_url("https://bücher.example/path?source=test").unwrap();
        assert_eq!(host, "xn--bcher-kva.example");
        assert!(normalized.starts_with("https://xn--bcher-kva.example/"));
        assert_eq!(port, 443);
        assert!(parse_fetch_url("https://@example.com/").is_err());
    }

    /// Scanning the raw string for '@' only catches the forms that contain a
    /// literal "://". The url crate accepts several that do not, and
    /// re-serializes the credentials into the request, so the check has to run
    /// against the parsed URL.
    #[test]
    fn fetch_url_parser_rejects_userinfo_without_a_literal_scheme_separator() {
        for url in [
            "https:user:pass@evil.example/ipfilter.zip",
            "https:@evil.example/",
            "https:/\\/\\user@evil.example/",
            "https://trusted.example@evil.example/",
        ] {
            assert!(
                parse_fetch_url(url).is_err(),
                "expected userinfo rejection for {url}"
            );
        }
    }

    /// `host_str()` keeps the brackets on an IPv6 literal; the private-address
    /// checks parse this value as an `Ipv6Addr`, so brackets would make both of
    /// them dead code and let every IPv6 URL fall through to a DNS lookup.
    #[test]
    fn fetch_url_parser_returns_a_bare_ipv6_host() {
        let (_, host, port) = parse_fetch_url("https://[2606:4700:4700::1111]/x").unwrap();
        assert_eq!(host, "2606:4700:4700::1111");
        assert_eq!(port, 443);
        assert!(host.parse::<std::net::Ipv6Addr>().is_ok());
    }

    #[test]
    fn single_flight_rejects_overlap_and_releases_on_drop() {
        let flag = AtomicBool::new(false);
        let first = try_begin_single_flight(&flag).expect("first request starts");
        assert!(try_begin_single_flight(&flag).is_none());
        drop(first);
        assert!(try_begin_single_flight(&flag).is_some());
    }

    #[test]
    fn sanitize_chat_text_keeps_newlines_strips_overrides() {
        // L20: chat text preserves whitespace newlines but drops
        // override / zero-width formatting.
        assert_eq!(sanitize_chat_text("hello\nworld"), "hello\nworld");
        assert_eq!(sanitize_chat_text("hello\rworld"), "hello\rworld");
        assert_eq!(sanitize_chat_text("a\tb"), "a\tb");
        assert_eq!(
            sanitize_chat_text("paypal\u{202E}moc.lapyap"),
            "paypalmoc.lapyap",
        );
        assert_eq!(sanitize_chat_text("invisible\u{200B}text"), "invisibletext");
        // NUL bytes are still stripped.
        assert_eq!(sanitize_chat_text("a\0b"), "ab");
        // Cap respected.
        let big = "x".repeat(8_000);
        assert_eq!(sanitize_chat_text(&big).len(), 4096);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn restricted_windows_directory_keeps_current_user_access() {
        let dir = std::env::temp_dir().join(format!(
            "ember-acl-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        restrict_file_permissions_checked(&dir).unwrap();

        let file = dir.join("ember.log.test");
        std::fs::write(&file, b"log").expect("restricted directory must remain writable");
        restrict_file_permissions_checked(&file).unwrap();
        assert_eq!(
            std::fs::read(&file).expect("restricted file must remain readable"),
            b"log"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn repairs_windows_file_left_with_empty_inherited_acl() {
        use std::os::windows::process::CommandExt;

        let dir = std::env::temp_dir().join(format!(
            "ember-acl-repair-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("ember.db-wal");
        std::fs::write(&file, b"state").unwrap();

        // Reproduce the old bug: removing inheritance from a file with no
        // explicit user ACE leaves it inaccessible.
        let output = std::process::Command::new("icacls")
            .arg(&file)
            .args(["/inheritance:r", "/q"])
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(output.status.success());

        restrict_file_permissions_checked(&file).expect("ACL repair must restore owner access");
        assert_eq!(std::fs::read(&file).unwrap(), b"state");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
