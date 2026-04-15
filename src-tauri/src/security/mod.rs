#[cfg(target_os = "windows")]
pub mod firewall;

use std::path::{Component, Path, PathBuf};

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "bat", "cmd", "com", "scr", "pif", "msi", "msp", "mst",
    "cpl", "hta", "inf", "ins", "isp", "jse", "lnk", "reg", "rgs",
    "sct", "shb", "shs", "vbe", "vbs", "wsc", "wsf", "wsh", "ws",
    "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "psm1",
    "application", "gadget", "msh", "msh1", "msh2", "mshxml",
    "msh1xml", "msh2xml", "dll", "sys", "drv",
];

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

pub(crate) fn is_special_use_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback() || v4.is_private() || v4.is_link_local()
        || v4.is_unspecified() || v4.is_broadcast()
        || is_shared_address(v4)
        || is_documentation_v4(v4)
        || is_benchmarking_v4(v4)
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

pub(crate) fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_special_use_v4(v4),
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
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
                    (segs[6] >> 8) as u8, segs[6] as u8,
                    (segs[7] >> 8) as u8, segs[7] as u8,
                );
                return is_special_use_v4(mapped);
            }
            false
        }
    }
}

/// Validate a URL for safe fetching. Blocks non-HTTP schemes and private IPs.
/// Also resolves hostnames and returns the validated (host, resolved_addrs) pair
/// so callers can pin DNS with `reqwest::Client::builder().resolve()`,
/// preventing TOCTOU DNS rebinding attacks.
pub async fn validate_fetch_url(url: &str) -> Result<(String, String, Vec<std::net::SocketAddr>), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("URL is empty".into());
    }
    let url_lower = url.to_ascii_lowercase();
    if !url_lower.starts_with("https://") && !url_lower.starts_with("http://") {
        return Err("Only http:// and https:// URLs are allowed".into());
    }

    let scheme_port: u16 = if url_lower.starts_with("https://") { 443 } else { 80 };
    let scheme_str = if url_lower.starts_with("https://") { "https://" } else { "http://" };

    let host_part = url_lower
        .strip_prefix("https://")
        .or_else(|| url_lower.strip_prefix("http://"))
        .unwrap_or("");
    let raw_authority = host_part.split('/').next().unwrap_or("");
    if raw_authority.contains('@') {
        return Err("URLs with userinfo (user:pass@host) are not allowed".into());
    }
    let authority = raw_authority;

    let host = if authority.starts_with('[') {
        authority.split(']').next().unwrap_or("").trim_start_matches('[').to_lowercase()
    } else {
        authority.split(':').next().unwrap_or("").to_lowercase()
    };

    if host.is_empty() {
        return Err("URL has no host".into());
    }

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

    let original_after_scheme = &url[scheme_str.len()..];
    let path_and_rest = original_after_scheme.find('/').map(|i| &original_after_scheme[i..]).unwrap_or("");
    let normalized_url = format!("{}{}{}", scheme_str, authority, path_and_rest);

    let url_port = if authority.starts_with('[') {
        authority.rsplit(']').next()
            .and_then(|rest| rest.strip_prefix(':'))
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(scheme_port)
    } else if authority.matches(':').count() == 1 {
        authority.split(':').nth(1)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(scheme_port)
    } else {
        scheme_port
    };

    let mut resolved_addrs = Vec::new();

    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        resolved_addrs.push(std::net::SocketAddr::new(std::net::IpAddr::V4(ipv4), url_port));
    } else if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        resolved_addrs.push(std::net::SocketAddr::new(std::net::IpAddr::V6(ipv6), url_port));
    } else {
        let lookup_host = host.clone();
        let lookup_addr = format!("{lookup_host}:{scheme_port}");
        let resolved = tokio::task::spawn_blocking(move || {
            std::net::ToSocketAddrs::to_socket_addrs(&lookup_addr.as_str())
                .map(|addrs| addrs.collect::<Vec<_>>())
        })
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?;
        let addrs = resolved.map_err(|e| format!("DNS lookup failed: {e}"))?;
        if addrs.is_empty() {
            return Err("URL hostname could not be resolved".into());
        }
        for addr in &addrs {
            if is_private_ip(addr.ip()) {
                return Err("URL hostname resolves to a private/loopback address".into());
            }
        }
        resolved_addrs = addrs.iter()
            .map(|a| std::net::SocketAddr::new(a.ip(), url_port))
            .collect();
    }

    Ok((normalized_url, host, resolved_addrs))
}

/// Build a reqwest client that pins DNS to pre-validated addresses,
/// preventing TOCTOU DNS rebinding attacks.
pub fn build_pinned_client(host: &str, addrs: &[std::net::SocketAddr]) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();
    for addr in addrs {
        builder = builder.resolve(host, *addr);
    }
    builder.build().map_err(|e| format!("Failed to build HTTP client: {e}"))
}

/// Check whether a canonical path is within one of the allowed directories.
pub fn is_path_within_dirs(canonical: &Path, allowed_dirs: &[String]) -> bool {
    allowed_dirs.iter().any(|dir| {
        match std::fs::canonicalize(dir) {
            Ok(canon_dir) => canonical.starts_with(&canon_dir),
            Err(e) => {
                tracing::debug!("Skipping non-canonicalizable allowed dir {dir:?}: {e}");
                false
            }
        }
    })
}

fn normalize_match_path(path: &str) -> String {
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
pub fn path_matches_dir(path: &str, dir: &str) -> bool {
    let normalized_path = normalize_match_path(path);
    let normalized_dir = normalize_match_path(dir);
    if normalized_dir.is_empty() {
        return false;
    }
    normalized_path == normalized_dir
        || normalized_path.starts_with(&(normalized_dir.clone() + "/"))
}

/// Restrict file permissions to the current user only (platform-specific).
pub fn restrict_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(target_os = "windows")]
    {
        let path_str = path.to_string_lossy().to_string();
        use std::os::windows::process::CommandExt;
        let _ = std::process::Command::new("icacls")
            .args([
                &path_str,
                "/inheritance:r",
                "/grant:r",
                &format!("{}:(F)", whoami()),
                "/q",
            ])
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output();
    }
}

/// Write data to a file that is created with restricted permissions from
/// the start, avoiding the TOCTOU window of write-then-chmod.
pub fn write_file_restricted(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        std::io::Write::write_all(&mut f, data)?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        let dir = path.parent().unwrap_or(path);
        let tmp = dir.join(format!(".ember_tmp_{}", std::process::id()));
        std::fs::write(&tmp, data)?;
        restrict_file_permissions(&tmp);
        match std::fs::rename(&tmp, path) {
            Ok(()) => Ok(()),
            Err(_first_err) => {
                let _ = std::fs::remove_file(path);
                match std::fs::rename(&tmp, path) {
                    Ok(()) => Ok(()),
                    Err(_retry_err) => {
                        tracing::warn!("Atomic rename failed, falling back to direct write for {}", path.display());
                        let _ = std::fs::remove_file(&tmp);
                        std::fs::write(path, data)?;
                        restrict_file_permissions(path);
                        Ok(())
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn whoami() -> String {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("whoami")
        .creation_flags(0x08000000)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s: String| s.trim().to_string())
        .unwrap_or_else(|| std::env::var("USERNAME").unwrap_or_else(|_| "CURRENTUSER".to_string()))
}

/// Clean up log files older than the given number of days.
pub fn cleanup_old_logs(log_dir: &Path, max_age_days: u64) {
    let Ok(entries) = std::fs::read_dir(log_dir) else { return };
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
            c if c.is_control() => '_',
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
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
        "LPT9",
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

    let safe = safe.trim_end_matches(|c: char| c == '.' || c == ' ').to_string();
    if safe.is_empty() {
        return "unnamed_file".to_string();
    }

    safe
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

/// Sanitize a nickname/display name from a peer. Removes control characters
/// and limits length to prevent UI injection.
pub fn sanitize_display_name(name: &str) -> String {
    const MAX_DISPLAY_NAME_LEN: usize = 128;

    let sanitized: String = name
        .chars()
        .filter(|c| !c.is_control() && *c != '\0')
        .take(MAX_DISPLAY_NAME_LEN)
        .collect();

    if sanitized.trim().is_empty() {
        "Anonymous".to_string()
    } else {
        sanitized.trim().to_string()
    }
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
}
