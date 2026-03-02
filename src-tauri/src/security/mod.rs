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
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    DANGEROUS_EXTENSIONS.contains(&ext.as_str())
}

/// Validate a URL for safe fetching. Blocks non-HTTP schemes and private IPs.
pub fn validate_fetch_url(url: &str) -> Result<(), String> {
    let url = url.trim();
    if url.is_empty() {
        return Err("URL is empty".into());
    }
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err("Only http:// and https:// URLs are allowed".into());
    }

    let host_part = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or("");
    let host = host_part
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_lowercase();

    if host.is_empty() {
        return Err("URL has no host".into());
    }
    if host == "localhost"
        || host == "127.0.0.1"
        || host == "[::1]"
        || host == "0.0.0.0"
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.")
    {
        return Err("URLs pointing to private/loopback addresses are blocked".into());
    }
    if host.starts_with("172.") {
        if let Some(second_octet) = host.strip_prefix("172.").and_then(|s| s.split('.').next()) {
            if let Ok(n) = second_octet.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return Err("URLs pointing to private addresses are blocked".into());
                }
            }
        }
    }
    Ok(())
}

/// Check whether a canonical path is within one of the allowed directories.
pub fn is_path_within_dirs(canonical: &Path, allowed_dirs: &[String]) -> bool {
    allowed_dirs.iter().any(|dir| {
        if let Ok(canon_dir) = std::fs::canonicalize(dir) {
            canonical.starts_with(&canon_dir)
        } else {
            false
        }
    })
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

#[cfg(target_os = "windows")]
fn whoami() -> String {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("whoami")
        .creation_flags(0x08000000)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s: String| s.trim().to_string())
        .unwrap_or_else(|| "%USERNAME%".to_string())
}

/// Clean up log files older than the given number of days.
pub fn cleanup_old_logs(log_dir: &Path, max_age_days: u64) {
    let Ok(entries) = std::fs::read_dir(log_dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("nexus.log.") {
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
        safe[..255].to_string()
    } else {
        safe
    };

    safe
}

/// Validate that a path stays within the given base directory.
/// Returns the canonical-ish safe path, or None if it escapes the base.
pub fn validate_path_within(base: &Path, relative: &str) -> Option<PathBuf> {
    let sanitized = sanitize_filename(relative);
    let full = base.join(&sanitized);

    let canonical_base = std::fs::canonicalize(base).ok()?;
    // Since the file might not exist yet, we canonicalize the parent
    let parent = full.parent()?;
    let canonical_parent = std::fs::canonicalize(parent).ok()?;

    if canonical_parent.starts_with(&canonical_base) {
        Some(full)
    } else {
        None
    }
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
