#[cfg(target_os = "windows")]
pub mod firewall;

use std::path::{Component, Path, PathBuf};

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
