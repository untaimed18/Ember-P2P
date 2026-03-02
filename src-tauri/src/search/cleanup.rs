/// Filename cleanup matching eMule's CleanupFilename from OtherFunctions.cpp.
/// This is for display only -- the actual filename on disk is not modified.

pub const DEFAULT_CLEANUP_STRINGS: &str =
    "http|www.|.com|.de|.org|.net|shared|powered|sponsored|sharelive|filedonkey";

const COMMENT_URL_PATTERNS: &[&str] = &["http://", "https://", "ftp://", "www.", "ftp."];

/// Clean up a filename for display. Removes promotional text, replaces separators
/// with spaces, strips bracketed ads, and applies title case.
pub fn cleanup_filename(name: &str, cleanup_strings: &[String]) -> String {
    if name.is_empty() {
        return String::new();
    }

    let (stem, ext) = split_name_ext(name);

    let mut result = url_decode(&stem);

    let lower = result.to_lowercase();
    for pattern in cleanup_strings {
        let pat_lower = pattern.to_lowercase();
        if pat_lower.is_empty() {
            continue;
        }
        let mut cleaned = String::with_capacity(result.len());
        let mut search_in = lower.as_str();
        let mut orig = result.as_str();
        while let Some(pos) = search_in.find(&pat_lower) {
            cleaned.push_str(&orig[..pos]);
            search_in = &search_in[pos + pat_lower.len()..];
            orig = &orig[pos + pat_lower.len()..];
        }
        cleaned.push_str(orig);
        result = cleaned;
    }

    result = replace_dots_with_spaces(&result);

    result = result
        .chars()
        .map(|c| match c {
            '_' | '+' | '=' => ' ',
            c if is_invalid_filename_char(c) => ' ',
            c => c,
        })
        .collect();

    result = strip_brackets(&result);

    result = title_case(&result);

    result = collapse_spaces(&result);

    if !ext.is_empty() {
        format!("{result}.{ext}")
    } else {
        result
    }
}

/// Strip URLs and URL-like patterns from a comment string.
pub fn strip_comment_urls(comment: &str) -> String {
    let mut result = comment.to_string();
    for pattern in COMMENT_URL_PATTERNS {
        while let Some(start) = result.to_lowercase().find(&pattern.to_lowercase()) {
            let end = result[start..]
                .find(|c: char| c.is_whitespace())
                .map(|pos| start + pos)
                .unwrap_or(result.len());
            result.replace_range(start..end, "");
        }
    }
    collapse_spaces(&result)
}

/// Parse user-configured cleanup strings (pipe-separated).
pub fn parse_cleanup_strings(config: &str) -> Vec<String> {
    config
        .split('|')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn split_name_ext(name: &str) -> (String, String) {
    if let Some(dot_pos) = name.rfind('.') {
        if dot_pos > 0 && dot_pos < name.len() - 1 {
            let stem = name[..dot_pos].to_string();
            let ext = name[dot_pos + 1..].to_string();
            return (stem, ext);
        }
    }
    (name.to_string(), String::new())
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                if byte >= 0x20 {
                    result.push(byte as char);
                    i += 3;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn replace_dots_with_spaces(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::with_capacity(s.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '.' {
            let prev_digit = i > 0 && chars[i - 1].is_ascii_digit();
            let next_digit = i + 1 < chars.len() && chars[i + 1].is_ascii_digit();
            if prev_digit && next_digit {
                result.push('.');
            } else {
                result.push(' ');
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn is_invalid_filename_char(c: char) -> bool {
    matches!(c, '"' | '*' | '<' | '>' | '?' | '|' | '\\' | '/')
}

fn strip_brackets(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut depth = 0usize;
    let mut bracket_content = String::new();
    for c in s.chars() {
        match c {
            '[' => {
                depth += 1;
                bracket_content.clear();
            }
            ']' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    let trimmed = bracket_content.trim();
                    if trimmed.len() <= 3 && trimmed.chars().all(|c| c.is_alphanumeric()) {
                        result.push('[');
                        result.push_str(trimmed);
                        result.push(']');
                    }
                }
            }
            _ => {
                if depth > 0 {
                    bracket_content.push(c);
                } else {
                    result.push(c);
                }
            }
        }
    }
    result
}

fn title_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut capitalize_next = true;
    for c in s.chars() {
        if c.is_alphabetic() {
            if capitalize_next {
                result.extend(c.to_uppercase());
                capitalize_next = false;
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
            if c != '\'' {
                capitalize_next = !c.is_alphanumeric();
            }
        }
    }
    result
}

fn collapse_spaces(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut last_was_space = true;
    for c in s.chars() {
        if c == ' ' {
            if !last_was_space {
                result.push(' ');
            }
            last_was_space = true;
        } else {
            result.push(c);
            last_was_space = false;
        }
    }
    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cleanup() -> Vec<String> {
        parse_cleanup_strings(DEFAULT_CLEANUP_STRINGS)
    }

    #[test]
    fn test_basic_cleanup() {
        let result = cleanup_filename(
            "Great.Movie.2024.1080p.BluRay.x264-GROUP.mkv",
            &default_cleanup(),
        );
        assert_eq!(result, "Great Movie 2024 1080p BluRay X264-GROUP.mkv");
    }

    #[test]
    fn test_url_removal() {
        let result = cleanup_filename(
            "Song_-_Artist_[www.site.com].mp3",
            &default_cleanup(),
        );
        assert!(!result.contains("www"));
        assert!(!result.contains("site"));
    }

    #[test]
    fn test_underscore_replacement() {
        let result = cleanup_filename("my_cool_file.txt", &default_cleanup());
        assert_eq!(result, "My Cool File.txt");
    }

    #[test]
    fn test_preserves_decimal() {
        let result = cleanup_filename("version.1.5.patch.zip", &default_cleanup());
        assert!(result.contains("1.5"));
    }

    #[test]
    fn test_strip_comment_urls() {
        let comment = "Great file! Download more at http://spam.com thanks";
        let result = strip_comment_urls(comment);
        assert!(!result.contains("http://"));
        assert!(!result.contains("spam.com"));
    }

    #[test]
    fn test_empty_filename() {
        assert_eq!(cleanup_filename("", &default_cleanup()), "");
    }

    #[test]
    fn test_short_bracket_kept() {
        let result = cleanup_filename("Song [HD] remix.mp3", &default_cleanup());
        assert!(result.contains("[HD]"));
    }
}
