/// Filename cleanup matching eMule's CleanupFilename from OtherFunctions.cpp.
/// This is for display only -- the actual filename on disk is not modified.

pub const DEFAULT_CLEANUP_STRINGS: &str =
    "http|www.|.com|.de|.org|.net|shared|powered|sponsored|sharelive|filedonkey";

const COMMENT_URL_PATTERNS: &[&str] = &["http://", "https://", "ftp://", "www.", "ftp."];

/// Removes every (possibly cascading) occurrence of `pat_lower`
/// (already-lowercased) from `chars`, case-insensitively — the same
/// fixpoint as "find the leftmost match, remove it, repeat until none
/// remain" — but in a single O(len(chars)) pass instead of one O(len)
/// rescan *per removal*.
///
/// Implemented as a stack: each source char is pushed, then we check
/// whether the stack's last `pat_char_len` chars now spell out the
/// pattern; if so we pop them instead of keeping them. Removing a
/// match can make the chars just before and after it adjacent, which
/// can immediately form a *new* match (e.g. pattern "aa" on "a"+"a"+"a"
/// removes the first two, leaving "a"+"a" adjacent, which then also
/// matches) — restarting the scan from scratch handles that correctly
/// but is what made the old loop quadratic; the stack handles it for
/// free, since the next char pushed is always compared against
/// whatever the *current* stack top is, which already reflects every
/// removal so far. Every char is pushed and popped at most once, so
/// this is O(len(chars) * pat_char_len) total — pat_char_len is a
/// small bounded constant (cleanup strings are short words), so this
/// is effectively linear in the filename length.
///
/// This matters because eD2k filenames are fully attacker-controlled
/// (any peer can publish any filename for a shared/searched file): a
/// filename engineered with many repeated short cleanup-pattern
/// instances (e.g. thousands of "www." in a row) drove the old
/// per-removal-rescan loop to quadratic time, i.e. remotely-triggered
/// CPU cost on every UI render of the crafted name.
fn remove_all_case_insensitive(chars: &[char], pat_lower: &str) -> Vec<char> {
    let pat_char_len = pat_lower.chars().count();
    if pat_char_len == 0 {
        return chars.to_vec();
    }
    let mut stack: Vec<char> = Vec::with_capacity(chars.len());
    for &c in chars {
        stack.push(c);
        if stack.len() >= pat_char_len {
            let tail_start = stack.len() - pat_char_len;
            let tail_matches = stack[tail_start..]
                .iter()
                .flat_map(|c| c.to_lowercase())
                .eq(pat_lower.chars());
            if tail_matches {
                stack.truncate(tail_start);
            }
        }
    }
    stack
}

/// Clean up a filename for display. Removes promotional text, replaces separators
/// with spaces, strips bracketed ads, and applies title case.
pub fn cleanup_filename(name: &str, cleanup_strings: &[String]) -> String {
    if name.is_empty() {
        return String::new();
    }

    let (stem, ext) = split_name_ext(name);

    let mut result = url_decode(&stem);

    for pattern in cleanup_strings {
        let pat_lower = pattern.to_lowercase();
        if pat_lower.is_empty() {
            continue;
        }
        let chars: Vec<char> = result.chars().collect();
        result = remove_all_case_insensitive(&chars, &pat_lower)
            .into_iter()
            .collect();
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

/// Removes every occurrence of `pat_lower` (already-lowercased) from
/// `s`, together with everything from the start of that occurrence up
/// to (but not including) the next whitespace character — i.e. "drop
/// the whole URL-like word". Same result as the old find-one /
/// remove-one / restart-from-byte-0 loop, but a single left-to-right
/// pass instead of re-lowercasing and re-scanning the *entire
/// remaining string* after every removal.
///
/// Unlike `remove_all_case_insensitive` above, this doesn't need
/// stack/cascading logic: every removed span stops right at a
/// whitespace char (or the string's end), and none of
/// `COMMENT_URL_PATTERNS` contain whitespace, so a removal can never
/// glue two non-whitespace runs together and create a *new* pattern
/// match at the join point. A single forward pass therefore finds
/// every match a from-scratch restart would have found.
///
/// Comment strings are just as attacker-controlled as filenames (any
/// peer can attach any comment to a shared file), so the same
/// quadratic-blowup concern applies — a comment packed with many
/// short "wordN " tokens each starting with one of these patterns
/// drove the old loop to quadratic time.
fn remove_url_words_case_insensitive(s: &str, pat_lower: &str) -> String {
    if pat_lower.is_empty() {
        return s.to_string();
    }
    let chars: Vec<char> = s.chars().collect();
    let lower_chars: Vec<char> = s.to_lowercase().chars().collect();
    // Case-folding essentially never changes char count for the
    // ASCII-only patterns here, but if it ever does for some exotic
    // input, positions in `lower_chars` can't be safely mapped back
    // onto `chars` — bail out unchanged rather than risk misaligned
    // indexing.
    if lower_chars.len() != chars.len() {
        return s.to_string();
    }
    let pat_chars: Vec<char> = pat_lower.chars().collect();
    let pat_len = pat_chars.len();
    let n = chars.len();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < n {
        if i + pat_len <= n && lower_chars[i..i + pat_len] == pat_chars[..] {
            let mut j = i;
            while j < n && !chars[j].is_whitespace() {
                j += 1;
            }
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Strip URLs and URL-like patterns from a comment string.
pub fn strip_comment_urls(comment: &str) -> String {
    let mut result = comment.to_string();
    for pattern in COMMENT_URL_PATTERNS {
        let pat_lower = pattern.to_lowercase();
        result = remove_url_words_case_insensitive(&result, &pat_lower);
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
    let mut decoded_bytes = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                if byte >= 0x20 {
                    decoded_bytes.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        decoded_bytes.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(decoded_bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn replace_dots_with_spaces(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len();
    let mut result = String::with_capacity(s.len());
    for (i, &c) in chars.iter().enumerate() {
        if c == '.' {
            let prev_digit = i > 0 && chars[i - 1].is_ascii_digit();
            let next_digit = i + 1 < len && chars[i + 1].is_ascii_digit();
            if prev_digit && next_digit {
                // Count digit-run lengths on each side to distinguish real
                // decimals (e.g. "1.5", "3.14") from scene-style separators
                // (e.g. "2024.1080").  Keep the dot only when at least one
                // side is a short (≤2 digit) number.
                let left_digits = (0..i)
                    .rev()
                    .take_while(|&j| chars[j].is_ascii_digit())
                    .count();
                let right_digits = (i + 1..len)
                    .take_while(|&j| chars[j].is_ascii_digit())
                    .count();
                if left_digits <= 2 || right_digits <= 2 {
                    result.push('.');
                } else {
                    result.push(' ');
                }
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
                if depth == 0 {
                    bracket_content.clear();
                } else {
                    bracket_content.push(c);
                }
                depth += 1;
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
                } else {
                    bracket_content.push(c);
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
    if depth > 0 {
        result.push('[');
        result.push_str(&bracket_content);
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
        let result = cleanup_filename("Song_-_Artist_[www.site.com].mp3", &default_cleanup());
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

    #[test]
    fn test_cascading_pattern_removal_matches_naive_fixpoint() {
        // Removing one match can make the chars on either side
        // adjacent, forming a *new* match — verify the stack-based
        // single pass still finds cascaded matches, e.g. "aa" applied
        // to "aaaa" must fully collapse (a naive single left-to-right
        // greedy scan without cascading would stop early and leave
        // "aa" remnants when the removal boundaries don't align this
        // way, e.g. patterns overlapping at odd offsets).
        let chars: Vec<char> = "aaaa".chars().collect();
        let result: String = remove_all_case_insensitive(&chars, "aa")
            .into_iter()
            .collect();
        assert_eq!(result, "");

        let chars: Vec<char> = "aabb".chars().collect();
        let result: String = remove_all_case_insensitive(&chars, "ab")
            .into_iter()
            .collect();
        assert_eq!(result, "");
    }

    #[test]
    fn test_many_repeated_patterns_still_fully_removed() {
        // Regression test for the O(N^2) blowup (C3): a filename
        // stuffed with thousands of repeated cleanup-pattern instances
        // used to make `cleanup_filename` quadratic in length. This
        // both checks correctness (every instance is still removed)
        // and, since the test suite has an overall timeout, implicitly
        // guards against the quadratic behaviour regressing.
        let stem = "www.".repeat(5000);
        let name = format!("{stem}real_title.mp3");
        let result = cleanup_filename(&name, &default_cleanup());
        assert!(!result.to_lowercase().contains("www"));
        assert!(result.contains("Real Title"));
    }

    #[test]
    fn test_strip_comment_urls_many_tokens() {
        // Many separate short URL-like tokens in a row — regression
        // test for the same O(N^2) blowup class in
        // `strip_comment_urls`.
        let mut comment = String::new();
        for i in 0..5000 {
            comment.push_str(&format!("www.spam{i}.com "));
        }
        comment.push_str("this part should survive");
        let result = strip_comment_urls(&comment);
        assert!(!result.to_lowercase().contains("www"));
        assert!(result.contains("this part should survive"));
    }
}
