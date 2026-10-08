/// A random identifier the webview can hand back unchanged.
///
/// Tokens cross the IPC boundary as JSON numbers, and JavaScript has only
/// `f64` to receive them with: anything above 2^53-1 arrives rounded, so a
/// full-width `u64` comes back as a *different* number and never matches the
/// one that was issued. That failure is silent and total — every call looks
/// like an expired session or an unknown token.
///
/// 53 bits is still far more than enough to keep one session or prompt from
/// being mistaken for the next; these identify a live in-memory entry, they
/// are not secrets guarding anything.
pub(crate) fn js_safe_token() -> u64 {
    const JS_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
    rand::random::<u64>() & JS_MAX_SAFE_INTEGER
}

/// Longest native dialog title taken from the renderer.
const MAX_PICKER_TITLE_CHARS: usize = 120;

/// The title for a native file or folder picker: the renderer's translation,
/// or `fallback` when it sent none. Control characters are dropped and the
/// length capped, since whatever arrives is drawn in OS chrome.
pub(crate) fn picker_title(title: Option<String>, fallback: &str) -> String {
    title
        .map(|t| {
            t.chars()
                .filter(|c| !c.is_control())
                .take(MAX_PICKER_TITLE_CHARS)
                .collect::<String>()
                .trim()
                .to_string()
        })
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::{js_safe_token, picker_title};

    #[test]
    fn a_picker_title_falls_back_and_is_kept_to_plain_text() {
        assert_eq!(picker_title(None, "Choose"), "Choose");
        assert_eq!(picker_title(Some("   ".into()), "Choose"), "Choose");
        assert_eq!(picker_title(Some("Datei wählen".into()), "Choose"), "Datei wählen");
        assert_eq!(picker_title(Some("a\nb\u{7}c".into()), "Choose"), "abc");
        assert_eq!(picker_title(Some("x".repeat(500)), "Choose").chars().count(), 120);
    }

    /// The whole point of the helper, and a bound no future "more entropy"
    /// change can quietly raise: a token above this is corrupted in transit.
    #[test]
    fn tokens_survive_a_round_trip_through_a_javascript_number() {
        const JS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
        for _ in 0..10_000 {
            let token = js_safe_token();
            assert!(token <= JS_MAX_SAFE_INTEGER, "{token} is not representable");
            // What the webview would send back after parsing it as an f64.
            assert_eq!(token as f64 as u64, token);
        }
    }
}

pub mod backup;
pub mod channel_recovery;
pub mod channels;
pub mod chat_attachments;
pub mod chat_window;
pub mod collections;
pub mod comments;
pub mod deeplink;
pub mod emule_import;
pub mod errors;
pub mod peers;
pub mod preview;
pub mod search;
pub mod security;
pub mod server;
pub mod settings;
pub mod share_browser;
pub mod sharing;
pub mod speed_test;
pub mod statistics;
pub mod system;
pub mod transfers;
pub mod updater;
