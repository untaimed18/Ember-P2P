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

#[cfg(test)]
mod tests {
    use super::js_safe_token;

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
pub mod channels;
pub mod chat_attachments;
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
