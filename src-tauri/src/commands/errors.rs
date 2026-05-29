//! Structured, translatable command errors.
//!
//! Tauri commands return `Result<T, String>`; an `Err` string is delivered
//! to the frontend verbatim. Historically those strings were hardcoded
//! English, which made them impossible to localize. Instead of changing
//! every command's signature to a custom error type, we encode a small
//! JSON envelope into the error `String`:
//!
//! ```json
//! { "__coded": true, "code": "server_ip_required", "context": "…optional…" }
//! ```
//!
//! The frontend (`src/lib/errors.ts`) detects the `__coded` sentinel,
//! maps `code` to a Paraglide message key (`m.error_<code>()`), and
//! interpolates `context` when present. Anything that isn't a coded
//! envelope is shown as-is, so untouched/foreign error strings still
//! surface their original text.
//!
//! Keep `code` values stable: they are the contract with the frontend
//! message catalog. Use snake_case matching the `error_<code>` key.

use serde::Serialize;

#[derive(Serialize)]
struct CodedError {
    /// Sentinel so the frontend can distinguish our envelopes from
    /// arbitrary error strings that merely happen to be valid JSON.
    __coded: bool,
    code: &'static str,
    /// English fallback. Shown if the frontend has no key for `code`
    /// (e.g. an older UI build against a newer backend), so we never
    /// regress to a blank or opaque error.
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

/// Build a coded error with no dynamic context.
///
/// `code` is the stable machine code (snake_case, matches the
/// `error_<code>` message key). `message` is the English fallback.
pub fn coded(code: &'static str, message: impl Into<String>) -> String {
    serde_json::to_string(&CodedError {
        __coded: true,
        code,
        message: message.into(),
        context: None,
    })
    // Serialization of this fixed shape cannot fail in practice; fall
    // back to the bare message so an error is never swallowed.
    .unwrap_or_else(|_| code.to_string())
}

/// Build a coded error that carries dynamic detail (e.g. the
/// `Display` of an underlying error). The frontend interpolates
/// `context` into the translated framing via `{context}`.
pub fn coded_ctx(
    code: &'static str,
    message: impl Into<String>,
    context: impl std::fmt::Display,
) -> String {
    serde_json::to_string(&CodedError {
        __coded: true,
        code,
        message: message.into(),
        context: Some(context.to_string()),
    })
    .unwrap_or_else(|_| code.to_string())
}
