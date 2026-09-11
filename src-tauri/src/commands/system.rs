//! Desktop notifications and the runtime status the clock-driven features
//! publish.
//!
//! ## Why the text comes from the frontend
//!
//! Every notification names something only the renderer knows how to say: a
//! friend's nickname, a room's name, a message preview, a file name — wrapped
//! in one of nine locales that the backend has no handle on (the active locale
//! lives in the webview, in `localStorage`, via Paraglide). So the renderer
//! composes the title and body and this command performs the OS call.
//!
//! That makes this an IPC surface that renders attacker-influenced text on the
//! desktop, outside the webview's CSP, so it does not trust its arguments:
//! every string is stripped of control and direction-override characters and
//! truncated, the master switch is re-read from the authoritative config
//! rather than taken on the caller's word, and the whole command is rate
//! limited. The per-event switches stay in the renderer, where the context
//! needed to apply them already is.

use std::sync::atomic::{AtomicU64, Ordering};

use tauri_plugin_notification::NotificationExt;

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::types::RuntimeStatus;

/// Ceiling on a notification title, in characters.
const MAX_TITLE_CHARS: usize = 120;
/// Ceiling on a notification body, in characters. Every desktop shell
/// truncates well before this; the cap exists so a hostile peer cannot hand us
/// a megabyte to copy through IPC and into the shell.
const MAX_BODY_CHARS: usize = 400;

/// Burst allowance, and how fast it refills. Five at once covers a legitimate
/// flurry — three downloads finishing as a friend comes online — and one every
/// three seconds thereafter is far below what a person can read, so anything
/// hitting this ceiling is a loop rather than a user's day.
const NOTIFY_BURST: u64 = 5;
const NOTIFY_REFILL_MILLIS: u64 = 3_000;

/// Rate-limiter state, encoded as two atomics so the check needs no lock.
/// `tokens` is in thousandths of a token to keep the refill arithmetic in
/// integers.
static NOTIFY_TOKENS_MILLI: AtomicU64 = AtomicU64::new(NOTIFY_BURST * 1_000);
static NOTIFY_LAST_REFILL_MILLIS: AtomicU64 = AtomicU64::new(0);

fn monotonic_millis() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Whether a notification may be shown now, spending a token if so.
///
/// Single-threaded in practice (one webview), so a compare-exchange loop would
/// buy nothing: a lost race costs at most one extra notification, which is
/// three orders of magnitude away from the abuse this bounds.
fn take_notify_token() -> bool {
    let now = monotonic_millis();
    let last = NOTIFY_LAST_REFILL_MILLIS.swap(now, Ordering::Relaxed);
    let elapsed = now.saturating_sub(last);
    let refilled = elapsed.saturating_mul(1_000) / NOTIFY_REFILL_MILLIS;
    let ceiling = NOTIFY_BURST * 1_000;

    let current = NOTIFY_TOKENS_MILLI.load(Ordering::Relaxed);
    let available = current.saturating_add(refilled).min(ceiling);
    if available < 1_000 {
        NOTIFY_TOKENS_MILLI.store(available, Ordering::Relaxed);
        return false;
    }
    NOTIFY_TOKENS_MILLI.store(available - 1_000, Ordering::Relaxed);
    true
}

/// Collapse a renderer-supplied string into something safe to hand a desktop
/// shell.
///
/// Newlines are folded to spaces rather than dropped: a body is a single line
/// in most shells, and a message preview carrying `\n` would otherwise let a
/// peer forge what looks like a second field. Control characters and the bidi
/// overrides go entirely — the same set `coded_ctx` strips, and for the same
/// reason: a right-to-left override in a file name can make a notification read
/// as text nobody sent.
fn sanitize(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars * 4));
    let mut chars = 0usize;
    let mut truncated = false;
    for ch in raw.chars() {
        let ch = if ch == '\n' || ch == '\r' || ch == '\t' {
            ' '
        } else {
            ch
        };
        if ch.is_control() || crate::security::is_invisible_or_bidi_control_pub(ch) {
            continue;
        }
        if chars >= max_chars {
            truncated = true;
            break;
        }
        out.push(ch);
        chars += 1;
    }
    // Collapse the runs the newline folding above can create, so a preview does
    // not arrive as a line of spaces.
    let mut collapsed = String::with_capacity(out.len());
    let mut last_was_space = false;
    for ch in out.chars() {
        if ch == ' ' {
            if !last_was_space {
                collapsed.push(ch);
            }
            last_was_space = true;
        } else {
            collapsed.push(ch);
            last_was_space = false;
        }
    }
    let mut trimmed = collapsed.trim().to_string();
    if truncated && !trimmed.is_empty() {
        trimmed.push('\u{2026}');
    }
    trimmed
}

/// Show a desktop notification.
///
/// `force` is set only by the "Send a test notification" button in Settings, so
/// a user who has just switched notifications on can confirm the OS will
/// actually show them without saving first. It skips the persisted master
/// switch and nothing else: sanitization and the rate limit still apply.
#[tauri::command]
pub async fn show_notification(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    title: String,
    body: String,
    force: Option<bool>,
) -> Result<(), String> {
    let force = force.unwrap_or(false);
    if !force {
        // Authoritative, not the caller's claim: a Settings save that switches
        // notifications off must silence a renderer whose cached copy of the
        // settings has not caught up yet.
        let enabled = state.config.read().await.settings.notifications_enabled;
        if !enabled {
            return Ok(());
        }
    }

    let title = sanitize(&title, MAX_TITLE_CHARS);
    let body = sanitize(&body, MAX_BODY_CHARS);
    if title.is_empty() {
        return Err(coded(
            "notification_empty_title",
            "A notification needs a title",
        ));
    }
    if !take_notify_token() {
        return Err(coded(
            "notification_rate_limited",
            "Too many notifications at once; try again shortly",
        ));
    }

    let mut builder = app.notification().builder().title(title);
    if !body.is_empty() {
        builder = builder.body(body);
    }
    builder.show().map_err(|error| {
        coded_ctx(
            "notification_show_failed",
            "The system would not show the notification",
            error,
        )
    })
}

/// Snapshot of the schedule window in force and whether sleep is being
/// deferred. Paired with the `ember:runtime-status` event, which carries the
/// same shape whenever it changes.
#[tauri::command]
pub async fn get_runtime_status(
    state: tauri::State<'_, AppState>,
) -> Result<RuntimeStatus, String> {
    Ok(crate::background::snapshot(&state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_folds_newlines_and_collapses_the_runs() {
        assert_eq!(sanitize("hello\nworld", 100), "hello world");
        assert_eq!(sanitize("a\r\n\tb", 100), "a b");
        assert_eq!(sanitize("  padded  ", 100), "padded");
    }

    /// A right-to-left override in a peer-supplied file name can make
    /// `report.txt` render as something else entirely. The notification is
    /// drawn by the shell, outside anything the webview sanitizes.
    #[test]
    fn sanitize_strips_direction_overrides_and_zero_width_characters() {
        let hostile = "invoice\u{202E}gnp.exe\u{200B}";
        let cleaned = sanitize(hostile, 100);
        assert_eq!(cleaned, "invoicegnp.exe");
        assert!(!cleaned.contains('\u{202E}'));
        assert!(!cleaned.contains('\u{200B}'));
    }

    #[test]
    fn sanitize_truncates_by_characters_and_marks_it() {
        let long = "a".repeat(MAX_BODY_CHARS + 50);
        let cleaned = sanitize(&long, MAX_BODY_CHARS);
        assert_eq!(cleaned.chars().count(), MAX_BODY_CHARS + 1, "cap plus the ellipsis");
        assert!(cleaned.ends_with('\u{2026}'));

        // Multi-byte text gets the same character budget, not a third of it.
        let cjk = "夜".repeat(MAX_BODY_CHARS + 10);
        assert_eq!(
            sanitize(&cjk, MAX_BODY_CHARS).chars().count(),
            MAX_BODY_CHARS + 1
        );
    }

    /// A string that is nothing but stripped characters has to come out empty
    /// so the caller's "is the title blank?" check still fires.
    #[test]
    fn sanitize_reduces_invisible_only_input_to_nothing() {
        assert_eq!(sanitize("\u{200B}\u{202E}\u{0007}", 100), "");
        assert!(sanitize("", 100).is_empty());
    }

    /// The limiter has to allow a real flurry and then stop a loop. Runs
    /// against the process-wide statics, so it resets them first and is the
    /// only test that touches them.
    #[test]
    fn the_rate_limiter_allows_a_burst_then_throttles() {
        NOTIFY_TOKENS_MILLI.store(NOTIFY_BURST * 1_000, Ordering::Relaxed);
        NOTIFY_LAST_REFILL_MILLIS.store(monotonic_millis(), Ordering::Relaxed);

        for n in 0..NOTIFY_BURST {
            assert!(take_notify_token(), "burst notification {n} must be allowed");
        }
        assert!(
            !take_notify_token(),
            "a caller past the burst must be throttled"
        );
    }
}
