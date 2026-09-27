//! The chat, popped out of the main window's dock into a window of its own.
//!
//! The chat window loads the same app as the main window; the frontend reads
//! its label and draws only the chat. It is created here rather than from the
//! renderer so the webview never needs the permission to create windows, and
//! so the window it asks for can only ever be this one, with this label.
//!
//! Its X docks the chat back into the main window rather than closing it
//! outright: the close is held, the chat window is asked to hand its drafts
//! and active conversation back ([`CHAT_WINDOW_REDOCK_EVENT`]), and it then
//! destroys itself. It never quits Ember — the close-to-tray handling in
//! `lib.rs` is for the main window alone.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};

use crate::commands::errors::{coded, coded_ctx};

pub const CHAT_WINDOW_LABEL: &str = "chat";
/// Emitted when the chat window is gone, however it went, so the main window
/// stops treating conversations as being read in it — and docks the chat back
/// if the window went without saying so.
pub const CHAT_WINDOW_CLOSED_EVENT: &str = "ember:chat-window-closed";
/// Sent to the chat window when its X is pressed: dock back, then close.
pub const CHAT_WINDOW_REDOCK_EVENT: &str = "ember:chat-window-redock";
/// How long a chat window that was asked to dock back has to do it before it
/// is closed anyway. A hung webview must not leave a window that cannot close.
const REDOCK_GRACE: Duration = Duration::from_millis(1_500);

/// Bumped for every chat window opened, so a grace timer started for one
/// window cannot close the next one opened in the meantime.
static WINDOW_GENERATION: AtomicU64 = AtomicU64::new(0);

const DEFAULT_WIDTH: f64 = 440.0;
const DEFAULT_HEIGHT: f64 = 640.0;
const MIN_WIDTH: f64 = 340.0;
const MIN_HEIGHT: f64 = 420.0;
/// Far past any real monitor; bounds larger than this are a corrupt setting.
const MAX_EXTENT: f64 = 16_384.0;
const MAX_TITLE_CHARS: usize = 80;

/// Where the chat window was last left, in logical pixels, as the renderer
/// remembered it.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ChatWindowBounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl ChatWindowBounds {
    fn is_sane(&self) -> bool {
        [self.x, self.y, self.width, self.height]
            .iter()
            .all(|v| v.is_finite() && v.abs() <= MAX_EXTENT)
            && self.width >= MIN_WIDTH
            && self.height >= MIN_HEIGHT
    }
}

/// Whether a window at `bounds` would have its title bar on a monitor that is
/// still attached. A window restored onto a monitor that was unplugged since
/// opens where nobody can see it, and cannot be dragged back.
fn title_bar_on_screen(bounds: &ChatWindowBounds, monitors: &[tauri::Monitor]) -> bool {
    let grab_x = bounds.x + bounds.width.min(240.0) / 2.0;
    let grab_y = bounds.y + 12.0;
    monitors.iter().any(|monitor| {
        let scale = monitor.scale_factor();
        let area = monitor.work_area();
        let left = f64::from(area.position.x) / scale;
        let top = f64::from(area.position.y) / scale;
        let right = left + f64::from(area.size.width) / scale;
        let bottom = top + f64::from(area.size.height) / scale;
        grab_x >= left && grab_x < right && grab_y >= top && grab_y < bottom
    })
}

fn bring_forward(window: &tauri::WebviewWindow) {
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
}

/// Open the chat window, or bring it forward if it is already open.
#[tauri::command]
pub async fn open_chat_window(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    title: String,
    bounds: Option<ChatWindowBounds>,
) -> Result<(), String> {
    if window.label() != "main" {
        return Err(coded(
            "chat_window_wrong_window",
            "The chat window can only be opened from the main window",
        ));
    }
    if let Some(existing) = app.get_webview_window(CHAT_WINDOW_LABEL) {
        bring_forward(&existing);
        return Ok(());
    }

    let title = crate::commands::system::sanitize(&title, MAX_TITLE_CHARS);
    let title = if title.trim().is_empty() { "Ember".to_string() } else { title };
    let monitors = app.available_monitors().unwrap_or_default();
    let restore = bounds.filter(|b| b.is_sane() && title_bar_on_screen(b, &monitors));

    let mut builder = WebviewWindowBuilder::new(&app, CHAT_WINDOW_LABEL, WebviewUrl::default())
        .title(title)
        .min_inner_size(MIN_WIDTH, MIN_HEIGHT)
        .zoom_hotkeys_enabled(true);
    builder = match restore {
        Some(b) => builder.inner_size(b.width, b.height).position(b.x, b.y),
        None => builder.inner_size(DEFAULT_WIDTH, DEFAULT_HEIGHT).center(),
    };
    let created = builder.build().map_err(|error| {
        coded_ctx("chat_window_open_failed", "Could not open the chat window", error)
    })?;
    WINDOW_GENERATION.fetch_add(1, Ordering::AcqRel);
    bring_forward(&created);
    Ok(())
}

/// The chat window's X was pressed and its close held. Ask it to dock back —
/// which ends in [`close_chat_window`] — and close it regardless once
/// [`REDOCK_GRACE`] has passed; the main window then docks the chat back from
/// [`CHAT_WINDOW_CLOSED_EVENT`] with whatever drafts it last heard about.
pub fn request_redock(window: &tauri::Window) {
    let app = window.app_handle().clone();
    if app.emit_to(CHAT_WINDOW_LABEL, CHAT_WINDOW_REDOCK_EVENT, ()).is_err() {
        let _ = window.destroy();
        return;
    }
    let generation = WINDOW_GENERATION.load(Ordering::Acquire);
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(REDOCK_GRACE).await;
        if WINDOW_GENERATION.load(Ordering::Acquire) != generation {
            return;
        }
        if let Some(chat) = app.get_webview_window(CHAT_WINDOW_LABEL) {
            let _ = chat.destroy();
        }
    });
}

/// Hide the chat window with the main one when Ember goes to the tray, and
/// bring it back with it. Left on screen alone it would be Ember with no way
/// back to the rest of it.
pub fn set_chat_window_visible(app: &tauri::AppHandle, visible: bool) {
    if let Some(chat) = app.get_webview_window(CHAT_WINDOW_LABEL) {
        let _ = if visible { chat.show() } else { chat.hide() };
    }
}

/// Close the chat window, once the chat is docked back. Destroys rather than
/// closes: a close would come back through the X's redock handling.
#[tauri::command]
pub async fn close_chat_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(chat) = app.get_webview_window(CHAT_WINDOW_LABEL) {
        chat.destroy().map_err(|error| {
            coded_ctx("chat_window_close_failed", "Could not close the chat window", error)
        })?;
    }
    Ok(())
}

/// Bring the main window to the front, for the chat window's links into it
/// (the Friends page, docking back). The renderer cannot focus another window
/// itself without a capability that would let it focus any of them.
#[tauri::command]
pub async fn focus_main_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(main) = app.get_webview_window("main") {
        bring_forward(&main);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds_below_the_minimum_or_absurdly_large_are_rejected() {
        let ok = ChatWindowBounds { x: 10.0, y: 10.0, width: 400.0, height: 600.0 };
        assert!(ok.is_sane());
        assert!(!ChatWindowBounds { width: 100.0, ..ok }.is_sane());
        assert!(!ChatWindowBounds { height: 100.0, ..ok }.is_sane());
        assert!(!ChatWindowBounds { x: f64::NAN, ..ok }.is_sane());
        assert!(!ChatWindowBounds { width: 1e9, ..ok }.is_sane());
    }

    #[test]
    fn no_monitors_means_nowhere_to_restore_to() {
        let b = ChatWindowBounds { x: 10.0, y: 10.0, width: 400.0, height: 600.0 };
        assert!(!title_bar_on_screen(&b, &[]));
    }
}
