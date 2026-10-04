//! `window-state.json`: where the main window sat when Ember last quit, so an
//! ordinary launch opens it there again. An update restart restores the
//! fuller session in `update-resume.json` instead.
//!
//! Like that file this is input, not instructions: it is validated on the way
//! in, and a position on a monitor that has since gone is not applied.

use std::path::Path;

use tauri::AppHandle;

use crate::auto_update::resume::{self, Visibility, WindowSnapshot};

pub const FILE: &str = "window-state.json";
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// Record the main window as it is now. Best-effort.
pub fn save(app: &AppHandle) {
    let dir = match crate::storage::paths::ensure_data_dir() {
        Ok(dir) => dir,
        Err(error) => {
            tracing::debug!("Not saving the window position: {error}");
            return;
        }
    };
    let snapshot = keep_known_bounds(resume::capture_window(app), load(&dir));
    match serde_json::to_vec(&snapshot) {
        Ok(bytes) => {
            if let Err(error) = crate::security::atomic_write(&dir.join(FILE), &bytes, true) {
                tracing::debug!("Not saving the window position: {error:#}");
            }
        }
        Err(error) => tracing::debug!("Not saving the window position: {error}"),
    }
}

/// A window quit while minimized reports no usable frame; the one it had when
/// last saved is still where it will be restored to. On Linux the same goes
/// for a window hidden in the tray, whose position GTK may report as 0,0.
fn keep_known_bounds(mut current: WindowSnapshot, previous: Option<WindowSnapshot>) -> WindowSnapshot {
    let unreliable = cfg!(target_os = "linux") && current.visibility == Visibility::Tray;
    if (current.bounds.is_none() || unreliable) && !current.maximized {
        if let Some(bounds) = previous.and_then(|previous| previous.bounds) {
            current.bounds = Some(bounds);
        }
    }
    current
}

/// The saved window, or `None` when there is none worth using.
pub fn load(dir: &Path) -> Option<WindowSnapshot> {
    let path = dir.join(FILE);
    let size = std::fs::metadata(&path).ok()?.len();
    if size > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    let snapshot: WindowSnapshot = serde_json::from_slice(&bytes).ok()?;
    Some(resume::sanitize_window(snapshot))
}

/// How the main window opens on a launch that is not resuming an update.
///
/// The saved geometry is kept but never how it was left: quitting from the tray
/// is not a request to start in it. Only a launch at sign-in with
/// `start_hidden` comes up there.
pub fn for_launch(
    saved: Option<WindowSnapshot>,
    launch_maximized: bool,
    start_hidden: bool,
) -> Option<WindowSnapshot> {
    if saved.is_none() && !start_hidden {
        return None;
    }
    let mut snapshot = saved.unwrap_or(WindowSnapshot {
        visibility: Visibility::Normal,
        maximized: false,
        bounds: None,
        maximized_center: None,
        chat_window_open: false,
    });
    snapshot.visibility = if start_hidden {
        Visibility::Tray
    } else {
        Visibility::Normal
    };
    snapshot.maximized |= launch_maximized;
    snapshot.chat_window_open = false;
    Some(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto_update::resume::Bounds;

    fn snapshot(visibility: Visibility, bounds: Option<Bounds>) -> WindowSnapshot {
        WindowSnapshot {
            visibility,
            maximized: false,
            bounds,
            maximized_center: None,
            chat_window_open: true,
        }
    }

    const BOUNDS: Bounds = Bounds {
        x: 40,
        y: 60,
        width: 1200,
        height: 800,
    };

    #[test]
    fn nothing_saved_opens_the_ordinary_way() {
        assert_eq!(for_launch(None, true, false), None);
    }

    #[test]
    fn a_window_quit_from_the_tray_opens_on_the_desktop() {
        let launch = for_launch(Some(snapshot(Visibility::Tray, Some(BOUNDS))), false, false)
            .expect("a saved window is used");
        assert_eq!(launch.visibility, Visibility::Normal);
        assert_eq!(launch.bounds, Some(BOUNDS));
        assert!(!launch.chat_window_open, "only an update restart reopens the chat");
    }

    #[test]
    fn a_hidden_sign_in_launch_goes_to_the_tray_with_or_without_a_saved_window() {
        let launch = for_launch(None, false, true).expect("hidden needs a snapshot");
        assert_eq!(launch.visibility, Visibility::Tray);

        let launch = for_launch(Some(snapshot(Visibility::Minimized, Some(BOUNDS))), true, true)
            .expect("a saved window is used");
        assert_eq!(launch.visibility, Visibility::Tray);
        assert!(launch.maximized, "launch maximized still applies");
    }

    #[test]
    fn a_minimized_quit_keeps_the_frame_from_before() {
        let previous = snapshot(Visibility::Normal, Some(BOUNDS));
        let kept = keep_known_bounds(snapshot(Visibility::Minimized, None), Some(previous.clone()));
        assert_eq!(kept.bounds, Some(BOUNDS));

        let mut maximized = snapshot(Visibility::Normal, None);
        maximized.maximized = true;
        assert_eq!(keep_known_bounds(maximized, Some(previous)).bounds, None);
    }

    #[test]
    fn an_implausible_file_is_not_applied() {
        let dir = std::env::temp_dir().join(format!("ember-window-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join(FILE), b"{not json").expect("write");
        assert_eq!(load(&dir), None);

        let mut wild = snapshot(Visibility::Normal, Some(BOUNDS));
        wild.bounds = Some(Bounds {
            width: 10,
            ..BOUNDS
        });
        std::fs::write(dir.join(FILE), serde_json::to_vec(&wild).expect("json")).expect("write");
        assert_eq!(load(&dir).expect("parsed").bounds, None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
