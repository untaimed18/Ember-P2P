//! Starting Ember when the user signs in: a per-user `Run` value on Windows, a
//! Launch Agent on macOS, an XDG autostart entry on Linux (pointing at the
//! AppImage when run from one).
//!
//! `auto-launch` directly rather than `tauri-plugin-autostart`, which cannot be
//! told to stay per-user (run elevated, it registers in `HKLM` and starts Ember
//! for everyone on the machine) and writes the executable path unquoted into
//! command lines that split on spaces.

use auto_launch::{AutoLaunch, AutoLaunchBuilder};
use tauri::AppHandle;
#[cfg(target_os = "linux")]
use tauri::Manager;

/// Passed by the OS entry, so a launch at sign-in can be told apart.
pub const AUTOSTART_ARG: &str = "--autostart";

pub fn launched_at_login() -> bool {
    std::env::args().skip(1).any(|arg| arg == AUTOSTART_ARG)
}

fn launcher(app: &AppHandle) -> Result<AutoLaunch, String> {
    let exe = std::env::current_exe().map_err(|error| error.to_string())?;
    #[cfg(target_os = "linux")]
    let exe = app
        .env()
        .appimage
        .map(std::path::PathBuf::from)
        .unwrap_or(exe);
    #[cfg(target_os = "macos")]
    let exe = exe.canonicalize().unwrap_or(exe);
    let path = exe
        .to_str()
        .ok_or_else(|| "the executable path is not valid Unicode".to_string())?;

    let mut builder = AutoLaunchBuilder::new();
    builder
        .set_app_name(&app.package_info().name)
        .set_app_path(&command_path(path))
        .set_args(&[AUTOSTART_ARG]);
    #[cfg(windows)]
    builder.set_windows_enable_mode(auto_launch::WindowsEnableMode::CurrentUser);
    #[cfg(target_os = "macos")]
    builder.set_macos_launch_mode(auto_launch::MacOSLaunchMode::LaunchAgent);
    builder.build().map_err(|error| error.to_string())
}

/// `path` as the first word of the command line the OS entry holds.
///
/// A Windows `Run` value and an XDG `Exec=` line are both parsed as command
/// lines, so an unquoted `C:\Users\Jane Doe\...` names `C:\Users\Jane`. A
/// Launch Agent takes an argument array and needs nothing.
fn command_path(path: &str) -> String {
    if cfg!(windows) {
        // A Windows path cannot contain `"`.
        format!("\"{path}\"")
    } else if cfg!(target_os = "linux") {
        xdg_quoted(path)
    } else {
        path.to_string()
    }
}

/// Quote an argument for a desktop entry's `Exec` key. Inside the quotes `"`,
/// `` ` ``, `$` and `\` take a backslash, and the value's own string escaping
/// then doubles every backslash; `%` is a field code unless doubled.
fn xdg_quoted(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    for c in arg.chars() {
        match c {
            '\\' => out.push_str("\\\\\\\\"),
            '"' | '`' | '$' => {
                out.push_str("\\\\");
                out.push(c);
            }
            '%' => out.push_str("%%"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Register or remove the OS entry. Registering also clears a Task Manager
/// "Disabled" on Windows, which is what an explicit switch-on asks for.
pub fn apply(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let launcher = launcher(app)?;
    let result = if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    };
    result.map_err(|error| error.to_string())
}

/// Remove an entry left behind while the setting is off, off the main thread.
///
/// Only that direction. Re-registering at every launch would override the user
/// turning Ember off in Task Manager or their desktop's startup settings, and
/// those are as much their choice as this setting is.
///
/// Not for debug builds or harness nodes, which must not touch the user's real
/// sign-in entry.
pub fn reconcile_at_launch(app: &AppHandle, enabled: bool) {
    let harness = std::env::var(crate::storage::paths::EMBER_DATA_DIR_ENV)
        .is_ok_and(|value| !value.trim().is_empty());
    if enabled || cfg!(debug_assertions) || harness {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let stale = launcher(&app).and_then(|launcher| {
            if launcher.is_enabled().unwrap_or(false) {
                launcher.disable().map_err(|error| error.to_string())
            } else {
                Ok(())
            }
        });
        if let Err(error) = stale {
            tracing::warn!("Could not remove the launch-at-sign-in entry: {error}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_desktop_entry_path_survives_spaces_and_reserved_characters() {
        assert_eq!(xdg_quoted("/home/jane doe/Ember.AppImage"), "\"/home/jane doe/Ember.AppImage\"");
        assert_eq!(xdg_quoted("/opt/100%/a$b"), "\"/opt/100%%/a\\\\$b\"");
        assert_eq!(xdg_quoted("/x\\y\"z"), "\"/x\\\\\\\\y\\\\\"z\"");
    }

    #[cfg(windows)]
    #[test]
    fn a_run_value_quotes_the_executable() {
        assert_eq!(
            command_path(r"C:\Users\Jane Doe\AppData\Local\Ember\ember.exe"),
            r#""C:\Users\Jane Doe\AppData\Local\Ember\ember.exe""#
        );
    }
}
