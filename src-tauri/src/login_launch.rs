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

/// Debug builds and harness nodes must not touch the user's real sign-in
/// entry: it would point at `target\debug`, or at a test node's data.
fn touches_nothing() -> bool {
    cfg!(debug_assertions)
        || std::env::var(crate::storage::paths::EMBER_DATA_DIR_ENV)
            .is_ok_and(|value| !value.trim().is_empty())
}

/// Register or remove the OS entry. Registering also clears a Task Manager
/// "Disabled" on Windows, which is what an explicit switch-on asks for.
pub fn apply(app: &AppHandle, enabled: bool) -> Result<(), String> {
    if touches_nothing() {
        tracing::info!("Not changing the launch-at-sign-in entry from a debug build or harness node");
        return Ok(());
    }
    let launcher = launcher(app)?;
    let result = if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    };
    result.map_err(|error| error.to_string())
}

/// Bring the OS entry in line with the setting at launch, off the main thread.
///
/// With the setting off, an entry left behind is removed. With it on, only an
/// entry that is gone altogether is written again — on Windows, where a
/// reinstall's uninstall step deletes the `Run` value while the setting stays
/// on. One the user turned off in Task Manager keeps its value and is left
/// alone, as is anything their desktop's startup settings did elsewhere: those
/// are as much their choice as this setting is.
///
/// Not for debug builds or harness nodes, which must not touch the user's real
/// sign-in entry.
pub fn reconcile_at_launch(app: &AppHandle, enabled: bool) {
    if touches_nothing() || (enabled && !cfg!(windows)) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let result = launcher(&app).and_then(|launcher| {
            if enabled {
                restore_missing_entry(&app, &launcher)
            } else if launcher.is_enabled().unwrap_or(false) {
                launcher.disable().map_err(|error| error.to_string())
            } else {
                Ok(())
            }
        });
        if let Err(error) = result {
            tracing::warn!("Could not reconcile the launch-at-sign-in entry: {error}");
        }
    });
}

#[cfg(windows)]
fn restore_missing_entry(app: &AppHandle, launcher: &AutoLaunch) -> Result<(), String> {
    if run_value_present(&app.package_info().name)? {
        return Ok(());
    }
    tracing::info!("Launch at sign-in is on but its Run entry is gone; registering it again");
    launcher.enable().map_err(|error| error.to_string())
}

#[cfg(not(windows))]
fn restore_missing_entry(_app: &AppHandle, _launcher: &AutoLaunch) -> Result<(), String> {
    Ok(())
}

/// Whether the per-user `Run` key holds a value named `name`, whatever it says.
#[cfg(windows)]
fn run_value_present(name: &str) -> Result<bool, String> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_ANY};

    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let subkey = wide(r"Software\Microsoft\Windows\CurrentVersion\Run");
    let value = wide(name);
    // SAFETY: both strings are NUL-terminated and outlive the call, and with
    // every out-pointer null the call only reports whether the value exists.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_ANY,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    match status {
        ERROR_SUCCESS => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        other => Err(format!("reading the Run key failed with error {other}")),
    }
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
