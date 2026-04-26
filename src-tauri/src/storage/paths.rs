//! Centralized resolution of Ember's per-app data directory.
//!
//! Historically, every call site re-derived the data directory using
//! either `directories::ProjectDirs::from("com", "ember", "p2p")` (in
//! contexts without a `tauri::AppHandle`) or `app.path().app_data_dir()`
//! (in command handlers). Both reach the same path in production, but
//! made it impossible to run multiple isolated Ember instances on a
//! single machine for harness / multi-node testing.
//!
//! This module funnels every resolution through a single check:
//!
//! 1. `EMBER_DATA_DIR` environment variable, if set and non-empty.
//! 2. The Tauri-provided `app_data_dir()` (when an `AppHandle` is on hand).
//! 3. `directories::ProjectDirs::from("com", "ember", "p2p")`.
//! 4. Final fallback to `std::env::temp_dir()`.
//!
//! With the env var set, the harness can launch multiple Ember
//! processes that share no config, identity, database, downloads, or
//! logs but speak to the same local rendezvous server.

use std::path::PathBuf;

use tauri::Manager;

/// Environment variable that overrides the resolved data directory for
/// every Ember subsystem (config, identity, database, sharing, network,
/// logs). When set to a non-empty path, the directory is created on
/// demand and used in place of the Tauri / ProjectDirs default.
pub const EMBER_DATA_DIR_ENV: &str = "EMBER_DATA_DIR";

/// Read the env override, returning `None` if the variable is unset or
/// empty. Whitespace-only values are also treated as unset; this
/// matches PowerShell's habit of leaving `$env:EMBER_DATA_DIR = ""` as
/// "" rather than removing the variable.
fn env_override() -> Option<PathBuf> {
    let raw = std::env::var(EMBER_DATA_DIR_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Resolve the data directory using a `tauri::AppHandle` when one is
/// available. Prefers the env override, then `app_data_dir()`, then
/// `ProjectDirs`, then `std::env::temp_dir()`. The returned path is
/// **not** created on disk; callers that need it materialised should
/// follow up with `std::fs::create_dir_all` (or use
/// [`ensure_data_dir_with_app`]).
pub fn resolve_data_dir_with_app(app: &tauri::AppHandle) -> PathBuf {
    if let Some(p) = env_override() {
        return p;
    }
    if let Ok(p) = app.path().app_data_dir() {
        return p;
    }
    project_dirs_fallback()
}

/// Resolve the data directory without a `tauri::AppHandle`. Same env-
/// override-first ordering as [`resolve_data_dir_with_app`], but
/// without the Tauri layer (used by helpers in `commands/` that don't
/// take an `AppHandle`, by the network task during startup, and by the
/// startup-scan worker in `lib.rs`).
pub fn resolve_data_dir() -> PathBuf {
    if let Some(p) = env_override() {
        return p;
    }
    project_dirs_fallback()
}

fn project_dirs_fallback() -> PathBuf {
    directories::ProjectDirs::from("com", "ember", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir)
}

/// Convenience: resolve and `create_dir_all` the data directory using a
/// Tauri `AppHandle`. Returns the resolved path on success.
pub fn ensure_data_dir_with_app(app: &tauri::AppHandle) -> std::io::Result<PathBuf> {
    let dir = resolve_data_dir_with_app(app);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Convenience: resolve and `create_dir_all` the data directory without
/// a Tauri `AppHandle`.
pub fn ensure_data_dir() -> std::io::Result<PathBuf> {
    let dir = resolve_data_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `env_override` must respect the `EMBER_DATA_DIR_ENV` constant by
    /// name — that's what every documented harness invocation references.
    /// Set the variable, snapshot the resolved path, and ensure
    /// downstream callers see the override.
    #[test]
    fn env_override_takes_priority_when_set() {
        let original = std::env::var(EMBER_DATA_DIR_ENV).ok();

        let tmp = std::env::temp_dir().join("ember-paths-test-override");
        std::env::set_var(EMBER_DATA_DIR_ENV, &tmp);
        assert_eq!(resolve_data_dir(), tmp);

        match original {
            Some(v) => std::env::set_var(EMBER_DATA_DIR_ENV, v),
            None => std::env::remove_var(EMBER_DATA_DIR_ENV),
        }
    }

    #[test]
    fn empty_env_value_is_treated_as_unset() {
        let original = std::env::var(EMBER_DATA_DIR_ENV).ok();

        std::env::set_var(EMBER_DATA_DIR_ENV, "   ");
        let resolved = resolve_data_dir();
        assert_ne!(resolved, PathBuf::from("   "));
        assert!(!resolved.as_os_str().is_empty());

        match original {
            Some(v) => std::env::set_var(EMBER_DATA_DIR_ENV, v),
            None => std::env::remove_var(EMBER_DATA_DIR_ENV),
        }
    }
}
