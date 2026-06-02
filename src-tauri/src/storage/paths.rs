//! Centralized resolution of Ember's per-app data directory.
//!
//! Historically, call sites split state between
//! `directories::ProjectDirs::from("com", "ember", "p2p")` and Tauri's
//! `app.path().app_data_dir()`. On Windows those are different directories,
//! which made startup scans miss `known.met` and rehash shared files even
//! though the network task had saved a valid cache.
//!
//! This module funnels every resolution through a single check:
//!
//! 1. `EMBER_DATA_DIR` environment variable, if set and non-empty.
//! 2. `directories::ProjectDirs::from("com", "ember", "p2p")`.
//! 3. Final fallback to `std::env::temp_dir()`.
//!
//! `ensure_data_dir_with_app` also copies any files that only exist in the old
//! Tauri app-data directory into the canonical directory. We copy, rather than
//! move, so a failed migration never destroys user data.
//!
//! With the env var set, the harness can launch multiple Ember
//! processes that share no config, identity, database, downloads, or
//! logs but speak to the same local rendezvous server.

use std::path::{Path, PathBuf};

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

/// Resolve the data directory using the same policy as [`resolve_data_dir`].
///
/// The `AppHandle` is accepted for API compatibility with call sites that
/// already have one, but it intentionally does not affect the returned path.
/// This keeps frontend commands, startup tasks, and the network task on the
/// same on-disk state.
pub fn resolve_data_dir_with_app(_app: &tauri::AppHandle) -> PathBuf {
    resolve_data_dir()
}

/// Resolve the data directory. Used by helpers in `commands/`, the network
/// task during startup, the startup-scan worker in `lib.rs`, and any
/// `AppHandle`-owning call site via [`resolve_data_dir_with_app`].
pub fn resolve_data_dir() -> PathBuf {
    if let Some(p) = env_override() {
        return p;
    }
    project_dirs_fallback()
}

fn project_dirs_fallback() -> PathBuf {
    if let Some(d) = directories::ProjectDirs::from("com", "ember", "p2p") {
        return d.data_dir().to_path_buf();
    }
    // ProjectDirs only fails when no valid home directory can be determined.
    // Fall back to an explicit per-user location rather than a volatile temp
    // dir: the OS can purge temp between runs, which would silently drop the
    // user's identity, downloads DB, and .met state. Temp is the absolute
    // last resort, with a loud warning so the situation is diagnosable.
    #[cfg(target_os = "windows")]
    let base = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(target_os = "windows"))]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share"));
    if let Some(base) = base {
        if !base.as_os_str().is_empty() {
            return base.join("ember").join("p2p");
        }
    }
    tracing::error!(
        "Could not determine a stable data directory (no ProjectDirs / APPDATA / HOME); \
         falling back to a temp directory — data may NOT persist across runs"
    );
    std::env::temp_dir().join("ember-p2p")
}

/// Convenience: resolve and `create_dir_all` the canonical data directory.
///
/// In production, this also copies missing files from Tauri's legacy
/// `app_data_dir()` into the canonical `ProjectDirs` location. Harness runs
/// set `EMBER_DATA_DIR`, which skips this migration so isolated node
/// directories stay isolated.
pub fn ensure_data_dir_with_app(app: &tauri::AppHandle) -> std::io::Result<PathBuf> {
    let dir = resolve_data_dir();
    std::fs::create_dir_all(&dir)?;
    if env_override().is_none() {
        if let Ok(legacy) = app.path().app_data_dir() {
            migrate_legacy_app_data(&legacy, &dir)?;
        }
    }
    Ok(dir)
}

/// Convenience: resolve and `create_dir_all` the data directory without
/// a Tauri `AppHandle`.
pub fn ensure_data_dir() -> std::io::Result<PathBuf> {
    let dir = resolve_data_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn migrate_legacy_app_data(legacy: &Path, canonical: &Path) -> std::io::Result<()> {
    if paths_equivalent(legacy, canonical) || !legacy.exists() {
        return Ok(());
    }
    copy_missing_entries(legacy, canonical)
}

fn copy_missing_entries(src_dir: &Path, dst_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst_dir)?;
    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let src = entry.path();
        let dst = dst_dir.join(entry.file_name());
        let meta = entry.metadata()?;
        if dst.exists() {
            if meta.is_dir() && dst.is_dir() {
                copy_missing_entries(&src, &dst)?;
            }
            continue;
        }

        if meta.is_dir() {
            copy_missing_entries(&src, &dst)?;
        } else if meta.is_file() {
            std::fs::copy(&src, &dst)?;
            crate::security::restrict_file_permissions(&dst);
        }
    }
    Ok(())
}

fn paths_equivalent(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ if cfg!(target_os = "windows") => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
        _ => a == b,
    }
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

    #[test]
    fn copy_missing_entries_preserves_existing_destination_files() {
        let root = std::env::temp_dir().join(format!(
            "ember-paths-migration-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let legacy = root.join("legacy");
        let canonical = root.join("canonical");
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::create_dir_all(&canonical).unwrap();
        std::fs::write(legacy.join("config.json"), b"legacy").unwrap();
        std::fs::write(legacy.join("ember.db"), b"db").unwrap();
        std::fs::write(canonical.join("config.json"), b"canonical").unwrap();

        copy_missing_entries(&legacy, &canonical).unwrap();

        assert_eq!(
            std::fs::read(canonical.join("config.json")).unwrap(),
            b"canonical"
        );
        assert_eq!(std::fs::read(canonical.join("ember.db")).unwrap(), b"db");
        let _ = std::fs::remove_dir_all(root);
    }
}
