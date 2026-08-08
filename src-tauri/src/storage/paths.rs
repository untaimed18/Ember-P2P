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
use std::sync::atomic::{AtomicU64, Ordering};

use tauri::Manager;

/// Environment variable that overrides the resolved data directory for
/// every Ember subsystem (config, identity, database, sharing, network,
/// logs). When set to a non-empty path, the directory is created on
/// demand and used in place of the Tauri / ProjectDirs default.
pub const EMBER_DATA_DIR_ENV: &str = "EMBER_DATA_DIR";
static MIGRATION_COPY_SEQ: AtomicU64 = AtomicU64::new(0);

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
    let legacy_meta = std::fs::symlink_metadata(legacy)?;
    if metadata_is_link_or_reparse(&legacy_meta) {
        tracing::warn!(
            "Skipping legacy data migration from symlink/reparse-point root {}",
            legacy.display()
        );
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
        // Do not let a symlink/junction inside the legacy tree escape that
        // tree during recursive migration. `DirEntry::metadata()` follows
        // links; `symlink_metadata()` plus the Windows reparse bit does not.
        let meta = std::fs::symlink_metadata(&src)?;
        if metadata_is_link_or_reparse(&meta) {
            tracing::warn!(
                "Skipping symlink/reparse point during legacy migration: {}",
                src.display()
            );
            continue;
        }
        if dst.exists() {
            let dst_meta = std::fs::symlink_metadata(&dst)?;
            if metadata_is_link_or_reparse(&dst_meta) {
                tracing::warn!(
                    "Skipping legacy migration destination symlink/reparse point: {}",
                    dst.display()
                );
            } else if meta.is_dir() && dst_meta.is_dir() {
                copy_missing_entries(&src, &dst)?;
            } else if meta.is_file() && dst_meta.is_file() {
                let source_is_newer = meta
                    .modified()
                    .ok()
                    .zip(dst_meta.modified().ok())
                    .is_some_and(|(source, target)| source > target);
                // Freshness, not size, decides which nonempty copy wins. A
                // newer compacted DB/config is legitimately smaller than its
                // stale canonical predecessor and must still migrate.
                if meta.len() > 0 && (dst_meta.len() == 0 || source_is_newer) {
                    replace_stale_migration_file(&src, &dst, meta.len())?;
                }
            }
            continue;
        }

        if meta.is_dir() {
            copy_missing_entries(&src, &dst)?;
        } else if meta.is_file() {
            copy_file_atomically(&src, &dst, meta.len())?;
        }
    }
    Ok(())
}

fn replace_stale_migration_file(src: &Path, dst: &Path, expected_len: u64) -> std::io::Result<()> {
    let seq = MIGRATION_COPY_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = dst
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "file".into());
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let mut backup = parent.join(format!(".{file_name}.{pid}.{seq}.pre-migration.bak"));
    let mut collision = 0u32;
    while backup.exists() {
        collision = collision.saturating_add(1);
        backup = parent.join(format!(
            ".{file_name}.{pid}.{seq}.{collision}.pre-migration.bak"
        ));
    }
    std::fs::rename(dst, &backup)?;
    match copy_file_atomically(src, dst, expected_len) {
        Ok(()) => {
            tracing::warn!(
                "Replaced stale canonical data file {} with newer legacy copy; previous file preserved at {}",
                dst.display(),
                backup.display()
            );
            Ok(())
        }
        Err(error) => match std::fs::rename(&backup, dst) {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(std::io::Error::new(
                error.kind(),
                format!(
                    "{error}; rollback failed ({rollback_error}); canonical backup remains at {}",
                    backup.display()
                ),
            )),
        },
    }
}

fn copy_file_atomically(src: &Path, dst: &Path, expected_len: u64) -> std::io::Result<()> {
    use std::io::{Read, Write};

    let seq = MIGRATION_COPY_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let file_name = dst
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "file".into());
    let tmp = dst
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".{file_name}.{pid}.{seq}.migration-tmp"));

    let result = (|| {
        let mut source = std::fs::File::open(src)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const GENERIC_WRITE: u32 = 0x4000_0000;
            // WRITE_DAC must be requested when the handle is opened; the ACL
            // restriction below cannot rewrite a DACL through a handle that was
            // not granted it, and GENERIC_WRITE does not imply it.
            const WRITE_DAC: u32 = 0x0004_0000;
            options.access_mode(GENERIC_WRITE | WRITE_DAC);
        }
        let mut target = options.open(&tmp)?;
        // This copies identity.json, chat-history.key and cryptkey.dat for
        // upgrading users, so the secret must never exist on disk under
        // inherited access — restrict the open handle before the first byte is
        // written, and fail the migration if that cannot be done rather than
        // logging a warning and publishing the copy anyway. Same contract as
        // `security::atomic_write`.
        crate::security::restrict_open_file_permissions_checked(&target, false)?;
        let copied = std::io::copy(&mut source, &mut target)?;
        target.flush()?;
        target.sync_all()?;
        if copied != expected_len || source.metadata()?.len() != expected_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "legacy migration source changed while copying {}",
                    src.display()
                ),
            ));
        }
        // Read one byte at EOF to make the completed stream check explicit.
        let mut trailing = [0u8; 1];
        if source.read(&mut trailing)? != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "legacy migration copied an unstable source",
            ));
        }
        drop(target);
        std::fs::rename(&tmp, dst)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn paths_equivalent(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ if cfg!(target_os = "windows") => {
            normalize_windows_path_alias(a) == normalize_windows_path_alias(b)
        }
        _ => a == b,
    }
}

fn normalize_windows_path_alias(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('/', "\\");
    let normalized = normalized
        .strip_prefix(r"\\?\UNC\")
        .map(|rest| format!(r"\\{rest}"))
        .or_else(|| normalized.strip_prefix(r"\\?\").map(str::to_string))
        .unwrap_or(normalized);
    normalized.trim_end_matches('\\').to_ascii_lowercase()
}

fn metadata_is_link_or_reparse(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }
    #[cfg(not(target_os = "windows"))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes tests that mutate the process-global `EMBER_DATA_DIR_ENV`.
    /// Cargo runs tests on parallel threads in one process, so without this a
    /// second test's `set_var`/`remove_var` can clobber the variable between
    /// another test's own `set_var` and its `resolve_data_dir()` read, making
    /// the assertion fail nondeterministically. Recover from poisoning so one
    /// failing test doesn't cascade into the other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// `env_override` must respect the `EMBER_DATA_DIR_ENV` constant by
    /// name — that's what every documented harness invocation references.
    /// Set the variable, snapshot the resolved path, and ensure
    /// downstream callers see the override.
    #[test]
    fn env_override_takes_priority_when_set() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    /// The migration carries key material (identity.json, chat-history.key,
    /// cryptkey.dat) into the canonical directory, so the copy must be
    /// restricted before it holds any bytes and the copy must fail if it
    /// cannot be.
    #[test]
    fn migrated_secret_files_are_restricted() {
        let root = std::env::temp_dir().join(format!(
            "ember-paths-restrict-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let src = root.join("cryptkey.dat");
        let dst = root.join("cryptkey.copy.dat");
        let secret = b"secret-key-material";
        std::fs::write(&src, secret).unwrap();

        copy_file_atomically(&src, &dst, secret.len() as u64).unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), secret);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dst).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "migrated secret must be owner-only");
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
