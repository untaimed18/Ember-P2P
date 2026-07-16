use std::path::{Path, PathBuf};

use tracing::info;

use crate::storage::paths;
use crate::types::AppSettings;

/// Move a corrupt or semantically-invalid `config.json` aside so the user's
/// original settings stay recoverable, returning the backup path on success.
/// Uses a timestamp + counter so repeated failures within the same wall-clock
/// second don't clobber a previous backup.
fn backup_corrupt_config(config_path: &Path, reason: &str) -> anyhow::Result<PathBuf> {
    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let mut bak = config_path.with_extension(format!("json.{ts}.bak"));
    let mut n = 1u32;
    while bak.exists() && n < 1000 {
        bak = config_path.with_extension(format!("json.{ts}.{n}.bak"));
        n += 1;
    }
    if std::fs::rename(config_path, &bak).is_ok() {
        tracing::warn!(
            "config.json {reason}; reset to defaults. Original preserved at {}",
            bak.display()
        );
        Ok(bak)
    } else if std::fs::copy(config_path, &bak).is_ok() {
        std::fs::remove_file(config_path).map_err(|e| {
            anyhow::anyhow!(
                "Copied unreadable config.json to {}, but could not remove the original: {e}",
                bak.display()
            )
        })?;
        tracing::warn!(
            "config.json {reason}; reset to defaults. Original copied to {}",
            bak.display()
        );
        Ok(bak)
    } else {
        anyhow::bail!(
            "config.json {reason}, and it could not be moved or copied to a backup; \
             refusing to overwrite the only recoverable copy"
        )
    }
}

/// Compares two filesystem paths for equality without requiring either to
/// exist on disk. `Path::canonicalize` needs a real, resolvable path and
/// silently fails to detect equality for a not-yet-created folder — exactly
/// the situation these migration checks run into on a fresh install/first
/// launch, before the app has created its default download subfolder.
/// Falling back to plain `Path` equality in that case is case-sensitive and
/// mixed-separator-sensitive on Windows, which can miss a match that's
/// semantically the same folder (e.g. a config.json hand-edited or written
/// by a different code path with different casing) and add a harmless but
/// confusing duplicate `shared_folders` entry. Comparing via `components()`
/// instead normalizes separators and trailing slashes; the Windows-only
/// ASCII case-fold matches its case-insensitive filesystem.
fn paths_likely_equal(a: &Path, b: &Path) -> bool {
    let normalize = |p: &Path| {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    };
    let (na, nb) = (normalize(a), normalize(b));
    if cfg!(target_os = "windows") {
        na.eq_ignore_ascii_case(&nb)
    } else {
        na == nb
    }
}

pub struct AppConfig {
    pub settings: AppSettings,
    config_path: PathBuf,
    /// Set to the `.bak` path when `config.json` was corrupt at load time and
    /// the app fell back to defaults. Lets startup surface a non-silent notice
    /// to the user (their settings were reset; the original is recoverable).
    pub corrupt_backup: Option<PathBuf>,
}

impl AppConfig {
    pub fn load(app_handle: &tauri::AppHandle) -> anyhow::Result<Self> {
        let app_dir = paths::ensure_data_dir_with_app(app_handle)
            .map_err(|e| anyhow::anyhow!("Failed to prepare data dir: {e}"))?;

        let config_path = app_dir.join("config.json");

        let config_existed = config_path.exists();
        let mut corrupt_backup: Option<PathBuf> = None;
        let mut config_missing_during_read = false;
        let mut config_changed = false;
        let mut settings = if config_existed {
            let data = match std::fs::read_to_string(&config_path) {
                Ok(data) => Some(data),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // The file vanished between `exists()` and the read. Treat
                    // this exactly like a fresh install rather than failing
                    // startup on a harmless TOCTOU race.
                    config_missing_during_read = true;
                    config_changed = true;
                    None
                }
                Err(e) => {
                    let backup =
                        backup_corrupt_config(&config_path, &format!("could not be read ({e})"))?;
                    corrupt_backup = Some(backup);
                    config_changed = true;
                    None
                }
            };
            match data.as_deref().map(serde_json::from_str::<AppSettings>) {
                None => AppSettings::default(),
                // Parsed cleanly *and* passes the same validation enforced on
                // every save. Re-validating here stops a hand-edited or
                // downgraded config.json with out-of-range values (e.g.
                // `tcp_port: 0`) from reaching bind/connection logic. App-written
                // configs always pass, so this only trips on foreign input —
                // which we treat like corruption: preserve and reset.
                // Overlapping shared folders from older builds are soft-fixed
                // first so upgrade does not wipe the whole settings file.
                Some(Ok(mut s)) => {
                    let (deduped, deduped_changed) =
                        crate::commands::settings::dedupe_overlapping_shared_folders(
                            std::mem::take(&mut s.shared_folders),
                        );
                    s.shared_folders = deduped;
                    if deduped_changed {
                        tracing::warn!(
                            "Removed overlapping/duplicate shared folders from config on load"
                        );
                        config_changed = true;
                    }
                    // Soft-fix legacy configs that had USS on with unlimited
                    // upload. validate_settings rejects that combo on save; if
                    // we didn't clear here, load would treat the file as
                    // corrupt and reset the whole settings file.
                    if s.uss_enabled && s.max_upload_speed == 0 {
                        tracing::warn!(
                            "Disabled Upload Speed Sense because no upload speed limit is set"
                        );
                        s.uss_enabled = false;
                        config_changed = true;
                    }
                    match crate::commands::settings::validate_settings(&s) {
                        Ok(()) => s,
                        Err(e) => {
                            corrupt_backup = Some(backup_corrupt_config(
                                &config_path,
                                &format!("has invalid settings ({e})"),
                            )?);
                            config_changed = true;
                            AppSettings::default()
                        }
                    }
                }
                Some(Err(e)) => {
                    corrupt_backup = Some(backup_corrupt_config(
                        &config_path,
                        &format!("corrupt ({e})"),
                    )?);
                    config_changed = true;
                    AppSettings::default()
                }
            }
        } else {
            AppSettings::default()
        };

        // Existing users who upgrade to a version with the wizard should skip it.
        // Only applies when a real config file existed on disk (not a fresh install).
        if config_existed && !settings.setup_complete {
            settings.setup_complete = true;
            config_changed = true;
        }

        // Migrate: old configs pointed download_folder directly at the user's
        // Downloads dir.  It should be a Ember subfolder so we don't pollute it.
        if !settings.download_folder.is_empty() {
            let dl = std::path::Path::new(&settings.download_folder);
            let is_default = directories::UserDirs::new()
                .and_then(|u| u.download_dir().map(|d| d.to_path_buf()))
                .map(|d| paths_likely_equal(dl, &d))
                .unwrap_or(false);
            if is_default
                && dl
                    .file_name()
                    .map(|n| !n.eq_ignore_ascii_case("Ember"))
                    .unwrap_or(false)
            {
                let migrated = dl.join("Ember").to_string_lossy().to_string();
                tracing::info!(
                    "Migrating download_folder: {} -> {}",
                    settings.download_folder,
                    migrated
                );
                settings.download_folder = migrated;
                let _ = std::fs::create_dir_all(&settings.download_folder);
                config_changed = true;
            }
        }

        // Seed the default share once, not on every launch. Existing configs
        // from builds predating this marker are marked as already considered:
        // those builds always seeded the folder themselves, so an absent entry
        // means the user deliberately removed it and must be respected.
        if !settings.default_shared_folder_seeded {
            let should_seed =
                !config_existed || config_missing_during_read || corrupt_backup.is_some();
            if should_seed && !settings.download_folder.is_empty() {
                let completed_path =
                    std::path::Path::new(&settings.download_folder).join("Downloads");
                let completed_dir = completed_path.to_string_lossy().to_string();
                let already_shared = settings.shared_folders.iter().any(|f| {
                    let a = std::path::Path::new(f);
                    let b = &completed_path;
                    paths_likely_equal(a, b)
                        || a.canonicalize()
                            .ok()
                            .zip(b.canonicalize().ok())
                            .is_some_and(|(ca, cb)| ca == cb)
                });
                if !already_shared {
                    tracing::info!("Adding default shared folder: {completed_dir}");
                    settings.shared_folders.push(completed_dir);
                }
            }
            settings.default_shared_folder_seeded = true;
            config_changed = true;
        }

        if config_changed {
            let data = serde_json::to_string_pretty(&settings)?;
            crate::security::atomic_write(&config_path, data.as_bytes(), true)?;
        }

        info!("Config loaded from {}", config_path.display());
        Ok(Self {
            settings,
            config_path,
            corrupt_backup,
        })
    }

    /// Serialize the *given* settings to JSON and return the data + path for
    /// async writing, without touching the in-memory config. This lets the
    /// caller drop the RwLock before doing file I/O, and lets it persist to
    /// disk first and only commit the new settings to `self.settings` after the
    /// write succeeds, so a failed write can't leave the running config diverged
    /// from disk. The tmp path is a placeholder for back-compat; the actual temp
    /// path is generated uniquely per write inside `write_to_disk`.
    pub fn prepare_save_settings(
        &self,
        settings: &AppSettings,
    ) -> anyhow::Result<(String, std::path::PathBuf, std::path::PathBuf)> {
        let data = serde_json::to_string_pretty(settings)?;
        Ok((data, self.config_path.clone(), self.config_path.clone()))
    }

    /// Blocking file write -- call this OUTSIDE of the RwLock.
    /// `_tmp_path` is retained for back-compat but ignored; `atomic_write`
    /// generates a unique temp path internally.
    pub fn write_to_disk(
        data: &str,
        _tmp_path: &std::path::Path,
        final_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        crate::security::atomic_write(final_path, data.as_bytes(), true)?;
        info!("Config saved");
        Ok(())
    }
}
