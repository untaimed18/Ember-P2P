use std::path::PathBuf;

use tracing::info;

use crate::storage::paths;
use crate::types::AppSettings;

pub struct AppConfig {
    pub settings: AppSettings,
    config_path: PathBuf,
}

impl AppConfig {
    pub fn load(app_handle: &tauri::AppHandle) -> anyhow::Result<Self> {
        let app_dir = paths::ensure_data_dir_with_app(app_handle)
            .map_err(|e| anyhow::anyhow!("Failed to prepare data dir: {e}"))?;

        let config_path = app_dir.join("config.json");

        let config_existed = config_path.exists();
        let mut settings = if config_existed {
            let data = std::fs::read_to_string(&config_path)?;
            match serde_json::from_str(&data) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Config file corrupt, using defaults: {e}");
                    let ts = chrono::Utc::now().format("%Y%m%d%H%M%S");
                    // Pick a backup name that doesn't already exist. The old
                    // fallback reused a fixed `json.bak`, so a second corruption
                    // within the same wall-clock second clobbered the previous
                    // backup; disambiguate with a counter so every corrupt
                    // config is preserved.
                    let mut bak = config_path.with_extension(format!("json.{ts}.bak"));
                    let mut n = 1u32;
                    while bak.exists() && n < 1000 {
                        bak = config_path.with_extension(format!("json.{ts}.{n}.bak"));
                        n += 1;
                    }
                    let _ = std::fs::rename(&config_path, &bak);
                    AppSettings::default()
                }
            }
        } else {
            AppSettings::default()
        };

        let mut config_changed = false;

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
                .map(|d| dl == d.as_path())
                .unwrap_or(false);
            if is_default && dl.file_name().map(|n| !n.eq_ignore_ascii_case("Ember")).unwrap_or(false) {
                let migrated = dl.join("Ember").to_string_lossy().to_string();
                tracing::info!("Migrating download_folder: {} -> {}", settings.download_folder, migrated);
                settings.download_folder = migrated;
                let _ = std::fs::create_dir_all(&settings.download_folder);
                config_changed = true;
            }
        }

        if !settings.download_folder.is_empty() {
            let completed_path = std::path::Path::new(&settings.download_folder).join("Downloads");
            let completed_dir = completed_path.to_string_lossy().to_string();
            let already_shared = settings.shared_folders.iter().any(|f| {
                let a = std::path::Path::new(f);
                let b = &completed_path;
                a == b || a.canonicalize().ok().zip(b.canonicalize().ok()).map_or(false, |(ca, cb)| ca == cb)
            });
            if !already_shared {
                tracing::info!("Adding default shared folder: {completed_dir}");
                settings.shared_folders.push(completed_dir);
                config_changed = true;
            }
        }

        if config_changed {
            let data = serde_json::to_string_pretty(&settings)?;
            crate::security::atomic_write(&config_path, data.as_bytes(), true)?;
        }

        info!("Config loaded from {}", config_path.display());
        Ok(Self {
            settings,
            config_path,
        })
    }

    /// Serialize settings to JSON and return the data + path for async writing.
    /// This lets the caller drop the RwLock before doing file I/O.
    /// The tmp path is a placeholder for back-compat; the actual temp path is
    /// generated uniquely per write inside `write_to_disk`.
    pub fn prepare_save(&self) -> anyhow::Result<(String, std::path::PathBuf, std::path::PathBuf)> {
        let data = serde_json::to_string_pretty(&self.settings)?;
        Ok((data, self.config_path.clone(), self.config_path.clone()))
    }

    /// Blocking file write -- call this OUTSIDE of the RwLock.
    /// `_tmp_path` is retained for back-compat but ignored; `atomic_write`
    /// generates a unique temp path internally.
    pub fn write_to_disk(data: &str, _tmp_path: &std::path::Path, final_path: &std::path::Path) -> anyhow::Result<()> {
        crate::security::atomic_write(final_path, data.as_bytes(), true)?;
        info!("Config saved");
        Ok(())
    }
}
