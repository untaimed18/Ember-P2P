use std::path::PathBuf;

use tauri::Manager;
use tracing::info;

use crate::types::AppSettings;

pub struct AppConfig {
    pub settings: AppSettings,
    config_path: PathBuf,
}

impl AppConfig {
    pub fn load(app_handle: &tauri::AppHandle) -> anyhow::Result<Self> {
        let app_dir = app_handle
            .path()
            .app_data_dir()
            .map_err(|e| anyhow::anyhow!("Failed to get app data dir: {e}"))?;

        std::fs::create_dir_all(&app_dir)?;
        let config_path = app_dir.join("config.json");

        let mut settings = if config_path.exists() {
            let data = std::fs::read_to_string(&config_path)?;
            match serde_json::from_str(&data) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Config file corrupt, using defaults: {e}");
                    let bak = config_path.with_extension("json.bak");
                    let _ = std::fs::rename(&config_path, &bak);
                    AppSettings::default()
                }
            }
        } else {
            let defaults = AppSettings::default();
            let data = serde_json::to_string_pretty(&defaults)?;
            std::fs::write(&config_path, data)?;
            defaults
        };

        let mut config_changed = false;

        // Migrate: old configs pointed download_folder directly at the user's
        // Downloads dir.  It should be a Nexus subfolder so we don't pollute it.
        if !settings.download_folder.is_empty() {
            let dl = std::path::Path::new(&settings.download_folder);
            if dl.file_name().map(|n| n != "Nexus").unwrap_or(false) {
                let migrated = dl.join("Nexus").to_string_lossy().to_string();
                tracing::info!("Migrating download_folder: {} -> {}", settings.download_folder, migrated);
                settings.download_folder = migrated;
                config_changed = true;
            }
        }

        // Ensure the completed-downloads folder is shared by default.
        if !settings.download_folder.is_empty() {
            let completed_dir = std::path::Path::new(&settings.download_folder)
                .join("Downloads")
                .to_string_lossy()
                .to_string();
            if !settings.shared_folders.iter().any(|f| f == &completed_dir) {
                tracing::info!("Adding default shared folder: {completed_dir}");
                settings.shared_folders.push(completed_dir);
                config_changed = true;
            }
        }

        if config_changed {
            let data = serde_json::to_string_pretty(&settings)?;
            std::fs::write(&config_path, &data)?;
        }

        info!("Config loaded from {}", config_path.display());
        Ok(Self {
            settings,
            config_path,
        })
    }

    /// Serialize settings to JSON and return the data + path for async writing.
    /// This lets the caller drop the RwLock before doing file I/O.
    pub fn prepare_save(&self) -> anyhow::Result<(String, std::path::PathBuf, std::path::PathBuf)> {
        let data = serde_json::to_string_pretty(&self.settings)?;
        let tmp_path = self.config_path.with_extension("json.tmp");
        Ok((data, tmp_path, self.config_path.clone()))
    }

    /// Blocking file write -- call this OUTSIDE of the RwLock.
    pub fn write_to_disk(data: &str, tmp_path: &std::path::Path, final_path: &std::path::Path) -> anyhow::Result<()> {
        std::fs::write(tmp_path, data)?;
        std::fs::rename(tmp_path, final_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                final_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        info!("Config saved");
        Ok(())
    }

    /// Legacy synchronous save -- only used at startup before async runtime is available.
    pub fn save(&self) -> anyhow::Result<()> {
        let (data, tmp_path, final_path) = self.prepare_save()?;
        Self::write_to_disk(&data, &tmp_path, &final_path)
    }

    pub fn update(&mut self, settings: AppSettings) -> anyhow::Result<()> {
        self.settings = settings;
        self.save()
    }
}
