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

        let settings = if config_path.exists() {
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

        info!("Config loaded from {}", config_path.display());
        Ok(Self {
            settings,
            config_path,
        })
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let data = serde_json::to_string_pretty(&self.settings)?;
        let tmp_path = self.config_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, &self.config_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &self.config_path,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        info!("Config saved");
        Ok(())
    }

    pub fn update(&mut self, settings: AppSettings) -> anyhow::Result<()> {
        self.settings = settings;
        self.save()
    }
}
