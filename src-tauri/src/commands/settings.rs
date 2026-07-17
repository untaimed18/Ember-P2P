use tauri::Manager;
use tracing::{info, warn};

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::network::kad::bootstrap;
use crate::network::kad::ip_filter::count_valid_entries;
use crate::network::NetworkCommand;
use crate::types::AppSettings;

const NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";
const IPFILTER_URL: &str = "https://upd.emule-security.org/ipfilter.dat";

fn normalized_path_components(path: &std::path::Path) -> Vec<String> {
    path.components()
        .map(|component| {
            let value = component.as_os_str().to_string_lossy().into_owned();
            if cfg!(target_os = "windows") {
                value.to_ascii_lowercase()
            } else {
                value
            }
        })
        .collect()
}

pub(crate) fn shared_paths_overlap(a: &std::path::Path, b: &std::path::Path) -> bool {
    let a = normalized_path_components(a);
    let b = normalized_path_components(b);
    a == b || (a.len() < b.len() && b.starts_with(&a)) || (b.len() < a.len() && a.starts_with(&b))
}

/// Drop exact duplicates and nested children, preferring the shorter (parent)
/// path. Used on config load so an older build that allowed overlapping
/// `shared_folders` does not wipe the whole config on upgrade validation.
///
/// Returns `(deduped, changed)` where `changed` is true when any entry was
/// removed or replaced relative to the input order/contents.
pub(crate) fn dedupe_overlapping_shared_folders(folders: Vec<String>) -> (Vec<String>, bool) {
    let original = folders.clone();
    let mut kept: Vec<String> = Vec::with_capacity(folders.len());
    for folder in folders {
        let path = std::path::Path::new(&folder);
        let comps = normalized_path_components(path);
        let mut skip = false;
        kept.retain(|existing| {
            let existing_path = std::path::Path::new(existing);
            if !shared_paths_overlap(existing_path, path) {
                return true;
            }
            let existing_comps = normalized_path_components(existing_path);
            if existing_comps == comps {
                // Exact duplicate: keep the earlier entry.
                skip = true;
                true
            } else if existing_comps.len() < comps.len() {
                // Existing is a parent of the new path: drop the child.
                skip = true;
                true
            } else {
                // New path is a parent of an existing child: prefer the parent.
                false
            }
        });
        if !skip {
            kept.push(folder);
        }
    }
    let changed = kept != original;
    (kept, changed)
}

fn normalize_shared_folders(folders: Vec<String>) -> Result<Vec<String>, String> {
    let mut normalized: Vec<std::path::PathBuf> = Vec::with_capacity(folders.len());
    for folder in folders {
        let configured = std::path::PathBuf::from(&folder);
        // A temporarily offline USB/network path must not fail the entire
        // settings save. Keep the configured string and still run overlap /
        // duplicate checks via path components.
        let canonical = match configured.canonicalize() {
            Ok(path) => path,
            Err(e) => {
                warn!(
                    "Shared folder cannot be resolved (keeping configured path): {folder} ({e})"
                );
                configured
            }
        };
        let canonical_components = normalized_path_components(&canonical);
        if normalized
            .iter()
            .any(|existing| normalized_path_components(existing) == canonical_components)
        {
            continue;
        }
        if let Some(existing) = normalized
            .iter()
            .find(|existing| shared_paths_overlap(existing, &canonical))
        {
            return Err(coded_ctx(
                "settings_shared_folder_overlap",
                "Shared folders must not overlap",
                format!("{} and {}", existing.display(), canonical.display()),
            ));
        }
        normalized.push(canonical);
    }
    Ok(normalized
        .into_iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect())
}

#[tauri::command]
pub async fn get_settings(state: tauri::State<'_, AppState>) -> Result<AppSettings, String> {
    let config = state.config.read().await;
    Ok(config.settings.clone())
}

/// Upper bounds for IPC inputs. These exist to prevent a malicious/buggy
/// frontend from pushing multi-megabyte blobs through the Tauri bridge, which
/// would bloat `config.json`, block the async runtime on serialize, and
/// potentially exhaust memory. Values are deliberately generous vs. normal use.
const MAX_PATH_LEN: usize = 4 * 1024;
const MAX_SHARED_FOLDERS: usize = 512;
const MAX_URL_LEN: usize = 2 * 1024;
const MAX_FILENAME_CLEANUPS_LEN: usize = 16 * 1024;
const MAX_CONFIGURED_SPEED_BPS: u64 = 100 * 1024 * 1024 * 1024;

fn clamp_assign<T: Ord + Copy>(value: &mut T, min: T, max: T) -> bool {
    let clamped = (*value).clamp(min, max);
    if clamped != *value {
        *value = clamped;
        true
    } else {
        false
    }
}

/// Clamp out-of-range numerics and reset invalid enum strings so a hand-edited
/// or downgraded `config.json` can load without wiping every setting. Returns
/// whether any field was changed. Call before [`validate_settings`] on load;
/// remaining failures (paths, nickname, etc.) still trigger backup+defaults.
pub(crate) fn soft_repair_settings(settings: &mut AppSettings) -> bool {
    use crate::network::kad::types::{DEFAULT_TCP_PORT, DEFAULT_UDP_PORT};

    let mut changed = false;

    let profile = settings.spam_filter_profile.trim().to_ascii_lowercase();
    if profile != "relaxed" && profile != "balanced" && profile != "aggressive" {
        settings.spam_filter_profile = "balanced".to_string();
        changed = true;
    } else if profile != settings.spam_filter_profile {
        settings.spam_filter_profile = profile;
        changed = true;
    }

    let close_behavior = settings.close_to_tray_behavior.trim().to_ascii_lowercase();
    if close_behavior != "ask" && close_behavior != "tray" && close_behavior != "exit" {
        settings.close_to_tray_behavior = "ask".to_string();
        changed = true;
    } else if close_behavior != settings.close_to_tray_behavior {
        settings.close_to_tray_behavior = close_behavior;
        changed = true;
    }

    let freq = settings.update_check_frequency.trim().to_ascii_lowercase();
    if freq != "daily" && freq != "weekly" && freq != "monthly" {
        settings.update_check_frequency = "daily".to_string();
        changed = true;
    } else if freq != settings.update_check_frequency {
        settings.update_check_frequency = freq;
        changed = true;
    }

    if settings.tcp_port == 0 {
        settings.tcp_port = DEFAULT_TCP_PORT;
        changed = true;
    }
    if settings.udp_port == 0 {
        settings.udp_port = DEFAULT_UDP_PORT;
        changed = true;
    }

    changed |= clamp_assign(&mut settings.max_concurrent_downloads, 1, 50);
    changed |= clamp_assign(&mut settings.max_concurrent_uploads, 1, 50);
    if settings.max_upload_speed > MAX_CONFIGURED_SPEED_BPS {
        settings.max_upload_speed = MAX_CONFIGURED_SPEED_BPS;
        changed = true;
    }
    if settings.max_download_speed > MAX_CONFIGURED_SPEED_BPS {
        settings.max_download_speed = MAX_CONFIGURED_SPEED_BPS;
        changed = true;
    }
    // Soft-disable USS when upload is unlimited (validate rejects that combo).
    if settings.uss_enabled && settings.max_upload_speed == 0 {
        settings.uss_enabled = false;
        changed = true;
    }
    changed |= clamp_assign(&mut settings.download_queue_wait_secs, 60, 14400);
    changed |= clamp_assign(&mut settings.max_sources_per_file, 1, 2000);
    changed |= clamp_assign(&mut settings.max_connections, 1, 2000);
    changed |= clamp_assign(&mut settings.multisource_retry_rounds, 1, 20);
    changed |= clamp_assign(&mut settings.download_part_retry_rounds, 1, 20);
    changed |= clamp_assign(&mut settings.max_download_file_size_gib, 1, 16_384);
    changed |= clamp_assign(&mut settings.search_timeout_secs, 30, 600);
    changed |= clamp_assign(&mut settings.max_friends, 1, 500);

    // Friend session encryption is not a user-facing toggle; keep it on even
    // if an older config.json or hand edit turned it off.
    if !settings.friend_session_encryption {
        settings.friend_session_encryption = true;
        changed = true;
    }

    // Drop shared folders that would fail validate (sensitive segments) or that
    // contain / are the Ember data directory. Older builds allowed some AppData
    // paths; rejecting them in validate alone would wipe the entire config.
    let data_dir = crate::storage::paths::resolve_data_dir();
    let data_canon = data_dir.canonicalize().unwrap_or(data_dir);
    let before_len = settings.shared_folders.len();
    settings.shared_folders.retain(|folder| {
        let path = std::path::Path::new(folder);
        let folder_canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if folder_canon == data_canon
            || data_canon.starts_with(&folder_canon)
            || crate::security::path_matches_dir(
                &data_canon.to_string_lossy(),
                &folder_canon.to_string_lossy(),
            )
        {
            tracing::warn!(
                "Removing shared folder that covers Ember data directory on load: {folder}"
            );
            return false;
        }
        let canonical = path.canonicalize().ok();
        let scan_paths = std::iter::once(path.to_path_buf()).chain(canonical);
        for scan_path in scan_paths {
            for component in scan_path.components() {
                if let std::path::Component::Normal(seg) = component {
                    if crate::sharing::is_sensitive_dir_name(&seg.to_string_lossy()) {
                        tracing::warn!(
                            "Removing shared folder with sensitive path segment on load: {folder}"
                        );
                        return false;
                    }
                }
            }
        }
        true
    });
    if settings.shared_folders.len() != before_len {
        changed = true;
    }

    changed
}

pub(crate) fn validate_settings(settings: &AppSettings) -> Result<(), String> {
    if settings.spam_filter_profile != "relaxed"
        && settings.spam_filter_profile != "balanced"
        && settings.spam_filter_profile != "aggressive"
    {
        return Err(coded(
            "settings_spam_filter_profile_invalid",
            "Spam filter profile must be 'relaxed', 'balanced', or 'aggressive'",
        ));
    }
    // Accept the same three values the UI exposes; reject anything else
    // so a future migration / hand-edited config can't silently disable
    // the close-confirmation dialog by dropping a typo into config.json.
    if settings.close_to_tray_behavior != "ask"
        && settings.close_to_tray_behavior != "tray"
        && settings.close_to_tray_behavior != "exit"
    {
        return Err(coded(
            "settings_close_behavior_invalid",
            "Close behavior must be 'ask', 'tray', or 'exit'",
        ));
    }
    if settings.update_check_frequency != "daily"
        && settings.update_check_frequency != "weekly"
        && settings.update_check_frequency != "monthly"
    {
        return Err(coded(
            "settings_update_check_frequency_invalid",
            "Update check frequency must be 'daily', 'weekly', or 'monthly'",
        ));
    }
    if settings.download_folder.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "settings_download_folder_too_long",
            format!("Download folder path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    if settings.shared_folders.len() > MAX_SHARED_FOLDERS {
        return Err(coded_ctx(
            "settings_too_many_shared_folders",
            format!("Too many shared folders (max {MAX_SHARED_FOLDERS})"),
            MAX_SHARED_FOLDERS,
        ));
    }
    for folder in &settings.shared_folders {
        if folder.len() > MAX_PATH_LEN {
            return Err(coded_ctx(
                "settings_shared_folder_too_long",
                format!("Shared folder path exceeds {MAX_PATH_LEN} bytes"),
                MAX_PATH_LEN,
            ));
        }
    }
    // `folder_priorities` has no natural bound from the UI (unlike
    // `shared_folders`, which the sharing commands already cap), so a
    // hand-edited `config.json` could otherwise grow this map and its key
    // lengths unboundedly, slowing settings load/save. Mirror the
    // shared-folder limits.
    if settings.folder_priorities.len() > MAX_SHARED_FOLDERS {
        return Err(coded_ctx(
            "settings_too_many_folder_priorities",
            format!("Too many folder priorities (max {MAX_SHARED_FOLDERS})"),
            MAX_SHARED_FOLDERS,
        ));
    }
    for path in settings.folder_priorities.keys() {
        if path.len() > MAX_PATH_LEN {
            return Err(coded_ctx(
                "settings_folder_priority_path_too_long",
                format!("Folder priority path exceeds {MAX_PATH_LEN} bytes"),
                MAX_PATH_LEN,
            ));
        }
    }
    if settings.rendezvous_url.len() > MAX_URL_LEN {
        return Err(coded_ctx(
            "settings_rendezvous_url_too_long",
            format!("Rendezvous URL exceeds {MAX_URL_LEN} bytes"),
            MAX_URL_LEN,
        ));
    }
    if settings.nodes_dat_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "settings_nodes_dat_path_too_long",
            format!("nodes.dat path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    if settings.server_list_path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "settings_server_list_path_too_long",
            format!("server.met path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    if settings.filename_cleanups.len() > MAX_FILENAME_CLEANUPS_LEN {
        return Err(coded_ctx(
            "settings_filename_cleanups_too_long",
            format!("filename_cleanups exceeds {MAX_FILENAME_CLEANUPS_LEN} bytes"),
            MAX_FILENAME_CLEANUPS_LEN,
        ));
    }
    if settings.tcp_port == 0 {
        return Err(coded(
            "settings_tcp_port_invalid",
            "TCP port must be between 1 and 65535",
        ));
    }
    if settings.udp_port == 0 {
        return Err(coded(
            "settings_udp_port_invalid",
            "UDP port must be between 1 and 65535",
        ));
    }
    if settings.max_concurrent_downloads == 0 || settings.max_concurrent_downloads > 50 {
        return Err(coded(
            "settings_max_concurrent_downloads_invalid",
            "Max concurrent downloads must be between 1 and 50",
        ));
    }
    if settings.max_concurrent_uploads == 0 || settings.max_concurrent_uploads > 50 {
        return Err(coded(
            "settings_max_concurrent_uploads_invalid",
            "Max concurrent uploads must be between 1 and 50",
        ));
    }
    if settings.max_upload_speed > MAX_CONFIGURED_SPEED_BPS {
        return Err(coded_ctx(
            "settings_max_upload_speed_invalid",
            format!("Max upload speed must be 0 or at most {MAX_CONFIGURED_SPEED_BPS} B/s"),
            MAX_CONFIGURED_SPEED_BPS,
        ));
    }
    // USS throttles under the configured upload cap; with unlimited upload
    // (0) there is no ceiling to sense against. Reject rather than silently
    // leaving uss_enabled true but inert — config load soft-fixes legacy
    // configs before this check runs.
    if settings.uss_enabled && settings.max_upload_speed == 0 {
        return Err(coded(
            "settings_uss_requires_upload_limit",
            "Upload Speed Sense requires an upload speed limit to be set",
        ));
    }
    if settings.max_download_speed > MAX_CONFIGURED_SPEED_BPS {
        return Err(coded_ctx(
            "settings_max_download_speed_invalid",
            format!("Max download speed must be 0 or at most {MAX_CONFIGURED_SPEED_BPS} B/s"),
            MAX_CONFIGURED_SPEED_BPS,
        ));
    }
    if !(60..=14400).contains(&settings.download_queue_wait_secs) {
        return Err(coded(
            "settings_download_queue_wait_invalid",
            "Download queue wait must be between 60 and 14400 seconds",
        ));
    }
    if !(1..=2000).contains(&settings.max_sources_per_file) {
        return Err(coded(
            "settings_max_sources_per_file_invalid",
            "Max sources per file must be between 1 and 2000",
        ));
    }
    if !(1..=2000).contains(&settings.max_connections) {
        return Err(coded(
            "settings_max_connections_invalid",
            "Max connections must be between 1 and 2000",
        ));
    }
    if !(1..=20).contains(&settings.multisource_retry_rounds) {
        return Err(coded(
            "settings_multisource_retry_rounds_invalid",
            "Multi-source retry rounds must be between 1 and 20",
        ));
    }
    if !(1..=20).contains(&settings.download_part_retry_rounds) {
        return Err(coded(
            "settings_download_part_retry_rounds_invalid",
            "Part hash retry rounds must be between 1 and 20",
        ));
    }
    if !(1..=16_384).contains(&settings.max_download_file_size_gib) {
        return Err(coded(
            "settings_max_download_file_size_invalid",
            "Max download file size must be between 1 and 16384 GiB",
        ));
    }
    if !(30..=600).contains(&settings.search_timeout_secs) {
        return Err(coded(
            "settings_search_timeout_invalid",
            "Search timeout must be between 30 and 600 seconds",
        ));
    }
    if !(1..=500).contains(&settings.max_friends) {
        return Err(coded(
            "settings_max_friends_invalid",
            "Max friends must be between 1 and 500",
        ));
    }
    if settings.nickname.trim().is_empty() {
        return Err(coded(
            "settings_nickname_empty",
            "Nickname must not be empty",
        ));
    }
    if settings.nickname.len() > 128 {
        return Err(coded(
            "settings_nickname_too_long",
            "Nickname must be 128 bytes or fewer",
        ));
    }
    let is_filesystem_root = |path: &std::path::Path| {
        path.has_root()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::Normal(_)))
    };
    if !settings.download_folder.is_empty() {
        let path = std::path::Path::new(&settings.download_folder);
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(coded(
                "settings_download_folder_parent_dir",
                "Download folder must not contain '..' path components",
            ));
        }
        if is_filesystem_root(path)
            || path
                .canonicalize()
                .ok()
                .as_deref()
                .is_some_and(is_filesystem_root)
        {
            return Err(coded_ctx(
                "settings_download_folder_root",
                "Download folder must not be a filesystem root",
                &settings.download_folder,
            ));
        }
        // Scan the literal path AND (best-effort) its canonical form. A
        // junction/symlink can point a benign-looking folder at a blocked
        // system directory; canonicalizing resolves the reparse point so the
        // segment check can't be bypassed. A not-yet-created folder won't
        // canonicalize — fall back to the literal check in that case.
        let canonical = path.canonicalize().ok();
        let scan_paths = std::iter::once(path.to_path_buf()).chain(canonical);
        for scan_path in scan_paths {
            for component in scan_path.components() {
                if let std::path::Component::Normal(seg) = component {
                    if crate::sharing::is_sensitive_dir_name(&seg.to_string_lossy()) {
                        return Err(coded_ctx(
                            "settings_download_folder_system_dir",
                            "Cannot use system directory as download folder",
                            &settings.download_folder,
                        ));
                    }
                }
            }
        }
    }
    if !settings.rendezvous_url.is_empty() {
        let url_lower = settings.rendezvous_url.to_ascii_lowercase();
        if !url_lower.starts_with("https://") {
            return Err(coded(
                "settings_rendezvous_url_not_https",
                "Rendezvous URL must use HTTPS",
            ));
        }
        let after_scheme = &settings.rendezvous_url["https://".len()..];
        if after_scheme.is_empty() || after_scheme.starts_with('/') {
            return Err(coded(
                "settings_rendezvous_url_no_host",
                "Rendezvous URL must have a valid host",
            ));
        }
        if after_scheme.contains('@') {
            return Err(coded(
                "settings_rendezvous_url_has_credentials",
                "Rendezvous URL must not contain credentials",
            ));
        }
    }

    for folder in &settings.shared_folders {
        let path = std::path::Path::new(folder);
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(coded_ctx(
                "settings_shared_folder_parent_dir",
                "Shared folder must not contain '..' path components",
                folder,
            ));
        }
        if is_filesystem_root(path)
            || path
                .canonicalize()
                .ok()
                .as_deref()
                .is_some_and(is_filesystem_root)
        {
            return Err(coded_ctx(
                "settings_shared_folder_root",
                "Cannot share a filesystem root",
                folder,
            ));
        }
        // Scan the literal path AND (best-effort) its canonical form. A
        // junction/symlink can point a benign-looking folder at a blocked
        // system directory; canonicalizing resolves the reparse point so the
        // segment check can't be bypassed (mirrors the download_folder branch
        // above and the canonicalize-first check in `add_shared_folder`). A
        // not-yet-created folder won't canonicalize — fall back to literal.
        let canonical = path.canonicalize().ok();
        let scan_paths = std::iter::once(path.to_path_buf()).chain(canonical.clone());
        for scan_path in scan_paths {
            for component in scan_path.components() {
                if let std::path::Component::Normal(seg) = component {
                    if crate::sharing::is_sensitive_dir_name(&seg.to_string_lossy()) {
                        return Err(coded_ctx(
                            "settings_shared_folder_system_dir",
                            "Cannot share system directory",
                            folder,
                        ));
                    }
                }
            }
        }
        // Refuse Ember's own data directory (or a parent that covers it).
        // Mirrors soft_repair / add_shared_folder so a settings save can't
        // reintroduce a folder that covers config, identity, known.met, …
        let data_dir = crate::storage::paths::resolve_data_dir();
        let data_canon = data_dir.canonicalize().unwrap_or(data_dir);
        let folder_canon = canonical.unwrap_or_else(|| path.to_path_buf());
        if folder_canon == data_canon
            || data_canon.starts_with(&folder_canon)
            || crate::security::path_matches_dir(
                &data_canon.to_string_lossy(),
                &folder_canon.to_string_lossy(),
            )
        {
            return Err(coded_ctx(
                "settings_cannot_share_data_dir",
                "Cannot share Ember data directory or a parent of it",
                folder,
            ));
        }
    }
    for (index, folder) in settings.shared_folders.iter().enumerate() {
        if let Some(other) = settings.shared_folders[index + 1..].iter().find(|other| {
            shared_paths_overlap(std::path::Path::new(folder), std::path::Path::new(other))
        }) {
            return Err(coded_ctx(
                "settings_shared_folder_overlap",
                "Shared folders must not overlap",
                format!("{folder} and {other}"),
            ));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn update_settings(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    settings: AppSettings,
) -> Result<String, String> {
    let mut settings = settings;
    settings.spam_filter_profile = settings.spam_filter_profile.trim().to_ascii_lowercase();
    settings.close_to_tray_behavior = settings.close_to_tray_behavior.trim().to_ascii_lowercase();
    settings.update_check_frequency = settings.update_check_frequency.trim().to_ascii_lowercase();
    // Not exposed in Settings UI — always keep friend sessions encrypted.
    settings.friend_session_encryption = true;
    // L20: strip bidi/zero-width/control formatters from the
    // local user's own nickname before it's stored or sent on the
    // wire (Hello/EmuleInfo/HelloAnswer all carry it). Without
    // this the local user could paste an override character and
    // every peer's friends list would render the spoofed string;
    // with this, the field is normalised at the boundary so wire
    // and storage are consistent. We avoid the
    // `sanitize_display_name` fallback to "Anonymous" so a user
    // whose entire nickname was invisible characters still trips
    // the empty-nickname check below — we'd rather reject than
    // silently rewrite their identity.
    settings.nickname = settings
        .nickname
        .chars()
        .filter(|c| {
            !c.is_control() && *c != '\0' && !crate::security::is_invisible_or_bidi_control_pub(*c)
        })
        .collect::<String>()
        .trim()
        .to_string();
    let shared_folders = std::mem::take(&mut settings.shared_folders);
    settings.shared_folders =
        tokio::task::spawn_blocking(move || normalize_shared_folders(shared_folders))
            .await
            .map_err(|e| coded_ctx("settings_validation_task_failed", "Validation failed", e))??;
    {
        let settings_for_validation = settings.clone();
        tokio::task::spawn_blocking(move || validate_settings(&settings_for_validation))
            .await
            .map_err(|e| coded_ctx("settings_validation_task_failed", "Validation failed", e))??;
    }

    let _settings_save_guard = state.settings_save_lock.lock().await;
    let old_settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };
    if settings.settings_revision != old_settings.settings_revision {
        return Err(coded(
            "settings_stale_revision",
            "Settings changed in another window or command; reload and apply your changes again",
        ));
    }
    settings.settings_revision = old_settings.settings_revision.saturating_add(1);

    let port_changed =
        settings.tcp_port != old_settings.tcp_port || settings.udp_port != old_settings.udp_port;

    // Persist to disk BEFORE mutating the in-memory config so a failed write
    // can't leave the running session (and the runtime apply below) diverged
    // from what's on disk. Only commit the new settings once the write succeeds.
    let save_data = {
        let config = state.config.read().await;
        config.prepare_save_settings(&settings).map_err(|e| {
            coded_ctx(
                "settings_serialize_failed",
                "Failed to serialize settings",
                e,
            )
        })?
    };
    {
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
        })
        .await
        .map_err(|e| coded_ctx("settings_save_failed", "Save failed", e))?
        .map_err(|e| coded_ctx("settings_save_failed", "Save failed", e))?;
    }
    {
        let mut config = state.config.write().await;
        config.settings = settings.clone();
    }

    // Keep the synchronous mirror used by the close-event handler in sync
    // with the canonical config so that a behavior change made here takes
    // effect on the very next title-bar X click without restarting.
    *state.close_behavior.write() = settings.close_to_tray_behavior.clone();

    state
        .bandwidth_limiter
        .set_configured_limits(settings.max_upload_speed, settings.max_download_speed);

    // Apply the new concurrent-download cap and promote any queued downloads
    // that the higher cap now allows. Previously this only set the field, so
    // raising the limit left queued downloads waiting until some unrelated
    // event (a completion/failure) happened to trigger promotion.
    let promoted = {
        let mut manager = state.transfer_manager.write().await;
        manager.set_max_concurrent(settings.max_concurrent_downloads)
    };
    if !promoted.is_empty() {
        super::transfers::start_promoted_downloads(&state, &promoted).await;
    }

    {
        let mut live = state.upload_shared_folders.write().await;
        *live = settings.shared_folders.clone();
    }

    // Keep the shared-folder filesystem watcher in sync. The dedicated
    // add/remove-folder commands do this, but the generic settings save can
    // also change `shared_folders`, and without re-syncing the watcher would
    // keep monitoring the old set (missing auto-detection of files in newly
    // added folders, and needlessly watching removed ones).
    if let Some(watcher) = state.shared_folder_watcher.as_ref() {
        watcher.sync_paths(&settings.shared_folders);
    }
    {
        let config = state.config.read().await;
        crate::commands::sharing::sync_asset_protocol_scope(&app, &config);
    }

    // Settings are already persisted to disk above; if the runtime update
    // cannot be queued, report partial success instead of silently leaving the
    // live network task on old values until restart.
    if let Err(e) = state.network_tx.try_send(NetworkCommand::UpdateSettings {
        settings: settings.clone(),
    }) {
        tracing::warn!(
            "Settings saved to disk, but live network update was dropped (channel full): {e}"
        );
        return Err(coded_ctx(
            "settings_saved_live_update_failed",
            "Settings were saved, but the live network update failed; restart or retry to apply them now",
            e,
        ));
    }

    if port_changed {
        Ok("Settings saved. Port changes require an application restart to take effect.".into())
    } else {
        Ok("Settings saved.".into())
    }
}

#[tauri::command]
pub async fn download_nodes_dat(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    info!("Downloading nodes.dat from {NODES_DAT_URL}");

    const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
    let response = crate::security::fetch_pinned_get(NODES_DAT_URL)
        .await
        .map_err(|e| coded_ctx("settings_http_request_failed", "HTTP request failed", e))?
        .error_for_status()
        .map_err(|e| coded_ctx("settings_http_error", "HTTP error", e))?;
    if let Some(cl) = response.content_length() {
        if cl > MAX_RESPONSE_BYTES as u64 {
            return Err(coded(
                "settings_response_too_large",
                "Response too large (Content-Length exceeds limit)",
            ));
        }
    }
    let bytes = {
        use futures::StreamExt;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                coded_ctx(
                    "settings_response_read_failed",
                    "Failed to read response body",
                    e,
                )
            })?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(coded("settings_response_too_large", "Response too large"));
            }
        }
        body
    };

    let data_dir = crate::storage::paths::resolve_data_dir_with_app(&app);
    tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
        coded_ctx(
            "settings_create_data_dir_failed",
            "Failed to create data dir",
            e,
        )
    })?;

    let nodes_path = data_dir.join("nodes.dat");
    // Parse-validate the buffer in-memory first so we never leave a half-written
    // temp file on disk and so the atomic_write path is also the last write.
    let validation_bytes = bytes.clone();
    let contacts = {
        let scratch = data_dir.join(format!(
            ".nodes.dat.validate.{}.{}.tmp",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let scratch_w = scratch.clone();
        tokio::fs::write(&scratch_w, &validation_bytes)
            .await
            .map_err(|e| {
                coded_ctx(
                    "settings_nodes_dat_scratch_write_failed",
                    "Failed to write nodes.dat scratch",
                    e,
                )
            })?;
        let scratch_r = scratch.clone();
        let parsed = tokio::task::spawn_blocking(move || bootstrap::load_nodes_dat(&scratch_r))
            .await
            .map_err(|e| {
                coded_ctx(
                    "settings_validation_task_failed",
                    "Validation task failed",
                    e,
                )
            })?;
        let _ = tokio::fs::remove_file(&scratch).await;
        match parsed {
            Ok(c) => c,
            Err(e) => {
                return Err(coded_ctx(
                    "settings_nodes_dat_corrupt",
                    "Downloaded file is corrupt",
                    e,
                ))
            }
        }
    };

    {
        let nodes_path_w = nodes_path.clone();
        let write_bytes = bytes.clone();
        tokio::task::spawn_blocking(move || {
            crate::security::atomic_write(&nodes_path_w, &write_bytes, false)
        })
        .await
        .map_err(|e| coded_ctx("settings_save_task_failed", "Save task failed", e))?
        .map_err(|e| {
            coded_ctx(
                "settings_finalize_nodes_dat_failed",
                "Failed to finalize nodes.dat",
                e,
            )
        })?;
    }

    let contact_count = contacts.len();
    let byte_count = bytes.len();

    // Inject contacts into the running network. The file is already
    // safely on disk above, so a saturated channel here should not
    // surface as a failed save — bootstrap will pick the contacts up
    // on the next launch (or as soon as the network drains the queue
    // and we manually re-trigger). Mirrors the "saved but not applied
    // live" message style used by `update_settings`.
    let live_msg = match state
        .network_tx
        .try_send(NetworkCommand::BootstrapContacts { contacts })
    {
        Ok(()) => "bootstrapping now",
        Err(e) => {
            tracing::warn!(
                "nodes.dat saved to disk, but live bootstrap injection was dropped (channel full): {e}"
            );
            "will bootstrap on next launch"
        }
    };

    let msg = format!(
        "Downloaded and loaded {contact_count} contacts ({byte_count} bytes) — {live_msg}",
    );
    info!("{msg}");
    Ok(msg)
}

#[tauri::command]
pub async fn download_ipfilter(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    info!("Downloading ipfilter.dat from {IPFILTER_URL}");

    const MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
    let response = crate::security::fetch_pinned_get(IPFILTER_URL)
        .await
        .map_err(|e| coded_ctx("settings_http_request_failed", "HTTP request failed", e))?
        .error_for_status()
        .map_err(|e| coded_ctx("settings_http_error", "HTTP error", e))?;
    if let Some(cl) = response.content_length() {
        if cl > MAX_RESPONSE_BYTES as u64 {
            return Err(coded(
                "settings_response_too_large",
                "Response too large (Content-Length exceeds limit)",
            ));
        }
    }
    let bytes = {
        use futures::StreamExt;
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                coded_ctx(
                    "settings_response_read_failed",
                    "Failed to read response body",
                    e,
                )
            })?;
            body.extend_from_slice(&chunk);
            if body.len() > MAX_RESPONSE_BYTES {
                return Err(coded("settings_response_too_large", "Response too large"));
            }
        }
        body
    };

    // Validate before anything on disk or in memory is touched. Without
    // this, a dead mirror serving an HTML error page (still a 200, so
    // `error_for_status` doesn't catch it) would sail straight through to
    // `atomic_write` + `ReloadIpFilter`, which faithfully replaces the
    // working filter with an empty one — silently wiping out the user's
    // protection while this command still reports success. See
    // `commands::security::download_and_load_ipfilter` for the same fix.
    let (bytes, entry_count) = tokio::task::spawn_blocking(move || {
        let entry_count = count_valid_entries(&bytes, "dat");
        (bytes, entry_count)
    })
    .await
    .map_err(|e| {
        coded_ctx(
            "settings_validation_task_failed",
            "Validation task failed",
            e,
        )
    })?;
    if entry_count == 0 {
        return Err(coded(
            "settings_ipfilter_no_valid_entries",
            "Downloaded file does not contain any valid IP filter entries — keeping the existing filter",
        ));
    }

    let data_dir = crate::storage::paths::resolve_data_dir_with_app(&app);
    tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
        coded_ctx(
            "settings_create_data_dir_failed",
            "Failed to create data dir",
            e,
        )
    })?;

    let filter_path = data_dir.join("ipfilter.dat");
    {
        let filter_path_w = filter_path.clone();
        let write_bytes = bytes.clone();
        tokio::task::spawn_blocking(move || {
            crate::security::atomic_write(&filter_path_w, &write_bytes, false)
        })
        .await
        .map_err(|e| coded_ctx("settings_save_task_failed", "Save task failed", e))?
        .map_err(|e| {
            coded_ctx(
                "settings_finalize_ipfilter_failed",
                "Failed to finalize ipfilter.dat",
                e,
            )
        })?;
    }

    let byte_count = bytes.len();

    let reload_ok = state
        .network_tx
        .try_send(NetworkCommand::ReloadIpFilter { path: filter_path })
        .is_ok();

    let msg = if reload_ok {
        format!(
            "Downloaded ipfilter.dat ({byte_count} bytes, {entry_count} entries) — reloading filter now"
        )
    } else {
        format!(
            "Downloaded ipfilter.dat ({byte_count} bytes, {entry_count} entries) — network busy, filter will load on restart"
        )
    };
    info!("{msg}");
    Ok(msg)
}

// ---------------------------------------------------------------------------
// Window lifecycle commands wired up to the close-to-tray UX.
//
// `hide_to_tray` is invoked from the close-confirmation dialog when the user
// picks "Minimize to Tray". `quit_app` is the explicit-exit path (dialog's
// "Exit Ember" button + the tray menu's Quit entry); we route through
// `app.exit(0)` so the existing `RunEvent::Exit` handler in `lib::run` drains
// the network/save pipeline before the process dies.
//
// `set_close_behavior` is a thin wrapper over `update_settings` for the case
// where the dialog flips the saved preference at the same moment as the
// close action — keeps the round trip on a tiny payload instead of pushing
// the entire AppSettings struct just to change a single string.
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn hide_to_tray(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        window.hide().map_err(|e| {
            coded_ctx(
                "settings_hide_window_failed",
                "Failed to hide main window",
                e,
            )
        })?;
    }
    Ok(())
}

#[tauri::command]
pub async fn show_main_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window("main") {
        // Unminimize first — `show()` doesn't restore from minimized on
        // Windows, only from the hidden state. Without this the tray-icon
        // double-click would be a no-op for users who minimized through
        // the title-bar instead of closing.
        let _ = window.unminimize();
        window.show().map_err(|e| {
            coded_ctx(
                "settings_show_window_failed",
                "Failed to show main window",
                e,
            )
        })?;
        let _ = window.set_focus();
    }
    Ok(())
}

#[tauri::command]
pub async fn quit_app(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    // Mark the close as user-confirmed so the `WindowEvent::CloseRequested`
    // hook in `lib::run` lets the destroy proceed even when the saved
    // behavior is "tray" or "ask". Exit is initiated via `app.exit(0)`,
    // which still triggers `RunEvent::Exit` and the network shutdown.
    state
        .quit_confirmed
        .store(true, std::sync::atomic::Ordering::Release);
    app.exit(0);
    Ok(())
}

#[tauri::command]
pub async fn set_close_behavior(
    state: tauri::State<'_, AppState>,
    behavior: String,
) -> Result<(), String> {
    let normalized = behavior.trim().to_ascii_lowercase();
    if normalized != "ask" && normalized != "tray" && normalized != "exit" {
        return Err(coded(
            "settings_close_behavior_invalid",
            "Close behavior must be 'ask', 'tray', or 'exit'",
        ));
    }
    let _settings_save_guard = state.settings_save_lock.lock().await;
    // Persist before committing the in-memory change (see update_settings) so
    // a failed write can't leave the live close-behavior diverged from disk.
    let (new_settings, save_data) = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings.close_to_tray_behavior = normalized.clone();
        new_settings.settings_revision = config.settings.settings_revision.saturating_add(1);
        let data = config.prepare_save_settings(&new_settings).map_err(|e| {
            coded_ctx(
                "settings_serialize_failed",
                "Failed to serialize settings",
                e,
            )
        })?;
        (new_settings, data)
    };
    let (data, tmp, final_path) = save_data;
    tokio::task::spawn_blocking(move || {
        crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path)
    })
    .await
    .map_err(|e| coded_ctx("settings_save_failed", "Save failed", e))?
    .map_err(|e| coded_ctx("settings_save_failed", "Save failed", e))?;
    {
        let mut config = state.config.write().await;
        config.settings = new_settings;
    }
    *state.close_behavior.write() = normalized;
    Ok(())
}

/// Official Ember project website (GitHub Pages).
const EMBER_WEBSITE_URL: &str = "https://untaimed18.github.io/Ember-P2P/";

/// Open the Ember website in the user's default browser.
///
/// The URL is hardcoded so the frontend cannot redirect this command at an
/// arbitrary destination.
#[tauri::command]
pub async fn open_ember_website() -> Result<(), String> {
    opener::open(EMBER_WEBSITE_URL).map_err(|e| {
        coded_ctx(
            "settings_open_website_failed",
            "Failed to open the Ember website",
            e,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_pass_validation() {
        // Config load now re-validates persisted settings and resets to
        // defaults on failure. If the defaults themselves failed validation,
        // every launch would reset the config in a loop — assert they don't.
        if let Err(e) = validate_settings(&AppSettings::default()) {
            panic!("AppSettings::default() must satisfy validate_settings, got: {e}");
        }
    }

    #[test]
    fn soft_repair_clamps_ranges_and_enums() {
        let mut settings = AppSettings::default();
        settings.tcp_port = 0;
        settings.max_concurrent_downloads = 999;
        settings.spam_filter_profile = "nope".to_string();
        settings.uss_enabled = true;
        settings.max_upload_speed = 0;
        assert!(soft_repair_settings(&mut settings));
        assert_ne!(settings.tcp_port, 0);
        assert_eq!(settings.max_concurrent_downloads, 50);
        assert_eq!(settings.spam_filter_profile, "balanced");
        assert!(!settings.uss_enabled);
        assert!(validate_settings(&settings).is_ok());
    }

    #[test]
    fn soft_repair_forces_friend_session_encryption_on() {
        let mut settings = AppSettings::default();
        settings.friend_session_encryption = false;
        assert!(soft_repair_settings(&mut settings));
        assert!(settings.friend_session_encryption);
    }

    #[test]
    fn uss_requires_nonzero_upload_limit() {
        let mut settings = AppSettings::default();
        settings.uss_enabled = true;
        settings.max_upload_speed = 0;
        let err = validate_settings(&settings).expect_err("USS + unlimited must fail");
        assert!(
            err.contains("settings_uss_requires_upload_limit"),
            "unexpected error: {err}"
        );

        settings.max_upload_speed = 512 * 1024;
        assert!(validate_settings(&settings).is_ok());

        settings.uss_enabled = false;
        settings.max_upload_speed = 0;
        assert!(validate_settings(&settings).is_ok());
    }

    #[test]
    fn shared_folder_overlap_uses_component_boundaries() {
        assert!(shared_paths_overlap(
            std::path::Path::new("root/media"),
            std::path::Path::new("root/media/movies"),
        ));
        assert!(!shared_paths_overlap(
            std::path::Path::new("root/media"),
            std::path::Path::new("root/media-old"),
        ));
    }

    #[test]
    fn dedupe_overlapping_shared_folders_prefers_parents() {
        let (deduped, changed) = dedupe_overlapping_shared_folders(vec![
            "root/media/movies".into(),
            "root/media".into(),
            "root/media".into(),
            "root/other".into(),
            "root/media/tv".into(),
        ]);
        assert!(changed);
        assert_eq!(
            deduped,
            vec!["root/media".to_string(), "root/other".to_string()]
        );

        let (same, unchanged) =
            dedupe_overlapping_shared_folders(vec!["a/b".into(), "c/d".into()]);
        assert!(!unchanged);
        assert_eq!(same, vec!["a/b".to_string(), "c/d".to_string()]);
    }
}
