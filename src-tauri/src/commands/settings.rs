use tauri::{Emitter, Manager};
use tauri_plugin_dialog::DialogExt;
use tracing::{info, warn};

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::network::kad::bootstrap;
use crate::network::kad::ip_filter::count_valid_entries;
use crate::network::NetworkCommand;
use crate::types::AppSettings;

const NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";
/// Official mirror only ships the zip nowadays; the bare `.dat` URL 404s
/// (which made the first-run wizard IP-filter step always fail).
const IPFILTER_ARCHIVE_URL: &str = "https://upd.emule-security.org/ipfilter.zip";
const IPFILTER_MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;

#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettingsUpdateOutcome {
    Applied,
    RestartRequired,
    Deferred,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSettingsResult {
    pub outcome: SettingsUpdateOutcome,
    pub settings: AppSettings,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveApplyOutcome {
    Applied,
    Deferred,
    Failed,
}

fn ip_filter_outcome_from_ack(ack: Option<Result<(), String>>) -> LiveApplyOutcome {
    match ack {
        Some(Ok(())) => LiveApplyOutcome::Applied,
        Some(Err(_)) => LiveApplyOutcome::Failed,
        None => LiveApplyOutcome::Deferred,
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodesDatDownloadResult {
    pub outcome: LiveApplyOutcome,
    pub parsed_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_count: Option<usize>,
    pub byte_count: usize,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpFilterDownloadResult {
    pub outcome: LiveApplyOutcome,
    pub entry_count: usize,
    pub byte_count: usize,
}

pub(crate) fn persist_with_root_transaction(
    registry: std::sync::Arc<crate::security::filesystem::ApprovedRootRegistry>,
    configured_roots: &[String],
    explicit_additions: &[String],
    reapprovals: &[String],
    persist_settings: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut update = registry
        .prepare_update(configured_roots, explicit_additions, reapprovals)
        .map_err(|error| anyhow::anyhow!("prepare approved roots: {error}"))?;
    update
        .commit()
        .map_err(|error| anyhow::anyhow!("commit approved roots: {error}"))?;
    if let Err(save_error) = persist_settings() {
        if let Err(rollback_error) = update.rollback() {
            return Err(anyhow::anyhow!(
                "settings persistence failed: {save_error}; approved-root rollback also failed: {rollback_error}"
            ));
        }
        return Err(save_error);
    }
    if let Err(error) = update.finish() {
        tracing::warn!(
            "Settings and approved roots committed, but transaction journal cleanup was deferred: {error}"
        );
    }
    Ok(())
}

/// Fields persisted inside `AppSettings` but owned exclusively by backend
/// workflows. The frontend still receives them in `get_settings` so existing
/// setup/settings forms can round-trip one object, but `update_settings`
/// always restores these values from the authoritative in-memory config.
const BACKEND_OWNED_SETTINGS_FIELDS: &[&str] = &[
    "shared_folders",
    "default_shared_folder_seeded",
    "folder_priorities",
    "pending_share_states",
    "pending_file_priorities",
    "shared_folder_scan_cursors",
    // Historical one-shot marker; the overlay is now always on, but the
    // renderer still must not clear it (it would re-run the migration).
    "ember_default_on_migrated",
    "ember_native_enabled",
];

fn merge_renderer_settings(
    mut renderer: serde_json::Value,
    authoritative: &AppSettings,
) -> Result<AppSettings, String> {
    let renderer_object = renderer.as_object_mut().ok_or_else(|| {
        coded(
            "settings_invalid_update",
            "Settings update must be a JSON object",
        )
    })?;
    let authoritative_value = serde_json::to_value(authoritative).map_err(|error| {
        coded_ctx(
            "settings_serialize_failed",
            "Failed to prepare settings update",
            error,
        )
    })?;
    let authoritative_object = authoritative_value.as_object().ok_or_else(|| {
        coded(
            "settings_serialize_failed",
            "Failed to prepare settings update",
        )
    })?;
    for field in BACKEND_OWNED_SETTINGS_FIELDS {
        if let Some(value) = authoritative_object.get(*field) {
            renderer_object.insert((*field).to_string(), value.clone());
        } else {
            renderer_object.remove(*field);
        }
    }
    serde_json::from_value(renderer).map_err(|error| {
        coded_ctx(
            "settings_invalid_update",
            "Settings update is invalid",
            error,
        )
    })
}

/// Download roots the OS picker handed us this session.
///
/// Changing the download folder grants the sandbox a new root and redirects
/// every future download and `.part` file, so — exactly as with shared folders
/// — the path has to come from a native picker rather than from whatever string
/// the renderer submits. Session-scoped and tiny: a user picks a download
/// folder once, if ever.
fn picked_download_roots() -> &'static std::sync::Mutex<Vec<Vec<String>>> {
    static PICKED: std::sync::OnceLock<std::sync::Mutex<Vec<Vec<String>>>> =
        std::sync::OnceLock::new();
    PICKED.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Remembered in the same normalized form the change check below compares in,
/// so a path can never be authorized and then fail to match itself.
fn remember_picked_download_root(path: &std::path::Path) {
    const MAX_REMEMBERED: usize = 16;
    let key = normalized_path_components(path);
    let mut picked = picked_download_roots()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if picked.contains(&key) {
        return;
    }
    if picked.len() >= MAX_REMEMBERED {
        picked.remove(0);
    }
    picked.push(key);
}

fn download_root_was_picked(path: &std::path::Path) -> bool {
    let key = normalized_path_components(path);
    picked_download_roots()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains(&key)
}

/// Open a trusted native directory picker for the download folder.
///
/// Mirrors `pick_shared_folder`: the renderer never gets to name the path that
/// will be authorized. The selection is returned only so the Settings form and
/// the setup wizard can display it before the user saves.
#[tauri::command]
pub async fn pick_download_folder(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<Option<String>, String> {
    if window.label() != "main" {
        return Err(coded(
            "settings_download_folder_picker_failed",
            "The download folder can only be chosen from the main window",
        ));
    }
    let picker_app = app.clone();
    let selected = tokio::task::spawn_blocking(move || {
        picker_app
            .dialog()
            .file()
            .set_title("Choose where downloads are saved")
            .blocking_pick_folder()
            .map(|folder| {
                folder.into_path().map_err(|error| {
                    coded_ctx(
                        "settings_download_folder_picker_failed",
                        "Invalid selected folder",
                        error,
                    )
                })
            })
            .transpose()
    })
    .await
    .map_err(|error| {
        coded_ctx(
            "settings_download_folder_picker_failed",
            "Folder picker failed",
            error,
        )
    })??;

    let Some(path) = selected else {
        return Ok(None);
    };
    remember_picked_download_root(&path);
    Ok(Some(path.to_string_lossy().into_owned()))
}

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
                warn!("Shared folder cannot be resolved (keeping configured path): {folder} ({e})");
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

fn shared_folder_paths_equal(a: &str, b: &str) -> bool {
    crate::search::index::normalize_path_key(a).trim_end_matches(['/', '\\'])
        == crate::search::index::normalize_path_key(b).trim_end_matches(['/', '\\'])
}

fn shared_folder_changes(
    old_folders: &[String],
    new_folders: &[String],
) -> (Vec<String>, Vec<String>) {
    let removed = old_folders
        .iter()
        .filter(|old| {
            !new_folders
                .iter()
                .any(|new| shared_folder_paths_equal(old, new))
        })
        .cloned()
        .collect();
    let added = new_folders
        .iter()
        .filter(|new| {
            !old_folders
                .iter()
                .any(|old| shared_folder_paths_equal(old, new))
        })
        .cloned()
        .collect();
    (removed, added)
}

fn prune_removed_shared_folder_state(
    settings: &mut AppSettings,
    removed_folders: &[String],
    active_folders: &[String],
) {
    if removed_folders.is_empty() {
        return;
    }
    let is_under_removed_root = |path: &str| {
        removed_folders.iter().any(|root| {
            crate::security::path_matches_dir(path, root)
                && !active_folders
                    .iter()
                    .any(|active| crate::security::path_matches_dir(path, active))
        })
    };

    settings
        .folder_priorities
        .retain(|folder, _| !is_under_removed_root(folder));
    settings
        .pending_share_states
        .retain(|path, _| !is_under_removed_root(path));
    settings
        .pending_file_priorities
        .retain(|path, _| !is_under_removed_root(path));
    settings
        .shared_folder_scan_cursors
        .retain(|folder, _| !is_under_removed_root(folder));
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

    let offers = settings.channel_file_offers.trim().to_ascii_lowercase();
    if offers != crate::types::CHANNEL_FILE_OFFERS_EVERYONE
        && offers != crate::types::CHANNEL_FILE_OFFERS_FRIENDS
        && offers != crate::types::CHANNEL_FILE_OFFERS_NOBODY
    {
        settings.channel_file_offers = crate::types::CHANNEL_FILE_OFFERS_EVERYONE.to_string();
        changed = true;
    } else if offers != settings.channel_file_offers {
        settings.channel_file_offers = offers;
        changed = true;
    }

    // A username stored under the older, looser rule (spaces, punctuation, up
    // to 32 bytes) is not a corrupt config — but `validate_settings` now
    // refuses it, and on load that answer means backup-and-reset of every
    // other setting. Repair it to the closest legal handle instead, and clear
    // it when nothing legal is left: empty is a valid state that makes the
    // Channels page ask for a new one.
    if !settings.channel_username.is_empty()
        && crate::commands::channels::sanitize_channel_username(&settings.channel_username).is_err()
    {
        let repaired: String = settings
            .channel_username
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(crate::commands::channels::CHANNEL_USERNAME_MAX)
            .collect();
        settings.channel_username =
            match crate::commands::channels::sanitize_channel_username(&repaired) {
                Ok(name) => name,
                Err(_) => String::new(),
            };
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
    changed |= clamp_assign(&mut settings.max_download_file_size_gib, 1, 593);
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
    if settings.channel_file_offers != crate::types::CHANNEL_FILE_OFFERS_EVERYONE
        && settings.channel_file_offers != crate::types::CHANNEL_FILE_OFFERS_FRIENDS
        && settings.channel_file_offers != crate::types::CHANNEL_FILE_OFFERS_NOBODY
    {
        return Err(coded(
            "settings_channel_file_offers_invalid",
            "Channel file offers must be 'everyone', 'friends', or 'nobody'",
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
    if !(1..=593).contains(&settings.max_download_file_size_gib) {
        return Err(coded(
            "settings_max_download_file_size_invalid",
            "Max download file size must be between 1 and 593 GiB",
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
    if !settings.channel_username.is_empty() {
        crate::commands::channels::sanitize_channel_username(&settings.channel_username)?;
    }
    let is_filesystem_root = |path: &std::path::Path| {
        path.has_root()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::Normal(_)))
    };
    // Rejected rather than skipped. An empty value used to bypass the whole
    // path-safety block below, then compose the *relative* path `Downloads`
    // against the process CWD, while `lib.rs` skipped both `create_dir_all` and
    // the approved-root registration for it — leaving `open_or_create_approved`
    // with no root to admit and every download failing with nothing to point at.
    // The picker code is reused because an empty value means no folder has been
    // chosen, which is the same remedy.
    if settings.download_folder.is_empty() {
        return Err(coded(
            "settings_download_folder_not_picked",
            "Choose the download folder with Browse before saving",
        ));
    }
    // Braced to keep `path`/`canonical` out of the shared-folder loop below,
    // which binds the same names.
    {
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
    settings: serde_json::Value,
    // Absent for every background/partial save; see the re-approval block below.
    reapprove_download_root: Option<bool>,
) -> Result<UpdateSettingsResult, String> {
    let reapprove_download_root = reapprove_download_root.unwrap_or(false);
    // Serialize the read/merge/write transaction before deserializing the
    // renderer payload. Internal cursor/pending maps can advance without
    // changing the visible settings revision, so reading them before this lock
    // could overwrite newer backend state with a stale renderer echo.
    let _settings_save_guard = state.settings_save_lock.lock().await;
    let old_settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };
    let mut settings = merge_renderer_settings(settings, &old_settings)?;
    settings.spam_filter_profile = settings.spam_filter_profile.trim().to_ascii_lowercase();
    settings.close_to_tray_behavior = settings.close_to_tray_behavior.trim().to_ascii_lowercase();
    settings.channel_file_offers = settings.channel_file_offers.trim().to_ascii_lowercase();
    settings.update_check_frequency = settings.update_check_frequency.trim().to_ascii_lowercase();
    // Not exposed in Settings UI — always keep friend sessions encrypted.
    settings.friend_session_encryption = true;
    // Ember overlay is always on. The Settings / Ember-page switches stay
    // visible but disabled, so a crafted or stale payload cannot turn it off.
    settings.ember_native_enabled = true;
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
    settings.channel_username = settings
        .channel_username
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

    if settings.channel_username != old_settings.channel_username {
        if settings.channel_username.is_empty() {
            if !old_settings.channel_username.is_empty() {
                return Err(coded(
                    "channels_username_required",
                    "Choose a Channel username before creating or joining a room",
                ));
            }
        } else {
            settings.channel_username = crate::commands::channels::claim_username_on_registry(
                &state,
                &settings.channel_username,
            )
            .await?;
        }
    }

    if settings.settings_revision != old_settings.settings_revision {
        return Err(coded(
            "settings_stale_revision",
            "Settings changed in another window or command; reload and apply your changes again",
        ));
    }
    let (removed_shared_folders, added_shared_folders) =
        shared_folder_changes(&old_settings.shared_folders, &settings.shared_folders);
    // Per-folder defaults, pending file intents, and page cursors have no
    // meaning after their root is removed. Prune them in the same durable
    // settings transaction as the root update so they cannot be restored by a
    // later re-add of an unrelated path.
    let active_shared_folders = settings.shared_folders.clone();
    prune_removed_shared_folder_state(
        &mut settings,
        &removed_shared_folders,
        &active_shared_folders,
    );
    settings.settings_revision = old_settings.settings_revision.saturating_add(1);

    let port_changed =
        settings.tcp_port != old_settings.tcp_port || settings.udp_port != old_settings.udp_port;

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
        let mut roots = settings.shared_folders.clone();
        if !settings.download_folder.is_empty() {
            roots.push(settings.download_folder.clone());
        }
        let mut explicit_additions = added_shared_folders.clone();
        if !settings.download_folder.is_empty()
            && normalized_path_components(std::path::Path::new(&settings.download_folder))
                != normalized_path_components(std::path::Path::new(&old_settings.download_folder))
        {
            // Moving the download folder approves a new sandbox root and
            // redirects every future download, so the path must have come from
            // `pick_download_folder`, not from whatever the renderer submitted.
            // `shared_folders` is protected by being backend-owned outright;
            // this one has to stay writable because the form saves it with
            // everything else, so it is provenance that is checked instead.
            // Only a *change* is gated: an unchanged path re-saved by a
            // background caller (the UPnP auto-disable handler persists through
            // here with no user present) never reaches this branch.
            if !download_root_was_picked(std::path::Path::new(&settings.download_folder)) {
                return Err(coded(
                    "settings_download_folder_not_picked",
                    "Choose the download folder with Browse before saving",
                ));
            }
            explicit_additions.push(settings.download_folder.clone());
        }
        let registry = state.approved_roots.clone();
        // A root revoked for an identity mismatch stays unusable until it is
        // re-approved, and the download folder has no other way back:
        // re-picking the same folder is not an addition, so it never reaches
        // `explicit_additions` and every download keeps failing.
        //
        // Deliberately narrow. `reapprove_download_root` is set only by the
        // Settings page's own save button, because `update_settings` is also
        // reached from background paths with no user present — the UPnP
        // auto-disable handler persists through it from a network event — and
        // re-approval grants the sandbox to whatever object now sits at the
        // path. It is also skipped unless something is actually there: a root
        // that is merely offline (unplugged drive, disconnected share) must
        // keep its record, which `build_next` retains on `NotFound`, rather
        // than be re-captured and lost.
        let download_folder = settings.download_folder.clone();
        let (data, tmp, final_path) = save_data;
        tokio::task::spawn_blocking(move || {
            let mut reapprovals = Vec::new();
            if reapprove_download_root
                && !download_folder.is_empty()
                && std::fs::symlink_metadata(&download_folder).is_ok()
                && registry
                    .verify_root(std::path::Path::new(&download_folder))
                    .is_err()
            {
                tracing::info!("Re-approving download folder on an explicit settings save");
                reapprovals.push(download_folder);
            }
            persist_with_root_transaction(
                registry,
                &roots,
                &explicit_additions,
                &reapprovals,
                || crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &final_path),
            )
        })
        .await
        .map_err(|e| coded_ctx("settings_transaction_task_failed", "Save failed", e))?
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

    // Queue the loop-owned runtime settings before releasing the transaction
    // lock, preserving commit order with a concurrent settings save. Root
    // reconciliation below may wait for a scan that persists cursors under
    // this same lock, so it must run only after the durable transaction ends.
    let runtime_update_deferred = match state.network_tx.try_send(NetworkCommand::UpdateSettings {
        settings: settings.clone(),
    }) {
        Ok(()) => false,
        Err(e) => {
            tracing::warn!(
                "Settings saved to disk, but live network update was dropped (channel full): {e}"
            );
            true
        }
    };
    drop(_settings_save_guard);

    if !removed_shared_folders.is_empty() || !added_shared_folders.is_empty() {
        // Revoke removed roots from the upload path immediately — the spawned
        // reconcile repeats this, but the guarantee must hold before this
        // command returns.
        {
            let active = state.config.read().await.settings.shared_folders.clone();
            *state.upload_shared_folders.write().await = active;
        }
        // Reconcile in the background: it queues behind `scan_coordination`,
        // which a first-run library hash pass can hold for hours. Blocking the
        // command here froze the Settings save UI for that whole time (and a
        // user retry then failed with `settings_stale_revision`). The task
        // re-reads current config under the lock, so a later save is safe.
        let reconcile_app = app.clone();
        tauri::async_runtime::spawn(async move {
            let state = reconcile_app.state::<AppState>();
            crate::commands::sharing::reconcile_shared_folder_roots(
                &reconcile_app,
                &state,
                &removed_shared_folders,
                &added_shared_folders,
            )
            .await;
        });
    }

    if runtime_update_deferred {
        return Ok(UpdateSettingsResult {
            outcome: SettingsUpdateOutcome::Deferred,
            settings,
        });
    }

    let outcome = if port_changed {
        SettingsUpdateOutcome::RestartRequired
    } else {
        SettingsUpdateOutcome::Applied
    };
    Ok(UpdateSettingsResult { outcome, settings })
}

#[tauri::command]
pub async fn download_nodes_dat(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<NodesDatDownloadResult, String> {
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

    let parsed_count = contacts.len();
    let byte_count = bytes.len();

    // Inject contacts into the running network. The file is already
    // safely on disk above, so a saturated channel here should not
    // surface as a failed save — bootstrap will pick the contacts up
    // on the next launch (or as soon as the network drains the queue
    // and we manually re-trigger). Mirrors the "saved but not applied
    // live" message style used by `update_settings`.
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let (outcome, applied_count) = match state
        .network_tx
        .try_send(NetworkCommand::BootstrapContacts { contacts, tx })
    {
        Ok(()) => match tokio::time::timeout(std::time::Duration::from_secs(5), &mut rx).await {
            Ok(Ok(count)) => (LiveApplyOutcome::Applied, Some(count)),
            Ok(Err(_)) => {
                tracing::warn!(
                    "nodes.dat was saved, but the network task did not confirm live contact injection"
                );
                (LiveApplyOutcome::Deferred, None)
            }
            Err(_) => {
                tracing::warn!("nodes.dat was saved, but live contact injection is still pending");
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let Ok(applied_count) = rx.await else {
                        return;
                    };
                    let _ = app.emit(
                        "nodes-bootstrap-result",
                        serde_json::json!({
                            "outcome": "applied",
                            "parsed_count": parsed_count,
                            "applied_count": applied_count,
                            "byte_count": byte_count,
                        }),
                    );
                });
                (LiveApplyOutcome::Deferred, None)
            }
        },
        Err(e) => {
            tracing::warn!(
                "nodes.dat saved to disk, but live bootstrap injection was dropped (channel full): {e}"
            );
            (LiveApplyOutcome::Deferred, None)
        }
    };

    info!("Downloaded nodes.dat with {parsed_count} contacts ({byte_count} bytes)");
    Ok(NodesDatDownloadResult {
        outcome,
        parsed_count,
        applied_count,
        byte_count,
    })
}

#[tauri::command]
pub async fn download_ipfilter(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<IpFilterDownloadResult, String> {
    info!("Downloading ipfilter.zip from {IPFILTER_ARCHIVE_URL}");

    let response = crate::security::fetch_pinned_get(IPFILTER_ARCHIVE_URL)
        .await
        .map_err(|e| coded_ctx("settings_http_request_failed", "HTTP request failed", e))?
        .error_for_status()
        .map_err(|e| coded_ctx("settings_http_error", "HTTP error", e))?;
    if let Some(cl) = response.content_length() {
        if cl > IPFILTER_MAX_RESPONSE_BYTES as u64 {
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
            if body.len() > IPFILTER_MAX_RESPONSE_BYTES {
                return Err(coded("settings_response_too_large", "Response too large"));
            }
        }
        body
    };

    let extracted = tokio::task::spawn_blocking(move || {
        crate::commands::security::extract_ipfilter_from_zip(&bytes)
    })
    .await
    .map_err(|e| {
        coded_ctx(
            "settings_extraction_task_failed",
            "Extraction task failed",
            e,
        )
    })??;

    // Validate before anything on disk or in memory is touched. Without
    // this, a dead mirror serving an HTML error page (still a 200, so
    // `error_for_status` doesn't catch it) would sail straight through to
    // `atomic_write` + `ReloadIpFilter`, which faithfully replaces the
    // working filter with an empty one — silently wiping out the user's
    // protection while this command still reports success. See
    // `commands::security::download_and_load_ipfilter` for the same fix.
    let (extracted, entry_count) = tokio::task::spawn_blocking(move || {
        let entry_count = count_valid_entries(&extracted, "dat");
        (extracted, entry_count)
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
        let write_bytes = extracted.clone();
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

    let byte_count = extracted.len();

    // Match the Security-page download: first-run wizard should leave the
    // filter enabled, not just drop a dormant file on disk.
    crate::commands::security::persist_ip_filter_enabled(&state).await?;

    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let outcome = match state.network_tx.try_send(NetworkCommand::ReloadIpFilter {
        path: filter_path,
        tx: Some(tx),
    }) {
        Ok(()) => match tokio::time::timeout(std::time::Duration::from_secs(5), &mut rx).await {
            Ok(Ok(ack)) => {
                if let Err(error) = &ack {
                    tracing::warn!("ipfilter.dat was saved, but live reload failed: {error}");
                }
                ip_filter_outcome_from_ack(Some(ack))
            }
            Ok(Err(_)) => {
                tracing::warn!(
                    "ipfilter.dat was saved, but the network task did not confirm live reload"
                );
                ip_filter_outcome_from_ack(None)
            }
            Err(_) => {
                tracing::warn!("ipfilter.dat was saved, but live reload is still pending");
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let outcome = match rx.await {
                        Ok(Ok(())) => "applied",
                        Ok(Err(_)) => "failed",
                        Err(_) => return,
                    };
                    let _ = app.emit(
                        "ipfilter-reload-result",
                        serde_json::json!({
                            "outcome": outcome,
                            "entry_count": entry_count,
                            "byte_count": byte_count,
                        }),
                    );
                });
                ip_filter_outcome_from_ack(None)
            }
        },
        Err(error) => {
            tracing::warn!("ipfilter.dat was saved, but live reload was not queued: {error}");
            ip_filter_outcome_from_ack(None)
        }
    };
    info!("Downloaded ipfilter.dat ({byte_count} bytes, {entry_count} entries)");
    Ok(IpFilterDownloadResult {
        outcome,
        entry_count,
        byte_count,
    })
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
pub fn hide_to_tray(app: tauri::AppHandle) -> Result<(), String> {
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
pub fn show_main_window(app: tauri::AppHandle) -> Result<(), String> {
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
pub fn quit_app(app: tauri::AppHandle, state: tauri::State<'_, AppState>) -> Result<(), String> {
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

/// Consume a close request that arrived before the frontend listener was
/// ready. `swap(false)` makes the handoff one-shot while allowing a later
/// native close to set the latch again.
#[tauri::command]
pub fn take_pending_close_request(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    Ok(state
        .pending_close_request
        .swap(false, std::sync::atomic::Ordering::AcqRel))
}

/// Consume the "we turned the Ember overlay on for you" notice, if startup
/// raised one. One-shot, like the close-request latch: the config migration
/// behind it has already been written and never runs again, so the notice has
/// exactly one chance to reach the user.
#[tauri::command]
pub fn take_pending_ember_default_on_notice(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    Ok(state
        .pending_ember_default_on_notice
        .swap(false, std::sync::atomic::Ordering::AcqRel))
}

/// Consume the "staged restore failed or is still pending" notice, if
/// startup raised one. One-shot latch, same reason as the Ember-default-on
/// notice: the condition is already on disk and an event fired before the
/// webview is listening would never be shown.
#[tauri::command]
pub fn take_pending_restore_failed_notice(
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    Ok(state
        .pending_restore_failed_notice
        .swap(false, std::sync::atomic::Ordering::AcqRel))
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

/// The official site, for copying. Same constant [`open_ember_website`] opens
/// so the clipboard and the browser cannot drift.
#[tauri::command]
pub fn get_ember_website_url() -> String {
    EMBER_WEBSITE_URL.to_string()
}

/// Where `ember.log` and its rotated copies live.
///
/// Resolved here rather than taken from the renderer, so neither this nor
/// [`open_log_folder`] can be pointed somewhere else. Shown as text as well as
/// opened: a bug report needs the path even when the file manager will not
/// launch, and a tester on a locked-down machine can still get there by hand.
#[tauri::command]
pub fn get_log_folder_path() -> String {
    crate::storage::paths::resolve_data_dir()
        .join("logs")
        .to_string_lossy()
        .into_owned()
}

/// Reveal the log folder in the system file manager.
///
/// Logs are pseudonymised — IPs, paths, hashes and search text are replaced
/// with tokens — unless `EMBER_VERBOSE_DIAGNOSTICS` was set for the session,
/// which stays env-only precisely so this button cannot produce a file that is
/// unsafe to send anyone.
#[tauri::command]
pub async fn open_log_folder() -> Result<(), String> {
    let dir = crate::storage::paths::resolve_data_dir().join("logs");
    // Created rather than reported missing: file logging makes this on startup,
    // but if that failed then an empty folder still answers "where do the logs
    // go" better than an error the user cannot act on.
    std::fs::create_dir_all(&dir).map_err(|e| {
        coded_ctx(
            "settings_open_logs_failed",
            "Failed to open the log folder",
            e,
        )
    })?;
    opener::open(&dir).map_err(|e| {
        coded_ctx(
            "settings_open_logs_failed",
            "Failed to open the log folder",
            e,
        )
    })
}

/// Longest share caption the frontend may send. Tweet-sized; anything larger
/// is not a caption, it is a way to stuff a query string.
const EMBER_SHARE_TEXT_MAX: usize = 280;

fn percent_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Intent URL for a named share target. The site is always
/// [`EMBER_WEBSITE_URL`]; `target` is an allowlist, not a URL.
fn ember_share_intent_url(target: &str, text: &str) -> Result<String, String> {
    if text.len() > EMBER_SHARE_TEXT_MAX {
        return Err(coded(
            "settings_share_text_too_long",
            "Share text is too long",
        ));
    }
    if text.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(coded(
            "settings_share_text_invalid",
            "Share text contains invalid characters",
        ));
    }
    let url_q = percent_encode_query(EMBER_WEBSITE_URL);
    let text_q = percent_encode_query(text);
    let intent = match target {
        "x" => format!("https://x.com/intent/tweet?url={url_q}&text={text_q}"),
        "facebook" => format!("https://www.facebook.com/sharer/sharer.php?u={url_q}"),
        "reddit" => format!("https://www.reddit.com/submit?url={url_q}&title={text_q}"),
        "bluesky" => format!("https://bsky.app/intent/compose?text={text_q}%20{url_q}"),
        "linkedin" => format!("https://www.linkedin.com/sharing/share-offsite/?url={url_q}"),
        "telegram" => format!("https://t.me/share/url?url={url_q}&text={text_q}"),
        "whatsapp" => format!("https://api.whatsapp.com/send?text={text_q}%20{url_q}"),
        "email" => {
            let body_q = percent_encode_query(&format!("{text}\n\n{EMBER_WEBSITE_URL}"));
            format!("mailto:?subject={text_q}&body={body_q}")
        }
        _ => {
            return Err(coded(
                "settings_unknown_share_target",
                "Unknown share target",
            ))
        }
    };
    Ok(intent)
}

/// Open a share sheet for the official Ember website in the default browser
/// (or the mail client, for email).
///
/// `target` is a name (`x`, `facebook`, …), never a URL. The site itself is
/// the same hardcoded constant [`open_ember_website`] uses, so a compromised
/// renderer cannot point this at an arbitrary host.
#[tauri::command]
pub async fn open_ember_share(target: String, text: String) -> Result<(), String> {
    let intent = ember_share_intent_url(&target, &text)?;
    opener::open(&intent).map_err(|e| {
        coded_ctx(
            "settings_open_share_failed",
            "Failed to open the share link",
            e,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ember_share_intents_stay_on_allowlisted_hosts_and_the_official_site() {
        let text = "Ember P2P";
        let encoded_site = percent_encode_query(EMBER_WEBSITE_URL);

        let x = ember_share_intent_url("x", text).unwrap();
        assert!(x.starts_with("https://x.com/intent/tweet?"));
        assert!(x.contains(&encoded_site));

        let facebook = ember_share_intent_url("facebook", text).unwrap();
        assert!(facebook.starts_with("https://www.facebook.com/sharer/sharer.php?"));
        assert!(facebook.contains(&encoded_site));

        let reddit = ember_share_intent_url("reddit", text).unwrap();
        assert!(reddit.starts_with("https://www.reddit.com/submit?"));
        assert!(reddit.contains(&encoded_site));

        let bluesky = ember_share_intent_url("bluesky", text).unwrap();
        assert!(bluesky.starts_with("https://bsky.app/intent/compose?"));
        assert!(bluesky.contains(&encoded_site));

        let linkedin = ember_share_intent_url("linkedin", text).unwrap();
        assert!(linkedin.starts_with("https://www.linkedin.com/sharing/share-offsite/?"));
        assert!(linkedin.contains(&encoded_site));

        let telegram = ember_share_intent_url("telegram", text).unwrap();
        assert!(telegram.starts_with("https://t.me/share/url?"));
        assert!(telegram.contains(&encoded_site));

        let whatsapp = ember_share_intent_url("whatsapp", text).unwrap();
        assert!(whatsapp.starts_with("https://api.whatsapp.com/send?"));
        assert!(whatsapp.contains(&encoded_site));

        let email = ember_share_intent_url("email", text).unwrap();
        assert!(email.starts_with("mailto:?"));
        assert!(email.contains(&encoded_site));

        let encoded_text = percent_encode_query(text);
        assert!(x.contains(&encoded_text), "X caption must be encoded into the intent");
        assert!(reddit.contains(&encoded_text));
        assert!(bluesky.contains(&encoded_text));
        assert!(telegram.contains(&encoded_text));
        assert!(whatsapp.contains(&encoded_text));
        assert!(email.contains(&encoded_text));
    }

    #[test]
    fn ember_share_encodes_text_so_it_cannot_inject_query_params() {
        let hijack = "hi&url=https://evil.example/";
        let x = ember_share_intent_url("x", hijack).unwrap();
        assert!(
            !x.contains("&url=https://evil.example/"),
            "raw ampersands in caption must not add query parameters"
        );
        assert!(x.contains(&percent_encode_query(hijack)));
        assert!(x.contains(&percent_encode_query(EMBER_WEBSITE_URL)));
    }

    #[test]
    fn ember_share_rejects_unknown_targets_and_overlong_text() {
        assert!(ember_share_intent_url("https://evil.example/", "hi").is_err());
        assert!(ember_share_intent_url("javascript", "hi").is_err());
        assert!(ember_share_intent_url("X", "hi").is_err(), "allowlist is lowercase");
        let too_long = "n".repeat(EMBER_SHARE_TEXT_MAX + 1);
        assert!(ember_share_intent_url("x", &too_long).is_err());
        assert!(ember_share_intent_url("x", "ok\0no").is_err());
    }

    #[test]
    fn get_ember_website_url_is_the_hardcoded_site() {
        assert_eq!(get_ember_website_url(), EMBER_WEBSITE_URL);
        assert!(EMBER_WEBSITE_URL.starts_with("https://"));
    }

    #[test]
    fn config_write_failure_restores_exact_approved_root_snapshot() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-transaction-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let data = base.join("data");
        let old_root = base.join("old");
        let new_root = base.join("new");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&old_root).unwrap();
        std::fs::create_dir_all(&new_root).unwrap();
        let old = old_root.to_string_lossy().into_owned();
        let new = new_root.to_string_lossy().into_owned();
        let registry = crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&old),
        )
        .unwrap();
        let state_path = data.join("approved_roots.json");
        let before = std::fs::read(&state_path).unwrap();

        let error = persist_with_root_transaction(
            registry.clone(),
            std::slice::from_ref(&new),
            std::slice::from_ref(&new),
            &[],
            || anyhow::bail!("injected config write failure"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("injected config write failure"));
        assert!(registry.verify_root(&old_root).is_ok());
        assert!(registry.verify_root(&new_root).is_err());
        assert_eq!(std::fs::read(&state_path).unwrap(), before);
        assert!(!data.join("approved_roots.transaction.json").exists());

        let mut interrupted = registry
            .prepare_update(std::slice::from_ref(&new), std::slice::from_ref(&new), &[])
            .unwrap();
        interrupted.commit().unwrap();
        drop(interrupted);
        assert!(data.join("approved_roots.transaction.json").exists());
        let recovered = crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&old),
        )
        .unwrap();
        assert!(recovered.verify_root(&old_root).is_ok());
        assert!(recovered.verify_root(&new_root).is_err());
        assert!(!data.join("approved_roots.transaction.json").exists());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn default_settings_pass_validation() {
        // Config load now re-validates persisted settings and resets to
        // defaults on failure. If the defaults themselves failed validation,
        // every launch would reset the config in a loop — assert they don't.
        if let Err(e) = validate_settings(&AppSettings::default()) {
            panic!("AppSettings::default() must satisfy validate_settings, got: {e}");
        }
    }

    /// Tightening the Channel username to 2–12 alphanumerics made every
    /// handle stored under the old 32-byte rule fail `validate_settings` — and
    /// on load that answer backs up `config.json` and resets *every* setting.
    /// Soft repair has to salvage those instead.
    #[test]
    fn a_legacy_channel_username_is_repaired_not_treated_as_corrupt() {
        for (stored, expected) in [
            ("Ada Lovelace", "AdaLovelace"),
            ("ada_lovelace_the_first", "adalovelacet"),
            ("Ada!", "Ada"),
            ("!!", ""),
            ("日本語", ""),
        ] {
            let mut settings = AppSettings {
                channel_username: stored.to_string(),
                ..AppSettings::default()
            };
            assert!(
                soft_repair_settings(&mut settings),
                "{stored:?} needs repairing"
            );
            assert_eq!(settings.channel_username, expected, "repairing {stored:?}");
            validate_settings(&settings)
                .unwrap_or_else(|e| panic!("repaired {stored:?} must load: {e}"));
        }
    }

    /// A handle that already obeys the rule must survive untouched, or a save
    /// would silently rename the user in every room.
    #[test]
    fn a_valid_channel_username_is_left_alone() {
        let mut settings = AppSettings {
            channel_username: "Ada1".to_string(),
            ..AppSettings::default()
        };
        soft_repair_settings(&mut settings);
        assert_eq!(settings.channel_username, "Ada1");
    }

    /// An empty download folder used to skip the path-safety block instead of
    /// failing it, then compose the relative path `Downloads` against the
    /// process CWD — never created, never registered as an approved root, so
    /// every download failed with nothing to point the user at.
    #[test]
    fn empty_download_folder_is_rejected_not_skipped() {
        let settings = AppSettings {
            download_folder: String::new(),
            ..AppSettings::default()
        };
        let err = validate_settings(&settings).expect_err("an empty download folder must fail");
        assert!(
            err.contains("settings_download_folder_not_picked"),
            "unexpected error: {err}"
        );
    }

    /// The default has to be absolute, or `AppSettings::default()` composes
    /// `completed_dir` against whatever directory the process happens to be in.
    #[test]
    fn default_download_folder_is_absolute() {
        let settings = AppSettings::default();
        assert!(
            std::path::Path::new(&settings.download_folder).is_absolute(),
            "default download folder must be absolute, got {:?}",
            settings.download_folder
        );
        // `Default` derives the seeded shared folder from the same base, so an
        // empty base made this relative too.
        for folder in &settings.shared_folders {
            assert!(
                std::path::Path::new(folder).is_absolute(),
                "default shared folder must be absolute, got {folder:?}"
            );
        }
    }

    #[test]
    fn ipfilter_outcome_requires_successful_reload_ack() {
        assert_eq!(
            ip_filter_outcome_from_ack(Some(Ok(()))),
            LiveApplyOutcome::Applied
        );
        assert_eq!(
            ip_filter_outcome_from_ack(Some(Err("parse failed".into()))),
            LiveApplyOutcome::Failed
        );
        assert_eq!(ip_filter_outcome_from_ack(None), LiveApplyOutcome::Deferred);
    }

    #[test]
    fn soft_repair_clamps_ranges_and_enums() {
        let mut settings = AppSettings {
            tcp_port: 0,
            max_concurrent_downloads: 999,
            spam_filter_profile: "nope".to_string(),
            uss_enabled: true,
            max_upload_speed: 0,
            ..AppSettings::default()
        };
        assert!(soft_repair_settings(&mut settings));
        assert_ne!(settings.tcp_port, 0);
        assert_eq!(settings.max_concurrent_downloads, 50);
        assert_eq!(settings.spam_filter_profile, "balanced");
        assert!(!settings.uss_enabled);
        assert!(validate_settings(&settings).is_ok());
    }

    #[test]
    fn soft_repair_forces_friend_session_encryption_on() {
        let mut settings = AppSettings {
            friend_session_encryption: false,
            ..AppSettings::default()
        };
        assert!(soft_repair_settings(&mut settings));
        assert!(settings.friend_session_encryption);
    }

    #[test]
    fn uss_requires_nonzero_upload_limit() {
        let mut settings = AppSettings {
            uss_enabled: true,
            max_upload_speed: 0,
            ..AppSettings::default()
        };
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

        let (same, unchanged) = dedupe_overlapping_shared_folders(vec!["a/b".into(), "c/d".into()]);
        assert!(!unchanged);
        assert_eq!(same, vec!["a/b".to_string(), "c/d".to_string()]);
    }

    #[test]
    fn shared_folder_settings_change_prunes_removed_root_state() {
        let old_folders = vec!["/library/removed".to_string(), "/library/kept".to_string()];
        let new_folders = vec!["/library/kept".to_string(), "/library/added".to_string()];
        let (removed, added) = shared_folder_changes(&old_folders, &new_folders);
        assert_eq!(removed, vec!["/library/removed"]);
        assert_eq!(added, vec!["/library/added"]);

        let mut settings = AppSettings::default();
        settings
            .folder_priorities
            .insert("/library/removed".to_string(), "high".to_string());
        settings.folder_priorities.insert(
            "/library/removed/stale-child".to_string(),
            "release".to_string(),
        );
        settings
            .folder_priorities
            .insert("/library/kept".to_string(), "low".to_string());
        settings
            .pending_share_states
            .insert("/library/removed/pending.bin".to_string(), false);
        settings
            .pending_share_states
            .insert("/library/kept/pending.bin".to_string(), true);
        settings.pending_file_priorities.insert(
            "/library/removed/pending.bin".to_string(),
            "release".to_string(),
        );
        settings
            .shared_folder_scan_cursors
            .insert("/library/removed".to_string(), "cursor".to_string());
        settings.shared_folder_scan_cursors.insert(
            "/library/removed/stale-child".to_string(),
            "cursor".to_string(),
        );

        prune_removed_shared_folder_state(&mut settings, &removed, &new_folders);

        assert_eq!(settings.folder_priorities.len(), 1);
        assert!(settings.folder_priorities.contains_key("/library/kept"));
        assert_eq!(settings.pending_share_states.len(), 1);
        assert!(settings
            .pending_share_states
            .contains_key("/library/kept/pending.bin"));
        assert!(settings.pending_file_priorities.is_empty());
        assert!(settings.shared_folder_scan_cursors.is_empty());
    }

    #[test]
    fn parent_to_child_root_change_preserves_child_scoped_state() {
        let old_folders = vec!["/library/parent".to_string()];
        let new_folders = vec!["/library/parent/child".to_string()];
        let (removed, added) = shared_folder_changes(&old_folders, &new_folders);
        assert_eq!(removed, old_folders);
        assert_eq!(added, new_folders);

        let mut settings = AppSettings::default();
        settings
            .folder_priorities
            .insert("/library/parent/child".to_string(), "release".to_string());
        settings
            .folder_priorities
            .insert("/library/parent/other".to_string(), "low".to_string());
        settings
            .pending_share_states
            .insert("/library/parent/child/pending.bin".to_string(), false);
        settings
            .pending_share_states
            .insert("/library/parent/other/pending.bin".to_string(), false);
        settings.pending_file_priorities.insert(
            "/library/parent/child/pending.bin".to_string(),
            "high".to_string(),
        );
        settings.shared_folder_scan_cursors.insert(
            "/library/parent/child".to_string(),
            "child-cursor".to_string(),
        );

        prune_removed_shared_folder_state(&mut settings, &removed, &new_folders);

        assert!(settings
            .folder_priorities
            .contains_key("/library/parent/child"));
        assert!(!settings
            .folder_priorities
            .contains_key("/library/parent/other"));
        assert!(settings
            .pending_share_states
            .contains_key("/library/parent/child/pending.bin"));
        assert!(!settings
            .pending_share_states
            .contains_key("/library/parent/other/pending.bin"));
        assert!(settings
            .pending_file_priorities
            .contains_key("/library/parent/child/pending.bin"));
        assert!(settings
            .shared_folder_scan_cursors
            .contains_key("/library/parent/child"));
    }

    #[test]
    fn renderer_settings_cannot_replace_backend_owned_fields() {
        let mut authoritative = AppSettings {
            shared_folders: vec!["/trusted/share".into()],
            default_shared_folder_seeded: true,
            ..AppSettings::default()
        };
        authoritative
            .folder_priorities
            .insert("/trusted/share".into(), "high".into());
        authoritative
            .pending_share_states
            .insert("/trusted/share/pending.bin".into(), false);
        authoritative
            .pending_file_priorities
            .insert("/trusted/share/pending.bin".into(), "release".into());
        authoritative
            .shared_folder_scan_cursors
            .insert("/trusted/share".into(), "cursor-7".into());

        let mut renderer = serde_json::to_value(&authoritative).unwrap();
        let object = renderer.as_object_mut().unwrap();
        object.insert("nickname".into(), serde_json::json!("Allowed change"));
        object.insert(
            "shared_folders".into(),
            serde_json::json!(["/renderer/injected"]),
        );
        object.insert(
            "default_shared_folder_seeded".into(),
            serde_json::json!(false),
        );
        object.insert(
            "folder_priorities".into(),
            serde_json::json!({"/renderer/injected": "low"}),
        );
        object.insert(
            "pending_share_states".into(),
            serde_json::json!({"/renderer/injected/file": true}),
        );
        object.insert(
            "pending_file_priorities".into(),
            serde_json::json!({"/renderer/injected/file": "high"}),
        );
        object.insert(
            "shared_folder_scan_cursors".into(),
            serde_json::json!({"/renderer/injected": "stolen"}),
        );

        let merged = merge_renderer_settings(renderer, &authoritative).unwrap();
        assert_eq!(merged.nickname, "Allowed change");
        assert_eq!(merged.shared_folders, authoritative.shared_folders);
        assert_eq!(
            merged.default_shared_folder_seeded,
            authoritative.default_shared_folder_seeded
        );
        assert_eq!(merged.folder_priorities, authoritative.folder_priorities);
        assert_eq!(
            merged.pending_share_states,
            authoritative.pending_share_states
        );
        assert_eq!(
            merged.pending_file_priorities,
            authoritative.pending_file_priorities
        );
        assert_eq!(
            merged.shared_folder_scan_cursors,
            authoritative.shared_folder_scan_cursors
        );
    }
}
