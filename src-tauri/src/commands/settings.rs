use tauri::Manager;
use tracing::info;

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::network::kad::bootstrap;
use crate::network::NetworkCommand;
use crate::types::AppSettings;

const NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";
const IPFILTER_URL: &str = "https://emuling.gitlab.io/ipfilter.dat";

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
    let blocked_segments: &[&str] = &[
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        ".ssh",
        ".gnupg",
        "etc",
        "usr",
        "bin",
        "sbin",
        "var",
        "root",
        "tmp",
        "temp",
        "proc",
        "sys",
        "dev",
    ];
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
                    let seg_lower = seg.to_string_lossy().to_lowercase();
                    if blocked_segments.contains(&seg_lower.as_str()) {
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
        // Scan the literal path AND (best-effort) its canonical form. A
        // junction/symlink can point a benign-looking folder at a blocked
        // system directory; canonicalizing resolves the reparse point so the
        // segment check can't be bypassed (mirrors the download_folder branch
        // above and the canonicalize-first check in `add_shared_folder`). A
        // not-yet-created folder won't canonicalize — fall back to literal.
        let canonical = path.canonicalize().ok();
        let scan_paths = std::iter::once(path.to_path_buf()).chain(canonical);
        for scan_path in scan_paths {
            for component in scan_path.components() {
                if let std::path::Component::Normal(seg) = component {
                    let seg_lower = seg.to_string_lossy().to_lowercase();
                    if blocked_segments.contains(&seg_lower.as_str()) {
                        return Err(coded_ctx(
                            "settings_shared_folder_system_dir",
                            "Cannot share system directory",
                            folder,
                        ));
                    }
                    if seg_lower == "appdata" {
                        let rest: String = scan_path
                            .components()
                            .skip_while(|c| {
                                if let std::path::Component::Normal(s) = c {
                                    s.to_string_lossy().to_lowercase() != "appdata"
                                } else {
                                    true
                                }
                            })
                            .skip(1)
                            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
                            .collect::<Vec<_>>()
                            .join("/");
                        if rest.starts_with("local/temp") || rest.starts_with("local\\temp") {
                            return Err(coded_ctx(
                                "settings_shared_folder_system_dir",
                                "Cannot share system directory",
                                folder,
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn update_settings(
    state: tauri::State<'_, AppState>,
    settings: AppSettings,
) -> Result<String, String> {
    let mut settings = settings;
    settings.spam_filter_profile = settings.spam_filter_profile.trim().to_ascii_lowercase();
    settings.close_to_tray_behavior = settings.close_to_tray_behavior.trim().to_ascii_lowercase();
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
    validate_settings(&settings)?;

    let old_settings = {
        let config = state.config.read().await;
        config.settings.clone()
    };

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

    // Settings are already persisted to disk above; the network task
    // only needs the new values to apply them at runtime. If the
    // command channel is briefly saturated we'd rather log a warning
    // than fail the whole save — the user's choices are already on
    // disk and the network will pick them up at the next restart (or
    // the next `UpdateSettings` push). Returning `Err` here used to
    // make the UI show "save failed" even though the save succeeded.
    if let Err(e) = state.network_tx.try_send(NetworkCommand::UpdateSettings {
        settings: settings.clone(),
    }) {
        tracing::warn!(
            "Settings saved to disk, but live network update was dropped (channel full): {e}"
        );
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
    let line_count = bytes.iter().filter(|&&b| b == b'\n').count();

    let reload_ok = state
        .network_tx
        .try_send(NetworkCommand::ReloadIpFilter { path: filter_path })
        .is_ok();

    let msg = if reload_ok {
        format!(
            "Downloaded ipfilter.dat ({byte_count} bytes, ~{line_count} entries) — reloading filter now"
        )
    } else {
        format!(
            "Downloaded ipfilter.dat ({byte_count} bytes, ~{line_count} entries) — network busy, filter will load on restart"
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
    // Persist before committing the in-memory change (see update_settings) so
    // a failed write can't leave the live close-behavior diverged from disk.
    let (new_settings, save_data) = {
        let config = state.config.read().await;
        let mut new_settings = config.settings.clone();
        new_settings.close_to_tray_behavior = normalized.clone();
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
}
