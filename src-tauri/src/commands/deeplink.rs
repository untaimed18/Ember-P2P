use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use tauri::{AppHandle, Emitter, Manager};

use crate::app_state::{AppState, PendingDeepLink};
use crate::commands::errors::{coded, coded_ctx};
use crate::network::ed2k::collection::Collection;

/// Upper bound on a single buffered deep-link payload. Real ed2k links and
/// collection paths are well under this; anything larger is almost certainly
/// junk and rejected before it reaches the buffer.
const MAX_PAYLOAD_LEN: usize = 8192;
/// Pending deep-link identifiers are opaque, app-generated tokens. Bound an
/// IPC-supplied id before using it as a lookup key so arbitrary webview input
/// cannot turn the durable queue lookup into an unbounded allocation/logging
/// surface.
const MAX_PENDING_ID_LEN: usize = 128;

/// Cap on the pending buffer so a flood of links (or a misbehaving caller)
/// can't grow it without bound before the frontend drains it.
const MAX_PENDING: usize = 256;

/// Largest `.emulecollection` we'll read when opened via the OS file
/// association. Mirrors the spirit of the binary loader's own entry cap.
const MAX_COLLECTION_BYTES: u64 = 32 * 1024 * 1024;
const PENDING_QUEUE_FILE: &str = "pending_deep_links.json";
static NEXT_PENDING_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeepLinkPreview {
    pub kind: String,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub hash: Option<String>,
    /// Untrusted `eh=` digest from the link, shown on confirm so the user can
    /// see it. Never passed to `start_download` — a pasted link must not pin
    /// the BLAKE3 we verify against.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ember: Option<String>,
    pub endpoint: Option<String>,
    pub host: Option<String>,
}

fn ed2k_segments(link: &str) -> Vec<&str> {
    link.get("ed2k://|".len()..)
        .unwrap_or_default()
        .split('|')
        .map(str::trim)
        .filter(|segment| !segment.is_empty() && *segment != "/")
        .collect()
}

fn canonicalize_ed2k_payload(payload: &str) -> String {
    if crate::network::ed2k::hash::looks_like_ed2k_uri(payload) {
        crate::network::ed2k::hash::normalize_ed2k_uri(payload)
    } else {
        payload.trim().to_string()
    }
}

pub(crate) fn preview_deep_link_payload(payload: &str) -> Result<DeepLinkPreview, String> {
    let payload = canonicalize_ed2k_payload(payload);
    let lower = payload.to_ascii_lowercase();
    if lower.starts_with("ed2k://|file|") {
        let info = crate::commands::search::parse_ed2k_link(payload)?;
        return Ok(DeepLinkPreview {
            kind: "file".into(),
            name: Some(crate::security::sanitize_remote_text(&info.name, 8192)),
            size: Some(info.size),
            hash: Some(info.hash.to_ascii_lowercase()),
            ember: info.ember,
            endpoint: None,
            host: None,
        });
    }
    if lower.starts_with("ed2k://|server|") {
        let segments = ed2k_segments(&payload);
        let ip = segments.get(1).copied().unwrap_or_default();
        let port = segments
            .get(2)
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|port| *port > 0)
            .ok_or_else(|| coded("deeplink_terminal_invalid", "Invalid server deep link"))?;
        let ip: std::net::IpAddr = ip
            .parse()
            .map_err(|_| coded("deeplink_terminal_invalid", "Invalid server deep link"))?;
        return Ok(DeepLinkPreview {
            kind: "server".into(),
            name: None,
            size: None,
            hash: None,
            ember: None,
            endpoint: Some(format!("{ip}:{port}")),
            host: None,
        });
    }
    if lower.starts_with("ed2k://|serverlist|") {
        let segments = ed2k_segments(&payload);
        let url = segments.get(1).copied().unwrap_or_default();
        let parsed = url::Url::parse(url)
            .map_err(|_| coded("deeplink_terminal_invalid", "Invalid server-list deep link"))?;
        if parsed.scheme() != "https" {
            return Err(coded(
                "deeplink_terminal_invalid",
                "Server-list links must use HTTPS",
            ));
        }
        let host = parsed
            .host_str()
            .map(|host| crate::security::sanitize_remote_text(host, 255))
            .filter(|host| !host.is_empty())
            .ok_or_else(|| {
                coded(
                    "deeplink_terminal_invalid",
                    "Server-list link has no valid host",
                )
            })?;
        return Ok(DeepLinkPreview {
            kind: "serverList".into(),
            name: None,
            size: None,
            hash: None,
            ember: None,
            // Validated HTTPS URL so the UI does not re-split a browser-encoded
            // payload that still contains `%7C` instead of `|`.
            endpoint: Some(url.to_string()),
            host: Some(host),
        });
    }
    if lower.starts_with("ember3:") || lower.starts_with("ember2:") {
        let code = crate::commands::peers::parse_friend_code(&payload)?;
        return Ok(DeepLinkPreview {
            kind: "friend".into(),
            name: None,
            size: None,
            hash: Some(code.canonical),
            ember: None,
            endpoint: None,
            host: None,
        });
    }
    if lower.starts_with("ember-channel:") {
        let invite = crate::network::ember::channel::ChannelInvite::parse(&payload)
            .ok_or_else(|| coded("deeplink_terminal_invalid", "Invalid channel invite"))?;
        let name = crate::security::sanitize_remote_text(&invite.name, 64);
        return Ok(DeepLinkPreview {
            kind: "channel".into(),
            name: if name.is_empty() { None } else { Some(name) },
            size: None,
            hash: Some(hex::encode(invite.channel_id)),
            // A channel invite carries no file, so there is no `eh=` digest to
            // show. This branch only exists on this line of development, which
            // is why adding the field to the other previews did not cover it.
            ember: None,
            endpoint: None,
            host: None,
        });
    }
    if !lower.starts_with("ed2k://") && lower.ends_with(".emulecollection") {
        if is_network_path(&payload) {
            return Err(coded(
                "deeplink_terminal_invalid",
                "Collections on a network share cannot be opened from a link",
            ));
        }
        let name = std::path::Path::new(&payload)
            .file_name()
            .map(|name| crate::security::sanitize_remote_text(&name.to_string_lossy(), 1024))
            .filter(|name| !name.is_empty());
        return Ok(DeepLinkPreview {
            kind: "collection".into(),
            name,
            size: None,
            hash: None,
            ember: None,
            endpoint: None,
            host: None,
        });
    }
    Err(coded(
        "deeplink_terminal_invalid",
        "Unsupported or malformed deep link",
    ))
}

#[tauri::command]
pub fn preview_deep_link(payload: String) -> Result<DeepLinkPreview, String> {
    if payload.len() > MAX_PAYLOAD_LEN {
        return Err(coded(
            "deeplink_terminal_invalid",
            "Deep link exceeds the maximum length",
        ));
    }
    preview_deep_link_payload(&payload)
}

fn pending_queue_path(app: &AppHandle) -> std::path::PathBuf {
    crate::storage::paths::resolve_data_dir_with_app(app).join(PENDING_QUEUE_FILE)
}

fn persist_pending_queue(path: &Path, entries: &[PendingDeepLink]) -> Result<(), String> {
    let data = serde_json::to_vec(entries).map_err(|e| {
        coded_ctx(
            "deeplink_queue_serialize_failed",
            "Deep-link queue error",
            e,
        )
    })?;
    crate::security::atomic_write(path, &data, true)
        .map_err(|e| coded_ctx("deeplink_queue_save_failed", "Deep-link queue error", e))
}

/// Serializes durable queue writes. Each writer clones the live in-memory
/// queue under this lock so a late dispatch persist cannot overwrite a
/// completed ack.
fn pending_queue_persist_lock() -> &'static parking_lot::Mutex<()> {
    static LOCK: OnceLock<parking_lot::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| parking_lot::Mutex::new(()))
}

/// Persist the current in-memory queue. When `ack_id` is set, the durable
/// snapshot excludes that entry and the in-memory queue is updated only
/// after the write succeeds, so a failed write leaves the entry queued.
fn persist_live_pending_queue(
    app: &AppHandle,
    queue: &parking_lot::Mutex<Vec<PendingDeepLink>>,
    ack_id: Option<&str>,
) -> Result<(), String> {
    persist_live_pending_queue_at(&pending_queue_path(app), queue, ack_id)
}

fn persist_live_pending_queue_at(
    path: &Path,
    queue: &parking_lot::Mutex<Vec<PendingDeepLink>>,
    ack_id: Option<&str>,
) -> Result<(), String> {
    let _persist_guard = pending_queue_persist_lock().lock();
    let snapshot = {
        let pending = queue.lock();
        match ack_id {
            Some(id) => pending
                .iter()
                .filter(|entry| entry.id != id)
                .cloned()
                .collect(),
            None => pending.clone(),
        }
    };
    persist_pending_queue(path, &snapshot)?;
    if let Some(id) = ack_id {
        queue.lock().retain(|entry| entry.id != id);
    }
    Ok(())
}

/// Load a bounded durable queue before `AppState` is managed. Corrupt queues
/// are ignored rather than preventing the application from starting.
pub fn load_pending_queue(app: &AppHandle) -> Vec<PendingDeepLink> {
    let path = pending_queue_path(app);
    let Ok(data) = std::fs::read(&path) else {
        return Vec::new();
    };
    serde_json::from_slice::<Vec<PendingDeepLink>>(&data)
        .map(|entries| entries.into_iter().take(MAX_PENDING).collect())
        .unwrap_or_else(|e| {
            tracing::warn!("Ignoring corrupt persisted deep-link queue: {e}");
            Vec::new()
        })
}

use crate::security::is_network_path;

/// True if `arg` looks like a deep link we should act on: an `ed2k:` URI
/// (including browser-encoded `ed2k://%7Cfile%7C…` forms), an absolute local
/// path ending in `.emulecollection`, or an in-app Ember invite / friend code.
///
/// A relative path is not one the OS hands over for a double-clicked file. It
/// would be opened against the running Ember's working directory, not the
/// launcher's, and it is what is left of a path with spaces after the NSIS
/// installer's relaunch has split it.
pub fn is_deep_link_payload(arg: &str) -> bool {
    let trimmed = arg.trim();
    let lower = trimmed.to_ascii_lowercase();
    crate::network::ed2k::hash::looks_like_ed2k_uri(trimmed)
        || (lower.ends_with(".emulecollection")
            && Path::new(trimmed).is_absolute()
            && !is_network_path(trimmed))
        || lower.starts_with("ember3:")
        || lower.starts_with("ember2:")
        || lower.starts_with("ember-channel:")
}

/// Split an OS drop into the collection files to open and the paths to share.
///
/// A dropped `.emulecollection` means what double-clicking it means, so it
/// takes the same confirmed path a double-click's argv does rather than being
/// shared as an ordinary file. One the deep-link checks refuse (a network
/// path, an overlong one) stays with the drop and is shared as before.
pub fn take_dropped_collections(
    paths: Vec<std::path::PathBuf>,
) -> (Vec<String>, Vec<std::path::PathBuf>) {
    let mut collections = Vec::new();
    let mut rest = Vec::new();
    for path in paths {
        let is_collection = path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("emulecollection"));
        match path.to_str() {
            Some(s) if is_collection && s.len() <= MAX_PAYLOAD_LEN && is_deep_link_payload(s) => {
                collections.push(s.to_string());
            }
            _ => rest.push(path),
        }
    }
    (collections, rest)
}

/// Pull the deep-link payloads out of a process/instance argv.
///
/// `argv[0]` (the executable path) is always skipped, as are empty entries and
/// anything that doesn't look like a link/collection path. The OS passes a
/// clicked `ed2k://` link or a double-clicked `.emulecollection` file as a
/// trailing argument, so a permissive scan over the tail is sufficient and
/// robust against the leading flags some launchers prepend.
pub fn extract_deep_link_payloads(args: &[String]) -> Vec<String> {
    args.iter()
        .skip(1)
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty() && a.len() <= MAX_PAYLOAD_LEN && is_deep_link_payload(a))
        .map(|a| {
            if crate::network::ed2k::hash::looks_like_ed2k_uri(&a) {
                crate::network::ed2k::hash::normalize_ed2k_uri(&a)
            } else {
                a
            }
        })
        .filter(|a| !a.is_empty() && a.len() <= MAX_PAYLOAD_LEN)
        .collect()
}

/// A second launch's argv as that launch had it, from what the Windows
/// single-instance plugin delivers: it joins the arguments with `|` and splits
/// them on `|` again, so a raw `ed2k://|file|…|/` arrives as `ed2k://`,
/// `file`, …. A link left unfinished takes back the pieces after it, up to the
/// next `ed2k:` link. Other platforms deliver argv whole, where no link is
/// unfinished and nothing changes.
///
/// After an `ed2k:` link only another `ed2k:` link may split off: the pieces
/// may be the link's own fields, which whoever wrote the link controls, so a
/// field that reads as a collection path or an invite must not become a
/// payload of its own. That holds after a link that already looks finished
/// too — a browser-encoded `ed2k://%7Cfile%7C…%7C/` can be followed by raw
/// `|` pieces of the same URL. A launch the OS makes for a clicked link or a
/// double-clicked collection carries one payload, so nothing real follows one.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn rejoin_forwarded_args(args: Vec<String>) -> Vec<String> {
    use crate::network::ed2k::hash::looks_like_ed2k_uri;
    let mut rejoined: Vec<String> = Vec::with_capacity(args.len());
    let mut open_link = false;
    let mut after_link = false;
    for (index, piece) in args.into_iter().enumerate() {
        let is_payload = index > 0
            && if after_link {
                looks_like_ed2k_uri(&piece)
            } else {
                is_deep_link_payload(&piece)
            };
        if after_link && !is_payload {
            if open_link {
                if let Some(link) = rejoined.last_mut() {
                    link.push('|');
                    link.push_str(&piece);
                }
            }
            continue;
        }
        after_link = after_link || (is_payload && looks_like_ed2k_uri(&piece));
        open_link = is_payload && ed2k_link_unfinished(&piece);
        rejoined.push(piece);
    }
    rejoined
}

/// Every complete `ed2k:` link ends in `|/`, however its pipes arrived.
#[cfg_attr(not(windows), allow(dead_code))]
fn ed2k_link_unfinished(piece: &str) -> bool {
    use crate::network::ed2k::hash::{looks_like_ed2k_uri, normalize_ed2k_uri};
    looks_like_ed2k_uri(piece) && !normalize_ed2k_uri(piece).ends_with("|/")
}

/// Whether a Linux launch should make itself the `ed2k://` handler, given the
/// desktop entry `xdg-mime` reports for the scheme now.
///
/// Only when nothing handles it, or when the handler is one of Ember's own
/// entries: the one the plugin writes, rewritten so it follows an AppImage
/// that has moved, or the `.deb`'s, whose `Exec` carries no `%u` for the link.
/// The plugin's `register` runs `xdg-mime default`, so claiming on every launch
/// took the scheme back from whichever client the user had chosen since.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn should_claim_scheme(current_default: &str, own_entries: &[&str]) -> bool {
    let current = current_default.trim();
    current.is_empty() || own_entries.contains(&current)
}

/// Register `ed2k://` with the desktop unless another handler already has it.
///
/// Linux has no installer step to do this, unlike NSIS/MSI on Windows.
#[cfg(target_os = "linux")]
pub fn register_scheme_unless_taken(app: &AppHandle) {
    use tauri_plugin_deep_link::DeepLinkExt;
    // The plugin names its entry after the executable, in the same way; the
    // bundler names the package's after the product.
    let bundle_entry = format!(
        "{}.desktop",
        app.config().product_name.as_deref().unwrap_or("Ember")
    );
    let own_handler = match tauri::utils::platform::current_exe() {
        Ok(exe) => match exe.file_name() {
            Some(name) => format!("{}-handler.desktop", name.to_string_lossy()),
            None => return,
        },
        Err(e) => {
            tracing::warn!("Not registering ed2k:// links: no executable path ({e})");
            return;
        }
    };
    // An `xdg-mime` that cannot run reads as "no handler"; `register_all`
    // needs it too, and reports that failure itself.
    let current = std::process::Command::new("xdg-mime")
        .args(["query", "default", "x-scheme-handler/ed2k"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    if !should_claim_scheme(&current, &[own_handler.as_str(), bundle_entry.as_str()]) {
        tracing::info!(
            "Leaving ed2k:// links with {}, the handler already chosen",
            current.trim()
        );
        return;
    }
    if let Err(e) = app.deep_link().register_all() {
        tracing::warn!("Failed to register ed2k:// deep link scheme: {e}");
    }
}

/// Buffer `payloads` for the frontend and emit a wake signal.
///
/// The buffer — not the event payload — is the single source of truth:
/// `list_pending_deep_links` reads it and `ack_pending_deep_link` removes each
/// entry only once its action has completed, so a cold-start link (buffered
/// before any listener exists) and a running-instance link (buffered +
/// signalled) flow through exactly the same path with no risk of
/// double-processing. The main window is also brought forward so a link
/// clicked while Ember is minimised or in the tray produces a visible result.
pub fn dispatch_deep_links(app: &AppHandle, payloads: Vec<String>) {
    if payloads.is_empty() {
        return;
    }

    if let Some(state) = app.try_state::<AppState>() {
        let queue = state.pending_deep_links.clone();
        let mut enqueued = false;
        {
            let mut pending = queue.lock();
            for p in payloads {
                if pending.len() >= MAX_PENDING {
                    tracing::warn!("Dropping deep link; pending buffer full ({MAX_PENDING})");
                    break;
                }
                let sequence = NEXT_PENDING_ID.fetch_add(1, Ordering::Relaxed);
                pending.push(PendingDeepLink {
                    id: format!(
                        "{:x}-{sequence:x}",
                        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
                    ),
                    payload: p,
                });
                enqueued = true;
            }
        }
        if enqueued {
            let app_for_persist = app.clone();
            // Detached: the window proc must return before the fsync completes.
            drop(tauri::async_runtime::spawn_blocking(move || {
                if let Err(error) = persist_live_pending_queue(&app_for_persist, &queue, None) {
                    tracing::warn!("Failed to persist deep-link queue: {error}");
                }
            }));
        }
    } else {
        // AppState isn't managed yet (very early startup). This shouldn't
        // happen because cold-start dispatch runs after `app.manage`, but if
        // it does the link is dropped rather than panicking.
        tracing::warn!("Deep link arrived before AppState was ready; dropping");
        return;
    }

    crate::commands::chat_window::set_chat_window_visible(app, true);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }

    let _ = app.emit("deep-link-received", ());
}

/// Return every pending deep link without removing it. The frontend must call
/// `ack_pending_deep_link` only after the associated action has completed.
#[tauri::command]
pub fn list_pending_deep_links(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PendingDeepLink>, String> {
    Ok(state.pending_deep_links.lock().clone())
}

#[tauri::command]
pub async fn ack_pending_deep_link(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<(), String> {
    {
        let pending = state.pending_deep_links.lock();
        if !pending.iter().any(|entry| entry.id == id) {
            return Ok(());
        }
    }
    let queue = state.pending_deep_links.clone();
    tokio::task::spawn_blocking(move || persist_live_pending_queue(&app, &queue, Some(&id)))
        .await
        .map_err(|e| coded_ctx("deeplink_queue_save_failed", "Deep-link queue error", e))??;
    Ok(())
}

/// Load a collection from a path already authorized by an OS file association
/// or the native file picker.
///
/// Unlike `collections::load_collection` (which constrains the path to the
/// user's shared/download folders because it's driven by an in-app file
/// dialog), a `.emulecollection` opened from the shell can live anywhere
/// (Downloads, Desktop, an email attachment). The user double-clicking the
/// file *is* the authorization, so we drop the folder-containment check and
/// instead lean on extension, regular-file, and size validation.
///
/// This is deliberately not a Tauri command. Exposing a raw unrestricted path
/// to the webview would let injected renderer code use the OS-authorized
/// loader as a filesystem oracle. [`open_pending_collection`] resolves an
/// opaque, server-owned queue id before calling this function.
pub(crate) async fn open_collection_file(path: String) -> Result<Collection, String> {
    const MAX_PATH_LEN: usize = 4 * 1024;
    if path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "collections_path_too_long",
            format!("Path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let p = std::path::PathBuf::from(&path);

    let ext = p
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase());
    if !matches!(ext.as_deref(), Some("emulecollection") | Some("txt")) {
        return Err(coded(
            "collections_invalid_file_extension",
            "File must be a .emulecollection or .txt file",
        ));
    }

    let canonical = tokio::task::spawn_blocking(move || std::fs::canonicalize(&p))
        .await
        .map_err(|e| {
            coded_ctx(
                "collections_canonicalize_task_failed",
                "Canonicalize task failed",
                e,
            )
        })?
        .map_err(|e| coded_ctx("collections_cannot_resolve_path", "Cannot resolve path", e))?;

    let meta = tokio::fs::metadata(&canonical)
        .await
        .map_err(|e| coded_ctx("collections_file_not_found", "File does not exist", e))?;
    if !meta.is_file() {
        return Err(coded("collections_file_not_found", "File does not exist"));
    }
    if meta.len() > MAX_COLLECTION_BYTES {
        return Err(coded(
            "collections_too_large",
            "Collection file is too large",
        ));
    }

    tokio::task::spawn_blocking(move || {
        Collection::load(&canonical)
            .map_err(|e| coded_ctx("collections_load_failed", "Failed to load collection", e))
    })
    .await
    .map_err(|e| coded_ctx("collections_load_task_failed", "Load task failed", e))?
}

fn collection_path_from_pending(pending: &[PendingDeepLink], id: &str) -> Result<String, String> {
    if id.is_empty() || id.len() > MAX_PENDING_ID_LEN {
        return Err(coded(
            "deeplink_terminal_invalid",
            "Unknown pending deep link",
        ));
    }
    let payload = pending
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.payload.clone())
        .ok_or_else(|| coded("deeplink_terminal_invalid", "Unknown pending deep link"))?;
    let preview = preview_deep_link_payload(&payload)?;
    if preview.kind != "collection" {
        return Err(coded(
            "deeplink_terminal_invalid",
            "Pending deep link is not a collection",
        ));
    }
    Ok(payload)
}

/// Open an OS-delivered collection by its durable queue identifier.
///
/// The server resolves the opaque identifier against `pending_deep_links`
/// rather than accepting a renderer-provided path. The entry remains queued
/// until the existing acknowledgement flow confirms the Library presentation,
/// preserving retry behaviour if parsing or navigation fails.
#[tauri::command]
pub async fn open_pending_collection(
    state: tauri::State<'_, AppState>,
    id: String,
) -> Result<Collection, String> {
    let path = {
        let pending = state.pending_deep_links.lock();
        collection_path_from_pending(&pending, &id)?
    };
    open_collection_file(path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dropped_collections_open_and_everything_else_is_shared() {
        let root = if cfg!(windows) { "C:\\drop\\" } else { "/drop/" };
        let collection = format!("{root}set.eMuleCollection");
        let folder = format!("{root}Movies");
        let lookalike = format!("{root}notes.emulecollection.txt");
        let relative = "set.emulecollection".to_string();
        let (open, share) = take_dropped_collections(vec![
            collection.clone().into(),
            folder.clone().into(),
            lookalike.clone().into(),
            relative.clone().into(),
        ]);
        assert_eq!(open, vec![collection]);
        assert_eq!(
            share,
            vec![
                std::path::PathBuf::from(folder),
                lookalike.into(),
                relative.into(),
            ],
            "only an absolute collection path is opened; the rest is shared as before"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_dropped_collection_on_a_network_share_is_not_opened() {
        let (open, share) =
            take_dropped_collections(vec![r"\\server\share\set.emulecollection".into()]);
        assert!(open.is_empty());
        assert_eq!(share.len(), 1);
    }

    #[test]
    fn linux_claims_ed2k_only_when_unowned_or_already_ours() {
        let ours = ["ember-handler.desktop", "Ember.desktop"];
        assert!(should_claim_scheme("", &ours), "no handler yet");
        assert!(should_claim_scheme("\n", &ours), "xdg-mime prints a bare newline for none");
        assert!(
            should_claim_scheme("ember-handler.desktop\n", &ours),
            "our own entry is refreshed so a moved AppImage still opens"
        );
        assert!(
            should_claim_scheme("Ember.desktop\n", &ours),
            "the .deb's entry is Ember's too, and its Exec has no %u for the link"
        );
        assert!(
            !should_claim_scheme("amule.desktop\n", &ours),
            "a client the user chose keeps the scheme"
        );
        assert!(
            !should_claim_scheme("ember-handler.desktop.bak\n", &ours),
            "only an exact entry name counts as ours"
        );
    }

    #[test]
    fn previews_sanitize_and_classify_confirmation_details() {
        let file = preview_deep_link_payload(
            "ed2k://|file|report\u{202E}fdp.exe|42|0123456789abcdef0123456789abcdef|/",
        )
        .unwrap();
        assert_eq!(file.kind, "file");
        assert_eq!(file.name.as_deref(), Some("reportfdp.exe"));
        assert_eq!(file.size, Some(42));
        assert_eq!(
            file.hash.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );

        let server = preview_deep_link_payload("ed2k://|server|203.0.113.8|4661|/").unwrap();
        assert_eq!(server.endpoint.as_deref(), Some("203.0.113.8:4661"));

        let list =
            preview_deep_link_payload("ed2k://|serverlist|https://example.test/server.met|/")
                .unwrap();
        assert_eq!(list.host.as_deref(), Some("example.test"));
        assert_eq!(
            list.endpoint.as_deref(),
            Some("https://example.test/server.met")
        );

        let encoded_server =
            preview_deep_link_payload("ed2k://%7Cserver%7C203.0.113.8%7C4661%7C/").unwrap();
        assert_eq!(encoded_server.endpoint.as_deref(), Some("203.0.113.8:4661"));
    }

    #[test]
    fn previews_ember2_friend_codes_and_rejects_broken_ones() {
        let key = crate::network::ember::crypto::signing_key_from_bytes(&[7u8; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let hash = crate::network::ember::crypto::node_id_from_ed25519_bytes(&pubkey).unwrap();
        let hash_hex = hex::encode(hash);
        let code = format!("ember2:{}:{}", hash_hex, hex::encode(pubkey));
        let preview = preview_deep_link_payload(&code).unwrap();
        assert_eq!(preview.kind, "friend");
        assert_eq!(preview.hash.as_deref(), Some(hash_hex.as_str()));
        assert!(is_deep_link_payload(&code));
        let mixed = format!("Ember2:{}:{}", hash_hex, hex::encode(pubkey));
        assert!(is_deep_link_payload(&mixed));
        assert_eq!(
            preview_deep_link_payload(&mixed).unwrap().hash.as_deref(),
            Some(hash_hex.as_str()),
            "a code detected in any case must also parse in any case"
        );
        assert!(preview_deep_link_payload("ember2:not-a-code").is_err());
    }

    #[test]
    fn previews_ember3_friend_codes_and_rejects_broken_ones() {
        let key = crate::network::ember::crypto::signing_key_from_bytes(&[7u8; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let hash = crate::network::ember::crypto::node_id_from_ed25519_bytes(&pubkey).unwrap();
        let code = crate::commands::peers::format_friend_code(&hash, &pubkey, &[0x3Cu8; 16]);
        assert!(is_deep_link_payload(&code));
        assert!(is_deep_link_payload(&code.to_ascii_uppercase()));
        let preview = preview_deep_link_payload(&code).unwrap();
        assert_eq!(preview.kind, "friend");
        assert_eq!(preview.hash.as_deref(), Some(hex::encode(hash).as_str()));
        assert!(preview_deep_link_payload("ember3:not-a-code").is_err());
        assert!(preview_deep_link_payload(&code[..code.len() - 2]).is_err());
    }

    #[test]
    fn permanently_malformed_links_are_terminal_errors() {
        assert!(preview_deep_link_payload("ed2k://|server|not-an-ip|0|/").is_err());
        assert!(preview_deep_link_payload("ed2k://|serverlist|http://example.test/x|/").is_err());
        assert!(preview_deep_link_payload("ed2k://|unknown|value|/").is_err());
    }

    #[test]
    fn browser_encoded_file_links_are_not_terminal_errors() {
        let encoded = "ed2k://%7Cfile%7CComic%20#43%20Issue.cbr%7C26434789%7C0123456789abcdef0123456789abcdef%7C/";
        let preview = preview_deep_link_payload(encoded).unwrap();
        assert_eq!(preview.kind, "file");
        assert_eq!(preview.name.as_deref(), Some("Comic #43 Issue.cbr"));
        assert_eq!(preview.size, Some(26434789));
    }

    #[test]
    fn extract_normalizes_browser_encoded_argv() {
        let encoded = "ed2k://%7Cfile%7Cmovie.avi%7C1234%7C0123456789abcdef0123456789abcdef%7C/";
        let args = vec!["ember.exe".to_string(), encoded.to_string()];
        let payloads = extract_deep_link_payloads(&args);
        assert_eq!(
            payloads,
            vec!["ed2k://|file|movie.avi|1234|0123456789abcdef0123456789abcdef|/".to_string()]
        );
    }

    /// What the Windows single-instance plugin does to a second launch's argv.
    fn forwarded(args: &[&str]) -> Vec<String> {
        args.join("|").split('|').map(str::to_string).collect()
    }

    #[test]
    fn a_link_the_single_instance_plugin_split_at_its_pipes_is_rejoined() {
        let raw = "ed2k://|file|a b.iso|1024|0123456789ABCDEF0123456789ABCDEF|/";
        let with_sources = "ed2k://|file|c.iso|2048|FEDCBA9876543210FEDCBA9876543210|/|sources,198.51.100.7:4662|/";
        let encoded = "ed2k://%7Cfile%7Cd.iso%7C4096%7C00112233445566778899AABBCCDDEEFF%7C/";
        let mixed = "ed2k://%7Cfile%7Ce#1.iso|8192|00112233445566778899AABBCCDDEEFF|/";
        let cases: [&[&str]; 5] = [
            &["ember.exe", raw],
            &["ember.exe", with_sources],
            &["ember.exe", raw, with_sources],
            &["ember.exe", encoded],
            &["ember.exe", mixed],
        ];
        for args in cases {
            let owned: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
            assert_eq!(rejoin_forwarded_args(forwarded(args)), owned, "{args:?}");
            assert_eq!(
                extract_deep_link_payloads(&rejoin_forwarded_args(forwarded(args))),
                extract_deep_link_payloads(&owned),
            );
        }
        let plain = vec!["ember.exe".to_string()];
        assert_eq!(rejoin_forwarded_args(plain.clone()), plain);
    }

    #[test]
    fn a_field_inside_a_forwarded_link_never_becomes_its_own_payload() {
        let local = std::env::temp_dir()
            .join("set.emulecollection")
            .to_string_lossy()
            .into_owned();
        let hash = "0123456789ABCDEF0123456789ABCDEF";
        let links = [
            format!(r"ed2k://|file|\\attacker.example\s\list.emulecollection|1|{hash}|/"),
            format!("ed2k://|file|{local}|1|{hash}|/"),
            format!("ed2k://|file|ember-channel:abc|1|{hash}|/"),
            format!("ed2k://|file|ember3:abc|1|{hash}|/"),
            format!("ed2k://|file|x.iso|1|{hash}|/|{local}"),
            format!("ed2k://%7Cfile%7Cx.iso%7C1%7C{hash}%7C/|ember-channel:abc"),
            format!("ed2k://%7Cfile%7Cx.iso%7C1%7C{hash}%7C/|ember3:abc"),
            format!("ed2k://%7Cfile%7Cx.iso%7C1%7C{hash}%7C/|{local}"),
        ];
        for link in &links {
            let payloads =
                extract_deep_link_payloads(&rejoin_forwarded_args(forwarded(&["ember.exe", link])));
            assert_eq!(payloads.len(), 1, "{link}");
            assert!(payloads[0].starts_with("ed2k://|file|"), "{link}");
        }
    }

    #[test]
    fn collections_on_a_network_share_are_refused() {
        let remote = [
            r"\\attacker.example\s\list.emulecollection",
            "//attacker.example/s/list.emulecollection",
            r"\\?\UNC\attacker.example\s\list.emulecollection",
            r"\\.\UNC\attacker.example\s\list.emulecollection",
            r"\\?\GLOBALROOT\Device\Mup\attacker.example\s\list.emulecollection",
            r"\\.\C:\..\UNC\attacker.example\s\list.emulecollection",
            r"\\.\C:\Users\..\..\UNC\attacker.example\s\list.emulecollection",
        ];
        for path in remote {
            assert!(is_network_path(path), "{path}");
            assert!(!is_deep_link_payload(path), "{path}");
            assert!(preview_deep_link_payload(path).is_err(), "{path}");
            let pending = vec![PendingDeepLink {
                id: "remote".to_string(),
                payload: path.to_string(),
            }];
            assert!(
                collection_path_from_pending(&pending, "remote").is_err(),
                "{path}"
            );
        }
        for local in [
            r"C:\Users\Ember\set.emulecollection",
            r"\\?\C:\Users\Ember\set.emulecollection",
            "/home/ember/set.emulecollection",
        ] {
            assert!(!is_network_path(local), "{local}");
            assert_eq!(preview_deep_link_payload(local).unwrap().kind, "collection");
        }
    }

    #[test]
    fn only_an_absolute_collection_path_is_a_deep_link() {
        let absolute = std::env::temp_dir()
            .join("John Smith")
            .join("set.emulecollection")
            .to_string_lossy()
            .into_owned();
        let split: Vec<String> = std::iter::once("ember.exe")
            .chain(absolute.split(' '))
            .map(str::to_string)
            .collect();
        assert_eq!(
            extract_deep_link_payloads(&["ember.exe".to_string(), absolute.clone()]),
            vec![absolute]
        );
        assert!(extract_deep_link_payloads(&split).is_empty());
        assert!(!is_deep_link_payload("set.emulecollection"));
        assert!(!is_deep_link_payload(r"Smith\Downloads\set.emulecollection"));
    }

    #[test]
    fn pending_collection_lookup_authorizes_only_queued_collection_paths() {
        let pending = vec![
            PendingDeepLink {
                id: "collection".to_string(),
                payload: r"C:\Users\Ember\Downloads\shared.emulecollection".to_string(),
            },
            PendingDeepLink {
                id: "file-link".to_string(),
                payload: "ed2k://|file|example.iso|1|0123456789abcdef0123456789abcdef|/"
                    .to_string(),
            },
        ];

        assert_eq!(
            collection_path_from_pending(&pending, "collection").unwrap(),
            r"C:\Users\Ember\Downloads\shared.emulecollection"
        );
        assert!(collection_path_from_pending(&pending, "file-link").is_err());
        assert!(collection_path_from_pending(&pending, "unknown").is_err());
        assert!(
            collection_path_from_pending(&pending, &"a".repeat(MAX_PENDING_ID_LEN + 1)).is_err()
        );
    }

    fn sample_pending(id: &str) -> PendingDeepLink {
        PendingDeepLink {
            id: id.to_string(),
            payload: "ed2k://|file|example.iso|1|0123456789abcdef0123456789abcdef|/".to_string(),
        }
    }

    fn load_persisted_queue(path: &Path) -> Vec<PendingDeepLink> {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn acked_id_is_not_resurrected_by_dispatch_persist() {
        let dir = std::env::temp_dir().join(format!(
            "ember-deeplink-persist-{}-{}",
            std::process::id(),
            NEXT_PENDING_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pending_deep_links.json");

        let queue =
            parking_lot::Mutex::new(vec![sample_pending("ack-me"), sample_pending("keep-me")]);
        persist_live_pending_queue_at(&path, &queue, Some("ack-me")).unwrap();
        let after_ack = load_persisted_queue(&path);
        assert!(after_ack.iter().all(|entry| entry.id != "ack-me"));
        assert!(after_ack.iter().any(|entry| entry.id == "keep-me"));
        assert!(queue.lock().iter().all(|entry| entry.id != "ack-me"));

        persist_live_pending_queue_at(&path, &queue, None).unwrap();
        let after_dispatch = load_persisted_queue(&path);
        assert!(after_dispatch.iter().all(|entry| entry.id != "ack-me"));
        assert_eq!(after_dispatch.len(), 1);
        assert_eq!(after_dispatch[0].id, "keep-me");

        for _ in 0..8 {
            let queue =
                parking_lot::Mutex::new(vec![sample_pending("ack-me"), sample_pending("keep-me")]);
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    persist_live_pending_queue_at(&path, &queue, Some("ack-me")).unwrap();
                });
                scope.spawn(|| {
                    persist_live_pending_queue_at(&path, &queue, None).unwrap();
                });
            });
            let on_disk = load_persisted_queue(&path);
            assert!(
                on_disk.iter().all(|entry| entry.id != "ack-me"),
                "acked id reappeared on disk"
            );
            assert!(queue.lock().iter().all(|entry| entry.id != "ack-me"));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
