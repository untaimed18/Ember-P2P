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

pub(crate) fn preview_deep_link_payload(payload: &str) -> Result<DeepLinkPreview, String> {
    let payload = payload.trim();
    let lower = payload.to_ascii_lowercase();
    if lower.starts_with("ed2k://|file|") {
        let info = crate::commands::search::parse_ed2k_link(payload.to_string())?;
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
        let segments = ed2k_segments(payload);
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
        let segments = ed2k_segments(payload);
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
            endpoint: None,
            host: Some(host),
        });
    }
    if !lower.starts_with("ed2k://") && lower.ends_with(".emulecollection") {
        let name = std::path::Path::new(payload)
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

/// True if `arg` looks like a deep link we should act on: an `ed2k://` URI or
/// a path ending in `.emulecollection`.
pub fn is_deep_link_payload(arg: &str) -> bool {
    let lower = arg.trim().to_ascii_lowercase();
    lower.starts_with("ed2k://") || lower.ends_with(".emulecollection")
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
        .collect()
}

/// Buffer `payloads` for the frontend and emit a wake signal.
///
/// The buffer — not the event payload — is the single source of truth:
/// `take_pending_deep_links` drains it atomically, so a cold-start link
/// (buffered before any listener exists) and a running-instance link (buffered
/// + signalled) flow through exactly the same path with no risk of
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

/// Compatibility alias for older frontends. It intentionally no longer drains
/// the queue, so a setup-wizard relaunch cannot lose unacknowledged links.
#[tauri::command]
pub fn take_pending_deep_links(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    Ok(state
        .pending_deep_links
        .lock()
        .iter()
        .map(|entry| entry.payload.clone())
        .collect())
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
    }

    #[test]
    fn permanently_malformed_links_are_terminal_errors() {
        assert!(preview_deep_link_payload("ed2k://|server|not-an-ip|0|/").is_err());
        assert!(preview_deep_link_payload("ed2k://|serverlist|http://example.test/x|/").is_err());
        assert!(preview_deep_link_payload("ed2k://|unknown|value|/").is_err());
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

        let queue = parking_lot::Mutex::new(vec![
            sample_pending("ack-me"),
            sample_pending("keep-me"),
        ]);
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
