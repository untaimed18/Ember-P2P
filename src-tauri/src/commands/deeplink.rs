use std::sync::atomic::{AtomicU64, Ordering};

use tauri::{AppHandle, Emitter, Manager};

use crate::app_state::{AppState, PendingDeepLink};
use crate::commands::errors::{coded, coded_ctx};
use crate::network::ed2k::collection::Collection;

/// Upper bound on a single buffered deep-link payload. Real ed2k links and
/// collection paths are well under this; anything larger is almost certainly
/// junk and rejected before it reaches the buffer.
const MAX_PAYLOAD_LEN: usize = 8192;

/// Cap on the pending buffer so a flood of links (or a misbehaving caller)
/// can't grow it without bound before the frontend drains it.
const MAX_PENDING: usize = 256;

/// Largest `.emulecollection` we'll read when opened via the OS file
/// association. Mirrors the spirit of the binary loader's own entry cap.
const MAX_COLLECTION_BYTES: u64 = 32 * 1024 * 1024;
const PENDING_QUEUE_FILE: &str = "pending_deep_links.json";
static NEXT_PENDING_ID: AtomicU64 = AtomicU64::new(1);

fn pending_queue_path(app: &AppHandle) -> std::path::PathBuf {
    crate::storage::paths::resolve_data_dir_with_app(app).join(PENDING_QUEUE_FILE)
}

fn persist_pending_queue(app: &AppHandle, entries: &[PendingDeepLink]) -> Result<(), String> {
    let data = serde_json::to_vec(entries)
        .map_err(|e| coded_ctx("deeplink_queue_serialize_failed", "Deep-link queue error", e))?;
    crate::security::atomic_write(&pending_queue_path(app), &data, false)
        .map_err(|e| coded_ctx("deeplink_queue_save_failed", "Deep-link queue error", e))
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
        let mut pending = state.pending_deep_links.lock();
        for p in payloads {
            if pending.len() >= MAX_PENDING {
                tracing::warn!("Dropping deep link; pending buffer full ({MAX_PENDING})");
                break;
            }
            let sequence = NEXT_PENDING_ID.fetch_add(1, Ordering::Relaxed);
            pending.push(PendingDeepLink {
                id: format!("{:x}-{sequence:x}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                payload: p,
            });
        }
        if let Err(error) = persist_pending_queue(app, &pending) {
            tracing::warn!("Failed to persist deep-link queue: {error}");
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
pub async fn list_pending_deep_links(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PendingDeepLink>, String> {
    Ok(state.pending_deep_links.lock().clone())
}

/// Compatibility alias for older frontends. It intentionally no longer drains
/// the queue, so a setup-wizard relaunch cannot lose unacknowledged links.
#[tauri::command]
pub async fn take_pending_deep_links(
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
    let mut pending = state.pending_deep_links.lock();
    let before = pending.len();
    pending.retain(|entry| entry.id != id);
    if pending.len() == before {
        return Ok(());
    }
    persist_pending_queue(&app, &pending)
}

/// Load a collection from a path supplied by the OS file association.
///
/// Unlike `collections::load_collection` (which constrains the path to the
/// user's shared/download folders because it's driven by an in-app file
/// dialog), a `.emulecollection` opened from the shell can live anywhere
/// (Downloads, Desktop, an email attachment). The user double-clicking the
/// file *is* the authorization, so we drop the folder-containment check and
/// instead lean on extension, regular-file, and size validation.
#[tauri::command]
pub async fn open_collection_file(path: String) -> Result<Collection, String> {
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
