use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use notify_debouncer_mini::{
    new_debouncer,
    notify::{RecommendedWatcher, RecursiveMode},
    DebounceEventResult, Debouncer,
};
use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::app_state::AppState;

/// Keeps a filesystem watcher in sync with the currently shared folders and
/// triggers a background re-scan + `shared-files-changed` event whenever a
/// file is added, removed, or modified underneath any shared folder.
///
/// Behaviour summary:
/// - A single `notify-debouncer-mini` debouncer watches every shared folder
///   recursively. Events are collapsed into a 2-second debounce window.
/// - Each debounced batch sends one ping on an internal channel; the handler
///   task coalesces multiple pings into a single reload call.
/// - The reload path reuses the existing `reload_shared_files` Tauri command
///   so hashing, KAD (re)publishing, and UI events behave identically to a
///   manual reload triggered from the frontend.
/// - Folders added via `add_shared_folder` are added with `sync_paths`;
///   folders removed via `remove_shared_folder` are unwatched the same way.
pub struct SharedFoldersWatcher {
    watched: Mutex<HashSet<PathBuf>>,
    debouncer: Mutex<Option<Debouncer<RecommendedWatcher>>>,
}

impl SharedFoldersWatcher {
    /// Create and start the watcher. Returns `None` if the OS-level watcher
    /// cannot be initialised (in which case live folder tracking is simply
    /// disabled — the app still functions, the user just needs to reload
    /// manually).
    pub fn start(app: AppHandle, initial_paths: Vec<String>) -> Option<Arc<Self>> {
        // Bounded ping channel — the coalescing loop only needs to know that
        // *some* event arrived, so a small capacity plus `try_send` drops
        // extras. This caps memory under a bulk copy that fires thousands of
        // notifications before the reload driver catches up.
        let (reload_tx, mut reload_rx) = mpsc::channel::<()>(8);

        // Reload driver task: coalesces pings, emits the UI event, and
        // reuses reload_shared_files so the heavy lifting (discover, hash,
        // publish) is shared with the manual-reload path.
        let app_for_handler = app.clone();
        // NOTE: must use `tauri::async_runtime::spawn` (not `tokio::spawn`)
        // because `SharedFoldersWatcher::start` is called from Tauri's
        // synchronous `setup` hook, which is not itself running inside a
        // Tokio reactor context.
        tauri::async_runtime::spawn(async move {
            // Upper bound on total time we'll defer a rescan while new events
            // keep arriving. Without this, a long-running bulk copy that emits
            // a steady trickle of events could starve the reload indefinitely.
            const MAX_COALESCE_WINDOW: Duration = Duration::from_secs(15);
            const COALESCE_COOLDOWN: Duration = Duration::from_millis(400);

            while reload_rx.recv().await.is_some() {
                let first_event = std::time::Instant::now();
                while reload_rx.try_recv().is_ok() {}
                tokio::time::sleep(COALESCE_COOLDOWN).await;
                while reload_rx.try_recv().is_ok() {}

                // If more events arrived during the cooldown, coalesce them
                // but stop deferring once we've been holding the rescan for
                // longer than MAX_COALESCE_WINDOW.
                loop {
                    let elapsed = first_event.elapsed();
                    if elapsed >= MAX_COALESCE_WINDOW {
                        break;
                    }
                    match tokio::time::timeout(COALESCE_COOLDOWN, reload_rx.recv()).await {
                        Ok(Some(_)) => {
                            while reload_rx.try_recv().is_ok() {}
                        }
                        _ => break,
                    }
                }

                info!("FS watcher: triggering shared-folder rescan");
                let _ = app_for_handler.emit(
                    "shared-files-changed",
                    serde_json::json!({ "phase": "fs-changed" }),
                );

                let state_ref = app_for_handler.state::<AppState>();
                if let Err(e) = crate::commands::sharing::reload_shared_files(
                    app_for_handler.clone(),
                    state_ref,
                )
                .await
                {
                    warn!("FS watcher: reload_shared_files failed: {e}");
                }
            }
        });

        let tx_for_debouncer = reload_tx.clone();
        let debouncer_result = new_debouncer(
            Duration::from_secs(2),
            move |res: DebounceEventResult| match res {
                Ok(events) => {
                    if events.is_empty() {
                        return;
                    }
                    debug!("FS watcher: {} debounced event(s)", events.len());
                    // try_send + discard on full: a pending ping already means
                    // a reload is queued; no information is lost by dropping
                    // the redundant notification.
                    match tx_for_debouncer.try_send(()) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            debug!("FS watcher: reload queue full, ping coalesced");
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!("FS watcher: reload driver task has exited");
                        }
                    }
                }
                Err(e) => warn!("FS watcher error: {e:?}"),
            },
        );

        let debouncer = match debouncer_result {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "FS watcher: failed to initialise ({e}); live folder tracking disabled"
                );
                return None;
            }
        };

        let watcher = Arc::new(Self {
            watched: Mutex::new(HashSet::new()),
            debouncer: Mutex::new(Some(debouncer)),
        });
        watcher.sync_paths(&initial_paths);
        Some(watcher)
    }

    /// Make the watched set exactly match `desired`. Paths that don't exist
    /// on disk are skipped (logged once). Errors from the underlying
    /// watcher are logged but non-fatal.
    pub fn sync_paths(&self, desired: &[String]) {
        let desired_set: HashSet<PathBuf> = desired
            .iter()
            .filter_map(|p| {
                let pb = PathBuf::from(p);
                if pb.exists() {
                    Some(pb)
                } else {
                    warn!("FS watcher: skipping non-existent path {}", pb.display());
                    None
                }
            })
            .collect();

        let mut current = self.watched.lock();
        let mut debouncer_guard = self.debouncer.lock();
        let Some(debouncer) = debouncer_guard.as_mut() else {
            return;
        };

        let to_remove: Vec<PathBuf> = current.difference(&desired_set).cloned().collect();
        let to_add: Vec<PathBuf> = desired_set.difference(&current).cloned().collect();

        for path in &to_remove {
            if let Err(e) = debouncer.watcher().unwatch(path) {
                warn!("FS watcher: failed to unwatch {}: {e}", path.display());
            }
            current.remove(path);
        }
        for path in &to_add {
            match debouncer.watcher().watch(path, RecursiveMode::Recursive) {
                Ok(()) => {
                    current.insert(path.clone());
                    debug!("FS watcher: watching {}", path.display());
                }
                Err(e) => warn!("FS watcher: failed to watch {}: {e}", path.display()),
            }
        }

        if !to_add.is_empty() || !to_remove.is_empty() {
            info!(
                "FS watcher: now tracking {} folder(s) (+{}, -{})",
                current.len(),
                to_add.len(),
                to_remove.len()
            );
        }
    }
}
