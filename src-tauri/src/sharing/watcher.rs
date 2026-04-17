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
        let (reload_tx, mut reload_rx) = mpsc::unbounded_channel::<()>();

        // Reload driver task: coalesces pings, emits the UI event, and
        // reuses reload_shared_files so the heavy lifting (discover, hash,
        // publish) is shared with the manual-reload path.
        let app_for_handler = app.clone();
        tokio::spawn(async move {
            while reload_rx.recv().await.is_some() {
                while reload_rx.try_recv().is_ok() {}
                // Small cooldown on top of notify's debounce to let a burst
                // of related file operations (e.g. a drag-copy) settle.
                tokio::time::sleep(Duration::from_millis(400)).await;
                while reload_rx.try_recv().is_ok() {}

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
                    let _ = tx_for_debouncer.send(());
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
