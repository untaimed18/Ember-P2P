//! Saving state when a Unix session manager ends the process.
//!
//! Logoff and shutdown on Linux arrive as SIGTERM, which never delivers
//! `RunEvent::Exit`, so [`crate::run_graceful_shutdown`] was skipped and the
//! gap maps of every running download were lost. Routing the signal through
//! `app.exit(0)` takes the normal exit path. Windows needs nothing here: tao
//! ends the event loop on `WM_ENDSESSION`, which does deliver `RunEvent::Exit`.

/// Starts listening for the end of the session.
pub fn watch(app: &tauri::AppHandle) {
    #[cfg(unix)]
    unix::watch(app.clone());
    #[cfg(not(unix))]
    let _ = app;
}

#[cfg(unix)]
mod unix {
    use tauri::Manager;

    pub(super) fn watch(app: tauri::AppHandle) {
        tauri::async_runtime::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut terminate = match signal(SignalKind::terminate()) {
                Ok(terminate) => terminate,
                Err(e) => {
                    tracing::warn!("Cannot listen for SIGTERM: {e}");
                    return;
                }
            };
            if terminate.recv().await.is_some() {
                tracing::info!("SIGTERM received; exiting through the normal shutdown");
                if let Some(state) = app.try_state::<crate::app_state::AppState>() {
                    state
                        .quit_confirmed
                        .store(true, std::sync::atomic::Ordering::Release);
                }
                app.exit(0);
            }
        });
    }
}
