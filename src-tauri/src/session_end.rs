//! Saving state when a Unix session manager ends the process.
//!
//! Logoff and shutdown on Linux arrive as SIGTERM, which never delivers
//! `RunEvent::Exit`, so [`crate::run_graceful_shutdown`] was skipped and the
//! gap maps of every running download were lost. Routing the signal through
//! `app.exit(0)` takes the normal exit path. SIGINT (Ctrl+C in the terminal
//! Ember was started from) and SIGHUP (that terminal closing) used to end the
//! process the same abrupt way and get the same treatment. Windows needs
//! nothing here: tao ends the event loop on `WM_ENDSESSION`, which does deliver
//! `RunEvent::Exit`.

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
    use tokio::signal::unix::{signal, Signal, SignalKind};

    pub(super) fn watch(app: tauri::AppHandle) {
        tauri::async_runtime::spawn(async move {
            let listen = |kind: SignalKind, name: &str| match signal(kind) {
                Ok(stream) => Some(stream),
                Err(e) => {
                    tracing::warn!("Cannot listen for {name}: {e}");
                    None
                }
            };
            let mut terminate = listen(SignalKind::terminate(), "SIGTERM");
            // A launcher that set these to be ignored (`nohup`, a shell's
            // background job) meant Ember to outlive the terminal; listening
            // would replace that disposition and end it after all.
            let mut interrupt = (!ignored(libc::SIGINT))
                .then(|| listen(SignalKind::interrupt(), "SIGINT"))
                .flatten();
            let mut hangup = (!ignored(libc::SIGHUP))
                .then(|| listen(SignalKind::hangup(), "SIGHUP"))
                .flatten();
            if terminate.is_none() && interrupt.is_none() && hangup.is_none() {
                return;
            }

            let name = next_signal(&mut terminate, &mut interrupt, &mut hangup).await;
            tracing::info!("{name} received; exiting through the normal shutdown");
            if let Some(state) = app.try_state::<crate::app_state::AppState>() {
                state
                    .quit_confirmed
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            app.exit(0);

            // Listening replaced the default action, so without this a shutdown
            // that hangs could no longer be interrupted at all. Asking twice is
            // how a terminal user says "now".
            let name = next_signal(&mut terminate, &mut interrupt, &mut hangup).await;
            tracing::warn!("{name} received again during shutdown; exiting immediately");
            std::process::exit(130);
        });
    }

    /// Whether `signal` is set to be ignored, as inherited from the launcher.
    fn ignored(signal: libc::c_int) -> bool {
        // SAFETY: with a null new action, `sigaction` only writes the current
        // one into `current`, which is a zeroed, properly sized struct.
        unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(signal, std::ptr::null(), &mut current) == 0
                && current.sa_sigaction == libc::SIG_IGN
        }
    }

    /// The name of the next signal to arrive on any stream still listening.
    async fn next_signal(
        terminate: &mut Option<Signal>,
        interrupt: &mut Option<Signal>,
        hangup: &mut Option<Signal>,
    ) -> &'static str {
        async fn recv(stream: &mut Option<Signal>) {
            if let Some(stream) = stream {
                if stream.recv().await.is_some() {
                    return;
                }
            }
            std::future::pending().await
        }
        tokio::select! {
            () = recv(terminate) => "SIGTERM",
            () = recv(interrupt) => "SIGINT",
            () = recv(hangup) => "SIGHUP",
        }
    }
}
