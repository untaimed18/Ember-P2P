//! The periodic update check.
//!
//! Lives in the backend rather than on a webview timer because the people who
//! most need it are the ones who leave Ember hidden in the tray for weeks: the
//! frontend used to check once, a few seconds after launch, so a long-running
//! Ember never heard about a release at all. A hidden webview is also throttled
//! by the OS, which makes it the wrong place for anything that has to happen on
//! a clock.
//!
//! The result is emitted to the frontend, which applies it exactly as it applies
//! a silent check it ran itself.

use std::time::Duration;

use futures::FutureExt;
use tauri::{AppHandle, Emitter, Manager};

use crate::app_state::AppState;
use crate::commands::updater::{run_check, SecureUpdateCheckResult, UpdaterService};

use super::record;

/// Emitted with a [`SecureUpdateCheckResult`] after every automatic check.
pub const CHECK_RESULT_EVENT: &str = "ember:updater-check-result";

/// Delay before the first automatic check of a session. Long enough that it
/// never competes with first paint or store initialisation, and that the
/// frontend's hand-off status query (1.5 s after mount) has settled first.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(15);

/// How often the scheduler asks whether a check is due. Asking is only a config
/// read and a small file read; the fastest cadence it serves is hourly, which
/// this keeps within a few minutes of on time.
const POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Pause before restarting a panicked scheduler, so a panic that reproduces on
/// every poll cannot become a busy loop.
const RESTART_DELAY: Duration = Duration::from_secs(60);

/// Start the scheduler. Call once, after `AppState` is managed.
///
/// Release builds only: a dev build's version is whatever the working tree says,
/// and the published manifest would spuriously offer it an "update".
pub fn spawn(app: AppHandle) {
    if cfg!(debug_assertions) {
        tracing::debug!("Automatic update checks are disabled in development builds");
        return;
    }
    tauri::async_runtime::spawn(async move {
        loop {
            let result = std::panic::AssertUnwindSafe(run(app.clone()))
                .catch_unwind()
                .await;
            if result.is_ok() {
                return;
            }
            tracing::error!("Update scheduler panicked; restarting it");
            tokio::time::sleep(RESTART_DELAY).await;
        }
    });
}

async fn run(app: AppHandle) {
    tokio::time::sleep(FIRST_CHECK_DELAY).await;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    // A machine waking from a week of sleep should check once, not replay a
    // week of missed polls.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        maybe_check(&app).await;
    }
}

async fn maybe_check(app: &AppHandle) {
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let (enabled, frequency) = {
        let config = state.config.read().await;
        (
            config.settings.auto_check_updates,
            config.settings.update_check_frequency.clone(),
        )
    };
    if !enabled {
        return;
    }
    let dir = match crate::storage::paths::ensure_data_dir() {
        Ok(dir) => dir,
        Err(error) => {
            tracing::warn!("Skipping the automatic update check: no data folder ({error})");
            return;
        }
    };
    let last = record::load(&dir).last_check_at;
    if !record::check_due(last, chrono::Utc::now().timestamp(), &frequency) {
        return;
    }

    let service = app.state::<UpdaterService>();
    let result = run_check(app, &service)
        .await
        .unwrap_or_else(SecureUpdateCheckResult::failed);
    if let Some(error) = result.error() {
        tracing::debug!("Automatic update check reported a failure: {error}");
    }
    if let Err(error) = app.emit(CHECK_RESULT_EVENT, &result) {
        tracing::debug!("Could not emit the automatic update check result: {error}");
    }
}
