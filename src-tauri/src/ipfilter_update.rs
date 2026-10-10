//! Automatic IP filter updates.
//!
//! When the user leaves the Security page's Auto-update switch on, the bundled
//! default list is downloaded again once it is a day old: on a timer while
//! Ember runs, and on the next launch when the day ran out while it was
//! closed. Lives in the backend for the reason the app update check does: a
//! hidden webview is throttled, and the people who leave Ember in the tray for
//! weeks are the ones whose list goes stale.
//!
//! Only a list that came from the default URL is replaced. One the user
//! installed from a file or another URL is theirs to keep, so the record of
//! where the installed list came from ([`IpFilterRecord`]) pauses the updates
//! until the default list is installed again. The user's own range edits
//! survive either way: they are kept apart and re-applied to every new list
//! (`storage::ipfilter_edits`).

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::FutureExt;
use tauri::{AppHandle, Emitter, Manager};

use crate::app_state::AppState;

/// Emitted with the entry count after an automatic update installs a list, so
/// an open Security page can refresh its counts.
pub const UPDATED_EVENT: &str = "ipfilter-auto-updated";

/// How old the installed list may get before it is fetched again.
const MAX_AGE_SECS: i64 = 24 * 60 * 60;

/// Wait after a failed attempt before the next one. The poll runs more often
/// than this; without it, a mirror that is down would be asked every poll.
const RETRY_AFTER_FAILURE_SECS: i64 = 60 * 60;

/// Delay before the first check of a session, so it never competes with
/// startup or the network coming up.
const FIRST_CHECK_DELAY: Duration = Duration::from_secs(60);

/// How often the scheduler asks whether an update is due. Asking is a config
/// read and a small file read.
const POLL_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Pause before restarting a panicked scheduler.
const RESTART_DELAY: Duration = Duration::from_secs(60);

const RECORD_FILE: &str = "ipfilter_update.json";

/// Where the installed IP filter came from, and when.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpFilterRecord {
    /// The installed list is the bundled default; false once the user
    /// installed one from a file or another URL.
    #[serde(default = "default_true")]
    pub from_default: bool,
    /// Unix seconds the installed list was written; 0 when unknown.
    #[serde(default)]
    pub updated_at: i64,
    /// Unix seconds of the last automatic attempt that failed; 0 when none.
    #[serde(default)]
    pub failed_at: i64,
}

fn default_true() -> bool {
    true
}

fn record_path(data_dir: &Path) -> PathBuf {
    data_dir.join(RECORD_FILE)
}

/// The record, or what can be told without one: an older install has a list
/// but no record, and is taken to hold the default list as of the file's own
/// modification time — the default is what nearly everyone runs, and the
/// first-run wizard installs it.
pub fn read_record(data_dir: &Path) -> IpFilterRecord {
    if let Some(record) = std::fs::read(record_path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<IpFilterRecord>(&bytes).ok())
    {
        return record;
    }
    let updated_at = std::fs::metadata(data_dir.join("ipfilter.dat"))
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    IpFilterRecord { from_default: true, updated_at, failed_at: 0 }
}

fn write_record(data_dir: &Path, record: &IpFilterRecord) {
    let Ok(bytes) = serde_json::to_vec(record) else {
        return;
    };
    if let Err(error) = crate::security::atomic_write(&record_path(data_dir), &bytes, false) {
        tracing::warn!("Could not record the IP filter update: {error}");
    }
}

/// Note that a new list was installed: from the default URL, or from
/// somewhere the user chose. Blocking (a small file write).
pub fn note_installed(data_dir: &Path, from_default: bool) {
    write_record(
        data_dir,
        &IpFilterRecord {
            from_default,
            updated_at: chrono::Utc::now().timestamp(),
            failed_at: 0,
        },
    );
}

/// Whether an automatic update is due at `now`.
fn update_due(record: &IpFilterRecord, now: i64) -> bool {
    record.from_default
        && now.saturating_sub(record.updated_at) >= MAX_AGE_SECS
        && now.saturating_sub(record.failed_at) >= RETRY_AFTER_FAILURE_SECS
}

/// Start the scheduler. Call once, after `AppState` is managed.
pub fn spawn(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            let result = std::panic::AssertUnwindSafe(run(app.clone()))
                .catch_unwind()
                .await;
            if result.is_ok() {
                return;
            }
            tracing::error!("IP filter update scheduler panicked; restarting it");
            tokio::time::sleep(RESTART_DELAY).await;
        }
    });
}

async fn run(app: AppHandle) {
    tokio::time::sleep(FIRST_CHECK_DELAY).await;
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    // Waking from a long sleep updates once, not once per missed poll.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        maybe_update(&app).await;
    }
}

/// Serializes attempts: the poll and the switch being turned on can both ask.
static UPDATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Update the IP filter if the switch is on, the filter is in use, the list is
/// the default one, and it is a day old.
pub async fn maybe_update(app: &AppHandle) {
    let Ok(_guard) = UPDATE_LOCK.try_lock() else {
        return;
    };
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    let (auto_update, filter_enabled) = {
        let config = state.config.read().await;
        (config.settings.ip_filter_auto_update, config.settings.ip_filter_enabled)
    };
    // A switched-off filter is not being used; downloading for it would only
    // spend bandwidth on a list nothing reads.
    if !auto_update || !filter_enabled {
        return;
    }
    let data_dir = crate::storage::paths::resolve_data_dir_with_app(app);
    let record = {
        let dir = data_dir.clone();
        match tokio::task::spawn_blocking(move || read_record(&dir)).await {
            Ok(record) => record,
            Err(_) => return,
        }
    };
    if !update_due(&record, chrono::Utc::now().timestamp()) {
        return;
    }
    tracing::info!("IP filter is over a day old; downloading the default list");
    match crate::commands::security::install_default_ipfilter(app, &state, false).await {
        Ok(result) => {
            let _ = app.emit(UPDATED_EVENT, result.entry_count);
        }
        Err(error) => {
            tracing::warn!("Automatic IP filter update failed: {error}");
            let failed = IpFilterRecord {
                failed_at: chrono::Utc::now().timestamp(),
                ..record
            };
            let dir = data_dir.clone();
            let _ = tokio::task::spawn_blocking(move || write_record(&dir, &failed)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = MAX_AGE_SECS;

    #[test]
    fn a_default_list_is_updated_once_it_is_a_day_old() {
        let record = IpFilterRecord { from_default: true, updated_at: 1_000_000, failed_at: 0 };
        assert!(!update_due(&record, 1_000_000 + DAY - 1));
        assert!(update_due(&record, 1_000_000 + DAY));
    }

    #[test]
    fn a_list_the_user_installed_from_elsewhere_is_left_alone() {
        let record = IpFilterRecord { from_default: false, updated_at: 0, failed_at: 0 };
        assert!(!update_due(&record, 10 * DAY));
    }

    #[test]
    fn a_failed_attempt_waits_before_the_next() {
        let now = 10 * DAY;
        let record = IpFilterRecord { from_default: true, updated_at: 0, failed_at: now - 60 };
        assert!(!update_due(&record, now));
        assert!(update_due(&record, now - 60 + RETRY_AFTER_FAILURE_SECS));
    }

    #[test]
    fn no_list_at_all_is_due_at_once() {
        assert!(update_due(&IpFilterRecord { from_default: true, updated_at: 0, failed_at: 0 }, DAY));
    }
}
