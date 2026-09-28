//! `silent-update-state.json`: the scheduler's memory across restarts.
//!
//! Untrusted like every other file in the data directory — anything running as
//! the user can rewrite it. Nothing read from here may choose what is
//! installed; at most it can make a check or an install happen later or not at
//! all, which the user could equally do by switching the feature off.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const RECORD_FILE: &str = "silent-update-state.json";

/// Serialises read-modify-write cycles. The scheduler and the check command
/// both stamp the file, and two interleaved updates would drop one field.
static RECORD_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// A stamp further ahead than this was written while the clock was wrong. Taken
/// at face value it would hold off every automatic check until wall time
/// caught up — months, for a clock that was set a year out.
const MAX_FUTURE_SKEW_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRecord {
    /// Unix seconds of the last update check, manual or automatic, whatever its
    /// outcome. An attempt counts even when it fails, so "check weekly" retries
    /// roughly weekly rather than on every poll after one offline evening.
    #[serde(default)]
    pub last_check_at: Option<i64>,
}

fn record_path(dir: &Path) -> PathBuf {
    dir.join(RECORD_FILE)
}

/// Read the record, treating a missing or unreadable file as a fresh start.
/// A corrupt file is not worth surfacing: the worst it costs is one check
/// earlier than the configured cadence.
pub fn load(dir: &Path) -> UpdateRecord {
    match std::fs::read(record_path(dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            tracing::warn!("Ignoring an unreadable {RECORD_FILE}: {error}");
            UpdateRecord::default()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => UpdateRecord::default(),
        Err(error) => {
            tracing::warn!("Could not read {RECORD_FILE}: {error}");
            UpdateRecord::default()
        }
    }
}

/// Apply `change` to the stored record and write it back.
pub fn update(dir: &Path, change: impl FnOnce(&mut UpdateRecord)) {
    let _guard = RECORD_LOCK.lock();
    let mut record = load(dir);
    change(&mut record);
    let bytes = match serde_json::to_vec_pretty(&record) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!("Could not serialize {RECORD_FILE}: {error}");
            return;
        }
    };
    if let Err(error) = crate::security::atomic_write(&record_path(dir), &bytes, true) {
        tracing::warn!("Could not write {RECORD_FILE}: {error}");
    }
}

/// Stamp an update check as having been attempted now.
pub fn note_check_attempt() {
    match crate::storage::paths::ensure_data_dir() {
        Ok(dir) => update(&dir, |record| {
            record.last_check_at = Some(chrono::Utc::now().timestamp());
        }),
        Err(error) => tracing::warn!("Could not resolve the data folder to stamp an update check: {error}"),
    }
}

/// Seconds between automatic checks for a `update_check_frequency` value.
/// Anything unrecognised falls back to daily, the default.
pub fn check_interval_secs(frequency: &str) -> i64 {
    match frequency {
        "weekly" => 7 * 24 * 3600,
        "monthly" => 30 * 24 * 3600,
        _ => 24 * 3600,
    }
}

/// Whether an automatic check is due at `now` (Unix seconds).
pub fn check_due(last_check_at: Option<i64>, now: i64, frequency: &str) -> bool {
    let Some(last) = last_check_at else {
        return true;
    };
    if last > now.saturating_add(MAX_FUTURE_SKEW_SECS) {
        return true;
    }
    now.saturating_sub(last) >= check_interval_secs(frequency)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;
    const DAY: i64 = 24 * 3600;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = format!(
            "ember-update-record-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn due_when_never_checked() {
        assert!(check_due(None, NOW, "weekly"));
    }

    #[test]
    fn follows_the_configured_interval() {
        let two_days_ago = Some(NOW - 2 * DAY);
        assert!(check_due(two_days_ago, NOW, "daily"));
        assert!(!check_due(two_days_ago, NOW, "weekly"));
        assert!(!check_due(two_days_ago, NOW, "monthly"));
        assert!(check_due(Some(NOW - 31 * DAY), NOW, "monthly"));
    }

    #[test]
    fn unknown_frequency_is_daily() {
        assert!(!check_due(Some(NOW - DAY + 60), NOW, "hourly"));
        assert!(check_due(Some(NOW - DAY), NOW, "hourly"));
    }

    #[test]
    fn tolerates_a_stamp_slightly_ahead_of_the_clock() {
        assert!(!check_due(Some(NOW + 3600), NOW, "daily"));
    }

    #[test]
    fn a_stamp_far_in_the_future_counts_as_never_checked() {
        assert!(check_due(Some(NOW + 365 * DAY), NOW, "monthly"));
    }

    #[test]
    fn round_trips_and_survives_corruption() {
        let dir = temp_dir("round-trip");
        assert_eq!(load(&dir), UpdateRecord::default());

        update(&dir, |record| record.last_check_at = Some(NOW));
        assert_eq!(load(&dir).last_check_at, Some(NOW));

        std::fs::write(dir.join(RECORD_FILE), b"{not json").unwrap();
        assert_eq!(load(&dir), UpdateRecord::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_fields_from_a_newer_build_are_ignored() {
        let dir = temp_dir("unknown-fields");
        std::fs::write(
            dir.join(RECORD_FILE),
            br#"{"last_check_at": 5, "something_new": true}"#,
        )
        .unwrap();
        assert_eq!(load(&dir).last_check_at, Some(5));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
