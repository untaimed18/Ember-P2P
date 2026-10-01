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

/// A stamp further ahead than this was written before the clock stepped back.
/// Taken at face value it would hold off every automatic check until wall time
/// caught up — months, for a clock that was set a year out.
const MAX_FUTURE_SKEW_SECS: i64 = 5 * 60;

/// The last check this session attempted, in case the record could not take
/// it: on a full disk the stamp never lands, and the scheduler would check on
/// every poll.
static LAST_CHECK_THIS_SESSION: parking_lot::Mutex<Option<i64>> = parking_lot::Mutex::new(None);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRecord {
    /// Unix seconds of the last update check, manual or automatic, whatever its
    /// outcome. An attempt counts even when it fails, so "check weekly" retries
    /// roughly weekly rather than on every poll after one offline evening.
    #[serde(default)]
    pub last_check_at: Option<i64>,
    /// "Not now" on the silent-update countdown: no silent install before this
    /// (Unix seconds).
    #[serde(default)]
    pub postponed_until: Option<i64>,
    /// "Skip this version": never installed silently. The ordinary notice still
    /// offers it.
    #[serde(default)]
    pub skipped_version: Option<String>,
    /// A version whose silent install did not produce it. Never tried silently
    /// again, so one bad release cannot become a restart loop.
    #[serde(default)]
    pub failed_version: Option<String>,
    /// The last update that installed itself, for Settings → About.
    #[serde(default)]
    pub last_success: Option<LastSuccess>,
    /// When the staged version first became ready to install silently, so a
    /// machine that is never idle is told after a week instead of never.
    #[serde(default)]
    pub ready_since: Option<ReadySince>,
    /// A silent install handed over and not yet seen to land. Written before
    /// the hand-off, so the next launch can tell a failed install from a
    /// successful one even when the resume file could not be written — the
    /// full disk that forces that is also a likely reason for the install to
    /// fail.
    #[serde(default)]
    pub attempting: Option<Attempt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub from: String,
    pub to: String,
    /// Unix seconds.
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastSuccess {
    pub from: String,
    pub to: String,
    /// Unix seconds.
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadySince {
    pub version: String,
    /// Unix seconds.
    pub at: i64,
}

fn record_path(dir: &Path) -> PathBuf {
    dir.join(RECORD_FILE)
}

/// Read the record. A missing file is a fresh start, and so is one that does
/// not parse, since nothing in it can be recovered. A file that is there but
/// cannot be read right now is an error: taking it for a fresh record would
/// drop its skip, postpone and failed version, and writing one back would make
/// that permanent.
fn read(dir: &Path) -> std::io::Result<UpdateRecord> {
    let path = record_path(dir);
    // A crash in the middle of a replace leaves the record only under its
    // backup name, which would otherwise read as no record at all.
    crate::security::recover_interrupted_replace(&path);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            tracing::warn!("Ignoring an unreadable {RECORD_FILE}: {error}");
            UpdateRecord::default()
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(UpdateRecord::default()),
        Err(error) => {
            tracing::warn!("Could not read {RECORD_FILE}: {error}");
            Err(error)
        }
    }
}

/// Read the record, treating a file that cannot be read as a fresh start. For
/// callers to whom the worst that costs is one check earlier than the cadence.
pub fn load(dir: &Path) -> UpdateRecord {
    let _guard = RECORD_LOCK.lock();
    read(dir).unwrap_or_default()
}

/// Apply `change` to the stored record and write it back. Nothing is written
/// when the stored record cannot be read; an error means the change is not on
/// disk.
pub fn update(dir: &Path, change: impl FnOnce(&mut UpdateRecord)) -> std::io::Result<()> {
    let _guard = RECORD_LOCK.lock();
    let mut record = read(dir)?;
    change(&mut record);
    let bytes = serde_json::to_vec_pretty(&record).map_err(|error| {
        tracing::warn!("Could not serialize {RECORD_FILE}: {error}");
        std::io::Error::other(error)
    })?;
    crate::security::atomic_write(&record_path(dir), &bytes, true).inspect_err(|error| {
        tracing::warn!("Could not write {RECORD_FILE}: {error}");
    })
}

/// Apply `change` to the record in the data folder.
pub fn update_stored(change: impl FnOnce(&mut UpdateRecord)) -> std::io::Result<()> {
    let dir = crate::storage::paths::ensure_data_dir().inspect_err(|error| {
        tracing::warn!("Could not resolve the data folder for {RECORD_FILE}: {error}");
    })?;
    update(&dir, change)
}

/// The record in the data folder, or a fresh one if it cannot be read.
pub fn load_stored() -> UpdateRecord {
    crate::storage::paths::ensure_data_dir()
        .map(|dir| load(&dir))
        .unwrap_or_default()
}

/// The record in the data folder, or an error when it is there and cannot be
/// read right now.
pub fn read_stored() -> std::io::Result<UpdateRecord> {
    let dir = crate::storage::paths::ensure_data_dir()?;
    let _guard = RECORD_LOCK.lock();
    read(&dir)
}

/// Stamp an update check as having been attempted now.
pub fn note_check_attempt() {
    let now = chrono::Utc::now().timestamp();
    *LAST_CHECK_THIS_SESSION.lock() = Some(now);
    let _ = update_stored(|record| record.last_check_at = Some(now));
}

/// When the last update check was attempted: this session's own stamp once it
/// has one, which is never older than the record's, else the record's.
pub fn last_check_at(dir: &Path) -> Option<i64> {
    let this_session = *LAST_CHECK_THIS_SESSION.lock();
    this_session.or_else(|| load(dir).last_check_at)
}

/// Every value `update_check_frequency` may take.
pub const CHECK_FREQUENCIES: &[&str] = &["hourly", "daily", "weekly", "monthly"];

/// Seconds between automatic checks for a `update_check_frequency` value.
/// Anything unrecognised falls back to daily, the default.
pub fn check_interval_secs(frequency: &str) -> i64 {
    match frequency {
        "hourly" => 3600,
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
    fn hourly_checks_once_an_hour() {
        assert!(!check_due(Some(NOW - 3600 + 60), NOW, "hourly"));
        assert!(check_due(Some(NOW - 3600), NOW, "hourly"));
    }

    #[test]
    fn unknown_frequency_is_daily() {
        assert!(!check_due(Some(NOW - DAY + 60), NOW, "yearly"));
        assert!(check_due(Some(NOW - DAY), NOW, "yearly"));
    }

    #[test]
    fn tolerates_a_stamp_slightly_ahead_of_the_clock() {
        assert!(!check_due(Some(NOW + 60), NOW, "daily"));
    }

    #[test]
    fn a_stamp_from_before_the_clock_stepped_back_counts_as_never_checked() {
        assert!(check_due(Some(NOW + 3600), NOW, "daily"));
        assert!(check_due(Some(NOW + 20 * 3600), NOW, "hourly"));
        assert!(check_due(Some(NOW + 365 * DAY), NOW, "monthly"));
    }

    #[test]
    fn round_trips_and_survives_corruption() {
        let dir = temp_dir("round-trip");
        assert_eq!(load(&dir), UpdateRecord::default());

        update(&dir, |record| record.last_check_at = Some(NOW)).unwrap();
        assert_eq!(load(&dir).last_check_at, Some(NOW));

        std::fs::write(dir.join(RECORD_FILE), b"{not json").unwrap();
        assert_eq!(load(&dir), UpdateRecord::default());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_change_that_could_not_be_written_says_so() {
        let dir = temp_dir("unwritable").join("missing");
        assert!(update(&dir, |record| record.last_check_at = Some(NOW)).is_err());
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    /// A record that cannot be read right now is not an empty one: writing
    /// back over it would drop its skip, postpone and failed version for good.
    #[test]
    fn an_unreadable_record_is_left_as_it_is() {
        let dir = temp_dir("unreadable");
        std::fs::create_dir(dir.join(RECORD_FILE)).unwrap();
        let mut changed = false;
        assert!(update(&dir, |_| changed = true).is_err());
        assert!(!changed, "nothing is applied to a record that was never read");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_parked_by_an_interrupted_replace_is_read_back() {
        let dir = temp_dir("interrupted-replace");
        let parked = UpdateRecord {
            skipped_version: Some("1.8.0".to_string()),
            ..Default::default()
        };
        std::fs::write(
            dir.join(format!("{RECORD_FILE}.ember-replace-bak")),
            serde_json::to_vec(&parked).unwrap(),
        )
        .unwrap();
        assert_eq!(load(&dir), parked);

        update(&dir, |record| record.last_check_at = Some(NOW)).unwrap();
        let record = load(&dir);
        assert_eq!(record.skipped_version.as_deref(), Some("1.8.0"));
        assert_eq!(record.last_check_at, Some(NOW));
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
