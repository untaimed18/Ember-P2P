//! The daily upload quota: once a set amount has been uploaded since local
//! midnight, uploads are held to a lower speed until the next one.
//!
//! For connections metered by volume, and for ISPs that throttle or flag a
//! home line once its daily upload passes some amount. The time-of-day
//! schedule cannot express that, since what decides it is how much has gone
//! out, not when.
//!
//! The count is what passed through the bandwidth limiter: file data to eD2K
//! peers, friends, rooms and feed followers, and relays. Control traffic does
//! not (KAD, eD2K server UDP, the Ember DHT), nor does protocol overhead below
//! the limiter (TCP, IP, encryption padding), so an ISP measuring at the line
//! sees a few percent more; the quota is set in whole gigabytes, which leaves
//! room for that.
//!
//! Downloads are left alone once it is reached, unlike under every other
//! upload limit, which holds downloads to a multiple of a very low upload
//! rate (`ratio`, eMule's rule against taking without giving): the quota is
//! there to keep a metered line within its allowance, and slowing downloads
//! would spend a user's evening for no saving on the upload side.
//!
//! The day is the local calendar day, because that is the day the user setting
//! "per day" means. The count survives a restart through a small file, and a
//! day that has ended starts again at zero however long Ember was closed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Bytes in the quota's gigabyte: decimal, as an ISP's data cap is written.
pub const BYTES_PER_GB: u64 = 1_000_000_000;

/// How far the count moves between the writes made while Ember runs: each is
/// a synced replace of the file, and eD2K traffic moves the count every
/// minute. What a crash loses is at most this; leaving writes any change.
pub const SAVE_STEP: u64 = 10_000_000;

/// The file the day's count is kept in, beside the other runtime state.
pub fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join("upload_quota.json")
}

/// What is kept across a restart: which day it is, and how much went out in it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    day: String,
    bytes: u64,
}

/// Today's upload count.
///
/// The limiter counts what this process has uploaded since it started. Today's
/// total is what earlier sessions uploaded today, plus what this one has since
/// the day began or the session did, whichever was later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UploadQuota {
    day: String,
    /// Uploaded today before `session_base` was taken.
    carried: u64,
    /// The limiter's session total when today began counting.
    session_base: u64,
    /// The count last written to disk, so an unchanged one is not written again.
    saved: Option<Saved>,
}

impl UploadQuota {
    /// The count for a session starting now on `today`, from what `saved` held.
    fn starting(today: &str, saved: Option<Saved>) -> Self {
        let (day, carried) = match &saved {
            Some(saved) if !starts_a_new_day(&saved.day, today) => (saved.day.clone(), saved.bytes),
            _ => (today.to_string(), 0),
        };
        Self {
            day,
            carried,
            session_base: 0,
            saved,
        }
    }

    /// Read the count from `path`. A missing or unreadable file is a day with
    /// nothing uploaded yet, which errs toward letting uploads through.
    pub fn load(path: &Path, today: &str) -> Self {
        crate::security::recover_interrupted_replace(path);
        let saved = std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Saved>(&bytes).ok());
        Self::starting(today, saved)
    }

    /// Bytes uploaded on `today`, given the limiter's session total now.
    ///
    /// A new day starts the count again from the session total as it stands,
    /// so what went out before midnight is yesterday's.
    pub fn observe(&mut self, today: &str, session_total: u64) -> u64 {
        if starts_a_new_day(&self.day, today) {
            self.day = today.to_string();
            self.carried = 0;
            self.session_base = session_total;
        }
        self.carried
            .saturating_add(session_total.saturating_sub(self.session_base))
    }

    /// The bytes to write to disk, if the day changed since the last write or
    /// the count moved by `min_step` or more (any amount, given 0). The caller
    /// writes them and then calls [`Self::note_saved`].
    pub fn pending_save(&self, session_total: u64, min_step: u64) -> Option<Vec<u8>> {
        let now = Saved {
            day: self.day.clone(),
            bytes: self
                .carried
                .saturating_add(session_total.saturating_sub(self.session_base)),
        };
        if self.saved.as_ref().is_some_and(|saved| {
            saved.day == now.day && (saved.bytes == now.bytes || saved.bytes.abs_diff(now.bytes) < min_step)
        }) {
            return None;
        }
        serde_json::to_vec(&now).ok()
    }

    /// Record that `bytes` (from [`Self::pending_save`]) reached the disk.
    pub fn note_saved(&mut self, bytes: &[u8]) {
        if let Ok(saved) = serde_json::from_slice::<Saved>(bytes) {
            self.saved = Some(saved);
        }
    }
}

/// Whether the count kept for `day` gives way to `today`'s: the date moved on,
/// or back by more than a day, as when a clock set wrongly ahead is corrected.
/// A step back of a day at most (a clock adjusted around midnight, a move one
/// time zone west) keeps counting into the day already under way, so it can
/// neither lift a quota already reached nor wipe what the day has used.
fn starts_a_new_day(day: &str, today: &str) -> bool {
    let parse = |text: &str| chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").ok();
    match (parse(day), parse(today)) {
        (Some(day), Some(today)) => today > day || (day - today).num_days() > 1,
        _ => day != today,
    }
}

/// Write a [`UploadQuota::pending_save`] payload. Blocking.
pub fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    crate::security::atomic_write(path, bytes, true)
}

/// The upload speed the quota holds uploads to right now, or `None` while it
/// has not been reached (or is off).
pub fn cap(settings: &crate::types::AppSettings, uploaded_today: u64) -> Option<u64> {
    if !settings.upload_quota_enabled {
        return None;
    }
    let quota = u64::from(settings.upload_quota_gb).saturating_mul(BYTES_PER_GB);
    (uploaded_today >= quota).then_some(settings.upload_quota_speed)
}

/// `upload` (bytes/s, `0` = unlimited) with the quota's `cap` applied: the
/// lower of the two, so the quota never raises a limit already below it.
pub fn apply(upload: u64, cap: Option<u64>) -> u64 {
    match cap {
        None => upload,
        Some(cap) if upload == 0 => cap,
        Some(cap) => upload.min(cap),
    }
}

/// Today's local date, as the quota keys its count.
pub fn local_today() -> String {
    chrono::Local::now().date_naive().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(enabled: bool, gb: u32, speed: u64) -> crate::types::AppSettings {
        crate::types::AppSettings {
            upload_quota_enabled: enabled,
            upload_quota_gb: gb,
            upload_quota_speed: speed,
            ..Default::default()
        }
    }

    #[test]
    fn the_quota_holds_uploads_once_reached_and_never_raises_a_limit() {
        let on = settings(true, 2, 20_000);
        assert_eq!(cap(&on, 2 * BYTES_PER_GB - 1), None, "just under");
        assert_eq!(cap(&on, 2 * BYTES_PER_GB), Some(20_000), "reached");
        assert_eq!(cap(&settings(false, 2, 20_000), 10 * BYTES_PER_GB), None, "off");

        assert_eq!(apply(0, Some(20_000)), 20_000, "unlimited is held to the quota speed");
        assert_eq!(apply(100_000, Some(20_000)), 20_000);
        assert_eq!(apply(5_000, Some(20_000)), 5_000, "a lower limit stands");
        assert_eq!(apply(100_000, None), 100_000);
    }

    #[test]
    fn todays_count_carries_across_a_restart_and_starts_over_on_a_new_day() {
        let saved = Saved {
            day: "2026-11-06".into(),
            bytes: 700,
        };
        let mut quota = UploadQuota::starting("2026-11-06", Some(saved.clone()));
        assert_eq!(quota.observe("2026-11-06", 0), 700, "earlier sessions today count");
        assert_eq!(quota.observe("2026-11-06", 300), 1_000);

        let mut stale = UploadQuota::starting("2026-11-07", Some(saved));
        assert_eq!(stale.observe("2026-11-07", 50), 50, "yesterday's count is not today's");

        // Midnight mid-session: what went out before it is yesterday's.
        assert_eq!(quota.observe("2026-11-07", 1_300), 0);
        assert_eq!(quota.observe("2026-11-07", 1_450), 150);
    }

    #[test]
    fn the_count_is_written_only_when_it_moved() {
        let mut quota = UploadQuota::starting("2026-11-06", None);
        quota.observe("2026-11-06", 10);
        let first = quota.pending_save(10, SAVE_STEP).expect("a new count is written");
        quota.note_saved(&first);
        assert!(quota.pending_save(10, 0).is_none(), "unchanged");
        assert!(quota.pending_save(11, SAVE_STEP).is_none(), "not far enough to write while running");
        let moved = quota.pending_save(11, 0).expect("written on the way out");
        let back: Saved = serde_json::from_slice(&moved).unwrap();
        assert_eq!(back, Saved { day: "2026-11-06".into(), bytes: 11 });
        assert!(quota.pending_save(10 + SAVE_STEP, SAVE_STEP).is_some(), "a step on");
        quota.observe("2026-11-07", 11);
        assert!(quota.pending_save(11, SAVE_STEP).is_some(), "a new day is written at once");
    }

    #[test]
    fn a_clock_stepping_back_keeps_the_day_already_under_way() {
        let mut quota = UploadQuota::starting("2026-11-09", None);
        assert_eq!(quota.observe("2026-11-09", 500), 500);
        assert_eq!(quota.observe("2026-11-08", 600), 600, "back across midnight: still counting");
        assert_eq!(quota.observe("2026-11-09", 700), 700);
        assert_eq!(quota.observe("2026-11-01", 800), 0, "a clock set wrongly ahead, corrected");
        let saved = Saved { day: "2026-11-09".into(), bytes: 900 };
        let mut restarted = UploadQuota::starting("2026-11-08", Some(saved));
        assert_eq!(restarted.observe("2026-11-08", 0), 900, "and across a restart");
    }

    #[test]
    fn the_count_round_trips_through_its_file() {
        let dir = std::env::temp_dir().join(format!("ember-quota-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = path_in(&dir);
        let mut quota = UploadQuota::starting("2026-11-06", None);
        quota.observe("2026-11-06", 0);
        let bytes = quota.pending_save(4_242, 0).unwrap();
        write(&path, &bytes).unwrap();
        let mut reloaded = UploadQuota::load(&path, "2026-11-06");
        assert_eq!(reloaded.observe("2026-11-06", 0), 4_242);
        let mut garbage_dir = UploadQuota::load(&dir.join("missing.json"), "2026-11-06");
        assert_eq!(garbage_dir.observe("2026-11-06", 0), 0, "no file is nothing uploaded");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
