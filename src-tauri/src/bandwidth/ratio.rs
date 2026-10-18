//! eMule's upload/download ratio: a client that uploads very little may not
//! download at full speed.
//!
//! `CPreferences::GetMaxDownloadInBytesPerSec` (eMule 0.50a, unchanged in the
//! community 0.70 builds) holds the download limit to three times the upload
//! limit while that is below 4 KB/s, and to four times it while it is below
//! 10 KB/s. From 10 KB/s up, or with uploads unlimited, the download limit
//! stands as set. An unlimited download limit is capped like any other: eMule
//! stores it as `UNLIMITED` (65535 KB/s), which every capped value is below.
//!
//! eMule's "dynamic" variant, used while Upload SpeedSense is on, measures the
//! cap against the live upload rate instead. Ember measures it against the
//! upload limit the user chose — manual, alternative or scheduled — so the cap
//! is a number Settings can state rather than one that moves every second with
//! however much the queue happens to be asking for.

use serde::Serialize;

/// Upload limits below this, in bytes/s, hold downloads to
/// [`LOW_UPLOAD_RATIO`] times the upload limit.
pub const LOW_UPLOAD_BPS: u64 = 4 * 1024;
pub const LOW_UPLOAD_RATIO: u64 = 3;
/// Upload limits below this, in bytes/s, hold downloads to
/// [`LIMITED_UPLOAD_RATIO`] times the upload limit.
pub const LIMITED_UPLOAD_BPS: u64 = 10 * 1024;
pub const LIMITED_UPLOAD_RATIO: u64 = 4;

/// The ratio rule lowering the download limit, for the Settings note.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DownloadRatioCap {
    /// The download limit in force, bytes/s.
    pub limit: u64,
    /// The multiple of the upload limit that `limit` is.
    pub ratio: u64,
    /// The threshold the upload limit is below, bytes/s.
    pub upload_below: u64,
}

/// The most `upload` (bytes/s, `0` = unlimited) lets downloads run at, or
/// `None` when it imposes nothing.
pub fn download_cap(upload: u64) -> Option<DownloadRatioCap> {
    let (ratio, upload_below) = match upload {
        0 => return None,
        u if u < LOW_UPLOAD_BPS => (LOW_UPLOAD_RATIO, LOW_UPLOAD_BPS),
        u if u < LIMITED_UPLOAD_BPS => (LIMITED_UPLOAD_RATIO, LIMITED_UPLOAD_BPS),
        _ => return None,
    };
    Some(DownloadRatioCap {
        limit: upload * ratio,
        ratio,
        upload_below,
    })
}

/// The download limit to enforce for this pair of limits (both bytes/s,
/// `0` = unlimited), and the cap when it is what lowered it.
///
/// A download limit already at or below the cap is left alone and reports no
/// cap, as eMule's strict `<` does: the note would explain a limit the user
/// set themselves.
pub fn effective_download(upload: u64, download: u64) -> (u64, Option<DownloadRatioCap>) {
    match download_cap(upload) {
        Some(cap) if download == 0 || cap.limit < download => (cap.limit, Some(cap)),
        _ => (download, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KB: u64 = 1024;

    #[test]
    fn under_4_kb_s_downloads_get_three_times_the_upload() {
        let up = LOW_UPLOAD_BPS - 1;
        assert_eq!(
            effective_download(up, 0),
            (
                3 * up,
                Some(DownloadRatioCap {
                    limit: 3 * up,
                    ratio: 3,
                    upload_below: 4 * KB,
                })
            )
        );
        assert_eq!(effective_download(KB, 100 * KB).0, 3 * KB);
    }

    #[test]
    fn at_4_kb_s_the_ratio_becomes_four() {
        let (down, cap) = effective_download(4 * KB, 0);
        assert_eq!(down, 16 * KB);
        assert_eq!(cap.map(|c| (c.ratio, c.upload_below)), Some((4, 10 * KB)));
    }

    #[test]
    fn just_under_10_kb_s_downloads_get_four_times_the_upload() {
        let up = LIMITED_UPLOAD_BPS - 1;
        let (down, cap) = effective_download(up, 0);
        assert_eq!(down, 4 * up);
        assert_eq!(cap.map(|c| c.ratio), Some(4));
    }

    #[test]
    fn from_10_kb_s_the_download_limit_stands() {
        assert_eq!(effective_download(10 * KB, 0), (0, None));
        assert_eq!(effective_download(10 * KB, 500 * KB), (500 * KB, None));
        assert_eq!(download_cap(10 * KB), None);
    }

    #[test]
    fn unlimited_upload_imposes_nothing() {
        assert_eq!(download_cap(0), None);
        assert_eq!(effective_download(0, 0), (0, None));
        assert_eq!(effective_download(0, 7), (7, None));
    }

    /// Unlimited download is not exempt: it is the case the rule exists for.
    #[test]
    fn an_unlimited_download_is_capped() {
        assert_eq!(effective_download(2 * KB, 0).0, 6 * KB);
        assert_eq!(effective_download(5 * KB, 0).0, 20 * KB);
    }

    #[test]
    fn a_download_limit_at_or_below_the_cap_is_left_alone() {
        assert_eq!(effective_download(2 * KB, 5 * KB), (5 * KB, None));
        assert_eq!(effective_download(2 * KB, 6 * KB), (6 * KB, None), "equal is not capped");
        assert_eq!(effective_download(5 * KB, 20 * KB), (20 * KB, None));
        let (down, cap) = effective_download(5 * KB, 20 * KB + 1);
        assert_eq!((down, cap.is_some()), (20 * KB, true));
    }
}
