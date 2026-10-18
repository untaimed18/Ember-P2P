use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing::info;

const MIN_PREVIEW_SIZE: u64 = 16 * 1024;
const COPY_BUFFER_SIZE: usize = 16 * 1024;

/// Ceiling on each verified run copied into the preview temp file (the head,
/// and for [`TRAILING_INDEX_EXTENSIONS`] the tail).
///
/// The contiguous MD4-verified run reaches the end of the file on a nearly
/// complete download, and copying all of it duplicated multiple gigabytes into
/// the temp directory — and blocked the command for as long as that took — to
/// answer a question ("is this the file it claims to be?") that a few minutes
/// of playable media settles. Well above the first-256 KB window
/// [`can_preview`] gates on, so the preview stays genuinely watchable.
pub const PREVIEW_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Containers that normally keep the index a player needs before it can
/// decode anything (the MP4 `moov` box) at the end of the file, addressed by
/// absolute offsets into the media data. A head-only copy of one of these
/// opens in the player and then shows nothing, which is why preview priority
/// fetches the last part as well as the first.
const TRAILING_INDEX_EXTENSIONS: &[&str] = &["mp4", "m4v", "mov", "m4a", "3gp"];
static PREVIEW_TEMP: OnceLock<
    parking_lot::Mutex<Option<crate::security::filesystem::PinnedTempDir>>,
> = OnceLock::new();

/// The preview written by the previous call, so it can be reclaimed.
///
/// Only one preview is ever useful at a time — [`launch_preview`] hands the path
/// to the shell and nothing else reads it — but each call used to add a new
/// randomly-named file and leave every earlier one in place. Bounded only by
/// [`PREVIEW_MAX_BYTES`] apiece, twenty previews in a session left well over a
/// gigabyte behind, and previewing the same file twice left two copies.
static LAST_PREVIEW: OnceLock<parking_lot::Mutex<Option<PathBuf>>> = OnceLock::new();

/// Drop the preview from the previous call.
///
/// Best-effort: on Windows the media player may still hold the file open, in
/// which case the removal fails and the shutdown `remove_dir_all` — plus the
/// startup sweep for directories a crash left behind — remains the backstop.
/// Replacing the path either way keeps at most one deletable file outstanding.
fn reclaim_previous_preview(next: &Path) {
    let mut guard = LAST_PREVIEW
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock();
    if let Some(previous) = guard.replace(next.to_path_buf()) {
        if previous != next {
            if let Err(error) = std::fs::remove_file(&previous) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!(%error, "could not remove the previous preview file");
                }
            }
        }
    }
}

const VIDEO_EXTENSIONS: &[&str] = &[
    "avi", "mp4", "mkv", "wmv", "mpg", "mpeg", "mov", "flv", "webm", "m4v", "3gp", "divx", "ogm",
    "ogv", "rm", "rmvb", "ts", "vob",
];

const AUDIO_EXTENSIONS: &[&str] = &[
    "mp3", "ogg", "wav", "flac", "aac", "wma", "m4a", "opus", "ape",
];

#[derive(Debug)]
pub struct FilledRange {
    pub start: u64,
    pub end: u64,
}

pub fn is_previewable_extension(ext: &str) -> bool {
    let ext_lower = ext.to_lowercase();
    VIDEO_EXTENSIONS.contains(&ext_lower.as_str()) || AUDIO_EXTENSIONS.contains(&ext_lower.as_str())
}

/// Check if a partially downloaded file is ready for preview.
///
/// Requires:
/// - Previewable file type (audio/video extension).
/// - Minimum downloaded size.
/// - All **parts** covering the preview window (the first ED2K part) have
///   been MD4-verified against the known hashset. This prevents a malicious
///   source from feeding arbitrary bytes to the user's media player: a part
///   only reaches `verified_complete_parts[idx] == true` after its MD4 hash
///   matched `part_hashes[idx]`.
/// - `verified_complete_parts` must reflect tracker state AFTER any AICH
///   recovery / `mark_incomplete` has been applied, and `part_hashes` must be
///   the hashset bound to `file_hash`.
pub fn can_preview(
    file_name: &str,
    file_size: u64,
    completed_bytes: u64,
    has_part_hashes: bool,
    verified_complete_parts: &[bool],
    part_size: u64,
) -> bool {
    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();

    if !is_previewable_extension(&ext) {
        return false;
    }

    if completed_bytes < MIN_PREVIEW_SIZE {
        return false;
    }

    // Without a verified hashset we cannot know whether the bytes on disk
    // match what the publisher intended. Refuse to launch.
    if !has_part_hashes || verified_complete_parts.is_empty() || part_size == 0 {
        return false;
    }

    // Require every part covering [0, preview_end) to be verified.
    let first_256k = 256 * 1024u64;
    let preview_end = first_256k.min(file_size);
    let required_parts = preview_end.div_ceil(part_size) as usize;
    if required_parts == 0 || required_parts > verified_complete_parts.len() {
        return false;
    }
    verified_complete_parts[..required_parts]
        .iter()
        .all(|&ok| ok)
}

/// The MD4-verified byte ranges a preview copies, in ascending order.
///
/// The contiguous verified run from the start of the file, and nothing past
/// the first gap. Copying every verified part instead sized the preview to the
/// last one and left the holes between as zeros: with preview priority
/// fetching the first and last parts first, the player got a full-length file
/// whose middle was silence, and read its duration off that.
///
/// [`TRAILING_INDEX_EXTENSIONS`] are the exception. They cannot play at all
/// without their tail, and they read their duration from the index rather
/// than the file length, so the contiguous verified run at the end of the
/// file is copied too, at its real offset, leaving a hole in between.
///
/// Each run is bounded by [`PREVIEW_MAX_BYTES`]: on a nearly complete
/// download the head run *is* the whole file.
pub fn preview_ranges(
    file_name: &str,
    file_size: u64,
    verified_parts: &[bool],
    part_size: u64,
) -> Vec<FilledRange> {
    let mut ranges = Vec::new();
    let leading = verified_parts.iter().take_while(|&&ok| ok).count() as u64;
    let head_end = leading
        .saturating_mul(part_size)
        .min(file_size)
        .min(PREVIEW_MAX_BYTES);
    if head_end > 0 {
        ranges.push(FilledRange {
            start: 0,
            end: head_end,
        });
    }

    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if TRAILING_INDEX_EXTENSIONS.contains(&ext.as_str()) {
        let trailing = verified_parts.iter().rev().take_while(|&&ok| ok).count();
        if trailing > 0 {
            let first_tail_part = (verified_parts.len() - trailing) as u64;
            let tail_start = first_tail_part
                .saturating_mul(part_size)
                .max(file_size.saturating_sub(PREVIEW_MAX_BYTES))
                .max(head_end);
            if tail_start < file_size {
                ranges.push(FilledRange {
                    start: tail_start,
                    end: file_size,
                });
            }
        }
    }
    ranges
}

/// Ask the filesystem not to allocate the unwritten parts of `file`.
///
/// A preview with a tail is as long as the download, and NTFS fills every
/// byte below a write with real zeros unless the file is sparse — which would
/// put back the multi-gigabyte copy [`PREVIEW_MAX_BYTES`] exists to prevent.
#[cfg(windows)]
fn mark_sparse(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_SET_SPARSE;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut returned: u32 = 0;
    // SAFETY: `file` owns the handle for the duration of the call, and
    // FSCTL_SET_SPARSE takes no input or output buffers.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Elsewhere the filesystem leaves a region past `set_len` unallocated on its own.
#[cfg(not(windows))]
fn mark_sparse(_file: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

/// Create a temporary preview file by copying filled ranges.
pub fn create_preview_file(
    part_file_path: &Path,
    verified_ranges: &[FilledRange],
    file_name: &str,
) -> anyhow::Result<PathBuf> {
    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut temp_guard = PREVIEW_TEMP
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock();
    if temp_guard.is_none() {
        *temp_guard = Some(crate::security::filesystem::PinnedTempDir::create(
            "preview",
        )?);
    }
    let temp_dir = temp_guard
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("preview temp directory unavailable"))?;
    temp_dir.verify()?;

    let stem = Path::new(file_name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "preview".to_string());

    // Route the temp filename through the same sanitizer used for downloads so
    // a hostile `file_name` can't produce traversal, reserved-device, or other
    // odd names in the preview dir. `sanitize_filename` returns a single path
    // component, which keeps the joined result inside `temp_dir`.
    let raw = if ext.is_empty() {
        format!("{stem}_preview")
    } else {
        format!("{stem}_preview.{ext}")
    };
    let safe = crate::security::sanitize_filename(&raw);
    let safe_path = Path::new(&safe);
    let safe_stem = safe_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("preview");
    let safe_ext = safe_path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let (preview_path, mut dst) = temp_dir.create_random_file(safe_stem, safe_ext)?;

    let mut src = std::fs::File::open(part_file_path)?;

    let contiguous = verified_ranges
        .iter()
        .scan(0u64, |reached, range| {
            (range.start == *reached).then(|| *reached = range.end)
        })
        .count();
    let mut verified_ranges = verified_ranges;
    if contiguous < verified_ranges.len() {
        if let Err(error) = mark_sparse(&dst) {
            tracing::warn!(
                %error,
                "the preview temp folder cannot hold sparse files; previewing the start of the file only"
            );
            verified_ranges = &verified_ranges[..contiguous];
        }
    }

    let last_end = verified_ranges.iter().map(|r| r.end).max().unwrap_or(0);
    dst.set_len(last_end)?;

    let mut buf = vec![0u8; COPY_BUFFER_SIZE];

    for range in verified_ranges {
        if range.start >= range.end || range.end > src.metadata()?.len() {
            drop(dst);
            let _ = std::fs::remove_file(&preview_path);
            anyhow::bail!("invalid MD4-verified preview range");
        }
        src.seek(SeekFrom::Start(range.start))?;
        dst.seek(SeekFrom::Start(range.start))?;

        let mut remaining = range.end - range.start;
        while remaining > 0 {
            let to_read = (remaining as usize).min(COPY_BUFFER_SIZE);
            let n = src.read(&mut buf[..to_read])?;
            if n == 0 {
                drop(dst);
                let _ = std::fs::remove_file(&preview_path);
                anyhow::bail!(
                    "unexpected EOF copying preview range [{}, {}), {} bytes remaining",
                    range.start,
                    range.end,
                    remaining
                );
            }
            dst.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
    }

    dst.sync_all()?;
    // Only after the new one is complete on disk, so a failure above leaves the
    // previous preview playable rather than deleting it for a replacement that
    // never arrived.
    reclaim_previous_preview(&preview_path);
    // Log the basename only — the full path can contain the username / folder
    // layout (PII) and shows up in default logs and support bundles.
    info!(
        "Created preview file: {}",
        preview_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<preview>")
    );
    Ok(preview_path)
}

/// The external player to use, if the configured one is usable.
///
/// `None` means "hand it to the system's default handler", which covers both
/// the unconfigured case and a configured player that is no longer there.
///
/// A missing player falls back rather than failing. The setting is opt-in and
/// the complaint it answers was that Preview did nothing at all, so a player
/// that has since been uninstalled or moved must not put it back in that
/// state — the caller logs the mismatch instead.
fn resolve_player(configured: &str) -> Option<PathBuf> {
    if configured.is_empty() {
        return None;
    }
    let path = PathBuf::from(configured);
    // The path's authority came from the native picker at the moment it was
    // set (see `pick_preview_player`), but config.json can also arrive from a
    // restored backup.
    player_is_usable(&path).then_some(path)
}

/// Whether Preview would start `path`: a regular file on a local drive whose
/// real location, after links, is local too. The one check both the picker
/// and the launch use, so a player the picker accepts is never then ignored.
pub(crate) fn player_is_usable(path: &Path) -> bool {
    // Before anything touches the path: merely opening a UNC path makes
    // Windows authenticate to that host.
    if !player_path_is_local(path) || !path.is_file() {
        return false;
    }
    // A local path can still be a link onto a share.
    std::fs::canonicalize(path).is_ok_and(|real| player_path_is_local(&real))
}

/// Whether `path` names a program on a local drive: absolute, and on Windows
/// a drive-letter path whose drive is not a network mapping. UNC, device and
/// relative paths are refused.
///
/// Does not touch `path` itself, so it is safe to ask about a path that has
/// not been vetted yet. A drive that is merely absent passes; the caller's
/// own file check handles that.
pub(crate) fn player_path_is_local(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let letter = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
                _ => return false,
            },
            _ => return false,
        };
        if !path.is_absolute() || !letter.is_ascii_alphabetic() {
            return false;
        }
        drive_is_not_remote(letter)
    }
    #[cfg(not(windows))]
    {
        path.is_absolute()
    }
}

#[cfg(windows)]
fn drive_is_not_remote(letter: u8) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_REMOTE: u32 = 4;
    let root: Vec<u16> = format!("{}:\\", letter as char)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `root` is a NUL-terminated UTF-16 string that outlives the call.
    unsafe { GetDriveTypeW(root.as_ptr()) != DRIVE_REMOTE }
}

/// Launch the user's media player for the file, or the system default.
///
/// `configured_player` is `AppSettings::preview_player`, empty when the user
/// has not chosen one.
pub fn launch_preview(file_path: &Path, configured_player: &str) -> anyhow::Result<()> {
    // Basename only — avoid logging the full local path (PII) at info level.
    info!(
        "Launching preview: {}",
        file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<file>")
    );

    let declared = file_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("preview path has no usable name"))?;
    // Still enforced when an explicit player is configured. The allowlist is
    // about what these bytes are, not about who opens them: the copy came off
    // the wire, and `can_preview` gating on the extension is only worth
    // anything if the extension is checked against the content here too.
    if !crate::security::filesystem::passive_type_agrees(declared, file_path) {
        anyhow::bail!("preview type is not on the passive launch allowlist");
    }
    match resolve_player(configured_player) {
        Some(player) => {
            crate::security::filesystem::launch_with_player(&player, file_path)?;
        }
        None => {
            if !configured_player.is_empty() {
                tracing::warn!(
                    "The configured media player is no longer there or is not on a local drive; \
                     using the default handler"
                );
            }
            crate::security::filesystem::open_with_default_app(file_path)?;
        }
    }
    Ok(())
}

/// Clean up preview temp files. Removes all files in the preview directory.
pub fn cleanup_previews() {
    if let Some(last) = LAST_PREVIEW.get() {
        last.lock().take();
    }
    if let Some(temp) = PREVIEW_TEMP.get() {
        temp.lock().take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A preview is copied and then handed to the shell, so everything
    /// [`can_preview`] accepts has to be on the one-click launch allowlist as
    /// well. It was not: `.flv`, `.ts`, `.vob`, `.3gp`, `.divx`, `.ogm`,
    /// `.ogv`, `.rm`, `.rmvb`, `.wma` and `.ape` all reported `preview_ready`,
    /// so the button enabled itself, the verified prefix was copied, and
    /// `launch_preview` then refused at the last step.
    #[test]
    fn every_previewable_extension_can_actually_be_launched() {
        for ext in VIDEO_EXTENSIONS.iter().chain(AUDIO_EXTENSIONS) {
            let name = format!("clip.{ext}");
            assert!(
                crate::security::filesystem::passive_type_agrees(&name, Path::new(&name)),
                "{ext} is previewable but not launchable"
            );
        }
    }

    /// The setting exists because Preview had no way to say which player to
    /// use. It must not become a new way for Preview to do nothing: a player
    /// that has been uninstalled or moved since it was chosen falls back to
    /// the system handler rather than failing the launch.
    #[test]
    fn a_missing_player_falls_back_to_the_default_handler() {
        assert_eq!(resolve_player(""), None, "unconfigured");
        let absent = std::env::temp_dir().join(format!(
            "ember-player-that-is-not-there-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        assert_eq!(
            resolve_player(&absent.to_string_lossy()),
            None,
            "configured but gone"
        );
        // A directory would spawn nothing, so it is not a player either.
        assert_eq!(
            resolve_player(&std::env::temp_dir().to_string_lossy()),
            None,
            "a directory is not a program"
        );

        let player = std::env::temp_dir().join(format!(
            "ember-player-{}-{}.exe",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&player, b"not really a program").unwrap();
        assert_eq!(
            resolve_player(&player.to_string_lossy()),
            Some(player.clone()),
            "a configured player that is still there is used"
        );
        let _ = std::fs::remove_file(&player);
    }

    /// config.json can come from a restored backup, so the player path cannot
    /// be trusted to be one the picker produced.
    #[test]
    fn a_player_that_is_not_on_a_local_drive_is_refused() {
        assert!(!player_path_is_local(Path::new("relative\\player.exe")));
        assert!(!player_path_is_local(Path::new("relative/player")));
        #[cfg(windows)]
        {
            for remote in [
                r"\\attacker\share\p.exe",
                r"\\?\UNC\attacker\share\p.exe",
                r"\\.\pipe\p.exe",
                r"\Windows\System32\cmd.exe",
                "C:player.exe",
            ] {
                assert!(!player_path_is_local(Path::new(remote)), "{remote}");
                assert_eq!(resolve_player(remote), None, "{remote}");
            }
            let local = std::env::temp_dir().join("player.exe");
            assert!(player_path_is_local(&local));
        }
    }

    #[test]
    fn preview_copies_only_supplied_verified_ranges() {
        let part = std::env::temp_dir().join(format!(
            "ember-preview-range-test-{}-{}.part",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&part, b"GOODUNVERIFIED").unwrap();
        let preview =
            create_preview_file(&part, &[FilledRange { start: 0, end: 4 }], "movie.mp4").unwrap();
        assert_eq!(std::fs::read(&preview).unwrap(), b"GOOD");
        let _ = std::fs::remove_file(preview);
        let _ = std::fs::remove_file(part);
    }

    fn spans(ranges: &[FilledRange]) -> Vec<(u64, u64)> {
        ranges.iter().map(|r| (r.start, r.end)).collect()
    }

    #[test]
    fn a_preview_stops_at_the_first_gap() {
        let size = 3 * 100 - 40;
        assert_eq!(
            spans(&preview_ranges("movie.mkv", size, &[true, false, true], 100)),
            vec![(0, 100)]
        );
        assert_eq!(
            spans(&preview_ranges("movie.mkv", size, &[true, true, true], 100)),
            vec![(0, size)]
        );
    }

    /// An MP4 whose `moov` is at the end opened as a blank window when only
    /// the head was copied, though preview priority had already fetched the
    /// last part.
    #[test]
    fn an_mp4_preview_keeps_its_verified_tail_at_its_real_offset() {
        let size = 4 * 100 - 40;
        assert_eq!(
            spans(&preview_ranges("Movie.MP4", size, &[true, false, true, true], 100)),
            vec![(0, 100), (200, size)]
        );
        assert_eq!(
            spans(&preview_ranges("movie.mp4", size, &[true, false, false, false], 100)),
            vec![(0, 100)],
            "no verified tail yet"
        );
        assert_eq!(
            spans(&preview_ranges("movie.mp4", size, &[true; 4], 100)),
            vec![(0, size)],
            "a complete run is not split in two"
        );
    }

    #[test]
    fn each_preview_run_is_capped() {
        let part = 10 * 1024 * 1024;
        let size = 100 * part;
        let mut verified = vec![true; 100];
        assert_eq!(
            spans(&preview_ranges("movie.mkv", size, &verified, part)),
            vec![(0, PREVIEW_MAX_BYTES)]
        );
        verified[50] = false;
        assert_eq!(
            spans(&preview_ranges("movie.mp4", size, &verified, part)),
            vec![(0, PREVIEW_MAX_BYTES), (size - PREVIEW_MAX_BYTES, size)]
        );
    }

    #[test]
    fn a_preview_with_a_tail_leaves_the_gap_empty() {
        let part = std::env::temp_dir().join(format!(
            "ember-preview-tail-test-{}-{}.part",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&part, b"HEADskipTAIL").unwrap();
        let preview = create_preview_file(
            &part,
            &[
                FilledRange { start: 0, end: 4 },
                FilledRange { start: 8, end: 12 },
            ],
            "movie.mp4",
        )
        .unwrap();
        assert_eq!(std::fs::read(&preview).unwrap(), b"HEAD\0\0\0\0TAIL");
        let _ = std::fs::remove_file(preview);
        let _ = std::fs::remove_file(part);
    }
}
