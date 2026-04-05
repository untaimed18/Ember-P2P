use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tracing::info;

const MIN_PREVIEW_SIZE: u64 = 16 * 1024;
const COPY_BUFFER_SIZE: usize = 16 * 1024;

const VIDEO_EXTENSIONS: &[&str] = &[
    "avi", "mp4", "mkv", "wmv", "mpg", "mpeg", "mov", "flv", "webm",
    "m4v", "3gp", "divx", "ogm", "ogv", "rm", "rmvb", "ts", "vob",
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
/// Requires: first part downloaded, minimum size, previewable file type.
pub fn can_preview(
    file_name: &str,
    file_size: u64,
    filled_ranges: &[FilledRange],
    completed_bytes: u64,
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

    if filled_ranges.is_empty() {
        return false;
    }

    let first_256k = 256 * 1024u64;
    let check_end = first_256k.min(file_size);
    filled_ranges.iter().any(|r| r.start == 0 && r.end >= check_end)
}

/// Create a temporary preview file by copying filled ranges.
pub fn create_preview_file(
    part_file_path: &Path,
    filled_ranges: &[FilledRange],
    file_name: &str,
) -> anyhow::Result<PathBuf> {
    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();

    let temp_dir = std::env::temp_dir().join("ember_preview");
    std::fs::create_dir_all(&temp_dir)?;

    let stem = Path::new(file_name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "preview".to_string())
        .replace(['/', '\\', ':', '\0'], "_");
    let ext = ext.replace(['/', '\\', ':', '\0'], "_");

    let preview_path = temp_dir.join(format!("{stem}_preview.{ext}"));

    let mut src = std::fs::File::open(part_file_path)?;
    let mut dst = std::fs::File::create(&preview_path)?;

    let last_end = filled_ranges.iter().map(|r| r.end).max().unwrap_or(0);
    dst.set_len(last_end)?;

    let mut buf = vec![0u8; COPY_BUFFER_SIZE];

    for range in filled_ranges {
        src.seek(SeekFrom::Start(range.start))?;
        dst.seek(SeekFrom::Start(range.start))?;

        let mut remaining = range.end - range.start;
        while remaining > 0 {
            let to_read = (remaining as usize).min(COPY_BUFFER_SIZE);
            let n = src.read(&mut buf[..to_read])?;
            if n == 0 {
                tracing::warn!(
                    "Preview: unexpected EOF copying range [{}, {}), {} bytes remaining",
                    range.start, range.end, remaining
                );
                break;
            }
            dst.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
    }

    dst.sync_all()?;
    info!("Created preview file: {}", preview_path.display());
    Ok(preview_path)
}

/// Launch the system default media player for the file.
pub fn launch_preview(file_path: &Path) -> anyhow::Result<()> {
    info!("Launching preview: {}", file_path.display());

    #[cfg(target_os = "windows")]
    {
        opener::open(file_path)?;
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(file_path)
            .spawn()?;
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(file_path)
            .spawn()?;
    }

    Ok(())
}

/// Clean up preview temp files. Removes all files in the preview directory.
pub fn cleanup_previews() {
    let temp_dir = std::env::temp_dir().join("ember_preview");
    if temp_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(&temp_dir);
    }
}
