//! Which folder inside `Downloads` a finished download goes to, by category.
//!
//! eMule gives each category its own incoming folder. Here a category's
//! folder is always inside the download folder's `Downloads`, the folder
//! eMule calls Incoming, so it is inside an approved root, sharing a shared
//! `Downloads` shares it too, and nothing new has to be approved. The setting
//! is `AppSettings::download_category_folders`; a category with no entry
//! finishes in `Downloads` itself.
//!
//! The download workers have no settings or transfer list to read at the
//! moment they finish, and the folder to use is the one in force then, not the
//! one when the download started — the same rule the download folder follows.
//! So the network loop keeps this up to date with the settings, the transfer
//! list with each download's category, and the worker asks here.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Most folder levels below `Downloads`, so `Video/TV Series/Drama` is the
/// deepest. The recorded-file check that lets Open and Reveal reach a file in
/// a download folder no longer approved allows exactly this many.
pub const MAX_DEPTH: usize = 3;

/// Longest folder name at each level, in characters.
pub const MAX_SEGMENT_CHARS: usize = 64;

/// The folder a category value names, cleaned the way finished file names are:
/// split on `/` or `\`, each level trimmed, `.` and `..` and empty levels
/// dropped, at most [`MAX_DEPTH`] levels of at most [`MAX_SEGMENT_CHARS`]
/// characters, and each made safe by `sanitize_filename` — characters Windows
/// refuses become `_`, trailing dots and spaces go, device names get a `_`.
/// `None` when nothing is left, which means `Downloads` itself.
pub fn normalize_folder(value: &str) -> Option<String> {
    let segments = folder_segments(value);
    (!segments.is_empty()).then(|| segments.join("/"))
}

/// [`normalize_folder`] as the folder names, outermost first.
pub fn folder_segments(value: &str) -> Vec<String> {
    value
        .split(['/', '\\'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty() && *segment != "." && *segment != "..")
        .filter_map(|segment| {
            let cut: String = segment.chars().take(MAX_SEGMENT_CHARS).collect();
            let trimmed = cut.trim_end_matches(['.', ' ']);
            if trimmed.is_empty() {
                return None;
            }
            // Replaced here, before `sanitize_filename` sees it: that one reads
            // its input as a path, and on Windows `C:` is a drive prefix there,
            // not a name, so a level named that came back as `unnamed_file`.
            let replaced: String = trimmed
                .chars()
                .map(|c| match c {
                    '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                    c if c.is_control() || crate::security::is_invisible_or_bidi_control_pub(c) => '_',
                    c => c,
                })
                .collect();
            Some(crate::security::sanitize_filename(&replaced))
        })
        .take(MAX_DEPTH)
        .collect()
}

#[derive(Default)]
struct Routes {
    /// Category value to its folder's names, as the settings hold them now.
    folders: HashMap<String, Vec<String>>,
    /// Each download the transfer list holds, to its category.
    categories: HashMap<String, String>,
}

fn routes() -> &'static parking_lot::Mutex<Routes> {
    static ROUTES: std::sync::OnceLock<parking_lot::Mutex<Routes>> = std::sync::OnceLock::new();
    ROUTES.get_or_init(Default::default)
}

/// Take the category folders from the settings now in force.
pub fn set_folders(folders: &BTreeMap<String, String>) {
    let parsed = folders
        .iter()
        .map(|(category, folder)| (category.clone(), folder_segments(folder)))
        .filter(|(_, segments)| !segments.is_empty())
        .collect();
    routes().lock().folders = parsed;
}

/// Remember the category a download has now.
pub fn note_category(transfer_id: &str, category: &str) {
    let mut routes = routes().lock();
    if category.is_empty() {
        routes.categories.remove(transfer_id);
    } else {
        routes
            .categories
            .insert(transfer_id.to_string(), category.to_string());
    }
}

/// Forget a download that has left the transfer list.
pub fn forget(transfer_id: &str) {
    routes().lock().categories.remove(transfer_id);
}

/// The folder names below `Downloads` this download finishes into: its
/// category's folder, or none for `Downloads` itself. Non-blocking.
pub fn completion_subdir(transfer_id: &str) -> Vec<String> {
    let routes = routes().lock();
    routes
        .categories
        .get(transfer_id)
        .and_then(|category| routes.folders.get(category))
        .cloned()
        .unwrap_or_default()
}

/// The folder names below `Downloads` of every category folder in force,
/// each once. For the startup sweeps that look for what an interrupted
/// completion left where finished files land.
pub fn configured_subdirs() -> Vec<Vec<String>> {
    let routes = routes().lock();
    let mut out: Vec<Vec<String>> = Vec::new();
    for segments in routes.folders.values() {
        let taken = out.iter().any(|known| {
            known.len() == segments.len()
                && known
                    .iter()
                    .zip(segments)
                    .all(|(a, b)| same_name(a, b))
        });
        if !taken {
            out.push(segments.clone());
        }
    }
    out
}

/// `Downloads` in `root` and every category folder in it, `Downloads` first.
pub fn finished_download_dirs(root: &Path) -> Vec<PathBuf> {
    let downloads = root.join("Downloads");
    std::iter::once(downloads.clone())
        .chain(configured_subdirs().into_iter().map(|segments| {
            segments
                .iter()
                .fold(downloads.clone(), |dir, segment| dir.join(segment))
        }))
        .collect()
}

/// Folder names as the platform's file system compares them.
fn same_name(a: &str, b: &str) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        a.to_lowercase() == b.to_lowercase()
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_is_cleaned_the_way_finished_file_names_are() {
        assert_eq!(normalize_folder("TV Series").as_deref(), Some("TV Series"));
        assert_eq!(normalize_folder("  Video / TV Series ").as_deref(), Some("Video/TV Series"));
        assert_eq!(normalize_folder(r"Video\Films").as_deref(), Some("Video/Films"));
        assert_eq!(normalize_folder("TV: Series?").as_deref(), Some("TV_ Series_"));
        assert_eq!(normalize_folder("Series.. ").as_deref(), Some("Series"));
        assert_eq!(normalize_folder("CON").as_deref(), Some("_CON"));
        assert_eq!(normalize_folder("a//b").as_deref(), Some("a/b"));
        assert_eq!(normalize_folder("a/b/c/d").as_deref(), Some("a/b/c"), "three levels at most");
        let long = "x".repeat(MAX_SEGMENT_CHARS + 10);
        assert_eq!(
            normalize_folder(&long).map(|f| f.chars().count()),
            Some(MAX_SEGMENT_CHARS)
        );
        // Within the 255 bytes Linux allows a name: 64 four-byte characters
        // would be 256. `categoryFolders.ts` pins the same 63.
        let emoji = "\u{1F3AC}".repeat(MAX_SEGMENT_CHARS + 2);
        let segment = folder_segments(&emoji).remove(0);
        assert_eq!(segment.chars().count(), 63);
        assert!(segment.len() <= 255);
    }

    #[test]
    fn nothing_usable_means_downloads_itself() {
        for value in ["", "   ", "/", ".", "..", "../..", " . / .. ", "..."] {
            assert_eq!(normalize_folder(value), None, "{value:?}");
        }
        // A traversal step is dropped, never followed.
        assert_eq!(normalize_folder("../Films").as_deref(), Some("Films"));
        assert_eq!(normalize_folder("/abs/path").as_deref(), Some("abs/path"));
        assert_eq!(normalize_folder("C:/Films").as_deref(), Some("C_/Films"));
    }

    #[test]
    fn a_download_finishes_into_its_category_folder_at_the_time() {
        let mut folders = BTreeMap::new();
        folders.insert("TV Series".to_string(), "TV Series".to_string());
        folders.insert("Audio".to_string(), "Music/Albums".to_string());
        set_folders(&folders);

        let (tv, song, other) = ("cf-test-tv", "cf-test-song", "cf-test-other");
        note_category(tv, "TV Series");
        note_category(song, "Audio");
        note_category(other, "Unmapped");
        assert_eq!(completion_subdir(tv), vec!["TV Series".to_string()]);
        assert_eq!(completion_subdir(song), vec!["Music".to_string(), "Albums".to_string()]);
        assert!(completion_subdir(other).is_empty(), "no folder: Downloads itself");

        // A category changed before it finishes is the one that counts.
        note_category(tv, "Audio");
        assert_eq!(completion_subdir(tv).len(), 2);
        note_category(tv, "");
        assert!(completion_subdir(tv).is_empty());
        forget(song);
        assert!(completion_subdir(song).is_empty());
        forget(other);
        // The routes are process-wide; leave none behind for other tests.
        set_folders(&BTreeMap::new());
    }
}
