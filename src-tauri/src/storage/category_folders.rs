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

/// Most folder levels a category's folder has, so `Video/TV Series/Drama` is
/// the deepest.
pub const MAX_CATEGORY_DEPTH: usize = 3;

/// Most folder levels a collection entry's own folder has (`Season 1/Extras`).
pub const MAX_COLLECTION_ENTRY_DEPTH: usize = 4;

/// Most folder levels a download from a collection adds below its category's
/// folder: the collection's name, then the entry's folders.
pub const MAX_COLLECTION_DEPTH: usize = 1 + MAX_COLLECTION_ENTRY_DEPTH;

/// Most folder levels below `Downloads` a finished download can be in: its
/// category's folder, then its collection's. The recorded-file check that lets
/// Open and Reveal reach a file in a download folder no longer approved allows
/// exactly this many.
pub const MAX_DEPTH: usize = MAX_CATEGORY_DEPTH + MAX_COLLECTION_DEPTH;

/// Longest folder name at each level, in characters.
pub const MAX_SEGMENT_CHARS: usize = 64;

/// The folder a category value names, cleaned the way finished file names are:
/// split on `/` or `\`, each level trimmed, `.` and `..` and empty levels
/// dropped, at most [`MAX_CATEGORY_DEPTH`] levels of at most
/// [`MAX_SEGMENT_CHARS`] characters, and each made safe by `sanitize_filename`
/// — characters Windows refuses become `_`, trailing dots and spaces go, device
/// names get a `_`. `None` when nothing is left, which means `Downloads`
/// itself.
pub fn normalize_folder(value: &str) -> Option<String> {
    let segments = folder_segments(value);
    (!segments.is_empty()).then(|| segments.join("/"))
}

/// [`normalize_folder`] as the folder names, outermost first.
pub fn folder_segments(value: &str) -> Vec<String> {
    segments_of(value, MAX_CATEGORY_DEPTH)
}

/// A collection entry's folder (`Season 1/Extras`), cleaned as a category's is
/// but to [`MAX_COLLECTION_ENTRY_DEPTH`] levels, `/`-joined; empty for the
/// collection's top level. A collection comes from anyone, so this is what
/// stands between its folder tag and the download folder: nothing it names can
/// climb out, be absolute, or name a device.
pub fn normalize_collection_entry_folder(value: &str) -> String {
    segments_of(value, MAX_COLLECTION_ENTRY_DEPTH).join("/")
}

/// The folders a download from the collection `collection_name` finishes in
/// below its category's folder: the collection's name as one level (a `/` in
/// it is part of the name, not a level), then `entry_folder`'s levels. Empty
/// when neither leaves anything.
pub fn collection_segments(collection_name: &str, entry_folder: &str) -> Vec<String> {
    clean_segment(collection_name)
        .into_iter()
        .chain(segments_of(entry_folder, MAX_COLLECTION_ENTRY_DEPTH))
        .take(MAX_COLLECTION_DEPTH)
        .collect()
}

fn segments_of(value: &str, max: usize) -> Vec<String> {
    value
        .split(['/', '\\'])
        .filter_map(clean_segment)
        .take(max)
        .collect()
}

/// One folder level made safe, or `None` when nothing usable is left.
fn clean_segment(segment: &str) -> Option<String> {
    let segment = segment.trim();
    if segment.is_empty() || segment == "." || segment == ".." {
        return None;
    }
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
}

#[derive(Default)]
struct Routes {
    /// Category value to its folder's names, as the settings hold them now.
    folders: HashMap<String, Vec<String>>,
    /// Each download the transfer list holds, to its category.
    categories: HashMap<String, String>,
    /// Each download from a collection, to its collection's folders below the
    /// category's (see [`collection_segments`]).
    collections: HashMap<String, Vec<String>>,
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

/// Remember that the download `transfer_id` came from a collection and
/// finishes in `segments` below its category's folder (see
/// [`collection_segments`]). Empty forgets it.
pub fn note_collection_folder(transfer_id: &str, segments: Vec<String>) {
    let mut routes = routes().lock();
    if segments.is_empty() {
        routes.collections.remove(transfer_id);
    } else {
        routes.collections.insert(transfer_id.to_string(), segments);
    }
}

/// Take the collection folders of the downloads the database holds, as
/// `/`-joined folders, replacing any. Each is cleaned again on the way in.
pub fn load_collection_folders(rows: impl IntoIterator<Item = (String, String)>) {
    let parsed = rows
        .into_iter()
        .map(|(transfer_id, folder)| (transfer_id, segments_of(&folder, MAX_COLLECTION_DEPTH)))
        .filter(|(_, segments)| !segments.is_empty())
        .collect();
    routes().lock().collections = parsed;
}

/// Forget a download that has left the transfer list.
pub fn forget(transfer_id: &str) {
    let mut routes = routes().lock();
    routes.categories.remove(transfer_id);
    routes.collections.remove(transfer_id);
}

/// Forget a finished download's category, keeping its collection folder: a
/// category changed after it finished moves the file to the new category's
/// folder and keeps it in its collection's folders there.
pub fn forget_category(transfer_id: &str) {
    routes().lock().categories.remove(transfer_id);
}

/// The collection folders a download finishes in below its category's, or
/// none for a download that did not come from a collection.
pub fn collection_subdir(transfer_id: &str) -> Vec<String> {
    routes()
        .lock()
        .collections
        .get(transfer_id)
        .cloned()
        .unwrap_or_default()
}

/// The folder names below `Downloads` this download finishes into: its
/// category's folder, then its collection's, or none for `Downloads` itself.
/// Non-blocking.
pub fn completion_subdir(transfer_id: &str) -> Vec<String> {
    let routes = routes().lock();
    subdir_in(&routes, transfer_id)
}

fn subdir_in(routes: &Routes, transfer_id: &str) -> Vec<String> {
    routes
        .categories
        .get(transfer_id)
        .and_then(|category| routes.folders.get(category))
        .into_iter()
        .flatten()
        .chain(routes.collections.get(transfer_id).into_iter().flatten())
        .take(MAX_DEPTH)
        .cloned()
        .collect()
}

/// The folder names below `Downloads` of every category folder in force, and
/// of every collection folder a download in the list finishes in, each once.
/// For the startup sweeps that look for what an interrupted completion left
/// where finished files land.
pub fn configured_subdirs() -> Vec<Vec<String>> {
    let routes = routes().lock();
    let mut out: Vec<Vec<String>> = Vec::new();
    let collection_dirs: Vec<Vec<String>> = routes
        .collections
        .keys()
        .map(|transfer_id| subdir_in(&routes, transfer_id))
        .collect();
    for segments in routes.folders.values().chain(collection_dirs.iter()) {
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
        assert_eq!(MAX_CATEGORY_DEPTH, 3);
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

    /// The routes are process-wide, so the tests that set them take turns.
    static ROUTES_TEST: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn a_download_finishes_into_its_category_folder_at_the_time() {
        let _turn = ROUTES_TEST.lock();
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

    /// A collection's folders come from whoever wrote it, so nothing in them
    /// may climb out, be absolute, name a device or run deeper than allowed.
    #[test]
    fn a_collection_folder_cannot_leave_the_download_folder() {
        assert_eq!(normalize_collection_entry_folder("Season 1/Extras"), "Season 1/Extras");
        assert_eq!(normalize_collection_entry_folder(r"..\..\Windows\System32"), "Windows/System32");
        assert_eq!(normalize_collection_entry_folder("/etc/passwd"), "etc/passwd");
        assert_eq!(normalize_collection_entry_folder("C:/Users"), "C_/Users");
        assert_eq!(normalize_collection_entry_folder("CON/aux"), "_CON/_aux");
        assert_eq!(normalize_collection_entry_folder("a/b/c/d/e/f"), "a/b/c/d", "four levels at most");
        assert_eq!(normalize_collection_entry_folder(" . / .. "), "");

        assert_eq!(collection_segments("My Show", "Season 1"), vec!["My Show", "Season 1"]);
        assert_eq!(
            collection_segments("Show/Name", "S1"),
            vec!["Show_Name", "S1"],
            "the collection's name is one level"
        );
        assert_eq!(collection_segments("..", "S1"), vec!["S1"]);
        assert!(collection_segments("", "").is_empty());
        assert_eq!(collection_segments("N", "a/b/c/d/e").len(), MAX_COLLECTION_DEPTH);
    }

    #[test]
    fn a_collection_download_finishes_below_its_category_folder() {
        let _turn = ROUTES_TEST.lock();
        let mut folders = BTreeMap::new();
        folders.insert("Video".to_string(), "Video".to_string());
        set_folders(&folders);
        let (with_category, without) = ("cf-coll-a", "cf-coll-b");
        note_category(with_category, "Video");
        note_collection_folder(with_category, collection_segments("Show", "Season 1"));
        load_collection_folders([(without.to_string(), "Show/../Season 2".to_string())]);
        assert!(completion_subdir(with_category) == vec!["Video".to_string()], "load replaced the map");

        note_collection_folder(with_category, collection_segments("Show", "Season 1"));
        assert_eq!(completion_subdir(with_category), vec!["Video", "Show", "Season 1"]);
        assert_eq!(completion_subdir(without), vec!["Show", "Season 2"]);
        assert!(configured_subdirs().contains(&vec!["Video".to_string(), "Show".into(), "Season 1".into()]));
        assert!(completion_subdir(with_category).len() <= MAX_DEPTH);

        forget(with_category);
        forget(without);
        assert!(completion_subdir(with_category).is_empty());
        assert!(completion_subdir(without).is_empty());
        set_folders(&BTreeMap::new());
    }
}
