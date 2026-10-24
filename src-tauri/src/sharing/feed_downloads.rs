//! Files downloaded from a followed feed: each finishes in its feed's own
//! folder, `<download folder>/Feeds/<feed>`, and stays private, as a chat
//! attachment received does. Its partial is neither advertised nor served,
//! and the finished file goes in no index, known.met, KAD or server list. A
//! walk of a shared folder that holds a download folder does not enter that
//! download folder's `Feeds`; sharing `Feeds` itself on purpose still works.
//!
//! Which feed folder a download finishes in is kept with it, in the
//! database (`transfer_feed_folders`) and here by transfer id, for the
//! workers and the restore and recovery paths, which have no database to read.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The folder in a download folder that feeds' files finish in, beside
/// `Downloads` rather than in it, so sharing `Downloads` does not share them.
pub const FEEDS_DIR: &str = "Feeds";

/// The name a feed folder takes when a feed's title leaves nothing usable.
const FALLBACK_FOLDER: &str = "Feed";

/// A file Ember leaves in every `Feeds` it makes, so a walk knows the folder
/// for one however the path to it is spelled (a junction, a mapped drive)
/// and after its download folder is no longer one Ember uses. Never shared.
pub const MARKER: &str = ".ember-feeds";

/// Leave [`MARKER`] in the `Feeds` folder `dir`, unless it is there. Best
/// effort: the configured folders are known without it. Blocking.
pub fn mark_feeds_dir(dir: &Path) {
    let marker = dir.join(MARKER);
    if std::fs::symlink_metadata(&marker).is_ok() {
        return;
    }
    let note = "Ember keeps the files you download from feeds here. They are not shared.\n";
    if let Err(error) = std::fs::write(&marker, note) {
        tracing::debug!("Could not mark {} as Ember's Feeds folder: {error}", dir.display());
    }
}

fn folders() -> &'static parking_lot::RwLock<HashMap<String, String>> {
    static FOLDERS: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, String>>> =
        std::sync::OnceLock::new();
    FOLDERS.get_or_init(Default::default)
}

fn feeds_dirs() -> &'static parking_lot::RwLock<Vec<String>> {
    static DIRS: std::sync::OnceLock<parking_lot::RwLock<Vec<String>>> = std::sync::OnceLock::new();
    DIRS.get_or_init(Default::default)
}

/// Take the feed folders of the downloads the database holds, replacing any.
pub fn load(rows: impl IntoIterator<Item = (String, String)>) {
    *folders().write() = rows.into_iter().collect();
}

/// The download `transfer_id` is from a feed, and finishes in its `folder`.
pub fn note(transfer_id: &str, folder: &str) {
    folders().write().insert(transfer_id.to_string(), folder.to_string());
}

/// Forget a download that has left the transfer list.
pub fn forget(transfer_id: &str) {
    folders().write().remove(transfer_id);
}

/// The feed folder the download finishes in; `None` for any other download.
pub fn folder_of(transfer_id: &str) -> Option<String> {
    folders().read().get(transfer_id).cloned()
}

/// Whether the download is from a feed, and so kept private.
pub fn is_private(transfer_id: &str) -> bool {
    folders().read().contains_key(transfer_id)
}

/// Take the download folders now in force, current first.
pub fn set_roots(download_roots: &[String]) {
    *feeds_dirs().write() = download_roots
        .iter()
        .filter(|root| !root.trim().is_empty())
        .map(|root| feeds_dir(Path::new(root)).to_string_lossy().into_owned())
        .collect();
}

/// The `Feeds` folder of the download folder `root`.
pub fn feeds_dir(root: &Path) -> PathBuf {
    root.join(FEEDS_DIR)
}

/// Where a download finishing in `folder` lands, in the download folder `root`.
pub fn folder_dir(root: &Path, folder: &str) -> PathBuf {
    feeds_dir(root).join(folder)
}

/// `Feeds` in the download folder `root` and every feed folder in it, where
/// a completion copy of a feed's download may be left. Blocking.
pub fn finished_dirs(root: &Path) -> Vec<PathBuf> {
    let feeds = feeds_dir(root);
    let subdirs: Vec<PathBuf> = std::fs::read_dir(&feeds)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect();
    std::iter::once(feeds).chain(subdirs).collect()
}

/// Whether `path` is the `Feeds` folder of a download folder: one of those
/// now in force, compared as spelled the way shared folders are, or any
/// `Feeds` holding [`MARKER`]. Blocking only for a folder named `Feeds`.
pub fn is_feeds_dir(path: &Path) -> bool {
    if !path
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case(FEEDS_DIR))
    {
        return false;
    }
    let text = path.to_string_lossy();
    feeds_dirs().read().iter().any(|dir| same_dir(&text, dir))
        || std::fs::symlink_metadata(path.join(MARKER)).is_ok_and(|meta| meta.is_file())
}

/// Whether a walk of `root` passes through a download folder's `Feeds` on
/// the way to `path`, below it, and so never reaches it. `Feeds` shared
/// itself, or a folder in it, is walked as any shared folder is.
pub fn walk_passes_feeds_dir(root: &Path, path: &Path) -> bool {
    let root = root.to_string_lossy();
    path.ancestors()
        .skip(1)
        .take_while(|dir| {
            let dir = dir.to_string_lossy();
            crate::security::path_within_dir(&dir, &root) && !same_dir(&dir, &root)
        })
        .any(is_feeds_dir)
}

fn same_dir(a: &str, b: &str) -> bool {
    crate::security::path_within_dir(a, b) && crate::security::path_within_dir(b, a)
}

/// A folder name for a feed titled `title`: one level, made safe as a
/// category folder's are, `Feed` when nothing usable is left.
pub fn folder_name(title: &str) -> String {
    crate::storage::category_folders::folder_segments(&title.replace(['/', '\\'], "_"))
        .into_iter()
        .next()
        .unwrap_or_else(|| FALLBACK_FOLDER.to_string())
}

/// [`folder_name`] for the feed `salt`, made unlike every one of `taken`,
/// compared without case as Windows does: the name, or the name with the
/// start of the salt after it.
pub fn unique_folder_name(title: &str, salt: &str, taken: &[String]) -> String {
    let base = folder_name(title);
    let free = |name: &str| !taken.iter().any(|other| other.eq_ignore_ascii_case(name));
    if free(&base) {
        return base;
    }
    let short = salt.get(..8).unwrap_or(salt);
    let mut n = 0u32;
    loop {
        let suffix = if n == 0 { format!(" ({short})") } else { format!(" ({short}-{n})") };
        let cut: String = base
            .chars()
            .take(crate::storage::category_folders::MAX_SEGMENT_CHARS.saturating_sub(suffix.chars().count()))
            .collect();
        let name = format!("{}{suffix}", cut.trim_end_matches(['.', ' ']));
        if free(&name) {
            return name;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_feed_title_makes_one_safe_folder() {
        assert_eq!(folder_name("Mixes"), "Mixes");
        assert_eq!(folder_name("AC/DC: Live"), "AC_DC_ Live");
        assert_eq!(folder_name("..\\..\\Windows"), ".._.._Windows");
        assert_eq!(folder_name("CON"), "_CON");
        assert_eq!(folder_name("  ...  "), "Feed");
        assert_eq!(folder_name(""), "Feed");
        assert!(folder_name(&"x".repeat(200)).chars().count() <= crate::storage::category_folders::MAX_SEGMENT_CHARS);
    }

    #[test]
    fn two_feeds_of_one_title_get_their_own_folders() {
        let salt = "0123456789abcdef";
        assert_eq!(unique_folder_name("Mixes", salt, &[]), "Mixes");
        assert_eq!(unique_folder_name("Mixes", salt, &["mixes".into()]), "Mixes (01234567)");
        assert_eq!(
            unique_folder_name("Mixes", salt, &["Mixes".into(), "Mixes (01234567)".into()]),
            "Mixes (01234567-1)"
        );
        let long = unique_folder_name(&"y".repeat(64), salt, &["y".repeat(64)]);
        assert!(long.chars().count() <= crate::storage::category_folders::MAX_SEGMENT_CHARS);
        assert!(long.ends_with(" (01234567)"));
    }

    #[test]
    fn a_walk_does_not_enter_a_download_folders_feeds() {
        let root = std::env::temp_dir().join(format!("ember-feeds-walk-{}", std::process::id()));
        set_roots(&[root.to_string_lossy().into_owned()]);
        let feeds = feeds_dir(&root);
        let file = feeds.join("Mixes").join("a.mp3");
        assert!(is_feeds_dir(&feeds));
        assert!(!is_feeds_dir(&root.join("Downloads").join(FEEDS_DIR)), "a user's own folder of that name");
        assert!(walk_passes_feeds_dir(&root, &file), "sharing the download folder");
        assert!(walk_passes_feeds_dir(root.parent().unwrap(), &file), "sharing a folder above it");
        assert!(!walk_passes_feeds_dir(&feeds, &file), "sharing Feeds on purpose");
        assert!(!walk_passes_feeds_dir(&feeds.join("Mixes"), &file), "sharing one feed's folder on purpose");
        assert!(!walk_passes_feeds_dir(&root, &root.join("Downloads").join("a.mp3")));
        set_roots(&[]);
    }

    /// A `Feeds` Ember made is known by its marker once its download folder
    /// is no longer one Ember uses, or when reached by another spelling.
    #[test]
    fn a_marked_feeds_folder_is_known_without_its_download_folder() {
        let root = std::env::temp_dir().join(format!("ember-feeds-marker-{}", uuid::Uuid::new_v4()));
        let feeds = feeds_dir(&root);
        std::fs::create_dir_all(feeds.join("Mixes")).unwrap();
        let file = feeds.join("Mixes").join("a.mp3");
        assert!(!is_feeds_dir(&feeds), "neither configured nor marked");
        assert!(!walk_passes_feeds_dir(&root, &file));
        mark_feeds_dir(&feeds);
        mark_feeds_dir(&feeds);
        assert!(is_feeds_dir(&feeds));
        assert!(walk_passes_feeds_dir(&root, &file));
        assert!(!walk_passes_feeds_dir(&feeds, &file), "sharing Feeds on purpose");
        assert!(crate::sharing::indexer::is_excluded_share_file_name(&feeds.join(MARKER)));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_download_is_private_while_it_has_a_feed_folder() {
        let id = format!("feed-dl-{}", uuid::Uuid::new_v4());
        assert!(!is_private(&id));
        note(&id, "Mixes");
        assert_eq!(folder_of(&id).as_deref(), Some("Mixes"));
        assert!(is_private(&id));
        forget(&id);
        assert!(!is_private(&id));
    }
}
