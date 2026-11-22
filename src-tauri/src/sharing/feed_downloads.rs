//! Files downloaded from a followed feed: each finishes in its feed's own
//! folder, `<download folder>/Feeds/<feed>`, and stays private, as a chat
//! attachment received does. Its partial is neither advertised nor served,
//! and the finished file goes in no index, known.met, KAD or server list. A
//! walk of a shared folder that holds a download folder does not enter that
//! download folder's `Feeds`; sharing `Feeds` itself on purpose still works.
//!
//! A feed whose follower turned on "Share files from this feed" is the
//! exception: its downloads are advertised and served as any download is, and
//! its folder is shared (`sharing::feed_shares`), which a walk passing through
//! `Feeds` enters too. Its downloads are still the feed's, shown on its page
//! rather than among Transfers.
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
    let note = "Ember keeps the files you download from feeds here. They are not shared, \
                but for a feed whose sharing you turned on.\n";
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

/// The folders of the feeds that share their files, by their names
/// lowercased: folder names are unique without case (`unique_folder_name`).
fn sharing() -> &'static parking_lot::RwLock<HashMap<String, String>> {
    static SHARING: std::sync::OnceLock<parking_lot::RwLock<HashMap<String, String>>> =
        std::sync::OnceLock::new();
    SHARING.get_or_init(Default::default)
}

/// Take the feed folders of the downloads the database holds, replacing any.
pub fn load(rows: impl IntoIterator<Item = (String, String)>) {
    *folders().write() = rows.into_iter().collect();
}

/// Take the folders of the feeds that share their files, replacing any.
pub fn set_sharing(folders: impl IntoIterator<Item = String>) {
    *sharing().write() = folders
        .into_iter()
        .filter(|folder| !folder.is_empty())
        .map(|folder| (folder.to_lowercase(), folder))
        .collect();
}

/// Held by tests that set which feeds share, which is process-wide.
#[cfg(test)]
pub(crate) fn sharing_test_lock() -> parking_lot::MutexGuard<'static, ()> {
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    LOCK.lock()
}

/// The folders of the feeds that share their files.
pub fn sharing_folders() -> Vec<String> {
    let mut folders: Vec<String> = sharing().read().values().cloned().collect();
    folders.sort();
    folders
}

/// Whether the feed whose files finish in `folder` shares them.
pub fn shares(folder: &str) -> bool {
    !folder.is_empty() && sharing().read().contains_key(&folder.to_lowercase())
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

/// Whether the download is from a feed, shown on the feed's page and not
/// among Transfers, whether or not the feed shares it.
pub fn is_feed_download(transfer_id: &str) -> bool {
    folders().read().contains_key(transfer_id)
}

/// Whether the download is kept off the network: from a feed that does not
/// share its files.
pub fn is_private(transfer_id: &str) -> bool {
    folders().read().get(transfer_id).is_some_and(|folder| !shares(folder))
}

/// The folders of the feeds that share their files, in the `Feeds` folder
/// `feeds`, that are there. Blocking.
pub fn sharing_dirs_in(feeds: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = sharing()
        .read()
        .values()
        .map(|folder| feeds.join(folder))
        .collect();
    dirs.retain(|dir| std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()));
    dirs.sort();
    dirs
}

/// Take the download folders now in force, current first.
pub fn set_roots(download_roots: &[String]) {
    *feeds_dirs().write() = download_roots
        .iter()
        .filter(|root| !root.trim().is_empty())
        .map(|root| feeds_dir(Path::new(root)).to_string_lossy().into_owned())
        .collect();
}

/// The folders in every `Feeds` there is now. A feed no longer followed
/// leaves its downloads in its folder, which another feed must not be given:
/// sharing that feed's files would share them too. Blocking.
pub fn folders_on_disk() -> Vec<String> {
    let dirs = feeds_dirs().read().clone();
    dirs.iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flat_map(|entries| entries.flatten())
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect()
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
/// itself, or a folder in it, is walked as any shared folder is, and so is
/// the folder of a feed that shares its files: a walk passing `Feeds`
/// enters that one alone.
pub fn walk_passes_feeds_dir(root: &Path, path: &Path) -> bool {
    let root = root.to_string_lossy();
    let chain: Vec<&Path> = path.ancestors().collect();
    chain
        .iter()
        .enumerate()
        .skip(1)
        .take_while(|(_, dir)| {
            let dir = dir.to_string_lossy();
            crate::security::path_within_dir(&dir, &root) && !same_dir(&dir, &root)
        })
        .any(|(at, dir)| {
            is_feeds_dir(dir)
                && !chain[at - 1]
                    .file_name()
                    .is_some_and(|name| shares(&name.to_string_lossy()) && (at >= 2 || path.is_dir()))
        })
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
/// start of the salt after it. [`MARKER`] counts as taken: `Feeds` holds a
/// file of that name, so no folder of it can be made there.
pub fn unique_folder_name(title: &str, salt: &str, taken: &[String]) -> String {
    let base = folder_name(title);
    let free = |name: &str| !name.eq_ignore_ascii_case(MARKER) && !taken.iter().any(|other| other.eq_ignore_ascii_case(name));
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
    fn a_feed_titled_as_the_marker_does_not_take_its_name() {
        let salt = "0123456789abcdef";
        assert_eq!(unique_folder_name(MARKER, salt, &[]), format!("{MARKER} (01234567)"));
        assert_eq!(unique_folder_name(&MARKER.to_uppercase(), salt, &[]), format!("{} (01234567)", MARKER.to_uppercase()));
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
        assert!(is_feed_download(&id));
        forget(&id);
        assert!(!is_private(&id));
        assert!(!is_feed_download(&id));
    }

    /// A feed that shares its files: its downloads go on the network and stay
    /// the feed's, and a walk passing `Feeds` reaches its folder and no other.
    #[test]
    fn a_sharing_feeds_files_are_not_private_and_are_walked_to() {
        let _sharing = sharing_test_lock();
        let shared = format!("Shared {}", uuid::Uuid::new_v4());
        let id = format!("feed-dl-{}", uuid::Uuid::new_v4());
        note(&id, &shared);
        assert!(is_private(&id));

        let root = std::env::temp_dir().join(format!("ember-feeds-share-{}", uuid::Uuid::new_v4()));
        let feeds = feeds_dir(&root);
        std::fs::create_dir_all(feeds.join(&shared)).unwrap();
        std::fs::create_dir_all(feeds.join("Private")).unwrap();
        mark_feeds_dir(&feeds);
        let shared_file = feeds.join(&shared).join("a.mp3");
        let private_file = feeds.join("Private").join("b.mp3");
        assert!(walk_passes_feeds_dir(&root, &shared_file));

        set_sharing([shared.to_uppercase(), String::new()]);
        assert!(shares(&shared), "matched without case");
        assert!(!is_private(&id));
        assert!(is_feed_download(&id), "still shown on the feed's page");
        assert!(!walk_passes_feeds_dir(&root, &shared_file));
        assert!(!walk_passes_feeds_dir(&root, &feeds.join(&shared)), "the folder itself");
        assert!(walk_passes_feeds_dir(&root, &private_file), "another feed's stays private");
        assert!(walk_passes_feeds_dir(&root, &feeds.join(MARKER)));

        set_sharing([shared.clone()]);
        assert_eq!(sharing_dirs_in(&feeds), vec![feeds.join(&shared)]);
        assert_eq!(sharing_folders(), vec![shared.clone()]);

        set_sharing([]);
        assert!(is_private(&id));
        assert!(walk_passes_feeds_dir(&root, &shared_file));
        forget(&id);
        let _ = std::fs::remove_dir_all(&root);
    }
}
