//! Which download folder holds a download's `.part`.
//!
//! A download keeps its `.part` and `.part.met` in the `Temp` of the download
//! folder it started in, and its finished file goes to the `Downloads` of the
//! folder that is current when it completes — eMule keeps its temp
//! directories apart from the incoming one the same way. Changing the
//! download folder therefore leaves unfinished downloads where they are, and
//! the old folder is remembered in `AppSettings::previous_download_folders`
//! until none of them is left in it.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The most earlier download folders remembered at once, newest first. Each
/// is an approved root, so a restored or hand-edited config cannot list an
/// unbounded number of them.
pub const MAX_PREVIOUS_DOWNLOAD_FOLDERS: usize = 16;

/// How long startup waits for the earlier download folders to be listed. An
/// offline network share can hold `read_dir` for tens of seconds, and this
/// runs before the window exists.
const STARTUP_LISTING_BUDGET: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DownloadFolders {
    pub current: PathBuf,
    pub previous: Vec<PathBuf>,
}

/// Held by the workers and the upload listener, which outlive a settings
/// change: a running download completes into the folder current at that
/// moment, not the one it was started under.
pub type SharedDownloadFolders = Arc<parking_lot::RwLock<DownloadFolders>>;

/// Where [`DownloadFolders::locate_part`] found a download's part files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartLocation {
    /// This folder's `Temp` holds its `.part` or `.part.met`.
    Found(PathBuf),
    /// No folder holds either; these folders could not be looked at.
    Absent { unreachable: Vec<PathBuf> },
}

/// Where each download's part files were last found or opened, this session
/// or (restored from the database's record) the last. Read by the network
/// loop, which must not touch the disk to answer.
fn located() -> &'static parking_lot::Mutex<HashMap<String, PathBuf>> {
    static LOCATED: std::sync::OnceLock<parking_lot::Mutex<HashMap<String, PathBuf>>> =
        std::sync::OnceLock::new();
    LOCATED.get_or_init(Default::default)
}

/// Remember that this download's part files are in `folder`.
pub fn note_located(transfer_id: &str, folder: &Path) {
    located()
        .lock()
        .insert(transfer_id.to_string(), folder.to_path_buf());
}

/// The folder this download's part files were last found in. Non-blocking.
pub fn located_folder(transfer_id: &str) -> Option<PathBuf> {
    located().lock().get(transfer_id).cloned()
}

/// Whether `folder` can be looked at: it exists, or it is gone from a volume
/// that is still there. Only the volume decides — the drive or share root on
/// Windows, the mount point elsewhere — so a folder the user deleted, parents
/// and all, is not taken for an unplugged drive.
fn folder_reachable(folder: &Path) -> bool {
    #[cfg(test)]
    if unplugged_volumes()
        .lock()
        .iter()
        .any(|volume| folder.starts_with(volume))
    {
        return false;
    }
    match std::fs::symlink_metadata(folder) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => volume_present(folder),
        Err(_) => false,
    }
}

#[cfg(test)]
fn unplugged_volumes() -> &'static parking_lot::Mutex<Vec<PathBuf>> {
    static UNPLUGGED: std::sync::OnceLock<parking_lot::Mutex<Vec<PathBuf>>> =
        std::sync::OnceLock::new();
    UNPLUGGED.get_or_init(Default::default)
}

/// Make every folder under `volume` read as on a volume that is not there,
/// or, with `unplugged` false, as it really is.
#[cfg(test)]
pub(crate) fn simulate_unplugged(volume: &Path, unplugged: bool) {
    let mut volumes = unplugged_volumes().lock();
    volumes.retain(|known| known != volume);
    if unplugged {
        volumes.push(volume.to_path_buf());
    }
}

/// Whether the drive letter or share `folder` is on answers.
#[cfg(windows)]
fn volume_present(folder: &Path) -> bool {
    folder
        .ancestors()
        .last()
        .is_some_and(|root| std::fs::symlink_metadata(root).is_ok())
}

/// Whether the volume `folder` is on is mounted: its nearest existing
/// ancestor is not where removable and network volumes are mounted, nor an
/// empty mount point there.
#[cfg(unix)]
fn volume_present(folder: &Path) -> bool {
    for ancestor in folder.ancestors().skip(1) {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => return !where_volumes_mount(ancestor) && !unmounted_mount_point(ancestor),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
    }
    false
}

/// `/` and the folders removable and network volumes are mounted in.
#[cfg(unix)]
fn where_volumes_mount(dir: &Path) -> bool {
    ["/", "/mnt", "/media", "/run/media", "/Volumes"]
        .iter()
        .any(|mounts| dir == Path::new(mounts))
        || dir.parent().is_some_and(|parent| {
            parent == Path::new("/media") || parent == Path::new("/run/media")
        })
}

/// An empty folder where volumes are mounted, as an fstab mount point is
/// while its volume is not.
#[cfg(unix)]
fn unmounted_mount_point(dir: &Path) -> bool {
    dir.parent().is_some_and(where_volumes_mount)
        && std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_none())
}

impl DownloadFolders {
    pub fn new(current: &str, previous: &[String]) -> Self {
        Self {
            current: PathBuf::from(current),
            previous: previous
                .iter()
                .filter(|folder| !folder.is_empty())
                .map(PathBuf::from)
                .collect(),
        }
    }

    pub fn shared(self) -> SharedDownloadFolders {
        Arc::new(parking_lot::RwLock::new(self))
    }

    fn all(&self) -> impl Iterator<Item = &Path> {
        std::iter::once(self.current.as_path())
            .chain(self.previous.iter().map(PathBuf::as_path))
            .filter(|folder| !folder.as_os_str().is_empty())
    }

    /// Every folder as an approved-root string, current first.
    pub fn roots(&self) -> Vec<String> {
        self.all()
            .map(|folder| folder.to_string_lossy().into_owned())
            .collect()
    }

    /// Where `<transfer_id>.part` would be in each folder, current first.
    pub fn part_paths(&self, transfer_id: &str) -> Vec<PathBuf> {
        self.all()
            .map(|folder| folder.join("Temp").join(format!("{transfer_id}.part")))
            .collect()
    }

    /// The first folder, current first, whose `Temp` holds this download's
    /// `.part` or `.part.met`. Blocking.
    pub fn locate_part(&self, transfer_id: &str) -> PartLocation {
        let names = [
            format!("{transfer_id}.part"),
            format!("{transfer_id}.part.met"),
        ];
        let mut unreachable = Vec::new();
        for folder in self.all() {
            let temp = folder.join("Temp");
            if names
                .iter()
                .any(|name| std::fs::symlink_metadata(temp.join(name)).is_ok())
            {
                note_located(transfer_id, folder);
                return PartLocation::Found(folder.to_path_buf());
            }
            if !folder_reachable(folder) {
                unreachable.push(folder.to_path_buf());
            }
        }
        PartLocation::Absent { unreachable }
    }

    /// The folder whose `Temp` holds this download's `.part` or `.part.met`,
    /// or the current one for a download that has neither yet.
    ///
    /// Blocking, but it only touches the disk when there are previous folders.
    pub fn part_folder_for(&self, transfer_id: &str) -> PathBuf {
        if self.previous.is_empty() {
            return self.current.clone();
        }
        match self.locate_part(transfer_id) {
            PartLocation::Found(folder) => folder,
            PartLocation::Absent { .. } => self.current.clone(),
        }
    }

    /// `<folder>/Temp/<transfer_id>.part` in [`Self::part_folder_for`].
    pub fn part_path_for(&self, transfer_id: &str) -> PathBuf {
        self.part_folder_for(transfer_id)
            .join("Temp")
            .join(format!("{transfer_id}.part"))
    }

    /// The folder a download worker opens this download's `.part` in, or
    /// `Err` with the folder its part files were last in when that one
    /// cannot be reached.
    ///
    /// Starting such a download in the current folder would begin a second
    /// `.part` from zero, and once the drive came back the current folder's
    /// copy would win and strand the real progress. A download found nowhere
    /// whose folder is not offline, or is not known, starts over in the
    /// current folder. Blocking.
    pub fn folder_to_resume_in(&self, transfer_id: &str) -> Result<PathBuf, PathBuf> {
        if self.previous.is_empty() {
            return Ok(self.current.clone());
        }
        match self.locate_part(transfer_id) {
            PartLocation::Found(folder) => Ok(folder),
            PartLocation::Absent { unreachable } => {
                let last_seen = located_folder(transfer_id);
                let holding = last_seen.and_then(|last_seen| {
                    unreachable.into_iter().find(|folder| {
                        same_folder(&folder.to_string_lossy(), &last_seen.to_string_lossy())
                    })
                });
                match holding {
                    Some(folder) => Err(folder),
                    None => Ok(self.current.clone()),
                }
            }
        }
    }
}

/// The id a `.part` or `.part.met` file name belongs to.
fn part_owner(name: &str) -> Option<&str> {
    name.strip_suffix(".part.met")
        .or_else(|| name.strip_suffix(".part"))
        .filter(|id| !id.is_empty())
}

/// Whether a part file owner is one the startup orphan sweep
/// (`commands::transfers::sweep_orphan_part_files`) manages: a download's
/// UUID or a room transfer.
fn swept_owner(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok() || id.starts_with("ember-xfer-")
}

/// Whether `folder`'s `Temp` holds a part file whose owner `keep` accepts.
///
/// A folder that cannot be reached at all counts as holding one: an unplugged
/// drive or an offline share is no evidence that its downloads are gone, and
/// forgetting the folder would revoke its approval for when it comes back.
fn holds_parts(folder: &Path, keep: impl Fn(&str) -> bool) -> bool {
    match std::fs::read_dir(folder.join("Temp")) {
        Ok(entries) => entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(part_owner)
                .is_some_and(&keep)
        }),
        Err(_) => !folder_reachable(folder),
    }
}

/// The owners of the part files in `folder`'s `Temp`, or `None` when the
/// folder cannot be reached. Blocking.
fn part_owners(folder: &Path) -> Option<HashSet<String>> {
    match std::fs::read_dir(folder.join("Temp")) {
        Ok(entries) => Some(
            entries
                .flatten()
                .filter_map(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .and_then(part_owner)
                        .map(str::to_string)
                })
                .collect(),
        ),
        Err(_) => folder_reachable(folder).then(HashSet::new),
    }
}

/// What startup learns about a download folder: the owners of the part files
/// in its `Temp` (`None`: it cannot be reached) and what it resolves to
/// (`None`: unknown).
#[derive(Clone, Debug, Default)]
struct FolderListing {
    owners: Option<HashSet<String>>,
    canonical: Option<PathBuf>,
}

/// Each folder's [`FolderListing`], read in parallel. A folder that has not
/// answered within `budget` counts as unreachable; its thread is left to
/// finish on its own.
fn list_folders_within(folders: &[PathBuf], budget: Duration) -> Vec<FolderListing> {
    let (tx, rx) = std::sync::mpsc::channel();
    for (index, folder) in folders.iter().enumerate() {
        let tx = tx.clone();
        let folder = folder.clone();
        let spawned = std::thread::Builder::new()
            .name("ember-part-folder-listing".into())
            .spawn(move || {
                let listing = FolderListing {
                    owners: part_owners(&folder),
                    canonical: folder.canonicalize().ok(),
                };
                let _ = tx.send((index, listing));
            });
        if let Err(e) = spawned {
            tracing::warn!("Could not list {}: {e}", folders[index].display());
        }
    }
    drop(tx);
    let mut listings = vec![FolderListing::default(); folders.len()];
    let deadline = std::time::Instant::now() + budget;
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((index, listing)) => listings[index] = listing,
            Err(_) => break,
        }
    }
    listings
}

fn same_folder(a: &str, b: &str) -> bool {
    crate::commands::settings::normalized_path_components(Path::new(a))
        == crate::commands::settings::normalized_path_components(Path::new(b))
}

/// The previous download folders once the download folder moves from
/// `old_current` to `new_current`.
///
/// Any part file at all keeps a folder: something may still be writing it — a
/// running download, a chat attachment, a room transfer — and each of those
/// needs the folder approved until it finishes. Startup narrows this down to
/// the downloads that survive a restart ([`retain_needed`]). Blocking.
pub fn previous_after_change(
    old_current: &str,
    old_previous: &[String],
    new_current: &str,
) -> Vec<String> {
    let mut previous: Vec<String> = Vec::new();
    for folder in std::iter::once(old_current).chain(old_previous.iter().map(String::as_str)) {
        if folder.is_empty()
            || same_folder(folder, new_current)
            || previous.iter().any(|kept| same_folder(kept, folder))
        {
            continue;
        }
        if holds_parts(Path::new(folder), |_| true) {
            previous.push(folder.to_string());
        }
    }
    previous.truncate(MAX_PREVIOUS_DOWNLOAD_FOLDERS);
    previous
}

/// What the database says about the unfinished downloads.
#[derive(Debug, Default)]
pub struct UnfinishedDownloads {
    /// Every one of them, whose part files the orphan sweep leaves alone.
    pub ids: HashSet<String>,
    /// Those with bytes on disk, each with the folder its `.part` was last
    /// recorded in (empty when unknown).
    pub with_progress: HashMap<String, String>,
}

/// The previous download folders still needed, given `listings[i]` for
/// `folders[i]`. `folders[0]` is the current folder and the rest are the
/// previous ones, in order.
///
/// A folder that can be listed is kept while it holds a part file of an
/// unfinished download, or an orphan the startup sweep is about to remove
/// from it — forgotten first, the folder would lose its approval and the
/// orphan, which can be a whole file whose removal failed after completion,
/// would stay behind for good. One that cannot be listed is kept only while
/// an unfinished download with progress in none of the folders that can was
/// last recorded in it.
fn retain_needed(
    folders: &[PathBuf],
    listings: &[FolderListing],
    unfinished: &UnfinishedDownloads,
) -> Vec<String> {
    let listed: Vec<&HashSet<String>> = listings
        .iter()
        .filter_map(|listing| listing.owners.as_ref())
        .collect();
    let stranded_in: Vec<&str> = unfinished
        .with_progress
        .iter()
        .filter(|(id, _)| !listed.iter().any(|owners| owners.contains(*id)))
        .map(|(_, recorded)| recorded.as_str())
        .filter(|recorded| !recorded.is_empty())
        .collect();
    folders
        .iter()
        .zip(listings)
        .skip(1)
        .filter(|(folder, listing)| match &listing.owners {
            Some(owners) => owners
                .iter()
                .any(|id| unfinished.ids.contains(id) || swept_owner(id)),
            None => stranded_in
                .iter()
                .any(|recorded| same_folder(recorded, &folder.to_string_lossy())),
        })
        .map(|(folder, _)| folder.to_string_lossy().into_owned())
        .collect()
}

/// The previous folders, in order, that pass the download folder's checks
/// on what they resolve to — the config load could only check the text — and
/// resolve to a folder neither the current one nor an earlier entry does.
/// One that did not resolve is kept: the checks on its text stand.
fn resolve_previous(folders: &[PathBuf], listings: &[FolderListing]) -> Vec<usize> {
    let mut taken: Vec<Vec<String>> = listings[0]
        .canonical
        .iter()
        .map(|canonical| crate::commands::settings::normalized_path_components(canonical))
        .collect();
    let mut kept = Vec::new();
    for (index, listing) in listings.iter().enumerate().skip(1) {
        if let Some(canonical) = &listing.canonical {
            if crate::commands::settings::resolved_download_folder_refused(canonical) {
                tracing::warn!(
                    "Forgetting earlier download folder that resolves to where downloads cannot \
                     go: {}",
                    folders[index].display()
                );
                continue;
            }
            let key = crate::commands::settings::normalized_path_components(canonical);
            if taken.contains(&key) {
                continue;
            }
            taken.push(key);
        }
        kept.push(index);
    }
    kept
}

/// Check the previous download folders against what they resolve to, and
/// forget those no unfinished download needs any more. Runs at startup,
/// before the approved roots are built from the settings: nothing is writing
/// to them yet, and only a download the database still lists can resume from
/// one. Touches the disk for at most [`STARTUP_LISTING_BUDGET`].
pub fn forget_finished_previous_folders(
    db: &crate::storage::database::Database,
    config: &mut crate::storage::config::AppConfig,
) {
    let previous = &config.settings.previous_download_folders;
    if previous.is_empty() {
        return;
    }
    let folders: Vec<PathBuf> = std::iter::once(config.settings.download_folder.as_str())
        .chain(previous.iter().map(String::as_str))
        .map(PathBuf::from)
        .collect();
    let listings = list_folders_within(&folders, STARTUP_LISTING_BUDGET);
    let resolved = resolve_previous(&folders, &listings);
    let folders: Vec<PathBuf> = std::iter::once(0)
        .chain(resolved.iter().copied())
        .map(|index| folders[index].clone())
        .collect();
    let listings: Vec<FolderListing> = std::iter::once(0)
        .chain(resolved.iter().copied())
        .map(|index| listings[index].clone())
        .collect();
    let kept = match (
        db.incomplete_downloads_owning_partials(),
        db.incomplete_downloads_with_progress(),
    ) {
        (Ok(ids), Ok(with_progress)) => {
            retain_needed(&folders, &listings, &UnfinishedDownloads { ids, with_progress })
        }
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(
                "Keeping earlier download folders: unfinished downloads unreadable ({e})"
            );
            folders[1..]
                .iter()
                .map(|folder| folder.to_string_lossy().into_owned())
                .collect()
        }
    };
    if kept.len() == previous.len() {
        return;
    }
    let mut settings = config.settings.clone();
    settings.previous_download_folders = kept;
    let saved = config
        .prepare_save_settings(&settings)
        .and_then(|(data, tmp, path)| {
            crate::storage::config::AppConfig::write_to_disk(&data, &tmp, &path)
        });
    match saved {
        Ok(()) => config.settings = settings,
        Err(e) => tracing::warn!("Could not forget finished download folders: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ember-part-folders-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn folder(&self, name: &str) -> String {
            let folder = self.0.join(name);
            std::fs::create_dir_all(folder.join("Temp")).unwrap();
            folder.to_string_lossy().into_owned()
        }

        /// A folder on a volume that is not there.
        fn offline(&self, name: &str) -> String {
            simulate_unplugged(&self.unplugged(), true);
            self.unplugged().join(name).to_string_lossy().into_owned()
        }

        fn unplugged(&self) -> PathBuf {
            self.0.join("unplugged")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            simulate_unplugged(&self.unplugged(), false);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn touch(folder: &str, name: &str) {
        std::fs::write(Path::new(folder).join("Temp").join(name), b"x").unwrap();
    }

    fn uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    fn a_download_is_found_in_the_folder_it_started_in() {
        let scratch = Scratch::new();
        let old = scratch.folder("old");
        let new = scratch.folder("new");
        touch(&old, "started-before.part");
        touch(&old, "only-met.part.met");
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&old));

        assert_eq!(
            folders.part_folder_for("started-before"),
            PathBuf::from(&old)
        );
        assert_eq!(
            folders.part_path_for("started-before"),
            PathBuf::from(&old).join("Temp").join("started-before.part")
        );
        assert_eq!(
            folders.part_folder_for("only-met"),
            PathBuf::from(&old),
            "a `.part.met` alone still says where the download's progress is"
        );
        assert_eq!(
            folders.part_folder_for("brand-new"),
            PathBuf::from(&new),
            "a download with nothing on disk starts in the current folder"
        );
        touch(&new, "started-before.part");
        assert_eq!(
            folders.part_folder_for("started-before"),
            PathBuf::from(&new),
            "the current folder wins if both have one"
        );
    }

    #[test]
    fn a_located_part_is_remembered_without_asking_the_disk_again() {
        let scratch = Scratch::new();
        let old = scratch.folder("old");
        let new = scratch.folder("new");
        let id = uuid();
        touch(&old, &format!("{id}.part"));
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&old));
        assert_eq!(located_folder(&id), None);

        folders.part_folder_for(&id);
        assert_eq!(located_folder(&id), Some(PathBuf::from(&old)));
    }

    #[test]
    fn a_download_whose_folder_is_offline_is_held_rather_than_restarted() {
        let scratch = Scratch::new();
        let new = scratch.folder("new");
        let offline = scratch.offline("old");
        let other_offline = scratch.offline("older");
        let folders = DownloadFolders::new(&new, &[offline.clone(), other_offline.clone()]);

        let seen_there = uuid();
        note_located(&seen_there, Path::new(&offline));
        assert_eq!(
            folders.folder_to_resume_in(&seen_there),
            Err(PathBuf::from(&offline)),
            "its progress is on the drive that is not connected"
        );

        let restored_unrecorded = uuid();
        assert_eq!(
            folders.folder_to_resume_in(&restored_unrecorded),
            Ok(PathBuf::from(&new)),
            "with no record of where it was, it starts over rather than wait for any drive"
        );

        let seen_in_current = uuid();
        note_located(&seen_in_current, Path::new(&new));
        assert_eq!(
            folders.folder_to_resume_in(&seen_in_current),
            Ok(PathBuf::from(&new)),
            "an offline folder it was never in does not hold it"
        );

        let seen_in_a_reachable_earlier_folder = uuid();
        let gone = scratch.folder("gone");
        note_located(&seen_in_a_reachable_earlier_folder, Path::new(&gone));
        assert_eq!(
            folders.folder_to_resume_in(&seen_in_a_reachable_earlier_folder),
            Ok(PathBuf::from(&new)),
            "its folder is there and its part is not: it starts over"
        );
    }

    #[test]
    fn a_held_download_resumes_once_its_folder_is_back() {
        let scratch = Scratch::new();
        let new = scratch.folder("new");
        let offline = scratch.offline("old");
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&offline));
        let id = uuid();
        note_located(&id, Path::new(&offline));
        assert!(folders.folder_to_resume_in(&id).is_err());

        simulate_unplugged(&scratch.unplugged(), false);
        std::fs::create_dir_all(Path::new(&offline).join("Temp")).unwrap();
        touch(&offline, &format!("{id}.part"));
        assert_eq!(
            folders.folder_to_resume_in(&id),
            Ok(PathBuf::from(&offline))
        );
    }

    /// Deleting `D:\P2P` along with the `D:\P2P\Ember` download folder in it
    /// leaves no parent, but the drive is there: nothing is offline.
    #[test]
    fn a_deleted_folder_on_a_present_volume_is_not_offline() {
        let scratch = Scratch::new();
        let new = scratch.folder("new");
        let deleted = scratch
            .0
            .join("deleted")
            .join("Ember")
            .to_string_lossy()
            .into_owned();
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&deleted));
        let id = uuid();
        note_located(&id, Path::new(&deleted));
        assert_eq!(
            folders.locate_part(&id),
            PartLocation::Absent {
                unreachable: Vec::new()
            }
        );
        assert_eq!(folders.folder_to_resume_in(&id), Ok(PathBuf::from(&new)));
    }

    /// The volume decides: a missing drive letter on Windows reads as offline
    /// whatever is below it.
    #[cfg(windows)]
    #[test]
    fn a_folder_on_a_drive_letter_that_is_not_there_is_offline() {
        let Some(missing) = (b'D'..=b'Z')
            .rev()
            .map(|letter| PathBuf::from(format!("{}:\\", letter as char)))
            .find(|root| std::fs::symlink_metadata(root).is_err())
        else {
            return;
        };
        assert!(!folder_reachable(&missing.join("P2P").join("Ember")));
        assert!(folder_reachable(&std::env::temp_dir().join("no-such").join("Ember")));
    }

    #[test]
    fn roots_and_part_paths_list_the_current_folder_first() {
        let folders = DownloadFolders::new("/dl/new", &["/dl/old".to_string(), String::new()]);
        assert_eq!(
            folders.roots(),
            vec!["/dl/new".to_string(), "/dl/old".to_string()]
        );
        assert_eq!(
            folders.part_paths("id"),
            vec![
                PathBuf::from("/dl/new").join("Temp").join("id.part"),
                PathBuf::from("/dl/old").join("Temp").join("id.part"),
            ]
        );
    }

    #[test]
    fn the_approved_roots_keep_every_folder_a_download_is_in() {
        let settings = crate::types::AppSettings {
            shared_folders: vec!["/share".into()],
            download_folder: "/dl/new".into(),
            previous_download_folders: vec!["/dl/old".into()],
            ..crate::types::AppSettings::default()
        };
        assert_eq!(
            settings.configured_roots(),
            ["/share", "/dl/new", "/dl/old"]
        );
    }

    #[test]
    fn a_folder_change_remembers_the_old_folder_only_while_it_holds_parts() {
        let scratch = Scratch::new();
        let a = scratch.folder("a");
        let b = scratch.folder("b");
        let c = scratch.folder("c");
        touch(&a, "unfinished.part");
        touch(&a, "unfinished.part.met");

        assert_eq!(previous_after_change(&a, &[], &b), vec![a.clone()]);
        assert!(
            previous_after_change(&b, &[], &c).is_empty(),
            "a folder with nothing unfinished in it is not kept"
        );
        assert_eq!(
            previous_after_change(&b, std::slice::from_ref(&a), &c),
            vec![a.clone()],
            "an earlier folder still holding a download is carried over"
        );
        assert!(
            previous_after_change(&b, std::slice::from_ref(&a), &a).is_empty(),
            "moving back to a previous folder makes it current again"
        );
        assert_eq!(
            previous_after_change(&a, std::slice::from_ref(&a), &b),
            vec![a.clone()],
            "listed once"
        );
    }

    #[test]
    fn a_folder_change_keeps_at_most_the_newest_previous_folders() {
        let scratch = Scratch::new();
        let older: Vec<String> = (0..MAX_PREVIOUS_DOWNLOAD_FOLDERS + 4)
            .map(|i| {
                let folder = scratch.folder(&format!("old-{i}"));
                touch(&folder, "unfinished.part");
                folder
            })
            .collect();
        let current = scratch.folder("current");
        touch(&current, "unfinished.part");
        let new = scratch.folder("new");

        let kept = previous_after_change(&current, &older, &new);
        assert_eq!(kept.len(), MAX_PREVIOUS_DOWNLOAD_FOLDERS);
        assert_eq!(kept[0], current, "the folder just left is the newest");
    }

    #[test]
    fn an_unreachable_previous_folder_is_kept_on_a_change() {
        let scratch = Scratch::new();
        let gone = scratch.offline("old");
        let new = scratch.folder("new");
        assert_eq!(previous_after_change(&gone, &[], &new), vec![gone]);
    }

    /// `with_progress` pairs each id with the folder recorded for it.
    fn unfinished(ids: &[&str], with_progress: &[(&str, &str)]) -> UnfinishedDownloads {
        UnfinishedDownloads {
            ids: ids.iter().map(|id| id.to_string()).collect(),
            with_progress: with_progress
                .iter()
                .map(|(id, folder)| (id.to_string(), folder.to_string()))
                .collect(),
        }
    }

    /// Current first; an `offline:` name is a folder on a missing volume.
    fn folders(scratch: &Scratch, names: &[&str]) -> Vec<PathBuf> {
        names
            .iter()
            .map(|name| match name.strip_prefix("offline:") {
                Some(name) => PathBuf::from(scratch.offline(name)),
                None => PathBuf::from(scratch.folder(name)),
            })
            .collect()
    }

    #[test]
    fn startup_keeps_folders_holding_an_unfinished_download_or_a_sweepable_orphan() {
        let scratch = Scratch::new();
        let (live, orphan) = (uuid(), uuid());
        let folders = folders(&scratch, &["current", "owned", "orphan", "foreign"]);
        let path = |i: usize| folders[i].to_string_lossy().into_owned();
        touch(&path(1), &format!("{live}.part"));
        touch(&path(2), &format!("{orphan}.part"));
        touch(&path(3), "not-ember.part");
        touch(&path(3), "ember-write-probe");
        let listings = list_folders_within(&folders, Duration::from_secs(5));

        assert_eq!(
            retain_needed(&folders, &listings, &unfinished(&[&live], &[(&live, &path(1))])),
            vec![path(1), path(2)],
            "the orphan's folder stays approved until the startup sweep has removed it"
        );
        assert_eq!(
            retain_needed(&folders, &listings, &unfinished(&[], &[])),
            vec![path(1), path(2)],
            "with nothing unfinished, every part file is an orphan, and its folder is kept \
             for the sweep"
        );
    }

    #[test]
    fn startup_keeps_an_offline_folder_only_for_progress_recorded_on_it() {
        let scratch = Scratch::new();
        let (here, elsewhere, unrecorded) = (uuid(), uuid(), uuid());
        let folders = folders(&scratch, &["current", "offline:old", "offline:older"]);
        let path = |i: usize| folders[i].to_string_lossy().into_owned();
        touch(&path(0), &format!("{here}.part"));
        let listings = list_folders_within(&folders, Duration::from_secs(5));
        assert_eq!(listings[1].owners, None);

        assert!(
            retain_needed(&folders, &listings, &unfinished(&[&here], &[(&here, &path(1))]))
                .is_empty(),
            "every download with progress is accounted for elsewhere"
        );
        assert!(
            retain_needed(
                &folders,
                &listings,
                &unfinished(&[&here, &elsewhere], &[(&here, &path(0))])
            )
            .is_empty(),
            "a download with no bytes yet cannot be stranded"
        );
        assert_eq!(
            retain_needed(
                &folders,
                &listings,
                &unfinished(&[&elsewhere], &[(&elsewhere, &path(1))])
            ),
            vec![path(1)],
            "progress found in no reachable folder is waited for on the folder it was in"
        );
        assert!(
            retain_needed(
                &folders,
                &listings,
                &unfinished(&[&unrecorded], &[(&unrecorded, "")])
            )
            .is_empty(),
            "progress with no folder on record holds none"
        );
    }

    /// The config load checks only the text; what an earlier folder resolves
    /// to is checked here, at startup, where a slow drive has a time limit.
    #[test]
    fn startup_drops_earlier_folders_that_resolve_badly_or_to_a_duplicate() {
        let (current, old, system, root) = if cfg!(windows) {
            (r"Q:\Ember Now", r"Q:\Ember Old", r"Q:\Windows\Ember", r"Q:\")
        } else {
            ("/srv/ember-now", "/srv/ember-old", "/etc/ember", "/")
        };
        let listing = |canonical: Option<&str>| FolderListing {
            owners: Some(HashSet::new()),
            canonical: canonical.map(PathBuf::from),
        };
        let folders: Vec<PathBuf> = ["current", "old", "offline", "alias", "link", "drive"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let listings = [
            listing(Some(current)),
            listing(Some(old)),
            listing(None),
            listing(Some(old)),
            listing(Some(system)),
            listing(Some(root)),
        ];
        assert_eq!(
            resolve_previous(&folders, &listings),
            vec![1, 2],
            "a second spelling of a folder, a link into a system folder and a drive root go; \
             one that did not resolve stays"
        );
        assert!(
            resolve_previous(&folders[..2], &[listing(Some(current)), listing(Some(current))])
                .is_empty(),
            "one that resolves to the current folder is the current folder"
        );
    }
}
