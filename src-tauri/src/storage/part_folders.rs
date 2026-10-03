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

/// Where each download's part files were last found or opened this session,
/// and which downloads the database restored with progress. Read by the
/// network loop, which must not touch the disk to answer either.
#[derive(Default)]
struct PartRecord {
    located: HashMap<String, PathBuf>,
    restored_with_progress: HashSet<String>,
}

fn part_record() -> &'static parking_lot::Mutex<PartRecord> {
    static RECORD: std::sync::OnceLock<parking_lot::Mutex<PartRecord>> = std::sync::OnceLock::new();
    RECORD.get_or_init(Default::default)
}

/// Remember that this download's part files are in `folder`.
pub fn note_located(transfer_id: &str, folder: &Path) {
    part_record()
        .lock()
        .located
        .insert(transfer_id.to_string(), folder.to_path_buf());
}

/// Remember that the database restored this download with bytes on disk, so
/// a missing `.part` is not taken as a download that never started.
pub fn note_restored_with_progress(transfer_id: &str) {
    part_record()
        .lock()
        .restored_with_progress
        .insert(transfer_id.to_string());
}

/// The folder this download's part files were last found in this session.
/// Non-blocking.
pub fn located_folder(transfer_id: &str) -> Option<PathBuf> {
    part_record().lock().located.get(transfer_id).cloned()
}

/// Whether `folder` can be looked at: it exists, or it is gone from a volume
/// that is still there. An unplugged drive or an offline share takes the
/// folder's parent with it; a folder the user deleted leaves the parent.
fn folder_reachable(folder: &Path) -> bool {
    std::fs::symlink_metadata(folder).is_ok()
        || folder
            .parent()
            .is_some_and(|parent| std::fs::symlink_metadata(parent).is_ok())
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
    /// `Err` with a folder that cannot be reached and may hold its progress.
    ///
    /// Starting such a download in the current folder would begin a second
    /// `.part` from zero, and once the drive came back the current folder's
    /// copy would win and strand the real progress. Blocking.
    pub fn folder_to_resume_in(&self, transfer_id: &str) -> Result<PathBuf, PathBuf> {
        if self.previous.is_empty() {
            return Ok(self.current.clone());
        }
        match self.locate_part(transfer_id) {
            PartLocation::Found(folder) => Ok(folder),
            PartLocation::Absent { unreachable } => {
                let record = part_record().lock();
                let holding = match record.located.get(transfer_id) {
                    Some(last_seen) => unreachable.iter().find(|folder| *folder == last_seen),
                    None if record.restored_with_progress.contains(transfer_id) => {
                        unreachable.first()
                    }
                    None => None,
                };
                match holding {
                    Some(folder) => Err(folder.clone()),
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

/// [`part_owners`] of each folder, listed in parallel. A folder that has not
/// answered within `budget` counts as unreachable; its thread is left to
/// finish on its own.
fn part_owners_within(folders: &[PathBuf], budget: Duration) -> Vec<Option<HashSet<String>>> {
    let (tx, rx) = std::sync::mpsc::channel();
    for (index, folder) in folders.iter().enumerate() {
        let tx = tx.clone();
        let folder = folder.clone();
        let spawned = std::thread::Builder::new()
            .name("ember-part-folder-listing".into())
            .spawn(move || {
                let _ = tx.send((index, part_owners(&folder)));
            });
        if let Err(e) = spawned {
            tracing::warn!("Could not list {}: {e}", folders[index].display());
        }
    }
    drop(tx);
    let mut listings = vec![None; folders.len()];
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
    /// Those with bytes on disk.
    pub with_progress: HashSet<String>,
}

/// The previous download folders still needed, given `listings[i]`, the part
/// file owners of `folders[i]` (`None`: unreachable). `folders[0]` is the
/// current folder and the rest are the previous ones, in order.
///
/// A folder that can be listed is kept while it holds a part file of an
/// unfinished download, or an orphan the startup sweep is about to remove
/// from it — forgotten first, the folder would lose its approval and the
/// orphan, which can be a whole file whose removal failed after completion,
/// would stay behind for good. One that cannot be listed is kept only while
/// some unfinished download with progress is in none of the folders that
/// can, since only then may that progress be on it.
fn retain_needed(
    folders: &[PathBuf],
    listings: &[Option<HashSet<String>>],
    unfinished: &UnfinishedDownloads,
) -> Vec<String> {
    let listed: Vec<&HashSet<String>> = listings.iter().flatten().collect();
    let stranded = unfinished
        .with_progress
        .iter()
        .any(|id| !listed.iter().any(|owners| owners.contains(id)));
    folders
        .iter()
        .zip(listings)
        .skip(1)
        .filter(|(_, listing)| match listing {
            Some(owners) => owners
                .iter()
                .any(|id| unfinished.ids.contains(id) || swept_owner(id)),
            None => stranded,
        })
        .map(|(folder, _)| folder.to_string_lossy().into_owned())
        .collect()
}

/// Forget the previous download folders no unfinished download needs any
/// more. Runs at startup, before the approved roots are built from the
/// settings: nothing is writing to them yet, and only a download the database
/// still lists can resume from one. Touches the disk only when there are
/// unfinished downloads, and for at most [`STARTUP_LISTING_BUDGET`].
pub fn forget_finished_previous_folders(
    db: &crate::storage::database::Database,
    config: &mut crate::storage::config::AppConfig,
) {
    let previous = &config.settings.previous_download_folders;
    if previous.is_empty() {
        return;
    }
    let unfinished = match (
        db.incomplete_downloads_owning_partials(),
        db.incomplete_downloads_with_progress(),
    ) {
        (Ok(ids), Ok(with_progress)) => UnfinishedDownloads { ids, with_progress },
        (Err(e), _) | (_, Err(e)) => {
            tracing::warn!(
                "Keeping earlier download folders: unfinished downloads unreadable ({e})"
            );
            return;
        }
    };
    let kept = if unfinished.ids.is_empty() {
        Vec::new()
    } else {
        let folders: Vec<PathBuf> = std::iter::once(config.settings.download_folder.as_str())
            .chain(previous.iter().map(String::as_str))
            .map(PathBuf::from)
            .collect();
        let listings = part_owners_within(&folders, STARTUP_LISTING_BUDGET);
        retain_needed(&folders, &listings, &unfinished)
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

        /// A folder on a volume that is not there: its parent is missing too.
        fn offline(&self, name: &str) -> String {
            self.0
                .join("unplugged")
                .join(name)
                .to_string_lossy()
                .into_owned()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
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
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&offline));

        let restored = uuid();
        note_restored_with_progress(&restored);
        assert_eq!(
            folders.folder_to_resume_in(&restored),
            Err(PathBuf::from(&offline)),
            "the database says it has bytes, and the only place they can be is offline"
        );

        let seen_there = uuid();
        note_located(&seen_there, Path::new(&offline));
        assert_eq!(
            folders.folder_to_resume_in(&seen_there),
            Err(PathBuf::from(&offline))
        );

        let fresh = uuid();
        assert_eq!(
            folders.folder_to_resume_in(&fresh),
            Ok(PathBuf::from(&new)),
            "a download that never wrote anything starts in the current folder"
        );

        let seen_in_current = uuid();
        note_located(&seen_in_current, Path::new(&new));
        assert_eq!(
            folders.folder_to_resume_in(&seen_in_current),
            Ok(PathBuf::from(&new)),
            "an offline folder it was never in does not hold it"
        );
    }

    #[test]
    fn a_held_download_resumes_once_its_folder_is_back() {
        let scratch = Scratch::new();
        let new = scratch.folder("new");
        let offline = scratch.offline("old");
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&offline));
        let id = uuid();
        note_restored_with_progress(&id);
        assert!(folders.folder_to_resume_in(&id).is_err());

        std::fs::create_dir_all(Path::new(&offline).join("Temp")).unwrap();
        touch(&offline, &format!("{id}.part"));
        assert_eq!(
            folders.folder_to_resume_in(&id),
            Ok(PathBuf::from(&offline))
        );
    }

    #[test]
    fn a_deleted_folder_on_a_present_volume_is_not_offline() {
        let scratch = Scratch::new();
        let new = scratch.folder("new");
        let deleted = scratch.0.join("deleted").to_string_lossy().into_owned();
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&deleted));
        let id = uuid();
        note_restored_with_progress(&id);
        assert_eq!(
            folders.locate_part(&id),
            PartLocation::Absent {
                unreachable: Vec::new()
            }
        );
        assert_eq!(folders.folder_to_resume_in(&id), Ok(PathBuf::from(&new)));
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

    fn unfinished(ids: &[&str], with_progress: &[&str]) -> UnfinishedDownloads {
        UnfinishedDownloads {
            ids: ids.iter().map(|id| id.to_string()).collect(),
            with_progress: with_progress.iter().map(|id| id.to_string()).collect(),
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
        let listings = part_owners_within(&folders, Duration::from_secs(5));

        assert_eq!(
            retain_needed(&folders, &listings, &unfinished(&[&live], &[&live])),
            vec![path(1), path(2)],
            "the orphan's folder stays approved until the startup sweep has removed it"
        );
    }

    #[test]
    fn startup_drops_an_offline_folder_once_no_progress_can_be_on_it() {
        let scratch = Scratch::new();
        let (here, elsewhere) = (uuid(), uuid());
        let folders = folders(&scratch, &["current", "offline:old"]);
        let current = folders[0].to_string_lossy().into_owned();
        touch(&current, &format!("{here}.part"));
        let listings = part_owners_within(&folders, Duration::from_secs(5));
        assert_eq!(listings[1], None);

        assert!(
            retain_needed(&folders, &listings, &unfinished(&[&here], &[&here])).is_empty(),
            "every download with progress is accounted for elsewhere"
        );
        assert!(
            retain_needed(
                &folders,
                &listings,
                &unfinished(&[&here, &elsewhere], &[&here])
            )
            .is_empty(),
            "a download with no bytes yet cannot be stranded"
        );
        assert_eq!(
            retain_needed(
                &folders,
                &listings,
                &unfinished(&[&elsewhere], &[&elsewhere])
            ),
            vec![folders[1].to_string_lossy().into_owned()],
            "progress found in no reachable folder may be on the offline one"
        );
    }
}
