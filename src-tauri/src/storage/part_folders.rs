//! Which download folder holds a download's `.part`.
//!
//! A download keeps its `.part` and `.part.met` in the `Temp` of the download
//! folder it started in, and its finished file goes to the `Downloads` of the
//! folder that is current when it completes — eMule keeps its temp
//! directories apart from the incoming one the same way. Changing the
//! download folder therefore leaves unfinished downloads where they are, and
//! the old folder is remembered in `AppSettings::previous_download_folders`
//! until none of them is left in it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DownloadFolders {
    pub current: PathBuf,
    pub previous: Vec<PathBuf>,
}

/// Held by the workers and the upload listener, which outlive a settings
/// change: a running download completes into the folder current at that
/// moment, not the one it was started under.
pub type SharedDownloadFolders = Arc<parking_lot::RwLock<DownloadFolders>>;

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

    /// The folder whose `Temp` holds this download's `.part` or `.part.met`,
    /// or the current one for a download that has neither yet.
    ///
    /// Blocking, but it only touches the disk when there are previous folders.
    pub fn part_folder_for(&self, transfer_id: &str) -> PathBuf {
        if self.previous.is_empty() {
            return self.current.clone();
        }
        self.all()
            .find(|folder| {
                let temp = folder.join("Temp");
                [format!("{transfer_id}.part"), format!("{transfer_id}.part.met")]
                    .iter()
                    .any(|name| std::fs::symlink_metadata(temp.join(name)).is_ok())
            })
            .unwrap_or(&self.current)
            .to_path_buf()
    }

    /// `<folder>/Temp/<transfer_id>.part` in [`Self::part_folder_for`].
    pub fn part_path_for(&self, transfer_id: &str) -> PathBuf {
        self.part_folder_for(transfer_id)
            .join("Temp")
            .join(format!("{transfer_id}.part"))
    }
}

/// The id a `.part` or `.part.met` file name belongs to.
fn part_owner(name: &str) -> Option<&str> {
    name.strip_suffix(".part.met")
        .or_else(|| name.strip_suffix(".part"))
        .filter(|id| !id.is_empty())
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
        Err(_) => std::fs::symlink_metadata(folder).is_err(),
    }
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
/// the downloads that survive a restart ([`retain_owned`]). Blocking.
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
    previous
}

/// The previous download folders that still hold a part file of a download
/// in `owned`, the unfinished downloads in the database. Blocking.
pub fn retain_owned(previous: &[String], owned: &HashSet<String>) -> Vec<String> {
    previous
        .iter()
        .filter(|folder| holds_parts(Path::new(folder), |id| owned.contains(id)))
        .cloned()
        .collect()
}

/// Forget the previous download folders whose downloads have all finished or
/// gone. Runs at startup, before the approved roots are built from the
/// settings: nothing is writing to them yet, and only a download the database
/// still lists can resume from one.
pub fn forget_finished_previous_folders(
    db: &crate::storage::database::Database,
    config: &mut crate::storage::config::AppConfig,
) {
    let previous = &config.settings.previous_download_folders;
    if previous.is_empty() {
        return;
    }
    let owned = match db.incomplete_downloads_owning_partials() {
        Ok(owned) => owned,
        Err(e) => {
            tracing::warn!("Keeping earlier download folders: unfinished downloads unreadable ({e})");
            return;
        }
    };
    let kept = retain_owned(previous, &owned);
    if kept.len() == previous.len() {
        return;
    }
    let mut settings = config.settings.clone();
    settings.previous_download_folders = kept;
    let saved = config.prepare_save_settings(&settings).and_then(|(data, tmp, path)| {
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
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn touch(folder: &str, name: &str) {
        std::fs::write(Path::new(folder).join("Temp").join(name), b"x").unwrap();
    }

    #[test]
    fn a_download_is_found_in_the_folder_it_started_in() {
        let scratch = Scratch::new();
        let old = scratch.folder("old");
        let new = scratch.folder("new");
        touch(&old, "started-before.part");
        touch(&old, "only-met.part.met");
        let folders = DownloadFolders::new(&new, std::slice::from_ref(&old));

        assert_eq!(folders.part_folder_for("started-before"), PathBuf::from(&old));
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
    fn roots_and_part_paths_list_the_current_folder_first() {
        let folders = DownloadFolders::new("/dl/new", &["/dl/old".to_string(), String::new()]);
        assert_eq!(folders.roots(), vec!["/dl/new".to_string(), "/dl/old".to_string()]);
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
        assert_eq!(settings.configured_roots(), ["/share", "/dl/new", "/dl/old"]);
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
    fn an_unreachable_previous_folder_is_kept() {
        let scratch = Scratch::new();
        let gone = scratch.0.join("unplugged").to_string_lossy().into_owned();
        let new = scratch.folder("new");
        assert_eq!(previous_after_change(&gone, &[], &new), vec![gone.clone()]);
        assert_eq!(
            retain_owned(std::slice::from_ref(&gone), &HashSet::new()),
            vec![gone]
        );
    }

    #[test]
    fn startup_keeps_only_folders_holding_an_unfinished_download() {
        let scratch = Scratch::new();
        let owned_here = scratch.folder("owned");
        let orphans_only = scratch.folder("orphans");
        touch(&owned_here, "live.part");
        touch(&orphans_only, "forgotten.part");
        touch(&orphans_only, "ember-write-probe");
        let owned: HashSet<String> = ["live".to_string()].into();

        assert_eq!(
            retain_owned(&[owned_here.clone(), orphans_only], &owned),
            vec![owned_here]
        );
    }
}
