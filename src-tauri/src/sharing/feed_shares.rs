//! "Share files from this feed" (`feeds_followed.share_files`), off by default.
//!
//! A feed that shares has its downloads advertised and served as any download
//! is (`feed_downloads::is_private`), and its folder in each download folder
//! shared. A shared folder that already holds the feed's folder shares it,
//! entering `Feeds` for that folder alone (`feed_downloads::walk_passes_feeds_dir`);
//! otherwise Ember adds the feed's folder to the shared list and records it in
//! `feed_share_folders`, so that only the feed's switch, or unfollowing it,
//! takes it back, and a folder the user shared is never taken back.

use std::path::{Path, PathBuf};

use crate::host::Manager;

use crate::app_state::AppState;
use crate::security::path_within_dir;

/// What to change so the shared list holds what the sharing feeds need.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Feed folders to add to the shared list.
    pub add: Vec<String>,
    /// Folders Ember added that no sharing feed needs any more.
    pub remove: Vec<String>,
}

fn same_folder(a: &str, b: &str) -> bool {
    path_within_dir(a, b) && path_within_dir(b, a)
}

/// The change from `shared` (the shared list) and `managed` (the folders in it
/// Ember added for feeds) to the list `wanted` needs: the sharing feeds'
/// folders that are there, spelled as the shared list spells folders.
pub(crate) fn plan(wanted: &[String], shared: &[String], managed: &[String]) -> Plan {
    let add = wanted
        .iter()
        .filter(|folder| !shared.iter().any(|entry| path_within_dir(folder, entry)))
        .cloned()
        .collect();
    let remove = managed
        .iter()
        .filter(|entry| shared.iter().any(|listed| same_folder(listed, entry)))
        .filter(|entry| !wanted.iter().any(|folder| same_folder(folder, entry)))
        .cloned()
        .collect();
    Plan { add, remove }
}

/// The folders of the feeds named in `folders` in each of `roots`, canonical,
/// for those that are there. Made in `current`, the download folder new files
/// finish in, so the folder can be shared before its first file. Blocking.
fn feed_folders(roots: &[String], current: &str, folders: &[String]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for root in roots.iter().filter(|root| !root.trim().is_empty()) {
        let feeds = crate::sharing::feed_downloads::feeds_dir(Path::new(root));
        for folder in folders {
            let dir = feeds.join(folder);
            if same_folder(root, current) && std::fs::create_dir_all(&dir).is_ok() {
                crate::sharing::feed_downloads::mark_feeds_dir(&feeds);
            }
            if let Some(canonical) = feed_folder_in(&feeds, &dir) {
                found.push(canonical);
            }
        }
    }
    found
}

/// `dir`, canonical, when it is a real folder of `feeds`: not a link or a
/// junction, and resolving inside `feeds`, so what gets shared is the feed's
/// folder and never wherever a link in its place points. Blocking.
fn feed_folder_in(feeds: &Path, dir: &Path) -> Option<PathBuf> {
    let link = |path: &Path| std::fs::symlink_metadata(path).map_or(true, |meta| meta.file_type().is_symlink());
    if link(feeds) || link(dir) {
        return None;
    }
    let (feeds, canonical) = (feeds.canonicalize().ok()?, dir.canonicalize().ok()?);
    let inside = canonical.parent() == Some(feeds.as_path()) && canonical.is_dir();
    inside.then_some(canonical)
}

/// One at a time: each reads the shared list, then changes it.
fn reconcile_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    &LOCK
}

/// Bring the shared list into line with the feeds that share their files
/// (`feed_downloads::sharing_folders`): add the folder of each that no shared
/// folder holds, and take back each Ember added that none needs now. `rescan`
/// names feed folders whose sharing changed, rescanned where a shared folder
/// of the user's holds them.
pub(crate) async fn reconcile(app: &crate::host::AppHandle, rescan: &[String]) {
    let _one = reconcile_lock().lock().await;
    let state = app.state::<AppState>();
    let (roots, current, shared, managed) = {
        let config = state.config.read().await;
        let settings = &config.settings;
        (
            settings.download_roots(),
            settings.download_folder.clone(),
            settings.shared_folders.clone(),
            settings.feed_share_folders.clone(),
        )
    };
    let folders = crate::sharing::feed_downloads::sharing_folders();
    let rescan = rescan.to_vec();
    let (wanted, rescan_dirs) = tokio::task::spawn_blocking({
        let roots = roots.clone();
        move || {
            let wanted = feed_folders(&roots, &current, &folders);
            let rescan_dirs: Vec<PathBuf> = roots
                .iter()
                .flat_map(|root| {
                    let feeds = crate::sharing::feed_downloads::feeds_dir(Path::new(root));
                    rescan.iter().map(move |folder| feeds.join(folder)).collect::<Vec<_>>()
                })
                .filter(|dir| dir.is_dir())
                .collect();
            (wanted, rescan_dirs)
        }
    })
    .await
    .unwrap_or_default();
    let wanted: Vec<String> = wanted.iter().map(|dir| dir.to_string_lossy().into_owned()).collect();
    let plan = plan(&wanted, &shared, &managed);

    for folder in plan.add {
        // Recorded before it is shared: one shared and not recorded would be,
        // to Ember, a folder the user shared, never taken back. A record left
        // by an add that does not happen is dropped below, or by the next
        // pass if this one is cut short.
        let recorded = crate::commands::settings::save_settings_change(app, &state, |settings| {
            if settings.feed_share_folders.iter().any(|listed| same_folder(listed, &folder)) {
                return Ok(false);
            }
            settings.feed_share_folders.push(folder.clone());
            Ok(true)
        })
        .await;
        if let Err(error) = recorded {
            tracing::warn!("Feed sharing: not sharing the feed folder {folder}, as it could not be recorded: {error}");
            continue;
        }
        let added = crate::commands::sharing::add_shared_folder_approved(
            app.clone(),
            app.state::<AppState>(),
            folder.clone(),
            None,
            crate::commands::sharing::ShareApproval::Native,
        )
        .await;
        match added {
            Ok(added) if added.outcome == crate::commands::sharing::FolderAddOutcome::Added => {
                tracing::info!("Feed sharing: shared the feed folder {folder}");
                continue;
            }
            // The user's own share of it, made meanwhile: theirs to keep.
            Ok(_) => {}
            Err(error) => tracing::warn!("Feed sharing: could not share the feed folder {folder}: {error}"),
        }
        let dropped = crate::commands::settings::save_settings_change(app, &state, |settings| {
            let before = settings.feed_share_folders.len();
            settings.feed_share_folders.retain(|listed| !same_folder(listed, &folder));
            Ok(settings.feed_share_folders.len() != before)
        })
        .await;
        if let Err(error) = dropped {
            tracing::debug!("Feed sharing: could not drop the record of {folder}: {error}");
        }
    }
    for folder in plan.remove {
        match crate::commands::sharing::remove_shared_folder_as(
            app.clone(),
            app.state::<AppState>(),
            folder.clone(),
            crate::commands::sharing::FolderRemoval::FeedShare,
        )
        .await
        {
            Ok(()) => tracing::info!("Feed sharing: no longer sharing the feed folder {folder}"),
            Err(error) => tracing::warn!("Feed sharing: could not stop sharing the feed folder {folder}: {error}"),
        }
    }
    // A folder recorded as the feed's that left the shared list some other way.
    let forgotten = crate::commands::settings::save_settings_change(app, &state, |settings| {
        let before = settings.feed_share_folders.len();
        let shared = settings.shared_folders.clone();
        settings
            .feed_share_folders
            .retain(|folder| shared.iter().any(|listed| same_folder(listed, folder)));
        Ok(settings.feed_share_folders.len() != before)
    })
    .await;
    if let Err(error) = forgotten {
        tracing::debug!("Feed sharing: could not tidy the feed folders recorded as shared: {error}");
    }

    if !rescan_dirs.is_empty() {
        if let Some(watcher) = state.shared_folder_watcher.clone() {
            watcher.queue_rescan_after(rescan_dirs, std::time::Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(path: &str) -> String {
        if cfg!(windows) {
            format!("C:{}", path.replace('/', "\\"))
        } else {
            path.to_string()
        }
    }

    fn dirs(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| dir(path)).collect()
    }

    #[test]
    fn a_sharing_feeds_folder_is_added_unless_a_shared_folder_holds_it() {
        let mixes = dirs(&["/dl/Feeds/Mixes"]);
        let both = dirs(&["/dl/Feeds/Mixes", "/dl/Feeds/Talks"]);
        assert_eq!(
            plan(&mixes, &dirs(&["/dl/Downloads"]), &[]),
            Plan { add: mixes.clone(), remove: vec![] },
            "only Downloads shared, as by default"
        );
        assert_eq!(plan(&mixes, &dirs(&["/dl"]), &[]), Plan::default(), "the whole download folder shared");
        assert_eq!(plan(&mixes, &mixes, &mixes), Plan::default(), "already added");
        assert_eq!(plan(&mixes, &mixes, &[]), Plan::default(), "shared by the user on purpose");
        assert_eq!(
            plan(&both, &mixes, &mixes),
            Plan { add: dirs(&["/dl/Feeds/Talks"]), remove: vec![] }
        );
    }

    #[test]
    fn only_a_real_folder_inside_feeds_is_shared() {
        let root = std::env::temp_dir().join(format!("ember-feed-shares-{}", uuid::Uuid::new_v4()));
        let feeds = crate::sharing::feed_downloads::feeds_dir(&root);
        let elsewhere = root.join("Elsewhere");
        std::fs::create_dir_all(feeds.join("Mixes")).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let mixes = feed_folder_in(&feeds, &feeds.join("Mixes")).expect("a folder of its own");
        assert!(mixes.ends_with("Mixes"));
        assert_eq!(feed_folder_in(&feeds, &feeds.join("Missing")), None);
        assert_eq!(feed_folder_in(&feeds, &feeds.join("Mixes").join("..").join("..").join("Elsewhere")), None);

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&elsewhere, feeds.join("Linked")).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(&elsewhere, feeds.join("Linked")).is_ok();
        if linked {
            assert_eq!(feed_folder_in(&feeds, &feeds.join("Linked")), None, "a link in a feed folder's place");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn only_a_folder_ember_added_is_taken_back() {
        let mixes = dirs(&["/dl/Feeds/Mixes"]);
        let talks = dirs(&["/dl/Feeds/Talks"]);
        assert_eq!(
            plan(&[], &dirs(&["/dl/Feeds/Mixes", "/dl/Feeds/Talks"]), &mixes),
            Plan { add: vec![], remove: mixes.clone() },
            "Talks is the user's own share"
        );
        assert_eq!(plan(&[], &talks, &mixes), Plan::default(), "already gone from the list");
        assert_eq!(plan(&mixes, &mixes, &mixes), Plan::default(), "still wanted");
    }
}
