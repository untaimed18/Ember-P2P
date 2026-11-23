//! "Share files from this feed" (`feeds_followed.share_files`), off by default.
//!
//! A feed that shares has its downloads advertised and served as any download
//! is (`feed_downloads::is_private`), and its folder in each download folder
//! shared. A shared folder that already holds the feed's folder shares it,
//! entering `Feeds` for that folder alone (`feed_downloads::walk_passes_feeds_dir`).
//! One shared in part, or flat as eMule shares folders, offers only what its
//! list names, so Ember puts the feed's folder on that list. Otherwise Ember
//! adds the feed's folder to the shared list. Either way it records the folder
//! in `feed_share_folders`, so that only the feed's switch, or unfollowing it,
//! takes it back, and a folder the user shared is never taken back.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::host::Manager;

use crate::app_state::AppState;
use crate::security::path_within_dir;

/// What to change so the shared list holds what the sharing feeds need.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Feed folders to add to the shared list.
    pub add: Vec<String>,
    /// Feed folders to put on the list of the folder shared in part that
    /// holds them.
    pub list: Vec<String>,
    /// Folders Ember added that no sharing feed needs any more.
    pub remove: Vec<String>,
}

fn same_folder(a: &str, b: &str) -> bool {
    path_within_dir(a, b) && path_within_dir(b, a)
}

fn same_key(a: &str, b: &str) -> bool {
    let key = |path: &str| crate::search::index::normalize_path_key(path).trim_end_matches(['/', '\\']).to_string();
    key(a) == key(b)
}

/// The change from `shared` (the shared list), `allowlists` (the lists of the
/// folders shared in part) and `managed` (the folders Ember added for feeds,
/// to either) to what `wanted` needs: the sharing feeds' folders that are
/// there, spelled as the shared list spells folders.
pub(crate) fn plan(
    wanted: &[String],
    shared: &[String],
    allowlists: &HashMap<String, Vec<String>>,
    managed: &[String],
) -> Plan {
    let offers = crate::sharing::indexer::AllowlistOffers::new(allowlists);
    let mut add = Vec::new();
    let mut list = Vec::new();
    for folder in wanted {
        let Some(holder) = shared.iter().find(|entry| path_within_dir(folder, entry)) else {
            add.push(folder.clone());
            continue;
        };
        // Only the shared folder's own list: one further in is a folder the
        // user unshared, which a feed's switch does not override.
        let innermost = allowlists
            .keys()
            .filter(|listed| path_within_dir(folder, listed))
            .max_by_key(|listed| listed.len());
        if !offers.offers_folder(folder) && innermost.is_some_and(|listed| same_folder(listed, holder)) {
            list.push(folder.clone());
        }
    }
    let listed = |entry: &String| {
        shared.iter().any(|folder| same_folder(folder, entry))
            || allowlists.values().flatten().any(|listed| same_key(listed, entry))
    };
    let remove = managed
        .iter()
        .filter(|entry| listed(entry))
        .filter(|entry| !wanted.iter().any(|folder| same_folder(folder, entry)))
        .cloned()
        .collect();
    Plan { add, list, remove }
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

/// Record `folder` as shared for a feed. Before it is shared: one shared and
/// not recorded would be, to Ember, a folder the user shared, never taken
/// back. A record left by a share that does not happen is dropped after it,
/// or by the next pass if that one is cut short.
async fn record(app: &crate::host::AppHandle, state: &AppState, folder: &str) -> Result<(), String> {
    crate::commands::settings::save_settings_change(app, state, |settings| {
        if settings.feed_share_folders.iter().any(|listed| same_folder(listed, folder)) {
            return Ok(false);
        }
        settings.feed_share_folders.push(folder.to_string());
        Ok(true)
    })
    .await
    .map(|_| ())
}

async fn drop_record(app: &crate::host::AppHandle, state: &AppState, folder: &str) {
    let dropped = crate::commands::settings::save_settings_change(app, state, |settings| {
        let before = settings.feed_share_folders.len();
        settings.feed_share_folders.retain(|listed| !same_folder(listed, folder));
        Ok(settings.feed_share_folders.len() != before)
    })
    .await;
    if let Err(error) = dropped {
        tracing::debug!("Feed sharing: could not drop the record of {folder}: {error}");
    }
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
    let (roots, current, shared, allowlists, managed) = {
        let config = state.config.read().await;
        let settings = &config.settings;
        (
            settings.download_roots(),
            settings.download_folder.clone(),
            settings.shared_folders.clone(),
            settings.pending_folder_allowlists.clone(),
            settings.feed_share_folders.clone(),
        )
    };
    let folders = crate::sharing::feed_downloads::sharing_folders();
    let still_sharing = folders.clone();
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
    let mut plan = plan(&wanted, &shared, &allowlists, &managed);
    // One whose drive is away is kept while its feed still shares, as a folder
    // the user shared is kept while offline: taken off, it would stay unshared
    // once the drive is back, the feed's switch still on.
    let removable = std::mem::take(&mut plan.remove);
    plan.remove = tokio::task::spawn_blocking(move || {
        removable
            .into_iter()
            .filter(|entry| {
                let path = Path::new(entry);
                let feed_shares = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| still_sharing.iter().any(|folder| folder.eq_ignore_ascii_case(name)));
                !feed_shares || path.parent().is_some_and(Path::is_dir)
            })
            .collect()
    })
    .await
    .unwrap_or_default();

    for folder in plan.add {
        if let Err(error) = record(app, &state, &folder).await {
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
        drop_record(app, &state, &folder).await;
    }
    for folder in plan.list {
        if let Err(error) = record(app, &state, &folder).await {
            tracing::warn!("Feed sharing: not sharing the feed folder {folder}, as it could not be recorded: {error}");
            continue;
        }
        match crate::commands::sharing::list_in_shared_folder(app.clone(), &state, &folder).await {
            Ok(true) => {
                tracing::info!("Feed sharing: shared the feed folder {folder} on its shared folder's list");
                continue;
            }
            // Named on the list meanwhile, or its folder shared whole or no
            // longer shared: nothing of the feed's to take back later.
            Ok(false) => {}
            Err(error) => tracing::warn!("Feed sharing: could not share the feed folder {folder}: {error}"),
        }
        drop_record(app, &state, &folder).await;
    }
    for folder in plan.remove {
        let on_shared_list = shared.iter().any(|listed| same_folder(listed, &folder));
        let removed = if on_shared_list {
            crate::commands::sharing::remove_shared_folder_as(
                app.clone(),
                app.state::<AppState>(),
                folder.clone(),
                crate::commands::sharing::FolderRemoval::FeedShare,
            )
            .await
        } else {
            crate::commands::sharing::unshare_folder_as(
                app.clone(),
                app.state::<AppState>(),
                folder.clone(),
                crate::commands::sharing::FolderRemoval::FeedShare,
            )
            .await
        };
        match removed {
            Ok(()) => tracing::info!("Feed sharing: no longer sharing the feed folder {folder}"),
            Err(error) => tracing::warn!("Feed sharing: could not stop sharing the feed folder {folder}: {error}"),
        }
    }
    // A folder recorded as the feed's that left the shared list, or its
    // folder's list, some other way.
    let forgotten = crate::commands::settings::save_settings_change(app, &state, |settings| {
        let before = settings.feed_share_folders.len();
        let shared = settings.shared_folders.clone();
        let allowlists = settings.pending_folder_allowlists.clone();
        settings.feed_share_folders.retain(|folder| {
            shared.iter().any(|listed| same_folder(listed, folder))
                || allowlists.values().flatten().any(|listed| same_key(listed, folder))
        });
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

    fn key(path: &str) -> String {
        crate::search::index::normalize_path_key(&dir(path))
    }

    fn lists(entries: &[(&str, &[String])]) -> HashMap<String, Vec<String>> {
        entries.iter().map(|(folder, listed)| (key(folder), listed.to_vec())).collect()
    }

    #[test]
    fn a_sharing_feeds_folder_is_added_unless_a_shared_folder_holds_it() {
        let none = HashMap::new();
        let mixes = dirs(&["/dl/Feeds/Mixes"]);
        let both = dirs(&["/dl/Feeds/Mixes", "/dl/Feeds/Talks"]);
        assert_eq!(
            plan(&mixes, &dirs(&["/dl/Downloads"]), &none, &[]),
            Plan { add: mixes.clone(), ..Plan::default() },
            "only Downloads shared, as by default"
        );
        assert_eq!(plan(&mixes, &dirs(&["/dl"]), &none, &[]), Plan::default(), "the whole download folder shared");
        assert_eq!(plan(&mixes, &mixes, &none, &mixes), Plan::default(), "already added");
        assert_eq!(plan(&mixes, &mixes, &none, &[]), Plan::default(), "shared by the user on purpose");
        assert_eq!(
            plan(&both, &mixes, &none, &mixes),
            Plan { add: dirs(&["/dl/Feeds/Talks"]), ..Plan::default() }
        );
    }

    /// A download folder shared with some files picked, or flat as eMule
    /// shares it, offers only what its list names: the feed's folder goes on
    /// that list rather than being shared as a folder of its own, which would
    /// overlap it.
    #[test]
    fn a_folder_shared_in_part_gets_the_feeds_folder_on_its_list() {
        let mixes = dirs(&["/dl/Feeds/Mixes"]);
        let shared = dirs(&["/dl"]);
        let picked = lists(&[("/dl", &[key("/dl/Downloads/song.mp3")])]);
        assert_eq!(plan(&mixes, &shared, &picked, &[]), Plan { list: mixes.clone(), ..Plan::default() });
        let flat = lists(&[("/dl", &[crate::sharing::indexer::flat_entry(&dir("/dl"))])]);
        assert_eq!(plan(&mixes, &shared, &flat, &[]), Plan { list: mixes.clone(), ..Plan::default() }, "a flat share");

        let listed = lists(&[("/dl", &[key("/dl/Feeds/Mixes")])]);
        assert_eq!(plan(&mixes, &shared, &listed, &mixes), Plan::default(), "already on the list");
        let feeds_picked = lists(&[("/dl", &[key("/dl/Feeds")])]);
        assert_eq!(plan(&mixes, &shared, &feeds_picked, &[]), Plan::default(), "the user picked all of Feeds");
        let unshared = lists(&[("/dl", &[key("/dl/Downloads")]), ("/dl/Feeds", &[])]);
        assert_eq!(plan(&mixes, &shared, &unshared, &[]), Plan::default(), "the user unshared Feeds itself");
    }

    #[test]
    fn a_feeds_folder_ember_put_on_a_list_is_taken_back_from_it() {
        let mixes = dirs(&["/dl/Feeds/Mixes"]);
        let shared = dirs(&["/dl"]);
        let listed = lists(&[("/dl", &[key("/dl/Downloads/song.mp3"), key("/dl/Feeds/Mixes")])]);
        assert_eq!(plan(&[], &shared, &listed, &mixes), Plan { remove: mixes.clone(), ..Plan::default() });
        assert_eq!(plan(&[], &shared, &listed, &[]), Plan::default(), "put there by the user");
        let gone = lists(&[("/dl", &[key("/dl/Downloads/song.mp3")])]);
        assert_eq!(plan(&[], &shared, &gone, &mixes), Plan::default(), "already off the list");
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
        let none = HashMap::new();
        let mixes = dirs(&["/dl/Feeds/Mixes"]);
        let talks = dirs(&["/dl/Feeds/Talks"]);
        assert_eq!(
            plan(&[], &dirs(&["/dl/Feeds/Mixes", "/dl/Feeds/Talks"]), &none, &mixes),
            Plan { remove: mixes.clone(), ..Plan::default() },
            "Talks is the user's own share"
        );
        assert_eq!(plan(&[], &talks, &none, &mixes), Plan::default(), "already gone from the list");
        assert_eq!(plan(&mixes, &mixes, &none, &mixes), Plan::default(), "still wanted");
    }
}
