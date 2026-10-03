//! Files Ember meant to remove and could not yet: a finished file's
//! temporary copy that a scanner held open, or a cancelled download's part
//! files on a drive that was not connected. Each is recorded with the
//! download folder it is in and removed once it can be; the folder stays a
//! download folder meanwhile (`part_folders::forget_finished_previous_folders`).

use std::path::Path;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use crate::storage::database::Database;
use crate::storage::part_folders::{folder_reachable, same_folder, DownloadFolders};

/// How often the network task tries the removals again.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);

static DATABASE: OnceLock<Weak<Database>> = OnceLock::new();

/// Where [`defer`] records, for code that has no database of its own.
pub fn install(db: &Arc<Database>) {
    let _ = DATABASE.set(Arc::downgrade(db));
}

/// Remove `path`, approved under one of `allowed_roots`, once it can be.
/// Blocking.
pub fn defer(path: &Path, allowed_roots: &[String]) {
    let Some(folder) = containing_root(path, allowed_roots) else {
        tracing::warn!(
            "Could not remove {}, which is in none of its download folders",
            path.display()
        );
        return;
    };
    match DATABASE.get().and_then(Weak::upgrade) {
        Some(db) => record(&db, &[(path.to_string_lossy().into_owned(), folder)]),
        None => tracing::warn!("Could not remove {}; nothing will retry it", path.display()),
    }
}

/// Remember each `(path, download folder)` for [`retry`].
pub fn record(db: &Database, removals: &[(String, String)]) {
    if let Err(e) = db.defer_file_removals(removals) {
        tracing::warn!("Could not remember files to remove later: {e}");
    }
}

fn containing_root(path: &Path, roots: &[String]) -> Option<String> {
    roots
        .iter()
        .find(|root| {
            let root = Path::new(root);
            path.starts_with(root)
                || root
                    .canonicalize()
                    .is_ok_and(|canonical| path.starts_with(canonical))
        })
        .cloned()
}

/// Remove what [`defer`] and [`record`] left, each from its folder while
/// that is still one of `folders` and can be reached. One whose folder is
/// no longer a download folder can no longer be removed safely and is
/// forgotten. Blocking.
pub fn retry(db: &Database, folders: &DownloadFolders) {
    let pending = match db.deferred_file_removals() {
        Ok(pending) => pending,
        Err(e) => {
            tracing::warn!("Could not read the files left to remove: {e}");
            return;
        }
    };
    if pending.is_empty() {
        return;
    }
    let roots = folders.roots();
    let mut done = Vec::new();
    for (path, folder) in pending {
        let Some(root) = roots.iter().find(|root| same_folder(root, &folder)) else {
            tracing::info!("Leaving {path}: {folder} is no longer a download folder");
            done.push(path);
            continue;
        };
        if !folder_reachable(Path::new(root)) {
            continue;
        }
        match crate::security::filesystem::remove_approved_file(
            Path::new(&path),
            std::slice::from_ref(root),
        ) {
            Ok(()) => {
                tracing::info!("Removed {path}, which could not be removed earlier");
                done.push(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => done.push(path),
            Err(e) => tracing::debug!("Could not remove {path} yet: {e}"),
        }
    }
    if let Err(e) = db.forget_deferred_file_removals(&done) {
        tracing::warn!("Could not forget removed files: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_removal_waits_for_its_folder_and_happens_once_it_is_back() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-deferred-removals-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let volume = base.join("drive");
        let (current, held) = (base.join("current"), volume.join("ember"));
        for dir in [current.join("Temp"), held.join("Temp"), base.join("data")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let part = held.join("Temp").join("cancelled.part");
        std::fs::write(&part, b"progress").unwrap();
        let folders = DownloadFolders::new(
            &current.to_string_lossy(),
            &[held.to_string_lossy().into_owned()],
        );
        crate::security::filesystem::initialize_approved_roots(
            &base.join("data"),
            &folders.roots(),
        )
        .unwrap();
        let db = Database::open_at(&base.join("data").join("ember.db")).unwrap();
        record(
            &db,
            &[(
                part.to_string_lossy().into_owned(),
                held.to_string_lossy().into_owned(),
            )],
        );

        crate::storage::part_folders::simulate_unplugged(&volume, true);
        retry(&db, &folders);
        crate::storage::part_folders::simulate_unplugged(&volume, false);
        assert!(part.exists());
        assert_eq!(db.deferred_file_removals().unwrap().len(), 1, "kept for later");

        retry(&db, &folders);
        assert!(!part.exists(), "removed once its drive is back");
        assert!(db.deferred_file_removals().unwrap().is_empty());

        record(&db, &[("/elsewhere/x.part".into(), "/not/a/download/folder".into())]);
        retry(&db, &folders);
        assert!(
            db.deferred_file_removals().unwrap().is_empty(),
            "one in a folder that is no longer a download folder is let go"
        );
        drop(db);
        let _ = std::fs::remove_dir_all(base);
    }
}
