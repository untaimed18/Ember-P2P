//! Ember's own releases, shared over eD2K for people who cannot reach GitHub.
//!
//! Every release lists an `ed2k://` link for each installer (on the website
//! and in the release body, from `scripts/ed2k-links.mjs`), and a link is only
//! as good as its sources. Two settings give it some:
//!
//! - **`share_ember_installer`**: when Ember installs an update it keeps the
//!   installer it verified and updated with. Each user shares the one file
//!   their platform needs, so a release has more sources the more people take
//!   it.
//! - **`seed_ember_releases`**: for a computer that stays on. When the update
//!   check sees a release, Ember fetches every platform's installer, the
//!   release's eMule collection and its notes, checks each against the
//!   release signature, and shares them, so every link has a source from the
//!   day it is published.
//!
//! Both keep their files in `<download folder>/Ember releases`, an ordinary
//! shared folder, so the Library shows what is shared and the files reach KAD
//! and the servers, and answer part-hash and AICH requests, exactly as any
//! other shared file does. Only files named for a release (`Ember_1.8.0_…`)
//! are ever written or removed there, and only the newest release's are kept.

use std::path::{Path, PathBuf};

/// The folder inside the download folder the releases are shared from.
pub const FOLDER_NAME: &str = "Ember releases";

/// The longest file name taken from a release URL.
const MAX_NAME_CHARS: usize = 128;

#[derive(Default)]
struct Config {
    share_installer: bool,
    seed_all: bool,
    folder: Option<PathBuf>,
}

fn config() -> &'static parking_lot::RwLock<Config> {
    static CONFIG: std::sync::OnceLock<parking_lot::RwLock<Config>> = std::sync::OnceLock::new();
    CONFIG.get_or_init(Default::default)
}

/// The folder for a download folder.
pub fn folder_in(download_folder: &str) -> Option<PathBuf> {
    (!download_folder.trim().is_empty()).then(|| Path::new(download_folder).join(FOLDER_NAME))
}

/// Follow the settings. Read by the updater, which has no handle on them.
///
/// The folder is the one the settings put in the shared folders
/// (`ember_releases_folder`), not one worked out again from the download
/// folder: after the download folder moves, the release folder follows only on
/// a later save, and until then the listed one is where files are shared from.
pub fn configure(settings: &crate::types::AppSettings) {
    let mut config = config().write();
    config.share_installer = settings.share_ember_installer;
    config.seed_all = settings.seed_ember_releases;
    config.folder = (!settings.ember_releases_folder.is_empty())
        .then(|| PathBuf::from(&settings.ember_releases_folder));
}

/// Whether either setting asks for the folder to be shared.
pub fn wanted(settings: &crate::types::AppSettings) -> bool {
    settings.share_ember_installer || settings.seed_ember_releases
}

/// Where to keep the installer an update was made with, when that is wanted.
pub fn installer_folder() -> Option<PathBuf> {
    let config = config().read();
    config.share_installer.then(|| config.folder.clone()).flatten()
}

/// Where to keep every file of each release, when that is wanted.
pub fn seed_folder() -> Option<PathBuf> {
    let config = config().read();
    config.seed_all.then(|| config.folder.clone()).flatten()
}

/// The `major.minor.patch` a release file's name carries: `Ember_1.8.0_…` or
/// `Ember_1.8.0.…`.
fn release_version_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("Ember_")?;
    let bytes = rest.as_bytes();
    let mut at = 0;
    for part in 0..3 {
        let start = at;
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        if at == start || at - start > 5 {
            return None;
        }
        if part < 2 {
            if bytes.get(at) != Some(&b'.') {
                return None;
            }
            at += 1;
        }
    }
    let ends = match bytes.get(at) {
        Some(b'_') => true,
        // An extension, not a fourth number.
        Some(b'.') => !bytes.get(at + 1).is_some_and(u8::is_ascii_digit),
        _ => false,
    };
    ends.then(|| &rest[..at])
}

/// The name to keep a release file under: the last segment of its URL, which
/// must name a file of `version` and nothing that could leave the folder.
pub fn release_file_name(url: &url::Url, version: &str) -> Option<String> {
    let segment = url.path_segments()?.next_back()?;
    let name = crate::network::ed2k::hash::percent_decode_str(segment);
    let safe = !name.is_empty()
        && name.chars().count() <= MAX_NAME_CHARS
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.contains("..");
    (safe && release_version_of(&name) == Some(version)).then_some(name)
}

/// Held while release files are written, moved or removed, so turning sharing
/// off cannot clear the folder in the middle of a write that lands afterwards,
/// and a write never finds its folder being cleared under it.
fn files_lock() -> &'static parking_lot::Mutex<()> {
    static LOCK: std::sync::OnceLock<parking_lot::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(Default::default)
}

/// Make `folder` when it is missing, but never the download folder it sits
/// in: a share that is offline, or a mount point with nothing mounted, must
/// not get a fresh tree on whatever disk is under it.
fn ensure_folder(folder: &Path) -> std::io::Result<()> {
    match std::fs::create_dir(folder) {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && folder.is_dir() => Ok(()),
        result => result,
    }
}

/// [`ensure_folder`], as the shared folders list it: canonical. Blocking.
pub fn create(folder: &Path) -> std::io::Result<PathBuf> {
    ensure_folder(folder)?;
    folder.canonicalize()
}

/// Keep `bytes`, which the caller has verified, as `name` in `folder`,
/// replacing whatever was there, if `still_wanted` says so once nothing else
/// can touch the folder. Whether it was kept. Blocking.
pub fn keep(folder: &Path, name: &str, bytes: &[u8], still_wanted: impl FnOnce() -> bool) -> std::io::Result<bool> {
    let _files = files_lock().lock();
    if !still_wanted() {
        return Ok(false);
    }
    ensure_folder(folder)?;
    crate::security::atomic_write(&folder.join(name), bytes, false)?;
    Ok(true)
}

/// Remove `name` from `folder`, if it is there. Whether it was. Blocking.
pub fn remove(folder: &Path, name: &str) -> bool {
    let _files = files_lock().lock();
    std::fs::remove_file(folder.join(name)).is_ok()
}

/// What `atomic_write` leaves of a release file whose write never finished:
/// `.<name>.<pid>.<random>.tmp`.
fn is_leftover_write(name: &str) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .and_then(release_version_of)
        .is_some()
}

/// Each release file and leftover write in `folder`, with whether it is a
/// leftover.
fn release_entries(folder: &Path) -> Vec<(std::fs::DirEntry, String, bool)> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            if is_leftover_write(&name) {
                Some((entry, name, true))
            } else {
                release_version_of(&name).is_some().then_some((entry, name, false))
            }
        })
        .collect()
}

/// What a file looked like when its content was last checked.
type Stamp = (u64, Option<std::time::SystemTime>);

fn stamp_of(path: &Path) -> Option<Stamp> {
    let meta = std::fs::metadata(path).ok().filter(std::fs::Metadata::is_file)?;
    Some((meta.len(), meta.modified().ok()))
}

type Checked = std::collections::HashMap<PathBuf, (Stamp, String)>;

fn checked() -> &'static parking_lot::Mutex<Checked> {
    static CHECKED: std::sync::OnceLock<parking_lot::Mutex<Checked>> = std::sync::OnceLock::new();
    CHECKED.get_or_init(Default::default)
}

/// Remember that `path`'s content was checked against `against` (the signed
/// hash it was held to) as the file is now, so the hourly check does not read
/// it again until it changes, the release names other bytes, or Ember restarts.
pub fn note_checked(path: &Path, against: &str) {
    if let Some(stamp) = stamp_of(path) {
        checked().lock().insert(path.to_path_buf(), (stamp, against.to_string()));
    }
}

/// Whether `path` was checked against `against` this session and has not
/// changed since.
pub fn checked_unchanged(path: &Path, against: &str) -> bool {
    let recorded = checked().lock().get(path).cloned();
    recorded.is_some_and(|(stamp, checked_against)| checked_against == against && stamp_of(path) == Some(stamp))
}

/// Whether `path` holds exactly `size` bytes whose SHA-256 is `sha256`
/// (lowercase hex). Blocking: it reads the whole file.
pub fn holds(path: &Path, size: u64, sha256: &str) -> bool {
    use sha2::Digest;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if file.metadata().map(|meta| meta.len()).ok() != Some(size) {
        return false;
    }
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut file, &mut hasher).is_ok() && hex::encode(hasher.finalize()) == sha256
}

/// Remove every release file in `folder` that is not of `keep_version`, and
/// every leftover write. Returns how many went. Blocking.
pub fn prune(folder: &Path, keep_version: &str) -> usize {
    let _files = files_lock().lock();
    release_entries(folder)
        .into_iter()
        .filter(|(_, name, leftover)| *leftover || release_version_of(name) != Some(keep_version))
        .filter(|(entry, _, _)| std::fs::remove_file(entry.path()).is_ok())
        .count()
}

/// Remove every release file in `folder` but the installers whose names end
/// in `installer_suffix`, and every leftover write: what is left when only
/// the installer this install updated with is to be shared. Blocking.
pub fn retain_installers(folder: &Path, installer_suffix: Option<&str>) -> usize {
    let _files = files_lock().lock();
    release_entries(folder)
        .into_iter()
        .filter(|(_, name, leftover)| *leftover || !installer_suffix.is_some_and(|suffix| name.ends_with(suffix)))
        .filter(|(entry, _, _)| std::fs::remove_file(entry.path()).is_ok())
        .count()
}

/// The end of the name of the installer this build updates with, as the
/// release workflow names them: what [`retain_installers`] keeps.
pub fn own_installer_suffix() -> Option<&'static str> {
    use tauri::utils::config::BundleType;
    match tauri::utils::platform::bundle_type()? {
        BundleType::Nsis => Some("-setup.exe"),
        BundleType::Msi => Some(".msi"),
        BundleType::Deb => Some(".deb"),
        BundleType::Rpm => Some(".rpm"),
        BundleType::AppImage => Some(".AppImage"),
        _ => None,
    }
}

/// Remove every release file and leftover write in `folder`, and the folder
/// if that leaves it empty: what turning both settings off undoes. Blocking.
pub fn clear(folder: &Path) {
    let _files = files_lock().lock();
    for (entry, _, _) in release_entries(folder) {
        let _ = std::fs::remove_file(entry.path());
    }
    let _ = std::fs::remove_dir(folder);
}

/// Carry the release files in `from` over to `to`, where the folder has moved
/// with the download folder, then [`clear`] what is left of `from`. A file
/// `to` already has is not replaced. Returns how many moved. Blocking.
pub fn migrate(from: &Path, to: &Path) -> usize {
    // Two spellings of one folder (a link in the download folder's path):
    // clearing `from` would delete what `to` holds.
    if from.canonicalize().is_ok_and(|from| to.canonicalize().is_ok_and(|to| to == from)) {
        return 0;
    }
    let moved = {
        let _files = files_lock().lock();
        if ensure_folder(to).is_err() {
            0
        } else {
            release_entries(from)
                .into_iter()
                .filter(|(_, name, leftover)| !*leftover && !to.join(name).exists())
                .filter(|(entry, name, _)| {
                    let target = to.join(name);
                    std::fs::rename(entry.path(), &target).is_ok()
                        || (std::fs::copy(entry.path(), &target).is_ok() && std::fs::remove_file(entry.path()).is_ok())
                })
                .count()
        }
    };
    clear(from);
    moved
}

/// Keep the installer an update is about to be made with, when the setting
/// asks for it. `url` is the signed artifact's, `bytes` what was verified
/// against it. Best-effort: never a reason not to update. Blocking.
pub fn keep_installer(url: &url::Url, version: &str, bytes: &[u8]) {
    let Some(folder) = installer_folder() else {
        return;
    };
    let Some(name) = release_file_name(url, version) else {
        tracing::debug!("Release sharing: {url} does not name an Ember {version} file; not keeping it");
        return;
    };
    let still_wanted = || installer_folder().as_deref() == Some(folder.as_path());
    match keep(&folder, &name, bytes, still_wanted) {
        Ok(true) => {
            let pruned = prune(&folder, version);
            tracing::info!("Release sharing: kept {name} to share (removed {pruned} older)");
        }
        Ok(false) => {}
        Err(error) => tracing::warn!("Release sharing: could not keep {name}: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }

    #[test]
    fn only_a_release_files_own_name_is_kept() {
        let base = "https://github.com/untaimed18/Ember-P2P/releases/download/v1.8.0/";
        for name in [
            "Ember_1.8.0_x64-setup.exe",
            "Ember_1.8.0_x64_en-US.msi",
            "Ember_1.8.0_amd64.deb",
            "Ember_1.8.0_amd64.AppImage",
            "Ember_1.8.0.emulecollection",
            "Ember_1.8.0_release-notes.md",
        ] {
            assert_eq!(release_file_name(&url(&format!("{base}{name}")), "1.8.0").as_deref(), Some(name));
        }
        assert_eq!(release_file_name(&url(&format!("{base}Ember_1.7.6_amd64.deb")), "1.8.0"), None, "another release's");
        assert_eq!(release_file_name(&url(&format!("{base}setup.exe")), "1.8.0"), None);
        assert_eq!(release_file_name(&url(&format!("{base}Ember_1.8.0_..%2F..%2Fx.exe")), "1.8.0"), None);
        assert_eq!(release_file_name(&url(&format!("{base}Ember_1.8.0_a%5Cb.exe")), "1.8.0"), None);
        assert_eq!(release_file_name(&url(&format!("{base}Ember_1.8.00_a.exe")), "1.8.0"), None);
        assert_eq!(release_file_name(&url(&format!("{base}Ember_1.8.0%20x.exe")), "1.8.0"), None);
    }

    #[test]
    fn only_release_files_of_other_versions_are_pruned() {
        let dir = std::env::temp_dir().join(format!("ember-release-share-{}-{}", std::process::id(), rand::random::<u64>()));
        assert!(keep(&dir, "Ember_1.7.6_amd64.deb", b"old", || true).unwrap());
        assert!(keep(&dir, "Ember_1.8.0_amd64.deb", b"new", || true).unwrap());
        assert!(!keep(&dir, "Ember_1.8.0_x64-setup.exe", b"late", || false).unwrap(), "turned off meanwhile");
        assert!(!dir.join("Ember_1.8.0_x64-setup.exe").exists());
        std::fs::write(dir.join("notes.txt"), b"the user's").unwrap();
        std::fs::write(dir.join("Ember_backup.zip"), b"not a release file").unwrap();
        std::fs::write(dir.join(".Ember_1.8.0_amd64.AppImage.4242.00ff.tmp"), b"a write that never finished").unwrap();
        std::fs::write(dir.join(".notes.txt.4242.00ff.tmp"), b"the user's own").unwrap();
        std::fs::create_dir_all(dir.join("Ember_1.7.6_folder")).unwrap();

        assert_eq!(prune(&dir, "1.8.0"), 2, "the older release and the leftover write");
        assert!(dir.join(".notes.txt.4242.00ff.tmp").exists());
        assert!(!dir.join("Ember_1.7.6_amd64.deb").exists());
        assert!(dir.join("Ember_1.8.0_amd64.deb").exists());
        assert!(dir.join("notes.txt").exists() && dir.join("Ember_backup.zip").exists());
        assert!(dir.join("Ember_1.7.6_folder").is_dir(), "folders are never removed");

        let deb = dir.join("Ember_1.8.0_amd64.deb");
        let sha = |bytes: &[u8]| {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(bytes))
        };
        assert!(holds(&deb, 3, &sha(b"new")));
        assert!(!holds(&deb, 3, &sha(b"neW")), "same size, other bytes");
        assert!(!holds(&deb, 4, &sha(b"new")));
        note_checked(&deb, &sha(b"new"));
        assert!(checked_unchanged(&deb, &sha(b"new")));
        assert!(!checked_unchanged(&deb, &sha(b"other")), "held to other bytes, it is checked again");
        keep(&dir, "Ember_1.8.0_amd64.deb", b"replaced", || true).unwrap();
        assert_eq!(std::fs::read(&deb).unwrap(), b"replaced");
        assert!(!checked_unchanged(&deb, &sha(b"new")), "a change is checked again");

        clear(&dir);
        assert!(!dir.join("Ember_1.8.0_amd64.deb").exists());
        assert!(dir.join("notes.txt").exists(), "a folder with the user's files in it stays");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_folder_is_never_made_where_its_download_folder_is_missing() {
        let base = std::env::temp_dir().join(format!("ember-release-unmounted-{}-{}", std::process::id(), rand::random::<u64>()));
        let folder = base.join("Downloads").join(FOLDER_NAME);
        assert!(create(&folder).is_err());
        assert!(keep(&folder, "Ember_1.8.0_amd64.deb", b"x", || true).is_err());
        assert!(!base.exists(), "nothing made on the disk under an empty mount point");
        std::fs::create_dir_all(base.join("Downloads")).unwrap();
        assert!(create(&folder).unwrap().is_dir());
        assert!(create(&folder).is_ok(), "already there");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_moved_folder_takes_its_release_files_along() {
        let base = std::env::temp_dir().join(format!("ember-release-move-{}-{}", std::process::id(), rand::random::<u64>()));
        let (from, to) = (base.join("old"), base.join("new"));
        std::fs::create_dir_all(&base).unwrap();
        keep(&from, "Ember_1.8.0_amd64.deb", b"kept", || true).unwrap();
        keep(&from, "Ember_1.8.0.emulecollection", b"old copy", || true).unwrap();
        keep(&to, "Ember_1.8.0.emulecollection", b"new copy", || true).unwrap();
        std::fs::write(from.join(".Ember_1.8.0_x64-setup.exe.1.2.tmp"), b"unfinished").unwrap();

        assert_eq!(migrate(&from, &to), 1);
        assert_eq!(std::fs::read(to.join("Ember_1.8.0_amd64.deb")).unwrap(), b"kept");
        assert_eq!(std::fs::read(to.join("Ember_1.8.0.emulecollection")).unwrap(), b"new copy", "not replaced");
        assert!(!to.join(".Ember_1.8.0_x64-setup.exe.1.2.tmp").exists());
        assert!(!from.exists(), "the old folder goes once it is empty");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn only_the_own_installer_stays_when_seeding_stops() {
        let dir = std::env::temp_dir().join(format!("ember-release-retain-{}-{}", std::process::id(), rand::random::<u64>()));
        for name in ["Ember_1.8.0_x64-setup.exe", "Ember_1.8.0_x64_en-US.msi", "Ember_1.8.0_amd64.deb", "Ember_1.8.0.emulecollection"] {
            keep(&dir, name, b"x", || true).unwrap();
        }
        std::fs::write(dir.join("readme.txt"), b"the user's").unwrap();
        assert_eq!(retain_installers(&dir, Some("-setup.exe")), 3);
        assert!(dir.join("Ember_1.8.0_x64-setup.exe").exists());
        assert!(dir.join("readme.txt").exists());
        assert_eq!(retain_installers(&dir, None), 1, "a build that updates with none of them keeps none");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_release_files_version_is_read_from_its_name() {
        assert_eq!(release_version_of("Ember_1.8.0_amd64.deb"), Some("1.8.0"));
        assert_eq!(release_version_of("Ember_1.8.0.emulecollection"), Some("1.8.0"));
        assert_eq!(release_version_of("Ember_10.20.300_x64-setup.exe"), Some("10.20.300"));
        for name in ["Ember_1.8_amd64.deb", "Ember_1.8.0", "Ember_1.8.0-beta.deb", "Ember_backup.zip", "ember_1.8.0_a.deb", "Ember_1.8.0.1_a"] {
            assert_eq!(release_version_of(name), None, "{name}");
        }
    }

    #[test]
    fn the_folder_is_inside_the_download_folder() {
        assert_eq!(folder_in("/home/a/Ember"), Some(Path::new("/home/a/Ember").join(FOLDER_NAME)));
        assert_eq!(folder_in("  "), None);
    }
}
