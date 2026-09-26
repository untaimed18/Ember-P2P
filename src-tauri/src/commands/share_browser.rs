//! In-app Explorer-style browser used to pick shared folders and files.
//!
//! The OS directory dialog cannot mark folders that are already shared, and it
//! is a poor stand-in for eMule's directory tree. This module lists drives,
//! child folders, and the files inside them for the Library UI. A checked
//! folder is shared in full. Checked files share only those files: the parent
//! folder is added with an allowlist, the same mechanism a file drop uses.
//!
//! Sharing is still not "the renderer named a path": listings issue opaque
//! entry ids bound to a short-lived session, and [`share_browser_selection`]
//! only honours those ids. But the renderer holds the session id and can list
//! any typed path, so the ids are bookkeeping, not authorization. What
//! authorizes a folder that is not shared yet is a native confirmation naming
//! it, which the webview can neither draw nor answer; the add itself refuses
//! any new root that confirmation did not name. The checks in
//! [`super::sharing::add_shared_folder`] still apply on top: no system or
//! profile drive, no Ember data directory, no sensitive names, no overlapping
//! shares.
//!
//! Listing never follows symlinks, junctions or mount points, so expanding a
//! folder cannot jump the tree to an unrelated location.

use std::collections::{HashMap, HashSet};
use std::fs::Metadata;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::commands::sharing::{
    add_shared_folder_approved, batch_share, finish_pick, path_key_covers,
    persist_folder_allowlists, share_all_in_folder, FolderAddOutcome, ShareApproval,
    SharedFolderPick,
};
use crate::commands::settings::{elide_for_dialog, shared_paths_overlap};
use crate::search::index::normalize_path_key;
use crate::sharing::indexer::is_excluded_share_file_name;
use crate::sharing::is_sensitive_dir_name;
use crate::storage::paths::resolve_data_dir;

const MAX_PATH_LEN: usize = 4 * 1024;
/// Subfolders returned for one location. A folder with more than this is
/// listed up to the cap and reported as truncated rather than refused: a
/// browser that fails outright on a big directory is worse than one that shows
/// the first few thousand entries and says so.
const MAX_CHILDREN: usize = 2_000;
/// Entries one session may issue ids for. Reached only by browsing tens of
/// thousands of folders without closing the dialog; the session is dropped on
/// close, so this bounds a single sitting rather than the process.
const MAX_SESSION_ENTRIES: usize = 100_000;
const MAX_SHARE_SELECTION: usize = 500;
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
/// How long one measurement may walk before it answers with a lower bound.
/// Long enough to finish an ordinary Documents folder on a local disk, short
/// enough that the summary does not sit on "Counting…" for a whole drive.
const MEASURE_BUDGET: Duration = Duration::from_secs(8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareBrowserKind {
    ThisPc,
    #[allow(dead_code)] // constructed on Unix only
    Home,
    Desktop,
    Documents,
    Downloads,
    Music,
    Pictures,
    Videos,
    Drive,
    Folder,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareBrowserStatus {
    Shareable,
    /// The folder is shared, but an allowlist limits which files are offered.
    Partial,
    Already,
    /// Inside a folder shared whole, so shared along with it: Ember shares a
    /// folder and everything under it.
    Inherited,
    /// Inside a partly shared folder, and not among what it offers.
    Overlap,
    /// Holds a folder that is already shared; shares cannot overlap.
    ContainsShared,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareBrowserEntry {
    pub id: u64,
    pub name: String,
    pub path: String,
    pub kind: ShareBrowserKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub letter: Option<String>,
    pub parent_id: Option<u64>,
    pub share_status: ShareBrowserStatus,
    /// Byte length of a file. Folders and drives leave this unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// How many files a partial share currently offers. Set only for [`ShareBrowserStatus::Partial`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareBrowserView {
    pub session_id: u64,
    pub current: ShareBrowserEntry,
    pub children: Vec<ShareBrowserEntry>,
    /// The location holds more folders and files than [`MAX_CHILDREN`], so
    /// `children` is the first page of them. Folders are kept ahead of files.
    pub truncated: bool,
}

#[derive(Clone)]
enum Location {
    ThisPc,
    Path(PathBuf),
}

#[derive(Clone)]
struct StoredEntry {
    location: Location,
    kind: ShareBrowserKind,
    letter: Option<String>,
    name: String,
    parent_id: Option<u64>,
    size: Option<u64>,
}

struct ShareBrowserSession {
    id: u64,
    /// Refreshed on every call, so [`SESSION_TTL`] measures idleness rather
    /// than how long the dialog has been open.
    last_used: Instant,
    next_entry: u64,
    entries: HashMap<u64, StoredEntry>,
    /// Id already issued for a location under a given parent, so listing the
    /// same folder again hands back the same ids instead of spending fresh
    /// ones against [`MAX_SESSION_ENTRIES`].
    issued: HashMap<(Option<u64>, String), u64>,
    shared_folders: Vec<PathBuf>,
    /// Partial shares: folder key → file keys that are actually shared.
    /// A shared folder with no entry here shares every file in it.
    allowlists: HashMap<String, Vec<String>>,
    /// Indexed files the user has taken off the network. A full share still
    /// contains them on disk; the picker must offer them again.
    unshared: HashSet<String>,
    /// Indexed vs. offered counts per shared folder, so a folder that is
    /// shared but not offering everything reads as partly shared.
    offers: HashMap<String, FolderOffer>,
    data_dir: PathBuf,
    /// Raised to stop the measurement in flight. Only the newest one is worth
    /// finishing: each answers a selection the user has since changed.
    measure_cancel: Option<Arc<AtomicBool>>,
}

impl Drop for ShareBrowserSession {
    /// Closing, replacing or expiring the session stops its measurement, which
    /// may otherwise be walking a whole drive for a dialog nobody has open.
    fn drop(&mut self) {
        if let Some(cancel) = self.measure_cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

/// What one shared folder currently contributes to the library.
#[derive(Clone, Copy, Default)]
struct FolderOffer {
    /// Files under this folder the index knows about.
    indexed: u32,
    /// Of those, the ones other peers can download.
    offered: u32,
}

impl ShareBrowserSession {
    fn new(id: u64, shared_folders: Vec<PathBuf>, data_dir: PathBuf) -> Self {
        Self {
            id,
            last_used: Instant::now(),
            next_entry: 1,
            entries: HashMap::new(),
            issued: HashMap::new(),
            shared_folders,
            allowlists: HashMap::new(),
            unshared: HashSet::new(),
            offers: HashMap::new(),
            data_dir,
            measure_cancel: None,
        }
    }

    fn insert(&mut self, stored: StoredEntry) -> Result<u64, String> {
        let location_key = match &stored.location {
            Location::ThisPc => String::new(),
            Location::Path(path) => normalize_path_key(&display_fs_path(path)),
        };
        let issued_key = (stored.parent_id, location_key);
        if let Some(id) = self.issued.get(&issued_key).copied() {
            // Same place, possibly a fresher size or name casing.
            self.entries.insert(id, stored);
            return Ok(id);
        }
        if self.entries.len() >= MAX_SESSION_ENTRIES {
            return Err(coded(
                "sharing_browser_session",
                "The folder browser session expired. Close it and try again.",
            ));
        }
        let id = self.next_entry;
        self.next_entry = self.next_entry.saturating_add(1);
        self.entries.insert(id, stored);
        self.issued.insert(issued_key, id);
        Ok(id)
    }
}

fn sessions() -> &'static Mutex<Option<ShareBrowserSession>> {
    static SESSION: OnceLock<Mutex<Option<ShareBrowserSession>>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(None))
}

fn lock_session() -> Result<std::sync::MutexGuard<'static, Option<ShareBrowserSession>>, String> {
    sessions()
        .lock()
        .map_err(|_| coded("sharing_browser_session", "Folder browser session is busy"))
}

fn require_main_window(window: &tauri::WebviewWindow) -> Result<(), String> {
    if window.label() != "main" {
        return Err(coded(
            "sharing_browser_wrong_window",
            "Shared folders can only be selected from the main window",
        ));
    }
    Ok(())
}

fn require_session(
    guard: &mut Option<ShareBrowserSession>,
    session_id: u64,
) -> Result<&mut ShareBrowserSession, String> {
    let expired = guard
        .as_ref()
        .is_some_and(|session| session.last_used.elapsed() > SESSION_TTL);
    if expired {
        *guard = None;
    }
    match guard.as_mut() {
        Some(session) if session.id == session_id => {
            session.last_used = Instant::now();
            Ok(session)
        }
        _ => Err(coded(
            "sharing_browser_session",
            "The folder browser session expired. Close it and try again.",
        )),
    }
}

pub(crate) fn display_fs_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        raw.into_owned()
    }
}

pub(crate) fn normalize_absolute(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(_) => out.push(component),
        }
    }
    out
}

fn same_folder(a: &str, b: &str) -> bool {
    let norm = |path: &str| {
        normalize_path_key(path)
            .trim_end_matches(['/', '\\'])
            .to_string()
    };
    norm(a) == norm(b)
}

fn is_filesystem_root(path: &Path) -> bool {
    crate::sharing::is_volume_root(path)
}

/// A volume root that may never be shared. Other drive roots are offered like
/// folders, and sharing one whole takes the whole-drive warning first.
fn root_share_refused(path: &Path) -> bool {
    crate::sharing::drive_root_share(path) == crate::sharing::DriveRootShare::Refused
}

fn path_has_sensitive_component(path: &Path) -> bool {
    path.components().any(|component| {
        if let Component::Normal(seg) = component {
            is_sensitive_dir_name(&seg.to_string_lossy())
        } else {
            false
        }
    })
}

pub(crate) fn is_noise_dir_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "$recycle.bin"
            | "system volume information"
            | "recovery"
            | "config.msi"
            | "windows.old"
            | "$windows.~bt"
            | "$windows.~ws"
    )
}

/// Hidden by Explorer's default view.
///
/// Deliberately not `HIDDEN | SYSTEM`: Windows sets SYSTEM on the customized
/// known folders (`Documents`, `Downloads`, `Pictures`, …), so treating it as
/// hidden made a user's own library folders vanish from the listing of their
/// home directory. Explorer itself hides on HIDDEN alone.
#[cfg(windows)]
fn is_hidden_entry(meta: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const HIDDEN: u32 = 0x2;
    meta.file_attributes() & HIDDEN != 0
}

#[cfg(not(windows))]
fn is_hidden_entry(_meta: &Metadata) -> bool {
    false
}

/// `path` is Ember's data directory or something inside it. Distinct from
/// [`covers_data_dir`], which also matches a *parent* of the data directory —
/// true of the user's home folder, which must stay browsable.
fn inside_data_dir(path: &Path, data_dir: &Path) -> bool {
    let path_s = display_fs_path(path);
    let data_s = display_fs_path(data_dir);
    same_folder(&path_s, &data_s) || crate::security::path_matches_dir(&path_s, &data_s)
}

fn covers_data_dir(path: &Path, data_dir: &Path) -> bool {
    let path_s = display_fs_path(path);
    let data_s = display_fs_path(data_dir);
    same_folder(&path_s, &data_s)
        || data_dir.starts_with(path)
        || crate::security::path_matches_dir(&data_s, &path_s)
}

fn share_status_for(
    path: &Path,
    kind: ShareBrowserKind,
    shared: &[PathBuf],
    data_dir: &Path,
    allowlists: &HashMap<String, Vec<String>>,
    offers: &HashMap<String, FolderOffer>,
) -> ShareBrowserStatus {
    if matches!(kind, ShareBrowserKind::ThisPc) || root_share_refused(path) {
        return ShareBrowserStatus::Blocked;
    }
    if path_has_sensitive_component(path) || covers_data_dir(path, data_dir) {
        return ShareBrowserStatus::Blocked;
    }
    let display = display_fs_path(path);
    for existing in shared {
        if same_folder(&display, &display_fs_path(existing)) {
            // Partly shared either because an allowlist limits what the next
            // scan offers, or because files under it were taken off the
            // network one at a time. Both are fixed by sharing the folder.
            let key = normalize_path_key(&display);
            let held_back = offers
                .get(&key)
                .is_some_and(|offer| offer.offered < offer.indexed);
            return if allowlists.contains_key(&key) || held_back {
                ShareBrowserStatus::Partial
            } else {
                ShareBrowserStatus::Already
            };
        }
        let existing_display = display_fs_path(existing);
        if shared_paths_overlap(Path::new(&display), Path::new(&existing_display)) {
            if !path_within(&display, &existing_display) {
                return ShareBrowserStatus::ContainsShared;
            }
            return match allowlist_contains(allowlists, existing, path) {
                // A folder offered whole through its share's allowlist.
                Some(true) => ShareBrowserStatus::Already,
                Some(false) => ShareBrowserStatus::Overlap,
                None => ShareBrowserStatus::Inherited,
            };
        }
    }
    ShareBrowserStatus::Shareable
}

/// Deepest shared folder that contains `file`, if any.
fn containing_share<'a>(file: &Path, shared: &'a [PathBuf]) -> Option<&'a Path> {
    let display = display_fs_path(file);
    shared
        .iter()
        .filter(|existing| path_within(&display, &display_fs_path(existing)))
        .max_by_key(|existing| display_fs_path(existing).len())
        .map(PathBuf::as_path)
}

fn allowlist_contains(allowlists: &HashMap<String, Vec<String>>, folder: &Path, file: &Path) -> Option<bool> {
    let list = allowlists.get(&normalize_path_key(&display_fs_path(folder)))?;
    let file_key = normalize_path_key(&display_fs_path(file));
    Some(list.iter().any(|item| path_key_covers(item, &file_key)))
}

/// A file is shared by adding its parent folder. One that already lives in a
/// full share is already shared; one left off a partial share can be added to
/// that list. A file sitting on a drive root has no folder we are allowed to add.
fn file_share_status(
    path: &Path,
    shared: &[PathBuf],
    data_dir: &Path,
    allowlists: &HashMap<String, Vec<String>>,
    unshared: &HashSet<String>,
) -> ShareBrowserStatus {
    if is_excluded_share_file_name(path) || path_has_sensitive_component(path) {
        return ShareBrowserStatus::Blocked;
    }
    let display = display_fs_path(path);
    let data_display = display_fs_path(data_dir);
    if crate::security::path_matches_dir(&display, &data_display) || covers_data_dir(path, data_dir)
    {
        return ShareBrowserStatus::Blocked;
    }
    if let Some(folder) = containing_share(path, shared) {
        // Taken off the network from the library. The folder may still be a
        // full share; this file is the one the user can offer again.
        if unshared.contains(&normalize_path_key(&display)) {
            return ShareBrowserStatus::Shareable;
        }
        return match allowlist_contains(allowlists, folder, path) {
            Some(true) | None => ShareBrowserStatus::Already,
            Some(false) => ShareBrowserStatus::Shareable,
        };
    }
    let Some(parent) = path.parent() else {
        return ShareBrowserStatus::Blocked;
    };
    if root_share_refused(parent) {
        return ShareBrowserStatus::Blocked;
    }
    match share_status_for(
        parent,
        ShareBrowserKind::Folder,
        shared,
        data_dir,
        allowlists,
        &HashMap::new(),
    ) {
        ShareBrowserStatus::Partial => ShareBrowserStatus::Shareable,
        status => status,
    }
}

fn entry_from_stored(
    id: u64,
    stored: &StoredEntry,
    session: &ShareBrowserSession,
) -> ShareBrowserEntry {
    match &stored.location {
        Location::ThisPc => ShareBrowserEntry {
            id,
            name: stored.name.clone(),
            path: String::new(),
            kind: ShareBrowserKind::ThisPc,
            letter: None,
            parent_id: None,
            share_status: ShareBrowserStatus::Blocked,
            size: None,
            shared_count: None,
        },
        Location::Path(path) => {
            let share_status = if stored.kind == ShareBrowserKind::File {
                file_share_status(
                    path,
                    &session.shared_folders,
                    &session.data_dir,
                    &session.allowlists,
                    &session.unshared,
                )
            } else {
                share_status_for(
                    path,
                    stored.kind,
                    &session.shared_folders,
                    &session.data_dir,
                    &session.allowlists,
                    &session.offers,
                )
            };
            let shared_count = if share_status == ShareBrowserStatus::Partial {
                let key = normalize_path_key(&display_fs_path(path));
                // Before the folder's first scan finishes nothing is indexed
                // yet, so the allowlist is the only count there is.
                match session.offers.get(&key) {
                    Some(offer) if offer.indexed > 0 => Some(offer.offered),
                    _ => session.allowlists.get(&key).map(|files| files.len() as u32),
                }
            } else {
                None
            };
            ShareBrowserEntry {
                id,
                name: stored.name.clone(),
                path: display_fs_path(path),
                kind: stored.kind,
                letter: stored.letter.clone(),
                parent_id: stored.parent_id,
                size: stored.size,
                share_status,
                shared_count,
            }
        }
    }
}

#[cfg(windows)]
fn logical_drives() -> Vec<(char, PathBuf)> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let mut root: Vec<u16> = format!("{letter}:\\").encode_utf16().collect();
        root.push(0);
        let dtype = unsafe { GetDriveTypeW(root.as_ptr()) };
        // 0 = DRIVE_UNKNOWN, 1 = DRIVE_NO_ROOT_DIR
        if dtype <= 1 {
            continue;
        }
        out.push((letter, PathBuf::from(format!("{letter}:\\"))));
    }
    out
}

#[cfg(not(windows))]
fn logical_drives() -> Vec<(char, PathBuf)> {
    Vec::new()
}

struct PendingChild {
    location: Location,
    kind: ShareBrowserKind,
    letter: Option<String>,
    name: String,
    size: Option<u64>,
}

fn special_folder_children() -> Vec<PendingChild> {
    let mut out = Vec::new();
    let Some(user) = directories::UserDirs::new() else {
        return out;
    };
    let mut push = |kind: ShareBrowserKind, path: PathBuf, name: &str| {
        if !path.is_dir() || path_has_sensitive_component(&path) {
            return;
        }
        if out.iter().any(|child| match &child.location {
            Location::Path(existing) => existing == &path,
            Location::ThisPc => false,
        }) {
            return;
        }
        out.push(PendingChild {
            location: Location::Path(path),
            kind,
            letter: None,
            name: name.to_string(),
            size: None,
        });
    };
    #[cfg(not(windows))]
    push(
        ShareBrowserKind::Home,
        user.home_dir().to_path_buf(),
        "Home",
    );
    if let Some(path) = user.desktop_dir() {
        push(ShareBrowserKind::Desktop, path.to_path_buf(), "Desktop");
    }
    if let Some(path) = user.document_dir() {
        push(
            ShareBrowserKind::Documents,
            path.to_path_buf(),
            "Documents",
        );
    }
    if let Some(path) = user.download_dir() {
        push(
            ShareBrowserKind::Downloads,
            path.to_path_buf(),
            "Downloads",
        );
    }
    if let Some(path) = user.audio_dir() {
        push(ShareBrowserKind::Music, path.to_path_buf(), "Music");
    }
    if let Some(path) = user.picture_dir() {
        push(ShareBrowserKind::Pictures, path.to_path_buf(), "Pictures");
    }
    if let Some(path) = user.video_dir() {
        push(ShareBrowserKind::Videos, path.to_path_buf(), "Videos");
    }
    out
}

fn this_pc_children() -> Vec<PendingChild> {
    let mut children = special_folder_children();
    for (letter, path) in logical_drives() {
        children.push(PendingChild {
            location: Location::Path(path),
            kind: ShareBrowserKind::Drive,
            letter: Some(letter.to_string()),
            name: format!("{letter}:"),
            size: None,
        });
    }
    #[cfg(not(windows))]
    {
        let root = PathBuf::from("/");
        if root.is_dir() {
            children.push(PendingChild {
                location: Location::Path(root),
                kind: ShareBrowserKind::Drive,
                letter: None,
                name: "/".to_string(),
                size: None,
            });
        }
    }
    children
}

/// Folders and files directly inside `parent`, and whether the listing hit
/// [`MAX_CHILDREN`]. Folders are kept ahead of files when the cap bites, so a
/// directory full of files still shows its subfolders.
///
/// Ember's own data directory is left out. Nothing in it can ever be shared,
/// so listing it is noise — and on platforms where it does not live under a
/// [`is_sensitive_dir_name`] segment (`~/.local/share` on Linux,
/// `~/Library/Application Support` on macOS) it is otherwise walkable.
fn list_child_dirs(parent: &Path, data_dir: &Path) -> Result<(Vec<PendingChild>, bool), String> {
    if path_has_sensitive_component(parent) || inside_data_dir(parent, data_dir) {
        return Err(coded(
            "sharing_browser_blocked",
            "Cannot share this location",
        ));
    }
    let iter = std::fs::read_dir(parent).map_err(|error| {
        coded_ctx(
            "sharing_browser_task_failed",
            "Folder browser failed",
            error,
        )
    })?;
    let mut folders = Vec::new();
    let mut files = Vec::new();
    let mut truncated = false;
    for entry in iter {
        if folders.len() >= MAX_CHILDREN && files.len() >= MAX_CHILDREN {
            truncated = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy().into_owned();
        if name_str.is_empty() {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        // On Windows this is every name-surrogate reparse point — symlinks,
        // junctions and volume mount points, the ones that redirect somewhere
        // else. It is not every reparse point: OneDrive placeholders and
        // deduplicated files carry one too, are ordinary files and folders
        // where they sit, and skipping those emptied OneDrive-backed folders.
        if file_type.is_symlink() {
            continue;
        }
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue,
        };
        if is_hidden_entry(&meta) {
            continue;
        }
        let path = parent.join(&name);
        if file_type.is_dir() {
            if is_noise_dir_name(&name_str)
                || is_sensitive_dir_name(&name_str)
                || inside_data_dir(&path, data_dir)
            {
                continue;
            }
            if folders.len() >= MAX_CHILDREN {
                truncated = true;
                continue;
            }
            folders.push(PendingChild {
                location: Location::Path(path),
                kind: ShareBrowserKind::Folder,
                letter: None,
                name: name_str,
                size: None,
            });
        } else if file_type.is_file() {
            if is_excluded_share_file_name(&path) {
                continue;
            }
            if files.len() >= MAX_CHILDREN {
                truncated = true;
                continue;
            }
            files.push(PendingChild {
                location: Location::Path(path),
                kind: ShareBrowserKind::File,
                letter: None,
                name: name_str,
                size: Some(meta.len()),
            });
        }
    }
    let by_name = |a: &PendingChild, b: &PendingChild| {
        a.name.to_lowercase().cmp(&b.name.to_lowercase())
    };
    folders.sort_by(by_name);
    files.sort_by(by_name);
    let mut children = folders;
    let room = MAX_CHILDREN.saturating_sub(children.len());
    if files.len() > room {
        truncated = true;
        files.truncate(room);
    }
    children.append(&mut files);
    Ok((children, truncated))
}

fn register_children(
    session: &mut ShareBrowserSession,
    parent_id: u64,
    pending: Vec<PendingChild>,
) -> Result<Vec<ShareBrowserEntry>, String> {
    let mut out = Vec::with_capacity(pending.len());
    for child in pending {
        let stored = StoredEntry {
            location: child.location,
            kind: child.kind,
            letter: child.letter,
            name: child.name,
            parent_id: Some(parent_id),
            size: child.size,
        };
        let id = session.insert(stored)?;
        let stored = session
            .entries
            .get(&id)
            .expect("just inserted")
            .clone();
        out.push(entry_from_stored(id, &stored, session));
    }
    Ok(out)
}

fn existing_dir(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_folder_path_too_long",
            format!("Folder path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    if !path.is_absolute() {
        return Err(coded(
            "sharing_path_not_dir",
            "Path does not exist or is not a directory",
        ));
    }
    let normalized = normalize_absolute(path);
    let meta = std::fs::symlink_metadata(&normalized).map_err(|error| {
        coded_ctx("sharing_invalid_path", "Invalid path", error)
    })?;
    if meta.file_type().is_symlink() {
        return Err(coded(
            "sharing_browser_symlink",
            "Cannot browse through a linked folder",
        ));
    }
    if !meta.is_dir() {
        return Err(coded(
            "sharing_path_not_dir",
            "Path does not exist or is not a directory",
        ));
    }
    Ok(normalized)
}

fn folder_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| display_fs_path(path))
}

/// The shared folders as configured right now.
///
/// Read on every listing rather than cached with the session: the "already
/// shared" marks are the whole reason this browser exists over the OS dialog,
/// and a folder added moments ago (here, by a drop, or in Settings) has to
/// show as shared the next time it is listed.
async fn current_shared_folders(state: &tauri::State<'_, AppState>) -> Vec<PathBuf> {
    let config = state.config.read().await;
    config
        .settings
        .shared_folders
        .iter()
        .map(PathBuf::from)
        .collect()
}

async fn current_allowlists(
    state: &tauri::State<'_, AppState>,
) -> HashMap<String, Vec<String>> {
    state
        .config
        .read()
        .await
        .settings
        .pending_folder_allowlists
        .clone()
}

/// Files the index still knows about but is not offering, and how much of
/// each shared folder is actually on the network. One pass over the index:
/// a file counts towards the deepest share that contains it, the same rule
/// the Library sidebar uses.
///
/// Runs on every listing, under the index read lock that hashing and search
/// write through, so it costs one key per file and no more: the roots are
/// keyed once up front and matched by prefix.
async fn current_offer_state(
    state: &tauri::State<'_, AppState>,
    shared: &[PathBuf],
) -> (HashSet<String>, HashMap<String, FolderOffer>) {
    let index = state.local_index.read().await;
    offer_state(
        index.all_files().iter().map(|file| (file.path.as_str(), file.shared)),
        shared,
    )
}

fn offer_state<'a>(
    files: impl Iterator<Item = (&'a str, bool)>,
    shared: &[PathBuf],
) -> (HashSet<String>, HashMap<String, FolderOffer>) {
    let mut roots: Vec<String> = shared
        .iter()
        .map(|path| {
            normalize_path_key(&display_fs_path(path))
                .trim_end_matches(['/', '\\'])
                .to_string()
        })
        .filter(|root| !root.is_empty())
        .collect();
    roots.sort_by_key(|root| std::cmp::Reverse(root.len()));
    roots.dedup();
    let mut offers: HashMap<String, FolderOffer> = roots
        .iter()
        .map(|root| (root.clone(), FolderOffer::default()))
        .collect();
    let mut unshared = HashSet::new();

    for (path, shared) in files {
        let key = normalize_path_key(path);
        if let Some(root) = roots
            .iter()
            .find(|root| path_key_covers(root, &key))
        {
            let offer = offers.entry(root.clone()).or_default();
            offer.indexed = offer.indexed.saturating_add(1);
            if shared {
                offer.offered = offer.offered.saturating_add(1);
            }
        }
        if !shared {
            unshared.insert(key);
        }
    }
    (unshared, offers)
}

/// Start a folder-browser session and return This PC / Computer plus its
/// first-level children (known folders and drives).
#[tauri::command]
pub async fn open_share_browser(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, AppState>,
) -> Result<ShareBrowserView, String> {
    require_main_window(&window)?;
    let shared_folders = current_shared_folders(&state).await;
    let allowlists = current_allowlists(&state).await;
    let (unshared, offers) = current_offer_state(&state, &shared_folders).await;
    let data_dir = resolve_data_dir();
    let data_dir = data_dir.canonicalize().unwrap_or(data_dir);
    let roots = tokio::task::spawn_blocking(this_pc_children)
        .await
        .map_err(|error| {
            coded_ctx(
                "sharing_browser_task_failed",
                "Folder browser failed",
                error,
            )
        })?;

    let mut session =
        ShareBrowserSession::new(crate::commands::js_safe_token(), shared_folders, data_dir);
    session.allowlists = allowlists;
    session.unshared = unshared;
    session.offers = offers;
    let current_id = session.insert(StoredEntry {
        location: Location::ThisPc,
        kind: ShareBrowserKind::ThisPc,
        letter: None,
        name: if cfg!(windows) {
            "This PC".to_string()
        } else {
            "Computer".to_string()
        },
        parent_id: None,
        size: None,
    })?;
    let children = register_children(&mut session, current_id, roots)?;
    let current = entry_from_stored(
        current_id,
        session.entries.get(&current_id).expect("this pc"),
        &session,
    );
    let session_id = session.id;
    *lock_session()? = Some(session);
    Ok(ShareBrowserView {
        session_id,
        current,
        children,
        truncated: false,
    })
}

/// List the folders and files inside a previously issued browser entry.
#[tauri::command]
pub async fn list_share_browser_children(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, AppState>,
    session_id: u64,
    entry_id: u64,
) -> Result<ShareBrowserView, String> {
    require_main_window(&window)?;
    let shared_folders = current_shared_folders(&state).await;
    let allowlists = current_allowlists(&state).await;
    let (unshared, offers) = current_offer_state(&state, &shared_folders).await;
    let (location, current_stored, data_dir) = {
        let mut guard = lock_session()?;
        let session = require_session(&mut guard, session_id)?;
        let stored = session
            .entries
            .get(&entry_id)
            .cloned()
            .ok_or_else(|| {
                coded(
                    "sharing_browser_entry",
                    "That folder is no longer in the browser session.",
                )
            })?;
        if stored.kind == ShareBrowserKind::File {
            return Err(coded(
                "sharing_browser_entry",
                "That folder is no longer in the browser session.",
            ));
        }
        (stored.location.clone(), stored, session.data_dir.clone())
    };

    let (pending, truncated) = tokio::task::spawn_blocking(move || match location {
        Location::ThisPc => Ok((this_pc_children(), false)),
        Location::Path(path) => list_child_dirs(&path, &data_dir),
    })
    .await
    .map_err(|error| {
        coded_ctx(
            "sharing_browser_task_failed",
            "Folder browser failed",
            error,
        )
    })??;

    let mut guard = lock_session()?;
    let session = require_session(&mut guard, session_id)?;
    session.shared_folders = shared_folders;
    session.allowlists = allowlists;
    session.unshared = unshared;
    session.offers = offers;
    let children = register_children(session, entry_id, pending)?;
    let current = entry_from_stored(entry_id, &current_stored, session);
    Ok(ShareBrowserView {
        session_id,
        current,
        children,
        truncated,
    })
}

/// Jump the browser to a typed path. The path is listed (so it receives an
/// entry id) rather than shared; sharing still goes through selection ids.
#[tauri::command]
pub async fn navigate_share_browser(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, AppState>,
    session_id: u64,
    path: String,
) -> Result<ShareBrowserView, String> {
    require_main_window(&window)?;
    if path.len() > MAX_PATH_LEN {
        return Err(coded_ctx(
            "sharing_folder_path_too_long",
            format!("Folder path exceeds {MAX_PATH_LEN} bytes"),
            MAX_PATH_LEN,
        ));
    }
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return list_share_browser_children(window, state, session_id, {
            let mut guard = lock_session()?;
            let session = require_session(&mut guard, session_id)?;
            session
                .entries
                .iter()
                .find_map(|(id, stored)| {
                    matches!(stored.location, Location::ThisPc).then_some(*id)
                })
                .ok_or_else(|| {
                    coded(
                        "sharing_browser_entry",
                        "That folder is no longer in the browser session.",
                    )
                })?
        })
        .await;
    }

    let requested = PathBuf::from(trimmed);
    let resolved = tokio::task::spawn_blocking(move || existing_dir(&requested))
        .await
        .map_err(|error| {
            coded_ctx(
                "sharing_browser_task_failed",
                "Folder browser failed",
                error,
            )
        })??;
    let browser_data_dir = {
        let mut guard = lock_session()?;
        require_session(&mut guard, session_id)?.data_dir.clone()
    };
    if path_has_sensitive_component(&resolved) || inside_data_dir(&resolved, &browser_data_dir) {
        return Err(coded(
            "sharing_browser_blocked",
            "Cannot share this location",
        ));
    }

    let (pending_list, truncated) = {
        let target = resolved.clone();
        let data_dir = browser_data_dir.clone();
        tokio::task::spawn_blocking(move || list_child_dirs(&target, &data_dir))
            .await
            .map_err(|error| {
                coded_ctx(
                    "sharing_browser_task_failed",
                    "Folder browser failed",
                    error,
                )
            })??
    };
    let shared_folders = current_shared_folders(&state).await;
    let allowlists = current_allowlists(&state).await;
    let (unshared, offers) = current_offer_state(&state, &shared_folders).await;

    let mut guard = lock_session()?;
    let session = require_session(&mut guard, session_id)?;
    session.shared_folders = shared_folders;
    session.allowlists = allowlists;
    session.unshared = unshared;
    session.offers = offers;
    let existing_id = session.entries.iter().find_map(|(id, stored)| match &stored.location {
        Location::Path(path) if same_folder(&display_fs_path(path), &display_fs_path(&resolved)) => {
            Some(*id)
        }
        _ => None,
    });
    let current_id = if let Some(id) = existing_id {
        id
    } else {
        let parent_id = resolved.parent().and_then(|parent| {
            session.entries.iter().find_map(|(id, stored)| match &stored.location {
                Location::Path(path)
                    if same_folder(&display_fs_path(path), &display_fs_path(parent)) =>
                {
                    Some(*id)
                }
                _ => None,
            })
        });
        session.insert(StoredEntry {
            location: Location::Path(resolved.clone()),
            kind: if is_filesystem_root(&resolved) {
                ShareBrowserKind::Drive
            } else {
                ShareBrowserKind::Folder
            },
            letter: None,
            name: folder_name(&resolved),
            parent_id,
            size: None,
        })?
    };
    let current_stored = session
        .entries
        .get(&current_id)
        .expect("current")
        .clone();
    let children = register_children(session, current_id, pending_list)?;
    let current = entry_from_stored(current_id, &current_stored, session);
    Ok(ShareBrowserView {
        session_id,
        current,
        children,
        truncated,
    })
}

struct ChosenShare {
    path: String,
    is_file: bool,
    /// A folder that is already shared but is not offering everything in it.
    /// Sharing it again is how the user offers the rest.
    was_partial: bool,
}

/// Selected entries that share through one folder's allowlist.
#[derive(Debug, Default, PartialEq)]
struct FileGroup {
    folder: String,
    files: Vec<String>,
    /// Selected folders inside `folder`, offered whole through its allowlist.
    dirs: Vec<String>,
}

/// Folders to share in full, and files grouped under the folder that will hold
/// their allowlist. A file inside a folder that is itself selected is covered
/// by that folder. A file already inside a shared folder joins that share's
/// allowlist instead of adding its immediate parent, which would overlap.
/// Files at several depths of one new folder collapse onto the shallowest
/// parent so the second add is not rejected as an overlap.
///
/// A selected folder inside a group's folder joins that group's allowlist
/// whole, for the same reason: added on its own after the group it is an
/// overlap, and the group's allowlist would then have left every file in it
/// unshared. A selected folder inside another selected folder is covered by
/// it.
fn selection_plan(chosen: &[ChosenShare], shared: &[PathBuf]) -> (Vec<String>, Vec<FileGroup>) {
    let mut folders: Vec<String> = Vec::new();
    for item in chosen.iter().filter(|item| !item.is_file) {
        let covered = chosen.iter().any(|other| {
            !other.is_file
                && !same_folder(&other.path, &item.path)
                && path_within(&item.path, &other.path)
        });
        if !covered {
            remember_once(&mut folders, item.path.clone());
        }
    }
    let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
    for item in chosen.iter().filter(|item| item.is_file) {
        if folders.iter().any(|folder| path_within(&item.path, folder)) {
            continue;
        }
        let path = Path::new(&item.path);
        let key = if let Some(folder) = containing_share(path, shared) {
            display_fs_path(folder)
        } else {
            let Some(parent) = path.parent() else {
                continue;
            };
            if root_share_refused(parent) {
                continue;
            }
            display_fs_path(parent)
        };
        grouped.entry(key).or_default().push(item.path.clone());
    }
    collapse_nested_file_groups(&mut grouped);
    let mut groups: Vec<FileGroup> = grouped
        .into_iter()
        .map(|(folder, files)| FileGroup {
            folder,
            files,
            dirs: Vec::new(),
        })
        .collect();
    groups.sort_by(|a, b| a.folder.cmp(&b.folder));
    folders.retain(|folder| {
        let Some(group) = groups
            .iter_mut()
            .filter(|group| {
                !same_folder(&group.folder, folder) && path_within(folder, &group.folder)
            })
            .max_by_key(|group| group.folder.len())
        else {
            return true;
        };
        group.dirs.push(folder.clone());
        false
    });
    (folders, groups)
}

/// Move files from a deeper parent into a shallower parent that is also being
/// added, deepest first, so `Album` absorbs `Album\Live` before `Music`
/// absorbs `Album`.
fn collapse_nested_file_groups(grouped: &mut HashMap<String, Vec<String>>) {
    let mut keys: Vec<String> = grouped.keys().cloned().collect();
    keys.sort_by_key(|key| std::cmp::Reverse(key.len()));
    for key in keys {
        let parent = grouped
            .keys()
            .filter(|other| *other != &key && path_within(&key, other))
            .max_by_key(|other| other.len())
            .cloned();
        let Some(parent) = parent else {
            continue;
        };
        let Some(files) = grouped.remove(&key) else {
            continue;
        };
        grouped.entry(parent).or_default().extend(files);
    }
}

fn remember_once(list: &mut Vec<String>, path: String) {
    if !list.iter().any(|existing| same_folder(existing, &path)) {
        list.push(path);
    }
}

/// See [`crate::security::path_within_dir`]: planning a selected drive and
/// something on it as two separate shares is what the drive-aware form stops.
fn path_within(path: &str, dir: &str) -> bool {
    crate::security::path_within_dir(path, dir)
}

/// `root` is already shared, or overlaps a share, so adding it either changes
/// nothing or is refused as an overlap.
pub(crate) fn overlaps_share(root: &str, shared: &[PathBuf]) -> bool {
    shared.iter().any(|existing| {
        let existing = display_fs_path(existing);
        same_folder(root, &existing) || shared_paths_overlap(Path::new(root), Path::new(&existing))
    })
}

fn allowlist_for<'a>(
    folder: &str,
    allowlists: &'a HashMap<String, Vec<String>>,
) -> Option<&'a Vec<String>> {
    allowlists
        .iter()
        .find_map(|(key, list)| same_folder(key, folder).then_some(list))
}

/// Roots one native confirmation may carry. Every one is listed: the dialog is
/// the only place the user sees what they are approving, so a selection that
/// needs more is refused rather than summarised as "and N more".
pub(crate) const MAX_CONFIRM_ROOTS: usize = 16;

pub(crate) fn too_many_to_confirm() -> String {
    coded_ctx(
        "sharing_share_too_many_to_confirm",
        format!("Too many folders to confirm at once (max {MAX_CONFIRM_ROOTS})"),
        MAX_CONFIRM_ROOTS,
    )
}

/// Set while a share confirmation is on screen. A selection arriving meanwhile
/// is refused rather than queued behind it: a renderer that could stack
/// prompts could keep asking until one is accepted by accident.
static CONFIRMING: AtomicBool = AtomicBool::new(false);

/// How much more of a folder a confirmation lets onto the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShareScope {
    /// Not shared yet; shared whole.
    Whole,
    /// Shared for part of its contents; now shared whole.
    Widened,
    /// Not shared yet; shared for only this many selected entries.
    Only(usize),
    /// Shared for part of its contents; this many more selected entries join.
    More(usize),
}

/// A folder a confirmation names.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct NewShareRoot {
    pub(crate) path: String,
    pub(crate) scope: ShareScope,
    pub(crate) whole_drive: bool,
}

impl NewShareRoot {
    pub(crate) fn new(path: &str, scope: ShareScope) -> Self {
        Self {
            path: path.to_string(),
            scope,
            whole_drive: is_filesystem_root(Path::new(path)),
        }
    }

    /// Every file on the drive, not a chosen few, would be offered.
    fn offers_whole_drive(&self) -> bool {
        self.whole_drive && matches!(self.scope, ShareScope::Whole | ShareScope::Widened)
    }
}

/// What prompted a confirmation, which decides how its last line reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShareOrigin {
    Browser,
    Drop,
}

/// The roots of a [`selection_plan`] the user has to confirm, drives first:
/// ones not shared yet, and partly shared ones the selection would widen,
/// whether to the whole folder or to more of its entries. A partial share was
/// only ever approved for what it lists, and the whole-drive warning was never
/// shown for one limited to a few files.
///
/// Folders already shared whole are left out; so are ones overlapping a share,
/// which the add refuses, since asking about a folder that cannot be added
/// would only teach the user to click through.
fn new_share_roots(
    folders: &[String],
    groups: &[FileGroup],
    shared: &[PathBuf],
    allowlists: &HashMap<String, Vec<String>>,
) -> Vec<NewShareRoot> {
    let is_share = |root: &str| {
        shared
            .iter()
            .any(|existing| same_folder(root, &display_fs_path(existing)))
    };
    let mut roots = Vec::new();
    for folder in folders {
        let scope = if is_share(folder) {
            if allowlist_for(folder, allowlists).is_none() {
                continue;
            }
            ShareScope::Widened
        } else if overlaps_share(folder, shared) {
            continue;
        } else {
            ShareScope::Whole
        };
        roots.push(NewShareRoot::new(folder, scope));
    }
    for group in groups {
        let entries = group.files.iter().chain(&group.dirs);
        let scope = if is_share(&group.folder) {
            let Some(list) = allowlist_for(&group.folder, allowlists) else {
                continue;
            };
            let more = entries
                .filter(|entry| {
                    let key = normalize_path_key(entry);
                    !list.iter().any(|item| path_key_covers(item, &key))
                })
                .count();
            if more == 0 {
                continue;
            }
            ShareScope::More(more)
        } else if overlaps_share(&group.folder, shared) {
            continue;
        } else {
            ShareScope::Only(group.files.len() + group.dirs.len())
        };
        roots.push(NewShareRoot::new(&group.folder, scope));
    }
    // Stable, so the rest keep the order the plan gave them.
    roots.sort_by_key(|root| !root.whole_drive);
    roots
}

/// Title and body of the native dialog confirming `roots`, every one listed.
pub(crate) fn share_confirmation_text(
    roots: &[NewShareRoot],
    origin: ShareOrigin,
) -> (&'static str, String) {
    let single = roots.len() == 1;
    let drive = roots.iter().any(NewShareRoot::offers_whole_drive);
    let title = if drive {
        "Share a whole drive?"
    } else if single {
        "Share this folder?"
    } else {
        "Share these folders?"
    };
    let mut body = if single {
        "Ember will offer files from this folder to other peers on the network:\n\n".to_string()
    } else {
        format!(
            "Ember will offer files from these {} folders to other peers on the network:\n\n",
            roots.len()
        )
    };
    for root in roots {
        body.push_str(&elide_for_dialog(&root.path));
        let note = match root.scope {
            ShareScope::Whole if root.whole_drive => "  (the entire drive)".to_string(),
            ShareScope::Whole => String::new(),
            ShareScope::Widened if root.whole_drive => {
                "  (the entire drive; only part of it is shared now)".to_string()
            }
            ShareScope::Widened => "  (all of it; only part of it is shared now)".to_string(),
            ShareScope::Only(1) => "  (only the selected item)".to_string(),
            ShareScope::Only(count) => format!("  (only the {count} selected items)"),
            ShareScope::More(1) => "  (partly shared; adds the selected item)".to_string(),
            ShareScope::More(count) => format!("  (partly shared; adds {count} selected items)"),
        };
        body.push_str(&note);
        body.push('\n');
    }
    if drive {
        body.push_str(
            "\nSharing an entire drive offers every file on it, in every folder. \
             Only do this for a drive that holds nothing but files you mean to share.\n",
        );
    }
    body.push_str(match (origin, single) {
        (ShareOrigin::Browser, true) => {
            "\nShare it only if you just chose it in Ember's folder browser."
        }
        (ShareOrigin::Browser, false) => {
            "\nShare them only if you just chose them in Ember's folder browser."
        }
        (ShareOrigin::Drop, true) => {
            "\nShare it only if you just dropped it, or a file in it, onto Ember."
        }
        (ShareOrigin::Drop, false) => {
            "\nShare them only if you just dropped them, or files in them, onto Ember."
        }
    });
    (title, body)
}

/// Ask, in a dialog the renderer can neither draw nor dismiss, whether to share
/// `roots`. False for a dismissed dialog, and while another is still open.
pub(crate) async fn confirm_share_roots(
    app: &tauri::AppHandle,
    roots: &[NewShareRoot],
    origin: ShareOrigin,
) -> bool {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
    struct Release;
    impl Drop for Release {
        fn drop(&mut self) {
            CONFIRMING.store(false, Ordering::Release);
        }
    }
    if CONFIRMING.swap(true, Ordering::AcqRel) {
        return false;
    }
    // Moved into the dialog thread so the flag outlives the dialog itself
    // even if this command's future is dropped while it is on screen.
    let release = Release;
    let (title, prompt) = share_confirmation_text(roots, origin);
    let app = app.clone();
    // `blocking_show` waits on the main thread to pump the dialog, so it
    // cannot run on the command's own task.
    tokio::task::spawn_blocking(move || {
        let _release = release;
        app.dialog()
            .message(prompt)
            .title(title)
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Share".to_string(),
                "Cancel".to_string(),
            ))
            .blocking_show()
    })
    .await
    .unwrap_or(false)
}

/// Share every selected browser entry. A folder is shared in full. Files are
/// shared through their parent folder's allowlist, which is how a drop shares
/// only the files that were dropped. Ids the session does not know are
/// rejected; a selection that shares nothing and has no already-shared hits
/// returns the first real add error, matching [`super::sharing::pick_shared_folder`].
///
/// Every folder the selection would newly share, or widen from a partial
/// share, is put to the user in one native dialog first; declining shares
/// nothing. Re-sharing a folder already shared whole does not ask.
#[tauri::command]
pub async fn share_browser_selection(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, AppState>,
    session_id: u64,
    entry_ids: Vec<u64>,
) -> Result<SharedFolderPick, String> {
    require_main_window(&window)?;
    if entry_ids.is_empty() {
        return Err(coded(
            "sharing_browser_selection_empty",
            "Select a folder or file to share",
        ));
    }
    if entry_ids.len() > MAX_SHARE_SELECTION {
        return Err(coded_ctx(
            "sharing_browser_selection_too_large",
            format!("Too many items selected (max {MAX_SHARE_SELECTION})"),
            MAX_SHARE_SELECTION,
        ));
    }
    let (picked, data_dir) = {
        let mut guard = lock_session()?;
        let session = require_session(&mut guard, session_id)?;
        let mut picked = Vec::with_capacity(entry_ids.len());
        for id in &entry_ids {
            let Some(stored) = session.entries.get(id) else {
                return Err(coded(
                    "sharing_browser_entry",
                    "That folder is no longer in the browser session.",
                ));
            };
            let Location::Path(path) = &stored.location else {
                return Err(coded(
                    "sharing_browser_blocked",
                    "Cannot share this location",
                ));
            };
            picked.push((path.clone(), stored.kind));
        }
        (picked, session.data_dir.clone())
    };
    // Judged in the form the shared list stores, so a folder browsed through
    // a mapped drive, a `subst` drive or a junctioned parent is recognised as
    // the share it already is rather than added a second time.
    let picked = tokio::task::spawn_blocking(move || {
        picked
            .into_iter()
            .map(|(path, kind)| (resolve_selected(&path, kind), kind))
            .collect::<Vec<_>>()
    })
    .await
    .map_err(|error| {
        coded_ctx(
            "sharing_browser_task_failed",
            "Folder browser failed",
            error,
        )
    })?;
    let shared_folders = current_shared_folders(&state).await;
    let allowlists = current_allowlists(&state).await;
    let (unshared, offers) = current_offer_state(&state, &shared_folders).await;
    let mut chosen = Vec::new();
    let mut already_noted = Vec::new();
    for (path, kind) in &picked {
        let status = if *kind == ShareBrowserKind::File {
            file_share_status(path, &shared_folders, &data_dir, &allowlists, &unshared)
        } else {
            share_status_for(
                path,
                *kind,
                &shared_folders,
                &data_dir,
                &allowlists,
                &offers,
            )
        };
        if status == ShareBrowserStatus::Blocked {
            return Err(coded(
                "sharing_browser_blocked",
                "Cannot share this location",
            ));
        }
        if matches!(status, ShareBrowserStatus::Already | ShareBrowserStatus::Inherited) {
            if let Some(folder) = containing_share(path, &shared_folders) {
                remember_once(&mut already_noted, display_fs_path(folder));
            } else {
                remember_once(&mut already_noted, display_fs_path(path));
            }
            continue;
        }
        chosen.push(ChosenShare {
            path: display_fs_path(path),
            is_file: *kind == ShareBrowserKind::File,
            was_partial: status == ShareBrowserStatus::Partial,
        });
    }

    let (folders, file_groups) = selection_plan(&chosen, &shared_folders);
    // Before anything below touches the shared list or an allowlist, so a
    // declined selection changes nothing.
    let new_roots = new_share_roots(&folders, &file_groups, &shared_folders, &allowlists);
    if new_roots.len() > MAX_CONFIRM_ROOTS {
        return Err(too_many_to_confirm());
    }
    if !new_roots.is_empty()
        && !confirm_share_roots(&app, &new_roots, ShareOrigin::Browser).await
    {
        return Err(coded(
            "sharing_share_not_confirmed",
            "Nothing was shared because it was not confirmed",
        ));
    }
    let approved: Vec<String> = new_roots.into_iter().map(|root| root.path).collect();
    let approval = ShareApproval::Confirmed(&approved);
    let mut result = SharedFolderPick {
        already_shared: already_noted,
        ..Default::default()
    };

    // Folders chosen in full drop any allowlist limiting them: the whole
    // folder is the share now.
    let promoted: Vec<String> = chosen
        .iter()
        .filter(|item| !item.is_file && item.was_partial)
        .filter(|item| {
            allowlist_for(&item.path, &allowlists).is_none()
                || approved.iter().any(|root| same_folder(root, &item.path))
        })
        .map(|item| item.path.clone())
        .collect();
    // Only ones the dialog above named as widened (or new) may lose their
    // allowlist; lifting it is what puts the rest of the folder on the network.
    let cleared: Vec<String> = folders
        .iter()
        .filter(|folder| approved.iter().any(|root| same_folder(root, folder)))
        .filter_map(|folder| allowlists.keys().find(|key| same_folder(key, folder)).cloned())
        .collect();
    if !cleared.is_empty() {
        persist_folder_allowlists(&state, &[], &cleared).await?;
    }

    for group in file_groups {
        let parent = group.folder;
        let entries: Vec<String> = group.files.iter().chain(&group.dirs).cloned().collect();
        let add = match add_shared_folder_approved(
            app.clone(),
            state.clone(),
            parent.clone(),
            Some(entries),
            approval,
        )
        .await
        {
            Ok(add) => add,
            Err(error) => {
                tracing::warn!("Selected files in {parent} were not shared: {error}");
                result.failed.push(error);
                continue;
            }
        };
        if add.outcome == FolderAddOutcome::Added {
            result.added.push(parent);
            continue;
        }
        // Already shared. The allowlist, if there is one, now names the
        // selection, which covers what the next scan finds; anything already
        // indexed and taken off the network has to be offered now.
        let mut offered: Vec<String> = Vec::new();
        let mut failed = false;
        if !add.files.is_empty() {
            match batch_share(app.clone(), state.clone(), add.files.clone()).await {
                Ok(0) => {}
                Ok(_) => offered.extend(add.files.iter().cloned()),
                Err(error) => {
                    tracing::warn!("Selected files in {parent} were not shared: {error}");
                    result.failed.push(error);
                    failed = true;
                }
            }
        }
        for dir in &add.dirs {
            match share_all_in_folder(app.clone(), state.inner(), dir).await {
                Ok(paths) => offered.extend(paths),
                Err(error) => {
                    tracing::warn!("Could not offer {dir}: {error}");
                    result.failed.push(error);
                    failed = true;
                }
            }
        }
        if offered.is_empty() && add.allowlist_grew {
            // Nothing indexed yet to flip, but the allowlist now offers them.
            offered = add.files.iter().chain(&add.dirs).cloned().collect();
        }
        if !offered.is_empty() {
            result.files_shared.extend(offered);
        } else if !failed {
            remember_once(&mut result.already_shared, parent);
        }
    }

    for path in folders {
        let promoting = promoted.iter().any(|folder| same_folder(folder, &path));
        match add_shared_folder_approved(app.clone(), state.clone(), path.clone(), None, approval)
            .await
        {
            Ok(add) if add.outcome == FolderAddOutcome::Added => result.added.push(path),
            Ok(add) if promoting => {
                match share_all_in_folder(app.clone(), state.inner(), &add.folder).await {
                    Ok(paths) if paths.is_empty() => {
                        remember_once(&mut result.already_shared, path);
                    }
                    Ok(paths) => result.files_shared.extend(paths),
                    Err(error) => {
                        tracing::warn!("Could not offer the rest of {path}: {error}");
                        result.failed.push(error);
                    }
                }
            }
            Ok(_) => remember_once(&mut result.already_shared, path),
            Err(error) => {
                tracing::warn!("Selected folder {path} was not shared: {error}");
                result.failed.push(error);
            }
        }
    }
    finish_pick(result)
}

/// A selected entry spelled the way the shared list stores it: a folder
/// canonicalized, a file as its canonicalized parent plus its name. Left as
/// browsed when it cannot be resolved; the add then refuses it. Blocking.
fn resolve_selected(path: &Path, kind: ShareBrowserKind) -> PathBuf {
    let resolved = if kind == ShareBrowserKind::File {
        path.parent()
            .and_then(|parent| parent.canonicalize().ok())
            .zip(path.file_name())
            .map(|(parent, name)| parent.join(name))
    } else {
        path.canonicalize().ok()
    };
    resolved.map_or_else(
        || path.to_path_buf(),
        |resolved| PathBuf::from(display_fs_path(&resolved)),
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct ShareBrowserMeasure {
    pub files: u64,
    pub bytes: u64,
    /// False when the count stopped early; `files` and `bytes` are then lower
    /// bounds rather than totals.
    pub complete: bool,
}

/// Count the files, and their bytes, that sharing these folders would offer,
/// ahead of the scan that sharing starts. Files among `entry_ids` are left to
/// the caller, which already has their sizes from the listing.
///
/// Starting a measurement stops the previous one: it answered a selection that
/// has since changed.
#[tauri::command]
pub async fn measure_share_browser_entries(
    window: tauri::WebviewWindow,
    session_id: u64,
    entry_ids: Vec<u64>,
) -> Result<ShareBrowserMeasure, String> {
    require_main_window(&window)?;
    if entry_ids.len() > MAX_SHARE_SELECTION {
        return Err(coded_ctx(
            "sharing_browser_selection_too_large",
            format!("Too many items selected (max {MAX_SHARE_SELECTION})"),
            MAX_SHARE_SELECTION,
        ));
    }
    let (roots, cancel) = {
        let mut guard = lock_session()?;
        let session = require_session(&mut guard, session_id)?;
        let mut roots = Vec::with_capacity(entry_ids.len());
        for id in &entry_ids {
            let stored = session.entries.get(id).ok_or_else(|| {
                coded(
                    "sharing_browser_entry",
                    "That folder is no longer in the browser session.",
                )
            })?;
            let Location::Path(path) = &stored.location else {
                continue;
            };
            if stored.kind == ShareBrowserKind::File
                || path_has_sensitive_component(path)
                || inside_data_dir(path, &session.data_dir)
            {
                continue;
            }
            roots.push(path.clone());
        }
        let cancel = Arc::new(AtomicBool::new(false));
        if let Some(previous) = session.measure_cancel.replace(cancel.clone()) {
            previous.store(true, Ordering::Relaxed);
        }
        (roots, cancel)
    };

    let measure = tokio::task::spawn_blocking(move || {
        crate::sharing::indexer::FileIndexer::measure_directories(
            &roots,
            Instant::now() + MEASURE_BUDGET,
            &cancel,
        )
    })
    .await
    .map_err(|error| {
        coded_ctx(
            "sharing_browser_task_failed",
            "Folder browser failed",
            error,
        )
    })?;
    Ok(ShareBrowserMeasure {
        files: measure.files,
        bytes: measure.bytes,
        complete: measure.complete,
    })
}

#[tauri::command]
pub async fn close_share_browser(
    window: tauri::WebviewWindow,
    session_id: u64,
) -> Result<(), String> {
    require_main_window(&window)?;
    let mut guard = lock_session()?;
    if guard.as_ref().is_some_and(|session| session.id == session_id) {
        *guard = None;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_path_strips_verbatim_prefix() {
        assert_eq!(
            display_fs_path(Path::new(r"\\?\C:\Users\a")),
            r"C:\Users\a"
        );
        assert_eq!(
            display_fs_path(Path::new(r"\\?\UNC\server\share")),
            r"\\server\share"
        );
    }

    #[test]
    fn normalize_absolute_resolves_dot_segments() {
        let path = if cfg!(windows) {
            PathBuf::from(r"C:\Users\..\Windows")
        } else {
            PathBuf::from("/home/../etc")
        };
        let normalized = normalize_absolute(&path);
        if cfg!(windows) {
            assert_eq!(normalized, PathBuf::from(r"C:\Windows"));
        } else {
            assert_eq!(normalized, PathBuf::from("/etc"));
        }
    }

    #[test]
    fn noise_and_sensitive_names_are_skipped() {
        assert!(is_noise_dir_name("$Recycle.Bin"));
        assert!(is_noise_dir_name("System Volume Information"));
        assert!(!is_noise_dir_name("Music"));
        assert!(is_sensitive_dir_name("AppData"));
        assert!(is_sensitive_dir_name("windows"));
    }

    #[test]
    fn a_file_inside_a_full_share_is_already_shared() {
        let (folder, file, data) = sample_paths();
        let status = file_share_status(
            Path::new(&file),
            &[PathBuf::from(&folder)],
            Path::new(&data),
            &HashMap::new(),
            &HashSet::new(),
        );
        assert_eq!(status, ShareBrowserStatus::Already);
    }

    #[test]
    fn a_file_taken_off_a_full_share_can_be_offered_again() {
        let (folder, file, data) = sample_paths();
        let unshared = HashSet::from([normalize_path_key(&file)]);
        let status = file_share_status(
            Path::new(&file),
            &[PathBuf::from(&folder)],
            Path::new(&data),
            &HashMap::new(),
            &unshared,
        );
        assert_eq!(status, ShareBrowserStatus::Shareable);
    }

    #[test]
    fn a_folder_with_an_allowlist_is_partial() {
        let (folder, file, data) = sample_paths();
        let allowlists = HashMap::from([(normalize_path_key(&folder), vec![normalize_path_key(&file)])]);
        let status = share_status_for(
            Path::new(&folder),
            ShareBrowserKind::Folder,
            &[PathBuf::from(&folder)],
            Path::new(&data),
            &allowlists,
            &HashMap::new(),
        );
        assert_eq!(status, ShareBrowserStatus::Partial);
    }

    #[test]
    fn a_full_share_holding_back_files_is_partial() {
        let (folder, _file, data) = sample_paths();
        // No allowlist: the folder shares everything it offers, but two of
        // its indexed files were taken off the network from the Library.
        let offers = HashMap::from([(
            normalize_path_key(&folder),
            FolderOffer {
                indexed: 5,
                offered: 3,
            },
        )]);
        let status = share_status_for(
            Path::new(&folder),
            ShareBrowserKind::Folder,
            &[PathBuf::from(&folder)],
            Path::new(&data),
            &HashMap::new(),
            &offers,
        );
        assert_eq!(status, ShareBrowserStatus::Partial);
    }

    #[test]
    fn a_full_share_offering_everything_is_already_shared() {
        let (folder, _file, data) = sample_paths();
        let offers = HashMap::from([(
            normalize_path_key(&folder),
            FolderOffer {
                indexed: 4,
                offered: 4,
            },
        )]);
        let status = share_status_for(
            Path::new(&folder),
            ShareBrowserKind::Folder,
            &[PathBuf::from(&folder)],
            Path::new(&data),
            &HashMap::new(),
            &offers,
        );
        assert_eq!(status, ShareBrowserStatus::Already);
    }

    #[test]
    fn a_file_left_off_an_allowlist_can_still_be_shared() {
        let (folder, file, data) = sample_paths();
        let other = if cfg!(windows) {
            r"C:\Music\other.mp3"
        } else {
            "/music/other.mp3"
        };
        let allowlists = HashMap::from([(
            normalize_path_key(&folder),
            vec![normalize_path_key(other)],
        )]);
        let status = file_share_status(
            Path::new(&file),
            &[PathBuf::from(&folder)],
            Path::new(&data),
            &allowlists,
            &HashSet::new(),
        );
        assert_eq!(status, ShareBrowserStatus::Shareable);
    }

    #[test]
    fn a_file_on_the_system_drive_root_cannot_be_shared() {
        let file = if cfg!(windows) { r"C:\song.mp3" } else { "/song.mp3" };
        let data = if cfg!(windows) { r"D:\Ember" } else { "/ember" };
        let status = file_share_status(
            Path::new(file),
            &[],
            Path::new(data),
            &HashMap::new(),
            &HashSet::new(),
        );
        assert_eq!(status, ShareBrowserStatus::Blocked);
    }

    #[test]
    fn a_file_in_a_new_folder_is_shareable() {
        let (_folder, file, data) = sample_paths();
        let status = file_share_status(
            Path::new(&file),
            &[],
            Path::new(&data),
            &HashMap::new(),
            &HashSet::new(),
        );
        assert_eq!(status, ShareBrowserStatus::Shareable);
    }

    #[test]
    fn selection_plan_lets_a_chosen_folder_cover_its_files() {
        let folder = if cfg!(windows) { r"C:\Music" } else { "/music" };
        let inside = if cfg!(windows) {
            r"C:\Music\a.mp3"
        } else {
            "/music/a.mp3"
        };
        let other = if cfg!(windows) {
            r"C:\Docs\b.txt"
        } else {
            "/docs/b.txt"
        };
        let chosen = vec![
            chosen_folder(folder),
            chosen_file(inside),
            chosen_file(other),
        ];
        let (folders, files) = selection_plan(&chosen, &[]);
        assert_eq!(folders, vec![folder.to_string()]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].files, vec![other.to_string()]);
    }

    #[test]
    fn a_nested_file_joins_the_share_that_already_contains_it() {
        let share = if cfg!(windows) { r"C:\Music" } else { "/music" };
        let nested = if cfg!(windows) {
            r"C:\Music\Album\new.mp3"
        } else {
            "/music/album/new.mp3"
        };
        let chosen = vec![chosen_file(nested)];
        let (_folders, files) = selection_plan(&chosen, &[PathBuf::from(share)]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].folder, share);
        assert_eq!(files[0].files, vec![nested.to_string()]);
    }

    #[test]
    fn files_at_two_depths_share_one_parent() {
        let top = if cfg!(windows) {
            r"C:\Music\a.mp3"
        } else {
            "/music/a.mp3"
        };
        let nested = if cfg!(windows) {
            r"C:\Music\Album\b.mp3"
        } else {
            "/music/album/b.mp3"
        };
        let parent = if cfg!(windows) { r"C:\Music" } else { "/music" };
        let chosen = vec![chosen_file(top), chosen_file(nested)];
        let (_folders, files) = selection_plan(&chosen, &[]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].folder, parent);
        let mut got = files[0].files.clone();
        got.sort();
        let mut expect = vec![top.to_string(), nested.to_string()];
        expect.sort();
        assert_eq!(got, expect);
    }

    #[test]
    fn a_folder_beside_a_selected_file_joins_that_files_allowlist() {
        let (file, folder, parent) = if cfg!(windows) {
            (r"C:\Music\a.mp3", r"C:\Music\Album", r"C:\Music")
        } else {
            ("/music/a.mp3", "/music/album", "/music")
        };
        let chosen = vec![chosen_file(file), chosen_folder(folder)];
        let (folders, groups) = selection_plan(&chosen, &[]);
        assert!(
            folders.is_empty(),
            "added on its own after the parent it would be refused as an overlap"
        );
        assert_eq!(
            groups,
            vec![FileGroup {
                folder: parent.to_string(),
                files: vec![file.to_string()],
                dirs: vec![folder.to_string()],
            }]
        );
    }

    #[test]
    fn a_folder_inside_another_selected_folder_is_covered_by_it() {
        let (outer, inner) = if cfg!(windows) {
            (r"C:\Music", r"C:\Music\Album")
        } else {
            ("/music", "/music/album")
        };
        let chosen = vec![chosen_folder(inner), chosen_folder(outer)];
        let (folders, groups) = selection_plan(&chosen, &[]);
        assert_eq!(folders, vec![outer.to_string()]);
        assert!(groups.is_empty());
    }

    #[test]
    fn a_folder_on_its_shares_allowlist_reads_as_shared() {
        let (share, album, other, file, data) = if cfg!(windows) {
            (
                r"C:\Music",
                r"C:\Music\Album",
                r"C:\Music\Other",
                r"C:\Music\Album\b.mp3",
                r"D:\Ember",
            )
        } else {
            (
                "/music",
                "/music/album",
                "/music/other",
                "/music/album/b.mp3",
                "/ember",
            )
        };
        let allowlists =
            HashMap::from([(normalize_path_key(share), vec![normalize_path_key(album)])]);
        let shared = [PathBuf::from(share)];
        let status = |path: &str| {
            share_status_for(
                Path::new(path),
                ShareBrowserKind::Folder,
                &shared,
                Path::new(data),
                &allowlists,
                &HashMap::new(),
            )
        };
        assert_eq!(status(album), ShareBrowserStatus::Already);
        assert_eq!(status(other), ShareBrowserStatus::Overlap);
        let file_status = file_share_status(
            Path::new(file),
            &shared,
            Path::new(data),
            &allowlists,
            &HashSet::new(),
        );
        assert_eq!(file_status, ShareBrowserStatus::Already);
    }

    #[test]
    fn a_subfolder_of_a_whole_share_reads_as_shared_with_it() {
        let (parent, share, sub, data) = if cfg!(windows) {
            (r"C:\Media", r"C:\Media\Music", r"C:\Media\Music\Album", r"D:\Ember")
        } else {
            ("/media", "/media/music", "/media/music/album", "/ember")
        };
        let shared = [PathBuf::from(share)];
        let status = |path: &str| {
            share_status_for(
                Path::new(path),
                ShareBrowserKind::Folder,
                &shared,
                Path::new(data),
                &HashMap::new(),
                &HashMap::new(),
            )
        };
        assert_eq!(status(share), ShareBrowserStatus::Already);
        assert_eq!(status(sub), ShareBrowserStatus::Inherited);
        assert_eq!(status(parent), ShareBrowserStatus::ContainsShared);
    }

    #[test]
    fn relisting_a_folder_reuses_its_ids() {
        let (folder, child) = if cfg!(windows) {
            (r"C:\Music", r"C:\Music\Album")
        } else {
            ("/music", "/music/album")
        };
        let mut session = ShareBrowserSession::new(1, Vec::new(), PathBuf::from("/ember"));
        let entry = |parent_id: Option<u64>, path: &str| StoredEntry {
            location: Location::Path(PathBuf::from(path)),
            kind: ShareBrowserKind::Folder,
            letter: None,
            name: "x".to_string(),
            parent_id,
            size: None,
        };
        let parent = session.insert(entry(None, folder)).unwrap();
        let first = session.insert(entry(Some(parent), child)).unwrap();
        for _ in 0..10 {
            assert_eq!(session.insert(entry(Some(parent), child)).unwrap(), first);
        }
        assert_eq!(session.entries.len(), 2);
        assert_ne!(
            session.insert(entry(Some(first), child)).unwrap(),
            first,
            "the same place reached through another parent keeps its own id"
        );
    }

    #[test]
    fn an_idle_session_expires_and_a_used_one_does_not() {
        let mut guard = Some(ShareBrowserSession::new(7, Vec::new(), PathBuf::from("/ember")));
        let past = Instant::now()
            .checked_sub(SESSION_TTL - Duration::from_secs(1))
            .expect("clock far enough from boot");
        guard.as_mut().unwrap().last_used = past;
        assert!(require_session(&mut guard, 7).is_ok());
        assert!(
            guard.as_ref().unwrap().last_used > past,
            "every use pushes the expiry back"
        );
        guard.as_mut().unwrap().last_used = Instant::now()
            .checked_sub(SESSION_TTL + Duration::from_secs(1))
            .expect("clock far enough from boot");
        assert!(require_session(&mut guard, 7).is_err());
        assert!(guard.is_none());
    }

    #[test]
    fn offer_state_counts_each_file_towards_its_deepest_share() {
        let (outer, inner, a, b, c, elsewhere) = if cfg!(windows) {
            (
                r"\\?\C:\Music",
                r"C:\Music\Live",
                r"C:\Music\a.mp3",
                r"C:\Music\Live\b.mp3",
                r"C:\Music\Live\c.mp3",
                r"C:\Musical\d.mp3",
            )
        } else {
            (
                "/music",
                "/music/live",
                "/music/a.mp3",
                "/music/live/b.mp3",
                "/music/live/c.mp3",
                "/musical/d.mp3",
            )
        };
        let files = [(a, true), (b, true), (c, false), (elsewhere, false)];
        let (unshared, offers) = offer_state(
            files.iter().copied(),
            &[PathBuf::from(outer), PathBuf::from(inner)],
        );
        let outer_offer = offers[&normalize_path_key(&display_fs_path(Path::new(outer)))];
        assert_eq!((outer_offer.indexed, outer_offer.offered), (1, 1));
        let inner_offer = offers[&normalize_path_key(inner)];
        assert_eq!((inner_offer.indexed, inner_offer.offered), (2, 1));
        assert_eq!(
            unshared,
            HashSet::from([normalize_path_key(c), normalize_path_key(elsewhere)])
        );
    }

    #[cfg(windows)]
    #[test]
    fn listing_skips_junctions_but_not_ordinary_folders() {
        // Not the system temp directory: it sits under `AppData`, which the
        // browser refuses to list at all.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(format!(
            "ember-share-browser-junction-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let target = dir.join("target");
        let listed = dir.join("listed");
        std::fs::create_dir_all(target.join("inner")).unwrap();
        std::fs::create_dir_all(listed.join("real")).unwrap();
        std::fs::write(listed.join("song.mp3"), b"x").unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(listed.join("link"))
            .arg(&target)
            .output()
            .expect("run mklink");
        assert!(made.status.success(), "mklink /J failed: {made:?}");

        let (children, truncated) =
            list_child_dirs(&listed, Path::new(r"Z:\no-ember-here")).unwrap();
        let names: Vec<&str> = children.iter().map(|child| child.name.as_str()).collect();
        assert!(!truncated);
        assert_eq!(names, vec!["real", "song.mp3"]);
        let _ = std::fs::remove_dir(listed.join("link"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_folders_not_yet_shared_need_confirming() {
        let (shared, inside, holder, fresh, fresh_parent, file) = if cfg!(windows) {
            (
                r"\\?\C:\Music",
                r"C:\Music\Album",
                r"C:\Media",
                r"C:\Users\a\Documents",
                r"C:\Photos",
                r"C:\Photos\a.jpg",
            )
        } else {
            (
                "/music",
                "/music/album",
                "/media",
                "/home/a/documents",
                "/photos",
                "/photos/a.jpg",
            )
        };
        // The only volume root on Unix holds every share, so it is never new.
        let drive = cfg!(windows).then_some(r"D:\");
        let shared = [PathBuf::from(shared)];
        let holder_child = Path::new(holder).join("Music");
        let shared_under_holder = [shared[0].clone(), holder_child];
        let mut folders = vec![
            display_fs_path(&shared[0]),
            inside.to_string(),
            fresh.to_string(),
        ];
        folders.extend(drive.map(str::to_string));
        let groups = vec![
            FileGroup {
                folder: display_fs_path(&shared[0]),
                files: vec![format!("{}{}x.mp3", inside, std::path::MAIN_SEPARATOR)],
                dirs: Vec::new(),
            },
            FileGroup {
                folder: fresh_parent.to_string(),
                files: vec![file.to_string()],
                dirs: vec![format!("{fresh_parent}{}Trip", std::path::MAIN_SEPARATOR)],
            },
        ];
        let roots = new_share_roots(&folders, &groups, &shared, &HashMap::new());
        let mut expected: Vec<NewShareRoot> = drive
            .map(|drive| NewShareRoot::new(drive, ShareScope::Whole))
            .into_iter()
            .collect();
        expected.push(NewShareRoot::new(fresh, ShareScope::Whole));
        expected.push(NewShareRoot::new(fresh_parent, ShareScope::Only(2)));
        assert_eq!(
            roots, expected,
            "re-shares, folders inside a share and a group joining a whole share are not asked about"
        );
        let roots = new_share_roots(&[holder.to_string()], &[], &shared_under_holder, &HashMap::new());
        assert!(roots.is_empty(), "a folder holding a share is refused, not asked about");
    }

    #[test]
    fn widening_a_partial_share_needs_confirming() {
        let (docs, listed, unlisted) = if cfg!(windows) {
            (r"C:\Docs", r"C:\Docs\a.txt", r"C:\Docs\b.txt")
        } else {
            ("/docs", "/docs/a.txt", "/docs/b.txt")
        };
        let drive = cfg!(windows).then_some((r"E:\", r"E:\x.txt"));
        let stored = |path: &str| {
            if cfg!(windows) {
                PathBuf::from(format!(r"\\?\{path}"))
            } else {
                PathBuf::from(path)
            }
        };
        let mut shared = vec![stored(docs)];
        let mut allowlists =
            HashMap::from([(normalize_path_key(docs), vec![normalize_path_key(listed)])]);
        let mut folders = vec![docs.to_string()];
        if let Some((root, file)) = drive {
            shared.push(stored(root));
            allowlists.insert(normalize_path_key(root), vec![normalize_path_key(file)]);
            folders.push(root.to_string());
        }
        let roots = new_share_roots(&folders, &[], &shared, &allowlists);
        let mut expected: Vec<NewShareRoot> = drive
            .map(|(root, _)| NewShareRoot::new(root, ShareScope::Widened))
            .into_iter()
            .collect();
        expected.push(NewShareRoot::new(docs, ShareScope::Widened));
        assert_eq!(roots, expected, "lifting an allowlist is a new approval");

        let group = |files: &[&str]| FileGroup {
            folder: docs.to_string(),
            files: files.iter().map(|file| file.to_string()).collect(),
            dirs: Vec::new(),
        };
        assert_eq!(
            new_share_roots(&[], &[group(&[listed, unlisted])], &shared, &allowlists),
            vec![NewShareRoot::new(docs, ShareScope::More(1))],
            "only the entries the allowlist lacks count"
        );
        assert!(
            new_share_roots(&[], &[group(&[listed])], &shared, &allowlists).is_empty(),
            "re-offering what the allowlist already names widens nothing"
        );
    }

    #[test]
    fn a_widened_drive_carries_the_drive_warning() {
        let drive = if cfg!(windows) { r"E:\" } else { "/" };
        let (title, body) = share_confirmation_text(
            &[NewShareRoot::new(drive, ShareScope::Widened)],
            ShareOrigin::Browser,
        );
        assert_eq!(title, "Share a whole drive?");
        assert!(
            body.contains(&format!("{drive}  (the entire drive; only part of it is shared now)\n")),
            "{body}"
        );
        assert!(body.contains("Sharing an entire drive offers every file"), "{body}");
    }

    #[test]
    fn a_single_folder_confirmation_names_its_path() {
        let path = if cfg!(windows) {
            r"C:\Users\a\Documents"
        } else {
            "/home/a/documents"
        };
        let (title, body) = share_confirmation_text(
            &[NewShareRoot::new(path, ShareScope::Whole)],
            ShareOrigin::Browser,
        );
        assert_eq!(title, "Share this folder?");
        assert!(body.contains(&format!("\n\n{path}\n")), "{body}");
        assert!(!body.contains("entire drive"), "{body}");
        assert!(body.ends_with("in Ember's folder browser."), "{body}");
    }

    #[test]
    fn every_root_a_confirmation_carries_is_listed() {
        let (drive, base) = if cfg!(windows) {
            (r"D:\", r"C:\Shares\f")
        } else {
            ("/", "/shares/f")
        };
        let mut roots = vec![NewShareRoot::new(drive, ShareScope::Whole)];
        roots.extend((1..MAX_CONFIRM_ROOTS).map(|i| {
            let scope = match i {
                1 => ShareScope::Only(3),
                2 => ShareScope::More(1),
                _ => ShareScope::Whole,
            };
            NewShareRoot::new(&format!("{base}{i:02}"), scope)
        }));
        let (title, body) = share_confirmation_text(&roots, ShareOrigin::Browser);
        assert_eq!(title, "Share a whole drive?");
        assert!(body.contains(&format!("these {MAX_CONFIRM_ROOTS} folders")), "{body}");
        assert!(body.contains(&format!("{drive}  (the entire drive)\n")), "{body}");
        assert!(body.contains(&format!("{base}01  (only the 3 selected items)\n")), "{body}");
        assert!(
            body.contains(&format!("{base}02  (partly shared; adds the selected item)\n")),
            "{body}"
        );
        for root in &roots {
            assert!(body.contains(&root.path), "{} is not named:\n{body}", root.path);
        }
        assert!(!body.contains("more folder"), "{body}");
    }

    #[test]
    fn a_limited_drive_root_is_not_described_as_shared_whole() {
        let drive = if cfg!(windows) { r"E:\" } else { "/" };
        let (title, body) = share_confirmation_text(
            &[NewShareRoot::new(drive, ShareScope::Only(1))],
            ShareOrigin::Browser,
        );
        assert_eq!(title, "Share this folder?");
        assert!(body.contains(&format!("{drive}  (only the selected item)\n")), "{body}");
        assert!(!body.contains("entire drive"), "{body}");
    }

    #[test]
    fn a_drop_confirmation_says_where_the_folders_came_from() {
        let (a, b) = if cfg!(windows) {
            (r"C:\Photos", r"C:\Scans")
        } else {
            ("/photos", "/scans")
        };
        let roots = [
            NewShareRoot::new(a, ShareScope::Whole),
            NewShareRoot::new(b, ShareScope::Whole),
        ];
        let (title, body) = share_confirmation_text(&roots, ShareOrigin::Drop);
        assert_eq!(title, "Share these folders?");
        assert!(body.ends_with("dropped them, or files in them, onto Ember."), "{body}");
    }

    #[test]
    fn containment_counts_a_drive_root_as_holding_its_contents() {
        let (drive, file, sub, music, musical) = if cfg!(windows) {
            (r"E:\", r"e:\A.txt", r"\\?\E:\Sub", r"C:\Music", r"C:\Musical\a.mp3")
        } else {
            ("/", "/a.txt", "/sub", "/music", "/musical/a.mp3")
        };
        assert!(path_within(file, drive));
        assert!(path_within(sub, drive));
        assert!(path_within(drive, drive));
        assert!(!path_within(drive, sub));
        assert!(!path_within(musical, music));
    }

    #[test]
    fn a_selected_drive_covers_what_is_selected_on_it() {
        let (drive, file, sub) = if cfg!(windows) {
            (r"E:\", r"E:\a.txt", r"E:\Sub")
        } else {
            ("/", "/a.txt", "/sub")
        };
        let chosen = vec![chosen_folder(drive), chosen_file(file), chosen_folder(sub)];
        let (folders, groups) = selection_plan(&chosen, &[]);
        assert_eq!(folders, vec![drive.to_string()]);
        assert!(groups.is_empty(), "{groups:?}");
    }

    #[test]
    fn a_folder_on_a_shared_drive_reads_as_shared_with_it() {
        let (drive, stored, sub, file, data) = if cfg!(windows) {
            (r"E:\", r"\\?\E:\", r"E:\Sub", r"E:\Sub\a.mp3", r"D:\Ember")
        } else {
            ("/", "/", "/sub", "/sub/a.mp3", "/ember")
        };
        let shared = [PathBuf::from(stored)];
        assert_eq!(
            containing_share(Path::new(file), &shared).map(display_fs_path),
            Some(drive.to_string())
        );
        let status = share_status_for(
            Path::new(sub),
            ShareBrowserKind::Folder,
            &shared,
            Path::new(data),
            &HashMap::new(),
            &HashMap::new(),
        );
        assert_eq!(status, ShareBrowserStatus::Inherited);
    }

    fn chosen_file(path: &str) -> ChosenShare {
        ChosenShare {
            path: path.to_string(),
            is_file: true,
            was_partial: false,
        }
    }

    fn chosen_folder(path: &str) -> ChosenShare {
        ChosenShare {
            path: path.to_string(),
            is_file: false,
            was_partial: false,
        }
    }

    fn sample_paths() -> (String, String, String) {
        if cfg!(windows) {
            (
                r"C:\Music".to_string(),
                r"C:\Music\a.mp3".to_string(),
                r"D:\Ember".to_string(),
            )
        } else {
            (
                "/music".to_string(),
                "/music/a.mp3".to_string(),
                "/ember".to_string(),
            )
        }
    }

    #[test]
    fn the_data_directory_is_not_browsable_but_its_parents_are() {
        let (data, inside, home) = if cfg!(windows) {
            (
                r"C:\Users\a\AppData\Roaming\ember\p2p",
                r"C:\Users\a\AppData\Roaming\ember\p2p\known.met",
                r"C:\Users\a",
            )
        } else {
            (
                "/home/a/.local/share/ember/p2p",
                "/home/a/.local/share/ember/p2p/known.met",
                "/home/a",
            )
        };
        assert!(inside_data_dir(Path::new(data), Path::new(data)));
        assert!(inside_data_dir(Path::new(inside), Path::new(data)));
        // The home folder contains the data directory. Sharing it is refused
        // elsewhere, but browsing to it must still work.
        assert!(!inside_data_dir(Path::new(home), Path::new(data)));
    }

    #[test]
    fn filesystem_roots_are_blocked() {
        if cfg!(windows) {
            assert!(is_filesystem_root(Path::new(r"C:\")));
            assert!(!is_filesystem_root(Path::new(r"C:\Users")));
        } else {
            assert!(is_filesystem_root(Path::new("/")));
            assert!(!is_filesystem_root(Path::new("/home")));
        }
    }
}
