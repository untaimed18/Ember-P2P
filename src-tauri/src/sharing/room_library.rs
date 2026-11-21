//! Room libraries: folders a member keeps for one private room alone, which
//! the room's other members may browse and take files from while the member
//! has it open (`network::room_library`).
//!
//! Kept apart from sharing in both directions. A folder in a room library is
//! never shared on eD2K, KAD or Ember: no walk of a shared folder enters one
//! ([`holds`], read by `sharing::indexer`), and one cannot be added inside,
//! around or as a shared folder or a download folder ([`check_new_folder`]).
//! Its files go in no index, known.met, keyword or source record, and are
//! served to nobody but a member of the room, through a room transfer.
//!
//! The listing a member is shown is built here ([`Catalog`]) by walking the
//! folders afresh, and names each folder and file by an id that says nothing
//! about where it is: a keyed hash of its path under a key this process draws
//! once, so the same file keeps its id while Ember runs.
//!
//! Static, as `feed_downloads` is: the walk, the commands and the network
//! loop all read which folders are libraries, and none has a handle the
//! others do.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};

use crate::network::ember::room_library::{
    EntryId, EntryKind, LibraryEntry, LibraryPage, ENTRY_ID_LEN, FOLDER_MAX_BYTES, NAME_MAX_BYTES,
};

/// Folders one room's library may hold.
pub const MAX_FOLDERS_PER_ROOM: usize = 16;
/// Folders and files one room's listing holds; past it, the walk stops.
pub const MAX_ENTRIES: usize = 50_000;
/// How deep below a library folder the walk goes.
const MAX_DEPTH: usize = 32;
/// Matches one search counts, and so pages through.
const MAX_SEARCH_MATCHES: usize = 1_000;
/// How long a walk stands for the folders it walked. Browsing pages through
/// one listing; a file added to a folder shows within this long.
const CATALOG_FRESH: Duration = Duration::from_secs(60);

/// One room's library as the user set it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomLibrary {
    pub open: bool,
    /// As stored: canonical, spelled for display.
    pub folders: Vec<String>,
}

fn libraries() -> &'static RwLock<BTreeMap<String, RoomLibrary>> {
    static LIBRARIES: OnceLock<RwLock<BTreeMap<String, RoomLibrary>>> = OnceLock::new();
    LIBRARIES.get_or_init(|| RwLock::new(BTreeMap::new()))
}

/// Every room's library, from the database, before the first walk of the
/// shared folders.
pub fn load(rows: Vec<(String, RoomLibrary)>) {
    let mut held = libraries().write();
    held.clear();
    for (channel_id, library) in rows {
        held.insert(channel_id.to_ascii_lowercase(), library);
    }
    catalogs().lock().clear();
}

/// What the user set for one room, now saved.
pub fn set(channel_id: &str, library: RoomLibrary) {
    let channel_id = channel_id.to_ascii_lowercase();
    if library.folders.is_empty() && !library.open {
        libraries().write().remove(&channel_id);
    } else {
        libraries().write().insert(channel_id.clone(), library);
    }
    catalogs().lock().remove(&channel_id);
}

pub fn get(channel_id: &str) -> RoomLibrary {
    libraries()
        .read()
        .get(&channel_id.to_ascii_lowercase())
        .cloned()
        .unwrap_or_default()
}

/// Whether the library of the room is open to it.
pub fn is_open(channel_id: &[u8; 16]) -> bool {
    libraries()
        .read()
        .get(&hex::encode(channel_id))
        .is_some_and(|library| library.open)
}

/// Rooms whose libraries are open.
pub fn open_rooms() -> Vec<[u8; 16]> {
    libraries()
        .read()
        .iter()
        .filter(|(_, library)| library.open)
        .filter_map(|(id, _)| {
            let mut out = [0u8; 16];
            hex::decode_to_slice(id, &mut out).ok().map(|()| out)
        })
        .collect()
}

/// Every folder in any room's library, open or not.
pub fn all_folders() -> Vec<String> {
    libraries()
        .read()
        .values()
        .flat_map(|library| library.folders.iter().cloned())
        .collect()
}

/// Whether `path` is a folder in a room's library or lies inside one, which a
/// walk of shared folders must not enter. Spelling-blind, as the shared list
/// is matched.
pub fn holds(path: &Path) -> bool {
    let path = path.to_string_lossy();
    libraries()
        .read()
        .values()
        .flat_map(|library| library.folders.iter())
        .any(|folder| crate::security::path_within_dir(&path, folder))
}

/// Why a folder cannot go in a room's library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FolderRefusal {
    /// Not there, or not a folder.
    Missing,
    /// A whole drive, a system folder, or Ember's own data.
    System,
    /// Shared, or a download folder, or inside or around one.
    Shared,
    /// Already in this room's library, or inside or around a folder that is.
    Overlap,
    TooMany,
}

impl FolderRefusal {
    pub fn coded(self) -> String {
        use crate::commands::errors::coded;
        match self {
            FolderRefusal::Missing => coded("room_library_folder_missing", "That folder does not exist"),
            FolderRefusal::System => coded(
                "room_library_folder_system",
                "Whole drives, system folders and Ember's own folder cannot be in a room library",
            ),
            FolderRefusal::Shared => coded(
                "room_library_folder_shared",
                "That folder is shared or holds downloads, or is inside or around one that does",
            ),
            FolderRefusal::Overlap => coded(
                "room_library_folder_overlap",
                "That folder is already in this room's library, or inside or around one that is",
            ),
            FolderRefusal::TooMany => coded("room_library_too_many_folders", "A room library holds up to 16 folders"),
        }
    }
}

/// Folders a new library folder must stay apart from.
pub struct KeptApart<'a> {
    /// The shared folders and every download root.
    pub shared: &'a [String],
    /// The folders already in this room's library.
    pub room: &'a [String],
}

/// The folder at `path`, canonical and spelled for display, if it may go in a
/// room's library. Blocking: it reads the filesystem.
pub fn check_new_folder(path: &Path, apart: &KeptApart<'_>) -> Result<String, FolderRefusal> {
    check_new_folder_with(path, apart, is_system_folder)
}

/// A whole drive, a folder sharing refuses as sensitive, or one holding or
/// inside Ember's data.
fn is_system_folder(canonical: &Path) -> bool {
    if crate::sharing::drive_root_share(canonical) != crate::sharing::DriveRootShare::NotARoot
        || crate::sharing::path_has_sensitive_component(canonical)
    {
        return true;
    }
    let data_dir = crate::storage::paths::resolve_data_dir();
    let data_canon = data_dir.canonicalize().unwrap_or(data_dir);
    canonical.starts_with(&data_canon) || data_canon.starts_with(canonical)
}

fn check_new_folder_with(
    path: &Path,
    apart: &KeptApart<'_>,
    is_system: impl Fn(&Path) -> bool,
) -> Result<String, FolderRefusal> {
    if apart.room.len() >= MAX_FOLDERS_PER_ROOM {
        return Err(FolderRefusal::TooMany);
    }
    if !path.is_dir() {
        return Err(FolderRefusal::Missing);
    }
    let canonical = path.canonicalize().map_err(|_| FolderRefusal::Missing)?;
    crate::security::filesystem::ensure_not_reparse(&canonical).map_err(|_| FolderRefusal::System)?;
    if is_system(&canonical) {
        return Err(FolderRefusal::System);
    }
    let overlaps = |other: &String| {
        let other = Path::new(other);
        let other_canon = other.canonicalize().unwrap_or_else(|_| other.to_path_buf());
        crate::commands::settings::shared_paths_overlap(&canonical, &other_canon)
            || crate::commands::settings::shared_paths_overlap(&canonical, other)
    };
    if apart.shared.iter().any(overlaps) {
        return Err(FolderRefusal::Shared);
    }
    if apart.room.iter().any(overlaps) {
        return Err(FolderRefusal::Overlap);
    }
    Ok(crate::commands::share_browser::display_fs_path(&canonical))
}

/// What one walk of a room's folders found, for the owner's view of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct CatalogStats {
    pub files: u64,
    pub folders: u64,
    pub bytes: u64,
    /// Files left out for being over what a room transfer carries.
    pub too_large: u64,
    /// The walk stopped at [`MAX_ENTRIES`].
    pub truncated: bool,
    /// Library folders that could not be read.
    pub unreadable: Vec<String>,
}

#[derive(Debug, Clone)]
struct CatalogFolder {
    name: String,
    /// From the library's top, for search results: `Music/Live`.
    label: String,
    modified: i64,
    /// Folders first, then files, each by name.
    children: Vec<EntryId>,
}

/// A file in a room's listing, and where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogFile {
    pub name: String,
    pub size: u64,
    pub modified: i64,
    pub path: PathBuf,
    /// The library folder it was found under, as walked.
    pub root: PathBuf,
    folder: EntryId,
}

/// One walk of a room's library folders.
#[derive(Debug)]
pub struct Catalog {
    built_at: Instant,
    walked: Vec<String>,
    folders: HashMap<EntryId, CatalogFolder>,
    files: HashMap<EntryId, CatalogFile>,
    /// What the library's top lists: the folders, or with only one, what is
    /// in it.
    top: Vec<EntryId>,
    /// The one library folder, when there is only one: its name is not shown.
    single_root: Option<EntryId>,
    pub stats: CatalogStats,
}

/// The key entry ids are hashed under, drawn once per process.
fn id_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        key
    })
}

fn entry_id(channel_id: &str, is_dir: bool, path: &Path) -> EntryId {
    let mut hasher = blake3::Hasher::new_keyed(id_key());
    hasher.update(channel_id.as_bytes());
    hasher.update(&[u8::from(is_dir)]);
    hasher.update(path.to_string_lossy().as_bytes());
    let mut id = [0u8; ENTRY_ID_LEN];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..ENTRY_ID_LEN]);
    id
}

fn modified_secs(metadata: &std::fs::Metadata) -> i64 {
    metadata
        .modified()
        .ok()
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|age| age.as_secs() as i64)
        .unwrap_or(0)
}

/// The name a file is listed and offered under: the one a room transfer of it
/// would carry, so the asker saves what it was shown.
pub fn wire_name(name: &str) -> String {
    crate::commands::chat_attachments::clamp_file_name_keep_extension(
        &crate::security::sanitize_filename(name),
        NAME_MAX_BYTES,
    )
}

/// `label` cut from the front to what a search result carries, keeping the
/// folders nearest the file.
fn clip_label(label: &str) -> String {
    if label.len() <= FOLDER_MAX_BYTES {
        return label.to_string();
    }
    const MARK: &str = "\u{2026}/";
    let mut start = label.len() - (FOLDER_MAX_BYTES - MARK.len());
    while !label.is_char_boundary(start) {
        start += 1;
    }
    format!("{MARK}{}", &label[start..])
}

fn sort_children(children: &mut [EntryId], folders: &HashMap<EntryId, CatalogFolder>, files: &HashMap<EntryId, CatalogFile>) {
    let key = |id: &EntryId| -> (bool, String) {
        match folders.get(id) {
            Some(folder) => (false, folder.name.to_lowercase()),
            None => (true, files.get(id).map(|f| f.name.to_lowercase()).unwrap_or_default()),
        }
    };
    children.sort_by_cached_key(key);
}

impl Catalog {
    /// Walk `folders` for the room `channel_id`. Blocking.
    pub fn build(channel_id: &str, folders: &[String]) -> Self {
        let mut catalog = Catalog {
            built_at: Instant::now(),
            walked: folders.to_vec(),
            folders: HashMap::new(),
            files: HashMap::new(),
            top: Vec::new(),
            single_root: None,
            stats: CatalogStats::default(),
        };
        let mut taken_names: HashMap<String, u32> = HashMap::new();
        let mut roots = Vec::new();
        for folder in folders {
            let root = PathBuf::from(folder);
            let metadata = match std::fs::symlink_metadata(&root) {
                Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => metadata,
                _ => {
                    catalog.stats.unreadable.push(folder.clone());
                    continue;
                }
            };
            let base = root
                .file_name()
                .map(|name| wire_name(&name.to_string_lossy()))
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| "Folder".to_string());
            // Two folders of one name are told apart on the asker's screen.
            let seen = taken_names.entry(base.to_lowercase()).or_insert(0);
            *seen += 1;
            let name = if *seen == 1 { base } else { format!("{base} ({seen})") };
            let id = entry_id(channel_id, true, &root);
            catalog.folders.insert(
                id,
                CatalogFolder {
                    label: name.clone(),
                    name,
                    modified: modified_secs(&metadata),
                    children: Vec::new(),
                },
            );
            roots.push((id, root));
        }
        let single = roots.len() == 1;
        for (id, root) in &roots {
            if !catalog.walk(channel_id, *id, root, single) {
                catalog.stats.unreadable.push(root.to_string_lossy().into_owned());
            }
        }
        catalog.top = if single {
            catalog.single_root = Some(roots[0].0);
            catalog.folders.get(&roots[0].0).map(|f| f.children.clone()).unwrap_or_default()
        } else {
            roots.iter().map(|(id, _)| *id).collect()
        };
        catalog.stats.folders = catalog.folders.len().saturating_sub(roots.len()) as u64;
        catalog
    }

    fn entries(&self) -> usize {
        self.folders.len() + self.files.len()
    }

    /// Walk one library folder into the catalog. `false` when the folder
    /// itself could not be listed.
    fn walk(&mut self, channel_id: &str, root_id: EntryId, root: &Path, single: bool) -> bool {
        let mut stack: Vec<(EntryId, PathBuf, usize)> = vec![(root_id, root.to_path_buf(), 0)];
        let mut listed_root = false;
        while let Some((folder_id, dir, depth)) = stack.pop() {
            if self.stats.truncated {
                break;
            }
            let Ok(read) = std::fs::read_dir(&dir) else {
                continue;
            };
            if folder_id == root_id {
                listed_root = true;
            }
            let parent_label = self.folders.get(&folder_id).map(|f| f.label.clone()).unwrap_or_default();
            let mut children = Vec::new();
            for entry in read.flatten() {
                if self.entries() >= MAX_ENTRIES {
                    self.stats.truncated = true;
                    break;
                }
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_symlink() {
                    continue;
                }
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                if crate::sharing::indexer::walk_skips_metadata(&metadata) {
                    continue;
                }
                let path = entry.path();
                let raw_name = entry.file_name().to_string_lossy().into_owned();
                if file_type.is_dir() {
                    if depth + 1 > MAX_DEPTH
                        || crate::sharing::is_index_skip_dir_name(&raw_name)
                        || crate::sharing::is_private_receive_dir_name(&raw_name)
                    {
                        continue;
                    }
                    let name = wire_name(&raw_name);
                    if name.is_empty() {
                        continue;
                    }
                    let id = entry_id(channel_id, true, &path);
                    // With one library folder its name is not shown, so a
                    // search result's folder starts below it.
                    let label = if single && folder_id == root_id {
                        name.clone()
                    } else {
                        format!("{parent_label}/{name}")
                    };
                    self.folders.insert(
                        id,
                        CatalogFolder {
                            name,
                            label,
                            modified: modified_secs(&metadata),
                            children: Vec::new(),
                        },
                    );
                    children.push(id);
                    stack.push((id, path, depth + 1));
                } else if file_type.is_file() {
                    let size = metadata.len();
                    if size == 0 || crate::sharing::indexer::is_excluded_share_file_name(&path) {
                        continue;
                    }
                    if size > crate::network::ember::channel::XFER_MAX_BYTES {
                        self.stats.too_large += 1;
                        continue;
                    }
                    let name = wire_name(&raw_name);
                    if name.is_empty() {
                        continue;
                    }
                    let id = entry_id(channel_id, false, &path);
                    self.stats.files += 1;
                    self.stats.bytes = self.stats.bytes.saturating_add(size);
                    self.files.insert(
                        id,
                        CatalogFile {
                            name,
                            size,
                            modified: modified_secs(&metadata),
                            path,
                            root: root.to_path_buf(),
                            folder: folder_id,
                        },
                    );
                    children.push(id);
                }
            }
            sort_children(&mut children, &self.folders, &self.files);
            if let Some(folder) = self.folders.get_mut(&folder_id) {
                folder.children = children;
            }
        }
        listed_root
    }

    fn entry(&self, id: &EntryId, with_folder: bool) -> Option<LibraryEntry> {
        if let Some(folder) = self.folders.get(id) {
            return Some(LibraryEntry {
                id: *id,
                kind: EntryKind::Folder { items: folder.children.len().min(u32::MAX as usize) as u32 },
                modified: folder.modified,
                name: folder.name.clone(),
                folder: String::new(),
            });
        }
        let file = self.files.get(id)?;
        let folder = if with_folder && self.single_root != Some(file.folder) {
            self.folders
                .get(&file.folder)
                .map(|folder| clip_label(&folder.label))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Some(LibraryEntry {
            id: *id,
            kind: EntryKind::File { size: file.size },
            modified: file.modified,
            name: file.name.clone(),
            folder,
        })
    }

    /// A page of `folder`, or of the top. `None` when the folder is not in
    /// this listing.
    pub fn list(&self, folder: Option<&EntryId>, offset: u32) -> Option<LibraryPage> {
        let children = match folder {
            None => &self.top,
            Some(id) => &self.folders.get(id)?.children,
        };
        let total = children.len().min(u32::MAX as usize) as u32;
        let rest = children
            .iter()
            .skip(offset as usize)
            .filter_map(|id| self.entry(id, false));
        Some(LibraryPage::fill(total, offset, rest))
    }

    /// A page of the files whose names hold every word of `query`, by name.
    pub fn search(&self, query: &str, offset: u32) -> LibraryPage {
        let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
        if words.is_empty() {
            return LibraryPage::default();
        }
        let mut matches: Vec<(&EntryId, String)> = self
            .files
            .iter()
            .filter_map(|(id, file)| {
                let lower = file.name.to_lowercase();
                words.iter().all(|word| lower.contains(word.as_str())).then_some((id, lower))
            })
            .collect();
        matches.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)));
        matches.truncate(MAX_SEARCH_MATCHES);
        let total = matches.len() as u32;
        let rest = matches
            .into_iter()
            .skip(offset as usize)
            .filter_map(|(id, _)| self.entry(id, true));
        LibraryPage::fill(total, offset, rest)
    }

    pub fn file(&self, id: &EntryId) -> Option<&CatalogFile> {
        self.files.get(id)
    }
}

fn catalogs() -> &'static Mutex<HashMap<String, Arc<Catalog>>> {
    static CATALOGS: OnceLock<Mutex<HashMap<String, Arc<Catalog>>>> = OnceLock::new();
    CATALOGS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The room's listing, walked afresh when the last walk is stale or the
/// folders changed. Blocking. One walk runs at a time, so a member paging
/// quickly through a large library does not start a walk per page.
pub fn catalog(channel_id: &str) -> Arc<Catalog> {
    static WALKING: OnceLock<Mutex<()>> = OnceLock::new();
    let channel_id = channel_id.to_ascii_lowercase();
    let current = |folders: &[String]| {
        catalogs()
            .lock()
            .get(&channel_id)
            .filter(|c| c.walked == folders && c.built_at.elapsed() < CATALOG_FRESH)
            .cloned()
    };
    let folders = get(&channel_id).folders;
    if let Some(found) = current(&folders) {
        return found;
    }
    let _walking = WALKING.get_or_init(|| Mutex::new(())).lock();
    let folders = get(&channel_id).folders;
    if let Some(found) = current(&folders) {
        return found;
    }
    let built = Arc::new(Catalog::build(&channel_id, &folders));
    catalogs().lock().insert(channel_id, built.clone());
    built
}

/// The file `id` names in the room's library, opened to be offered, if it is
/// still the `size` it was listed at and still inside a folder of the
/// library. Blocking. Returns the canonical path.
///
/// Checked again here rather than trusted from the listing: a folder may
/// have left the library, and a folder on the way to the file may have been
/// swapped for a link since the walk. The canonical path, which resolves any
/// link, has to lie under the canonical library folder.
pub fn resolve_file(channel_id: &str, id: &EntryId, size: u64) -> Option<(PathBuf, String)> {
    let file = catalog(channel_id).file(id)?.clone();
    if file.size != size {
        return None;
    }
    let folders = get(channel_id).folders;
    let root = folders.iter().find(|folder| Path::new(folder) == file.root)?;
    let root = Path::new(root).canonicalize().ok()?;
    let canonical = file.path.canonicalize().ok()?;
    if !canonical.starts_with(&root) || canonical == root {
        return None;
    }
    crate::security::filesystem::ensure_not_reparse(&canonical).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    if !metadata.is_file() || metadata.len() != size {
        return None;
    }
    Some((canonical, file.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "00112233445566778899aabbccddeeff";

    /// A folder of its own under the temp directory, gone when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("ember-room-library-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, bytes: usize) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, vec![7u8; bytes]).unwrap();
    }

    fn names(page: &LibraryPage) -> Vec<&str> {
        page.entries.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn one_folder_is_listed_by_what_is_in_it_folders_first() {
        let dir = Scratch::new();
        let root = dir.path().join("Shelf");
        write(&root.join("b.txt"), 3);
        write(&root.join("A.txt"), 2);
        write(&root.join("Live").join("track.flac"), 5);
        write(&root.join("empty.txt"), 0);
        let folders = vec![root.to_string_lossy().into_owned()];
        let catalog = Catalog::build(ROOM, &folders);
        let top = catalog.list(None, 0).unwrap();
        assert_eq!(names(&top), vec!["Live", "A.txt", "b.txt"], "empty files are left out");
        assert_eq!(top.total, 3);
        let live = top.entries[0].id;
        assert_eq!(top.entries[0].kind, EntryKind::Folder { items: 1 });
        let inside = catalog.list(Some(&live), 0).unwrap();
        assert_eq!(names(&inside), vec!["track.flac"]);
        assert_eq!(inside.entries[0].kind, EntryKind::File { size: 5 });
        assert_eq!(catalog.stats.files, 3);
        assert_eq!(catalog.stats.folders, 1);
        assert!(catalog.list(Some(&[0xAB; ENTRY_ID_LEN]), 0).is_none(), "an id it never made");
    }

    #[test]
    fn several_folders_are_the_top_and_two_of_one_name_are_told_apart() {
        let dir = Scratch::new();
        let a = dir.path().join("one").join("Music");
        let b = dir.path().join("two").join("Music");
        write(&a.join("x.mp3"), 1);
        write(&b.join("y.mp3"), 1);
        let folders = vec![a.to_string_lossy().into_owned(), b.to_string_lossy().into_owned()];
        let catalog = Catalog::build(ROOM, &folders);
        let top = catalog.list(None, 0).unwrap();
        assert_eq!(names(&top), vec!["Music", "Music (2)"]);
        let found = catalog.search("y", 0);
        assert_eq!(names(&found), vec!["y.mp3"]);
        assert_eq!(found.entries[0].folder, "Music (2)");
    }

    #[test]
    fn ids_are_stable_for_a_path_and_say_nothing_of_it() {
        let dir = Scratch::new();
        let root = dir.path().join("Shelf");
        write(&root.join("a.txt"), 1);
        let folders = vec![root.to_string_lossy().into_owned()];
        let first = Catalog::build(ROOM, &folders).list(None, 0).unwrap();
        let again = Catalog::build(ROOM, &folders).list(None, 0).unwrap();
        assert_eq!(first.entries[0].id, again.entries[0].id);
        let other_room = Catalog::build("ffeeddccbbaa99887766554433221100", &folders)
            .list(None, 0)
            .unwrap();
        assert_ne!(first.entries[0].id, other_room.entries[0].id, "a room's ids are its own");
    }

    #[test]
    fn search_matches_every_word_and_names_the_folder_below_a_single_root() {
        let dir = Scratch::new();
        let root = dir.path().join("Shelf");
        write(&root.join("Live").join("Paris 1999.flac"), 1);
        write(&root.join("Paris notes.txt"), 1);
        write(&root.join("Rome 1999.flac"), 1);
        let folders = vec![root.to_string_lossy().into_owned()];
        let catalog = Catalog::build(ROOM, &folders);
        let found = catalog.search("paris  1999", 0);
        assert_eq!(names(&found), vec!["Paris 1999.flac"]);
        assert_eq!(found.entries[0].folder, "Live");
        let at_top = catalog.search("notes", 0);
        assert_eq!(at_top.entries[0].folder, "", "a file at the top has no folder to name");
        assert!(catalog.search("   ", 0).entries.is_empty());
    }

    #[test]
    fn pages_continue_from_their_offset() {
        let dir = Scratch::new();
        let root = dir.path().join("Shelf");
        for n in 0..300 {
            write(&root.join(format!("file {n:03} with a fairly long name to fill pages.bin")), 1);
        }
        let folders = vec![root.to_string_lossy().into_owned()];
        let catalog = Catalog::build(ROOM, &folders);
        let mut seen = Vec::new();
        let mut offset = 0;
        loop {
            let page = catalog.list(None, offset).unwrap();
            assert_eq!(page.total, 300);
            if page.entries.is_empty() {
                break;
            }
            offset += page.entries.len() as u32;
            seen.extend(page.entries.into_iter().map(|e| e.name));
        }
        assert_eq!(seen.len(), 300);
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn long_folder_labels_keep_the_end() {
        let label = format!("{}/near/the/file", "far".repeat(60));
        let clipped = clip_label(&label);
        assert!(clipped.len() <= FOLDER_MAX_BYTES);
        assert!(clipped.starts_with('\u{2026}') && clipped.ends_with("/near/the/file"));
        assert_eq!(clip_label("Music/Live"), "Music/Live");
    }

    #[test]
    fn a_new_folder_stays_apart_from_shared_folders_and_from_the_rooms_own() {
        let dir = Scratch::new();
        let shared = dir.path().join("Shared");
        let inside_shared = shared.join("Inner");
        let free = dir.path().join("Free");
        let inside_free = free.join("Deeper");
        for folder in [&inside_shared, &inside_free] {
            std::fs::create_dir_all(folder).unwrap();
        }
        let shared_list = vec![shared.to_string_lossy().into_owned()];
        let none: Vec<String> = Vec::new();
        // The temp directory is itself one sharing refuses, so the system
        // check is left out here and tested apart below.
        let check = |path: &Path, apart: &KeptApart<'_>| check_new_folder_with(path, apart, |_| false);
        let apart = KeptApart { shared: &shared_list, room: &none };
        assert_eq!(check(&inside_shared, &apart), Err(FolderRefusal::Shared));
        assert_eq!(check(dir.path(), &apart), Err(FolderRefusal::Shared), "around a shared folder");
        assert_eq!(check(&dir.path().join("nope"), &apart), Err(FolderRefusal::Missing));
        let accepted = check(&free, &apart).unwrap();
        let room = vec![accepted];
        let apart = KeptApart { shared: &shared_list, room: &room };
        assert_eq!(check(&inside_free, &apart), Err(FolderRefusal::Overlap));
        assert_eq!(check(&free, &apart), Err(FolderRefusal::Overlap));
        let full: Vec<String> = (0..MAX_FOLDERS_PER_ROOM).map(|n| format!("/x/{n}")).collect();
        let apart = KeptApart { shared: &shared_list, room: &full };
        assert_eq!(check(&free, &apart), Err(FolderRefusal::TooMany));
        let apart = KeptApart { shared: &none, room: &none };
        assert_eq!(check_new_folder_with(&free, &apart, |_| true), Err(FolderRefusal::System));
    }

    #[test]
    fn a_whole_drive_is_a_system_folder() {
        let root = if cfg!(windows) { PathBuf::from("C:\\") } else { PathBuf::from("/") };
        assert!(is_system_folder(&root));
    }

    #[test]
    fn a_file_is_resolved_only_while_its_folder_is_in_the_library_and_unchanged() {
        let dir = Scratch::new();
        let root = dir.path().join("Shelf");
        write(&root.join("a.txt"), 4);
        let channel = "0123456789abcdef0123456789abcdef";
        let folder = root.canonicalize().unwrap().to_string_lossy().into_owned();
        set(channel, RoomLibrary { open: true, folders: vec![folder] });
        let id = catalog(channel).list(None, 0).unwrap().entries[0].id;
        let (path, name) = resolve_file(channel, &id, 4).expect("listed and unchanged");
        assert_eq!(name, "a.txt");
        assert!(path.ends_with("a.txt"));
        assert!(resolve_file(channel, &id, 5).is_none(), "not the size it was listed at");
        assert!(holds(&path));
        set(channel, RoomLibrary { open: true, folders: Vec::new() });
        assert!(resolve_file(channel, &id, 4).is_none(), "its folder left the library");
        assert!(!holds(&path));
        set(channel, RoomLibrary::default());
    }
}
