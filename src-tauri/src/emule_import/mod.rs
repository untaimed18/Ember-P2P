//! Importing an existing eMule or aMule installation (issue 126).
//!
//! Three steps, so nothing is swapped underneath a running process. Credits,
//! the SecIdent key and `known.met` are all held in memory and written back
//! as whole snapshots, so a file changed on disk behind them would simply be
//! overwritten:
//!
//! * [`scan`] reads the eMule config folder and reports what it would bring.
//! * [`stage`] converts the chosen parts into `emule-import-pending/` in the
//!   data directory, and moves or copies in-progress downloads beside Ember's
//!   own. This is where the slow copying happens, with progress.
//! * [`apply::apply_pending`] runs at the next launch, before the stores, the
//!   approved-root registry and the network read anything, and writes a report.
//!
//! The renderer never names a path. An eMule folder is one this module found
//! or the user picked in a native dialog, referred to by id, and a selection
//! is category flags plus indices into the preview.

pub mod apply;
pub mod formats;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::network::ed2k::part_tracker::{summarize_part_met, PartMetSummary, PartTracker};

pub const PENDING_DIR: &str = "emule-import-pending";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const REPORT_FILE: &str = "emule-import-report.json";
const MANIFEST_VERSION: u32 = 1;
/// Credits unused this long are left behind, as Ember's own are
/// (`CreditManager::cleanup_stale(90)`).
const CREDIT_MAX_AGE_SECS: i64 = 90 * 24 * 3600;
/// Counting the subfolders a recursive share would add stops here.
const SUBFOLDER_COUNT_CAP: usize = 5_000;
/// Prefix a staged `.part` carries until its transfer row exists. The orphan
/// sweep only deletes files named by a bare UUID, so a staged download that
/// never got its row is left alone rather than deleted.
pub const STAGED_PART_PREFIX: &str = "emule-import-";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EmuleClient {
    Emule,
    Amule,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmuleInstall {
    pub id: u32,
    pub path: String,
    pub client: EmuleClient,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FolderStatus {
    Ready,
    /// A whole data drive. Importable, flagged so the user sees what it means.
    DriveRoot,
    /// The system or profile drive, a system folder, or Ember's own data.
    Refused,
    Missing,
    /// Inside another listed folder; Ember shares subfolders, so it comes along.
    Covered,
    AlreadyShared,
    /// Holds a folder Ember already shares. Ember's shares do not overlap, and
    /// taking this one would widen that share past any files it was limited to.
    ContainsShared,
}

#[derive(Debug, Clone, Serialize)]
pub struct SharedFolderPreview {
    pub path: String,
    pub status: FolderStatus,
    /// Subfolders Ember will share that eMule did not: eMule shares exactly the
    /// folders listed, Ember a folder and everything under it.
    pub newly_shared_subfolders: usize,
    pub subfolder_count_capped: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DownloadStatus {
    Ready,
    MissingData,
    AlreadyDownloading,
    AlreadyHave,
    /// Held open by eMule, which is still running.
    InUse,
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadPreview {
    pub name: String,
    pub size: u64,
    pub done: u64,
    pub paused: bool,
    pub status: DownloadStatus,
    /// Size of the `.part` on disk, which a copy writes in full.
    pub part_bytes: u64,
    /// Whether the `.part` shares a volume with the download folder, and with
    /// eMule's incoming folder: a move when it does, a copy when it does not.
    /// `None` when that could not be told.
    pub same_volume_as_download_folder: Option<bool>,
    pub same_volume_as_incoming: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmulePreview {
    pub token: u64,
    pub source: EmuleInstall,
    pub nickname: Option<String>,
    pub tcp_port: Option<u16>,
    pub udp_port: Option<u16>,
    pub incoming_dir: Option<String>,
    /// Bytes per second, 0 for unlimited.
    pub max_upload: Option<u64>,
    pub max_download: Option<u64>,
    /// eMule's user hash and a SecIdent key it can use were both found.
    pub identity: bool,
    pub credits: usize,
    pub expired_credits: usize,
    pub known_files: usize,
    pub known2_sets: usize,
    pub known2_bytes: u64,
    pub shared_folders: Vec<SharedFolderPreview>,
    pub downloads: Vec<DownloadPreview>,
    pub servers: usize,
    pub nodes: usize,
    pub ipfilter: bool,
    /// Free space where copied downloads and the staged hash sets would go.
    pub free_download_folder: Option<u64>,
    pub free_incoming: Option<u64>,
    pub free_data_dir: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EmuleImportSelection {
    pub token: u64,
    #[serde(default)]
    pub preferences: bool,
    #[serde(default)]
    pub incoming_as_download_folder: bool,
    #[serde(default)]
    pub library: bool,
    #[serde(default)]
    pub shared_folders: Vec<usize>,
    #[serde(default)]
    pub identity: bool,
    #[serde(default)]
    pub credits: bool,
    #[serde(default)]
    pub downloads: Vec<usize>,
    #[serde(default)]
    pub servers: bool,
    #[serde(default)]
    pub nodes: bool,
    #[serde(default)]
    pub ipfilter: bool,
}

/// Settings an import changes, applied at the next launch.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SettingsChanges {
    pub nickname: Option<String>,
    pub tcp_port: Option<u16>,
    pub udp_port: Option<u16>,
    pub max_upload_speed: Option<u64>,
    pub max_download_speed: Option<u64>,
    pub max_sources_per_file: Option<u32>,
    pub obfuscation_enabled: Option<bool>,
    pub download_folder: Option<String>,
    pub ip_filter_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StagedDownload {
    pub id: String,
    pub file_hash: String,
    pub file_name: String,
    pub file_size: u64,
    pub completed: u64,
    pub paused: bool,
    /// `<download folder>/Temp`, where the staged files wait under
    /// [`STAGED_PART_PREFIX`].
    pub temp_dir: String,
    /// eMule's `.part` and `.part.met`. A staged file whose source is still
    /// there is a copy of it; one whose source is gone was moved from it and
    /// goes back there if the import is undone. Deciding by what exists, not
    /// by what was recorded, is what makes an interrupted stage undoable.
    pub source_part: String,
    pub source_met: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub staged_at: i64,
    pub source_dir: String,
    pub settings: SettingsChanges,
    pub shared_folders: Vec<String>,
    /// Hex. The matching `cryptkey.dat` is staged beside the manifest.
    pub user_hash: Option<String>,
    pub cryptkey: bool,
    pub credits: bool,
    pub known_met: bool,
    pub known2: bool,
    pub server_met: bool,
    pub nodes_dat: bool,
    pub ipfilter_dat: bool,
    pub downloads: Vec<StagedDownload>,
    /// Set once staging finished. The manifest is written before each
    /// download moves, so one without this was left by a stage that did not
    /// finish, and is undone rather than applied.
    #[serde(default)]
    pub complete: bool,
}

/// What `stage` put in place, for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct StageSummary {
    pub shared_folders: usize,
    pub downloads: usize,
    pub copied_downloads: usize,
    pub identity: bool,
    pub credits: usize,
    pub known_files: usize,
    pub known2_sets: usize,
    pub restart_required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StageProgress {
    pub phase: &'static str,
    pub done: u64,
    pub total: u64,
}

/// eMule folders found or picked this session, by id.
fn sources() -> &'static std::sync::Mutex<Vec<(PathBuf, EmuleClient)>> {
    static SOURCES: std::sync::OnceLock<std::sync::Mutex<Vec<(PathBuf, EmuleClient)>>> =
        std::sync::OnceLock::new();
    SOURCES.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// The last scan, which a stage call must name by token.
fn last_scan() -> &'static std::sync::Mutex<Option<Scan>> {
    static LAST: std::sync::OnceLock<std::sync::Mutex<Option<Scan>>> = std::sync::OnceLock::new();
    LAST.get_or_init(|| std::sync::Mutex::new(None))
}

/// The eMule config folder `dir` names, if any: the folder itself, or an eMule
/// install folder holding a `config` subfolder.
pub fn config_dir_of(dir: &Path) -> Option<(PathBuf, EmuleClient)> {
    for candidate in [dir.to_path_buf(), dir.join("config")] {
        if candidate.join("amule.conf").is_file() {
            return Some((candidate, EmuleClient::Amule));
        }
        if candidate.join("preferences.ini").is_file()
            || (candidate.join("known.met").is_file() && candidate.join("clients.met").is_file())
        {
            return Some((candidate, EmuleClient::Emule));
        }
    }
    None
}

/// Record a folder the user picked (or detection found) and give it an id.
pub fn register_source(dir: &Path) -> Option<EmuleInstall> {
    let (config_dir, client) = config_dir_of(dir)?;
    let config_dir = config_dir.canonicalize().unwrap_or(config_dir);
    let mut sources = sources().lock().unwrap_or_else(|e| e.into_inner());
    let id = match sources.iter().position(|(p, _)| *p == config_dir) {
        Some(index) => index,
        None => {
            sources.push((config_dir.clone(), client));
            sources.len() - 1
        }
    };
    Some(EmuleInstall {
        id: id as u32,
        path: crate::commands::share_browser::display_fs_path(&config_dir),
        client,
    })
}

fn source_by_id(id: u32) -> Option<(PathBuf, EmuleClient)> {
    sources()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id as usize)
        .cloned()
}

/// Where eMule and aMule keep their config by default.
fn default_locations() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let env = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    if cfg!(windows) {
        for var in ["LOCALAPPDATA", "APPDATA"] {
            if let Some(base) = env(var) {
                out.push(base.join("eMule").join("config"));
            }
        }
        if let Some(base) = env("APPDATA") {
            out.push(base.join("aMule"));
        }
        for var in ["ProgramFiles(x86)", "ProgramFiles"] {
            if let Some(base) = env(var) {
                out.push(base.join("eMule").join("config"));
            }
        }
    }
    if let Some(home) = env("HOME").or_else(|| env("USERPROFILE")) {
        out.push(home.join(".aMule"));
        out.push(home.join("Library").join("Application Support").join("aMule"));
    }
    out
}

pub fn detect() -> Vec<EmuleInstall> {
    default_locations()
        .iter()
        .filter(|dir| dir.is_dir())
        .filter_map(|dir| register_source(dir))
        .collect()
}

/// What Ember already has, so the preview can say what an import would add.
#[derive(Debug, Default)]
pub struct ScanContext {
    pub data_dir: PathBuf,
    pub download_folder: String,
    pub shared_folders: Vec<String>,
    pub downloading: HashSet<[u8; 16]>,
    pub library: HashSet<[u8; 16]>,
}

struct ScannedDownload {
    part: PathBuf,
    met: PathBuf,
    summary: PartMetSummary,
    done: u64,
    status: DownloadStatus,
}

struct Scan {
    token: u64,
    config_dir: PathBuf,
    prefs: formats::EmulePrefs,
    user_hash: Option<[u8; 16]>,
    keypair: Option<(Vec<u8>, Vec<u8>)>,
    credits: Vec<formats::EmuleCredit>,
    known_met: Option<PathBuf>,
    known_files: usize,
    known2: Option<PathBuf>,
    known2_sets: usize,
    folders: Vec<(PathBuf, FolderStatus)>,
    downloads: Vec<ScannedDownload>,
    server_met: Option<PathBuf>,
    nodes_dat: Option<PathBuf>,
    ipfilter: Option<PathBuf>,
}

fn existing(path: PathBuf) -> Option<PathBuf> {
    path.is_file().then_some(path)
}

/// The nearest part of `path` that exists: the download folder's `Temp`, or
/// the folder itself, may not have been created yet.
fn existing_ancestor(path: &Path) -> Option<&Path> {
    path.ancestors().find(|p| !p.as_os_str().is_empty() && p.exists())
}

fn free_space(path: &Path) -> Option<u64> {
    fs2::available_space(existing_ancestor(path)?).ok()
}

/// Whether a rename between `a` and `b` can move rather than copy.
fn same_volume(a: &Path, b: &Path) -> Option<bool> {
    let (a, b) = (existing_ancestor(a)?, existing_ancestor(b)?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(std::fs::metadata(a).ok()?.dev() == std::fs::metadata(b).ok()?.dev())
    }
    #[cfg(not(unix))]
    {
        let key = |p: &Path| crate::sharing::volume_key(&p.canonicalize().ok()?);
        Some(key(a)? == key(b)?)
    }
}

/// Read the eMule folder `source_id` names and describe what an import brings.
pub fn scan(source_id: u32, ctx: &ScanContext) -> anyhow::Result<EmulePreview> {
    let (config_dir, client) =
        source_by_id(source_id).ok_or_else(|| anyhow::anyhow!("unknown eMule folder"))?;
    let install = EmuleInstall {
        id: source_id,
        path: crate::commands::share_browser::display_fs_path(&config_dir),
        client,
    };
    let base_dir = config_dir.parent().unwrap_or(&config_dir).to_path_buf();
    let prefs_file = match client {
        EmuleClient::Amule => config_dir.join("amule.conf"),
        EmuleClient::Emule => config_dir.join("preferences.ini"),
    };
    let mut prefs = std::fs::read(&prefs_file)
        .map(|bytes| formats::parse_preferences(&formats::decode_text(&bytes), &base_dir))
        .unwrap_or_default();
    // Defaults eMule and aMule fall back to when the preference is unset.
    let default_dir = |name: &str| {
        [base_dir.join(name), config_dir.join(name)]
            .into_iter()
            .find(|dir| dir.is_dir())
    };
    if prefs.temp_dirs.is_empty() {
        prefs.temp_dirs.extend(default_dir("Temp"));
    }
    if prefs.incoming_dir.as_ref().is_none_or(|dir| !dir.is_dir()) {
        prefs.incoming_dir = prefs
            .incoming_dir
            .filter(|dir| dir.is_dir())
            .or_else(|| default_dir("Incoming"));
    }

    let user_hash = std::fs::read(config_dir.join("preferences.dat"))
        .ok()
        .and_then(|dat| formats::parse_user_hash(&dat));
    let keypair = std::fs::read(config_dir.join("cryptkey.dat"))
        .ok()
        .and_then(|raw| crate::network::ed2k::credits::decode_emule_cryptkey(&raw));

    let now = chrono::Utc::now().timestamp();
    let mut credits = std::fs::read(config_dir.join("clients.met"))
        .ok()
        .and_then(|data| formats::parse_clients_met(&data).ok())
        .unwrap_or_default();
    let total_credits = credits.len();
    credits.retain(|c| now.saturating_sub(c.last_seen) < CREDIT_MAX_AGE_SECS);
    let expired_credits = total_credits - credits.len();

    let known_met = existing(config_dir.join("known.met"));
    let known_files = known_met
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|data| crate::storage::known_files::KnownFileList::from_bytes(&data).ok())
        .map_or(0, |list| list.file_count());
    let known2 = existing(config_dir.join("known2_64.met"));
    let (known2_sets, known2_bytes) = known2.as_ref().map_or((0, 0), |p| {
        let sets = crate::network::ed2k::aich::Known2Store::open(p).map_or(0, |s| s.len());
        (sets, std::fs::metadata(p).map_or(0, |m| m.len()))
    });

    let folders = classify_shared_folders(&config_dir, &prefs, ctx);
    let listed: HashSet<PathBuf> = folders.iter().map(|(p, _)| p.clone()).collect();
    let folder_previews = folders
        .iter()
        .map(|(path, status)| {
            let (newly, capped) = if matches!(status, FolderStatus::Ready | FolderStatus::DriveRoot) {
                count_unlisted_subfolders(path, &listed)
            } else {
                (0, false)
            };
            SharedFolderPreview {
                path: crate::commands::share_browser::display_fs_path(path),
                status: *status,
                newly_shared_subfolders: newly,
                subfolder_count_capped: capped,
            }
        })
        .collect();

    let downloads = scan_downloads(&prefs.temp_dirs, ctx);
    let download_folder = PathBuf::from(&ctx.download_folder);
    let download_previews = downloads
        .iter()
        .map(|d| DownloadPreview {
            name: d.summary.file_name.clone(),
            size: d.summary.file_size,
            done: d.done,
            paused: d.summary.paused,
            status: d.status,
            part_bytes: std::fs::metadata(&d.part).map_or(0, |m| m.len()),
            same_volume_as_download_folder: same_volume(&d.part, &download_folder),
            same_volume_as_incoming: prefs
                .incoming_dir
                .as_deref()
                .and_then(|incoming| same_volume(&d.part, incoming)),
        })
        .collect();

    let server_met = existing(config_dir.join("server.met"));
    let servers = server_met.as_ref().map_or(0, |p| {
        crate::network::ed2k::server_list::ServerList::load_server_met(p).map_or(0, |l| l.len())
    });
    let nodes_dat = existing(config_dir.join("nodes.dat"));
    let nodes = nodes_dat
        .as_ref()
        .map_or(0, |p| crate::network::kad::bootstrap::load_nodes_dat(p).map_or(0, |c| c.len()));
    let ipfilter = existing(config_dir.join("ipfilter.dat"))
        .filter(|p| std::fs::metadata(p).is_ok_and(|m| m.len() > 0));

    let token = rand::random::<u64>();
    let preview = EmulePreview {
        token,
        source: install,
        nickname: prefs.nickname.clone(),
        tcp_port: prefs.tcp_port,
        udp_port: prefs.udp_port,
        incoming_dir: prefs
            .incoming_dir
            .as_ref()
            .map(|p| crate::commands::share_browser::display_fs_path(p)),
        max_upload: prefs.max_upload,
        max_download: prefs.max_download,
        identity: user_hash.is_some() && keypair.is_some(),
        credits: credits.len(),
        expired_credits,
        known_files,
        known2_sets,
        known2_bytes,
        shared_folders: folder_previews,
        downloads: download_previews,
        servers,
        nodes,
        ipfilter: ipfilter.is_some(),
        free_download_folder: free_space(&download_folder),
        free_incoming: prefs.incoming_dir.as_deref().and_then(free_space),
        free_data_dir: free_space(&ctx.data_dir),
    };
    // The incoming folder came out of a folder the user picked, so the wizard
    // and Settings may offer it as the download folder like a picked one.
    if let Some(incoming) = prefs.incoming_dir.as_ref() {
        crate::commands::settings::remember_picked_download_root(incoming);
    }
    *last_scan().lock().unwrap_or_else(|e| e.into_inner()) = Some(Scan {
        token,
        config_dir,
        prefs,
        user_hash,
        keypair,
        credits,
        known_met,
        known_files,
        known2,
        known2_sets,
        folders,
        downloads,
        server_met,
        nodes_dat,
        ipfilter,
    });
    Ok(preview)
}

/// The folders eMule shared (`shareddir.dat`, plus the incoming folder, which
/// eMule shares implicitly), canonicalized and judged by the rules
/// `add_shared_folder_limited` applies.
fn classify_shared_folders(
    config_dir: &Path,
    prefs: &formats::EmulePrefs,
    ctx: &ScanContext,
) -> Vec<(PathBuf, FolderStatus)> {
    let mut listed = std::fs::read(config_dir.join("shareddir.dat"))
        .map(|bytes| formats::parse_shared_dirs(&formats::decode_text(&bytes)))
        .unwrap_or_default();
    if let Some(incoming) = prefs.incoming_dir.clone() {
        listed.push(incoming);
    }
    let data_canon = ctx.data_dir.canonicalize().unwrap_or_else(|_| ctx.data_dir.clone());
    let ember_shares: Vec<PathBuf> = ctx
        .shared_folders
        .iter()
        .map(|f| PathBuf::from(f).canonicalize().unwrap_or_else(|_| PathBuf::from(f)))
        .collect();
    let mut out: Vec<(PathBuf, FolderStatus)> = Vec::new();
    for path in listed {
        let Ok(canonical) = path.canonicalize() else {
            out.push((path, FolderStatus::Missing));
            continue;
        };
        if !canonical.is_dir() {
            out.push((canonical, FolderStatus::Missing));
            continue;
        }
        if out.iter().any(|(p, _)| *p == canonical) {
            continue;
        }
        let sensitive = canonical.components().any(|c| match c {
            std::path::Component::Normal(seg) => {
                crate::sharing::is_sensitive_dir_name(&seg.to_string_lossy())
            }
            _ => false,
        });
        let covers_data = data_canon == canonical || data_canon.starts_with(&canonical);
        let status = if sensitive || covers_data {
            FolderStatus::Refused
        } else {
            match crate::sharing::drive_root_share(&canonical) {
                crate::sharing::DriveRootShare::Refused => FolderStatus::Refused,
                _ if ember_shares.iter().any(|s| canonical.starts_with(s)) => {
                    FolderStatus::AlreadyShared
                }
                _ if ember_shares.iter().any(|s| s.starts_with(&canonical)) => {
                    FolderStatus::ContainsShared
                }
                crate::sharing::DriveRootShare::NeedsConfirmation => FolderStatus::DriveRoot,
                crate::sharing::DriveRootShare::NotARoot => FolderStatus::Ready,
            }
        };
        out.push((canonical, status));
    }
    // A folder inside another importable one is shared along with it.
    let importable: Vec<PathBuf> = out
        .iter()
        .filter(|(_, s)| matches!(s, FolderStatus::Ready | FolderStatus::DriveRoot))
        .map(|(p, _)| p.clone())
        .collect();
    for (path, status) in &mut out {
        if matches!(status, FolderStatus::Ready | FolderStatus::DriveRoot)
            && importable.iter().any(|outer| outer != path && path.starts_with(outer))
        {
            *status = FolderStatus::Covered;
        }
    }
    out
}

/// Subfolders under `root` that eMule did not list, which a recursive share
/// would now offer. Walks at most [`SUBFOLDER_COUNT_CAP`] folders.
fn count_unlisted_subfolders(root: &Path, listed: &HashSet<PathBuf>) -> (usize, bool) {
    let mut stack = vec![root.to_path_buf()];
    let (mut unlisted, mut walked) = (0usize, 0usize);
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            if crate::sharing::is_sensitive_dir_name(&entry.file_name().to_string_lossy()) {
                continue;
            }
            walked += 1;
            if walked > SUBFOLDER_COUNT_CAP {
                return (unlisted, true);
            }
            let path = entry.path();
            let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
            if !listed.contains(&canonical) {
                unlisted += 1;
            }
            stack.push(path);
        }
    }
    (unlisted, false)
}

fn scan_downloads(temp_dirs: &[PathBuf], ctx: &ScanContext) -> Vec<ScannedDownload> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for dir in temp_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = strip_suffix_ignore_case(&name, ".part.met") else {
                continue;
            };
            let part = dir.join(format!("{stem}.part"));
            // eMule keeps a `.bak` of the previous save; use it when the
            // current one does not parse, and stage whichever one did.
            let Some((met, summary)) = [entry.path(), dir.join(format!("{stem}.part.met.bak"))]
                .into_iter()
                .find_map(|met| {
                    let summary = summarize_part_met(&std::fs::read(&met).ok()?).ok()?;
                    Some((met, summary))
                })
            else {
                continue;
            };
            if !seen.insert(summary.file_hash) {
                continue;
            }
            let status = if !part.is_file() {
                DownloadStatus::MissingData
            } else if ctx.downloading.contains(&summary.file_hash) {
                DownloadStatus::AlreadyDownloading
            } else if ctx.library.contains(&summary.file_hash) {
                DownloadStatus::AlreadyHave
            } else if in_use(&part) {
                DownloadStatus::InUse
            } else {
                DownloadStatus::Ready
            };
            let done = if status == DownloadStatus::MissingData {
                0
            } else {
                PartTracker::new_with_identity(summary.file_size, &part, summary.file_hash)
                    .completed_bytes()
            };
            out.push(ScannedDownload {
                part,
                met,
                summary,
                done,
                status,
            });
        }
    }
    out.sort_by(|a, b| a.summary.file_name.cmp(&b.summary.file_name));
    out
}

/// Whether another process has `path` open. eMule holds every download's
/// `.part` open while it runs, and moving one out from under it would leave a
/// copy it keeps writing to. Unix has no such exclusion to test for.
#[cfg(windows)]
fn in_use(path: &Path) -> bool {
    use std::os::windows::fs::OpenOptionsExt;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(path)
        .is_err_and(|e| e.raw_os_error() == Some(ERROR_SHARING_VIOLATION))
}

#[cfg(not(windows))]
fn in_use(_path: &Path) -> bool {
    false
}

fn strip_suffix_ignore_case<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let cut = name.len().checked_sub(suffix.len())?;
    (name.is_char_boundary(cut) && name[cut..].eq_ignore_ascii_case(suffix)).then(|| &name[..cut])
}

fn pending_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(PENDING_DIR)
}

pub fn read_manifest(data_dir: &Path) -> Option<Manifest> {
    let bytes = std::fs::read(pending_dir(data_dir).join(MANIFEST_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub(crate) fn staged_part(download: &StagedDownload) -> PathBuf {
    Path::new(&download.temp_dir).join(format!("{STAGED_PART_PREFIX}{}.part", download.id))
}

pub(crate) fn staged_met(download: &StagedDownload) -> PathBuf {
    Path::new(&download.temp_dir).join(format!("{STAGED_PART_PREFIX}{}.part.met", download.id))
}

/// Hand a staged download back: to eMule's folder when it was moved from
/// there, or deleted when it is a copy and eMule kept its own.
fn return_download(download: &StagedDownload) -> std::io::Result<()> {
    let pairs = [
        (staged_part(download), PathBuf::from(&download.source_part)),
        (staged_met(download), PathBuf::from(&download.source_met)),
    ];
    for (staged, source) in pairs {
        let _ = std::fs::remove_file(copying_path(&staged));
        if !staged.exists() {
            continue;
        }
        if !source.exists() {
            move_or_copy(&staged, &source, &mut |_| {})?;
        }
        let _ = std::fs::remove_file(&staged);
    }
    Ok(())
}

/// Where [`move_or_copy`] writes a copy until it is complete.
fn copying_path(to: &Path) -> PathBuf {
    let mut name = to.file_name().unwrap_or_default().to_os_string();
    name.push(".copying");
    to.with_file_name(name)
}

/// Move a file, or copy it when it is on another volume. Returns whether it
/// moved. A copy lands under its real name only once complete, so a file at
/// `to` is never a partial one.
fn move_or_copy(from: &Path, to: &Path, progress: &mut dyn FnMut(u64)) -> std::io::Result<bool> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(true);
    }
    let tmp = copying_path(to);
    let copied = (|| {
        let mut reader = std::fs::File::open(from)?;
        let mut writer = std::fs::File::create(&tmp)?;
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = std::io::Read::read(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            std::io::Write::write_all(&mut writer, &buf[..n])?;
            progress(n as u64);
        }
        writer.sync_all()?;
        drop(writer);
        std::fs::rename(&tmp, to)
    })();
    if copied.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    copied.map(|()| false)
}

/// Convert the selected parts of the last scan into `emule-import-pending/`
/// and place selected downloads under `<download folder>/Temp`.
///
/// `download_folder` is the one Ember will use after the next launch: the
/// current one, or eMule's incoming folder when that is selected too.
pub fn stage(
    data_dir: &Path,
    current_download_folder: &str,
    selection: &EmuleImportSelection,
    progress: &mut dyn FnMut(StageProgress),
) -> anyhow::Result<StageSummary> {
    let scan = {
        let mut slot = last_scan().lock().unwrap_or_else(|e| e.into_inner());
        match slot.take() {
            Some(scan) if scan.token == selection.token => scan,
            other => {
                *slot = other;
                anyhow::bail!("the preview is out of date; scan the eMule folder again");
            }
        }
    };
    let result = stage_scan(data_dir, current_download_folder, selection, &scan, progress);
    // A failed stage has put back whatever it moved, so the same preview can
    // be tried again. A successful one has moved the downloads it describes.
    if result.is_err() {
        let mut slot = last_scan().lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(scan);
        }
    }
    result
}

fn stage_scan(
    data_dir: &Path,
    current_download_folder: &str,
    selection: &EmuleImportSelection,
    scan: &Scan,
    progress: &mut dyn FnMut(StageProgress),
) -> anyhow::Result<StageSummary> {
    set_aside_unreadable(data_dir);
    if read_manifest(data_dir).is_some() {
        discard(data_dir)?;
    }
    let pending = pending_dir(data_dir);
    let _ = std::fs::remove_dir_all(&pending);
    std::fs::create_dir_all(&pending)?;

    let mut manifest = Manifest {
        version: MANIFEST_VERSION,
        staged_at: chrono::Utc::now().timestamp(),
        source_dir: scan.config_dir.to_string_lossy().into_owned(),
        settings: SettingsChanges::default(),
        shared_folders: Vec::new(),
        user_hash: None,
        cryptkey: false,
        credits: false,
        known_met: false,
        known2: false,
        server_met: false,
        nodes_dat: false,
        ipfilter_dat: false,
        downloads: Vec::new(),
        complete: false,
    };
    let mut summary = StageSummary {
        shared_folders: 0,
        downloads: 0,
        copied_downloads: 0,
        identity: false,
        credits: 0,
        known_files: 0,
        known2_sets: 0,
        restart_required: true,
    };

    if selection.identity {
        if let (Some(hash), Some((public, private))) = (scan.user_hash, scan.keypair.as_ref()) {
            let bytes = crate::network::ed2k::credits::encode_keypair_file(public, private)?;
            crate::security::atomic_write(&pending.join("cryptkey.dat"), &bytes, true)?;
            manifest.user_hash = Some(hex::encode(hash));
            manifest.cryptkey = true;
            summary.identity = true;
        }
    }
    if selection.credits && !scan.credits.is_empty() {
        crate::security::atomic_write(
            &pending.join("credits.json"),
            &serde_json::to_vec(&scan.credits)?,
            true,
        )?;
        manifest.credits = true;
        summary.credits = scan.credits.len();
    }
    if selection.library {
        if let Some(known_met) = scan.known_met.as_ref() {
            std::fs::copy(known_met, pending.join("known.met"))?;
            manifest.known_met = true;
            summary.known_files = scan.known_files;
        }
        if let Some(known2) = scan.known2.as_ref() {
            // Ember's own sets go in first, so the launch that applies this
            // swaps one file for another instead of merging a possibly
            // multi-gigabyte file before any window shows. A copy taken while
            // Ember appends may end in a torn record, which `open` drops; the
            // apply picks up whatever was saved after this copy.
            let staged_path = pending.join("known2_64.met");
            let ours = data_dir.join("known2_64.met");
            crate::security::recover_interrupted_replace(&ours);
            if ours.is_file() {
                std::fs::copy(&ours, &staged_path)?;
            }
            let mut staged = crate::network::ed2k::aich::Known2Store::open(&staged_path)?;
            staged.copy_missing_from(known2, &mut |done, total| {
                progress(StageProgress {
                    phase: "known2",
                    done,
                    total,
                })
            })?;
            manifest.known2 = !staged.is_empty();
            summary.known2_sets = scan.known2_sets;
        }
    }
    for (flag, source, name, slot) in [
        (selection.servers, scan.server_met.as_ref(), "server.met", &mut manifest.server_met),
        (selection.nodes, scan.nodes_dat.as_ref(), "nodes.dat", &mut manifest.nodes_dat),
        (selection.ipfilter, scan.ipfilter.as_ref(), "ipfilter.dat", &mut manifest.ipfilter_dat),
    ] {
        if let (true, Some(source)) = (flag, source) {
            std::fs::copy(source, pending.join(name))?;
            *slot = true;
        }
    }
    if manifest.ipfilter_dat {
        manifest.settings.ip_filter_enabled = Some(true);
    }

    for &index in &selection.shared_folders {
        if let Some((path, FolderStatus::Ready | FolderStatus::DriveRoot)) = scan.folders.get(index) {
            manifest.shared_folders.push(path.to_string_lossy().into_owned());
        }
    }
    summary.shared_folders = manifest.shared_folders.len();

    if selection.preferences {
        let prefs = &scan.prefs;
        manifest.settings.nickname = prefs.nickname.clone();
        manifest.settings.tcp_port = prefs.tcp_port;
        manifest.settings.udp_port = prefs.udp_port;
        manifest.settings.max_upload_speed = prefs.max_upload;
        manifest.settings.max_download_speed = prefs.max_download;
        manifest.settings.max_sources_per_file = prefs.max_sources_per_file;
        manifest.settings.obfuscation_enabled = prefs.obfuscation;
    }
    if selection.incoming_as_download_folder {
        manifest.settings.download_folder = scan
            .prefs
            .incoming_dir
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned());
    }

    let download_folder = manifest
        .settings
        .download_folder
        .clone()
        .unwrap_or_else(|| current_download_folder.to_string());
    let chosen: Vec<&ScannedDownload> = selection
        .downloads
        .iter()
        .filter_map(|&i| scan.downloads.get(i))
        .filter(|d| d.status == DownloadStatus::Ready)
        .collect();
    if !chosen.is_empty() {
        if download_folder.is_empty() {
            anyhow::bail!("no download folder to place the downloads in");
        }
        // Checked again here, before anything moves: eMule may have been
        // started since the preview.
        if let Some(busy) = chosen.iter().find(|d| in_use(&d.part)) {
            anyhow::bail!(
                "{} is open in eMule; close eMule and try again",
                busy.summary.file_name
            );
        }
        let temp_dir = Path::new(&download_folder).join("Temp");
        std::fs::create_dir_all(&temp_dir)?;
        let total: u64 = chosen.iter().map(|d| d.summary.file_size).sum();
        let mut done = 0u64;
        for download in chosen {
            let record = StagedDownload {
                id: uuid::Uuid::new_v4().to_string(),
                file_hash: hex::encode(download.summary.file_hash),
                file_name: download.summary.file_name.clone(),
                file_size: download.summary.file_size,
                completed: download.done,
                paused: download.summary.paused,
                temp_dir: temp_dir.to_string_lossy().into_owned(),
                source_part: download.part.to_string_lossy().into_owned(),
                source_met: download.met.to_string_lossy().into_owned(),
            };
            // On disk before anything moves: if Ember dies mid-copy, the next
            // stage or launch finds this download and can hand it back.
            manifest.downloads.push(record.clone());
            let placed = write_manifest(&pending, &manifest).and_then(|()| {
                let moved = move_or_copy(&download.part, &staged_part(&record), &mut |n| {
                    done += n;
                    progress(StageProgress {
                        phase: "downloads",
                        done,
                        total,
                    })
                })?;
                let met_moved = move_or_copy(&download.met, &staged_met(&record), &mut |_| {})?;
                if moved && !met_moved {
                    // The part left eMule, so its `.part.met` goes with it.
                    let _ = std::fs::remove_file(&download.met);
                }
                Ok(moved)
            });
            match placed {
                Ok(moved) => summary.copied_downloads += usize::from(!moved),
                Err(e) => {
                    if let Err(undo) = discard(data_dir) {
                        tracing::warn!("eMule import: could not undo the staged downloads: {undo}");
                    }
                    anyhow::bail!("could not place {}: {e}", download.summary.file_name);
                }
            }
        }
    }
    summary.downloads = manifest.downloads.len();

    manifest.complete = true;
    if let Err(e) = write_manifest(&pending, &manifest) {
        if let Err(undo) = discard(data_dir) {
            tracing::warn!("eMule import: could not undo the staged downloads: {undo}");
        }
        return Err(e.into());
    }
    Ok(summary)
}

fn write_manifest(pending: &Path, manifest: &Manifest) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest).map_err(std::io::Error::other)?;
    crate::security::atomic_write(&pending.join(MANIFEST_FILE), &bytes, true)
}

/// A staging folder whose manifest does not parse, left by another build, is
/// kept under a new name rather than deleted: it may list downloads that were
/// moved out of eMule.
fn set_aside_unreadable(data_dir: &Path) {
    let pending = pending_dir(data_dir);
    if !pending.join(MANIFEST_FILE).exists() || read_manifest(data_dir).is_some() {
        return;
    }
    let aside = data_dir.join(format!(
        "{PENDING_DIR}-unreadable-{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S")
    ));
    match std::fs::rename(&pending, &aside) {
        Ok(()) => tracing::warn!(
            "eMule import: set aside a staged import this build cannot read, at {}",
            aside.display()
        ),
        Err(e) => tracing::warn!("eMule import: could not set aside {}: {e}", pending.display()),
    }
}

/// Selected shared folders that are whole drives, which the user confirms in a
/// native dialog before they are staged.
pub fn selected_drive_roots(selection: &EmuleImportSelection) -> Vec<(usize, PathBuf)> {
    let slot = last_scan().lock().unwrap_or_else(|e| e.into_inner());
    let Some(scan) = slot.as_ref().filter(|s| s.token == selection.token) else {
        return Vec::new();
    };
    selection
        .shared_folders
        .iter()
        .filter_map(|&i| match scan.folders.get(i) {
            Some((path, FolderStatus::DriveRoot)) => Some((i, path.clone())),
            _ => None,
        })
        .collect()
}

/// Undo a staged import that has not been applied: put moved downloads back,
/// delete copied ones, and remove the staging folder.
pub fn discard(data_dir: &Path) -> anyhow::Result<()> {
    if let Some(manifest) = read_manifest(data_dir) {
        for download in &manifest.downloads {
            return_download(download)?;
        }
    }
    match std::fs::remove_dir_all(pending_dir(data_dir)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}
