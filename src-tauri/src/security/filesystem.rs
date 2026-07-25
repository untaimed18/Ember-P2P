use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

const ROOT_STATE_VERSION: u32 = 1;
const ROOT_STATE_FILE: &str = "approved_roots.json";

/// File-system identity captured without following the final path component.
/// On Windows this is the volume serial + 64-bit file ID returned by
/// `GetFileInformationByHandle`, together with the reparse attribute. On other
/// platforms canonical containment remains the enforcement mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    #[serde(default)]
    pub volume_serial: u64,
    #[serde(default)]
    pub file_id: u64,
    #[serde(default)]
    pub attributes: u32,
    #[serde(default)]
    pub reparse_point: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ApprovedRoot {
    configured: String,
    canonical: String,
    configured_identity: ObjectIdentity,
    target_identity: ObjectIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRoots {
    version: u32,
    roots: Vec<ApprovedRoot>,
}

/// Registry of roots the user approved. A configured path is not sufficient:
/// every use reopens the root without following its final component and checks
/// that both the configured object and its canonical target still have the
/// identities recorded when approval was granted.
pub struct ApprovedRootRegistry {
    state_path: PathBuf,
    roots: parking_lot::RwLock<HashMap<String, ApprovedRoot>>,
}

static ROOT_REGISTRY: OnceLock<parking_lot::RwLock<Option<Arc<ApprovedRootRegistry>>>> =
    OnceLock::new();

fn global_slot() -> &'static parking_lot::RwLock<Option<Arc<ApprovedRootRegistry>>> {
    ROOT_REGISTRY.get_or_init(|| parking_lot::RwLock::new(None))
}

fn path_key(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        value.to_ascii_lowercase()
    } else {
        value
    }
}

fn random_hex() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message.into())
}

impl ApprovedRoot {
    fn capture(configured: &Path) -> io::Result<Self> {
        let canonical = configured.canonicalize()?;
        let configured_identity = object_identity(configured)?;
        let target_identity = object_identity(&canonical)?;
        Ok(Self {
            configured: configured.to_string_lossy().into_owned(),
            canonical: canonical.to_string_lossy().into_owned(),
            configured_identity,
            target_identity,
        })
    }

    fn verify(&self) -> io::Result<PathBuf> {
        let configured = PathBuf::from(&self.configured);
        let canonical = configured.canonicalize()?;
        let configured_identity = object_identity(&configured)?;
        let target_identity = object_identity(&canonical)?;
        if configured_identity != self.configured_identity
            || target_identity != self.target_identity
            || path_key(&canonical) != path_key(Path::new(&self.canonical))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "approved root changed identity since it was authorized: {}",
                    configured.display()
                ),
            ));
        }
        Ok(canonical)
    }
}

impl ApprovedRootRegistry {
    fn state_snapshot(&self) -> PersistedRoots {
        PersistedRoots {
            version: ROOT_STATE_VERSION,
            roots: self.roots.read().values().cloned().collect(),
        }
    }

    fn persist(&self) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(&self.state_snapshot())
            .map_err(|error| io_other(format!("serialize approved roots: {error}")))?;
        crate::security::atomic_write(&self.state_path, &data, true)
    }

    /// Replace the configured root set after an explicit settings action.
    /// Existing roots must retain identity; only paths in `explicit_additions`
    /// may create a new approval record.
    pub fn update_roots(
        &self,
        configured_roots: &[String],
        explicit_additions: &[String],
    ) -> io::Result<()> {
        let additions: HashSet<String> = explicit_additions
            .iter()
            .map(|root| path_key(Path::new(root)))
            .collect();
        let current = self.roots.read().clone();
        let mut next = HashMap::new();
        for configured in configured_roots.iter().filter(|root| !root.is_empty()) {
            let configured_path = Path::new(configured);
            let key = path_key(configured_path);
            if let Some(existing) = current.get(&key) {
                match existing.verify() {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // Offline removable/network roots retain their prior
                        // identity and simply fail every attempted operation
                        // until the same object returns.
                    }
                    Err(error) => return Err(error),
                }
                next.insert(key, existing.clone());
            } else if additions.contains(&key) {
                match ApprovedRoot::capture(configured_path) {
                    Ok(captured) => {
                        next.insert(key, captured);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // There is no identity to approve yet. Keep it absent
                        // and fail closed if an operation is attempted.
                    }
                    Err(error) => return Err(error),
                }
            } else if std::fs::metadata(configured_path)
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                // Still-offline root that had no capturable identity during
                // the one-time migration. It remains unusable and unapproved.
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "configured root has no approved identity record: {}",
                        configured_path.display()
                    ),
                ));
            }
        }
        *self.roots.write() = next;
        self.persist()
    }

    pub fn verify_root(&self, configured: &Path) -> io::Result<PathBuf> {
        let key = path_key(configured);
        let record = self.roots.read().get(&key).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("path is not an approved root: {}", configured.display()),
            )
        })?;
        record.verify()
    }

    pub fn verify_existing_path(
        &self,
        candidate: &Path,
        allowed_roots: &[String],
    ) -> io::Result<PathBuf> {
        let canonical = candidate.canonicalize()?;
        if !canonical.is_file() && !canonical.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target is not a regular file or directory",
            ));
        }
        for root in allowed_roots.iter().filter(|root| !root.is_empty()) {
            let root_path = Path::new(root);
            let Ok(verified_root) = self.verify_root(root_path) else {
                continue;
            };
            if canonical.starts_with(&verified_root) {
                // Reopen the canonical target without following its final
                // component. A canonical regular target must not itself be a
                // reparse point.
                let target_identity = object_identity(&canonical)?;
                if target_identity.reparse_point {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target is a reparse point",
                    ));
                }
                return Ok(canonical);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target is outside the approved roots",
        ))
    }

    /// Validate a not-yet-created output by pinning and checking its parent.
    pub fn verify_output_path(
        &self,
        candidate: &Path,
        allowed_roots: &[String],
    ) -> io::Result<PathBuf> {
        if candidate.exists() {
            return self.verify_existing_path(candidate, allowed_roots);
        }
        let parent = candidate
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no parent"))?;
        let canonical_parent = self.verify_existing_path(parent, allowed_roots)?;
        ensure_not_reparse(&canonical_parent)?;
        let name = candidate.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output has no file name")
        })?;
        Ok(canonical_parent.join(name))
    }
}

/// Initialize the process registry. The first run migrates all current roots.
/// Once state exists, an unknown configured root is not silently approved at
/// startup; it must have been added by an explicit settings action.
pub fn initialize_approved_roots(
    data_dir: &Path,
    configured_roots: &[String],
) -> io::Result<Arc<ApprovedRootRegistry>> {
    let state_path = data_dir.join(ROOT_STATE_FILE);
    let state_exists = state_path.exists();
    let roots = if state_exists {
        let data = std::fs::read(&state_path)?;
        let persisted: PersistedRoots = serde_json::from_slice(&data)
            .map_err(|error| io_other(format!("parse approved roots: {error}")))?;
        if persisted.version != ROOT_STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported approved-root state version {}",
                    persisted.version
                ),
            ));
        }
        persisted
            .roots
            .into_iter()
            .map(|root| (path_key(Path::new(&root.configured)), root))
            .collect()
    } else {
        HashMap::new()
    };
    let registry = Arc::new(ApprovedRootRegistry {
        state_path,
        roots: parking_lot::RwLock::new(roots),
    });
    let additions = if state_exists {
        Vec::new()
    } else {
        configured_roots.to_vec()
    };
    registry.update_roots(configured_roots, &additions)?;
    *global_slot().write() = Some(registry.clone());
    Ok(registry)
}

pub fn approved_roots() -> io::Result<Arc<ApprovedRootRegistry>> {
    global_slot().read().clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approved-root registry is not initialized",
        )
    })
}

pub fn verify_existing_path(candidate: &Path, allowed_roots: &[String]) -> io::Result<PathBuf> {
    approved_roots()?.verify_existing_path(candidate, allowed_roots)
}

pub fn verify_output_path(candidate: &Path, allowed_roots: &[String]) -> io::Result<PathBuf> {
    approved_roots()?.verify_output_path(candidate, allowed_roots)
}

pub fn ensure_not_reparse(path: &Path) -> io::Result<()> {
    if object_identity(path)?.reparse_point {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("reparse points are not allowed here: {}", path.display()),
        ));
    }
    Ok(())
}

/// Open a new output without following a final reparse point.
pub fn create_new_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Private, random, per-process directory beneath a pinned system temp root.
pub struct PinnedTempDir {
    path: PathBuf,
    temp_root: PathBuf,
    temp_identity: ObjectIdentity,
    own_identity: ObjectIdentity,
}

impl PinnedTempDir {
    pub fn create(kind: &str) -> io::Result<Self> {
        let temp_root = std::env::temp_dir().canonicalize()?;
        ensure_not_reparse(&temp_root)?;
        let temp_identity = object_identity(&temp_root)?;
        let base = temp_root.join("Ember");
        if !base.exists() {
            std::fs::create_dir(&base)?;
        }
        ensure_not_reparse(&base)?;
        crate::security::restrict_file_permissions_checked(&base)?;
        for _ in 0..32 {
            let path = base.join(format!(
                "{}-{}-{}",
                crate::security::sanitize_filename(kind),
                std::process::id(),
                random_hex()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    crate::security::restrict_file_permissions_checked(&path)?;
                    let own_identity = object_identity(&path)?;
                    return Ok(Self {
                        path,
                        temp_root,
                        temp_identity,
                        own_identity,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate private temp directory",
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verify(&self) -> io::Result<()> {
        if self.temp_root.canonicalize()? != self.temp_root
            || object_identity(&self.temp_root)? != self.temp_identity
            || self.path.canonicalize()? != self.path
            || object_identity(&self.path)? != self.own_identity
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "pinned temporary directory changed identity",
            ));
        }
        ensure_not_reparse(&self.temp_root)?;
        ensure_not_reparse(&self.path)
    }

    pub fn create_random_file(&self, stem: &str, extension: &str) -> io::Result<(PathBuf, File)> {
        self.verify()?;
        let stem = crate::security::sanitize_filename(stem);
        let extension = crate::security::sanitize_filename(extension);
        for _ in 0..32 {
            let name = if extension.is_empty() {
                format!("{stem}-{}", random_hex())
            } else {
                format!("{stem}-{}.{}", random_hex(), extension)
            };
            let path = self.path.join(name);
            match create_new_nofollow(&path) {
                Ok(file) => {
                    crate::security::restrict_file_permissions_checked(&path)?;
                    return Ok((path, file));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate private temporary file",
        ))
    }
}

impl Drop for PinnedTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

const PASSIVE_EXTENSIONS: &[&str] = &[
    // Plain, non-script text/data.
    "txt", "md", "csv", "json", "xml",
    // Raster images (SVG/HTML deliberately excluded).
    "bmp", "gif", "jpeg", "jpg", "png", "webp", // Media handled by passive players.
    "aac", "avi", "flac", "m4a", "m4v", "mkv", "mov", "mp3", "mp4", "mpeg", "mpg", "ogg", "opus",
    "wav", "webm", "wmv",
    // PDF is retained for ordinary document usability; active office and
    // archive/container formats remain reveal-only.
    "pdf",
];

fn normalized_open_extension(name: &str) -> Option<String> {
    let component = Path::new(name).file_name()?.to_string_lossy();
    if component.contains('\0') || component.contains(':') {
        return None;
    }
    let normalized = component.trim_end_matches([' ', '.']);
    if normalized.is_empty() {
        return None;
    }
    Path::new(normalized)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.trim_end_matches([' ', '.']).to_ascii_lowercase())
        .filter(|extension| !extension.is_empty())
}

/// Conservative one-click launch policy. The declared network name and the
/// actual canonical target must resolve to the same passive extension after
/// Windows trailing-dot/space normalization; ADS syntax is always rejected.
pub fn passive_type_agrees(declared_name: &str, actual_target: &Path) -> bool {
    let Some(declared) = normalized_open_extension(declared_name) else {
        return false;
    };
    let Some(actual_name) = actual_target.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(actual) = normalized_open_extension(actual_name) else {
        return false;
    };
    declared == actual && PASSIVE_EXTENSIONS.contains(&actual.as_str())
}

#[cfg(windows)]
pub fn reveal_in_file_manager(path: &Path) -> io::Result<()> {
    use std::os::windows::process::CommandExt;
    let value = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))?;
    if value.contains('"') || value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains unsupported characters",
        ));
    }
    let clean = value.strip_prefix(r"\\?\").unwrap_or(value);
    std::process::Command::new("explorer")
        .raw_arg(format!(r#"/select,"{clean}""#))
        .spawn()?;
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn reveal_in_file_manager(path: &Path) -> io::Result<()> {
    std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn()?;
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn reveal_in_file_manager(path: &Path) -> io::Result<()> {
    for command in ["nautilus", "dolphin", "nemo"] {
        if std::process::Command::new(command)
            .arg("--select")
            .arg(path)
            .spawn()
            .is_ok()
        {
            return Ok(());
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target has no parent directory"))?;
    std::process::Command::new("xdg-open").arg(parent).spawn()?;
    Ok(())
}

#[cfg(windows)]
pub fn object_identity(path: &Path) -> io::Result<ObjectIdentity> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let result = unsafe { GetFileInformationByHandle(handle, &mut info) };
    let close_result = unsafe { CloseHandle(handle) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    if close_result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ObjectIdentity {
        volume_serial: info.dwVolumeSerialNumber as u64,
        file_id: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        attributes: info.dwFileAttributes,
        reparse_point: (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
    })
}

#[cfg(not(windows))]
pub fn object_identity(path: &Path) -> io::Result<ObjectIdentity> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(ObjectIdentity {
        volume_serial: 0,
        file_id: 0,
        attributes: 0,
        reparse_point: metadata.file_type().is_symlink(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passive_policy_normalizes_and_rejects_ads() {
        assert!(passive_type_agrees("movie.MP4", Path::new("movie (1).mp4")));
        assert!(passive_type_agrees("photo.jpg. ", Path::new("photo.jpg")));
        assert!(!passive_type_agrees("report.pdf", Path::new("report.exe")));
        assert!(!passive_type_agrees(
            "movie.mp4",
            Path::new("movie.mp4:payload.exe")
        ));
        assert!(!passive_type_agrees("script.ps1", Path::new("script.ps1")));
        assert!(!passive_type_agrees("page.html", Path::new("page.html")));
    }

    #[test]
    fn output_parent_must_remain_inside_root() {
        let base = std::env::temp_dir().join(format!(
            "ember-root-registry-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let state_path = base.join(ROOT_STATE_FILE);
        let registry = ApprovedRootRegistry {
            state_path,
            roots: parking_lot::RwLock::new(HashMap::new()),
        };
        let root_string = root.to_string_lossy().into_owned();
        registry
            .update_roots(
                std::slice::from_ref(&root_string),
                std::slice::from_ref(&root_string),
            )
            .unwrap();
        assert!(registry
            .verify_output_path(&root.join("new.bin"), std::slice::from_ref(&root_string))
            .is_ok());
        assert!(registry
            .verify_output_path(
                &base.join("outside.bin"),
                std::slice::from_ref(&root_string)
            )
            .is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(windows)]
    #[test]
    fn junction_retarget_invalidates_approved_root() {
        use std::os::windows::process::CommandExt;
        let base = std::env::temp_dir().join(format!(
            "ember-junction-root-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let target_one = base.join("one");
        let target_two = base.join("two");
        let junction = base.join("approved");
        std::fs::create_dir_all(&target_one).unwrap();
        std::fs::create_dir_all(&target_two).unwrap();
        let create = |target: &Path| {
            std::process::Command::new("cmd")
                .args([
                    "/c",
                    "mklink",
                    "/J",
                    junction.to_str().unwrap(),
                    target.to_str().unwrap(),
                ])
                .creation_flags(0x08000000)
                .output()
                .unwrap()
        };
        assert!(create(&target_one).status.success());
        let registry = ApprovedRootRegistry {
            state_path: base.join(ROOT_STATE_FILE),
            roots: parking_lot::RwLock::new(HashMap::new()),
        };
        let configured = junction.to_string_lossy().into_owned();
        registry
            .update_roots(
                std::slice::from_ref(&configured),
                std::slice::from_ref(&configured),
            )
            .unwrap();
        assert!(registry.verify_root(&junction).is_ok());

        std::fs::remove_dir(&junction).unwrap();
        assert!(create(&target_two).status.success());
        assert!(
            registry.verify_root(&junction).is_err(),
            "retargeted junction must not retain approval"
        );
        let _ = std::fs::remove_dir(&junction);
        let _ = std::fs::remove_dir_all(base);
    }
}
