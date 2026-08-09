use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

const ROOT_STATE_VERSION: u32 = 1;
const ROOT_STATE_FILE: &str = "approved_roots.json";
const ROOT_TRANSACTION_FILE: &str = "approved_roots.transaction.json";

/// File-system identity captured without following the final path component.
/// On Windows this is the volume serial + 64-bit file ID returned by
/// `GetFileInformationByHandle`, together with the reparse attribute. On Unix
/// this is `st_dev` + `st_ino` from `lstat` so replacing a root at the same
/// path cannot retain a prior approval.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct ObjectIdentity {
    #[serde(default)]
    pub volume_serial: u64,
    #[serde(default)]
    pub file_id: u64,
    /// Recorded for diagnostics and to keep an existing `approved_roots.json`
    /// round-tripping unchanged. Deliberately not part of equality; see the
    /// `PartialEq` impl below.
    #[serde(default)]
    pub attributes: u32,
    #[serde(default)]
    pub reparse_point: bool,
}

/// Only the volume serial and the file ID name an object; `dwFileAttributes` is
/// mutable metadata that a live system changes underneath us. Comparing it made
/// enabling NTFS compression, clearing "allow contents indexed", marking a
/// folder hidden or read-only, or a sync client toggling its pinned bits
/// indistinguishable from the folder having been replaced — which revoked the
/// approval durably and, for the download folder, with no way back.
///
/// The reparse flag stays in the comparison: an existing empty directory can be
/// turned into a junction in place, keeping its file ID, so it is a genuine
/// change of what the path names rather than metadata drift.
impl PartialEq for ObjectIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.volume_serial == other.volume_serial
            && self.file_id == other.file_id
            && self.reparse_point == other.reparse_point
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ApprovedRoot {
    configured: String,
    canonical: String,
    configured_identity: ObjectIdentity,
    target_identity: ObjectIdentity,
}

/// What to do when a recorded root no longer has the identity it was approved
/// with (folder deleted and recreated, volume re-imaged, path swapped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityMismatch {
    /// Surface the error. Used for explicit settings actions, where the user
    /// is waiting on the result and must be told the root was rejected.
    Reject,
    /// Drop the stale approval and carry on. Used at startup: the root becomes
    /// unapproved (so every operation on it still fails closed) but the
    /// process must not be unable to launch over it.
    Revoke,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRoots {
    version: u32,
    roots: Vec<ApprovedRoot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedRootTransaction {
    version: u32,
    configured_keys: Vec<String>,
    previous: PersistedRoots,
    next: PersistedRoots,
}

/// Prepared approved-root change. Callers may commit it before writing a
/// second durable file and roll it back if that write fails.
pub struct ApprovedRootUpdate {
    registry: Arc<ApprovedRootRegistry>,
    previous: HashMap<String, ApprovedRoot>,
    next: HashMap<String, ApprovedRoot>,
    configured_keys: Vec<String>,
    committed: bool,
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

#[cfg(test)]
static ROOT_REGISTRY_TEST_LOCK: OnceLock<parking_lot::Mutex<()>> = OnceLock::new();

/// Serialize tests that replace the process-global approved-root registry.
///
/// Production initializes this registry once. Tests intentionally install
/// isolated registries, so parallel test execution must not let one test
/// replace another test's roots while an asynchronous file open is pending.
#[cfg(test)]
pub(crate) fn test_registry_lock() -> parking_lot::MutexGuard<'static, ()> {
    ROOT_REGISTRY_TEST_LOCK
        .get_or_init(|| parking_lot::Mutex::new(()))
        .lock()
}

fn path_key(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('\\', "/");
    if cfg!(windows) {
        if let Some(rest) = value.strip_prefix("//?/UNC/") {
            value = format!("//{rest}");
        } else if let Some(rest) = value.strip_prefix("//?/") {
            value = rest.to_string();
        }
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

fn configured_root_keys(configured_roots: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = configured_roots
        .iter()
        .filter(|root| !root.is_empty())
        .map(|root| path_key(Path::new(root)))
        .collect();
    keys.sort();
    keys.dedup();
    keys
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
    fn snapshot_from(roots: &HashMap<String, ApprovedRoot>) -> PersistedRoots {
        PersistedRoots {
            version: ROOT_STATE_VERSION,
            roots: roots.values().cloned().collect(),
        }
    }

    fn persist_roots(&self, roots: &HashMap<String, ApprovedRoot>) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(&Self::snapshot_from(roots))
            .map_err(|error| io_other(format!("serialize approved roots: {error}")))?;
        crate::security::atomic_write(&self.state_path, &data, true)
    }

    fn transaction_path(&self) -> PathBuf {
        self.state_path.with_file_name(ROOT_TRANSACTION_FILE)
    }

    fn persist_transaction(
        &self,
        previous: &HashMap<String, ApprovedRoot>,
        next: &HashMap<String, ApprovedRoot>,
        configured_keys: &[String],
    ) -> io::Result<()> {
        let transaction = PersistedRootTransaction {
            version: ROOT_STATE_VERSION,
            configured_keys: configured_keys.to_vec(),
            previous: Self::snapshot_from(previous),
            next: Self::snapshot_from(next),
        };
        let data = serde_json::to_vec_pretty(&transaction)
            .map_err(|error| io_other(format!("serialize approved-root transaction: {error}")))?;
        crate::security::atomic_write(&self.transaction_path(), &data, true)
    }

    fn build_next(
        &self,
        configured_roots: &[String],
        explicit_additions: &[String],
        reapprovals: &[String],
        on_mismatch: IdentityMismatch,
    ) -> io::Result<(HashMap<String, ApprovedRoot>, HashMap<String, ApprovedRoot>)> {
        let reapprovals: HashSet<String> = reapprovals
            .iter()
            .filter(|root| !root.is_empty())
            .map(|root| path_key(Path::new(root)))
            .collect();
        let additions: HashSet<String> = explicit_additions
            .iter()
            .map(|root| path_key(Path::new(root)))
            .chain(reapprovals.iter().cloned())
            .collect();
        let current = self.roots.read().clone();
        let mut next = HashMap::new();
        for configured in configured_roots.iter().filter(|root| !root.is_empty()) {
            let configured_path = Path::new(configured);
            let key = path_key(configured_path);
            // An explicit re-approval ignores whatever record is on file so the
            // path is captured afresh — otherwise a stale record would be
            // verified against the object that replaced it and rejected again.
            let existing = current.get(&key).filter(|_| !reapprovals.contains(&key));
            if let Some(existing) = existing {
                match existing.verify() {
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        // Offline removable/network roots retain their prior
                        // identity and simply fail every attempted operation
                        // until the same object returns.
                    }
                    Err(error) if on_mismatch == IdentityMismatch::Revoke => {
                        tracing::warn!(
                            "Revoking approval for {}: {error}. It stays unusable until \
                             re-approved from Settings.",
                            configured_path.display()
                        );
                        continue;
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
                        // and fail closed if an operation is attempted —
                        // unless a record already exists, which means this is a
                        // re-approval (or re-add) of a root that is merely
                        // offline. Dropping it there would destroy a still-good
                        // approval that comes back with the volume, turning a
                        // recovery action into permanent breakage.
                        if let Some(previous) = current.get(&key) {
                            next.insert(key, previous.clone());
                        }
                    }
                    Err(error) => return Err(error),
                }
            } else if std::fs::metadata(configured_path)
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            {
                // Still-offline root that had no capturable identity during
                // the one-time migration. It remains unusable and unapproved.
            } else {
                // Settings may have been persisted before approval succeeded.
                // Keep the root absent so operations fail closed, but do not
                // brick process startup — an explicit UI action must approve it.
                tracing::warn!(
                    "configured root has no approved identity record and will stay unusable until re-approved: {}",
                    configured_path.display()
                );
            }
        }
        Ok((current, next))
    }

    /// Build, but do not persist or publish, a replacement root set.
    ///
    /// `reapprovals` re-captures a root whose recorded identity no longer
    /// matches. It is threaded through the transaction rather than applied by a
    /// separate [`ApprovedRootRegistry::reapprove_roots`] call so the recovery
    /// commits and rolls back with the settings write, and so every other root
    /// keeps [`IdentityMismatch::Reject`] instead of being silently revoked.
    pub fn prepare_update(
        self: &Arc<Self>,
        configured_roots: &[String],
        explicit_additions: &[String],
        reapprovals: &[String],
    ) -> io::Result<ApprovedRootUpdate> {
        let (previous, next) = self.build_next(
            configured_roots,
            explicit_additions,
            reapprovals,
            IdentityMismatch::Reject,
        )?;
        Ok(ApprovedRootUpdate {
            registry: self.clone(),
            previous,
            next,
            configured_keys: configured_root_keys(configured_roots),
            committed: false,
        })
    }

    /// Replace the configured root set after an explicit settings action.
    /// Existing roots must retain identity; only paths in `explicit_additions`
    /// may create a new approval record.
    pub fn update_roots(
        &self,
        configured_roots: &[String],
        explicit_additions: &[String],
    ) -> io::Result<()> {
        self.update_roots_with_policy(
            configured_roots,
            explicit_additions,
            &[],
            IdentityMismatch::Reject,
        )
    }

    /// Re-approve configured roots that lost their approval, without requiring
    /// the user to change the configured value.
    ///
    /// A root whose identity no longer matches is revoked at startup and then
    /// stays unusable, because only a path the user just *added* gets a new
    /// identity captured. A shared folder can be removed and re-added in
    /// Settings; the download folder cannot — re-picking the same folder is not
    /// an addition — so every download failed with no in-app way back. This is
    /// that way back. It grants approval to whatever object now sits at the
    /// configured path, so it must only ever run from an explicit user action,
    /// never automatically at startup.
    ///
    /// Roots that are not listed keep the approval they already hold. A
    /// mismatch on one of them revokes it (exactly as startup does) rather than
    /// failing the call: a recovery action must not be blocked by an unrelated
    /// stale root. Returns an error if a requested root could not be approved
    /// after all — it is absent, offline, or not among `configured_roots` — so
    /// the caller can say so instead of reporting a recovery that did nothing.
    pub fn reapprove_roots(
        &self,
        configured_roots: &[String],
        roots_to_reapprove: &[String],
    ) -> io::Result<()> {
        self.update_roots_with_policy(
            configured_roots,
            &[],
            roots_to_reapprove,
            IdentityMismatch::Revoke,
        )?;
        for root in roots_to_reapprove.iter().filter(|root| !root.is_empty()) {
            self.verify_root(Path::new(root))?;
        }
        Ok(())
    }

    fn update_roots_with_policy(
        &self,
        configured_roots: &[String],
        explicit_additions: &[String],
        reapprovals: &[String],
        on_mismatch: IdentityMismatch,
    ) -> io::Result<()> {
        let (_, next) =
            self.build_next(configured_roots, explicit_additions, reapprovals, on_mismatch)?;
        self.persist_roots(&next)?;
        *self.roots.write() = next;
        Ok(())
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
        match object_identity(candidate) {
            Ok(identity) if identity.reparse_point => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "output final component is a symlink or reparse point",
                ));
            }
            Ok(_) => return self.verify_existing_path(candidate, allowed_roots),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
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

impl ApprovedRootUpdate {
    /// Persist the prepared set before publishing it to readers. A persistence
    /// failure leaves the exact prior in-memory set untouched.
    pub fn commit(&mut self) -> io::Result<()> {
        if self.committed {
            return Ok(());
        }
        self.registry
            .persist_transaction(&self.previous, &self.next, &self.configured_keys)?;
        if let Err(error) = self.registry.persist_roots(&self.next) {
            let _ = std::fs::remove_file(self.registry.transaction_path());
            return Err(error);
        }
        *self.registry.roots.write() = self.next.clone();
        self.committed = true;
        Ok(())
    }

    /// Restore the exact root identities that existed before `commit`.
    pub fn rollback(&mut self) -> io::Result<()> {
        if !self.committed {
            return Ok(());
        }
        self.registry.persist_roots(&self.previous)?;
        *self.registry.roots.write() = self.previous.clone();
        self.committed = false;
        let _ = std::fs::remove_file(self.registry.transaction_path());
        Ok(())
    }

    /// Mark the paired settings write complete. If journal cleanup fails, the
    /// next startup recognizes that config already matches `next` and safely
    /// finishes the transaction.
    pub fn finish(&mut self) -> io::Result<()> {
        match std::fs::remove_file(self.registry.transaction_path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
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
    let transaction_path = data_dir.join(ROOT_TRANSACTION_FILE);
    let state_exists = state_path.exists();
    let mut roots: HashMap<String, ApprovedRoot> = if state_exists {
        match read_persisted_roots(&state_path) {
            Ok(roots) => roots,
            // Corrupt content: the file will never parse, so quarantining it and
            // continuing with nothing approved is the only way forward. Every root
            // fails closed until re-approved from Settings, and the empty set is
            // persisted below so this stays deliberate rather than looking like a
            // fresh install on the next launch.
            Err(error) if is_unparseable_root_state(&error) => {
                tracing::error!(
                    "Approved-root state at {} is unusable ({error}); quarantining it. \
                     Shared folders and the download folder must be re-approved in Settings.",
                    state_path.display()
                );
                quarantine_file(&state_path);
                HashMap::new()
            }
            // The file is intact; we just could not read it this time — a sharing
            // violation from a SYSTEM-level scanner, or a transient I/O error.
            // Treating that as corruption quarantined good state and then wrote an
            // empty set over it, so one unlucky startup permanently unapproved
            // every shared folder and the download folder. Worse, `quarantine_file`
            // renames to a fixed name, so a second occurrence discarded the copy
            // that still held the real approvals. Fail the launch instead and let
            // the user retry, matching `NodeIdentity::load_or_create`, which
            // refuses to mint a new identity on a transient error for the same
            // reason.
            Err(error) => {
                tracing::error!(
                    "Approved-root state at {} could not be read ({error}); refusing to \
                     discard it. Retry, or move the file aside if it is genuinely damaged.",
                    state_path.display()
                );
                return Err(error);
            }
        }
    } else {
        HashMap::new()
    };

    match read_root_transaction(&transaction_path) {
        Ok(Some(transaction)) => {
            let selected = if configured_root_keys(configured_roots) == transaction.configured_keys
            {
                transaction.next
            } else {
                transaction.previous
            };
            roots = selected
                .roots
                .into_iter()
                .map(|root| (path_key(Path::new(&root.configured)), root))
                .collect();
            let data = serde_json::to_vec_pretty(&ApprovedRootRegistry::snapshot_from(&roots))
                .map_err(|error| {
                    io_other(format!("serialize recovered approved roots: {error}"))
                })?;
            crate::security::atomic_write(&state_path, &data, true)?;
            let _ = std::fs::remove_file(&transaction_path);
        }
        Ok(None) => {}
        Err(error) => {
            // Same reasoning as the state file: an unreadable journal leaves the
            // roots we already loaded in place instead of blocking startup.
            tracing::error!(
                "Approved-root transaction journal at {} is unusable ({error}); quarantining it.",
                transaction_path.display()
            );
            quarantine_file(&transaction_path);
        }
    }

    let registry = Arc::new(ApprovedRootRegistry {
        state_path,
        roots: parking_lot::RwLock::new(roots),
    });
    let additions = if state_exists {
        Vec::new()
    } else {
        configured_roots.to_vec()
    };
    // Startup revokes roots whose identity changed rather than refusing to run:
    // a folder that was deleted and recreated (or a re-imaged volume) otherwise
    // left the app unable to launch at all, with no in-app way to recover.
    registry.update_roots_with_policy(configured_roots, &additions, &[], IdentityMismatch::Revoke)?;
    *global_slot().write() = Some(registry.clone());
    Ok(registry)
}

/// Whether an error from [`read_persisted_roots`] means the file's *content* is
/// unusable, as opposed to the read itself having failed.
///
/// Both arrive as `io::Error` because the parse failures are wrapped into one,
/// so the kind is what separates "this will never parse" from "try again".
fn is_unparseable_root_state(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    )
}

fn read_persisted_roots(state_path: &Path) -> io::Result<HashMap<String, ApprovedRoot>> {
    let data = std::fs::read(state_path)?;
    // `InvalidData`, not `Other`: the caller quarantines on that kind and only on
    // that kind, so a parse failure must be distinguishable from the `std::fs::read`
    // above having failed for an environmental reason.
    let persisted: PersistedRoots = serde_json::from_slice(&data).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("parse approved roots: {error}"),
        )
    })?;
    if persisted.version != ROOT_STATE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported approved-root state version {}",
                persisted.version
            ),
        ));
    }
    Ok(persisted
        .roots
        .into_iter()
        .map(|root| (path_key(Path::new(&root.configured)), root))
        .collect())
}

fn read_root_transaction(
    transaction_path: &Path,
) -> io::Result<Option<PersistedRootTransaction>> {
    let data = match std::fs::read(transaction_path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let transaction: PersistedRootTransaction = serde_json::from_slice(&data)
        .map_err(|error| io_other(format!("parse approved-root transaction: {error}")))?;
    if transaction.version != ROOT_STATE_VERSION
        || transaction.previous.version != ROOT_STATE_VERSION
        || transaction.next.version != ROOT_STATE_VERSION
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported approved-root transaction version",
        ));
    }
    Ok(Some(transaction))
}

/// Move an unusable state file aside so startup can continue and the original
/// bytes remain available for diagnosis. Best-effort: if the rename fails there
/// is nothing further to do, the caller already treats the state as absent.
fn quarantine_file(path: &Path) {
    let mut quarantined = path.as_os_str().to_os_string();
    quarantined.push(".corrupt.bak");
    if let Err(error) = std::fs::rename(path, PathBuf::from(quarantined)) {
        tracing::warn!("Failed to quarantine {}: {error}", path.display());
    }
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
    options.read(true).write(true).create_new(true);
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

fn single_path_component(name: &std::ffi::OsStr) -> io::Result<&std::ffi::OsStr> {
    let as_path = Path::new(name);
    if as_path.components().count() != 1
        || as_path.components().next().is_none_or(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file name must be a single path component",
        ));
    }
    as_path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file name must be a single path component",
        )
    })
}

#[cfg(unix)]
fn object_identity_from_file(file: &File) -> io::Result<ObjectIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(ObjectIdentity {
        volume_serial: metadata.dev(),
        file_id: metadata.ino(),
        attributes: 0,
        reparse_point: false,
    })
}

#[cfg(windows)]
fn object_identity_from_file(file: &File) -> io::Result<ObjectIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let result = unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ObjectIdentity {
        volume_serial: info.dwVolumeSerialNumber as u64,
        file_id: ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        attributes: info.dwFileAttributes,
        reparse_point: (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0,
    })
}

pub fn opened_file_identity(file: &File) -> io::Result<ObjectIdentity> {
    object_identity_from_file(file)
}

#[cfg(unix)]
fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(windows)]
fn open_windows_path(path: &Path, desired_access: u32, directory: bool) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut flags = FILE_FLAG_OPEN_REPARSE_POINT;
    if directory {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

#[cfg(windows)]
fn create_windows_new_file(path: &Path) -> io::Result<File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const WRITE_DAC_ACCESS: u32 = 0x0004_0000;

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | DELETE_ACCESS | WRITE_DAC_ACCESS,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
}

#[cfg(windows)]
fn delete_opened_file(file: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
fn open_directory_nofollow(path: &Path) -> io::Result<File> {
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
    open_windows_path(path, FILE_READ_ATTRIBUTES, true)
}

fn open_verified_directory(
    path: &Path,
    allowed_roots: &[String],
) -> io::Result<(PathBuf, File, ObjectIdentity)> {
    let verified = verify_existing_path(path, allowed_roots)?;
    if !verified.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "approved path is not a directory",
        ));
    }
    ensure_not_reparse(&verified)?;
    let expected = object_identity(&verified)?;
    let handle = open_directory_nofollow(&verified)?;
    let opened = object_identity_from_file(&handle)?;
    if opened != expected || opened.reparse_point || !handle.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approved directory changed while it was opened",
        ));
    }
    Ok((verified, handle, opened))
}

fn verified_parent_handle(
    parent: &Path,
    allowed_roots: &[String],
) -> io::Result<(PathBuf, File, ObjectIdentity)> {
    open_verified_directory(parent, allowed_roots)
}

#[cfg(unix)]
fn component_cstring(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file name contains NUL"))
}

#[cfg(unix)]
fn openat_child(
    parent: &File,
    name: &std::ffi::OsStr,
    flags: i32,
    mode: libc::mode_t,
) -> io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = component_cstring(name)?;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn link_opened_file_at(
    source: &File,
    destination_parent: &File,
    name: &std::ffi::OsStr,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let destination_name = component_cstring(name)?;
    let empty = c"";
    if unsafe {
        libc::linkat(
            source.as_raw_fd(),
            empty.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    } == 0
    {
        return Ok(());
    }
    let direct_error = io::Error::last_os_error();
    if direct_error.kind() == io::ErrorKind::AlreadyExists {
        return Err(direct_error);
    }

    // Normal users can be denied AT_EMPTY_PATH even for their own file.
    // Following the procfs descriptor symlink still names the exact open file
    // description, so it retains handle identity without reopening by path.
    let proc_path = std::ffi::CString::new(format!("/proc/self/fd/{}", source.as_raw_fd()))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid source descriptor"))?;
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            proc_path.as_ptr(),
            destination_parent.as_raw_fd(),
            destination_name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } == 0
    {
        return Ok(());
    }
    let proc_error = io::Error::last_os_error();
    if proc_error.kind() == io::ErrorKind::NotFound {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "handle-relative hard links require AT_EMPTY_PATH or procfs",
        ));
    }
    Err(proc_error)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn link_opened_file_at(
    _source: &File,
    _destination_parent: &File,
    _name: &std::ffi::OsStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this platform has no race-free open-handle hard-link API",
    ))
}

#[cfg(windows)]
fn final_path_from_file(file: &File) -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    let handle = file.as_raw_handle().cast();
    let needed =
        unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, FILE_NAME_NORMALIZED) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut wide = vec![0u16; needed as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            wide.as_mut_ptr(),
            wide.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= wide.len() {
        return Err(io::Error::last_os_error());
    }
    wide.truncate(written as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&wide)))
}

#[cfg(windows)]
fn opened_child_parent_matches(file: &File, verified_parent: &Path) -> io::Result<bool> {
    let opened = final_path_from_file(file)?;
    let Some(opened_parent) = opened.parent() else {
        return Ok(false);
    };
    Ok(path_key(opened_parent) == path_key(verified_parent))
}

#[cfg(windows)]
fn link_opened_file_at(
    source: &File,
    destination_parent: &File,
    name: &std::ffi::OsStr,
) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileLinkInformation, NtSetInformationFile, FILE_LINK_INFORMATION, FILE_LINK_INFORMATION_0,
    };
    use windows_sys::Win32::Foundation::RtlNtStatusToDosError;
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let wide: Vec<u16> = name.encode_wide().collect();
    let name_bytes = wide
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hard-link name is too long"))?;
    let header_len = std::mem::offset_of!(FILE_LINK_INFORMATION, FileName);
    let total_len = header_len
        .checked_add(name_bytes as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "hard-link name is too long"))?;
    let word_size = std::mem::size_of::<usize>();
    let mut storage = vec![0usize; total_len.div_ceil(word_size)];
    let info = storage.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
    unsafe {
        std::ptr::write(
            info,
            FILE_LINK_INFORMATION {
                Anonymous: FILE_LINK_INFORMATION_0 {
                    ReplaceIfExists: false,
                },
                RootDirectory: destination_parent.as_raw_handle().cast(),
                FileNameLength: name_bytes,
                FileName: [0],
            },
        );
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            wide.len(),
        );
    }

    let mut status_block = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            source.as_raw_handle().cast(),
            &mut status_block,
            info.cast(),
            u32::try_from(total_len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "link buffer too large")
            })?,
            FileLinkInformation,
        )
    };
    if status < 0 {
        let os_error = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(os_error as i32));
    }
    Ok(())
}

/// Open an existing approved regular file and validate the opened object before
/// returning it. No truncation or write occurs until this validation succeeds.
pub fn open_existing_approved(
    path: &Path,
    allowed_roots: &[String],
    writable: bool,
) -> io::Result<(PathBuf, File)> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name =
        single_path_component(path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path has no file name")
        })?)?;
    let (verified_parent, parent_handle, parent_identity) =
        verified_parent_handle(parent, allowed_roots)?;
    let verified = verified_parent.join(name);
    #[cfg(windows)]
    let _ = &parent_handle;

    #[cfg(unix)]
    let file = {
        let access = if writable {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };
        openat_child(
            &parent_handle,
            name,
            access | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?
    };
    #[cfg(windows)]
    let file = {
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        let access = if writable {
            GENERIC_READ | GENERIC_WRITE
        } else {
            GENERIC_READ
        };
        let file = open_windows_path(&verified, access, false)?;
        if object_identity(&verified_parent)? != parent_identity
            || !opened_child_parent_matches(&file, &verified_parent)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "opened file escaped or replaced its approved parent",
            ));
        }
        file
    };

    let opened = object_identity_from_file(&file)?;
    if opened.reparse_point || !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approved final component is not a regular non-reparse file",
        ));
    }
    Ok((verified, file))
}

fn split_verified_file_parent(
    path: &Path,
    allowed_roots: &[String],
) -> io::Result<(PathBuf, File, ObjectIdentity, std::ffi::OsString)> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name =
        single_path_component(path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "path has no file name")
        })?)?;
    let (verified_parent, parent_handle, parent_identity) =
        verified_parent_handle(parent, allowed_roots)?;
    Ok((
        verified_parent,
        parent_handle,
        parent_identity,
        name.to_os_string(),
    ))
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardLinkTestPoint {
    SourcePinned,
    DestinationLinked,
}

#[cfg(test)]
struct HardLinkTestHook {
    point: HardLinkTestPoint,
    reached: std::sync::mpsc::SyncSender<()>,
    resume: parking_lot::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
fn hard_link_test_hook_slot(
) -> &'static parking_lot::Mutex<Option<std::sync::Arc<HardLinkTestHook>>> {
    static SLOT: OnceLock<parking_lot::Mutex<Option<std::sync::Arc<HardLinkTestHook>>>> =
        OnceLock::new();
    SLOT.get_or_init(|| parking_lot::Mutex::new(None))
}

#[cfg(test)]
fn install_hard_link_test_hook(
    point: HardLinkTestPoint,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::SyncSender<()>,
) {
    let (reached_tx, reached_rx) = std::sync::mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = std::sync::mpsc::sync_channel(0);
    let hook = std::sync::Arc::new(HardLinkTestHook {
        point,
        reached: reached_tx,
        resume: parking_lot::Mutex::new(resume_rx),
    });
    let previous = hard_link_test_hook_slot().lock().replace(hook);
    assert!(previous.is_none(), "hard-link test hook already installed");
    (reached_rx, resume_tx)
}

#[cfg(test)]
fn hard_link_test_pause(point: HardLinkTestPoint) {
    let hook = {
        let mut slot = hard_link_test_hook_slot().lock();
        if slot.as_ref().is_some_and(|hook| hook.point == point) {
            slot.take()
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        let _ = hook.reached.send(());
        let _ = hook.resume.lock().recv();
    }
}

/// Create a hard link to the exact opened source object. The destination name
/// is claimed exclusively and then reopened without following reparses; a
/// path swap can therefore cause a clean failure but cannot publish a
/// different object.
pub fn hard_link_approved(
    source_path: &Path,
    destination_path: &Path,
    allowed_roots: &[String],
    expected_source: &ObjectIdentity,
) -> io::Result<PathBuf> {
    let (verified_source, source) = open_existing_approved(source_path, allowed_roots, false)?;
    let source_identity = object_identity_from_file(&source)?;
    if &source_identity != expected_source {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approved hard-link source changed identity",
        ));
    }

    let (destination_parent, destination_parent_handle, destination_parent_identity, name) =
        split_verified_file_parent(destination_path, allowed_roots)?;
    let destination = destination_parent.join(&name);

    #[cfg(unix)]
    {
        let _ = (&verified_source, destination_parent_identity);
        #[cfg(test)]
        hard_link_test_pause(HardLinkTestPoint::SourcePinned);
        link_opened_file_at(&source, &destination_parent_handle, &name)?;
        #[cfg(test)]
        hard_link_test_pause(HardLinkTestPoint::DestinationLinked);

        #[cfg(any(target_os = "linux", target_os = "android"))]
        let linked_result = openat_child(
            &destination_parent_handle,
            &name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        );
        #[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
        let linked_result = openat_child(
            &destination_parent_handle,
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        );
        let linked = match linked_result {
            Ok(linked) => linked,
            Err(error) => {
                // If the name still denotes our exact source object, remove
                // only that identity. A replacement (including a symlink)
                // fails the identity gate and is left untouched.
                let _ =
                    remove_approved_file_if_identity(&destination, allowed_roots, &source_identity);
                return Err(error);
            }
        };
        let linked_identity = object_identity_from_file(&linked)?;
        if linked_identity != source_identity
            || linked_identity.reparse_point
            || !linked.metadata()?.is_file()
        {
            // The source handle was linked atomically, so an identity mismatch
            // means the destination name was replaced after the link. Never
            // unlink that replacement by pathname.
            let _ = remove_approved_file_if_identity(&destination, allowed_roots, &source_identity);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hard-link destination did not bind the verified source",
            ));
        }
    }

    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
        const DELETE_ACCESS: u32 = 0x0001_0000;
        let link_source = open_windows_path(
            &verified_source,
            FILE_READ_ATTRIBUTES | DELETE_ACCESS,
            false,
        )?;
        let link_source_identity = object_identity_from_file(&link_source)?;
        let source_parent = verified_source
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source has no parent"))?;
        if link_source_identity != source_identity
            || link_source_identity.reparse_point
            || !link_source.metadata()?.is_file()
            || !opened_child_parent_matches(&link_source, source_parent)?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approved hard-link source changed before handle pinning",
            ));
        }

        #[cfg(test)]
        hard_link_test_pause(HardLinkTestPoint::SourcePinned);
        link_opened_file_at(&link_source, &destination_parent_handle, &name)?;
        #[cfg(test)]
        hard_link_test_pause(HardLinkTestPoint::DestinationLinked);

        let linked =
            match open_windows_path(&destination, FILE_READ_ATTRIBUTES | DELETE_ACCESS, false) {
                Ok(linked) => linked,
                Err(error) => {
                    let _ = remove_approved_file_if_identity(
                        &destination,
                        allowed_roots,
                        &source_identity,
                    );
                    return Err(error);
                }
            };
        let linked_identity = object_identity_from_file(&linked)?;
        if linked_identity != source_identity
            || linked_identity.reparse_point
            || !linked.metadata()?.is_file()
        {
            // A different identity can only be a replacement installed after
            // the handle-relative link. It is not ours, so never delete it.
            let _ = remove_approved_file_if_identity(&destination, allowed_roots, &source_identity);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hard-link destination did not bind the verified source",
            ));
        }
        if object_identity(&destination_parent)? != destination_parent_identity
            || !opened_child_parent_matches(&linked, &destination_parent)?
        {
            // `linked` is still the exact source object this call linked.
            // Handle deletion therefore cannot target a path replacement.
            delete_opened_file(&linked)?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "hard-link destination parent changed during publication",
            ));
        }
    }

    Ok(destination)
}

fn remove_approved_file_inner(
    path: &Path,
    allowed_roots: &[String],
    expected: Option<&ObjectIdentity>,
) -> io::Result<()> {
    let (verified_parent, parent_handle, parent_identity, name) =
        split_verified_file_parent(path, allowed_roots)?;
    #[cfg(windows)]
    let _ = &parent_handle;

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let opened = openat_child(
            &parent_handle,
            &name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        let opened_identity = object_identity_from_file(&opened)?;
        if expected.is_some_and(|identity| identity != &opened_identity)
            || opened_identity.reparse_point
            || !opened.metadata()?.is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approved file changed before deletion",
            ));
        }
        let original_name = component_cstring(&name)?;
        let quarantine_component = format!(".ember-delete-{}", random_hex());
        let quarantine_name = component_cstring(std::ffi::OsStr::new(&quarantine_component))?;
        // POSIX has no portable unlink-by-file-descriptor. Atomically move the
        // current final component to an unguessable name first, then verify
        // that moved object before unlinking it. A swap at the original name
        // can therefore move an unexpected object aside, but it cannot delete
        // that unexpected object.
        if unsafe {
            libc::renameat(
                parent_handle.as_raw_fd(),
                original_name.as_ptr(),
                parent_handle.as_raw_fd(),
                quarantine_name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let quarantined = openat_child(
            &parent_handle,
            std::ffi::OsStr::new(&quarantine_component),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        if object_identity_from_file(&quarantined)? != opened_identity
            || !quarantined.metadata()?.is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approved file changed during deletion quarantine",
            ));
        }
        if unsafe { libc::unlinkat(parent_handle.as_raw_fd(), quarantine_name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
        const DELETE_ACCESS: u32 = 0x0001_0000;
        let opened = open_windows_path(
            &verified_parent.join(&name),
            DELETE_ACCESS | FILE_READ_ATTRIBUTES,
            false,
        )?;
        let opened_identity = object_identity_from_file(&opened)?;
        if expected.is_some_and(|identity| identity != &opened_identity)
            || opened_identity.reparse_point
            || object_identity(&verified_parent)? != parent_identity
            || !opened_child_parent_matches(&opened, &verified_parent)?
            || !opened.metadata()?.is_file()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approved file changed before deletion",
            ));
        }
        delete_opened_file(&opened)
    }
}

/// Verify `parent`, hold its directory handle, and create `parent/<name>`
/// relative to that handle on Unix. Windows lacks a stable Win32
/// handle-relative create primitive, so it validates both the opened file's
/// final parent and the pinned parent before returning, without deleting by
/// pathname on failure.
pub fn create_new_in_approved_parent(
    parent: &Path,
    name: &std::ffi::OsStr,
    allowed_roots: &[String],
) -> io::Result<(PathBuf, File)> {
    let file_name = single_path_component(name)?;
    let (verified_parent, parent_handle, parent_identity) =
        verified_parent_handle(parent, allowed_roots)?;
    #[cfg(windows)]
    let _ = &parent_handle;
    let candidate = verified_parent.join(file_name);

    #[cfg(unix)]
    let file = openat_child(
        &parent_handle,
        file_name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    #[cfg(windows)]
    let file = create_windows_new_file(&candidate)?;

    let opened = object_identity_from_file(&file)?;
    if opened.reparse_point || !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "created output is not a regular non-reparse file",
        ));
    }
    #[cfg(windows)]
    {
        if object_identity(&verified_parent)? != parent_identity
            || !opened_child_parent_matches(&file, &verified_parent)?
        {
            // Never clean up through `candidate`: a swapped parent could make
            // pathname deletion target an unrelated file. Closing leaves at
            // worst the empty, exclusively-created object for orphan cleanup.
            let _ = delete_opened_file(&file);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approved parent changed during create",
            ));
        }
    }
    Ok((candidate, file))
}

/// Open an existing approved path for read/write, or create it under a pinned
/// parent when absent. Existing files are opened and handle-validated before
/// truncation.
pub fn open_or_create_approved(
    path: &Path,
    allowed_roots: &[String],
    truncate_existing: bool,
) -> io::Result<(PathBuf, File)> {
    match open_existing_approved(path, allowed_roots, true) {
        Ok((verified, file)) => {
            if truncate_existing {
                file.set_len(0)?;
            }
            return Ok((verified, file));
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        Err(_) => {}
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    create_new_in_approved_parent(parent, name, allowed_roots)
}

/// Ensure `root/<name>` exists as a real directory inside an approved root.
/// Unix creation is directory-handle-relative. Windows validates the opened
/// directory's final parent before returning and performs no path cleanup if a
/// parent swap is detected.
pub fn prepare_approved_subdir(
    root: &Path,
    name: &str,
    allowed_roots: &[String],
) -> io::Result<PathBuf> {
    let file_name = single_path_component(std::ffi::OsStr::new(name))?;
    let (verified_root, root_handle, root_identity) = open_verified_directory(root, allowed_roots)?;
    #[cfg(windows)]
    let _ = &root_handle;
    let candidate = verified_root.join(file_name);

    #[cfg(unix)]
    let open_child = || {
        openat_child(
            &root_handle,
            file_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    #[cfg(windows)]
    let open_child = || {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
        const DELETE_ACCESS: u32 = 0x0001_0000;
        open_windows_path(&candidate, FILE_READ_ATTRIBUTES | DELETE_ACCESS, true)
    };

    let directory = match open_child() {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::fd::AsRawFd;
                let name = component_cstring(file_name)?;
                if unsafe { libc::mkdirat(root_handle.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(windows)]
            std::fs::create_dir(&candidate)?;
            open_child()?
        }
        Err(error) => return Err(error),
    };
    let opened = object_identity_from_file(&directory)?;
    if opened.reparse_point || !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "approved subdirectory is not a real directory",
        ));
    }
    #[cfg(windows)]
    {
        if object_identity(&verified_root)? != root_identity
            || !opened_child_parent_matches(&directory, &verified_root)?
        {
            // Do not delete the opened directory on mismatch: after a junction
            // swap of the approved root, that handle may point at an
            // attacker-chosen path. Leaving an orphan under our real root is
            // preferable to deleting outside the approved tree.
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "approved root changed during directory create/open",
            ));
        }
    }
    Ok(candidate)
}

/// Re-pin an output parent and create a new file without following a final
/// reparse. Used by completion/copy paths after `verify_output_path`.
pub fn create_new_verified_output(
    verified_output: &Path,
    allowed_roots: &[String],
) -> io::Result<(PathBuf, File)> {
    let parent = verified_output
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no parent"))?;
    let name = verified_output
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output has no file name"))?;
    create_new_in_approved_parent(parent, name, allowed_roots)
}

/// Remove a regular file without allowing a swapped pathname to redirect the
/// deletion outside an approved directory handle.
pub fn remove_approved_file(path: &Path, allowed_roots: &[String]) -> io::Result<()> {
    remove_approved_file_inner(path, allowed_roots, None)
}

/// Remove only if the final component still names the exact object previously
/// pinned by the caller. Used by delayed/retried cleanup paths.
pub fn remove_approved_file_if_identity(
    path: &Path,
    allowed_roots: &[String],
    expected: &ObjectIdentity,
) -> io::Result<()> {
    remove_approved_file_inner(path, allowed_roots, Some(expected))
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
                    // The shared helper re-opens no-follow with WRITE_DAC;
                    // `create_new_nofollow` does not request that access, so the
                    // returned handle cannot carry the ACL write itself.
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

/// Launch `path` in the user's default application.
///
/// On Windows the extended-length `\\?\` prefix has to come off first. Every
/// path here comes from `canonicalize`, which always produces that form, and
/// the Shell APIs behind `opener` reject it — so "Open" failed for every file
/// while the neighbouring "Show in folder" worked, because
/// `reveal_in_file_manager` already strips it. A path that genuinely needs
/// the prefix to exceed MAX_PATH cannot be launched by the shell either way.
#[cfg(target_os = "windows")]
pub fn open_with_default_app(path: &Path) -> io::Result<()> {
    let value = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is not UTF-8"))?;
    let clean = match value.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => value.strip_prefix(r"\\?\").unwrap_or(value).to_string(),
    };
    opener::open(clean).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

#[cfg(not(target_os = "windows"))]
pub fn open_with_default_app(path: &Path) -> io::Result<()> {
    opener::open(path).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
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
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok(ObjectIdentity {
        volume_serial: metadata.dev(),
        file_id: metadata.ino(),
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

    #[test]
    fn unknown_configured_root_stays_unusable_without_bricking_update() {
        let base = std::env::temp_dir().join(format!(
            "ember-unapproved-root-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let approved = base.join("approved");
        let stranger = base.join("stranger");
        std::fs::create_dir_all(&approved).unwrap();
        std::fs::create_dir_all(&stranger).unwrap();
        let registry = ApprovedRootRegistry {
            state_path: base.join(ROOT_STATE_FILE),
            roots: parking_lot::RwLock::new(HashMap::new()),
        };
        let approved_s = approved.to_string_lossy().into_owned();
        registry
            .update_roots(
                std::slice::from_ref(&approved_s),
                std::slice::from_ref(&approved_s),
            )
            .unwrap();
        let stranger_s = stranger.to_string_lossy().into_owned();
        let roots = [approved_s.clone(), stranger_s.clone()];
        registry.update_roots(&roots, &[]).unwrap();
        assert!(registry.verify_root(&approved).is_ok());
        assert!(registry.verify_root(&stranger).is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn unix_directory_replace_invalidates_approved_root_identity() {
        let base = std::env::temp_dir().join(format!(
            "ember-inode-root-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("approved");
        std::fs::create_dir_all(&root).unwrap();
        let registry = ApprovedRootRegistry {
            state_path: base.join(ROOT_STATE_FILE),
            roots: parking_lot::RwLock::new(HashMap::new()),
        };
        let configured = root.to_string_lossy().into_owned();
        registry
            .update_roots(
                std::slice::from_ref(&configured),
                std::slice::from_ref(&configured),
            )
            .unwrap();
        assert!(registry.verify_root(&root).is_ok());
        std::fs::remove_dir(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(
            registry.verify_root(&root).is_err(),
            "replaced directory inode must not retain approval"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn create_new_in_approved_parent_rejects_outside_parent() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-create-parent-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
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
        *global_slot().write() = Some(Arc::new(registry));
        let allowed = [root_string];
        assert!(
            create_new_in_approved_parent(&outside, std::ffi::OsStr::new("x.bin"), &allowed)
                .is_err()
        );
        let (path, file) =
            create_new_in_approved_parent(&root, std::ffi::OsStr::new("ok.bin"), &allowed).unwrap();
        drop(file);
        let canonical_root = root.canonicalize().unwrap();
        assert!(
            path.starts_with(&canonical_root),
            "created {} must stay under {}",
            path.display(),
            canonical_root.display()
        );
        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn opened_file_handle_cannot_be_retargeted_before_truncate() {
        use std::io::Write;

        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-open-handle-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let target = root.join("target.part");
        let moved = root.join("opened-object.part");
        std::fs::write(&target, b"approved bytes").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let allowed = [root_string];

        let (_, mut opened) = open_existing_approved(&target, &allowed, true).unwrap();
        std::fs::rename(&target, &moved).unwrap();
        std::fs::write(&target, b"replacement must survive").unwrap();
        opened.set_len(0).unwrap();
        opened.write_all(b"opened").unwrap();

        assert_eq!(std::fs::read(&moved).unwrap(), b"opened");
        assert_eq!(std::fs::read(&target).unwrap(), b"replacement must survive");
        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn final_symlink_is_rejected_before_open_or_delete() {
        use std::os::unix::fs::symlink;

        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-final-symlink-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let victim = root.join("victim.bin");
        let candidate = root.join("candidate.part");
        std::fs::write(&victim, b"must survive").unwrap();
        symlink(&victim, &candidate).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let allowed = [root_string];

        assert!(open_or_create_approved(&candidate, &allowed, true).is_err());
        assert!(remove_approved_file(&candidate, &allowed).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"must survive");

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(windows)]
    #[test]
    fn windows_final_file_reparse_is_rejected_before_open_or_delete() {
        use std::os::windows::fs::symlink_file;

        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-final-reparse-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let victim = root.join("victim.bin");
        let candidate = root.join("candidate.part");
        std::fs::write(&victim, b"must survive").unwrap();
        if let Err(error) = symlink_file(&victim, &candidate) {
            // Windows requires Developer Mode or SeCreateSymbolicLinkPrivilege.
            // Keep CI portable while exercising the path whenever available.
            if error.kind() == io::ErrorKind::PermissionDenied || error.raw_os_error() == Some(1314)
            {
                let _ = std::fs::remove_dir_all(base);
                return;
            }
            panic!("could not create final-component symlink: {error}");
        }
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let allowed = [root_string];

        assert!(open_or_create_approved(&candidate, &allowed, true).is_err());
        assert!(remove_approved_file(&candidate, &allowed).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"must survive");

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn hard_link_uses_pinned_source_after_name_replacement() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-hard-link-source-race-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let source = root.join("source.part");
        let moved_source = root.join("source-opened.part");
        let destination = root.join("finished.bin");
        std::fs::write(&source, b"pinned source").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let allowed = vec![root_string];
        let (_, opened) = open_existing_approved(&source, &allowed, false).unwrap();
        let expected = opened_file_identity(&opened).unwrap();
        drop(opened);

        let (reached, resume) = install_hard_link_test_hook(HardLinkTestPoint::SourcePinned);
        let thread_source = source.clone();
        let thread_destination = destination.clone();
        let thread_allowed = allowed.clone();
        let thread_expected = expected.clone();
        let worker = std::thread::spawn(move || {
            hard_link_approved(
                &thread_source,
                &thread_destination,
                &thread_allowed,
                &thread_expected,
            )
        });
        reached
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("hard-link worker pinned its source handle");
        std::fs::rename(&source, &moved_source).unwrap();
        std::fs::write(&source, b"replacement source").unwrap();
        resume.send(()).unwrap();

        let linked_path = worker.join().unwrap().unwrap();
        let (_, linked) = open_existing_approved(&linked_path, &allowed, false).unwrap();
        assert_eq!(opened_file_identity(&linked).unwrap(), expected);
        assert_eq!(std::fs::read(&linked_path).unwrap(), b"pinned source");
        assert_eq!(std::fs::read(&source).unwrap(), b"replacement source");

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn hard_link_validation_never_deletes_destination_replacement() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-hard-link-destination-race-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let source = root.join("source.part");
        let destination = root.join("finished.bin");
        std::fs::write(&source, b"pinned source").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let allowed = vec![root_string];
        let (_, opened) = open_existing_approved(&source, &allowed, false).unwrap();
        let expected = opened_file_identity(&opened).unwrap();
        drop(opened);

        let (reached, resume) = install_hard_link_test_hook(HardLinkTestPoint::DestinationLinked);
        let thread_source = source.clone();
        let thread_destination = destination.clone();
        let thread_allowed = allowed.clone();
        let worker = std::thread::spawn(move || {
            hard_link_approved(
                &thread_source,
                &thread_destination,
                &thread_allowed,
                &expected,
            )
        });
        reached
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("hard-link worker created the destination link");
        std::fs::remove_file(&destination).unwrap();
        std::fs::write(&destination, b"replacement must survive").unwrap();
        resume.send(()).unwrap();

        assert!(worker.join().unwrap().is_err());
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"replacement must survive"
        );
        assert_eq!(std::fs::read(&source).unwrap(), b"pinned source");

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn identity_checked_cleanup_rejects_name_replacement() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-cleanup-identity-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let candidate = root.join("candidate.part");
        let moved = root.join("candidate-original.part");
        std::fs::write(&candidate, b"original").unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let allowed = [root_string];
        let (_, opened) = open_existing_approved(&candidate, &allowed, false).unwrap();
        let expected = opened_file_identity(&opened).unwrap();
        drop(opened);

        std::fs::rename(&candidate, &moved).unwrap();
        std::fs::write(&candidate, b"replacement must survive").unwrap();
        assert!(remove_approved_file_if_identity(&candidate, &allowed, &expected).is_err());
        assert_eq!(
            std::fs::read(&candidate).unwrap(),
            b"replacement must survive"
        );

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn unix_parent_handle_create_ignores_later_symlink_swap() {
        use std::os::unix::fs::symlink;

        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-openat-parent-test-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let parent = root.join("parent");
        let moved = root.join("parent-opened");
        let outside = base.join("outside");
        let data = base.join("data");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let allowed = [root_string];
        let (_, parent_handle, _) = verified_parent_handle(&parent, &allowed).unwrap();

        std::fs::rename(&parent, &moved).unwrap();
        symlink(&outside, &parent).unwrap();
        let created = openat_child(
            &parent_handle,
            std::ffi::OsStr::new("created.part"),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        drop(created);

        assert!(moved.join("created.part").exists());
        assert!(!outside.join("created.part").exists());
        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    /// A root that no longer has its approved identity (folder deleted and
    /// recreated, volume re-imaged) used to abort the setup hook, so the app
    /// could not launch at all and there was no in-app way to recover. Startup
    /// must revoke the stale approval and keep going; the root stays unusable.
    #[test]
    fn startup_revokes_root_with_changed_identity_instead_of_failing() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-identity-revoke-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();

        // Rewrite the recorded identity so it cannot match what is on disk.
        // Equivalent to the folder being replaced, but deterministic.
        let state_path = data.join(ROOT_STATE_FILE);
        let mut persisted: PersistedRoots =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(persisted.roots.len(), 1);
        for record in &mut persisted.roots {
            record.configured_identity.file_id ^= 0xFFFF_FFFF;
            record.target_identity.file_id ^= 0xFFFF_FFFF;
        }
        std::fs::write(&state_path, serde_json::to_vec(&persisted).unwrap()).unwrap();

        let registry = initialize_approved_roots(&data, std::slice::from_ref(&root_string))
            .expect("startup must survive a root whose identity changed");
        assert!(
            registry.verify_root(&root).is_err(),
            "revoked root must fail closed until it is re-approved"
        );
        let reloaded: PersistedRoots =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert!(
            reloaded.roots.is_empty(),
            "revocation must be durable, not re-trusted on the next launch"
        );

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    /// Attribute bits are not identity. Compression, the content-indexed flag,
    /// hidden/read-only and a sync client's pinned bits all change without the
    /// folder being replaced, and each one used to revoke the approval durably.
    #[test]
    fn attribute_drift_keeps_an_approved_root() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-attribute-drift-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();

        // Flip the recorded attribute word the way the filesystem would when
        // the folder is compressed or excluded from the index. Every other
        // recorded field still describes the object that is on disk.
        let state_path = data.join(ROOT_STATE_FILE);
        let mut persisted: PersistedRoots =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(persisted.roots.len(), 1);
        for record in &mut persisted.roots {
            record.configured_identity.attributes ^= 0x0000_2800;
            record.target_identity.attributes ^= 0x0000_2800;
        }
        std::fs::write(&state_path, serde_json::to_vec(&persisted).unwrap()).unwrap();

        let registry = initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        assert!(
            registry.verify_root(&root).is_ok(),
            "attribute drift must not look like a replaced directory"
        );
        let reloaded: PersistedRoots =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(
            reloaded.roots.len(),
            1,
            "the approval must survive on disk too"
        );

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    /// A revoked root — the download folder deleted and recreated, say — has to
    /// be recoverable in place. Settings cannot re-add it, because its value
    /// never changed, so an explicit re-approval is the only way back.
    #[test]
    fn revoked_root_can_be_reapproved_without_changing_its_path() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-reapprove-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();

        let state_path = data.join(ROOT_STATE_FILE);
        let mut persisted: PersistedRoots =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        for record in &mut persisted.roots {
            record.configured_identity.file_id ^= 0xFFFF_FFFF;
            record.target_identity.file_id ^= 0xFFFF_FFFF;
        }
        std::fs::write(&state_path, serde_json::to_vec(&persisted).unwrap()).unwrap();

        let registry = initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        assert!(registry.verify_root(&root).is_err(), "must start revoked");

        registry
            .reapprove_roots(
                std::slice::from_ref(&root_string),
                std::slice::from_ref(&root_string),
            )
            .expect("an explicit re-approval must restore a revoked root");
        assert!(registry.verify_root(&root).is_ok());

        // And it must be durable: the next launch has to find the record.
        let reopened = initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        assert!(reopened.verify_root(&root).is_ok());

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    /// Re-approving a root that is merely offline must not destroy its record.
    /// Capturing a fresh identity fails with `NotFound`, and dropping the
    /// approval there would turn "unplugged drive" into permanent breakage that
    /// survives the drive coming back.
    #[test]
    fn reapproving_an_offline_root_keeps_its_existing_record() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-reapprove-offline-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        let registry = initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        let before = std::fs::read(data.join("approved_roots.json")).unwrap();

        // Simulate the volume going away, then ask for a re-approval anyway.
        std::fs::remove_dir_all(&root).unwrap();
        registry
            .update_roots_with_policy(
                std::slice::from_ref(&root_string),
                &[],
                std::slice::from_ref(&root_string),
                IdentityMismatch::Reject,
            )
            .unwrap();
        assert_eq!(
            std::fs::read(data.join("approved_roots.json")).unwrap(),
            before,
            "an offline root's approval must survive a re-approval attempt"
        );

        // Recreating the path is a *different* object (new file id), so it must
        // still fail closed — the point is that the record was kept for the
        // original object rather than deleted, not that any directory at that
        // path now inherits the approval.
        std::fs::create_dir_all(&root).unwrap();
        let reopened = initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();
        assert!(reopened.verify_root(&root).is_err());

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    /// Re-approval only touches the paths it was given: an unrelated root is
    /// neither granted an approval it never had nor silently kept when its
    /// identity has moved.
    #[test]
    fn reapproval_does_not_approve_unrelated_roots() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-reapprove-scope-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let approved = base.join("approved");
        let stranger = base.join("stranger");
        let data = base.join("data");
        std::fs::create_dir_all(&approved).unwrap();
        std::fs::create_dir_all(&stranger).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let approved_string = approved.to_string_lossy().into_owned();
        let stranger_string = stranger.to_string_lossy().into_owned();
        let registry =
            initialize_approved_roots(&data, std::slice::from_ref(&approved_string)).unwrap();

        let configured = [approved_string.clone(), stranger_string];
        registry
            .reapprove_roots(&configured, std::slice::from_ref(&approved_string))
            .unwrap();
        assert!(registry.verify_root(&approved).is_ok());
        assert!(
            registry.verify_root(&stranger).is_err(),
            "a root that was not re-approved must stay unapproved"
        );

        // A path that is not configured at all cannot be approved this way.
        let outsider = base.join("outsider");
        std::fs::create_dir_all(&outsider).unwrap();
        let outsider_string = outsider.to_string_lossy().into_owned();
        assert!(registry
            .reapprove_roots(&configured, std::slice::from_ref(&outsider_string))
            .is_err());
        assert!(registry.verify_root(&outsider).is_err());

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    /// An explicit settings action still refuses a root whose identity moved —
    /// the user is waiting on that result and must be told, not silently
    /// downgraded.
    #[test]
    fn explicit_update_still_rejects_changed_identity() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-identity-reject-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        let registry = initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        let recaptured = ApprovedRoot::capture(&root).unwrap();
        let stale = registry.roots.read().values().next().cloned().unwrap();
        if recaptured.configured_identity != stale.configured_identity {
            assert!(
                registry
                    .update_roots(std::slice::from_ref(&root_string), &[])
                    .is_err(),
                "explicit updates must surface an identity mismatch"
            );
        }

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }

    /// Unreadable approval state is quarantined instead of blocking launch.
    #[test]
    fn corrupt_approved_root_state_is_quarantined_not_fatal() {
        let _registry_guard = test_registry_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-root-state-corrupt-{}-{}",
            std::process::id(),
            random_hex()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_string = root.to_string_lossy().into_owned();
        initialize_approved_roots(&data, std::slice::from_ref(&root_string)).unwrap();

        let state_path = data.join(ROOT_STATE_FILE);
        std::fs::write(&state_path, b"{ not valid json").unwrap();

        let registry = initialize_approved_roots(&data, std::slice::from_ref(&root_string))
            .expect("startup must survive unreadable approval state");
        assert!(registry.verify_root(&root).is_err());
        assert!(
            data.join(format!("{ROOT_STATE_FILE}.corrupt.bak")).exists(),
            "original bytes must be kept for diagnosis"
        );

        *global_slot().write() = None;
        let _ = std::fs::remove_dir_all(base);
    }
}
