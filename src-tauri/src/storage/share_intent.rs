use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

const STATE_FILE: &str = "share_intent.json";
const STATE_VERSION: u32 = 1;
const MAX_INTENTS: usize = 1_000_000;

/// Process-local fail-closed latch used when durable share-intent persistence
/// fails after catalog corruption. `effective_shared` consults this even when
/// the on-disk store could not be updated.
static FORCE_UNSHARED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedShareIntent {
    version: u32,
    /// A known.met catalog existed on an earlier successful load. Its later
    /// loss/corruption must therefore not be interpreted as a clean first run.
    catalog_seen: bool,
    /// Once entered, unknown rediscovered hashes default to unshared. Explicit
    /// per-hash allows remain possible and durable.
    fail_closed: bool,
    #[serde(default)]
    denied: HashSet<String>,
    #[serde(default)]
    explicit_allow: HashSet<String>,
}

impl Default for PersistedShareIntent {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            catalog_seen: false,
            fail_closed: false,
            denied: HashSet::new(),
            explicit_allow: HashSet::new(),
        }
    }
}

pub struct ShareIntentStore {
    path: std::path::PathBuf,
    state: parking_lot::RwLock<PersistedShareIntent>,
    /// [`WRITE_SEQUENCE`] value of the last explicit write per hash, this
    /// session. Taken only while `state` is write-locked.
    write_seq: parking_lot::Mutex<HashMap<[u8; 16], u64>>,
}

/// Orders explicit share-intent writes; see
/// [`ShareIntentStore::set_explicit_batch_unless_newer`].
static WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A point in the share-intent write order. A batch applied later with
/// [`set_explicit_batch_unless_newer`] cannot override any write that lands
/// after this call returns.
pub fn write_ticket() -> u64 {
    WRITE_SEQUENCE.load(Ordering::Acquire)
}

enum Slot {
    Uninitialized,
    /// share_intent.json is loaded but known.met has not been folded in yet.
    /// Readers wait: acting on this state would miss the catalog's unshared
    /// records and could publish a file the user unshared. The generation ties
    /// the state to one [`PendingInit`], so a guard outliving its
    /// initialization cannot settle a newer one.
    Pending(u64),
    Ready(Arc<ShareIntentStore>),
    Failed,
}

static NEXT_INIT_GENERATION: AtomicU64 = AtomicU64::new(1);

struct GlobalSlot {
    slot: parking_lot::RwLock<Slot>,
    /// Held while `slot` changes so a waiter cannot miss the notification
    /// between its check and its wait.
    settle: parking_lot::Mutex<()>,
    settled: parking_lot::Condvar,
}

impl GlobalSlot {
    fn set(&self, value: Slot) {
        let _settle = self.settle.lock();
        *self.slot.write() = value;
        self.settled.notify_all();
    }

    /// Replace `Pending(generation)` with `value`; any other state is left
    /// alone. Returns whether the replacement happened.
    fn settle_pending(&self, generation: u64, value: Slot) -> bool {
        let _settle = self.settle.lock();
        let mut slot = self.slot.write();
        if !matches!(*slot, Slot::Pending(current) if current == generation) {
            return false;
        }
        *slot = value;
        self.settled.notify_all();
        true
    }

    fn resolved(&self) -> Option<io::Result<Arc<ShareIntentStore>>> {
        match &*self.slot.read() {
            Slot::Ready(store) => Some(Ok(store.clone())),
            Slot::Pending(_) => None,
            Slot::Uninitialized => Some(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "share-intent store is not initialized",
            ))),
            Slot::Failed => Some(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "share-intent store failed to initialize",
            ))),
        }
    }
}

static SHARE_INTENT: OnceLock<GlobalSlot> = OnceLock::new();

#[cfg(test)]
static SHARE_INTENT_TEST_LOCK: OnceLock<parking_lot::Mutex<()>> = OnceLock::new();

/// Serialize tests that install the process-global share-intent store.
#[cfg(test)]
pub(crate) fn test_store_lock() -> parking_lot::MutexGuard<'static, ()> {
    SHARE_INTENT_TEST_LOCK
        .get_or_init(|| parking_lot::Mutex::new(()))
        .lock()
}

fn global_slot() -> &'static GlobalSlot {
    SHARE_INTENT.get_or_init(|| GlobalSlot {
        slot: parking_lot::RwLock::new(Slot::Uninitialized),
        settle: parking_lot::Mutex::new(()),
        settled: parking_lot::Condvar::new(),
    })
}

fn normalize_hash(hash: &[u8; 16]) -> String {
    hex::encode(hash)
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn write_state(path: &Path, state: &PersistedShareIntent) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(state)
        .map_err(|error| io_other(format!("serialize share intent: {error}")))?;
    crate::security::atomic_write(path, &data, true)
}

impl ShareIntentStore {
    fn persist_state(&self, state: &PersistedShareIntent) -> io::Result<()> {
        write_state(&self.path, state)
    }

    fn mutate(
        &self,
        mutation: impl FnOnce(&mut PersistedShareIntent) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut guard = self.state.write();
        let before = guard.clone();
        mutation(&mut guard)?;
        if let Err(error) = self.persist_state(&guard) {
            *guard = before;
            return Err(error);
        }
        Ok(())
    }

    pub fn effective_shared(&self, hash: &[u8; 16], catalog_value: bool) -> bool {
        if FORCE_UNSHARED.load(Ordering::Acquire) {
            return false;
        }
        let key = normalize_hash(hash);
        let state = self.state.read();
        if state.denied.contains(&key) {
            false
        } else if state.explicit_allow.contains(&key) {
            true
        } else if state.fail_closed {
            false
        } else {
            catalog_value
        }
    }

    /// Returns whether anything changed. A batch that is already in effect
    /// is not persisted: the reconcile re-asserts every independent deny on
    /// each pass, and each persist is a pretty-printed, fsync'd rewrite of
    /// the whole store.
    pub fn set_explicit_batch(&self, updates: &[([u8; 16], bool)]) -> io::Result<bool> {
        self.apply_explicit_batch(updates, None)
    }

    /// [`Self::set_explicit_batch`] for a decision made at [`write_ticket`]
    /// `ticket` and applied later: any hash written since then is left alone.
    /// Last-applied-wins is wrong for a write that was queued before a newer
    /// one — a deferred unshare landing after the user re-shared would deny
    /// the file for good while the Library and known.met say shared.
    pub fn set_explicit_batch_unless_newer(
        &self,
        updates: &[([u8; 16], bool)],
        ticket: u64,
    ) -> io::Result<bool> {
        self.apply_explicit_batch(updates, Some(ticket))
    }

    fn apply_explicit_batch(
        &self,
        updates: &[([u8; 16], bool)],
        ticket: Option<u64>,
    ) -> io::Result<bool> {
        let mut state = self.state.write();
        let mut write_seq = self.write_seq.lock();
        let updates: Vec<([u8; 16], bool)> = updates
            .iter()
            .copied()
            .filter(|(hash, _)| {
                ticket.is_none_or(|ticket| write_seq.get(hash).is_none_or(|seq| *seq <= ticket))
            })
            .collect();
        let seq = WRITE_SEQUENCE.fetch_add(1, Ordering::AcqRel) + 1;
        let in_effect = updates.iter().all(|(hash, shared)| {
            let key = normalize_hash(hash);
            if *shared {
                state.explicit_allow.contains(&key) && !state.denied.contains(&key)
            } else {
                state.denied.contains(&key) && !state.explicit_allow.contains(&key)
            }
        });
        if !in_effect {
            let before = state.clone();
            for (hash, shared) in &updates {
                let key = normalize_hash(hash);
                if *shared {
                    state.denied.remove(&key);
                    state.explicit_allow.insert(key);
                } else {
                    state.explicit_allow.remove(&key);
                    state.denied.insert(key);
                }
            }
            if state
                .denied
                .len()
                .saturating_add(state.explicit_allow.len())
                > MAX_INTENTS
            {
                *state = before;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "share-intent store exceeds its safety limit",
                ));
            }
            if let Err(error) = self.persist_state(&state) {
                *state = before;
                return Err(error);
            }
        }
        // Stamped even when nothing changed: a re-share of an already-allowed
        // file is still newer than a deny queued before it.
        for (hash, _) in &updates {
            write_seq.insert(*hash, seq);
        }
        Ok(!in_effect)
    }

    pub fn enter_fail_closed(&self) -> io::Result<()> {
        self.mutate(|state| {
            state.catalog_seen = true;
            note_fail_closed_entered(state);
            Ok(())
        })?;
        FORCE_UNSHARED.store(false, Ordering::Release);
        Ok(())
    }

    pub fn mark_catalog_seen(&self) -> io::Result<()> {
        if self.state.read().catalog_seen {
            return Ok(());
        }
        self.mutate(|state| {
            state.catalog_seen = true;
            Ok(())
        })
    }

    pub fn note_catalog_missing(&self) -> io::Result<()> {
        let state = self.state.read();
        if !state.catalog_seen || state.fail_closed {
            return Ok(());
        }
        drop(state);
        self.enter_fail_closed()
    }

    pub fn is_fail_closed(&self) -> bool {
        self.state.read().fail_closed
    }
}

/// Synchronous form of [`initialize_in_background`].
#[cfg(test)]
pub fn initialize(data_dir: &Path) -> io::Result<Arc<ShareIntentStore>> {
    let path = data_dir.join(STATE_FILE);
    let mut state = read_persisted(&path)?;
    absorb_known_catalog(data_dir, &mut state);
    install(path, state)
}

/// Initialize the independent share-intent store and migrate every existing
/// known.met `is_shared=false` record. If known.met existed previously but is
/// now absent or corrupt, the durable store enters fail-closed mode.
///
/// share_intent.json is read and rewritten on the calling thread, so an
/// unreadable or unwritable store stays fatal to startup. The known.met
/// migration (a parse of up to 256 MiB) runs on its own thread; until it lands,
/// [`global`] — and with it every share-state read and write — blocks rather
/// than answer from a state missing the catalog's unshared records. If the
/// migration cannot be persisted, the store settles as failed and sharing
/// stays fail-closed for the session.
pub fn initialize_in_background(data_dir: &Path) -> io::Result<()> {
    let path = data_dir.join(STATE_FILE);
    let mut state = read_persisted(&path)?;
    write_state(&path, &state)?;
    let pending = PendingInit::begin();
    let data_dir = data_dir.to_path_buf();
    std::thread::Builder::new()
        .name("share-intent-init".into())
        .spawn(move || {
            absorb_known_catalog(&data_dir, &mut state);
            match install_pending(pending.generation, path, state) {
                Ok(()) => pending.disarm(),
                Err(error) => {
                    tracing::error!("Failed to persist migrated share intent: {error}")
                }
            }
        })?;
    Ok(())
}

/// Block until a background [`initialize_in_background`] has settled. Returns
/// immediately when none is in flight. Lets blocking-pool callers absorb the
/// wait before they reach per-file [`effective_shared`] calls on an async task.
pub fn wait_until_initialized() {
    let _ = global();
}

/// Settles a background initialization that ends without installing a store
/// (persist failure, panic, or a thread that never started) as failed, so
/// waiters in [`global`] fall through to the fail-closed path instead of
/// hanging.
struct PendingInit {
    generation: u64,
}

impl PendingInit {
    fn begin() -> Self {
        let generation = NEXT_INIT_GENERATION.fetch_add(1, Ordering::Relaxed);
        global_slot().set(Slot::Pending(generation));
        Self { generation }
    }

    fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for PendingInit {
    fn drop(&mut self) {
        if global_slot().settle_pending(self.generation, Slot::Failed) {
            FORCE_UNSHARED.store(true, Ordering::Release);
            tracing::error!(
                "Share-intent initialization did not complete; sharing is disabled for this session"
            );
        }
    }
}

fn read_persisted(path: &Path) -> io::Result<PersistedShareIntent> {
    // Same interrupt window as identity/cryptkey: a parked backup with nothing
    // at `path` looks like a first run, and the persist that follows would then
    // restore the bak only to overwrite it with empty denied/allow sets.
    crate::security::recover_interrupted_replace(path);
    let state_existed = path.exists();
    let state = if state_existed {
        let data = std::fs::read(path)?;
        let parsed: PersistedShareIntent = serde_json::from_slice(&data)
            .map_err(|error| io_other(format!("parse share intent: {error}")))?;
        if parsed.version != STATE_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported share-intent version {}", parsed.version),
            ));
        }
        if parsed
            .denied
            .len()
            .saturating_add(parsed.explicit_allow.len())
            > MAX_INTENTS
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "share-intent store exceeds its safety limit",
            ));
        }
        parsed
    } else {
        PersistedShareIntent::default()
    };
    Ok(state)
}

fn absorb_known_catalog(data_dir: &Path, state: &mut PersistedShareIntent) {
    let known_path = data_dir.join("known.met");
    // `load_checked` restores a parked replace backup itself, but only after
    // the existence probe below. Probing first would read a restored catalog
    // as missing and, with `catalog_seen`, persist fail-closed for good.
    crate::security::recover_interrupted_replace(&known_path);
    let known_existed = known_path.exists();
    match crate::storage::known_files::KnownFileList::load_checked(&known_path) {
        Ok(known) if known_existed => {
            state.catalog_seen = true;
            for record in known.all_records().filter(|record| !record.is_shared) {
                let key = normalize_hash(&record.file_hash);
                state.explicit_allow.remove(&key);
                state.denied.insert(key);
            }
            // The unshares and restrictions past the readable part are gone
            // with it, as for a catalog that could not be read at all.
            if known.lost_records() {
                tracing::error!("known.met read only in part; enabling fail-closed sharing");
                note_fail_closed_entered(state);
            }
        }
        Ok(_) => {
            if state.catalog_seen {
                note_fail_closed_entered(state);
            }
        }
        Err(error) => {
            tracing::error!(
                "known.met security-state load failed: {error}; enabling fail-closed sharing"
            );
            // A corrupt existing catalog is proof of prior state even on the
            // feature's first migration run.
            if known_existed || state.catalog_seen {
                state.catalog_seen = true;
                note_fail_closed_entered(state);
            }
        }
    }
}

/// Set once this process has put sharing into fail-closed mode, for the
/// notice that tells the user why their files are unshared.
static FAIL_CLOSED_THIS_SESSION: AtomicBool = AtomicBool::new(false);

fn note_fail_closed_entered(state: &mut PersistedShareIntent) {
    if !state.fail_closed {
        FAIL_CLOSED_THIS_SESSION.store(true, Ordering::Release);
    }
    state.fail_closed = true;
}

/// Whether this process lost the file catalog (damaged, or gone after it had
/// been seen) and so began failing closed: no file is offered unless the user
/// shared it themselves. Not set by a store already failing closed at launch.
pub fn fail_closed_this_session() -> bool {
    FAIL_CLOSED_THIS_SESSION.load(Ordering::Acquire)
}

fn persisted_store(
    path: std::path::PathBuf,
    state: PersistedShareIntent,
) -> io::Result<Arc<ShareIntentStore>> {
    let store = Arc::new(ShareIntentStore {
        path,
        state: parking_lot::RwLock::new(state),
        write_seq: parking_lot::Mutex::new(HashMap::new()),
    });
    store.persist_state(&store.state.read())?;
    Ok(store)
}

#[cfg(test)]
fn install(
    path: std::path::PathBuf,
    state: PersistedShareIntent,
) -> io::Result<Arc<ShareIntentStore>> {
    let store = persisted_store(path, state)?;
    global_slot().set(Slot::Ready(store.clone()));
    Ok(store)
}

/// Persist and install the store for `generation`. A superseded
/// initialization neither writes nor installs.
fn install_pending(
    generation: u64,
    path: std::path::PathBuf,
    state: PersistedShareIntent,
) -> io::Result<()> {
    if !matches!(*global_slot().slot.read(), Slot::Pending(current) if current == generation) {
        return Ok(());
    }
    let store = persisted_store(path, state)?;
    global_slot().settle_pending(generation, Slot::Ready(store));
    Ok(())
}

/// The installed store. While [`initialize_in_background`] is still migrating
/// known.met this blocks until it settles.
pub fn global() -> io::Result<Arc<ShareIntentStore>> {
    let global = global_slot();
    if let Some(result) = global.resolved() {
        return result;
    }
    let mut settle = global.settle.lock();
    loop {
        if let Some(result) = global.resolved() {
            return result;
        }
        global.settled.wait(&mut settle);
    }
}

pub fn effective_shared(hash: &[u8; 16], catalog_value: bool) -> bool {
    if FORCE_UNSHARED.load(Ordering::Acquire) {
        return false;
    }
    global()
        .map(|store| store.effective_shared(hash, catalog_value))
        .unwrap_or(false)
}

/// Returns whether the store changed (and was persisted).
pub fn set_explicit_batch(updates: &[([u8; 16], bool)]) -> io::Result<bool> {
    global()?.set_explicit_batch(updates)
}

/// See [`ShareIntentStore::set_explicit_batch_unless_newer`].
pub fn set_explicit_batch_unless_newer(
    updates: &[([u8; 16], bool)],
    ticket: u64,
) -> io::Result<bool> {
    global()?.set_explicit_batch_unless_newer(updates, ticket)
}

/// Enter durable fail-closed mode. If persistence fails, latch a process-local
/// unshared-all flag so rediscovery cannot publish until the store recovers.
pub fn enter_fail_closed() -> io::Result<()> {
    match global()?.enter_fail_closed() {
        Ok(()) => Ok(()),
        Err(error) => {
            force_unshared_all();
            Err(error)
        }
    }
}

pub fn note_catalog_missing() -> io::Result<()> {
    match global()?.note_catalog_missing() {
        Ok(()) => Ok(()),
        Err(error) => {
            force_unshared_all();
            Err(error)
        }
    }
}

pub fn force_unshared_all() {
    FORCE_UNSHARED.store(true, Ordering::Release);
}

#[cfg(test)]
pub fn clear_force_unshared_for_tests() {
    FORCE_UNSHARED.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(fail_closed: bool) -> ShareIntentStore {
        ShareIntentStore {
            path: std::env::temp_dir().join(format!(
                "ember-share-intent-test-{}-{}.json",
                std::process::id(),
                rand::random::<u64>()
            )),
            state: parking_lot::RwLock::new(PersistedShareIntent {
                fail_closed,
                ..Default::default()
            }),
            write_seq: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn queued_deny_cannot_override_a_newer_share() {
        let store = test_store(false);
        let (reshared, untouched) = ([0x51; 16], [0x52; 16]);
        // The reconcile decides to deny both, but its write is deferred.
        let ticket = write_ticket();
        // Meanwhile the user re-shares one of them; an allow already in
        // effect still counts as the newer write.
        store.set_explicit_batch(&[(reshared, true)]).unwrap();
        store.set_explicit_batch(&[(reshared, true)]).unwrap();

        store
            .set_explicit_batch_unless_newer(&[(reshared, false), (untouched, false)], ticket)
            .unwrap();
        assert!(
            store.effective_shared(&reshared, false),
            "a deny queued before the re-share must not re-deny it"
        );
        assert!(
            !store.effective_shared(&untouched, true),
            "hashes nobody wrote since the ticket still get the deny"
        );

        // A write made after the stale one still applies normally.
        store.set_explicit_batch(&[(reshared, false)]).unwrap();
        assert!(!store.effective_shared(&reshared, true));
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn fail_closed_requires_explicit_allow() {
        let store = test_store(true);
        let hash = [0x42; 16];
        assert!(!store.effective_shared(&hash, true));
        store.set_explicit_batch(&[(hash, true)]).unwrap();
        assert!(store.effective_shared(&hash, false));
        store.set_explicit_batch(&[(hash, false)]).unwrap();
        assert!(!store.effective_shared(&hash, true));
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn deny_is_independent_of_catalog_value() {
        let store = test_store(false);
        let hash = [0x24; 16];
        store.set_explicit_batch(&[(hash, false)]).unwrap();
        assert!(!store.effective_shared(&hash, true));
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn batch_already_in_effect_is_not_persisted() {
        let store = test_store(false);
        let (a, b) = ([0x31; 16], [0x32; 16]);
        assert!(store.set_explicit_batch(&[(a, false), (b, true)]).unwrap());
        assert!(store.path.exists());
        std::fs::remove_file(&store.path).unwrap();

        assert!(!store.set_explicit_batch(&[(a, false), (b, true)]).unwrap());
        assert!(!store.set_explicit_batch(&[]).unwrap());
        assert!(
            !store.path.exists(),
            "a batch that changes nothing must not rewrite the store"
        );

        assert!(store.set_explicit_batch(&[(a, false), (b, false)]).unwrap());
        assert!(store.path.exists(), "a real change is still persisted");
        assert!(!store.effective_shared(&b, true));
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn force_unshared_blocks_even_without_durable_fail_closed() {
        let _lock = test_store_lock();
        clear_force_unshared_for_tests();
        let store = test_store(false);
        let hash = [0x11; 16];
        assert!(store.effective_shared(&hash, true));
        force_unshared_all();
        assert!(!effective_shared(&hash, true));
        clear_force_unshared_for_tests();
        let _ = std::fs::remove_file(&store.path);
    }

    fn save_catalog_with_unshared(base: &Path, hash: [u8; 16]) {
        use crate::storage::known_files::{KnownFileList, KnownFileRecord};
        let mut known = KnownFileList::new();
        known.add_or_update(KnownFileRecord {
            file_hash: hash,
            part_hashes: Vec::new(),
            file_name: "unshared.bin".into(),
            file_size: 4,
            file_path: base.join("unshared.bin").to_string_lossy().into_owned(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            modified_at: 1,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
            is_shared: false,
            friends_only: false,
            complete_sources: 0,
            last_ember_source_publish: 0,
            last_ember_keyword_publish: 0,
            media: None,
            media_scanned: false,
        });
        known.save(&base.join("known.met")).unwrap();
    }

    fn temp_base(label: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "ember-share-intent-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn migrates_unshared_known_record_and_detects_later_loss() {
        let _lock = test_store_lock();
        let base = temp_base("migration");
        let hash = [0x5a; 16];
        save_catalog_with_unshared(&base, hash);

        let migrated = initialize(&base).unwrap();
        assert!(!migrated.effective_shared(&hash, true));
        std::fs::remove_file(base.join("known.met")).unwrap();
        let after_loss = initialize(&base).unwrap();
        assert!(after_loss.is_fail_closed());
        assert!(!after_loss.effective_shared(&[0x77; 16], true));
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn initialize_restores_interrupted_replace_before_first_run_persist() {
        let _lock = test_store_lock();
        let base = std::env::temp_dir().join(format!(
            "ember-share-intent-recover-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let hash = [0x7e; 16];
        let first = initialize(&base).unwrap();
        first.set_explicit_batch(&[(hash, false)]).unwrap();
        assert!(!first.effective_shared(&hash, true));
        let path = base.join("share_intent.json");
        let bak = path.with_file_name("share_intent.json.ember-replace-bak");
        std::fs::rename(&path, &bak).unwrap();
        let restored = initialize(&base).unwrap();
        assert!(
            !restored.effective_shared(&hash, true),
            "denied hashes parked in the replace backup must survive a missing live file"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn background_initialize_migrates_catalog_before_readers_see_it() {
        let _lock = test_store_lock();
        let base = temp_base("background");
        let hash = [0x3c; 16];
        save_catalog_with_unshared(&base, hash);

        initialize_in_background(&base).unwrap();
        let store = global().unwrap();
        assert!(!store.effective_shared(&hash, true));
        assert!(!effective_shared(&hash, true));
        let _ = std::fs::remove_dir_all(base);
    }

    /// Tests that drive the slot by hand must not leave it `Pending` when they
    /// fail: every later `global()` caller in the test binary would hang.
    struct SlotReset;

    impl Drop for SlotReset {
        fn drop(&mut self) {
            global_slot().set(Slot::Uninitialized);
            clear_force_unshared_for_tests();
        }
    }

    #[test]
    fn global_waits_for_pending_initialization() {
        let _lock = test_store_lock();
        let _reset = SlotReset;
        let base = temp_base("pending");
        let pending = PendingInit::begin();
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || tx.send(global().is_ok()).unwrap());
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100)).is_err(),
            "readers must not observe a store before the catalog migration lands"
        );
        install_pending(
            pending.generation,
            base.join(STATE_FILE),
            PersistedShareIntent::default(),
        )
        .unwrap();
        pending.disarm();
        assert!(rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap());
        waiter.join().unwrap();
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn abandoned_initialization_settles_fail_closed() {
        let _lock = test_store_lock();
        let _reset = SlotReset;
        drop(PendingInit::begin());
        assert!(global().is_err());
        assert!(!effective_shared(&[0x19; 16], true));
    }

    #[test]
    fn stale_pending_guard_cannot_settle_a_newer_initialization() {
        let _lock = test_store_lock();
        let _reset = SlotReset;
        let base = temp_base("stale");
        let stale = PendingInit::begin();
        let current = PendingInit::begin();
        drop(stale);
        assert!(
            matches!(*global_slot().slot.read(), Slot::Pending(g) if g == current.generation)
        );
        install_pending(
            current.generation,
            base.join(STATE_FILE),
            PersistedShareIntent::default(),
        )
        .unwrap();
        current.disarm();
        assert!(global().is_ok());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn known_met_writes_wait_for_pending_initialization() {
        let _lock = test_store_lock();
        let _reset = SlotReset;
        let base = temp_base("write-gate");
        let pending = PendingInit::begin();
        let writer_base = base.clone();
        let writer = std::thread::spawn(move || {
            crate::storage::known_files::KnownFileList::new()
                .save(&writer_base.join("known.met"))
                .unwrap()
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            !base.join("known.met").exists(),
            "known.met must not be rewritten while the migration may be reading it"
        );
        install_pending(
            pending.generation,
            base.join(STATE_FILE),
            PersistedShareIntent::default(),
        )
        .unwrap();
        pending.disarm();
        writer.join().unwrap();
        assert!(base.join("known.met").exists());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn parked_catalog_backup_is_restored_before_the_missing_check() {
        let _lock = test_store_lock();
        let base = temp_base("parked-catalog");
        let hash = [0x6b; 16];
        save_catalog_with_unshared(&base, hash);
        initialize(&base).unwrap();
        std::fs::rename(
            base.join("known.met"),
            base.join("known.met.ember-replace-bak"),
        )
        .unwrap();
        let reopened = initialize(&base).unwrap();
        assert!(
            !reopened.is_fail_closed(),
            "a restorable catalog is not a lost one"
        );
        assert!(!reopened.effective_shared(&hash, true));
        let _ = std::fs::remove_dir_all(base);
    }
}
