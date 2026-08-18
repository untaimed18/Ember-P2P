use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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
}

static SHARE_INTENT: OnceLock<parking_lot::RwLock<Option<Arc<ShareIntentStore>>>> = OnceLock::new();

fn global_slot() -> &'static parking_lot::RwLock<Option<Arc<ShareIntentStore>>> {
    SHARE_INTENT.get_or_init(|| parking_lot::RwLock::new(None))
}

fn normalize_hash(hash: &[u8; 16]) -> String {
    hex::encode(hash)
}

fn io_other(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

impl ShareIntentStore {
    fn persist_state(&self, state: &PersistedShareIntent) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(state)
            .map_err(|error| io_other(format!("serialize share intent: {error}")))?;
        crate::security::atomic_write(&self.path, &data, true)
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

    pub fn set_explicit_batch(&self, updates: &[([u8; 16], bool)]) -> io::Result<()> {
        self.mutate(|state| {
            for (hash, shared) in updates {
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
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "share-intent store exceeds its safety limit",
                ));
            }
            Ok(())
        })
    }

    pub fn enter_fail_closed(&self) -> io::Result<()> {
        self.mutate(|state| {
            state.catalog_seen = true;
            state.fail_closed = true;
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

    #[cfg(test)]
    pub fn is_fail_closed(&self) -> bool {
        self.state.read().fail_closed
    }
}

/// Initialize the independent share-intent store and migrate every existing
/// known.met `is_shared=false` record. If known.met existed previously but is
/// now absent or corrupt, the durable store enters fail-closed mode.
pub fn initialize(data_dir: &Path) -> io::Result<Arc<ShareIntentStore>> {
    let path = data_dir.join(STATE_FILE);
    // Same interrupt window as identity/cryptkey: a parked backup with nothing
    // at `path` looks like a first run, and `persist_state` below would then
    // restore the bak only to overwrite it with empty denied/allow sets.
    crate::security::recover_interrupted_replace(&path);
    let state_existed = path.exists();
    let mut state = if state_existed {
        let data = std::fs::read(&path)?;
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

    let known_path = data_dir.join("known.met");
    let known_existed = known_path.exists();
    match crate::storage::known_files::KnownFileList::load_checked(&known_path) {
        Ok(known) if known_existed => {
            state.catalog_seen = true;
            for record in known.all_records().filter(|record| !record.is_shared) {
                let key = normalize_hash(&record.file_hash);
                state.explicit_allow.remove(&key);
                state.denied.insert(key);
            }
        }
        Ok(_) => {
            if state.catalog_seen {
                state.fail_closed = true;
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
                state.fail_closed = true;
            }
        }
    }

    let store = Arc::new(ShareIntentStore {
        path,
        state: parking_lot::RwLock::new(state),
    });
    store.persist_state(&store.state.read())?;
    *global_slot().write() = Some(store.clone());
    Ok(store)
}

pub fn global() -> io::Result<Arc<ShareIntentStore>> {
    global_slot().read().clone().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "share-intent store is not initialized",
        )
    })
}

pub fn effective_shared(hash: &[u8; 16], catalog_value: bool) -> bool {
    if FORCE_UNSHARED.load(Ordering::Acquire) {
        return false;
    }
    global()
        .map(|store| store.effective_shared(hash, catalog_value))
        .unwrap_or(false)
}

pub fn set_explicit_batch(updates: &[([u8; 16], bool)]) -> io::Result<()> {
    global()?.set_explicit_batch(updates)
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
        }
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
    fn force_unshared_blocks_even_without_durable_fail_closed() {
        clear_force_unshared_for_tests();
        let store = test_store(false);
        let hash = [0x11; 16];
        assert!(store.effective_shared(&hash, true));
        force_unshared_all();
        assert!(!effective_shared(&hash, true));
        clear_force_unshared_for_tests();
        let _ = std::fs::remove_file(&store.path);
    }

    #[test]
    fn migrates_unshared_known_record_and_detects_later_loss() {
        use crate::storage::known_files::{KnownFileList, KnownFileRecord};
        let base = std::env::temp_dir().join(format!(
            "ember-share-intent-migration-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let hash = [0x5a; 16];
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
        });
        known.save(&base.join("known.met")).unwrap();

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
}
