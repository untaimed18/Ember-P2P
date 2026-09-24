//! Background persistence: credits, `server.met`, `ipfilter.dat`, and the
//! AICH cache.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Cap on `pending_known2_sets`: recovery sets computed this session and not
/// yet appended to `known2_64.met`. The file itself has no cap (see
/// `ed2k::aich::Known2Store`); this only bounds what can pile up in memory if
/// appends keep failing, and a queue this deep means something is wrong.
pub(super) const MAX_AICH_HASH_SETS: usize = 10_000;

/// Soft cap on `aich_root_map` (ed2k → AICH root hash). At ~60 B per
/// entry, 100k mappings is ~6 MB — well within budget, but we log a
/// warning past this point so a runaway insert path is observable in
/// production logs without silently degrading corruption-recovery
/// integrity (eviction would risk losing the only trusted root for
/// a given file).
pub(super) const MAX_AICH_ROOT_MAP_SOFT_CAP: usize = 100_000;
pub(super) static AICH_CACHE_WRITE_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

pub(super) fn persist_aich_cache_entry(
    path: &Path,
    file_hash: [u8; 16],
    aich_hash: [u8; 20],
) -> std::io::Result<()> {
    let _guard = AICH_CACHE_WRITE_LOCK
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .map_err(|_| std::io::Error::other("AICH cache lock poisoned"))?;
    const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;
    let mut entries = std::collections::BTreeMap::<String, String>::new();
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > MAX_CACHE_BYTES => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "AICH cache exceeds size limit",
            ));
        }
        Ok(_) => {
            let contents = std::fs::read_to_string(path)?;
            for line in contents.lines() {
                let Some((file, root)) = line.split_once('=') else {
                    continue;
                };
                if file.len() == 32
                    && root.len() == 40
                    && file.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && root.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && entries.len() < MAX_AICH_ROOT_MAP_SOFT_CAP
                {
                    entries.insert(file.to_ascii_lowercase(), root.to_ascii_lowercase());
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    entries.insert(hex::encode(file_hash), hex::encode(aich_hash));
    if entries.len() > MAX_AICH_ROOT_MAP_SOFT_CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "AICH cache entry limit reached",
        ));
    }
    let mut output = String::with_capacity(entries.len().saturating_mul(74));
    for (file, root) in entries {
        output.push_str(&file);
        output.push('=');
        output.push_str(&root);
        output.push('\n');
    }
    crate::security::atomic_write(path, output.as_bytes(), true)
}

pub(super) async fn flush_credit_state(
    credit_manager: &Arc<RwLock<CreditManager>>,
    db: &Arc<Database>,
    data_dir: &std::path::Path,
    cleanup_stale: bool,
    save_ownership: &Arc<tokio::sync::Mutex<()>>,
) {
    // Serialize snapshot creation as well as persistence. If two callers
    // captured snapshots first and only serialized the writes, an older
    // snapshot could acquire the slot second and overwrite the newer flush.
    let ownership = save_ownership.clone().lock_owned().await;
    if cleanup_stale {
        let mut cm_w = credit_manager.write().await;
        cm_w.cleanup_stale(90);
    }

    // Skip the whole sequence when nothing has changed since the last
    // successful flush. It is expensive — DELETE plus full re-INSERT of both
    // credit tables, an `incremental_vacuum`, a `clients.met` copy and an
    // fsync'd rewrite — and this ran unconditionally every 60s, rewriting
    // byte-identical state ~1,440 times a day on a node whose peers had gone
    // quiet. The sweep above marks dirty when it evicts, so ageing still gets
    // persisted; the generation is captured after it for that reason.
    let flush_generation = {
        let cm = credit_manager.read().await;
        if !cm.is_dirty() {
            return;
        }
        cm.dirty_generation()
    };

    let (serialized_bytes, owned, ember_owned) = {
        let cm = credit_manager.read().await;
        let bytes = cm.serialize();
        let records: Vec<crate::storage::database::CreditRow> = cm
            .all_records()
            .iter()
            .map(|r| {
                (
                    r.user_hash,
                    r.uploaded,
                    r.downloaded,
                    r.last_seen,
                    r.public_key.clone(),
                    r.ident_ip,
                    r.ident_state.to_u8(),
                    r.ember_hash,
                    r.crypto_verified_once,
                    r.peer_name.clone(),
                    r.client_software.clone(),
                    r.seen_ip,
                )
            })
            .collect();
        // Snapshot the Ember table too. The columns are plain scalars
        // so an owned copy is cheap; holding the read lock only long
        // enough to clone keeps the upload dispatcher un-blocked
        // while the disk write runs below.
        let ember_records: Vec<([u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)> = cm
            .all_ember_records()
            .iter()
            .map(|r| {
                (
                    r.pub_key,
                    r.uploaded,
                    r.downloaded,
                    r.last_upload_time,
                    r.last_download_time,
                    r.completed_sessions,
                    r.total_sessions,
                    r.avg_upload_speed,
                    r.last_seen,
                    r.ident_verified,
                )
            })
            .collect();
        (bytes, records, ember_records)
    };
    // Own the save slot through the blocking DB/cache write itself. If the
    // async parent is aborted while spawn_blocking is running, this owned
    // guard remains inside the blocking closure, so shutdown cannot race a
    // newer snapshot against the still-running periodic write.
    let db_ref = db.clone();
    let data_dir = data_dir.to_path_buf();
    let save_result = tokio::task::spawn_blocking(move || {
        let _ownership = ownership;
        let refs: Vec<crate::storage::database::CreditRowRef<'_>> = owned
            .iter()
            .map(|(h, u, d, l, p, ip, st, eh, cv, name, software, seen)| {
                (
                    h,
                    *u,
                    *d,
                    *l,
                    p.as_slice(),
                    *ip,
                    *st,
                    eh.as_ref(),
                    *cv,
                    name.as_str(),
                    software.as_str(),
                    *seen,
                )
            })
            .collect();
        // Persist both credit tables in ONE SQLite transaction so they can
        // never diverge across a crash or partial failure.
        let ember_refs: Vec<(&[u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)> =
            ember_owned
                .iter()
                .map(|(pk, u, d, lu, ld, c, t, s, ls, v)| {
                    (pk, *u, *d, *lu, *ld, *c, *t, *s, *ls, *v)
                })
                .collect();
        // Persist SQLite first: it is authoritative on load. Only refresh the
        // clients.met cache after that transaction succeeds.
        let result = db_ref.save_all_credits_with_ember(&refs, &ember_refs);
        db_ref.incremental_vacuum();
        let mut cache_written = false;
        if result.is_ok() {
            let clients_met = data_dir.join("clients.met");
            let clients_bak = data_dir.join("clients.met.bak");
            if clients_met.exists() {
                if let Err(e) = std::fs::copy(&clients_met, &clients_bak) {
                    debug!("Failed to create clients.met backup: {e}");
                }
            }
            match crate::security::atomic_write(&clients_met, &serialized_bytes, false) {
                Ok(()) => cache_written = true,
                Err(e) => debug!("Failed to finalize clients.met: {e}"),
            }
        }
        (result, cache_written)
    })
    .await;
    match &save_result {
        Ok((Ok(()), cache_written)) => {
            if *cache_written {
                // Disk now matches the snapshot. A mutation that landed while
                // the blocking write ran bumped the generation, so the flag
                // stays set and the next tick persists it instead of dropping
                // it.
                credit_manager
                    .write()
                    .await
                    .mark_saved_if_generation(flush_generation);
            } else {
                debug!("clients.met cache write failed; keeping credits dirty for the next tick");
            }
        }
        Ok((Err(e), _)) => error!("Failed to save credits: {e}"),
        Err(e) => error!("Credit save task failed: {e}"),
    }
    if !matches!(save_result, Ok((Ok(()), _))) {
        debug!("Skipping clients.met cache write because the DB credit flush failed");
    }
}

pub(super) fn spawn_credit_flush(
    credit_manager: Arc<RwLock<CreditManager>>,
    db: Arc<Database>,
    data_dir: std::path::PathBuf,
    cleanup_stale: bool,
    save_ownership: Arc<tokio::sync::Mutex<()>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        flush_credit_state(
            &credit_manager,
            &db,
            &data_dir,
            cleanup_stale,
            &save_ownership,
        )
        .await;
    })
}

/// Serialize `server.met` on the network task, write it on the blocking pool
/// so select-arm saves don't stall UDP/timers/IPC on disk sync.
///
/// Each call bumps `generation`; a writer only commits if it is still the
/// latest generation when it reaches disk, so overlapping saves cannot
/// clobber newer metadata with an older snapshot.
pub(super) fn spawn_save_server_met(
    list: &ed2k::server_list::ServerList,
    path: PathBuf,
    generation: &std::sync::Arc<std::sync::atomic::AtomicU64>,
    save_lock: &std::sync::Arc<std::sync::Mutex<()>>,
) {
    let gen = generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    match list.to_server_met_bytes() {
        Ok(buf) => {
            let generation = generation.clone();
            let save_lock = save_lock.clone();
            tokio::task::spawn_blocking(move || {
                let _guard = match save_lock.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if generation.load(std::sync::atomic::Ordering::Relaxed) != gen {
                    return;
                }
                if let Err(e) = ed2k::server_list::ServerList::write_server_met_bytes(&path, &buf) {
                    warn!("Failed to save server.met: {e}");
                }
            });
        }
        Err(e) => warn!("Failed to serialize server.met: {e}"),
    }
}

/// Persist the live range list to `ipfilter.dat` after a manual edit.
///
/// Adding or removing a range used to touch memory only, so a range the user
/// blocked was gone after the next launch and one they deliberately unblocked
/// came back — a security control silently reverting while the Security page
/// reported success. Serialization happens here on the network task (cheap,
/// no I/O) and the write goes to the blocking pool.
pub(super) fn spawn_save_ipfilter_dat(ip_filter: &IpFilter, path: PathBuf) {
    // Never serialize a list that was never read. Startup skips the file
    // entirely while the filter is disabled, so writing the live (empty)
    // list would replace the user's whole downloaded blacklist with the one
    // range they just added. `ensure_ipfilter_loaded` normally makes this
    // unreachable; it stays as a hard stop against data loss.
    if !ip_filter.has_loaded_ranges() {
        warn!("Not writing ipfilter.dat: the persisted list was never loaded this session");
        return;
    }
    let bytes = ip_filter.canonical_dat_bytes();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::security::atomic_write(&path, &bytes, false) {
            warn!("Failed to persist ipfilter.dat after a manual range change: {e}");
        }
    });
}

/// Read `ipfilter.dat` into the live filter if it has not been read yet, so a
/// manual add/remove rewrites the full list rather than replacing it.
///
/// Loading while the filter is disabled is inert: every `is_blocked*` path
/// checks `enabled` before it consults the ranges.
pub(super) async fn ensure_ipfilter_loaded(state: &mut NetworkState) {
    if state.ip_filter.has_loaded_ranges() {
        return;
    }
    let path = state.data_dir.join("ipfilter.dat");
    if !path.exists() {
        // Nothing on disk to preserve, so the live list is authoritative.
        state.ip_filter.mark_loaded_from_disk();
        return;
    }
    let enabled = state.ip_filter.is_enabled();
    let block_private = state.ip_filter.blocks_private();
    let loaded = tokio::task::spawn_blocking(move || {
        let mut fresh = IpFilter::new(enabled, block_private);
        fresh.load_from_file(&path).map(|_| fresh)
    })
    .await
    .ok()
    .flatten();
    match loaded {
        Some(fresh) => {
            state.ip_filter.merge_ranges_from(&fresh);
            state.ip_filter.mark_loaded_from_disk();
        }
        None => warn!("Could not read ipfilter.dat before a manual range change"),
    }
}

/// Parse `ipfilter.dat` on the blocking pool when the filter is toggled on
/// without a prior disk load. The live filter stays fail-closed until this
/// succeeds; a zero-range or unreadable file leaves it that way.
pub(super) async fn load_ipfilter_on_enable(state: &mut NetworkState) {
    if !state.ip_filter.is_enabled() || state.ip_filter.has_loaded_ranges() {
        return;
    }
    let path = state.data_dir.join("ipfilter.dat");
    if !path.exists() {
        state.ip_filter.mark_ranges_ready();
        state
            .ip_filter
            .update_shared_snapshot(&state.shared_ip_filter);
        return;
    }
    let block_private = state.ip_filter.blocks_private();
    let loaded = tokio::task::spawn_blocking(move || {
        let mut fresh = IpFilter::new(true, block_private);
        match fresh.load_from_file(&path) {
            Some(n @ 1..) => {
                info!("Loaded {n} IP filter entries on enable");
                Some(fresh)
            }
            Some(0) => {
                warn!(
                    "ipfilter.dat contained no valid ranges on enable; leaving fail-closed until a successful reload"
                );
                None
            }
            None => {
                warn!(
                    "Failed to read ipfilter.dat on enable; leaving fail-closed until a successful reload"
                );
                None
            }
        }
    })
    .await;
    match loaded {
        Ok(Some(fresh)) => {
            state.ip_filter.merge_ranges_from(&fresh);
            state.ip_filter.mark_loaded_from_disk();
            state.ip_filter.mark_ranges_ready();
            info!(
                "IP filter enable load installed ({} ranges after merge)",
                state.ip_filter.range_count()
            );
            state
                .ip_filter
                .update_shared_snapshot(&state.shared_ip_filter);
            state.routing_table.evict_filtered_contacts();
            state.ember_dht.evict_filtered_contacts();
        }
        Ok(None) => {}
        Err(e) => {
            error!(
                "IP filter enable load task panicked: {e}; keeping previous filter"
            );
        }
    }
}

pub(super) struct DeferredDiskLoads {
    pub(super) ip_filter: IpFilter,
    pub(super) known_files: KnownFileList,
    pub(super) known2: Option<ed2k::aich::Known2Store>,
    pub(super) aich_root_map: HashMap<[u8; 16], [u8; 20]>,
}
