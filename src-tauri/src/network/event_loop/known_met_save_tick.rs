//! The periodic known.met save.

use super::*;

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn on_known_met_save_tick(
    state: &mut NetworkState,
    known_files: &mut KnownFileList,
    aich_set_rx: &mut mpsc::Receiver<ed2k::aich::AICHRecoveryHashSet>,
    known2_in_flight_len: &mut usize,
    known2_save_in_flight: &mut bool,
    known2_save_started_at: &mut Option<tokio::time::Instant>,
    known2_saved_len: Option<usize>,
    known_met_save_in_flight: &mut bool,
    known_met_save_result_tx: &mpsc::UnboundedSender<KnownMetSaveResult>,
    known_met_save_started_at: &mut Option<tokio::time::Instant>,
    periodic_save_result_tx: &mpsc::UnboundedSender<PeriodicSaveResult>,
) {
    if *known_met_save_in_flight
        && known_met_save_started_at
            .is_some_and(|started| started.elapsed() > std::time::Duration::from_secs(300))
    {
        warn!(
            "known.met save exceeded watchdog timeout; retaining serialized ownership and suppressing overlapping retries"
        );
    }
    sync_ember_publish_to_known(
        &state.ember_source_publish_unix,
        &state.ember_keyword_publish_unix,
        known_files,
    );
    // `is_authoritative` gates the attempt because this interval's
    // first tick fires immediately, roughly half a second before the
    // deferred known.met load lands. Without it every launch spent a
    // blocking task and the save lock on a write `save` then refused,
    // and reported the refusal back as `Ok(false)` — indistinguishable
    // from a genuine known_paths.dat durability failure, so the arm
    // below logged "save completed but companion was not durable"
    // immediately after `save` had logged that it skipped. Nothing was
    // lost either way (the catalog stays dirty and the next tick, by
    // which time the load has landed, writes it), but the pair of
    // contradictory warnings described a failure that never happened.
    // The `|| !exists` arm mirrors `save`'s own condition, which
    // refuses only when *both* hold. Gating on `is_authoritative`
    // alone would also block a genuine first run — where there is no
    // catalog on disk to protect and `save` would have written
    // happily — and because `authoritative` is only ever set by the
    // deferred load's absorb, a panic in that task would then skip
    // every periodic save for the rest of the session.
    if known_files.is_dirty()
        && (known_files.is_authoritative()
            || !state.data_dir.join("known.met").exists())
        && !*known_met_save_in_flight
    {
        let ownership = state
            .known_met_save_lock
            .clone()
            .lock_owned()
            .await;
        let known_path = state.data_dir.join("known.met");
        let generation = known_files.dirty_generation();
        let mut snapshot = known_files.clone();
        let tx = known_met_save_result_tx.clone();
        *known_met_save_in_flight = true;
        *known_met_save_started_at = Some(tokio::time::Instant::now());
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let _ownership = ownership;
                snapshot.save(&known_path).map(|_| !snapshot.is_dirty())
            })
            .await
            .map_err(|e| anyhow::anyhow!("known.met save task failed: {e}"))
            .and_then(|r| r);
            let _ = tx.send(KnownMetSaveResult { generation, result });
        });
    }
    while let Ok(hs) = aich_set_rx.try_recv() {
        // Cap aich_hash_sets to a sane upper bound. The
        // recovery sets are persisted to known2_64.met and
        // grow with the local file corpus; in normal use
        // this is bounded by user activity, but a buggy
        // hashing path or a maliciously-named file ingested
        // through the indexer could in principle insert
        // without limit. We refuse new sets past the cap
        // (rather than evicting) because dropping a stored
        // set risks losing the only AICH root we trust for
        // a file — eviction would silently downgrade
        // corruption-recovery integrity.
        if state.aich_hash_sets.len() >= MAX_AICH_HASH_SETS {
            warn!(
                "aich_hash_sets at cap ({}), dropping new set for root {}",
                MAX_AICH_HASH_SETS,
                hex::encode(hs.root_hash),
            );
            continue;
        }
        state.aich_hash_sets.push(hs);
    }
    // Gated on the set having actually grown, the way the
    // `known.met` save above is gated on `is_dirty()`. Unconditional,
    // this deep-cloned the whole recovery corpus on the event loop,
    // re-serialised it in the blocking task and rewrote the file
    // every 120s for the life of the session — at the loader's
    // 64 MiB ceiling, tens of GiB of writes a day to persist bytes
    // already on disk.
    if !state.aich_hash_sets.is_empty()
        && known2_saved_len != Some(state.aich_hash_sets.len())
        && !*known2_save_in_flight
    {
        let known2_path = state.data_dir.join("known2_64.met");
        let hash_sets = state.aich_hash_sets.clone();
        *known2_in_flight_len = hash_sets.len();
        let tx = periodic_save_result_tx.clone();
        *known2_save_in_flight = true;
        *known2_save_started_at = Some(tokio::time::Instant::now());
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                ed2k::aich::save_known2_met(&known2_path, &hash_sets)
                    .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| format!("known2_64.met save task failed: {e}"))
            .and_then(|r| r);
            let _ = tx.send(PeriodicSaveResult {
                job: PeriodicSaveJob::Known2,
                result,
            });
        });
    }

    // Visibility for the other AICH cache. Same eviction-is-
    // unsafe argument applies, so we surface a soft warning
    // instead of silently dropping entries — operators
    // running pathological libraries will see the log and
    // can intervene (split shares, increase the cap).
    if state.aich_root_map.len() >= MAX_AICH_ROOT_MAP_SOFT_CAP {
        warn!(
            "aich_root_map size {} above soft cap {}; \
             consider trimming the file library",
            state.aich_root_map.len(),
            MAX_AICH_ROOT_MAP_SOFT_CAP,
        );
    }
}
