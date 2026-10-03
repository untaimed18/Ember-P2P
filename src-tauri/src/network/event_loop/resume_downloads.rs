//! Resuming the incomplete downloads restored from the database once their
//! `.part` progress has been read: recovering interrupted verifications,
//! registering each for sources and KAD publishing, and starting the active
//! ones.

use super::*;

/// What the blocking pool read from a restored download's `.part`.
pub(in crate::network) struct RestoredPart {
    /// The download folder whose `Temp` holds it, which is not the current
    /// one for a download started before the download folder changed.
    folder: PathBuf,
    completed_bytes: u64,
    preview_ready: bool,
    all_complete: bool,
}

/// Keyed by transfer id, with an entry exactly when the `.part` existed.
pub(in crate::network) type RestoredParts = HashMap<String, RestoredPart>;

/// Read each restored download's `.part` from whichever download folder holds
/// it. Blocking.
fn read_restored_parts(
    folders: &crate::storage::part_folders::DownloadFolders,
    jobs: Vec<(String, u64, String)>,
) -> RestoredParts {
    let mut map = HashMap::new();
    for (id, total, name) in jobs {
        let folder = folders.part_folder_for(&id);
        let part_path = folder.join("Temp").join(format!("{id}.part"));
        if part_path.exists() && total > 0 {
            let tracker = crate::network::ed2k::part_tracker::PartTracker::new(total, &part_path);
            map.insert(
                id,
                RestoredPart {
                    folder,
                    completed_bytes: tracker.completed_bytes(),
                    preview_ready: tracker.is_preview_ready(&name, total),
                    all_complete: tracker.all_complete(),
                },
            );
        }
    }
    map
}

#[allow(clippy::too_many_arguments)]
pub(in crate::network) async fn resume_incomplete_downloads(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    db: &Arc<Database>,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    known_files: &KnownFileList,
    known_met_ready: bool,
    part_progress_map: &mut Option<RestoredParts>,
    part_progress_task: &mut Option<tokio::task::JoinHandle<RestoredParts>>,
    pending_incomplete_downloads: &mut Option<Vec<Transfer>>,
    startup_download_admission: &mut Option<tokio::sync::OwnedMutexGuard<()>>,
    upload_queue: &ed2k::upload::UploadQueueRef,
) {
    if let Some(pending) = pending_incomplete_downloads
        .as_ref()
        .filter(|_| part_progress_task.is_none() && part_progress_map.is_none())
    {
        let folders = settings.download_folders();
        let jobs: Vec<(String, u64, String)> = pending
            .iter()
            .map(|t| (t.id.clone(), t.total_size, t.file_name.clone()))
            .collect();
        *part_progress_task = Some(tokio::task::spawn_blocking(move || {
            read_restored_parts(&folders, jobs)
        }));
    }
    if let Some(handle) = part_progress_task.as_mut() {
        if handle.is_finished() {
            match part_progress_task.take().unwrap().await {
                Ok(map) => *part_progress_map = Some(map),
                Err(e) => {
                    warn!("Part progress restore task panicked: {e}");
                    *part_progress_map = Some(std::collections::HashMap::new());
                }
            }
        }
    }

    if pending_incomplete_downloads.is_some()
        && part_progress_map.is_some()
        && known_met_ready
    {
        let incomplete = pending_incomplete_downloads.take().unwrap();
        let progress_map = part_progress_map.take().unwrap();
        let count = incomplete.len();
        info!("Resuming {count} incomplete downloads from previous session");
        let dl_folder = settings.download_folder.clone();
        let mut restore_db_writes: Vec<Transfer> = Vec::new();
        let resume_restricted = {
            let index = local_index.read().await;
            collect_friends_only_hashes(&index, known_files)
        };
        for mut transfer in incomplete {
            // Hash-failed downloads are restored only to keep their Temp
            // `.part` owned (orphan sweep). Do not auto-start them.
            if transfer.status == TransferStatus::Failed {
                let mut mgr = transfer_manager.write().await;
                mgr.completed.push(transfer);
                if mgr.completed.len() > 1000 {
                    let keep_from = mgr.completed.len() - 1000;
                    mgr.completed.drain(..keep_from);
                }
                continue;
            }

            let control = TransferControl::new();
            if matches!(
                transfer.status,
                TransferStatus::Paused | TransferStatus::Stopped
            ) {
                control.pause();
            }

            // The map has an entry exactly when the `.part` existed and the
            // size was known as the blocking pool read it. Asking the disk
            // again here would cost a stat per download on the network loop.
            let restored = progress_map.get(&transfer.id);
            let part_folder = restored
                .map(|part| part.folder.clone())
                .unwrap_or_else(|| PathBuf::from(&dl_folder));
            let part_path = part_folder
                .join("Temp")
                .join(format!("{}.part", transfer.id));
            if let Some(&RestoredPart {
                completed_bytes,
                preview_ready,
                ..
            }) = restored
            {
                // `completed_bytes` is the on-disk figure, so it restores
                // Completed and drives progress. Transferred takes it as a
                // floor only: the real cumulative wire total is in the
                // `.part.met` and lands once the resumed download reports
                // progress, and claiming a smaller number here would make
                // the column jump backwards.
                transfer.completed_size = completed_bytes;
                transfer.transferred = transfer.transferred.max(completed_bytes);
                transfer.progress =
                    ((completed_bytes as f64 / transfer.total_size as f64) * 100.0).min(100.0);
                control.set_preview_ready(preview_ready);
            }

            // If the app crashed during Verifying/Completing, handle locally
            // instead of waiting for source discovery.
            if matches!(
                transfer.status,
                TransferStatus::Verifying | TransferStatus::Completing
            ) {
                let safe_name = crate::security::sanitize_filename(&transfer.file_name);
                let final_path = PathBuf::from(&dl_folder).join("Downloads").join(&safe_name);

                if !part_path.exists() && final_path.exists() {
                    // The .part is gone and a file with the target name
                    // exists. That usually means completion already moved
                    // the verified file and the app crashed before writing
                    // the terminal status. But a *pre-existing, unrelated*
                    // file of the same name would also satisfy this check,
                    // so re-hash the file and confirm it matches this
                    // transfer's ed2k hash before recording success —
                    // otherwise we'd mark a download complete against the
                    // wrong content (and Open/Reveal would point at it).
                    // Verify off the network task — do not await a full-file
                    // hash before the event loop can drain IPC.
                    let expected = transfer.file_hash.clone();
                    let expected_aich = transfer.expected_aich.clone();
                    // The Ember content pin is persisted on the transfer, so
                    // a crash is no reason to finish a pinned download
                    // without it: MD4 alone is what the pin exists to
                    // distrust, and completing here also lets the digest of
                    // whatever is on disk be written back to `known.met` as
                    // this file's official Ember hash.
                    let expected_ember = transfer.ember_file_hash.clone();
                    let ember_pinned = expected_ember.is_some();
                    let verify_path = final_path.clone();
                    let allowed_root = dl_folder.clone();
                    let tid = transfer.id.clone();
                    let tid_handle = tid.clone();
                    let tx = dl_event_tx.clone();
                    transfer.status = TransferStatus::Verifying;
                    transfer.speed = 0;
                    restore_db_writes.push(transfer.clone());
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.active.insert(tid.clone(), transfer);
                        mgr.register_control(&tid, control);
                    }
                    let handle = tokio::spawn(async move {
                        // `Ok(())` verified, `Err(msg)` mismatched, and the
                        // outer `None` means the file could not be read at
                        // all. Which check failed decides whether this is
                        // worth retrying, so the reason travels with it.
                        let verdict = tokio::task::spawn_blocking(move || {
                            let verified_path =
                                crate::security::filesystem::verify_existing_path(
                                    &verify_path,
                                    &[allowed_root],
                                )
                                .ok()?;
                            // All three digests from one read. Checked one
                            // at a time, this walked a restored multi-GB
                            // file up to three times over — and a restore
                            // re-verification is the moment a user is
                            // waiting to learn whether their file survived.
                            static NEVER: std::sync::atomic::AtomicBool =
                                std::sync::atomic::AtomicBool::new(false);
                            let mut file = std::fs::File::open(&verified_path).ok()?;
                            let digests = ed2k::hash::hash_open_file_digests_cancellable(
                                &mut file,
                                ed2k::hash::WantedDigests {
                                    aich: expected_aich.is_some(),
                                    ember: expected_ember.is_some(),
                                },
                                &NEVER,
                            )
                            .ok()?;
                            if !digests.ed2k.eq_ignore_ascii_case(&expected) {
                                return Some(Err("Restored final file hash mismatch".to_string()));
                            }
                            if let Some(expected_aich) = expected_aich {
                                let actual = hex::encode(digests.aich.unwrap_or_default());
                                if !actual.eq_ignore_ascii_case(&expected_aich) {
                                    return Some(Err(format!(
                                        "Expected AICH hash mismatch (expected {expected_aich}, got {actual})"
                                    )));
                                }
                            }
                            if let Some(expected_ember) = expected_ember {
                                let actual = hex::encode(digests.ember.unwrap_or_default());
                                if !actual.eq_ignore_ascii_case(&expected_ember) {
                                    // Reopening parts cannot turn these bytes
                                    // into the content the pin names, so use
                                    // the message the live path uses and let
                                    // it be classified as permanent.
                                    return Some(Err(
                                        ed2k::transfer::EMBER_BLAKE3_MISMATCH_MSG.to_string(),
                                    ));
                                }
                            }
                            Some(Ok(()))
                        })
                        .await
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| {
                            Err("Restored final file could not be read".to_string())
                        });
                        match verdict {
                            Ok(()) => {
                                let _ = tx
                                    .send(DownloadEvent::Completed {
                                        transfer_id: tid,
                                        final_path: Some(
                                            final_path.to_string_lossy().into_owned(),
                                        ),
                                        part_hashes: Vec::new(),
                                        ember_verified: ember_pinned,
                                    })
                                    .await;
                            }
                            Err(error) => {
                                warn!(
                                    "Restored download {tid} failed re-verification: {error}"
                                );
                                let failure_kind = ed2k::transfer::classify_error(&error);
                                let _ = tx
                                    .send(DownloadEvent::Failed {
                                        transfer_id: tid,
                                        error,
                                        failure_kind,
                                    })
                                    .await;
                            }
                        }
                    });
                    state.download_handles.insert(tid_handle, handle);
                    continue;
                }


                if part_path.exists() && transfer.total_size > 0 {
                    let all_complete = restored.is_some_and(|part| part.all_complete);
                    if all_complete {
                        info!(
                            "Restored download {} was Verifying with complete .part — re-verifying locally",
                            transfer.id
                        );
                        let tid = transfer.id.clone();
                        let file_hash = transfer.file_hash.clone();
                        let file_name = transfer.file_name.clone();
                        let file_size = transfer.total_size;
                        let expected_aich = transfer.expected_aich.clone();
                        let expected_ember = transfer.ember_file_hash.clone();
                        let ember_pinned = expected_ember.is_some();
                        let dl_dir = PathBuf::from(&dl_folder);
                        let part_dir = part_folder.clone();
                        let tx = dl_event_tx.clone();
                        let dl_tid = tid.clone();
                        let dl_tid2 = tid.clone();

                        transfer.status = TransferStatus::Verifying;
                        transfer.speed = 0;
                        restore_db_writes.push(transfer.clone());
                        {
                            let mut mgr = transfer_manager.write().await;
                            mgr.active.insert(tid.clone(), transfer);
                            mgr.register_control(&tid, control);
                        }

                        if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
                            old_handle.abort();
                        }
                        let handle = tokio::spawn(async move {
                            let result = reverify_complete_part_file(
                                &dl_tid,
                                &file_hash,
                                &file_name,
                                file_size,
                                expected_aich.as_deref(),
                                expected_ember.as_deref(),
                                &part_dir,
                                &dl_dir,
                            )
                            .await;
                            match result {
                                Ok(final_path) => {
                                    let _ = tx
                                        .send(DownloadEvent::Completed {
                                            transfer_id: dl_tid,
                                            final_path: Some(
                                                final_path.to_string_lossy().into_owned(),
                                            ),
                                            // `reverify_complete_part_file` only
                                            // re-checks the whole-file ed2k hash,
                                            // not a per-part hashset.
                                            part_hashes: Vec::new(),
                                            ember_verified: ember_pinned,
                                        })
                                        .await;
                                }
                                Err(e) => {
                                    warn!("Re-verification of restored download failed: {e}");
                                    let kind = ed2k::transfer::classify_error(&e.to_string());
                                    let _ = tx
                                        .send(DownloadEvent::Failed {
                                            transfer_id: dl_tid,
                                            error: e.to_string(),
                                            failure_kind: kind,
                                        })
                                        .await;
                                }
                            }
                        });
                        state.download_handles.insert(dl_tid2, handle);
                        continue;
                    }
                }

                // .part exists but not all complete, or .part is missing and
                // no final file — fall through to normal restore as Searching
                transfer.status = TransferStatus::Searching;
            }

            TransferManager::normalize_restored_incomplete_download(&mut transfer);
            restore_db_writes.push(transfer.clone());

            let active_now = {
                let mut mgr = transfer_manager.write().await;
                let active_now = mgr.enqueue(transfer.clone());
                mgr.register_control(&transfer.id, control.clone());
                active_now
            };
            // Register in pending_downloads regardless of whether active
            // or queued. Queued downloads still need source discovery
            // (KAD searches, server queries, retry timer) so they have
            // sources ready when promoted. Insufficient stays out of
            // pending until Resume (eMule ResumeFileInsufficient) —
            // but the transfer remains in the manager so Temp orphan
            // sweep will not delete its `.part`.
            if (active_now
                || matches!(
                    transfer.status,
                    TransferStatus::Searching | TransferStatus::Queued
                ))
                && transfer.status != TransferStatus::Insufficient
            {
                insert_pending_download_bounded(&mut state.pending_downloads,
                    transfer.id.clone(),
                    PendingDownload {
                        transfer_id: transfer.id.clone(),
                        file_hash: transfer.file_hash.clone(),
                        file_name: transfer.file_name.clone(),
                        file_size: transfer.total_size,
                        expected_aich: transfer.expected_aich.clone(),
                        control,
                        search_count: 0,
                        last_search_at: None,
                        priority: priority_str_to_u32(&transfer.priority),
                    },
                );
            }

            // Register partial download for KAD source publishing
            if let Ok(hash_bytes) = hex::decode(&transfer.file_hash) {
                if hash_bytes.len() >= 16
                    && transfer_may_advertise_partial(known_files, &resume_restricted, &transfer)
                {
                    let ext = std::path::Path::new(&transfer.file_name)
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let mut raw = [0u8; 16];
                    raw.copy_from_slice(&hash_bytes[..16]);
                    state.publish_manager.add_file(PublishableFile {
                        file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                        file_name: transfer.file_name.clone(),
                        file_size: transfer.total_size,
                        file_type: crate::search::index::infer_file_type(&ext),
                        complete_sources: 0,
                        keyword_publishable: false,
                        last_source_publish: known_files
                            .find_by_hash(&raw)
                            .map(|r| r.last_publish_src as i64)
                            .unwrap_or(0),
                    });
                }
            }
        }
        if !restore_db_writes.is_empty() {
            let db_restore = db.clone();
            let writer = tokio::task::spawn_blocking(move || {
                for transfer in restore_db_writes {
                    if let Err(e) = db_restore.save_transfer(&transfer) {
                        if transfer.status == TransferStatus::Verifying {
                            warn!(
                                "DB save_transfer failed for verifying transfer {}: {e}",
                                transfer.id
                            );
                        } else {
                            warn!(
                                "Failed to persist normalized restored download {}: {e}",
                                transfer.id
                            );
                        }
                    }
                }
            });
            if let Err(e) = writer.await {
                warn!("Restore DB write batch failed: {e}");
            }
        }
        // Startup rows now occupy the manager and pending network map;
        // renderer admissions may safely continue against the same totals.
        startup_download_admission.take();
        transfer_manager.write().await.restored = true;
        ed2k::upload_queue_store::merge_when_ready(
            &mut state.restored_upload_queue,
            upload_queue,
            local_index,
            transfer_manager,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_restored_download_resumes_from_the_folder_it_started_in() {
        let base = std::env::temp_dir().join(format!(
            "ember-restore-parts-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let old = base.join("old");
        let new = base.join("new");
        for dir in [old.join("Temp"), new.join("Temp")] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(old.join("Temp").join("before-change.part"), vec![0u8; 100]).unwrap();
        std::fs::write(new.join("Temp").join("after-change.part"), vec![0u8; 100]).unwrap();
        let folders = crate::storage::part_folders::DownloadFolders::new(
            &new.to_string_lossy(),
            &[old.to_string_lossy().into_owned()],
        );
        let job = |id: &str| (id.to_string(), 100, format!("{id}.bin"));

        let restored = read_restored_parts(
            &folders,
            vec![job("before-change"), job("after-change"), job("never-started")],
        );

        assert_eq!(restored["before-change"].folder, old);
        assert_eq!(restored["after-change"].folder, new);
        assert!(
            !restored.contains_key("never-started"),
            "no `.part` anywhere: nothing to restore"
        );
        let _ = std::fs::remove_dir_all(base);
    }
}
