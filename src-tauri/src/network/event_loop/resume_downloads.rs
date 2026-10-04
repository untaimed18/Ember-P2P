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

/// What the blocking pool learned about the restored downloads.
#[derive(Default)]
pub(in crate::network) struct RestoredParts {
    /// Keyed by transfer id, with an entry exactly when the `.part` existed.
    parts: HashMap<String, RestoredPart>,
    /// Completion copies of the whole file's size an earlier run left, each
    /// with the download folder it is in. Such a download is checked against
    /// them before it may resume: one may be its only complete copy.
    copies: HashMap<String, Vec<(PathBuf, String)>>,
    /// Where each download's part files were found.
    found: Vec<(String, String)>,
}

/// A restored download, as reading its part files needs it.
struct RestoreJob {
    id: String,
    total_size: u64,
    file_name: String,
    failed: bool,
}

/// Restored downloads whose finished copy is being checked, each with the
/// status it goes back to when the copy is not its file.
static COPY_CHECKS: parking_lot::Mutex<Option<HashMap<String, TransferStatus>>> =
    parking_lot::Mutex::new(None);

fn note_copy_check(transfer_id: &str, status: TransferStatus) {
    COPY_CHECKS
        .lock()
        .get_or_insert_with(HashMap::new)
        .insert(transfer_id.to_string(), status);
}

/// The status a restored download had before its finished copy was checked,
/// when this failure is that check's: the copy is no evidence against any
/// source, and a download the user had paused or stopped stays so.
pub(in crate::network) fn take_copy_check(transfer_id: &str) -> Option<TransferStatus> {
    COPY_CHECKS.lock().as_mut()?.remove(transfer_id)
}

/// What one listing of a download folder holds for the restore.
struct RootListing {
    parts: Option<HashSet<String>>,
    copies: Vec<(String, PathBuf)>,
}

#[cfg(test)]
static LISTED_ROOTS: parking_lot::Mutex<Vec<PathBuf>> = parking_lot::Mutex::new(Vec::new());

impl RootListing {
    /// `copies` says whether to list `Downloads` for completion copies. Only a
    /// completion across volumes makes one, or any completion on macOS, which
    /// copies even on one volume: with a single download folder elsewhere
    /// nothing can have, and listing what may be a huge `Downloads` on a
    /// share held up every restore for nothing.
    fn read(root: &Path, copies: bool) -> Self {
        #[cfg(test)]
        LISTED_ROOTS.lock().push(root.to_path_buf());
        Self {
            parts: crate::storage::part_folders::part_names(root),
            copies: if copies {
                ed2k::transfer::earlier_completion_copies(&root.join("Downloads"))
            } else {
                Vec::new()
            },
        }
    }

    /// [`Self::read`] for the current folder, whose part files are never
    /// unknown: when its `Temp` cannot be listed, each download's are looked
    /// up by name, as they were before there were earlier folders.
    fn read_current(root: &Path, jobs: &[RestoreJob], copies: bool) -> Self {
        let mut listing = Self::read(root, copies);
        if listing.parts.is_none() {
            let temp = root.join("Temp");
            listing.parts = Some(
                jobs.iter()
                    .flat_map(|job| [format!("{}.part", job.id), format!("{}.part.met", job.id)])
                    .filter(|name| temp.join(name).exists())
                    .collect(),
            );
        }
        listing
    }
}

/// Read each restored download's `.part` from whichever download folder holds
/// it, listing every folder once. The current folder is listed for as long
/// as it takes; the earlier ones in parallel with it, for at most `budget`.
/// One found nowhere is taken to be in the folder `recorded` last saw it
/// in, so a worker waits for that folder if it is offline.
///
/// A completion copy shorter than the file, or one of a download that failed
/// verification, is removed while the `.part` it was made from is there, and
/// kept beside one started since; one of the file's size is left for the
/// resume to check. Blocking.
fn read_restored_parts(
    folders: &crate::storage::part_folders::DownloadFolders,
    jobs: Vec<RestoreJob>,
    recorded: &HashMap<String, String>,
    budget: std::time::Duration,
) -> RestoredParts {
    let roots = folders.roots();
    let paths: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
    let Some((current, earlier)) = paths.split_first() else {
        return restore_from_listings(&roots, &[], jobs, recorded);
    };
    let copies = !earlier.is_empty() || cfg!(target_os = "macos");
    let listings: Vec<Option<RootListing>> = std::thread::scope(|scope| {
        let listing_earlier = (!earlier.is_empty()).then(|| {
            scope.spawn(|| {
                crate::storage::part_folders::probe_within(earlier, budget, |root| {
                    RootListing::read(root, true)
                })
            })
        });
        let current = RootListing::read_current(current, &jobs, copies);
        let earlier_listings = match listing_earlier {
            Some(listing) => listing
                .join()
                .unwrap_or_else(|_| earlier.iter().map(|_| None).collect()),
            None => Vec::new(),
        };
        std::iter::once(Some(current)).chain(earlier_listings).collect()
    });
    restore_from_listings(&roots, &listings, jobs, recorded)
}

/// [`read_restored_parts`] given `listings[i]` of `roots[i]`, `None` for one
/// that did not answer.
fn restore_from_listings(
    roots: &[String],
    listings: &[Option<RootListing>],
    jobs: Vec<RestoreJob>,
    recorded: &HashMap<String, String>,
) -> RestoredParts {
    use crate::storage::part_folders::{names_hold, same_folder};
    let paths: Vec<PathBuf> = roots.iter().map(PathBuf::from).collect();
    let mut copies: HashMap<String, Vec<(PathBuf, usize)>> = HashMap::new();
    for (index, listing) in listings.iter().enumerate() {
        for (stem, path) in listing.iter().flat_map(|listing| &listing.copies) {
            copies.entry(stem.clone()).or_default().push((path.clone(), index));
        }
    }
    let mut restored = RestoredParts::default();
    for job in jobs {
        let found = listings.iter().position(|listing| {
            listing
                .as_ref()
                .and_then(|l| l.parts.as_ref())
                .is_some_and(|names| names_hold(names, &job.id))
        });
        match found {
            Some(index) => {
                crate::storage::part_folders::note_located(&job.id, &paths[index]);
                restored.found.push((job.id.clone(), roots[index].clone()));
                let part_path = paths[index].join("Temp").join(format!("{}.part", job.id));
                let has_part = listings[index]
                    .as_ref()
                    .and_then(|l| l.parts.as_ref())
                    .is_some_and(|names| names.contains(&format!("{}.part", job.id)));
                if has_part && job.total_size > 0 {
                    let tracker = crate::network::ed2k::part_tracker::PartTracker::new(
                        job.total_size,
                        &part_path,
                    );
                    restored.parts.insert(
                        job.id.clone(),
                        RestoredPart {
                            folder: paths[index].clone(),
                            completed_bytes: tracker.completed_bytes(),
                            preview_ready: tracker.is_preview_ready(&job.file_name, job.total_size),
                            all_complete: tracker.all_complete(),
                        },
                    );
                }
            }
            None => {
                if let Some(recorded) = recorded
                    .get(&job.id)
                    .filter(|recorded| roots.iter().any(|root| same_folder(root, recorded)))
                {
                    crate::storage::part_folders::note_located(&job.id, Path::new(recorded))
                }
            }
        }
        let part_files = found.map(|index| {
            let temp = paths[index].join("Temp");
            std::fs::symlink_metadata(temp.join(format!("{}.part", job.id)))
                .or_else(|_| std::fs::symlink_metadata(temp.join(format!("{}.part.met", job.id))))
        });
        for (path, index) in copies.remove(&job.id).unwrap_or_default() {
            let Ok(copy) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if copy.len() == job.total_size && !job.failed {
                restored
                    .copies
                    .entry(job.id.clone())
                    .or_default()
                    .push((path, roots[index].clone()));
                continue;
            }
            let made_from_part = part_files.as_ref().is_some_and(|part| {
                part.as_ref()
                    .is_ok_and(|part| ed2k::transfer::made_before(part, &copy))
            });
            if !made_from_part {
                continue;
            }
            match crate::security::filesystem::remove_approved_file(
                &path,
                std::slice::from_ref(&roots[index]),
            ) {
                Ok(()) => info!("Removed interrupted completion copy {}", path.display()),
                Err(e) => warn!("Could not remove completion copy {}: {e}", path.display()),
            }
        }
    }
    restored
}

/// Whether the file `file` holds is the one this download pins: its ed2k
/// hash and, where known, its AICH root and Ember content hash, all from one
/// read. `Err` says which one did not match.
fn verify_restored_file(
    file: &mut std::fs::File,
    expected: &str,
    expected_aich: Option<&str>,
    expected_ember: Option<&str>,
) -> anyhow::Result<Result<(), String>> {
    static NEVER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let digests = ed2k::hash::hash_open_file_digests_cancellable(
        file,
        ed2k::hash::WantedDigests {
            aich: expected_aich.is_some(),
            ember: expected_ember.is_some(),
        },
        &NEVER,
    )?;
    if !digests.ed2k.eq_ignore_ascii_case(expected) {
        return Ok(Err("Restored final file hash mismatch".to_string()));
    }
    if let Some(expected_aich) = expected_aich {
        let actual = hex::encode(digests.aich.unwrap_or_default());
        if !actual.eq_ignore_ascii_case(expected_aich) {
            return Ok(Err(format!(
                "Expected AICH hash mismatch (expected {expected_aich}, got {actual})"
            )));
        }
    }
    if let Some(expected_ember) = expected_ember {
        let actual = hex::encode(digests.ember.unwrap_or_default());
        if !actual.eq_ignore_ascii_case(expected_ember) {
            // Reopening parts cannot turn these bytes into the content the
            // pin names, so use the message the live path uses and let it be
            // classified as permanent.
            return Ok(Err(ed2k::transfer::EMBER_BLAKE3_MISMATCH_MSG.to_string()));
        }
    }
    Ok(Ok(()))
}

/// Run a restored download's blocking re-verification `check` and send the
/// event it returns from the blocking task itself. Pause, Stop and Cancel
/// abort the returned task but cannot stop the check, which may still publish
/// the file and remove its `.part`: were the event sent from the task, the
/// row would be left unfinished beside a finished file, and Resume refused
/// until restart. A panicking check reports `Failed` with `panic_context`.
fn spawn_restore_check(
    tx: mpsc::Sender<DownloadEvent>,
    transfer_id: String,
    generation: Option<u64>,
    panic_context: &'static str,
    check: impl FnOnce() -> DownloadEvent + Send + 'static,
) -> tokio::task::JoinHandle<()> {
    let checking = tokio::task::spawn_blocking(move || {
        let event = std::panic::catch_unwind(std::panic::AssertUnwindSafe(check))
            .unwrap_or_else(|panic| {
                let error = format!("{panic_context}: {}", describe_panic(&*panic));
                DownloadEvent::Failed {
                    transfer_id,
                    failure_kind: ed2k::transfer::classify_error(&error),
                    error,
                    generation,
                }
            });
        let _ = tx.blocking_send(event);
    });
    tokio::spawn(async move {
        let _ = checking.await;
    })
}

/// Remove a recovered download's `.part` and `.part.met` from `folder`, or
/// have them removed once they can be. Blocking.
fn remove_recovered_part_files(folder: &Path, transfer_id: &str) {
    let allowed = [folder.to_string_lossy().into_owned()];
    for name in [format!("{transfer_id}.part"), format!("{transfer_id}.part.met")] {
        let path = folder.join("Temp").join(name);
        match crate::security::filesystem::remove_approved_file(&path, &allowed) {
            Ok(()) => info!("Removed {}, which a recovered finished copy replaces", path.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!("Could not remove {}: {e}. Removing it later.", path.display());
                crate::storage::deferred_removals::defer(&path, &allowed);
            }
        }
    }
}

/// Check a restored download's completion copies, one by one, and publish
/// the first that is its file into `download_root`'s `Downloads`; the others
/// are removed or, unreadable, kept. `Ok` names the published file, and
/// `Err` is why none was. Blocking.
fn recover_restored_copies(
    copies: &[(PathBuf, String)],
    download_root: &str,
    file_name: &str,
    size: u64,
    expected: &str,
    expected_aich: Option<&str>,
    expected_ember: Option<&str>,
) -> Result<PathBuf, String> {
    let is_the_file = |file: &mut std::fs::File| -> anyhow::Result<bool> {
        Ok(verify_restored_file(file, expected, expected_aich, expected_ember)?.is_ok())
    };
    let mut published = None;
    let mut unreadable = false;
    for (copy, root) in copies {
        if published.is_some() {
            if let Err(e) = crate::security::filesystem::remove_approved_file(
                copy,
                std::slice::from_ref(root),
            ) {
                warn!("Could not remove completion copy {}: {e}", copy.display());
            }
            continue;
        }
        match ed2k::transfer::recover_completion_copy(
            copy,
            root,
            download_root,
            file_name,
            size,
            &is_the_file,
        ) {
            Ok(
                ed2k::transfer::CopyRecovery::Published(path)
                | ed2k::transfer::CopyRecovery::AlreadyPublished(path),
            ) => published = Some(path),
            Ok(ed2k::transfer::CopyRecovery::NotTheFile) => {
                info!("Removed completion copy {}, which is not the finished file", copy.display())
            }
            Err(e) => {
                warn!("Keeping completion copy {}: {e}", copy.display());
                unreadable = true;
            }
        }
    }
    published.ok_or_else(|| {
        if unreadable {
            "Restored final file could not be read".to_string()
        } else {
            "Restored final file hash mismatch".to_string()
        }
    })
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
        let jobs: Vec<RestoreJob> = pending
            .iter()
            .map(|t| RestoreJob {
                id: t.id.clone(),
                total_size: t.total_size,
                file_name: t.file_name.clone(),
                failed: t.status == TransferStatus::Failed,
            })
            .collect();
        let db = db.clone();
        *part_progress_task = Some(tokio::task::spawn_blocking(move || {
            let recorded = db.download_part_folders().unwrap_or_else(|e| {
                warn!("Could not read where restored downloads were: {e}");
                HashMap::new()
            });
            let restored = read_restored_parts(
                &folders,
                jobs,
                &recorded,
                crate::storage::part_folders::STARTUP_LISTING_BUDGET,
            );
            if let Err(e) = db.record_part_folders(&restored.found) {
                warn!("Could not record where restored downloads are: {e}");
            }
            restored
        }));
    }
    if let Some(handle) = part_progress_task.as_mut() {
        if handle.is_finished() {
            match part_progress_task.take().unwrap().await {
                Ok(map) => *part_progress_map = Some(map),
                Err(e) => {
                    warn!("Part progress restore task panicked: {e}");
                    *part_progress_map = Some(RestoredParts::default());
                }
            }
        }
    }

    if pending_incomplete_downloads.is_some()
        && part_progress_map.is_some()
        && known_met_ready
    {
        let incomplete = pending_incomplete_downloads.take().unwrap();
        let RestoredParts {
            parts: progress_map,
            copies: mut completion_copies,
            found: found_parts,
        } = part_progress_map.take().unwrap();
        let found_parts: HashMap<String, String> = found_parts.into_iter().collect();
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

            // A completion copy of the file's size may be the only complete
            // copy: completion removed the `.part` and the copy's publication
            // never reached the disk, or a `.part` started over since. It is
            // checked before anything can start the download and write a
            // `.part`; the download completes from the copy that is its file,
            // and resumes as usual once none is.
            if let Some(copies) = completion_copies.remove(&transfer.id) {
                info!(
                    "Restored download {} has a finished copy from an interrupted completion — \
                     checking it before resuming",
                    transfer.id
                );
                let tid = transfer.id.clone();
                let file_name = transfer.file_name.clone();
                let file_size = transfer.total_size;
                let expected = transfer.file_hash.clone();
                let expected_aich = transfer.expected_aich.clone();
                let expected_ember = transfer.ember_file_hash.clone();
                let ember_pinned = expected_ember.is_some();
                let tx = dl_event_tx.clone();
                let download_root = dl_folder.clone();
                let part_files_in = found_parts.get(&tid).map(PathBuf::from);
                let generation = Some(control.generation());
                note_copy_check(&tid, transfer.status.clone());
                transfer.status = TransferStatus::Verifying;
                transfer.speed = 0;
                restore_db_writes.push(transfer.clone());
                {
                    let mut mgr = transfer_manager.write().await;
                    mgr.active.insert(tid.clone(), transfer);
                    mgr.begin_restore_verification(&tid, &control);
                    mgr.register_control(&tid, control);
                }
                let handle_id = tid.clone();
                let handle = spawn_restore_check(
                    tx,
                    tid.clone(),
                    generation,
                    "Restored final file could not be read",
                    move || {
                        let recovered = recover_restored_copies(
                            &copies,
                            &download_root,
                            &file_name,
                            file_size,
                            &expected,
                            expected_aich.as_deref(),
                            expected_ember.as_deref(),
                        );
                        if recovered.is_ok() {
                            if let Some(folder) = part_files_in {
                                remove_recovered_part_files(&folder, &tid);
                            }
                        }
                        match recovered {
                            Ok(final_path) => {
                                take_copy_check(&tid);
                                DownloadEvent::Completed {
                                    transfer_id: tid,
                                    final_path: Some(final_path.to_string_lossy().into_owned()),
                                    part_hashes: Vec::new(),
                                    ember_verified: ember_pinned,
                                    generation,
                                }
                            }
                            Err(error) => {
                                let failure_kind = ed2k::transfer::classify_error(&error);
                                DownloadEvent::Failed {
                                    transfer_id: tid,
                                    error,
                                    failure_kind,
                                    generation,
                                }
                            }
                        }
                    },
                );
                state.download_handles.insert(handle_id, handle);
                continue;
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
                    let generation = Some(control.generation());
                    transfer.status = TransferStatus::Verifying;
                    transfer.speed = 0;
                    restore_db_writes.push(transfer.clone());
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.active.insert(tid.clone(), transfer);
                        mgr.begin_restore_verification(&tid, &control);
                        mgr.register_control(&tid, control);
                    }
                    let handle = spawn_restore_check(
                        tx,
                        tid.clone(),
                        generation,
                        "Restored final file could not be read",
                        move || {
                            // `Ok(())` verified, `Err(msg)` mismatched, and
                            // `None` means the file could not be read at all.
                            // Which check failed decides whether this is
                            // worth retrying, so the reason travels with it.
                            let read_and_verify = || {
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
                                let mut file = std::fs::File::open(&verified_path).ok()?;
                                verify_restored_file(
                                    &mut file,
                                    &expected,
                                    expected_aich.as_deref(),
                                    expected_ember.as_deref(),
                                )
                                .ok()
                            };
                            let verdict = read_and_verify().unwrap_or_else(|| {
                                Err("Restored final file could not be read".to_string())
                            });
                            match verdict {
                                Ok(()) => DownloadEvent::Completed {
                                    transfer_id: tid,
                                    final_path: Some(final_path.to_string_lossy().into_owned()),
                                    part_hashes: Vec::new(),
                                    ember_verified: ember_pinned,
                                    generation,
                                },
                                Err(error) => {
                                    warn!(
                                        "Restored download {tid} failed re-verification: {error}"
                                    );
                                    let failure_kind = ed2k::transfer::classify_error(&error);
                                    DownloadEvent::Failed {
                                        transfer_id: tid,
                                        error,
                                        failure_kind,
                                        generation,
                                    }
                                }
                            }
                        },
                    );
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
                        let verify_control = control.clone();
                        let generation = Some(control.generation());
                        {
                            let mut mgr = transfer_manager.write().await;
                            mgr.active.insert(tid.clone(), transfer);
                            mgr.begin_restore_verification(&tid, &control);
                            mgr.register_control(&tid, control);
                        }

                        if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
                            old_handle.abort();
                        }
                        // Verify, move and report on one blocking task: a move
                        // left unreported would leave the row unfinished with
                        // its `.part` gone, so Resume would download it all
                        // again as "name (1)".
                        let handle = spawn_restore_check(
                            tx,
                            dl_tid.clone(),
                            generation,
                            "Re-verification of restored download failed",
                            move || {
                                let result = reverify_complete_part_file(
                                    &dl_tid,
                                    &file_hash,
                                    &file_name,
                                    file_size,
                                    expected_aich.as_deref(),
                                    expected_ember.as_deref(),
                                    &part_dir,
                                    &dl_dir,
                                    &verify_control,
                                );
                                match result {
                                    Ok(final_path) => DownloadEvent::Completed {
                                        transfer_id: dl_tid,
                                        final_path: Some(
                                            final_path.to_string_lossy().into_owned(),
                                        ),
                                        // `reverify_complete_part_file` only
                                        // re-checks the whole-file ed2k hash,
                                        // not a per-part hashset.
                                        part_hashes: Vec::new(),
                                        ember_verified: ember_pinned,
                                        generation,
                                    },
                                    Err(e) => {
                                        warn!("Re-verification of restored download failed: {e}");
                                        let error = e.to_string();
                                        let failure_kind = ed2k::transfer::classify_error(&error);
                                        DownloadEvent::Failed {
                                            transfer_id: dl_tid,
                                            error,
                                            failure_kind,
                                            generation,
                                        }
                                    }
                                }
                            },
                        );
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
    use crate::storage::part_folders::{located_folder, simulate_unplugged, DownloadFolders};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            Self(std::env::temp_dir().join(format!(
                "ember-restore-{name}-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            )))
        }

        fn folder(&self, name: &str) -> PathBuf {
            let folder = self.0.join(name);
            for dir in ["Temp", "Downloads"] {
                std::fs::create_dir_all(folder.join(dir)).unwrap();
            }
            folder
        }

        fn folders(&self, current: &Path, previous: &[&Path]) -> DownloadFolders {
            DownloadFolders::new(
                &current.to_string_lossy(),
                &previous
                    .iter()
                    .map(|folder| folder.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
            )
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            simulate_unplugged(&self.0.join("unplugged"), false);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn job(id: &str) -> RestoreJob {
        RestoreJob {
            id: id.to_string(),
            total_size: 100,
            file_name: format!("{id}.bin"),
            failed: false,
        }
    }

    fn uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    const BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

    #[test]
    fn a_restored_download_resumes_from_the_folder_it_started_in() {
        let scratch = Scratch::new("parts");
        let (old, new) = (scratch.folder("old"), scratch.folder("new"));
        let offline = scratch.0.join("unplugged").join("ember");
        let (before, after, never, gone, moved) = (uuid(), uuid(), uuid(), uuid(), uuid());
        std::fs::write(old.join("Temp").join(format!("{before}.part")), vec![0u8; 100]).unwrap();
        std::fs::write(new.join("Temp").join(format!("{after}.part")), vec![0u8; 100]).unwrap();
        std::fs::write(new.join("Temp").join(format!("{moved}.part")), vec![0u8; 100]).unwrap();
        let folders = scratch.folders(&new, &[&old, &offline]);
        simulate_unplugged(&scratch.0.join("unplugged"), true);
        let offline_text = offline.to_string_lossy().into_owned();
        let recorded = HashMap::from([
            (gone.clone(), offline_text.clone()),
            (moved.clone(), offline_text.clone()),
        ]);

        let restored = read_restored_parts(
            &folders,
            [&before, &after, &never, &gone, &moved]
                .into_iter()
                .map(|id| job(id))
                .collect(),
            &recorded,
            BUDGET,
        );

        assert_eq!(restored.parts[&before].folder, old);
        assert_eq!(restored.parts[&after].folder, new);
        assert!(!restored.parts.contains_key(&never), "no `.part` anywhere: nothing to restore");
        assert_eq!(
            located_folder(&gone),
            Some(offline.clone()),
            "found nowhere, it is where the database last saw it"
        );
        assert_eq!(located_folder(&moved), Some(new.clone()), "a `.part` on disk wins");
        let found: HashSet<&str> = restored.found.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(found, HashSet::from([before.as_str(), after.as_str(), moved.as_str()]));
    }

    /// Paused on an external drive that is unplugged at startup: with the
    /// drive on record it waits for it instead of starting over in the
    /// current folder, and resumes from it once it is back. With no record
    /// it is not held for a drive it may never have been on.
    #[test]
    fn a_paused_download_on_an_unplugged_drive_is_held_not_restarted() {
        let scratch = Scratch::new("unplugged");
        let current = scratch.folder("current");
        let volume = scratch.0.join("unplugged");
        let external = volume.join("ember");
        let folders = scratch.folders(&current, &[&external]);
        let (paused, unrecorded) = (uuid(), uuid());
        simulate_unplugged(&volume, true);

        read_restored_parts(
            &folders,
            vec![job(&paused), job(&unrecorded)],
            &HashMap::from([(paused.clone(), external.to_string_lossy().into_owned())]),
            BUDGET,
        );
        assert_eq!(folders.folder_to_resume_in(&paused), Err(external.clone()));
        assert_eq!(
            folders.folder_to_resume_in(&unrecorded),
            Ok(current.clone()),
            "no record of the drive: a missing `.part` starts over, as it always has"
        );
        assert!(!current.join("Temp").join(format!("{paused}.part")).exists());

        simulate_unplugged(&volume, false);
        std::fs::create_dir_all(external.join("Temp")).unwrap();
        std::fs::write(external.join("Temp").join(format!("{paused}.part")), b"progress").unwrap();
        assert_eq!(folders.folder_to_resume_in(&paused), Ok(external));
    }

    /// A drive that has not answered within the budget is unknown, exactly
    /// like one that is not there.
    #[test]
    fn a_folder_that_does_not_answer_in_time_holds_its_downloads() {
        let scratch = Scratch::new("timeout");
        let (current, slow) = (scratch.folder("current"), scratch.folder("slow"));
        let folders = scratch.folders(&current, &[&slow]);
        let id = uuid();
        restore_from_listings(
            &folders.roots(),
            &[Some(RootListing::read(&current, true)), None],
            vec![job(&id)],
            &HashMap::from([(id.clone(), slow.to_string_lossy().into_owned())]),
        );
        assert!(crate::storage::part_folders::known_this_run(&id));
        assert!(
            crate::storage::part_folders::may_hold_parts(&id, &slow),
            "held for the slow folder rather than started over"
        );
    }

    /// The current folder has no time limit: a slow disk or a huge folder
    /// still restores every download's progress, and the budget only ever
    /// cuts off an earlier folder.
    #[test]
    fn the_current_folder_is_listed_however_long_it_takes() {
        let scratch = Scratch::new("slow-current");
        let current = scratch.folder("current");
        let (partial, complete) = (uuid(), uuid());
        let mut half = vec![0u8; 100];
        half[..10].fill(1);
        std::fs::write(current.join("Temp").join(format!("{partial}.part")), &half).unwrap();
        std::fs::write(current.join("Temp").join(format!("{complete}.part")), vec![1u8; 100])
            .unwrap();
        let restored = read_restored_parts(
            &scratch.folders(&current, &[]),
            vec![job(&partial), job(&complete)],
            &HashMap::new(),
            std::time::Duration::ZERO,
        );
        assert_eq!(restored.parts[&partial].folder, current);
        assert_eq!(restored.parts[&complete].folder, current);

        let old = scratch.folder("old");
        let restored = read_restored_parts(
            &scratch.folders(&current, &[&old]),
            vec![job(&partial)],
            &HashMap::new(),
            std::time::Duration::ZERO,
        );
        assert_eq!(restored.parts[&partial].folder, current, "still no limit with earlier folders");
    }

    /// Regression, one download folder: restoring with progress is not held
    /// and not time-limited, whatever the budget, and the restored progress
    /// is read from the `.part` as before.
    #[test]
    fn a_single_folder_restore_reads_progress_without_a_budget_or_a_hold() {
        let scratch = Scratch::new("single");
        let current = scratch.folder("current");
        let folders = scratch.folders(&current, &[]);
        let (with_part, without_part) = (uuid(), uuid());
        std::fs::write(current.join("Temp").join(format!("{with_part}.part")), vec![0u8; 100])
            .unwrap();
        let restored = read_restored_parts(
            &folders,
            vec![job(&with_part), job(&without_part)],
            &HashMap::new(),
            std::time::Duration::ZERO,
        );
        assert_eq!(restored.parts[&with_part].folder, current);
        assert!(!restored.parts.contains_key(&without_part));
        for id in [&with_part, &without_part] {
            assert_eq!(folders.folder_to_resume_in(id), Ok(current.clone()), "never held");
            assert!(!crate::storage::part_folders::start_over_if_held(id, &current));
        }
    }

    #[test]
    fn each_download_folder_is_listed_once_however_many_downloads_there_are() {
        let scratch = Scratch::new("listed");
        let (current, old) = (scratch.folder("current"), scratch.folder("old"));
        let folders = scratch.folders(&current, &[&old]);
        let jobs: Vec<RestoreJob> = (0..50).map(|_| job(&uuid())).collect();
        read_restored_parts(&folders, jobs, &HashMap::new(), BUDGET);
        let listed = LISTED_ROOTS.lock().clone();
        for root in [&current, &old] {
            assert_eq!(listed.iter().filter(|listed| listed == &root).count(), 1);
        }
    }

    fn copy_in(folder: &Path, id: &str, bytes: &[u8]) -> PathBuf {
        let path = folder
            .join("Downloads")
            .join(format!(".ember-copy-{:016x}.{id}.tmp", rand::random::<u64>()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// With a single download folder, restoring lists its `Temp` and nothing
    /// else, as before there were earlier folders: no completion can have
    /// left a copy there except on macOS.
    #[test]
    fn a_single_download_folder_restores_without_listing_its_downloads() {
        let scratch = Scratch::new("single-no-copies");
        let current = scratch.folder("current");
        let folders = scratch.folders(&current, &[]);
        let id = uuid();
        std::fs::write(current.join("Temp").join(format!("{id}.part")), b"x").unwrap();
        let copy = copy_in(&current, &id, b"whole file");
        let restored = read_restored_parts(&folders, vec![job(&id)], &HashMap::new(), BUDGET);
        assert!(restored.parts.contains_key(&id));
        if cfg!(target_os = "macos") {
            assert_eq!(restored.copies[&id].len(), 1);
        } else {
            assert!(restored.copies.is_empty(), "Downloads was not looked at");
            assert!(copy.exists());
        }
    }

    /// The copy is settled before the download can resume, so a `.part`
    /// started over can never cost the only complete copy.
    #[test]
    fn a_finished_copy_is_settled_before_its_download_resumes() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let scratch = Scratch::new("copies");
        let (current, data) = (scratch.folder("current"), scratch.0.join("data"));
        std::fs::create_dir_all(&data).unwrap();
        // Copies come from completing across volumes, so from a download
        // folder changed since; with one folder only macOS makes them.
        let earlier = scratch.folder("earlier");
        let folders = scratch.folders(&current, &[&earlier]);
        crate::security::filesystem::initialize_approved_roots(&data, &folders.roots()).unwrap();
        let finished = vec![7u8; 100];
        let hashed = scratch.0.join("finished");
        std::fs::write(&hashed, &finished).unwrap();
        let hash = ed2k::hash::ed2k_hash_open_file(&mut std::fs::File::open(&hashed).unwrap())
            .unwrap();
        let (only_copy, restarted, half_done, failed, short_restarted) =
            (uuid(), uuid(), uuid(), uuid(), uuid());
        let part_of = |id: &str| current.join("Temp").join(format!("{id}.part"));
        std::fs::write(part_of(&half_done), b"x").unwrap();
        std::fs::write(part_of(&failed), b"x").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let whole = copy_in(&current, &only_copy, &finished);
        let beside_new_part = copy_in(&current, &restarted, &finished);
        let short = copy_in(&current, &half_done, &finished[..40]);
        let failed_copy = copy_in(&current, &failed, &finished);
        let short_beside_new_part = copy_in(&current, &short_restarted, &finished[..40]);
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(part_of(&restarted), b"x").unwrap();
        std::fs::write(part_of(&short_restarted), b"x").unwrap();

        let restored = read_restored_parts(
            &folders,
            vec![
                job(&only_copy),
                job(&restarted),
                job(&half_done),
                RestoreJob {
                    failed: true,
                    ..job(&failed)
                },
                job(&short_restarted),
            ],
            &HashMap::new(),
            BUDGET,
        );
        assert_eq!(restored.copies[&only_copy].len(), 1, "checked before it may resume");
        assert_eq!(restored.copies[&restarted].len(), 1, "even beside a newer `.part`");
        assert!(!short.exists(), "a copy cut short is not the file, and its `.part` is there");
        assert!(!restored.copies.contains_key(&half_done));
        assert!(!failed_copy.exists(), "a failed download keeps its `.part`, not a copy of it");
        assert!(!restored.copies.contains_key(&failed));
        assert!(
            short_beside_new_part.exists(),
            "a `.part` started since the copy never costs the copy"
        );

        let root = current.to_string_lossy().into_owned();
        let published = recover_restored_copies(
            &restored.copies[&restarted],
            &root,
            "movie.bin",
            100,
            &hash,
            None,
            None,
        )
        .unwrap();
        assert_eq!(published.file_name().unwrap(), "movie.bin");
        assert_eq!(std::fs::read(current.join("Downloads").join("movie.bin")).unwrap(), finished);
        assert!(!beside_new_part.exists());

        assert_eq!(
            recover_restored_copies(
                &restored.copies[&only_copy],
                &root,
                "movie.bin",
                100,
                &"00".repeat(16),
                None,
                None,
            ),
            Err("Restored final file hash mismatch".to_string()),
            "not the file: the download resumes as usual"
        );
        assert!(!whole.exists());
    }

    /// A failed copy check is told apart from a download's own failures, so
    /// it blames no source and the status the user left is kept; once only.
    #[test]
    fn a_copy_check_is_remembered_until_its_failure_is_handled() {
        let id = uuid();
        assert_eq!(take_copy_check(&id), None);
        note_copy_check(&id, TransferStatus::Paused);
        assert_eq!(take_copy_check(&id), Some(TransferStatus::Paused));
        assert_eq!(take_copy_check(&id), None, "a later failure is the download's own");
    }

    /// A copy left in an earlier folder's Downloads is published into the
    /// current one, as a completion would publish it, so Open and Reveal find
    /// it; and the `.part` it replaces goes with it.
    #[test]
    fn a_recovered_copy_is_published_into_the_current_downloads() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let scratch = Scratch::new("recovered-elsewhere");
        let (old, current, data) =
            (scratch.folder("old"), scratch.folder("current"), scratch.0.join("data"));
        std::fs::create_dir_all(&data).unwrap();
        let folders = scratch.folders(&current, &[&old]);
        crate::security::filesystem::initialize_approved_roots(&data, &folders.roots()).unwrap();
        let finished = vec![9u8; 100];
        let hashed = scratch.0.join("finished");
        std::fs::write(&hashed, &finished).unwrap();
        let hash = ed2k::hash::ed2k_hash_open_file(&mut std::fs::File::open(&hashed).unwrap())
            .unwrap();
        let id = uuid();
        let copy = copy_in(&old, &id, &finished);
        let part = old.join("Temp").join(format!("{id}.part"));
        std::fs::write(&part, b"started over").unwrap();
        std::fs::write(part.with_extension("part.met"), b"met").unwrap();

        let published = recover_restored_copies(
            &[(copy.clone(), old.to_string_lossy().into_owned())],
            &current.to_string_lossy(),
            "movie.bin",
            100,
            &hash,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            published.canonicalize().unwrap(),
            current.join("Downloads").join("movie.bin").canonicalize().unwrap()
        );
        assert_eq!(std::fs::read(&published).unwrap(), finished);
        assert!(!copy.exists());
        assert!(!old.join("Downloads").join("movie.bin").exists());

        remove_recovered_part_files(&old, &id);
        assert!(!part.exists(), "the stale `.part` does not outlive the recovery");
        assert!(!part.with_extension("part.met").exists());
    }

    /// A copy whose publication went through before the crash — its file
    /// already there as `name (1)`, linked or with its hash — is not
    /// published a second time.
    #[test]
    fn a_copy_already_published_under_a_numbered_name_is_not_published_again() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let scratch = Scratch::new("already-published");
        let (current, data) = (scratch.folder("current"), scratch.0.join("data"));
        std::fs::create_dir_all(&data).unwrap();
        let root = current.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(&data, std::slice::from_ref(&root))
            .unwrap();
        let finished = vec![5u8; 100];
        let hashed = scratch.0.join("finished");
        std::fs::write(&hashed, &finished).unwrap();
        let hash = ed2k::hash::ed2k_hash_open_file(&mut std::fs::File::open(&hashed).unwrap())
            .unwrap();
        let downloads = current.join("Downloads");
        std::fs::write(downloads.join("movie.bin"), b"someone else's").unwrap();
        let linked = copy_in(&current, &uuid(), &finished);
        std::fs::hard_link(&linked, downloads.join("movie (1).bin")).unwrap();

        let recover = |copy: &Path| {
            recover_restored_copies(
                &[(copy.to_path_buf(), root.clone())],
                &root,
                "movie.bin",
                100,
                &hash,
                None,
                None,
            )
        };
        let published = recover(&linked).unwrap();
        assert_eq!(published, downloads.join("movie (1).bin"));
        assert!(!linked.exists());
        assert!(!downloads.join("movie (2).bin").exists());

        let same_bytes = copy_in(&current, &uuid(), &finished);
        let published = recover(&same_bytes).unwrap();
        assert_eq!(published, downloads.join("movie (1).bin"), "the same file by its hash");
        assert!(!same_bytes.exists());
        assert!(!downloads.join("movie (2).bin").exists());
    }

    #[tokio::test]
    async fn restore_check_reports_even_when_its_task_is_aborted() {
        let (tx, mut rx) = mpsc::channel(4);
        let handle = spawn_restore_check(tx, "dl".to_string(), Some(7), "check failed", || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            DownloadEvent::Completed {
                transfer_id: "dl".to_string(),
                final_path: None,
                part_hashes: Vec::new(),
                ember_verified: false,
                generation: Some(7),
            }
        });
        handle.abort();

        let event = rx.recv().await.expect("the check's result is sent");
        assert!(matches!(event, DownloadEvent::Completed { generation: Some(7), .. }));
    }

    #[tokio::test]
    async fn panicking_restore_check_reports_a_failure_for_its_generation() {
        let (tx, mut rx) = mpsc::channel(4);
        let handle = spawn_restore_check(tx, "dl".to_string(), Some(7), "check failed", || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            panic!("disk vanished")
        });
        handle.abort();

        match rx.recv().await.expect("a panicking check still reports") {
            DownloadEvent::Failed { transfer_id, error, generation, .. } => {
                assert_eq!(transfer_id, "dl");
                assert_eq!(generation, Some(7));
                assert_eq!(error, "check failed: disk vanished");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
