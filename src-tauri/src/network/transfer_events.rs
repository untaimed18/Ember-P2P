//! Handling download and upload worker events.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

#[cfg(test)]
pub(super) async fn take_fresh_part_hashes(
    fresh_part_hashes: &Arc<RwLock<HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    file_hash: &[u8; 16],
) -> Option<Vec<[u8; 16]>> {
    fresh_part_hashes.write().await.remove(file_hash)
}

/// Re-verify a .part file that was fully downloaded but the app crashed before
/// completion.  On success, moves the file to `Downloads/` and cleans up.
pub(super) async fn reverify_complete_part_file(
    transfer_id: &str,
    file_hash: &str,
    file_name: &str,
    file_size: u64,
    expected_aich: Option<&str>,
    expected_ember: Option<&str>,
    part_dir: &std::path::Path,
    download_dir: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    let part_path = part_dir.join("Temp").join(format!("{transfer_id}.part"));
    let expected = file_hash.to_string();
    let verify_path = part_path.clone();
    let verify_root = part_dir.to_path_buf();
    let expected_aich_owned = expected_aich.map(str::to_string);
    let ember_wanted = expected_ember.is_some();
    let (computed_hash, verified_identity, computed_aich, computed_ember) =
        tokio::task::spawn_blocking(move || {
            let allowed = vec![verify_root.to_string_lossy().into_owned()];
            let (_, mut file) =
                crate::security::filesystem::open_existing_approved(&verify_path, &allowed, false)?;
            let identity = crate::security::filesystem::opened_file_identity(&file)?;
            let hash = ed2k::hash::ed2k_hash_open_file(&mut file)?;
            let aich = if expected_aich_owned.is_some() {
                Some(hex::encode(
                    ed2k::aich::AICHRecoveryHashSet::build_from_open_file(&mut file)?.root_hash,
                ))
            } else {
                None
            };
            // Hashed off the same handle the identity check covers, like the
            // other two, so all three describe the file that is about to move.
            let ember = if ember_wanted {
                Some(hex::encode(ember::crypto::blake3_hash_open_file(
                    &mut file,
                )?))
            } else {
                None
            };
            Ok::<_, anyhow::Error>((hash, identity, aich, ember))
        })
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;

    if computed_hash != expected {
        anyhow::bail!("Re-verification hash mismatch — .part preserved for retry");
    }
    if let Some(expected_aich) = expected_aich {
        let actual = computed_aich
            .ok_or_else(|| anyhow::anyhow!("AICH verification did not produce a root"))?;
        if !actual.eq_ignore_ascii_case(expected_aich) {
            anyhow::bail!(
                "Expected AICH hash mismatch — .part preserved for retry (expected {expected_aich}, got {actual})"
            );
        }
    }
    // The pin exists because a matching MD4 is not proof of the right content,
    // so a crash mid-verify is no reason to skip it. Reported with the same
    // message the live path uses, which classifies as permanent: no amount of
    // re-downloading turns these bytes into the content the pin names.
    if let Some(expected_ember) = expected_ember {
        let actual = computed_ember
            .ok_or_else(|| anyhow::anyhow!("Ember content verification did not produce a digest"))?;
        if !actual.eq_ignore_ascii_case(expected_ember) {
            anyhow::bail!("{}", ed2k::transfer::EMBER_BLAKE3_MISMATCH_MSG);
        }
    }

    let safe_name = crate::security::sanitize_filename(file_name);
    let pp = part_path.clone();
    let pp_root = part_dir.to_path_buf();
    let root = download_dir.to_path_buf();
    let actual_final = tokio::task::spawn_blocking(move || {
        ed2k::transfer::move_part_to_downloads(&pp, &pp_root, &root, &safe_name, &verified_identity)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;

    // Clean up .part.met
    let met_path = part_path.with_extension("part.met");
    let cleanup_root = part_dir.to_string_lossy().into_owned();
    let _ = tokio::task::spawn_blocking(move || {
        crate::security::filesystem::remove_approved_file(&met_path, &[cleanup_root])
    })
    .await;

    info!(
        "Re-verified and completed restored download {transfer_id} ({file_name}, {file_size} bytes)"
    );
    Ok(actual_final)
}

pub(super) async fn handle_download_event(
    event: DownloadEvent,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    db: &Arc<Database>,
    promoted_out: &mut Vec<Transfer>,
    stats_manager: &mut StatsManager,
    remove_finished: bool,
    a4af: &Arc<RwLock<ed2k::a4af::A4AFManager>>,
    download_roots: &[String],
    db_progress_last_persist: &mut HashMap<String, std::time::Instant>,
    db_progress_persist_interval: std::time::Duration,
    // Pending-since tracking for KAD callback placeholder rows. When
    // the `SourceDetail` handler removes stale placeholders, we also
    // drop their timestamp entries so the periodic timeout sweep in
    // `source_retry_timer` doesn't keep checking keys that no longer
    // refer to live rows.
    callback_row_pending_since: &mut HashMap<(String, String, u16), std::time::Instant>,
    status_writes: &Arc<TransferStatusWriteClock>,
) {
    match event {
        DownloadEvent::Progress {
            transfer_id,
            downloaded,
            transferred,
            total,
        } => {
            let capped_downloaded = if total > 0 {
                downloaded.min(total)
            } else {
                downloaded
            };
            let speed = {
                let mut mgr = transfer_manager.write().await;
                // eMule's split: `transferred` is the wire counter behind its
                // Transferred column, `capped_downloaded` the on-disk figure
                // behind Completed, and progress comes from the latter
                // (`DownloadListCtrl.cpp:1984`, `:1987`, `:1698`). Emitters with
                // no tracker send `None`, and then the on-disk figure stands in
                // for both rather than being reported as a wire total.
                mgr.update_progress(
                    &transfer_id,
                    transferred.unwrap_or(capped_downloaded),
                    Some(capped_downloaded),
                );
                if let Some(t) = mgr.active.get(&transfer_id) {
                    t.speed
                } else {
                    0
                }
            };
            let progress = if total > 0 {
                ((capped_downloaded as f64 / total as f64) * 100.0).min(100.0)
            } else {
                0.0
            };
            // Rate-limit the SQLite UPDATE: DownloadEvent::Progress fires many
            // times per second per active download, and we already keep the
            // authoritative in-memory state on `transfer_manager`. The DB
            // copy is only consulted at startup recovery, where the
            // `.part.met` (via PartTracker::new) supersedes it anyway. Flush
            // at most once per `db_progress_persist_interval` per transfer,
            // plus on completion/fail/verifying via the dedicated paths.
            let should_persist_db = match db_progress_last_persist.get(&transfer_id) {
                None => true,
                Some(last) => last.elapsed() >= db_progress_persist_interval,
            };
            if should_persist_db {
                let db_for_progress = db.clone();
                let transfer_id_for_progress = transfer_id.clone();
                tokio::task::spawn_blocking(move || {
                    // Guarded: this write is unsequenced and can be executed
                    // after the completion write it was queued before, which
                    // would leave a `completed` row showing the last
                    // rate-limited percentage instead of 100%.
                    if let Err(e) = db_for_progress.update_transfer_progress_if_active(
                        &transfer_id_for_progress,
                        capped_downloaded,
                        progress,
                        speed,
                    ) {
                        warn!(
                            "DB update_transfer_progress failed for {transfer_id_for_progress}: {e}"
                        );
                    }
                });
                db_progress_last_persist.insert(transfer_id.clone(), std::time::Instant::now());
            }
            let _ = app_handle.emit(
                "transfer-progress",
                &crate::types::TransferProgressPayload {
                    id: &transfer_id,
                    // Wire bytes, mirroring `uploaded` on the upload side. This is
                    // the Transferred column.
                    downloaded: transferred.unwrap_or(capped_downloaded),
                    total,
                    progress,
                    speed,
                    uploaded: None,
                    // Bytes on disk — the Completed column, and what `progress`
                    // above was computed from. Sending it matters: the frontend
                    // otherwise derives Completed from Transferred, which now
                    // counts re-fetched bytes and would drive the bar past 100%.
                    completed_size: Some(capped_downloaded),
                    direction: None,
                    upload_time: None,
                    up_part_status: None,
                    up_part_count: None,
                    up_peer_part_status: None,
                },
            );
        }
        DownloadEvent::Verifying { transfer_id } => {
            // A `Verifying` that was queued before the user paused or stopped
            // must not undo them. This arm had no guard at all, unlike the
            // `Failed` and `SourcesUpdate` arms, and `Verifying` is the worst
            // state to be stranded in: `active_download_count` counts it, so
            // the slot stays consumed after `pause_and_promote` already gave
            // it away; `resume()` does not handle it, so the user cannot get
            // out; and `compute_health_state` calls it Healthy, so no stall
            // detection fires. Same settled-state set the `Failed` arm uses.
            let settled_by_user = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&transfer_id).is_some_and(|t| {
                    matches!(
                        t.status,
                        TransferStatus::Paused
                            | TransferStatus::Stopped
                            | TransferStatus::Insufficient
                            | TransferStatus::Completed
                            | TransferStatus::Failed
                    )
                })
            };
            if settled_by_user {
                return;
            }
            {
                let mut mgr = transfer_manager.write().await;
                mgr.update_status(&transfer_id, crate::types::TransferStatus::Verifying);
            }
            spawn_transfer_status_write(
                status_writes,
                db.clone(),
                transfer_id.clone(),
                "verifying",
            );
            let _ = app_handle.emit(
                "transfer-status",
                serde_json::json!({
                    "id": transfer_id,
                    "status": "verifying",
                }),
            );
        }
        DownloadEvent::SourcesUpdate {
            transfer_id,
            total,
            active,
            queued,
        } => {
            let (payload, promoted_active) = {
                let mut mgr = transfer_manager.write().await;
                mgr.apply_source_column_counts(&transfer_id, Some(total), Some((active, queued)));
                // The column count the row ended up with, which can exceed the
                // worker's own `active` — see `apply_source_column_counts`.
                let effective_active = mgr
                    .source_counts(&transfer_id)
                    .map_or(active, |(_, active_sources, _)| active_sources);
                // Reflect live download activity in the overall status. The
                // status is only set to Active when the multi-source worker
                // first starts, so a download that began while every source was
                // queued (or whose start path left it Queued/Searching) keeps
                // showing "Queued" in the Status column even once one or more
                // sources are actively transferring. `active > 0` is the
                // worker's authoritative "a source is sending us bytes" signal,
                // so promote the row to Active the moment that becomes true.
                // Terminal / user-controlled states (Paused, Stopped, Verifying,
                // etc.) are deliberately left untouched.
                let current_status = mgr.active.get(&transfer_id).map(|t| t.status.clone());
                let promoted_active = if effective_active > 0
                    && matches!(
                        current_status,
                        Some(crate::types::TransferStatus::Queued)
                            | Some(crate::types::TransferStatus::Searching)
                    ) {
                    mgr.update_status(&transfer_id, crate::types::TransferStatus::Active);
                    true
                } else {
                    false
                };
                let payload = mgr
                    .source_counts(&transfer_id)
                    .map(|(sources, active_sources, queued_sources)| {
                        crate::types::TransferSourcesPayload {
                            id: transfer_id.as_str(),
                            sources,
                            active_sources,
                            queued_sources,
                        }
                    })
                    .unwrap_or(crate::types::TransferSourcesPayload {
                        id: transfer_id.as_str(),
                        sources: total,
                        active_sources: active,
                        queued_sources: queued,
                    });
                (payload, promoted_active)
            };
            // Emit the status change first so the Status column updates in the
            // same tick the Sources column does.
            if promoted_active {
                let _ = app_handle.emit(
                    "transfer-status",
                    serde_json::json!({
                        "id": transfer_id.as_str(),
                        "status": "active",
                        "sources": payload.sources,
                        "active_sources": payload.active_sources,
                        "queued_sources": payload.queued_sources,
                    }),
                );
            }
            let _ = app_handle.emit("transfer-sources", &payload);
        }
        DownloadEvent::SourceDetail {
            transfer_id,
            ip,
            port,
            status,
            queue_rank,
            speed,
            transferred,
            client_software,
            peer_name,
            available_parts,
            total_parts,
            country_code,
            ..
        } => {
            let source_status = match status.as_str() {
                "connecting" => crate::types::SourceStatus::Connecting,
                "wait_callback" | "wait_callback_kad" => crate::types::SourceStatus::WaitCallback,
                "stalled" => crate::types::SourceStatus::Stalled,
                "queued" => crate::types::SourceStatus::Queued,
                "queue_full" => crate::types::SourceStatus::QueueFull,
                "no_needed_parts" => crate::types::SourceStatus::NoNeededParts,
                "transferring" => crate::types::SourceStatus::Transferring,
                "completed" => crate::types::SourceStatus::Completed,
                // Parked states, mapped explicitly rather than left to the
                // catch-all. `maybe_escalate_to_friend_transfer` writes these
                // rows itself and the caller stops the originating event, so
                // nothing reaches this match with them today — but the fallback
                // is `Failed`, and the drawer drops a `Failed` row entirely, so
                // any future path that did emit one would silently delete a
                // source that is waiting perfectly healthily.
                "friend_connect" => crate::types::SourceStatus::FriendConnect,
                "unreachable" => crate::types::SourceStatus::Unreachable,
                // Transient hold-offs, not failures, and each now says which one
                // it is. Both are routine — the connection cap saturates on any
                // busy download, and a source arriving while every part it holds
                // is already in flight is the normal endgame of a well-swarmed
                // file — but neither is a failure and neither is a dial.
                //
                // These have been rendered two wrong ways already. `Failed` meant
                // the drawer deleted healthy rows and counted them as failures;
                // `Connecting` meant a row could sit claiming to be connecting for
                // as long as the hold-off lasted, which is what a stalled download
                // looks like from the outside and what made a real stall
                // impossible to tell apart from a busy one.
                "too_many_conns" => crate::types::SourceStatus::WaitingForSlot,
                "parts_busy" => crate::types::SourceStatus::PartsBusy,
                // The LowID/callback path reports its post-handshake state with
                // this string rather than a bare "connecting".
                "connected (callback)" => crate::types::SourceStatus::Connecting,
                // `duplicate` deliberately lands on `Failed`: another live route
                // already owns this peer, and `Failed` is the frontend's
                // documented remove-on-terminal-status signal, so the redundant
                // row disappears instead of lingering. It carries no fail_count
                // penalty — see the `emit_source!("duplicate", ..)` site.
                _ => crate::types::SourceStatus::Failed,
            };
            // Both the snapshot and the event below must speak the same closed
            // vocabulary; `status` is the worker's raw string and may not be in
            // it. `&'static str`, so it outlives the move of `source_status`.
            let status_wire = source_status.as_wire();
            // Every event here comes from a real download worker
            // (multi_source / transfer) reporting a *live* peer connection on
            // (ip, port). Placeholder rows we seed from KAD/server source
            // lists bypass `DownloadEvent` and are written straight to the
            // transfer manager, so any event here means "this peer is now
            // connected / being dialled". Give the live row the peer's stable
            // identity (its eD2k user hash, looked up by IP) so it can be
            // coalesced with any earlier row for the same peer: a LowID/KAD/
            // server callback or a Path-B push-grant reconnect lands on the
            // peer's *ephemeral* outbound port — a different (ip, port) key
            // than the listening port we seeded — and eMule keeps a single
            // client per peer keyed by hash (`CUpDownClient::Compare`).
            // Without this the UI shows two rows per peer (a forever-
            // "Connecting"/"Queued" row next to the real transferring row).
            //
            // Identity lookup is exact-first: the live worker registers the
            // peer's hash against the connection's *actual* port (the listening
            // port for a dialed HighID source, the ephemeral outbound port for
            // an adopted callback/push-grant stream), so an exact (ip, port)
            // match is unambiguous even when several peers share one NAT IP. We
            // only fall back to the by-IP identity when that port isn't
            // registered yet, and `unique_user_hash_for_ip` deliberately returns
            // `None` when the IP maps to more than one identity, so we never
            // mis-attribute a live connection or merge distinct peers behind one
            // NAT; callback placeholders at that IP are still cleaned up by
            // their `placeholder` flag inside `supersede_duplicate_peer_rows`.
            //
            // The origin rides along on the same lookup. A worker event is the
            // only thing that ever writes a row for a source nobody seeded a
            // placeholder for, so without reading it back here those rows would
            // be the ones with no Origin to show — and they are exactly the
            // sources that are actually working.
            let (live_hash, live_origin) = if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
                // Provenance is recorded per file, so the lookup needs this
                // transfer's hash. Read under its own guard, released before the
                // source lock is taken, so the two are never held at once.
                let file_hash_bytes = {
                    let mgr = transfer_manager.read().await;
                    mgr.get_transfer(&transfer_id)
                        .and_then(|t| parse_ed2k_hash16(&t.file_hash))
                };
                let sm = source_manager.read().await;
                (
                    sm.get_user_hash_by_addr(v4, port)
                        .or_else(|| sm.unique_user_hash_for_ip(v4)),
                    file_hash_bytes.and_then(|fh| sm.get_source_origin(&fh, v4, port)),
                )
            } else {
                (None, None)
            };
            let (placeholder_removed, source_payload, detail_origin) = {
                let mut mgr = transfer_manager.write().await;
                let counts_before = mgr.source_counts(&transfer_id);
                // Harvest origin from the placeholder / listening-port row
                // *before* supersede drops it. The live connection is often
                // on the ephemeral port, and a worker lookup then misses —
                // which is how working sources showed a dash (issue 121).
                let inherited_origin =
                    mgr.inherited_source_origin(&transfer_id, &ip, live_hash);
                let detail_origin = live_origin.or(inherited_origin);
                let removed = mgr.supersede_duplicate_peer_rows(&transfer_id, &ip, port, live_hash);
                mgr.update_source_detail(
                    &transfer_id,
                    crate::types::SourceInfo {
                        ip: ip.clone(),
                        port,
                        status: source_status,
                        queue_rank,
                        speed,
                        transferred,
                        client_software: client_software.clone(),
                        peer_name: peer_name.clone(),
                        available_parts,
                        total_parts,
                        country_code: country_code.clone(),
                        user_hash: live_hash,
                        origin: detail_origin,
                        // We are in contact with this peer, so whatever row is
                        // here stops being a not-yet-contacted placeholder.
                        placeholder: false,
                    },
                );
                // Report what the row now holds, not only what this lookup
                // found. The drawer builds a row from the first event it sees
                // for a peer, so an event saying "no origin" for a row the
                // backend has labelled left that peer on a dash for good.
                let detail_origin =
                    mgr.source_detail_origin(&transfer_id, &ip, port).or(detail_origin);
                // This row just changed a peer's state, which is exactly what
                // eMule's `xx`/`zz` count — and the worker atomics cannot see
                // a queue slot whose socket is gone. Only emit when the column
                // actually moved: source details fire per peer per state
                // change, and the UI already redraws off the detail event.
                mgr.apply_source_column_counts(&transfer_id, None, None);
                let payload = mgr
                    .source_counts(&transfer_id)
                    .filter(|counts| Some(*counts) != counts_before)
                    .map(|(sources, active_sources, queued_sources)| {
                        crate::types::TransferSourcesPayload {
                            id: transfer_id.as_str(),
                            sources,
                            active_sources,
                            queued_sources,
                        }
                    });
                (removed, payload, detail_origin)
            };
            for (rem_ip, rem_port) in placeholder_removed {
                callback_row_pending_since.remove(&(transfer_id.clone(), rem_ip.clone(), rem_port));
                let _ = app_handle.emit(
                    "transfer-source-detail",
                    serde_json::json!({
                        "transfer_id": &transfer_id,
                        "ip": rem_ip,
                        "port": rem_port,
                        "status": "failed",
                        "queue_rank": null,
                        "speed": 0,
                        "transferred": 0,
                        "client_software": "",
                        "peer_name": "",
                        "available_parts": null,
                        "total_parts": null,
                        "country_code": null,
                    }),
                );
            }
            if status == "queued" || status == "transferring" {
                // Scoped to the file this status is about — see
                // `update_source_state`. Queued or transferring means the peer
                // still has something this file wants, so it is not run dry here
                // whatever its queue position.
                let assigned = {
                    let mgr = transfer_manager.read().await;
                    mgr.get_transfer(&transfer_id)
                        .and_then(|t| parse_ed2k_hash16(&t.file_hash))
                };
                if let (Some(assigned), Ok(addr)) = (
                    assigned,
                    format!("{ip}:{port}").parse::<std::net::SocketAddr>(),
                ) {
                    let mut a4af_lock = a4af.write().await;
                    a4af_lock.update_source_state(
                        addr,
                        assigned,
                        queue_rank.unwrap_or(0).min(u16::MAX as u32) as u16,
                        true,
                        1.0,
                    );
                }
            }
            let _ = app_handle.emit(
                "transfer-source-detail",
                serde_json::json!({
                    "transfer_id": transfer_id,
                    "ip": ip,
                    "port": port,
                    "status": status_wire,
                    "queue_rank": queue_rank,
                    "speed": speed,
                    "transferred": transferred,
                    "client_software": client_software,
                    "peer_name": peer_name,
                    "available_parts": available_parts,
                    "total_parts": total_parts,
                    "country_code": country_code,
                    // Carried so a row this event creates (a source no
                    // discovery placeholder was seeded for) shows its Origin
                    // straight away, rather than blank until the next snapshot.
                    "origin": detail_origin,
                }),
            );
            if let Some(payload) = source_payload {
                let _ = app_handle.emit("transfer-sources", &payload);
            }
        }
        DownloadEvent::Completed {
            transfer_id,
            final_path,
            ember_verified,
            ..
        } => {
            // A download reaches Completed only after every part is present
            // and hash-verified, so the terminal row represents the whole
            // file. Persist 100% / full bytes (not the last in-memory progress
            // snapshot, which the rate-limited progress ticks can leave a few
            // percent short) so the saved row — and the UI after a refresh or
            // restart — shows a completed bar.
            let final_total = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&transfer_id).map(|t| t.total_size)
            };
            db_progress_last_persist.remove(&transfer_id);
            let completed_ok = if let Some(promoted) = {
                let mut mgr = transfer_manager.write().await;
                // Record the real on-disk path (possibly deduplicated by
                // `move_part_to_final`) BEFORE `complete()` moves the row out
                // of the active set, so Open/Reveal can target the exact file
                // we wrote rather than reconstructing it from the file name.
                if let Some(ref fp) = final_path {
                    mgr.set_completed_path(&transfer_id, fp.clone());
                }
                mgr.set_ember_verified(&transfer_id, ember_verified);
                mgr.complete(&transfer_id)
            } {
                // Mirror the upload path: only count after `complete()`
                // confirms the transfer existed. Counting beforehand
                // over-reported on duplicate/stale Completed events.
                stats_manager.record_completed_download();
                for t in &promoted {
                    info!(
                        "Promoted queued transfer {} ({}) to active",
                        t.id, t.file_name
                    );
                }
                promoted_out.extend(promoted);
                true
            } else {
                warn!("Completed event for transfer {transfer_id} not found in active set");
                false
            };

            // Skip history/DB completion work when the transfer was already
            // gone — those paths would otherwise write a second "completed"
            // history row for a phantom event.
            if !completed_ok {
                return;
            }

            let history_row = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&transfer_id)
                    .map(|t| (t.file_hash.clone(), t.file_name.clone(), t.total_size))
            };
            let db_for_completion = db.clone();
            let completion_transfer_id = transfer_id.clone();
            let completed_seq = status_writes.next_seq();
            let completed_clock = Arc::clone(status_writes);
            tokio::task::spawn_blocking(move || {
                apply_transfer_completion_write(
                    &completed_clock,
                    &db_for_completion,
                    &completion_transfer_id,
                    final_total,
                    history_row,
                    remove_finished,
                    completed_seq,
                );
            });

            let _ = app_handle.emit(
                "transfer-complete",
                serde_json::json!({
                    "id": transfer_id,
                    "ember_verified": ember_verified,
                }),
            );

            // Defensive cleanup: remove any leftover .part / .part.met files
            // that should have been moved/deleted during the completion flow.
            for root in download_roots {
                let temp_dir = PathBuf::from(root).join("Temp");
                let part_path = temp_dir.join(format!("{transfer_id}.part"));
                let met_path = temp_dir.join(format!("{transfer_id}.part.met"));
                if tokio::fs::try_exists(&part_path).await.unwrap_or(false) {
                    if let Err(e) = tokio::fs::remove_file(&part_path).await {
                        warn!(
                            "Failed to clean up leftover .part after completion: {} — {e}",
                            part_path.display()
                        );
                    } else {
                        info!(
                            "Cleaned up leftover .part file for completed download {transfer_id}"
                        );
                    }
                }
                if tokio::fs::try_exists(&met_path).await.unwrap_or(false) {
                    let _ = tokio::fs::remove_file(&met_path).await;
                }
            }

            if remove_finished {
                let mut mgr = transfer_manager.write().await;
                mgr.remove(&transfer_id);
            }
        }
        DownloadEvent::Failed {
            transfer_id,
            error,
            failure_kind,
        } => {
            let failure_stage = ed2k::transfer::infer_stage_from_error(&error).to_string();
            let failure_kind_name = ed2k::transfer::failure_kind_name(&failure_kind);
            let failure_code = ed2k::transfer::classify_failure(&error, &failure_kind);
            let failure_summary = failure_code.message();
            // User cancel is handled by cancel_transfer (history + row removal).
            // Emitting transfer-failed here would briefly turn the progress bar
            // red before the frontend drops the row.
            if ed2k::transfer::is_user_cancel_error(&error)
                || failure_code == ed2k::transfer::TransferFailureCode::Cancelled
            {
                return;
            }
            let current_status = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&transfer_id).map(|t| t.status.clone())
            };
            // `Completed` belongs here for the same reason the upload path
            // returns early when `fail()` finds nothing: once the row has moved
            // to `completed`, `mgr.fail` cannot touch it, but the DB write and
            // `transfer-failed` emit below still would — so a late or duplicate
            // failure from a worker that raced completion persisted "failed" for
            // a download whose bytes were verified and whose file was moved.
            if matches!(
                current_status,
                Some(
                    TransferStatus::Paused
                        | TransferStatus::Stopped
                        | TransferStatus::Insufficient
                        | TransferStatus::Completed
                )
            ) {
                return;
            }
            // Flush final progress snapshot (see Completed above) and drop
            // the rate-limit cache entry so a re-queue of the same id starts
            // with a fresh budget.
            let final_progress = {
                let mgr = transfer_manager.read().await;
                // `completed_size`, not `transferred`: the DB column is resume
                // progress, and the periodic writer above persists the same
                // on-disk figure. `transferred` is cumulative wire bytes and can
                // exceed the file size, which would both misreport progress on
                // restart and break the `total_size - transferred` remaining
                // calculation the queue-overflow query runs.
                mgr.get_transfer(&transfer_id)
                    .map(|t| (t.completed_size, t.progress, t.speed))
            };
            if let Some((transferred, progress, speed)) = final_progress {
                let db = db.clone();
                let transfer_id = transfer_id.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) =
                        db.update_transfer_progress(&transfer_id, transferred, progress, speed)
                    {
                        warn!("DB update_transfer_progress (final) failed for {transfer_id}: {e}");
                    }
                });
            }
            db_progress_last_persist.remove(&transfer_id);
            if let Some(promoted) = {
                let mut mgr = transfer_manager.write().await;
                mgr.fail(
                    &transfer_id,
                    failure_code,
                    Some(failure_kind_name.clone()),
                    Some(failure_stage.clone()),
                )
            } {
                for t in &promoted {
                    info!(
                        "Promoted queued transfer {} ({}) to active",
                        t.id, t.file_name
                    );
                }
                promoted_out.extend(promoted);
            } else {
                warn!("Failed event for transfer {transfer_id} not found in active set");
            }
            spawn_transfer_status_write(
                status_writes,
                db.clone(),
                transfer_id.clone(),
                "failed",
            );
            let _ = app_handle.emit(
                "transfer-failed",
                serde_json::json!({
                    "id": transfer_id,
                    "error": failure_summary,
                    "failure_code": failure_code.as_code(),
                    "failure_kind": failure_kind_name,
                    "failure_stage": failure_stage,
                }),
            );
        }
        DownloadEvent::SourceExchange { .. } => {
            // Handled directly in the network event loop (source injection).
        }
        DownloadEvent::EmberSources { .. }
        | DownloadEvent::EmberPeerDiscovered { .. }
        | DownloadEvent::EmberFriendRequest { .. } => {
            // Handled directly in the network event loop (EPX source injection / peer tracking / friend requests).
        }
        DownloadEvent::DataReceived { .. }
        | DownloadEvent::PartVerified { .. }
        | DownloadEvent::PartCorrupted { .. }
        | DownloadEvent::AichRecoveryFailed { .. }
        | DownloadEvent::PartFileReady { .. }
        | DownloadEvent::ProtocolViolation { .. }
        | DownloadEvent::FriendSeen { .. }
        | DownloadEvent::EmberChatMessage { .. }
        | DownloadEvent::EmberBrowseResponse { .. } => {
            // Handled directly in the network event loop.
        }
    }
}

pub(super) async fn handle_upload_event(
    event: UploadEvent,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    promoted_out: &mut Vec<Transfer>,
    stats_manager: &mut StatsManager,
    upload_speed_limit: u64,
) {
    match event.kind {
        UploadEventKind::Started {
            file_name,
            file_hash,
            total_size,
            peer_addr,
            peer_name,
            client_software,
            country_code,
            user_hash,
            wait_seconds,
            ember_hash,
        } => {
            let transfer = Transfer {
                id: event.transfer_id.clone(),
                file_name,
                file_hash,
                peer_id: peer_addr.clone(),
                peer_name,
                direction: TransferDirection::Upload,
                status: TransferStatus::Active,
                progress: 0.0,
                speed: 0,
                total_size,
                transferred: 0,
                completed_size: 0,
                started_at: chrono::Utc::now().timestamp(),
                failure_reason: None,
                failure_code: None,
                failure_kind: None,
                failure_stage: None,
                priority: "auto".to_string(),
                sources: 0,
                active_sources: 0,
                queued_sources: 0,
                queue_rank: None,
                last_seen_complete: None,
                last_received: None,
                health: TransferHealth::Healthy,
                health_reason: None,
                health_code: None,
                stalled_since: None,
                category: String::new(),
                wait_time: wait_seconds,
                upload_time: 0,
                a4af_sources: 0,
                max_sources: 0,
                preview_priority: false,
                preview_ready: false,
                ember_sources: 0,
                client_software,
                country_code,
                user_hash,
                ember_hash,
                expected_aich: None,
                ember_file_hash: None,
                completed_path: None,
                up_part_status: None,
                up_part_count: None,
                up_peer_part_status: None,
                ember_verified: false,
                friends_only: false,
            };
            {
                let mut mgr = transfer_manager.write().await;
                mgr.enqueue(transfer.clone());
            }
            let _ = app_handle.emit("transfer-started", &transfer);
        }
        UploadEventKind::Identity {
            ember_hash,
            client_software,
            peer_name,
        } => {
            let snapshot = {
                let mut mgr = transfer_manager.write().await;
                mgr.active.get_mut(&event.transfer_id).map(|t| {
                    if ember_hash.is_some() {
                        t.ember_hash = ember_hash;
                    }
                    if !client_software.is_empty() {
                        t.client_software = client_software;
                    }
                    if !peer_name.is_empty() {
                        t.peer_name = peer_name;
                    }
                    t.clone()
                })
            };
            if let Some(transfer) = snapshot {
                let _ = app_handle.emit("transfer-started", &transfer);
            }
        }
        UploadEventKind::Progress {
            uploaded: _,
            uploaded_wire,
            unique_uploaded,
            total,
            part_status,
            part_count,
            peer_part_status,
        } => {
            // Unique coverage, not session wire bytes. Re-requests inflate
            // `uploaded` past `total` while the peer still needs parts; the
            // percentage and `completed_size` follow unique bytes so a
            // small-file progress fill cannot read 100% while coverage is
            // still short. The chunked parts-bar overlay is served-parts /
            // part-count on the frontend.
            let unique_capped = if total > 0 {
                unique_uploaded.min(total)
            } else {
                unique_uploaded
            };
            let progress = if total > 0 {
                ((unique_capped as f64 / total as f64) * 100.0).min(100.0)
            } else {
                0.0
            };
            let (speed, upload_time_ms) = {
                let mut mgr = transfer_manager.write().await;
                // Wire bytes, not unique coverage and not payload. Speed is
                // bytes_delta over a rolling window; unique coverage can
                // stall (peer re-requesting a part we already served) while
                // the wire is still moving, and payload runs ahead of the wire
                // by the compression ratio on `OP_COMPRESSEDPART`.
                //
                // This line said "raw session wire bytes" while passing the
                // payload counter, which is issue 115: the limiter is charged
                // the compressed length, so the cap and the status-bar total
                // are wire figures, and a row derived from payload read high
                // by the compression ratio. Slots then summed above a cap they
                // had not breached, with the total sitting correctly below
                // them. The payload counter is not dropped: the event loop
                // reads `uploaded` off this same event before dispatching here
                // (`library_upload_delta`) for the all-time totals, and the
                // upload worker credits the peer with it directly.
                mgr.update_progress(&event.transfer_id, uploaded_wire, Some(unique_capped));
                // A fresh slot against a full token bucket can still window
                // above the cap; clamp so the row cannot read higher than the
                // limiter is allowed to spend (issue 115).
                mgr.cap_active_speed(&event.transfer_id, upload_speed_limit);
                let t = mgr.active.get_mut(&event.transfer_id);
                let speed = t.as_ref().map(|t| t.speed).unwrap_or(0);
                let ut = t
                    .map(|t| {
                        let elapsed =
                            (chrono::Utc::now().timestamp() - t.started_at).max(0) as u64 * 1000;
                        t.upload_time = elapsed;
                        // Persist the served-parts bitmap on the row so the
                        // 3 s transfer poll keeps the parts bar in sync with
                        // the live `transfer-progress` events between polls.
                        if part_status.is_some() {
                            t.up_part_status = part_status.clone();
                        }
                        if part_count.is_some() {
                            t.up_part_count = part_count;
                        }
                        // Always assign (Some or None): keyed by file hash on the
                        // session side, so if a row stops matching the advertised
                        // file the dark "peer has" shading clears instead of
                        // lingering stale.
                        t.up_peer_part_status = peer_part_status.clone();
                        elapsed
                    })
                    .unwrap_or(0);
                (speed, ut)
            };
            let _ = app_handle.emit(
                "transfer-progress",
                &crate::types::TransferProgressPayload {
                    id: &event.transfer_id,
                    downloaded: 0,
                    total,
                    progress,
                    speed,
                    // Wire bytes, matching the limiter and the row's speed.
                    // Passing the payload counter here made the Transferred
                    // column (and the frontend EWMA that reads it) run ahead
                    // of the cap by the compression ratio — issue 115.
                    uploaded: Some(uploaded_wire),
                    completed_size: Some(unique_capped),
                    direction: Some("upload"),
                    upload_time: Some(upload_time_ms),
                    up_part_status: part_status,
                    up_part_count: part_count,
                    up_peer_part_status: peer_part_status,
                },
            );
        }
        UploadEventKind::ShareInterest { .. } | UploadEventKind::SharesBrowsed { .. } => {}
        UploadEventKind::Completed { full_file } => {
            // Match eMule's "session ends → row vanishes" UX. We still
            // call `mgr.complete()` so the queued-promotion logic fires
            // and stats are accurate, but we then immediately drop the
            // transfer from `mgr.completed` so a subsequent `get_all()`
            // poll doesn't resurrect the row in the upload pane after
            // the frontend has already removed it on `transfer-complete`.
            // Cumulative byte totals live in `StatsManager`, not in the
            // per-session `Transfer`, so dropping the row loses no
            // historical data.
            // Bound so the write guard is released before anything below it
            // runs, rather than living as long as the `match` it scrutinises.
            let completed = {
                let mut mgr = transfer_manager.write().await;
                let promoted = mgr.complete(&event.transfer_id);
                mgr.completed.retain(|t| t.id != event.transfer_id);
                promoted
            };
            let Some(promoted) = completed else {
                return;
            };
            // Only count Statistics "Completed Uploads" when this peer
            // received the entire file — matching hash-verified download
            // completion. Partial sessions (idle timeout, preemption, mid-
            // slot file switch) still dismiss the row above but must not
            // inflate the counter. Also require `mgr.complete()` success so
            // duplicate/stale Completed events don't over-report.
            if full_file {
                stats_manager.record_completed_upload();
            }
            for t in &promoted {
                info!(
                    "Promoted queued transfer {} ({}) to active",
                    t.id, t.file_name
                );
            }
            promoted_out.extend(promoted);
            let _ = app_handle.emit(
                "transfer-complete",
                serde_json::json!({ "id": event.transfer_id, "direction": "upload" }),
            );
        }
        UploadEventKind::Failed { error } => {
            // Same removal rationale as `Completed` above. The previous
            // 5s sleep before `completed.retain(..)` was meant to let
            // the failure surface in the UI for a moment, but with the
            // frontend now actively dropping upload rows on the
            // `transfer-failed` event (matching eMule), keeping the
            // backend record around for 5s only created a window where
            // a poll could re-add the failed row to the store.
            // Redact the raw upload error the same way the download path does
            // (`classify_failure` only ever yields fixed, canned strings), so peer
            // IPs / local paths from anyhow chains don't leak into the UI's
            // `failure_reason` or upload history.
            let upload_failure =
                ed2k::transfer::classify_failure(&error, &ed2k::transfer::classify_error(&error));
            // Same as the Completed arm: bind the block so the write guard
            // does not outlive it.
            let failed = {
                let mut mgr = transfer_manager.write().await;
                let promoted = mgr.fail(&event.transfer_id, upload_failure, None, None);
                mgr.completed.retain(|t| t.id != event.transfer_id);
                promoted
            };
            let Some(promoted) = failed else {
                return;
            };
            for t in &promoted {
                info!(
                    "Promoted queued transfer {} ({}) to active",
                    t.id, t.file_name
                );
            }
            promoted_out.extend(promoted);
            let _ = app_handle.emit(
                "transfer-failed",
                serde_json::json!({
                    "id": event.transfer_id,
                    "error": upload_failure.message(),
                    "failure_code": upload_failure.as_code(),
                    "direction": "upload",
                }),
            );
        }
        UploadEventKind::EmberSources { .. }
        | UploadEventKind::EmberPeerDiscovered { .. }
        | UploadEventKind::FriendSeen { .. }
        | UploadEventKind::EmberChatMessage { .. }
        | UploadEventKind::EmberChatTyping { .. }
        | UploadEventKind::EmberChatRead { .. }
        | UploadEventKind::EmberBrowseRequest { .. }
        | UploadEventKind::EmberBrowseResponse { .. }
        | UploadEventKind::EmberBrowseScope { .. }
        | UploadEventKind::EmberBrowseSummary { .. }
        | UploadEventKind::EmberBrowseSessionReady { .. }
        | UploadEventKind::EmberBrowseSessionFailed { .. }
        | UploadEventKind::EmberFriendDisconnected { .. }
        | UploadEventKind::EmberFriendConnected { .. }
        | UploadEventKind::FriendEndpointDiscovered { .. }
        | UploadEventKind::EmberFriendSearchFailed { .. }
        | UploadEventKind::PeerAutoBanned { .. }
        | UploadEventKind::EmberTransferRequest { .. }
        | UploadEventKind::EmberTransferAck { .. }
        | UploadEventKind::EmberFileOffer { .. }
        | UploadEventKind::EmberAttachOffer { .. }
        | UploadEventKind::EmberAttachReply { .. }
        | UploadEventKind::EmberAttachCancel { .. }
        | UploadEventKind::EmberRelayOffer { .. }
        | UploadEventKind::EmberDhtContactRequest { .. }
        | UploadEventKind::EmberDhtContacts { .. }
        | UploadEventKind::EmberFileOfferAck { .. }
        | UploadEventKind::EmberFriendRequest { .. }
        | UploadEventKind::EmberFriendRetract { .. }
        | UploadEventKind::EmberFriendDecline { .. } => {
            // Handled directly in the network event loop.
        }
    }
}
