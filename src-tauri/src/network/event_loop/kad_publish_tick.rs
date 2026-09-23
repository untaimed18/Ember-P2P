//! The 2 s KAD publish scheduler (eMule KADEMLIAPUBLISHTIME): starts at most
//! one source, one keyword and one note store per tick.

use super::*;

pub(in crate::network) async fn on_kad_publish_tick(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
) {
    const KADEMLIA_TOTAL_STORE_SRC: usize = 4;
    const KADEMLIA_TOTAL_STORE_KEY: usize = 3;
    const KADEMLIA_TOTAL_STORE_NOTES: usize = 1;
    const REPUBLISH_NOTE_SECS: i64 = 24 * 3600;

    if state.stats.status == NetworkStatus::Disconnected || state.routing_table.is_empty() {
        return;
    }

    // eMule `CSharedFileList::Publish()` examines exactly one
    // round-robin candidate per type per tick — a blind index
    // walk (`m_currFileSrc`/`GetNextKeyword()`/`m_currFileNotes`)
    // that only sometimes lands on something actually due —
    // rather than scanning the whole set for the next due item.
    // With the concurrency caps below now an effective throttle
    // (searches occupy their slot for close to the full eMule
    // lifetime, see `check_phase_transition`), matching this
    // walk too avoids Ember reacting to "just became due" faster
    // than eMule ever would.
    let active_store_src = state.store_source_searches.len();
    if active_store_src < KADEMLIA_TOTAL_STORE_SRC {
        let in_flight_sources: HashSet<KadId> = state
            .store_source_searches
            .values()
            .map(|(hash, _)| *hash)
            .collect();
        if let Some(file) = state.publish_manager.next_source_candidate().cloned() {
            if in_flight_sources.contains(&file.file_hash) {
                // Already being published this cycle — eMule's
                // PrepareLookup would likewise no-op on a
                // duplicate target. The cursor already moved on.
            } else if let Some(msg) = state.publish_manager.build_source_publish(&file) {
                let closest = state
                    .routing_table
                    .find_closest_prefer_verified(&file.file_hash, SEARCH_INITIAL_CONTACTS);
                if !closest.is_empty() {
                    let sid = start_kad_search(
                        state,
                        app_handle,
                        file.file_hash,
                        SearchType::StoreFile,
                        closest,
                    );
                    if sid != SearchId(0) {
                        name_kad_search(state, sid, &file.file_name);
                        // Fresh publish cycle: reset before lookup-time
                        // publishes can receive acks.
                        state.source_publish_acks.insert(file.file_hash, 0);
                        state.store_source_searches.insert(sid, (file.file_hash, msg));
                    }
                }
            } else {
                debug!(
                    "Skipping source publish for {} — firewalled={} buddy={} direct_udp_cb={}",
                    file.file_hash,
                    state.publish_manager.firewalled,
                    state.publish_manager.buddy_id.is_some(),
                    state.publish_manager.direct_udp_callback,
                );
            }
        }
    }

    // Advertise ourselves under the Ember rendezvous key so a node
    // with an empty DHT table can find us. Rides the same store
    // slot budget and the same round-robin tick as shared-file
    // publishes, and is skipped unless we are actually useful as a
    // bootstrap contact:
    //
    //   * Ember on — otherwise we would not answer a DHT PING.
    //   * `build_source_publish` returns None for an unreachable
    //     firewalled node, which is exactly who should not be
    //     listed as a bootstrap contact.
    //
    // Deliberately *not* gated on sharing files any more. Ember has
    // no hardcoded bootstrap seeds, so this key is the only way a
    // cold node joins, and requiring a shared library to appear in
    // it excluded every downloader — a large share of exactly the
    // reachable, long-running nodes that make good first contacts.
    // Answering a DHT PING has nothing to do with having a library.
    // The cost is one source record per five hours.
    let rendezvous_now = chrono::Utc::now().timestamp();
    let rendezvous_due = settings.ember_native_enabled
        && rendezvous_now.saturating_sub(state.ember_rendezvous_published_at)
            > EMBER_RENDEZVOUS_REPUBLISH_SECS;
    if rendezvous_due && state.store_source_searches.len() < KADEMLIA_TOTAL_STORE_SRC {
        let key = kad::publish::ember_rendezvous_key();
        let already_publishing = state
            .store_source_searches
            .values()
            .any(|(hash, _)| *hash == key);
        if !already_publishing {
            // A synthetic record, deliberately never added to the
            // publish manager's file set: that set is mirrored from
            // the shared library, and a phantom entry there would
            // surface in share counts and reconcile passes.
            let advert = kad::publish::PublishableFile {
                file_hash: key,
                file_name: String::new(),
                file_size: 0,
                file_type: String::new(),
                complete_sources: 0,
                keyword_publishable: false,
                last_source_publish: 0,
            };
            if let Some(msg) = state.publish_manager.build_source_publish(&advert) {
                let closest = state
                    .routing_table
                    .find_closest_prefer_verified(&key, SEARCH_INITIAL_CONTACTS);
                if !closest.is_empty() {
                    let sid = start_kad_search(
                        state,
                        app_handle,
                        key,
                        SearchType::StoreFile,
                        closest,
                    );
                    if sid != SearchId(0) {
                        // The advert is synthetic and has no file
                        // name, so label the row by what it is.
                        // `kadSearchNameLabel` translates this
                        // sentinel on the way to the UI.
                        name_kad_search(state, sid, "Ember Rendezvous");
                        state.ember_rendezvous_published_at = rendezvous_now;
                        state.source_publish_acks.insert(key, 0);
                        state.store_source_searches.insert(sid, (key, msg));
                        // `info!`, not `debug!`: once per republish
                        // interval in steady state, and it is the
                        // only record that this node is discoverable
                        // by peers who have never met it.
                        info!("Ember rendezvous: advertising self under {key}");
                    }
                }
            }
        }
    }

    let active_store_key = state.store_keyword_searches.len();
    if active_store_key < KADEMLIA_TOTAL_STORE_KEY {
        let in_flight_keywords: HashSet<KadId> = state
            .store_keyword_searches
            .values()
            .map(|batch| batch.keyword_hash)
            .collect();
        if let Some(batch) = state.publish_manager.next_keyword_candidate() {
            if !in_flight_keywords.contains(&batch.keyword_hash) {
                let closest = state
                    .routing_table
                    .find_closest_prefer_verified(&batch.keyword_hash, SEARCH_INITIAL_CONTACTS);
                if !closest.is_empty() {
                    let sid = start_kad_search(
                        state,
                        app_handle,
                        batch.keyword_hash,
                        SearchType::StoreKeyword,
                        closest,
                    );
                    if sid != SearchId(0) {
                        name_kad_search(state, sid, &batch.keyword);
                        state.store_keyword_searches.insert(sid, batch);
                    }
                }
            }
        }
    }

    let active_store_notes = state.pending_note_publishes.len();
    if active_store_notes < KADEMLIA_TOTAL_STORE_NOTES {
        let now_ts = chrono::Utc::now().timestamp();
        let in_flight: HashSet<KadId> = state
            .pending_note_publishes
            .values()
            .map(|pending| pending.file_hash)
            .collect();
        let due_note = round_robin_next(&state.published_notes, &mut state.notes_publish_cursor)
            .filter(|hash| !in_flight.contains(hash))
            .and_then(|hash| state.published_notes.get(&hash).map(|note| (hash, note)))
            .filter(|(_, note)| now_ts - note.last_publish > REPUBLISH_NOTE_SECS)
            .map(|(hash, note)| {
                (
                    hash,
                    note.rating,
                    note.comment.clone(),
                    note.file_name.clone(),
                    note.file_size,
                )
            });

        if let Some((file_hash, rating, comment, file_name, file_size)) = due_note {
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&file_hash, SEARCH_INITIAL_CONTACTS);
            if !closest.is_empty() {
                let sid = start_kad_search(
                    state,
                    app_handle,
                    file_hash,
                    SearchType::StoreNotes,
                    closest,
                );
                if sid != SearchId(0) {
                    name_kad_search(
                        state,
                        sid,
                        file_name.as_deref().unwrap_or_default(),
                    );
                    let local_note_file = {
                        let index = local_index.read().await;
                        index.get_by_hash(&file_hash.to_hex()).cloned()
                    };
                    let message = build_publish_notes_message(
                        state.local_id,
                        file_hash,
                        local_note_file,
                        file_name.as_deref(),
                        file_size,
                        rating,
                        &comment,
                    );
                    state.pending_note_publishes.insert(
                        sid,
                        PendingNotePublish {
                            file_hash,
                            rating,
                            comment: comment.clone(),
                            file_name: file_name.clone(),
                            file_size,
                            message,
                        },
                    );
                    // `last_publish`/the DB row are updated once the
                    // search actually completes and PublishNotesReq
                    // packets go out (see the `sent > 0` branch in
                    // the StoreNotes search-completion handler
                    // below), not here at scheduling time — a
                    // search that finds no reachable closest nodes
                    // or times out would otherwise still reset the
                    // 24h republish timer despite nothing being
                    // published.
                    info!("Republishing KAD note for file {file_hash} (search {})", sid.0);
                }
            }
        }
    }
}
