//! Syncing each shared file's Peers count (known complete copies) into the
//! library.

use super::*;

pub(in crate::network) async fn on_source_count_sync_tick(
    state: &NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
    known_files: &mut KnownFileList,
    shared_files: &Arc<RwLock<Vec<FileInfo>>>,
) {
    let hashes = {
        let index = local_index.read().await;
        index.all_hashes()
    };
    if hashes.is_empty() {
        return;
    }
    // Library "Peers" = known complete copies (active download PFS)
    // and/or KAD peers that ACK'd our source publish. Do NOT use
    // SourceManager::source_count — that counts every known peer
    // including incomplete ones and inflated the column.
    // `per_file_sources` is keyed by transfer id, so answering
    // "how many complete sources for this hash" from it is a
    // linear scan. Done once per shared file that was
    // O(shared files × tracked files) every 60s on the event loop
    // — tens of millions of comparisons for a large library.
    // Invert it once instead, then probe.
    let complete_by_hash: HashMap<[u8; 16], u32> = {
        let mut m: HashMap<[u8; 16], u32> =
            HashMap::with_capacity(state.per_file_sources.len());
        for pfs in state.per_file_sources.values() {
            let count = u32::from(pfs.complete_source_count());
            m.entry(pfs.file_hash)
                .and_modify(|c| *c = (*c).max(count))
                .or_insert(count);
        }
        m
    };
    let mut computed: Vec<(String, [u8; 16], u32)> = Vec::with_capacity(hashes.len());
    for hash_hex in &hashes {
        let hash_bytes: [u8; 16] = match hex::decode(hash_hex) {
            Ok(b) if b.len() == 16 => {
                let mut h = [0u8; 16];
                h.copy_from_slice(&b);
                h
            }
            _ => continue,
        };
        let mut count = complete_by_hash.get(&hash_bytes).copied().unwrap_or(0);
        // Purely-shared files (never searched/downloaded) have no
        // PFS entry; fall back to KAD publish ACKs — peers that
        // stored our source record. Local copy is not counted.
        let kad_hash = md4_bytes_to_kad_id(&hash_bytes);
        if let Some(&ack_count) = state.source_publish_acks.get(&kad_hash) {
            count = count.max(ack_count);
        }
        computed.push((hash_hex.clone(), hash_bytes, count));
    }

    let mut updates: Vec<(String, [u8; 16], u32)> = Vec::new();
    {
        let index = local_index.read().await;
        for (hash_hex, hash_bytes, count) in &computed {
            let current = index
                .get_by_hash(hash_hex)
                .map(|f| f.complete_sources)
                .unwrap_or(0);
            if current != *count {
                updates.push((hash_hex.clone(), *hash_bytes, *count));
            }
        }
    }

    if updates.is_empty() {
        return;
    }

    {
        let mut index = local_index.write().await;
        for (hash_hex, _, count) in &updates {
            index.update_complete_sources(hash_hex, *count);
        }
    }
    // Persist so Library shows last-known Peers at next startup
    // (including clearing to 0 when the gauge drops).
    let mut known_dirty = false;
    for (_, hash_bytes, count) in &updates {
        if let Some(record) = known_files.find_by_hash_mut(hash_bytes) {
            if record.complete_sources != *count {
                record.complete_sources = *count;
                known_dirty = true;
            }
        }
    }
    if known_dirty {
        known_files.mark_dirty();
    }
    let li_ref = local_index.clone();
    let s_files = shared_files.clone();
    let app_for_peers = app_handle.clone();
    let changed_count = updates.len();
    let kad_connected = state.stats.status == NetworkStatus::Connected;
    let srv_connected = state.server_connected;
    let ember_live =
        settings.ember_native_enabled && state.ember_dht.routing().verified_len() > 0;
    let kad_published = state.publish_manager.source_published_md4_hashes();
    let ed2k_offered = state.offered_ed2k_hashes.clone();
    let ember_published = state.ember_published_sources.clone();
    tokio::spawn(async move {
        let file_snap = {
            let index = li_ref.read().await;
            let mut snap = index.all_files().to_vec();
            apply_publish_badges(
                &mut snap,
                kad_connected,
                srv_connected,
                ember_live,
                &kad_published,
                &ed2k_offered,
                &ember_published,
            );
            snap
        };
        *s_files.write().await = file_snap;
        // Library only refreshes on this event (or scan done) —
        // without it the Peers column stayed stale for the
        // whole session after the initial load.
        let _ = app_for_peers.emit(
            "shared-files-changed",
            serde_json::json!({
                "phase": "peer-counts",
                "count": changed_count,
            }),
        );
    });
}
