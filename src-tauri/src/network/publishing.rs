//! KAD and eD2K publishing of shared files, including friends-only
//! filtering and publish badges.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Order-independent fingerprint of an `OP_OFFERFILES` list: `(entry_count,
/// xor_fold)`. Used by the `SharedFilesChanged` handler to skip re-sending
/// an offer that's identical to what the server was already told — see
/// `NetworkState::last_offer_files_signature`. Iteration order of the
/// backing index isn't guaranteed stable across calls, so entries are
/// XOR-folded (commutative) rather than hashed positionally; `entry_count`
/// is included as a cheap extra guard against the (astronomically unlikely)
/// case of two differing sets XOR-folding to the same value.
pub(super) fn offer_files_signature(files: &[ed2k::server::OfferFile]) -> (usize, u64) {
    use std::hash::{Hash, Hasher};
    let mut fold: u64 = 0;
    for f in files {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        f.hash.hash(&mut h);
        f.size.hash(&mut h);
        f.is_complete.hash(&mut h);
        f.name.hash(&mut h);
        fold ^= h.finish();
    }
    (files.len(), fold)
}

/// eMule's `ED2KREPUBLISHTIME`: `CSharedFileList::Process` calls
/// `SendListToServer` at most this often while unpublished files remain.
pub(super) const ED2K_OFFER_PACKET_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Files we have not yet published this server session.
///
/// Uncapped: the `min(soft_files, 200)` limit in `SendListToServer` is per
/// packet, and eMule keeps sending one such packet every
/// `ED2KREPUBLISHTIME` until nothing unpublished is left. The drain applies
/// both. What must never happen is a hash going out twice in one session —
/// Lugdunum answers that with "Too many files republished by your client
/// software. Please upgrade it." (aMule bug 303 was the same shape).
pub(super) fn incremental_ed2k_offers(
    desired: Vec<ed2k::server::OfferFile>,
    already_offered: &HashSet<[u8; 16]>,
) -> Vec<ed2k::server::OfferFile> {
    desired
        .into_iter()
        .filter(|file| !already_offered.contains(&file.hash))
        .collect()
}

pub(super) fn parse_ed2k_hash16(hash_hex: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hash_hex).ok()?;
    if bytes.len() < 16 {
        return None;
    }
    let mut h = [0u8; 16];
    h.copy_from_slice(&bytes[..16]);
    Some(h)
}

/// Parse a hex-encoded Ember content BLAKE3 (`FileInfo::ember_file_hash`) to
/// 32 bytes. Invalid or empty input yields zeros (legacy / not-yet-hashed).
pub(super) fn parse_ember_file_hash(hash_hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = hex::decode(hash_hex) {
        if bytes.len() == 32 {
            out.copy_from_slice(&bytes);
        }
    }
    out
}

/// Hashes that must not be advertised on the open network (server offers,
/// KAD source publish, EPX, UDP reask, source exchange).
pub(super) fn collect_friends_only_hashes(
    local_index: &crate::search::index::LocalIndex,
    known_files: &KnownFileList,
) -> HashSet<String> {
    let mut out: HashSet<String> = local_index
        .all_files()
        .iter()
        .filter(|f| f.friends_only && !f.hash.is_empty())
        .map(|f| f.hash.to_ascii_lowercase())
        .collect();
    for hash in collect_known_friends_only_hashes(known_files) {
        out.insert(hex::encode(hash));
    }
    out
}

pub(super) fn hash_hex_is_friends_only(restricted: &HashSet<String>, file_hash: &str) -> bool {
    restricted.contains(&file_hash.to_ascii_lowercase())
}

/// Open-network advertise of a partial is allowed only after known.met has
/// been absorbed. Until then a friends-only hash that exists only on disk
/// looks public (empty catalog + index miss).
pub(super) fn kad_may_advertise_partial(
    known_files: &KnownFileList,
    restricted: &HashSet<String>,
    file_hash: &str,
) -> bool {
    known_files.is_authoritative() && !hash_hex_is_friends_only(restricted, file_hash)
}

/// [`kad_may_advertise_partial`] for one of our downloads. A download taken
/// from a friend who restricts the file carries that on the transfer, since
/// neither the index nor known.met knows the hash until it completes.
pub(super) fn transfer_may_advertise_partial(
    known_files: &KnownFileList,
    restricted: &HashSet<String>,
    transfer: &Transfer,
) -> bool {
    !transfer.friends_only && kad_may_advertise_partial(known_files, restricted, &transfer.file_hash)
}

/// Complete shares: must be publicly listable on the index *and* not
/// friends-only in known.met. Until the catalog is absorbed, skip them
/// the same way as partials — a rematch row looks public.
pub(super) fn kad_may_advertise_complete(
    file: &FileInfo,
    known_files: &KnownFileList,
    restricted: &HashSet<String>,
) -> bool {
    file.is_public_listable() && kad_may_advertise_partial(known_files, restricted, &file.hash)
}

pub(super) fn hash16_is_friends_only(
    hash: &[u8; 16],
    local_index: &crate::search::index::LocalIndex,
    known_files: &KnownFileList,
) -> bool {
    let hex = hex::encode(hash);
    local_index
        .get_by_hash(&hex)
        .or_else(|| local_index.get_by_hash(&hex.to_ascii_uppercase()))
        .is_some_and(|f| f.friends_only)
        || known_files.find_by_hash(hash).is_some_and(|r| r.friends_only)
}

/// True when we already hold `hash` under our own public scope. A friend's
/// restriction must not override that: the user chose to share this content
/// openly before the friend's copy entered the picture. known.met decides when
/// it has a record, as it does on completion; otherwise a library row does.
pub(super) fn hash16_has_public_copy(
    hash: &[u8; 16],
    local_index: &crate::search::index::LocalIndex,
    known_files: &KnownFileList,
) -> bool {
    if let Some(record) = known_files.find_by_hash(hash) {
        return !record.friends_only;
    }
    let hex = hex::encode(hash);
    local_index
        .get_by_hash(&hex)
        .or_else(|| local_index.get_by_hash(&hex.to_ascii_uppercase()))
        .is_some_and(|f| !f.friends_only)
}

/// Register active/queued public downloads for KAD source publish. No-ops
/// until known.met is authoritative so a disk-only friends-only hash is not
/// advertised in the startup window.
pub(super) async fn publish_kad_partials_from_transfers(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
    known_files: &KnownFileList,
) -> u32 {
    if !known_files.is_authoritative() {
        return 0;
    }
    let restricted = {
        let index = local_index.read().await;
        collect_friends_only_hashes(&index, known_files)
    };
    let mut partial_count = 0u32;
    let mgr = transfer_manager.read().await;
    for transfer in mgr.active.values().chain(mgr.queue.iter()) {
        if transfer.direction != TransferDirection::Download {
            continue;
        }
        if matches!(
            transfer.status,
            TransferStatus::Completed | TransferStatus::Failed
        ) {
            continue;
        }
        if !transfer_may_advertise_partial(known_files, &restricted, transfer) {
            continue;
        }
        let hash_bytes = match hex::decode(&transfer.file_hash) {
            Ok(bytes) if bytes.len() >= 16 => bytes,
            _ => continue,
        };
        let ext = std::path::Path::new(&transfer.file_name)
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        state.publish_manager.add_file(PublishableFile {
            file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
            file_name: transfer.file_name.clone(),
            file_size: transfer.total_size,
            file_type: crate::search::index::infer_file_type(&ext),
            complete_sources: 0,
            keyword_publishable: false,
            last_source_publish: {
                let mut raw = [0u8; 16];
                raw.copy_from_slice(&hash_bytes[..16]);
                known_files
                    .find_by_hash(&raw)
                    .map(|r| r.last_publish_src as i64)
                    .unwrap_or(0)
            },
        });
        partial_count += 1;
    }
    partial_count
}

/// Register publicly listable completes for KAD source+keyword publish.
/// No-ops until known.met is authoritative; skips known.met friends-only
/// hashes even when the index row still looks public.
pub(super) async fn publish_kad_completes_from_index(
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    known_files: &KnownFileList,
) -> usize {
    if !known_files.is_authoritative() {
        return 0;
    }
    let files: Vec<PublishableFile> = {
        let index = local_index.read().await;
        let restricted = collect_friends_only_hashes(&index, known_files);
        index
            .all_files()
            .iter()
            .filter(|f| kad_may_advertise_complete(f, known_files, &restricted))
            .filter_map(|f| {
                let hash_bytes = hex::decode(&f.hash).ok()?;
                if hash_bytes.len() < 16 {
                    return None;
                }
                Some(PublishableFile {
                    file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                    file_name: f.name.clone(),
                    file_size: f.size,
                    file_type: crate::search::index::infer_file_type(&f.extension),
                    complete_sources: f.complete_sources,
                    keyword_publishable: true,
                    last_source_publish: {
                        let mut raw = [0u8; 16];
                        raw.copy_from_slice(&hash_bytes[..16]);
                        known_files
                            .find_by_hash(&raw)
                            .map(|r| r.last_publish_src as i64)
                            .unwrap_or(0)
                    },
                })
            })
            .collect()
    };
    let n = files.len();
    state.publish_manager.add_files_batch(files);
    n
}

/// Promote Connecting → Connected and register public files for KAD publish.
///
/// Both the 10s routing-table tick and the UDP bootstrap handler can decide
/// we are Connected. Only the tick used to populate the publish manager, so a
/// session whose first verified contact arrived on UDP never registered the
/// library. Call this from every promotion site.
pub(super) async fn promote_kad_connected_and_first_publish(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    local_index: &Arc<RwLock<LocalIndex>>,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    known_files: &KnownFileList,
) {
    if state.stats.status == NetworkStatus::Connected {
        return;
    }
    if state.routing_table.verified_len() < KAD_MIN_VERIFIED_FOR_CONNECTED {
        return;
    }
    if !kad_has_fresh_contact(state) {
        return;
    }
    state.stats.status = NetworkStatus::Connected;
    let _ = app_handle.emit("network-status", NetworkStatus::Connected);
    if state.first_publish_done {
        return;
    }
    state.first_publish_done = true;
    let shared_count =
        publish_kad_completes_from_index(state, local_index, known_files).await;
    let partial_count = publish_kad_partials_from_transfers(
        state,
        transfer_manager,
        local_index,
        known_files,
    )
    .await;
    info!(
        "Populated publish manager with {shared_count} shared files + {partial_count} partial downloads after bootstrap"
    );
}

pub(super) async fn or_index_friends_only_from_known(
    local_index: &Arc<RwLock<LocalIndex>>,
    known_files: &KnownFileList,
) {
    let hashes = collect_known_friends_only_hashes(known_files);
    if hashes.is_empty() {
        return;
    }
    local_index
        .write()
        .await
        .or_friends_only_from_hashes(&hashes);
}

/// known.met's friends-only records, plus the share intent's copy, which
/// survives a lost or partly read known.met.
pub(super) fn collect_known_friends_only_hashes(known_files: &KnownFileList) -> HashSet<[u8; 16]> {
    let mut out = crate::storage::share_intent::friends_only_hashes_if_ready();
    out.extend(
        known_files
            .iter_records()
            .filter(|r| r.friends_only)
            .map(|r| r.file_hash),
    );
    out
}

pub(super) fn sync_shared_friends_only_hashes(
    dest: &upload_server::SharedFriendsOnlyHashes,
    known_files: &KnownFileList,
) {
    upload_server::replace_friends_only_hashes(
        dest,
        collect_known_friends_only_hashes(known_files),
    );
    if known_files.is_authoritative() {
        upload_server::mark_friends_only_snapshot_ready(dest);
    }
}

/// Cheap change-detector for everything [`apply_publish_badges`] reads.
///
/// XOR-folding each set is order-independent, so the result does not depend on
/// `HashSet` iteration order, and mixing the length in makes a same-tick swap
/// (one hash published, another dropped) visible where comparing lengths alone
/// would miss it. Costs one XOR per published hash, which buys skipping a deep
/// clone of the entire shared-file list on every tick that changed nothing.
pub(super) fn publish_badge_fingerprint(
    kad_connected: bool,
    server_connected: bool,
    ember_live: bool,
    kad_published: &HashSet<[u8; 16]>,
    ed2k_offered: &HashSet<[u8; 16]>,
    ember_published: &HashSet<[u8; 16]>,
) -> u64 {
    fn fold(set: &HashSet<[u8; 16]>) -> u64 {
        let mut acc = set.len() as u64;
        for hash in set {
            // Two independently rotated lanes so two hashes cannot swap which
            // half each contributes and cancel out.
            let lo = u64::from_le_bytes(hash[0..8].try_into().unwrap_or_default());
            let hi = u64::from_le_bytes(hash[8..16].try_into().unwrap_or_default());
            acc ^= lo.rotate_left(17) ^ hi.rotate_left(43);
        }
        acc
    }
    let flags =
        (kad_connected as u64) | ((server_connected as u64) << 1) | ((ember_live as u64) << 2);
    flags
        ^ fold(kad_published).rotate_left(3)
        ^ fold(ed2k_offered).rotate_left(23)
        ^ fold(ember_published).rotate_left(47)
}

/// Set the Library KAD / eD2K / Ember badges from real publish/offer state,
/// not mere connectivity.
/// `ember_live` must be a real liveness test (verified contacts > 0), not
/// `settings.ember_native_enabled`, which is now permanently true. The Ember
/// publish set is seeded at startup from `known.met` stamps still inside their
/// TTL — last session's STOREs — so without a liveness term the Library showed
/// a green Ember badge on every file while the status bar said Connecting and
/// the Ember page showed a warning triangle. The KAD and eD2K badges beside it
/// have always required their connection.
pub(super) fn apply_publish_badges(
    files: &mut [FileInfo],
    kad_connected: bool,
    server_connected: bool,
    ember_live: bool,
    kad_published: &HashSet<[u8; 16]>,
    ed2k_offered: &HashSet<[u8; 16]>,
    ember_published: &HashSet<[u8; 16]>,
) {
    for f in files {
        let hash = parse_ed2k_hash16(&f.hash);
        // A friends-only file is never published or offered, so its badges
        // must stay dark even while every network is connected.
        let listable = f.is_public_listable();
        f.shared_kad =
            listable && kad_connected && hash.map(|h| kad_published.contains(&h)).unwrap_or(false);
        f.shared_ed2k = listable
            && server_connected
            && hash.map(|h| ed2k_offered.contains(&h)).unwrap_or(false);
        f.shared_ember = listable
            && ember_live
            && hash.map(|h| ember_published.contains(&h)).unwrap_or(false);
    }
}

/// How many files currently carry each publish badge.
///
/// Used to decide whether a cache refresh is worth telling the Library about.
/// Counting rather than diffing pairwise keeps this allocation-free and
/// independent of index ordering; the rare case where one file gains a badge
/// in the same tick another loses it is covered by the next refresh, and an
/// unshare emits its own event anyway.
pub(super) fn badge_counts(files: &[FileInfo]) -> (usize, usize, usize) {
    files.iter().fold((0, 0, 0), |(kad, ed2k, ember), f| {
        (
            kad + f.shared_kad as usize,
            ed2k + f.shared_ed2k as usize,
            ember + f.shared_ember as usize,
        )
    })
}

pub(super) fn record_offered_ed2k_hashes(state: &mut NetworkState, files: &[ed2k::server::OfferFile]) {
    for f in files {
        state.offered_ed2k_hashes.insert(f.hash);
    }
}

#[cfg(test)]
mod incremental_ed2k_offer_tests {
    use super::*;

    fn offer(n: u8, complete: bool) -> ed2k::server::OfferFile {
        ed2k::server::OfferFile {
            hash: [n; 16],
            name: format!("f{n}"),
            size: u64::from(n) * 100,
            is_complete: complete,
            file_type: String::new(),
        }
    }

    #[test]
    fn a_library_past_one_packet_is_offered_in_full() {
        let desired: Vec<_> = (1..=250).map(|n| offer(n, true)).collect();
        let sent = incremental_ed2k_offers(desired, &HashSet::new());
        assert_eq!(sent.len(), 250, "the per-packet cap belongs to the drain, not the session");
    }

    #[test]
    fn later_changes_send_only_new_hashes() {
        let desired: Vec<_> = (1..=4).map(|n| offer(n, true)).collect();
        let already = HashSet::from([[1; 16], [2; 16]]);
        let sent = incremental_ed2k_offers(desired, &already);
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].hash, [3; 16]);
        assert_eq!(sent[1].hash, [4; 16]);
    }

    #[test]
    fn an_offered_hash_is_never_sent_twice() {
        let desired: Vec<_> = (1..=2).map(|n| offer(n, true)).collect();
        let already = HashSet::from([[1; 16], [2; 16]]);
        assert!(incremental_ed2k_offers(desired, &already).is_empty());
    }

    #[test]
    fn leftover_hashes_would_skip_a_new_server_opening_dump() {
        let leftover = HashSet::from([[1; 16], [2; 16], [3; 16]]);
        assert!(
            incremental_ed2k_offers((1..=3).map(|n| offer(n, true)).collect(), &leftover)
                .is_empty(),
            "hashes from a previous session must not count against a new server"
        );
        assert_eq!(
            incremental_ed2k_offers((1..=3).map(|n| offer(n, true)).collect(), &HashSet::new())
                .len(),
            3
        );
    }
}

/// The map a transfer enforces at completion may only be seeded from remote
/// claims that more than one publisher backs. A plurality with no minimum made a
/// lone record its own majority, and because the entry is then pinned by
/// `or_insert`, a single wrong claim failed that file's verification for as long
/// as the process lived.
#[cfg(test)]
mod known_friends_only_snapshot_tests {
    use super::*;
    use crate::storage::known_files::KnownFileRecord;

    fn rec(hash: [u8; 16], friends_only: bool, path: &str) -> KnownFileRecord {
        KnownFileRecord {
            file_hash: hash,
            part_hashes: Vec::new(),
            file_name: "a.bin".into(),
            file_size: 1,
            file_path: path.into(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            modified_at: 0,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
            is_shared: true,
            friends_only,
            complete_sources: 0,
            last_ember_source_publish: 0,
            last_ember_keyword_publish: 0,
            media: None,
            media_scanned: false,
        }
    }

    #[test]
    fn known_met_only_friends_only_lands_in_the_upload_snapshot() {
        let mut known = KnownFileList::new();
        known.add_or_update(rec([0x11; 16], true, "/restricted.bin"));
        known.add_or_update(rec([0x22; 16], false, "/public.bin"));
        let dest: upload_server::SharedFriendsOnlyHashes =
            Arc::new(std::sync::RwLock::new(Default::default()));
        sync_shared_friends_only_hashes(&dest, &known);
        assert!(
            upload_server::friends_only_snapshot_contains(&dest, &[0x11; 16]),
            "a known.met friends-only hash must reach the upload listener"
        );
        assert!(
            !upload_server::friends_only_snapshot_contains(&dest, &[0x22; 16]),
            "public known.met records must not be treated as friends-only"
        );
    }

    #[test]
    fn clearing_friends_only_drops_the_hash_from_the_upload_snapshot() {
        let mut known = KnownFileList::new();
        known.add_or_update(rec([0x33; 16], true, "/was-restricted.bin"));
        let dest: upload_server::SharedFriendsOnlyHashes =
            Arc::new(std::sync::RwLock::new(Default::default()));
        sync_shared_friends_only_hashes(&dest, &known);
        assert!(upload_server::friends_only_snapshot_contains(&dest, &[0x33; 16]));

        known.find_by_hash_mut(&[0x33; 16]).unwrap().friends_only = false;
        sync_shared_friends_only_hashes(&dest, &known);
        assert!(
            !upload_server::friends_only_snapshot_contains(&dest, &[0x33; 16]),
            "lifting friends-only must unsync the upload restriction"
        );
    }

    #[test]
    fn kad_partial_hex_guard_is_case_insensitive() {
        let mut known = KnownFileList::new();
        known.add_or_update(rec([0xAB; 16], true, "/r.bin"));
        let index = crate::search::index::LocalIndex::new();
        let restricted = collect_friends_only_hashes(&index, &known);
        let lower = hex::encode([0xAB; 16]);
        assert!(hash_hex_is_friends_only(&restricted, &lower));
        assert!(hash_hex_is_friends_only(
            &restricted,
            &lower.to_ascii_uppercase()
        ));
        assert!(hash16_is_friends_only(&[0xAB; 16], &index, &known));
        assert!(!hash16_is_friends_only(&[0xCD; 16], &index, &known));
        assert!(
            !kad_may_advertise_partial(&known, &restricted, &lower),
            "a placeholder catalog must not advertise even a known friends-only hash"
        );
        assert!(
            !kad_may_advertise_partial(&known, &restricted, &hex::encode([0xCD; 16])),
            "unknown hashes must not be advertised until known.met is absorbed"
        );
    }

    fn public_share(hash_hex: &str) -> FileInfo {
        FileInfo {
            id: hash_hex.to_string(),
            name: "a.bin".into(),
            path: "/a.bin".into(),
            size: 1,
            hash: hash_hex.to_string(),
            aich_hash: String::new(),
            ember_file_hash: String::new(),
            extension: "bin".into(),
            modified_at: 0,
            priority: "normal".into(),
            requests: 0,
            accepted: 0,
            bytes_transferred: 0,
            alltime_requests: 0,
            alltime_accepted: 0,
            alltime_transferred: 0,
            complete_sources: 0,
            folder: String::new(),
            shared: true,
            friends_only: false,
            shared_kad: false,
            shared_ed2k: false,
            shared_ember: false,
        }
    }

    #[test]
    fn kad_complete_advertise_skips_placeholder_and_known_met_restricted() {
        let hash = [0xAB; 16];
        let hex = hex::encode(hash);
        let public = public_share(&hex);

        let placeholder = KnownFileList::new();
        let empty_restricted = HashSet::new();
        assert!(
            !kad_may_advertise_complete(&public, &placeholder, &empty_restricted),
            "complete advertise must wait for known.met the same way partials do"
        );

        let mut known = KnownFileList::new();
        known.mark_authoritative_for_tests();
        let restricted = collect_friends_only_hashes(&LocalIndex::new(), &known);
        assert!(
            kad_may_advertise_complete(&public, &known, &restricted),
            "a public complete must advertise once the catalog is absorbed"
        );

        known.add_or_update(rec(hash, true, "/r.bin"));
        let restricted = collect_friends_only_hashes(&LocalIndex::new(), &known);
        assert!(
            !kad_may_advertise_complete(&public, &known, &restricted),
            "known.met friends-only must win over a rematched public index row"
        );

        let mut friends_only = public.clone();
        friends_only.friends_only = true;
        let mut known_public = KnownFileList::new();
        known_public.mark_authoritative_for_tests();
        known_public.add_or_update(rec(hash, false, "/r.bin"));
        let restricted = collect_friends_only_hashes(&LocalIndex::new(), &known_public);
        assert!(
            !kad_may_advertise_complete(&friends_only, &known_public, &restricted),
            "index friends_only must still keep a file off the open network"
        );
    }

    #[test]
    fn kad_partial_advertise_once_catalog_is_authoritative() {
        let restricted_hash = [0xAB; 16];
        let public_hash = [0xCD; 16];
        let mut known = KnownFileList::new();
        known.add_or_update(rec(restricted_hash, true, "/r.bin"));
        let restricted = collect_friends_only_hashes(&LocalIndex::new(), &known);
        known.mark_authoritative_for_tests();
        assert!(
            !kad_may_advertise_partial(&known, &restricted, &hex::encode(restricted_hash)),
            "friends-only partials stay unpublished after absorb"
        );
        assert!(
            kad_may_advertise_partial(&known, &restricted, &hex::encode(public_hash)),
            "a public partial must advertise once the catalog is absorbed"
        );
    }

    fn download_of(hash: [u8; 16], friends_only: bool) -> Transfer {
        serde_json::from_value(serde_json::json!({
            "id": "t1",
            "file_name": "from-friend.bin",
            "file_hash": hex::encode(hash),
            "peer_id": "",
            "peer_name": "",
            "direction": "download",
            "status": "active",
            "progress": 0.0,
            "speed": 0,
            "total_size": 10,
            "transferred": 0,
            "started_at": 0,
            "friends_only": friends_only,
        }))
        .unwrap()
    }

    /// Neither the index nor known.met knows a partial taken from a friend's
    /// friends-only listing, so only the transfer's own flag can hold it back.
    #[test]
    fn friend_restricted_partial_is_never_advertised() {
        let hash = [0xEE; 16];
        let mut known = KnownFileList::new();
        known.mark_authoritative_for_tests();
        let restricted = collect_friends_only_hashes(&LocalIndex::new(), &known);
        assert!(transfer_may_advertise_partial(&known, &restricted, &download_of(hash, false)));
        assert!(!transfer_may_advertise_partial(&known, &restricted, &download_of(hash, true)));

        known.add_or_update(rec(hash, true, "/r.bin"));
        let restricted = collect_friends_only_hashes(&LocalIndex::new(), &known);
        assert!(
            !transfer_may_advertise_partial(&known, &restricted, &download_of(hash, false)),
            "known.met restrictions still apply to unflagged transfers"
        );
    }

    #[test]
    fn our_own_public_copy_is_detected_from_known_met_then_the_index() {
        let hash = [0xE1; 16];
        let hex = hex::encode(hash);
        let mut index = LocalIndex::new();
        let mut known = KnownFileList::new();
        assert!(!hash16_has_public_copy(&hash, &index, &known), "content we do not hold");

        index.add_file(public_share(&hex));
        assert!(hash16_has_public_copy(&hash, &index, &known), "a public library row");

        known.add_or_update(rec(hash, true, "/r.bin"));
        assert!(
            !hash16_has_public_copy(&hash, &index, &known),
            "a restricted known.met record outranks a public-looking row"
        );
        known.add_or_update(rec(hash, false, "/r.bin"));
        assert!(hash16_has_public_copy(&hash, &index, &known));

        let mut restricted_row = public_share(&hex);
        restricted_row.friends_only = true;
        let mut restricted_index = LocalIndex::new();
        restricted_index.add_file(restricted_row);
        assert!(!hash16_has_public_copy(&hash, &restricted_index, &KnownFileList::new()));
    }

    #[test]
    fn transfer_friends_only_defaults_to_unrestricted_when_absent() {
        let mut value = serde_json::to_value(download_of([0x01; 16], true)).unwrap();
        value.as_object_mut().unwrap().remove("friends_only");
        let parsed: Transfer = serde_json::from_value(value).unwrap();
        assert!(!parsed.friends_only);
    }

    #[test]
    fn kad_source_publish_treats_unknown_tcp_as_firewalled() {
        use crate::network::kad::firewall::FirewallStatus;
        assert!(
            !kad_source_publish_treat_as_firewalled(false, FirewallStatus::Open),
            "HighID with proven TCP Open is a direct type-1/4 source"
        );
        assert!(
            kad_source_publish_treat_as_firewalled(false, FirewallStatus::Unknown),
            "HighID before the TCP check finishes must not publish type-1/4"
        );
        assert!(kad_source_publish_treat_as_firewalled(
            false,
            FirewallStatus::Firewalled
        ));
        assert!(
            kad_source_publish_treat_as_firewalled(true, FirewallStatus::Open),
            "LowID stays on the buddy/type-6 path even if KAD TCP is Open"
        );
    }

    #[test]
    fn later_transfer_status_seq_wins() {
        assert!(transfer_status_write_is_stale(Some(2), 1));
        assert!(!transfer_status_write_is_stale(Some(1), 2));
        assert!(!transfer_status_write_is_stale(None, 1));
        assert!(
            transfer_status_write_is_stale(Some(5), 5),
            "equal seq is a duplicate, not a newer write"
        );
    }
}
