//! Read-only snapshots for the UI: KAD contacts and searches, peers, file
//! details, the upload queue, and known clients.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

pub(super) fn kad_contacts_snapshot(state: &NetworkState, local_id: KadId) -> Vec<KadContactInfo> {
    state
        .routing_table
        .all_contacts()
        .map(|contact| {
            let distance = contact.id.xor_distance(&local_id);
            KadContactInfo {
                id: contact.id.to_hex(),
                contact_type: contact.contact_type,
                version: contact.version,
                distance: distance.to_hex(),
                ip_verified: contact.verified,
                bootstrap: contact.contact_type == CONTACT_TYPE_NEW && contact.version == 0,
            }
        })
        .collect()
}

pub(super) fn kad_searches_snapshot(state: &NetworkState) -> Vec<KadSearchInfo> {
    state
        .search_manager
        .active
        .iter()
        .map(|(sid, search)| {
            let type_name = match search.search_type {
                SearchType::FindNode => "Node",
                SearchType::FindKeyword => "Keyword",
                SearchType::FindSource { .. } => "File",
                SearchType::FindNotes { .. } => "Notes",
                SearchType::FindBuddy => "Buddy",
                SearchType::StoreFile => "Store File",
                SearchType::StoreKeyword => "Store Keyword",
                SearchType::StoreNotes => "Store Notes",
            };
            let name = match search.search_type {
                SearchType::FindKeyword => "Keyword Search".to_string(),
                SearchType::FindSource { .. } => state
                    .download_source_searches
                    .get(sid)
                    .and_then(|(tid, _)| {
                        state
                            .pending_downloads
                            .get(tid)
                            .map(|pd| pd.file_name.clone())
                    })
                    .unwrap_or_else(|| "Source Search".to_string()),
                SearchType::FindBuddy => "Find Buddy".to_string(),
                // Publishes carry their own subject (file name / keyword),
                // stamped by `name_kad_search` at scheduling time — the
                // publish side-maps cannot answer for them here because they
                // are cleared as soon as the search completes, while the row
                // remains listed as "STOPPING" for `STOP_GRACE_SECS`.
                SearchType::StoreFile | SearchType::StoreKeyword | SearchType::StoreNotes => {
                    search.display_name.clone()
                }
                SearchType::FindNode | SearchType::FindNotes { .. } => String::new(),
            };
            let is_store = matches!(
                search.search_type,
                SearchType::StoreFile | SearchType::StoreKeyword | SearchType::StoreNotes
            );
            let is_routing_walk = matches!(
                search.search_type,
                SearchType::FindNode | SearchType::FindBuddy
            );
            // Store searches: contacts in the closest-pool (where the publish
            // landed). Find* fetch searches (keyword/source/notes): actual
            // result entries. Pure routing walks (FindNode/FindBuddy) never
            // populate `results` — they walk the DHT to grow the routing
            // table — so their progress is best summarised as "verified
            // contacts found".
            let responses = if is_store {
                search.closest.len() as u32
            } else if is_routing_walk {
                search.responded_during_lookup.len() as u32
            } else {
                search.results.len() as u32
            };
            // K11: populate load_* from real search state so the UI can
            // actually render a progress meter. Semantics match eMule's
            // search-debugging columns as closely as the data permits:
            //   load_total:    contacts that have been queried at all
            //                  (i.e. whose outcome is known or pending).
            //   load_response: contacts that actually responded during
            //                  the lookup phase (verified alive).
            //   load:          percentage of queried contacts that have
            //                  answered — 0-100.
            let queried = search.queried.len() as u32;
            let responded = search.responded_during_lookup.len() as u32;
            let pending = search.pending.len() as u32;
            let load_total = queried.saturating_add(pending);
            let load_pct = (responded * 100).checked_div(queried).unwrap_or(0);
            KadSearchInfo {
                id: sid.0,
                target: search.target.to_hex(),
                search_type: type_name.to_string(),
                name,
                status: if search.completed {
                    "stopping".to_string()
                } else {
                    "active".to_string()
                },
                load: load_pct,
                load_response: responded,
                load_total,
                packets_sent: queried,
                request_answer: pending,
                responses,
                started_at: search.started_at,
            }
        })
        .collect()
}

pub(super) fn routing_peers_snapshot(state: &NetworkState) -> Vec<PeerInfo> {
    state
        .routing_table
        .all_contacts()
        .take(200)
        .map(|contact| PeerInfo {
            id: contact.id.to_hex(),
            addresses: vec![format!("{}:{}", contact.ip, contact.udp_port)],
            nickname: state
                .peer_nicknames
                .get(&contact.id)
                .cloned()
                .unwrap_or_default(),
            last_seen: contact.last_seen,
            files_shared: 0,
            banned: false,
        })
        .collect()
}

pub(super) fn merge_saved_peers(mut peers: Vec<PeerInfo>, saved_peers: Vec<PeerInfo>) -> Vec<PeerInfo> {
    for saved in saved_peers {
        if let Some(existing) = peers.iter_mut().find(|peer| peer.id == saved.id) {
            if !saved.nickname.is_empty() {
                existing.nickname = saved.nickname;
            }
            if !saved.addresses.is_empty() {
                existing.addresses = saved.addresses;
            }
            existing.last_seen = existing.last_seen.max(saved.last_seen);
            existing.files_shared = existing.files_shared.max(saved.files_shared);
            existing.banned = saved.banned;
        } else if saved.banned {
            peers.push(saved);
        }
    }

    peers
}

/// Map a `IdentState` enum value into the short label the UI displays
/// in the upload-pane "Queued" / "Known Clients" tabs. Mirrors the
/// strings eMule itself uses in its "Identification" client-detail
/// row so existing eMule users immediately recognise them.
pub(super) fn ident_state_label(state: ed2k::credits::IdentState) -> &'static str {
    use ed2k::credits::IdentState;
    match state {
        IdentState::Verified => "Verified",
        IdentState::Failed => "Failed",
        IdentState::BadGuy => "BadGuy",
        IdentState::Needed => "Needed",
        IdentState::Unknown => "Unknown",
    }
}

/// Build the chunk map and part counters behind the "File Details" window.
///
/// Two sources, because no one place holds both halves: the part tracker knows
/// what we have, and the persistent per-file source list knows what the swarm
/// has. The live per-source bitmaps belong to the download task and are not
/// reachable from here, so the swarm half is whatever the stored list last
/// learned from a TCP file status or a UDP reask — fresh enough for a window
/// the user opened deliberately, and the alternative is nothing at all.
pub(super) async fn download_file_details(
    state: &NetworkState,
    transfer_id: &str,
) -> crate::types::DownloadFileDetails {
    use crate::network::ed2k::part_tracker::pack_part_bitmap;

    /// Same budget the reask bitmap read uses: long enough that an uncontended
    /// read always wins, short enough that a busy tracker answers the window
    /// with "not available" instead of stalling the network task.
    const TRACKER_READ_BUDGET: std::time::Duration = std::time::Duration::from_millis(50);

    let mut details = crate::types::DownloadFileDetails {
        part_count: 0,
        local_part_status: String::new(),
        swarm_part_status: String::new(),
        verified_parts: 0,
        in_progress_parts: 0,
        rarest_part_sources: 0,
        sources_with_bitmaps: 0,
        completed_bytes: 0,
        verified_bytes: 0,
        remaining_bytes: 0,
        transferred: 0,
        tracked: false,
    };

    let tracker = state.tracker_registry.lock().get(transfer_id).cloned();
    let Some(tracker) = tracker else {
        return details;
    };
    let Ok(guard) = tokio::time::timeout(TRACKER_READ_BUDGET, tracker.read()).await else {
        debug!("Tracker busy for {transfer_id}; File Details has nothing to draw this time");
        return details;
    };

    let part_count = guard.part_count;
    let file_size = guard.file_size;
    details.tracked = true;
    details.part_count = part_count as u32;
    details.local_part_status = pack_part_bitmap(&guard.completed_parts());
    details.verified_parts = guard.verified_parts().iter().filter(|&&v| v).count() as u32;
    details.in_progress_parts = guard.in_progress_part_count() as u32;
    details.completed_bytes = guard.completed_bytes();
    details.verified_bytes = guard.verified_bytes();
    details.remaining_bytes = guard.remaining_gap_bytes();
    details.transferred = guard.transferred();
    drop(guard);

    if part_count == 0 {
        return details;
    }

    // Per-part source counts, built the way `ChunkSelector::update_frequencies`
    // builds its own: one pass per source that has sent a bitmap, ignoring the
    // ones that have not. The table stays here and only its minimum travels.
    let mut frequency = vec![0u16; part_count];
    let mut swarm = vec![false; part_count];
    // Peers advertise the eD2K *wire* part count, `floor(size / PARTSIZE) + 1`,
    // which is one more than the tracker's `ceil(size / PARTSIZE)` exactly when
    // the size is a whole multiple of `PARTSIZE`. Requiring strict equality
    // therefore rejected every bitmap for such a file, and the window claimed
    // nobody in the swarm held any part at all.
    let wire_part_count = ed2k::messages::ed2k_wire_part_count(file_size);
    if let Some(list) = state.per_file_sources.get(transfer_id) {
        for source in &list.sources {
            let len = source.available_parts.len();
            if len != part_count && len != wire_part_count {
                // A bitmap for a different part count describes a different
                // file, or a source that has not answered yet. Either way it
                // cannot be folded in.
                continue;
            }
            details.sources_with_bitmaps = details.sources_with_bitmaps.saturating_add(1);
            for (i, &has) in source.available_parts.iter().enumerate() {
                // Bound as `ChunkSelector::update_frequencies` does, so the
                // wire count's trailing pseudo-part is ignored rather than
                // overflowing the table.
                if has && i < part_count {
                    frequency[i] = frequency[i].saturating_add(1);
                    swarm[i] = true;
                }
            }
        }
    }
    details.swarm_part_status = pack_part_bitmap(&swarm);
    details.rarest_part_sources = frequency.iter().copied().min().unwrap_or(0);
    details
}

/// Build the on-demand snapshot for the upload-pane "Queued" tab.
/// Walks the upload queue once with a single read lock on each shared
/// resource (`upload_queue`, `credit_manager`, `local_index`,
/// `friend_hashes`) and resolves all per-row data the UI needs:
///   - file name (via local index)
///   - lifetime credit ratio + uploaded/downloaded totals
///   - 1-based queue rank computed via the same scoring rules the
///     upload server uses for slot allocation, so the rank shown here
///     matches the rank the peer sees in their own client UI
///   - geoip country code
///
/// Returns rows in the queue's natural insertion order; the UI is free
/// to re-sort by any column.
pub(super) async fn upload_queue_snapshot(
    queue: &ed2k::upload::UploadQueueRef,
    credit_manager: &Arc<RwLock<ed2k::credits::CreditManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    geoip: &crate::geoip::GeoIpReader,
) -> Vec<crate::types::UploadQueueClient> {
    // Snapshot the queue under a short-lived lock so we don't hold the
    // upload server's mutex while we're awaiting other RwLocks (which
    // could otherwise deadlock against `start_uploading_to_peer`).
    let queue_snapshot: Vec<ed2k::upload::QueueEntry> = {
        let mut q = queue.lock().await;
        // `last_request`, not `join_time`. eMule's waiting-list purge keys on
        // `GetLastUpRequest` (`UploadQueue.cpp:119`) and `QueueEntry` splits
        // the two fields precisely so seniority can accrue on one clock while
        // the purge runs on the other. Keying this site on `join_time` evicted
        // every waiter an hour after it arrived however faithfully it had been
        // re-asking — and because this runs from `get_upload_queue`, which the
        // transfers page polls every 15s on any tab, it bounded the whole
        // waiting list by arrivals-per-hour. Every other purge site already
        // uses `last_request`; this one was missed.
        q.retain(|e| e.last_request.elapsed().as_secs() < ed2k::upload::MAX_PURGEQUEUETIME_SECS);
        q.clone()
    };
    if queue_snapshot.is_empty() {
        return Vec::new();
    }
    // Peers also queue for files we are still downloading, which the shared
    // index does not hold. Read before the other locks and released at once.
    let downloading_names: HashMap<String, String> = {
        let wanted: HashSet<String> =
            queue_snapshot.iter().map(|e| hex::encode(e.file_hash)).collect();
        let mgr = transfer_manager.read().await;
        mgr.active
            .values()
            .chain(mgr.queue.iter())
            .filter(|t| t.direction == TransferDirection::Download && wanted.contains(&t.file_hash))
            .map(|t| (t.file_hash.clone(), t.file_name.clone()))
            .collect()
    };
    let cm = credit_manager.read().await;
    let idx = local_index.read().await;
    let friends = friend_hashes.read().await;

    let ranks = ed2k::upload::compute_queue_ranks(&cm, &idx, &queue_snapshot);
    let mut out = Vec::with_capacity(queue_snapshot.len());
    for (entry, &rank) in queue_snapshot.iter().zip(&ranks) {
        let wait_secs = entry.join_time.elapsed().as_secs();
        // Every waiting peer has a rank, so every row gets one.
        //
        // This used to be withheld whenever `current_addr` was `None`, on the
        // theory that it matched eMule showing `?` for a queued LowID waiting
        // for a callback. It does not: eMule's `?` is for *our* position in a
        // *remote* peer's queue, which we genuinely do not know until they
        // send `OP_QUEUERANKING`. Our own queue is the one place the number is
        // never in doubt — `compute_queue_ranks` above scores the whole queue
        // and does not care whether a socket happens to be open.
        //
        // And `current_addr` is `None` for almost every row: a peer that has
        // been told it is queued hangs up and re-asks later, which clears the
        // binding while the entry keeps its seniority. So the Position column
        // showed `?` and nothing else, for the entire queue. The connection
        // state it was standing in for now travels as its own field.
        let queue_rank = rank as u32;

        // The address the credit lookups below are allowed to see: the live
        // socket, or the identity when the identity *is* an address. Kept
        // deliberately narrow, and specifically without the `last_ip` fallback
        // used for display: `CreditManager` reads a zero IP as "we do not know
        // where this peer is right now" and declines to call a verified peer a
        // BadGuy on that basis. Handing it a stale address would re-flag every
        // peer on a dynamic IP the moment they re-asked from a new one.
        let credit_ip_v4 = match entry.current_addr {
            Some(addr) => match addr.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
            },
            None => match &entry.identity {
                ed2k::upload::QueueIdentity::Ip(ip) => match ip {
                    std::net::IpAddr::V4(v4) => Some(*v4),
                    std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                },
                ed2k::upload::QueueIdentity::UserHash(_) => None,
            },
        };
        let peer_ip_u32 = credit_ip_v4
            .map(|v4| u32::from_be_bytes(v4.octets()))
            .unwrap_or(0);

        // The address the row shows, and the one the flag is resolved from.
        // `last_ip` is the fallback that matters: it outlives the socket (it is
        // what the per-IP queue cap counts), and a queued peer is disconnected
        // between re-asks, so `current_addr` is `None` for nearly every row.
        // Without it a `UserHash` entry reported no address at all and the
        // Country column came out blank for the whole queue.
        let display_ip = entry
            .current_addr
            .map(|addr| addr.ip())
            .or(match &entry.identity {
                ed2k::upload::QueueIdentity::Ip(ip) => Some(*ip),
                ed2k::upload::QueueIdentity::UserHash(_) => None,
            })
            .or(entry.last_ip);
        let peer_ip_str = display_ip.map(|ip| ip.to_string()).unwrap_or_default();
        // Their advertised listen port, never the ephemeral source port of a
        // connection they happen to hold. Nothing displays this; the UI keys
        // its rows on it, so it has to name the peer the same way across a
        // re-ask, and the advertised port is the one the rest of the queue
        // identifies a peer by (`queue_row_owned_by_session`, matching eMule's
        // `AttachToAlreadyKnown`). Reporting the source port meant a row was
        // torn down and rebuilt every time the peer connected or hung up.
        let peer_port = entry.tcp_port;
        let credit_ratio = cm.get_score_ratio(&entry.user_hash, peer_ip_u32);
        let ident_state =
            ident_state_label(cm.get_current_ident_state(&entry.user_hash, peer_ip_u32))
                .to_string();
        let (uploaded, downloaded) = cm
            .get_record(&entry.user_hash)
            .map(|r| (r.uploaded, r.downloaded))
            .unwrap_or((0, 0));

        let file_hash_hex = hex::encode(entry.file_hash);
        let file_name = idx
            .get_by_hash(&file_hash_hex)
            .map(|f| f.name.clone())
            .or_else(|| downloading_names.get(&file_hash_hex).cloned())
            .unwrap_or_else(|| String::from("(unknown file)"));

        // Resolved from the full address, not a v4-mapped copy of it, so a
        // v6-only peer gets a flag too.
        let country_code = display_ip.and_then(|ip| crate::geoip::lookup_country(geoip, ip));

        let user_hash_hex = if entry.user_hash == [0u8; 16] {
            String::new()
        } else {
            hex::encode(entry.user_hash)
        };
        let is_friend = entry
            .ember_pubkey
            .filter(|_| entry.ember_verified)
            .map(|pk| {
                let hash = blake3::hash(&pk);
                let mut ember_id = [0u8; 16];
                ember_id.copy_from_slice(&hash.as_bytes()[..16]);
                friends.contains(&ember_id)
            })
            .unwrap_or(false);

        out.push(crate::types::UploadQueueClient {
            user_hash: user_hash_hex,
            peer_ip: peer_ip_str,
            peer_port,
            file_hash: file_hash_hex,
            file_name,
            wait_seconds: wait_secs,
            queue_rank,
            connected: entry.current_addr.is_some(),
            peer_name: entry.peer_name.clone(),
            client_software: entry.client_software.clone(),
            credit_ratio,
            uploaded,
            downloaded,
            ident_state,
            country_code,
            is_friend,
            emule_version: entry.emule_version,
        });
    }
    out
}

/// Build the on-demand snapshot for the upload-pane "Known Clients"
/// tab. Reads every persisted SecIdent credit record (eMule's
/// clients.met) so this tab is the lifetime view of every peer we've
/// ever traded credit with — independent of which peers happen to be
/// connected right now. Friend markers use the Ember node id bound to
/// each credit row (not the eD2K user hash).
///
/// Ember friends often land in `clients.met` via `set_ember_hash`
/// (reseed / Hello binding) with zero transfer bytes and `ident_ip == 0`.
/// Their usable address and last-seen live in the friends SQLite table,
/// so we join that metadata in here before handing rows to the UI.
/// Most rows [`known_clients_snapshot`] will let cross IPC. Shared with
/// [`known_client_counts`] so the tab label cannot describe a different set
/// than the table it opens.
pub(super) const MAX_KNOWN_CLIENT_ROWS: usize = 5_000;

/// Count what [`known_clients_snapshot`] would return, without building it.
///
/// Kept immediately beside that function because the two have to agree: a tab
/// label that disagrees with the table it opens is worse than a stale one. The
/// only thing that decides which tab a record lands on is whether it resolves
/// an Ember identity — from the persisted `ember_hash`, or from a live queue
/// row that verified one this session before the credit flush landed — so this
/// reproduces exactly that rule and nothing else. No friends lookup, no ident
/// state, no credit ratio, no GeoIP, and no per-row allocation.
pub(super) async fn known_client_counts(
    credit_manager: &Arc<RwLock<ed2k::credits::CreditManager>>,
    upload_queue: &ed2k::upload::UploadQueueRef,
) -> crate::types::KnownClientCounts {
    let live_ember: std::collections::HashSet<[u8; 16]> = {
        let q = upload_queue.lock().await;
        q.iter()
            .filter(|entry| {
                entry.user_hash != [0u8; 16] && entry.ember_verified && entry.ember_pubkey.is_some()
            })
            .map(|entry| entry.user_hash)
            .collect()
    };

    let cm = credit_manager.read().await;
    // The snapshot sorts most-recently-seen first and trims to
    // `MAX_KNOWN_CLIENT_ROWS`, so counting the whole ledger would make the
    // label jump every time the user entered or left the tab once the ledger
    // passed the cap. Reproduce the trim on the same key.
    //
    // The snapshot's key is `max(record.last_seen, friend last_seen)`; this
    // uses the record's alone, because reading the friends table is exactly
    // the cost this command exists to avoid. The two can only disagree about
    // rows sitting on the cap boundary, and only for friends whose DB row is
    // fresher than their credit row.
    let mut rows: Vec<(i64, bool)> = cm
        .all_records()
        .iter()
        .map(|record| {
            (
                record.last_seen,
                record.ember_hash.is_some() || live_ember.contains(&record.user_hash),
            )
        })
        .collect();
    if rows.len() > MAX_KNOWN_CLIENT_ROWS {
        rows.select_nth_unstable_by(MAX_KNOWN_CLIENT_ROWS, |a, b| b.0.cmp(&a.0));
        rows.truncate(MAX_KNOWN_CLIENT_ROWS);
    }

    let mut counts = crate::types::KnownClientCounts::default();
    for (_, is_ember) in rows {
        if is_ember {
            counts.ember = counts.ember.saturating_add(1);
        } else {
            counts.ed2k = counts.ed2k.saturating_add(1);
        }
    }
    counts
}

pub(super) async fn known_clients_snapshot(
    credit_manager: &Arc<RwLock<ed2k::credits::CreditManager>>,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    upload_queue: &ed2k::upload::UploadQueueRef,
    geoip: &crate::geoip::GeoIpReader,
    db: &Arc<Database>,
) -> Vec<crate::types::KnownClient> {
    struct FriendMeta {
        nickname: String,
        last_ip: String,
        last_seen: i64,
    }

    // Friends table is small; read off the network task so we never hold
    // the credit lock across a blocking SQLite call.
    let db_q = db.clone();
    // Keyed by raw hash bytes rather than lowercase hex: the ranking pass
    // below consults this once per credit record, and a hex key would force a
    // `String` allocation per record purely to do the lookup. The friends
    // table is small, so decoding once here is strictly cheaper.
    let friend_meta: std::collections::HashMap<[u8; 16], FriendMeta> =
        match tokio::task::spawn_blocking(move || {
            let mut map = std::collections::HashMap::new();
            match db_q.get_friends_full() {
                Ok(rows) => {
                    for (hash, nick, _added, last_ip, _port, last_seen, _mutual) in rows {
                        let Some(key) = parse_ed2k_hash16(&hash) else {
                            continue;
                        };
                        map.insert(
                            key,
                            FriendMeta {
                                nickname: nick,
                                last_ip,
                                last_seen,
                            },
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("known_clients_snapshot: friends lookup failed: {e}");
                }
            }
            map
        })
        .await
        {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!("known_clients_snapshot: friends lookup task failed: {e}");
                std::collections::HashMap::new()
            }
        };

    // Live queue bindings fill gaps for peers we verified this session
    // before the credit flush lands (and for older DB rows that predate
    // the ember_hash column).
    let mut live_ember: std::collections::HashMap<[u8; 16], [u8; 16]> =
        std::collections::HashMap::new();
    {
        let q = upload_queue.lock().await;
        for entry in q.iter() {
            if entry.user_hash == [0u8; 16] || !entry.ember_verified {
                continue;
            }
            if let Some(pk) = entry.ember_pubkey {
                let hash = blake3::hash(&pk);
                let mut ember_id = [0u8; 16];
                ember_id.copy_from_slice(&hash.as_bytes()[..16]);
                live_ember.insert(entry.user_hash, ember_id);
            }
        }
    }

    let cm = credit_manager.read().await;
    let friends = friend_hashes.read().await;
    let records = cm.all_records();

    // Rank before enriching. Every record used to pay an ident-state lookup, a
    // score-ratio computation, two `hex::encode`s, an IP parse, a GeoIP mmdb
    // lookup and several more allocations — up to 50,000 times at the credit
    // cap — and the truncate below then discarded ~90% of it. The sort key is
    // the same one the old code sorted on, `max(record.last_seen, friend
    // last_seen)`, but computing it now costs no allocation at all, so only
    // the survivors are built. This also cuts how long the credit read lock is
    // held roughly tenfold, which matters because tokio's fair `RwLock` parks
    // the upload path's credit writers behind this snapshot.
    let mut ranked: Vec<(i64, usize)> = records
        .iter()
        .enumerate()
        .map(|(idx, record)| {
            let ember = record
                .ember_hash
                .or_else(|| live_ember.get(&record.user_hash).copied());
            let meta_last_seen = ember
                .and_then(|eh| friend_meta.get(&eh))
                .map(|m| m.last_seen)
                .unwrap_or(i64::MIN);
            (record.last_seen.max(meta_last_seen), idx)
        })
        .collect();
    // Bound what crosses IPC. The credit ledger holds up to
    // `MAX_CREDIT_RECORDS` (50,000) rows and the Known Clients tab re-fetches
    // every 8 s, so an untrimmed snapshot serialised a multi-megabyte payload
    // on a repeating timer for a table that renders a thousand rows. Trimming
    // the *oldest* entries is the right end to lose: they are the peers a
    // lifetime-view is least likely to be asked about.
    if ranked.len() > MAX_KNOWN_CLIENT_ROWS {
        debug!(
            "Known clients snapshot: {} record(s) trimmed to the {MAX_KNOWN_CLIENT_ROWS} most recent",
            ranked.len()
        );
        ranked.select_nth_unstable_by(MAX_KNOWN_CLIENT_ROWS, |a, b| b.0.cmp(&a.0));
        ranked.truncate(MAX_KNOWN_CLIENT_ROWS);
    }
    // Stable, useful default order: most-recently-seen first. The UI can
    // re-sort by any column.
    ranked.sort_by_key(|(last_seen, _)| std::cmp::Reverse(*last_seen));

    ranked
        .into_iter()
        .filter_map(|(_, idx)| records.get(idx).copied())
        .map(|record| {
            let ident_state =
                ident_state_label(cm.get_current_ident_state(&record.user_hash, record.ident_ip))
                    .to_string();
            let credit_ratio = cm.get_score_ratio(&record.user_hash, record.ident_ip);
            let ember = record
                .ember_hash
                .or_else(|| live_ember.get(&record.user_hash).copied());
            let is_friend = ember.map(|eh| friends.contains(&eh)).unwrap_or(false);
            let meta = ember.and_then(|eh| friend_meta.get(&eh));

            // The proven address first: a session address is only as good as
            // the user hash the peer claimed on it.
            let ip_u32 = if record.ident_ip != 0 { record.ident_ip } else { record.seen_ip };
            let mut last_known_ip = (ip_u32 != 0)
                .then(|| std::net::Ipv4Addr::from(ip_u32.to_be_bytes()).to_string());
            if last_known_ip.is_none() {
                if let Some(m) = meta {
                    if !m.last_ip.is_empty() {
                        last_known_ip = Some(m.last_ip.clone());
                    }
                }
            }

            let mut last_seen = record.last_seen;
            if let Some(m) = meta {
                if m.last_seen > last_seen {
                    last_seen = m.last_seen;
                }
            }

            let country_code = last_known_ip.as_deref().and_then(|ip_str| {
                ip_str
                    .parse::<std::net::IpAddr>()
                    .ok()
                    .and_then(|ip| crate::geoip::lookup_country(geoip, ip))
            });

            crate::types::KnownClient {
                user_hash: hex::encode(record.user_hash),
                peer_name: record.peer_name.clone(),
                client_software: record.client_software.clone(),
                downloaded: record.downloaded,
                uploaded: record.uploaded,
                credit_ratio,
                last_seen,
                ident_state,
                last_known_ip,
                country_code,
                has_public_key: !record.public_key.is_empty(),
                ember_hash: ember.map(hex::encode),
                is_friend,
                nickname: meta.map(|m| m.nickname.clone()).unwrap_or_default(),
            }
        })
        .collect()
}

// ----- AntiLeech filter command helpers ----------------------------
//
// All four helpers run on the network task (synchronous; the
// `parking_lot` lock around the filter is non-blocking) so the upload
// hot path can never observe a half-applied state.
