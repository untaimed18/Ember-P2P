//! Download source discovery and injection: EPX sources, overflow queues,
//! server source requests, KAD callbacks, and asking every network.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Shared EPX source injection logic used by both DownloadEvent::EmberSources
/// and UploadEventKind::EmberSources handlers.
pub(super) async fn handle_epx_sources(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
    entries: &[([u8; 16], Vec<(Ipv4Addr, u16, u16, u8)>)],
    aich_roots: &[([u8; 16], [u8; 20])],
    ember_peers: &[(Ipv4Addr, u16)],
    relay_attestations: &[ember::RelayAttestation],
    // Ember identity of the peer this exchange came from, when one is bound.
    // Only used to charge relay attestations to an introducer.
    from_ember_hash: Option<[u8; 16]>,
    label: &str,
    include_pending_downloads: bool,
    we_are_unreachable: bool,
    // What a relay needs to reach a firewalled source, by `(ip, tcp_port)`.
    // Only our own DHT lookups know it; a peer's exchange carries neither.
    relay_targets: &HashMap<(Ipv4Addr, u16), ember::broker::RelayTarget>,
) -> usize {
    state.ember_diagnostics.epx_events_received = state
        .ember_diagnostics
        .epx_events_received
        .saturating_add(1);

    let mut total_injected = 0usize;
    let mut total_sources_this_event = 0usize;
    let mut total_sources_offered = 0usize;
    let mut total_sources_filtered = 0usize;
    let mut per_hash_persisted: HashMap<String, u32> = HashMap::new();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Charged to the peer that sent them, exactly as a friend's forwarded
    // offer is. Passing `None` here left EPX outside the per-introducer cap on
    // the grounds that reaching this path requires sharing a swarm with us —
    // but the global pool is small and evicts oldest-first, so one bound peer
    // could fill it with self-signed attestations and displace every relay
    // learned elsewhere. Sharing a swarm bounds who can try, not how much one
    // of them gets. A peer whose HELLO bound no identity stays uncharged and
    // is still held by the global cap alone.
    admit_relay_attestations(state, relay_attestations, now_unix, from_ember_hash, label);

    for (file_hash, sources) in entries {
        total_sources_offered += sources.len();
        let matching_ids = {
            let mgr = transfer_manager.read().await;
            let hash_hex = hex::encode(file_hash);
            let mut ids = matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex);
            if include_pending_downloads {
                for (tid, pd) in &state.pending_downloads {
                    if pd.file_hash == hash_hex && !ids.contains(tid) {
                        ids.push(tid.clone());
                    }
                }
            }
            ids
        };
        if matching_ids.is_empty() {
            continue;
        }
        for &(ip, port, udp_port, flags) in sources {
            if total_sources_this_event >= ember::MAX_EPX_TOTAL_SOURCES {
                break;
            }
            if flags & ember::SOURCE_FLAG_RELAY_CAPABLE != 0 {
                // Flag alone never admits a relay candidate — ERAT trailer
                // verification above is the only broker path. The peer is
                // still eligible for normal source injection below.
                debug!(
                    "EPX source {ip}:{port} advertised relay-capable; not treating flag as relay admission (attestation trailer required)"
                );
            }
            // Whether this source is worth having is decided in
            // `ember::ingest`, which takes only the facts it depends on and so
            // can be exercised without a `NetworkState`. Scoped: it borrows
            // three fields mutably, and the injection below needs the state
            // back.
            let verdict = {
                let mut admission = ember::ingest::SourceAdmission {
                    we_are_unreachable,
                    external_ip: state.external_ip,
                    dead_sources: &mut state.dead_sources,
                    ip_filter: &mut state.ip_filter,
                    banned_ips: &state.banned_ips,
                };
                admission.check(file_hash, ip, port, flags)
            };
            if let Err(reason) = verdict {
                total_sources_filtered += 1;
                debug!(
                    "EPX source {ip}:{port} dropped ({}) from {label}",
                    reason.as_str()
                );
                continue;
            }
            // A firewalled peer cannot accept a dial from us. `SourceAdmission`
            // keeps it only because *it* can reach us ("reachable ourselves, so
            // the peer can dial us"), and the address it declares is precisely
            // the one the DHT's anti-reflection bind exempts — see the
            // `SOURCE_FLAG_FIREWALLED` arm of `accept_record` in
            // `dht/engine.rs`, where a firewalled contact is stored without
            // having to match the sender's observed IP. So nothing vouches for
            // it, and handing it to a worker meant we dialled whatever host the
            // record named: useless against a genuinely firewalled peer, and a
            // way to aim a swarm of downloaders at a third party when the record
            // was forged.
            //
            // Keep the row out of TCP rotation. When we are also unreachable
            // and the source advertised `SOURCE_FLAG_RELAY_CAPABLE` (Ember DHT
            // firewalled publish does), start the same LowID↔LowID broker
            // KAD uses for Ember-capable callback sources — otherwise two
            // Ember-only firewalled peers that never hit KAD stay parked.
            // `LowToLowIp` / `EmberRelay` are never-dial; the broker hands
            // the worker an established stream on success.
            if flags & ember::SOURCE_FLAG_FIREWALLED != 0 {
                let mut stored_new = false;
                for transfer_id in &matching_ids {
                    let broker_started = ember_firewalled_source_should_broker(
                        we_are_unreachable,
                        flags,
                        ip,
                        port,
                    ) && start_ember_low_to_low_broker(
                        state,
                        transfer_id,
                        *file_hash,
                        ip,
                        port,
                        relay_targets.get(&(ip, port)).copied().unwrap_or_default(),
                    )
                    .await;
                    let pfs = state
                        .per_file_sources
                        .entry(transfer_id.clone())
                        .or_insert_with(|| {
                            ed2k::sources::PerFileSourceList::new(
                                *file_hash,
                                state.max_sources_per_file,
                            )
                        });
                    if pfs.add_source_full(ip, port, udp_port) {
                        stored_new = true;
                    }
                    if broker_started {
                        pfs.set_ember_relay(ip, port, None);
                    } else {
                        pfs.set_low_to_low(ip, port, None);
                    }
                }
                if stored_new {
                    state.ember_payload_dirty = true;
                    // Counted against the per-event ceiling like an injection,
                    // so a flood of firewalled entries cannot buy unlimited work.
                    total_sources_this_event += 1;
                    *per_hash_persisted
                        .entry(hex::encode(file_hash))
                        .or_default() += 1;
                }
                debug!(
                    "EPX source {ip}:{port} is firewalled; parked out of TCP dial ({label})"
                );
                continue;
            }
            // Only reuse connect_options / user_hash already known from
            // SourceManager. Never invent obfuscation (`0x02`) from the
            // unauthenticated EPX `SOURCE_FLAG_OBFUSCATION` bit alone —
            // that would steer dials toward crypt against peers that
            // never advertised it on the wire.
            let (peer_user_hash, peer_connect_options) = {
                let sm = source_manager.read().await;
                (
                    sm.get_user_hash(file_hash, ip, port),
                    sm.get_connect_options(file_hash, ip, port),
                )
            };
            let ds = ed2k::multi_source::DownloadSource {
                peer_ip: ip.to_string(),
                peer_port: port,
                available_parts: Vec::new(),
                peer_user_hash,
                peer_connect_options,
            };
            let stats = inject_source_into_active_transfers(
                state,
                *file_hash,
                &matching_ids,
                &ds,
                udp_port,
            );
            total_injected += stats.injected;
            // Persist EPX accepts into SourceManager so pause→resume can
            // reseed from SM (PFS-only peers were previously lost).
            if stats.injected > 0 || stats.persisted > 0 {
                let mut sm = source_manager.write().await;
                sm.register_source_full(
                    *file_hash,
                    ip,
                    port,
                    udp_port,
                    [0u8; 16],
                    // Ember Peer Exchange: another peer passed it on.
                    Some(crate::types::SourceOrigin::Exchange),
                );
            }
            // Only count sources that were actually new injections
            // against the per-event ceiling. The earlier behaviour
            // counted every source the EPX packet listed even when
            // `inject_source_into_active_transfers` deduped it as a
            // re-announcement; an attacker could then flood EPX with
            // many duplicate sources to saturate `MAX_EPX_TOTAL_SOURCES`
            // and force legitimate later-in-packet unique sources to
            // be dropped without being processed. Using `injected`
            // makes the cap track effective work, not packet bytes.
            if stats.injected > 0 {
                total_sources_this_event += stats.injected;
            }
            if stats.persisted > 0 {
                let hex = hex::encode(file_hash);
                *per_hash_persisted.entry(hex).or_default() += 1;
            }
        }
        if total_sources_this_event >= ember::MAX_EPX_TOTAL_SOURCES {
            break;
        }
    }

    // Pre-populate AICH root hashes received via EPX.
    //
    // EPX advertisements are unauthenticated, so a malicious peer could try
    // to poison the map by being the first to announce a wrong root for a
    // hash we haven't seen yet. To reduce the impact:
    //   1. Only accept the EPX-supplied root when we have *no* local master
    //      already (`aich_root_map` empty for this file).
    //   2. Only trust the root if it matches an existing authoritative
    //      source we already know (from a HashSet2 we retrieved ourselves
    //      or from an in-progress transfer) — otherwise treat it as a
    //      candidate and defer verification until recovery time
    //      (`corrupt_blocks_from_aich_recovery` already rejects blocks that
    //      don't reproduce the trusted master).
    //
    // The worst case is still that we try recovery against a bogus root and
    // reject the recovery — no blocks are written to disk without matching
    // the authoritative master.
    for (file_hash, aich_root) in aich_roots {
        if state.aich_root_map.contains_key(file_hash) {
            continue;
        }
        // Honour the same soft cap the periodic save timer warns
        // against. Refusing the insert (rather than evicting an
        // entry) keeps the security invariant — every retained root
        // came from a trusted hashset match — while bounding RAM
        // growth from a flood of EPX-advertised roots.
        if state.aich_root_map.len() >= MAX_AICH_ROOT_MAP_SOFT_CAP {
            tracing::warn!(
                "EPX: aich_root_map at soft cap ({}); skipping AICH pin for file {}",
                MAX_AICH_ROOT_MAP_SOFT_CAP,
                hex::encode(file_hash),
            );
            continue;
        }
        // L-EPX-AICH: `known2_64.met` is a flat list of recovery trees for
        // *all* of our own locally-known files with no ed2k-hash binding —
        // checking only `root_hash` membership let a peer pair a real root
        // belonging to an unrelated file we happen to have locally with an
        // arbitrary `file_hash`, poisoning that download's trusted AICH
        // master (recovery-DoS: every genuine block then fails to verify
        // against the wrong tree). Require the match to be specific to
        // *this* ed2k hash: only trust the EPX root when our own local
        // index's record for this exact file already carries the same
        // AICH root (populated once we've hashed/verified the file
        // ourselves — see the `aich_root_map` seeding in the EPX-rebuild
        // timer). Anything else is deferred, never pinned.
        let hash_hex = hex::encode(file_hash);
        let matches_trusted = {
            let index = local_index.read().await;
            index.get_by_hash(&hash_hex).is_some_and(|fi| {
                hex::decode(&fi.aich_hash)
                    .ok()
                    .is_some_and(|b| b.len() == 20 && b == aich_root)
            })
        };
        if matches_trusted {
            state.aich_root_map.insert(*file_hash, *aich_root);
            tracing::debug!(
                "EPX: pinned AICH root {} for file {} (matches our own local index record for this hash)",
                hex::encode(aich_root),
                hex::encode(file_hash)
            );
        } else {
            tracing::debug!(
                "EPX: deferring unverified AICH root {} for file {}",
                hex::encode(aich_root),
                hex::encode(file_hash)
            );
        }
    }

    // Track discovered Ember peers for mesh building. `record_known_ember_peer`
    // refreshes the timestamp on existing entries so peers we still hear
    // about don't get pruned by the TTL cycle.
    let mut new_peers = false;
    for &(ip, port) in ember_peers {
        if state.ip_filter.is_blocked(ip) {
            continue;
        }
        if state.banned_ips.contains(&ip) {
            continue;
        }
        if record_known_ember_peer(&mut state.known_ember_peers, ip, port) {
            new_peers = true;
        }
    }
    if new_peers {
        state.stats.ember_peers = state.known_ember_peers.len() as u32;
        state.ember_payload_dirty = true;
    }

    // Recorded whether or not anything was injected: an exchange that offered
    // hundreds of sources and yielded none is the case worth seeing, and it is
    // indistinguishable from a quiet network without these.
    state.ember_diagnostics.epx_sources_offered = state
        .ember_diagnostics
        .epx_sources_offered
        .saturating_add(total_sources_offered as u32);
    state.ember_diagnostics.epx_sources_filtered = state
        .ember_diagnostics
        .epx_sources_filtered
        .saturating_add(total_sources_filtered as u32);

    if total_injected > 0 {
        state.stats.epx_sources_received = state
            .stats
            .epx_sources_received
            .saturating_add(total_injected as u32);
        state.ember_payload_dirty = true;

        let mut mgr = transfer_manager.write().await;
        for t in mgr.active.values_mut() {
            if t.direction == TransferDirection::Download {
                if let Some(&count) = per_hash_persisted.get(&t.file_hash) {
                    t.ember_sources = t.ember_sources.saturating_add(count);
                }
            }
        }
        for t in mgr.queue.iter_mut() {
            if t.direction == TransferDirection::Download {
                if let Some(&count) = per_hash_persisted.get(&t.file_hash) {
                    t.ember_sources = t.ember_sources.saturating_add(count);
                }
            }
        }
        info!("Ember Peer Exchange ({label}): injected {total_injected} sources");
    }

    total_injected
}

pub(super) fn try_inject_source(
    sender: Option<&mpsc::Sender<DownloadSource>>,
    source: &DownloadSource,
) -> SourceInjectionResult {
    match sender {
        Some(sender) => match sender.try_send(source.clone()) {
            Ok(()) => SourceInjectionResult::Injected,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => SourceInjectionResult::Full,
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => SourceInjectionResult::Closed,
        },
        None => SourceInjectionResult::Closed,
    }
}

pub(super) const MAX_ACTIVE_SOURCE_OVERFLOW: usize = 128;
/// Buffer depth for newly-established (hole-punched / callback / relayed) peer
/// streams handed to a download worker before it picks them up. Each of these
/// is a live TCP connection that cannot be cheaply recreated, so the buffer is
/// kept generous to avoid dropping working connections under burst arrivals;
/// the worker drains it promptly so streams do not sit idle long.
pub(super) const ESTABLISHED_SOURCE_CHANNEL_CAP: usize = 32;
pub(super) const MAX_UDP_SOURCE_QUEUE: usize = 500;

pub(super) fn enqueue_overflow_source(
    state: &mut NetworkState,
    transfer_id: &str,
    source: &DownloadSource,
) -> bool {
    let queue = state
        .active_source_overflow
        .entry(transfer_id.to_string())
        .or_default();
    if queue
        .iter()
        .any(|queued| queued.peer_ip == source.peer_ip && queued.peer_port == source.peer_port)
    {
        return false;
    }
    if queue.len() >= MAX_ACTIVE_SOURCE_OVERFLOW {
        queue.pop_front();
    }
    queue.push_back(source.clone());
    true
}

pub(super) fn drain_active_source_overflow(state: &mut NetworkState) -> Vec<(String, usize, usize)> {
    let mut drained = Vec::new();
    let transfer_ids: Vec<String> = state.active_source_overflow.keys().cloned().collect();

    for transfer_id in transfer_ids {
        let Some(sender) = state.active_source_senders.get(&transfer_id).cloned() else {
            state.active_source_overflow.remove(&transfer_id);
            continue;
        };

        let mut injected = 0usize;
        let mut remaining = 0usize;
        let mut closed = false;

        if let Some(queue) = state.active_source_overflow.get_mut(&transfer_id) {
            while let Some(source) = queue.pop_front() {
                match sender.try_send(source) {
                    Ok(()) => injected += 1,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(source)) => {
                        queue.push_front(source);
                        break;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        closed = true;
                        break;
                    }
                }
            }
            remaining = queue.len();
        }

        if closed {
            state.active_source_senders.remove(&transfer_id);
            // Drop the established-source sender in lockstep so the
            // upload listener doesn't keep handing us inbound LowID
            // callback streams for a download that's no longer
            // listening (the receive task is gone with the worker).
            state.active_established_senders.remove(&transfer_id);
            state.active_source_overflow.remove(&transfer_id);
            state.active_kad_search_state.remove(&transfer_id);
            state
                .download_source_searches
                .retain(|_, (tid, _)| tid != &transfer_id);
            continue;
        }

        if remaining == 0 {
            state.active_source_overflow.remove(&transfer_id);
        }
        if injected > 0 || remaining > 0 {
            drained.push((transfer_id, injected, remaining));
        }
    }

    drained
}

/// How long a callback placeholder row stays visible before the periodic
/// sweep removes it. Matches eMule's [`FILEREASKTIME`](crate::network::ed2k::dead_sources::FILEREASKTIME_SECS)
/// cadence — the row is refreshed whenever we re-send `CallbackReq`.
pub(super) const KAD_CALLBACK_PLACEHOLDER_TIMEOUT_SECS: i64 =
    crate::network::ed2k::dead_sources::PENDING_KAD_CALLBACK_SECS;

/// Per-file interval for re-asking the connected eD2K server for sources when a
/// download is *starved* (no source currently transferring).
///
/// This is a *priority ordering*, not a licence to send: nothing leaves until
/// the shared frame budget below opens, and no file is asked again inside
/// [`SERVER_TCP_SRCREQ_FILE_REASK_SECS`], which is far longer than this. It
/// used to be the only gate, which put the real rate an order of magnitude
/// above what eMule permits itself.
pub(super) const STARVED_SERVER_REASK_SECS: i64 = 45;

/// Hashes one TCP `OP_GETSOURCES` frame may carry, and how long the connection
/// must then rest — eMule's `iMaxFilesPerTcpFrame` and `m_dwNextTCPSrcReq`
/// (`DownloadQueue.cpp:1307`, `:1387`).
///
/// eMule spells the reason out where it computes the delay: *"server credits:
/// 16 * iMaxFilesPerTcpFrame + 1 = 241"*. A Lugdunum server accounts for source
/// requests per connection and answers with silence once a client outruns its
/// credit, which takes the *whole* server half of source discovery down for the
/// session — so exceeding this is self-defeating rather than merely impolite.
///
/// Every request shares this one budget, because the server's accounting is per
/// connection and does not care which of our code paths a request came from.
/// The periodic sweep, the starved re-ask and warm-start each spend a frame;
/// a new download or Find Sources queues its file for the next one
/// ([`queue_server_source_ask`]) rather than sending, as eMule's
/// `SendLocalSrcRequest` does. Between them these paths once reached roughly 40
/// a minute against eMule's ceiling of 3, and a large collection could send
/// one per file at once.
pub(super) const SERVER_TCP_SRCREQ_MAX_PER_FRAME: usize = 15;
pub(super) const SERVER_TCP_SRCREQ_INTERVAL_SECS: i64 =
    (SERVER_TCP_SRCREQ_MAX_PER_FRAME as i64) * (16 + 4);

// The starved clock is an ordering hint *within* a frame interval, never a
// licence to send. Making it the longer of the two would silently restore an
// independent second rate, which is the bug this budget exists to close.
const _: () = assert!(STARVED_SERVER_REASK_SECS < SERVER_TCP_SRCREQ_INTERVAL_SECS);

/// Drop a written-off source from the persistent registry, so it stops counting
/// as a source we know about.
///
/// eMule pairs its dead-source marking with `RemoveSource` on every retire path
/// — connect failure and `DS_ERROR` (`BaseClient.cpp:1191-1193`), TCP
/// `OP_FILEREQANSNOFIL` (`ListenSocket.cpp:420-429`), UDP file-not-found
/// (`DownloadClient.cpp:1316-1325`) — and its `GetSourceCount()` is just
/// `srclist.GetCount()` (`PartFile.h:216`), so the number falls the moment a
/// source is written off.
///
/// Ember only did the marking. The row stayed in the registry, kept being
/// refreshed by whichever server or DHT answer re-offered it, and so kept
/// counting for up to `SOURCE_EXPIRY_SECS`. That matters twice over: it
/// overstates the swarm in the Sources column by however many peers we are
/// simultaneously refusing to contact, and the same figure gates every further
/// lookup against `max_sources_for_udp` — so a file whose sources have all died
/// reads as fully sourced and stops looking for more, which is exactly when it
/// needs to.
pub(super) async fn retire_dead_source_from_registry(
    source_manager: &Arc<RwLock<SourceManager>>,
    file_hash: &[u8; 16],
    ip: Ipv4Addr,
    port: u16,
) {
    source_manager
        .write()
        .await
        .remove_source(file_hash, &ip, port);
}

fn secs(s: i64) -> std::time::Duration {
    std::time::Duration::from_secs(s.max(0) as u64)
}

/// Whether another TCP source-request frame may go out now.
///
/// Also enforces the post-login settle window, so callers do not have to repeat
/// both checks.
///
/// The server source-request clocks here are monotonic, as eMule's
/// `::GetTickCount()` ones are: on the wall clock a step back closed the frame,
/// and held every file's re-ask floor, for the length of the step.
pub(super) fn server_tcp_srcreq_frame_open(state: &NetworkState, now: std::time::Instant) -> bool {
    state.server_connected
        && state
            .server_logged_in_at
            .is_some_and(|at| now.saturating_duration_since(at) >= secs(SERVER_SOURCE_SETTLE_SECS))
        && state.server_tcp_srcreq_next_at.is_none_or(|at| now >= at)
}

/// Close the frame after sending, mirroring eMule's
/// `m_dwNextTCPSrcReq = curTick + SEC2MS(...)`.
///
/// Charged once per frame regardless of how many of the 15 slots were used, as
/// eMule does — the credit is spent on the frame, not the hash.
pub(super) fn close_server_tcp_srcreq_frame(state: &mut NetworkState, now: std::time::Instant) {
    state.server_tcp_srcreq_next_at = Some(now + secs(SERVER_TCP_SRCREQ_INTERVAL_SECS));
}

/// eMule's `SERVERREASKTIME` (`Opcodes.h:65`): the least time between two TCP
/// `OP_GETSOURCES` for the same file, counted from its last request on any
/// path (`PartFile.cpp:2382`, stamped at `DownloadQueue.cpp:1337`).
///
/// The frame budget above limits how often a frame goes out, not what is in
/// it. With 15 or fewer downloads every file rode every frame, and the
/// post-login, warm-start and starved paths each asked again on top.
pub(super) const SERVER_TCP_SRCREQ_FILE_REASK_SECS: i64 = 15 * 60;

/// Whether `file_hash` may go out in another TCP `OP_GETSOURCES` at `now`.
pub(super) fn server_tcp_srcreq_file_due(
    asked_at: &HashMap<[u8; 16], std::time::Instant>,
    file_hash: &[u8; 16],
    now: std::time::Instant,
) -> bool {
    asked_at.get(file_hash).is_none_or(|at| {
        now.saturating_duration_since(*at) >= secs(SERVER_TCP_SRCREQ_FILE_REASK_SECS)
    })
}

/// Stamp `file_hash` as asked at `now`. Entries past the re-ask floor decide
/// nothing, so they are dropped whenever the map grows.
pub(super) fn note_server_tcp_srcreq_file(
    asked_at: &mut HashMap<[u8; 16], std::time::Instant>,
    file_hash: [u8; 16],
    now: std::time::Instant,
) {
    const PRUNE_ABOVE: usize = 1024;
    if asked_at.len() >= PRUNE_ABOVE {
        asked_at.retain(|_, at| {
            now.saturating_duration_since(*at) < secs(SERVER_TCP_SRCREQ_FILE_REASK_SECS)
        });
    }
    asked_at.insert(file_hash, now);
}

/// Explicit asks held for the coming frames. Past this the periodic sweep still
/// reaches every download, just not ahead of the others.
pub(super) const MAX_QUEUED_SERVER_SOURCE_ASKS: usize = 1024;

/// Put one download's file in line for the next TCP `OP_GETSOURCES` frame,
/// ahead of the periodic sweep's own picks — eMule's `SendLocalSrcRequest`.
/// When a frame is open the loop runs it at once (see the source timer in
/// `start_network`), so an ask is not left waiting on the sweep's 4-minute tick.
///
/// Returns whether the file is in line: false with no server session, when it
/// was asked within `SERVER_TCP_SRCREQ_FILE_REASK_SECS`, when this server
/// cannot index a file that large, or when the line is full.
pub(super) fn queue_server_source_ask(
    state: &mut NetworkState,
    transfer_id: &str,
    file_hash: [u8; 16],
    file_size: u64,
    now: std::time::Instant,
) -> bool {
    let Some(conn) = state.server_connection.as_ref().filter(|_| state.server_connected) else {
        return false;
    };
    if !ed2k::server::server_indexes_file_size(file_size, conn.session.server_flags) {
        return false;
    }
    push_server_source_ask(
        &mut state.server_tcp_srcreq_asks,
        &state.server_tcp_srcreq_file_at,
        transfer_id,
        file_hash,
        file_size,
        now,
    )
}

/// [`queue_server_source_ask`] past its session checks: one place in line
/// per file, none for a file inside its re-ask floor, and a bounded line.
pub(super) fn push_server_source_ask(
    asks: &mut VecDeque<(String, [u8; 16], u64)>,
    asked_at: &HashMap<[u8; 16], std::time::Instant>,
    transfer_id: &str,
    file_hash: [u8; 16],
    file_size: u64,
    now: std::time::Instant,
) -> bool {
    if !server_tcp_srcreq_file_due(asked_at, &file_hash, now) {
        return false;
    }
    if asks.iter().any(|(_, hash, _)| *hash == file_hash) {
        return true;
    }
    if asks.len() >= MAX_QUEUED_SERVER_SOURCE_ASKS {
        return false;
    }
    asks.push_back((transfer_id.to_string(), file_hash, file_size));
    true
}

/// Take the explicit asks that lead one frame off the head of the line,
/// oldest first and at most `max`. An ask `keep` refuses — its download has
/// gone, or its file was asked since it was queued — is dropped rather than
/// carried to the next frame.
pub(super) fn take_frame_source_asks(
    asks: &mut VecDeque<(String, [u8; 16], u64)>,
    max: usize,
    mut keep: impl FnMut(&str, &[u8; 16]) -> bool,
) -> Vec<(String, [u8; 16], u64)> {
    let mut frame: Vec<(String, [u8; 16], u64)> = Vec::new();
    while frame.len() < max {
        let Some((tid, fh, file_size)) = asks.pop_front() else {
            break;
        };
        if keep(&tid, &fh) && !frame.iter().any(|(_, queued, _)| *queued == fh) {
            frame.push((tid, fh, file_size));
        }
    }
    frame
}

/// Queue a TCP `OP_GETSOURCES` for one file, if there is a session and the
/// file's re-ask floor allows it. Every frame sends through here, so the floor
/// holds whichever path filled it.
///
/// Returns the wire bytes queued, 0 when nothing was sent — no session, asked
/// too recently, or a large file the server cannot index.
pub(super) fn send_server_get_sources(
    state: &mut NetworkState,
    file_hash: &[u8; 16],
    file_size: u64,
    now: std::time::Instant,
) -> anyhow::Result<u64> {
    if !server_tcp_srcreq_file_due(&state.server_tcp_srcreq_file_at, file_hash, now) {
        return Ok(0);
    }
    let Some(conn) = state.server_connection.as_mut() else {
        return Ok(0);
    };
    let bytes = conn.send_get_sources(file_hash, file_size)?;
    if bytes > 0 {
        note_server_tcp_srcreq_file(&mut state.server_tcp_srcreq_file_at, *file_hash, now);
    }
    Ok(bytes)
}

/// Grace period after a successful server login before we send the connection
/// its first OP_GETSOURCES requests. The server streams its post-login welcome
/// (OP_SERVERSTATUS / message / server list / ident) over the first ~1-2s;
/// firing source requests inside that window — especially the
/// login-batch + warm-start + starved-re-ask burst — is both premature and a
/// flood-protection risk on Lugdunum servers, which then silently drop the
/// requests. Holding off briefly lets the connection settle, matching eMule's
/// paced ProcessLocalRequests behaviour.
pub(super) const SERVER_SOURCE_SETTLE_SECS: i64 = 3;

pub(super) async fn register_or_refresh_pending_kad_callback(
    pending: &upload_server::PendingKadCallbacks,
    source_ip: Ipv4Addr,
    source_tcp_port: u16,
    file_hash: [u8; 16],
    user_hash: Option<[u8; 16]>,
    origin: crate::types::SourceOrigin,
) {
    // eMule matches a firewalled peer's callback connect-back primarily by its
    // ED2K *user hash* (ListenSocket OP_CALLBACK → AttachToAlreadyKnown →
    // CUpDownClient::Compare on the user hash), not by IP. The TAG_SOURCEIP a
    // firewalled peer publishes to the DHT is frequently its pre-NAT / stale
    // address, so its actual TCP connect-back arrives from a *different* egress
    // IP. Keying the pending callback only by the published IP (our old
    // behaviour) meant the inbound Hello — which carries the correct, stable
    // user hash but the "wrong" IP — never matched, so the source sat in
    // WaitCallback forever while the peer was in fact already knocking.
    //
    // Register under BOTH identities: the user hash (authoritative, matches
    // eMule) and the published IP (fast path when it happens to be accurate).
    // The inbound matcher in `upload.rs` already probes both key kinds.
    let mut keys: Vec<upload_server::PendingKadCallbackKey> = Vec::new();
    if let Some(h) = user_hash.filter(|h| *h != [0u8; 16]) {
        keys.push(upload_server::PendingKadCallbackKey::SourceUserHash(h));
    }
    if !source_ip.is_unspecified() {
        keys.push(upload_server::PendingKadCallbackKey::SourceIp(source_ip));
    }
    if keys.is_empty() {
        debug!(
            "Skipping pending KAD callback for {}: no TAG_SOURCEIP and no publisher user hash",
            hex::encode(file_hash),
        );
        return;
    }
    let key_desc = keys
        .iter()
        .map(|k| match k {
            upload_server::PendingKadCallbackKey::SourceIp(ip) => format!("ip={ip}"),
            upload_server::PendingKadCallbackKey::SourceUserHash(h) => {
                format!("uh={}", hex::encode(h))
            }
            upload_server::PendingKadCallbackKey::FriendEmber(h) => {
                format!("friend={}", hex::encode(h))
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    info!(
        "Registered pending KAD callback for file {} expecting connect-back from [{}] (tcp_port={})",
        hex::encode(file_hash),
        key_desc,
        source_tcp_port,
    );
    let now = chrono::Utc::now().timestamp();
    let mut cbs = pending.lock().await;
    for key in keys {
        let entries = cbs.entry(key).or_default();
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.file_hash == file_hash && e.expected_tcp_port == source_tcp_port)
        {
            entry.registered_at = now;
            entry.origin.get_or_insert(origin);
        } else if let Some(entry) = entries.iter_mut().find(|e| e.file_hash == file_hash) {
            entry.expected_tcp_port = source_tcp_port;
            entry.registered_at = now;
            entry.origin.get_or_insert(origin);
        } else {
            entries.push(upload_server::PendingKadCallbackEntry {
                file_hash,
                expected_tcp_port: source_tcp_port,
                registered_at: now,
                origin: Some(origin),
            });
        }
    }
}

/// Which of the buddy's two candidate UDP ports this attempt targets.
///
/// Publishers disagree about what `TAG_SERVERPORT` carries, so both
/// `buddy_port` and `buddy_port + 3` have to be tried — see the KAD
/// source-found call site for that history. What they must not do is go out in
/// the same instant.
///
/// eMule prices `KADEMLIA_CALLBACK_REQ` at a full minute's tokens per packet
/// (`PacketTracking.cpp:144-145`) against a bucket that is keyed on the sender
/// IP alone (`:161`) and caps at one minute (`:176-177`). A second packet to the
/// same IP is therefore always over budget, and the deficit does not clear
/// between attempts: from the second attempt onward the *primary* packet is
/// dropped as well, and on the sixth the buddy calls `AddBannedClient`
/// (`:188-192`) and ignores all our UDP for `CLIENTBANTIME` — two hours. Sending
/// both ports was thus a reliable way to never have a callback relayed at all,
/// which is what the "never relayed our CallbackReq" note elsewhere describes.
///
/// Alternating spends one token per 90 s attempt, which the bucket fully
/// replenishes, and still gives each candidate port three of the six tries
/// `MAX_CALLBACK_REASKS` allows.
pub(super) fn kad_callback_buddy_port(buddy_port: u16, attempt: u32) -> u16 {
    if attempt.is_multiple_of(2) {
        buddy_port
    } else {
        buddy_port.saturating_add(3)
    }
}

pub(super) async fn send_kad_callback_req(
    udp_socket: &UdpSocket,
    state: &NetworkState,
    buddy_ip: Ipv4Addr,
    buddy_port_raw: u16,
    buddy_hash: KadId,
    file_hash: [u8; 16],
    attempt: u32,
) -> bool {
    let callback_req = KadMessage::CallbackReq {
        buddy_id: buddy_hash,
        // eMule writes `CUInt128(reqfile->GetFileHash())` here, i.e. the
        // MD4 hash in KAD/CUInt128 byte order, not raw ed2k hash order.
        file_id: md4_bytes_to_kad_id(&file_hash),
        // The buddy relays this so the target peer knows what port to
        // connect back to us on — must be the STUN-confirmed public port
        // when remapped, not the raw local bind port (same reasoning as
        // FirewalledReq/Firewalled2Req).
        tcp_port: advertised_tcp_port(state),
    };
    let Ok(packet) = kad::messages::encode_packet(&callback_req) else {
        return false;
    };
    let buddy_addr = SocketAddr::new(
        buddy_ip.into(),
        kad_callback_buddy_port(buddy_port_raw, attempt),
    );
    // eMule BaseClient.cpp TryToConnect sends CallbackReq unencrypted
    // (`SendPacket(..., false, NULL, true, 0)`). Encrypting here breaks
    // delivery to buddies that expect a plain KADEMLIA_CALLBACK_REQ.
    //
    // One packet per attempt, matching `BaseClient.cpp:1451` — see
    // `kad_callback_buddy_port` for what a second one costs. Several of our
    // downloads can name the same firewalled source, and so the same buddy;
    // the shared per-destination budget holds all of them to one a minute.
    if !super::kad_io::kad_request_allowed(state, buddy_addr, &packet) {
        debug!("KAD CallbackReq to {buddy_addr} deferred: buddy's per-minute budget spent");
        return false;
    }
    match udp_socket.send_to(&packet, buddy_addr).await {
        Ok(_) => true,
        Err(e) => {
            warn!("Failed to send KAD CallbackReq to {buddy_addr}: {e}");
            false
        }
    }
}

pub(super) const MAX_FAIL_COUNT_FOR_UDP: u32 = 3;

/// Maximum number of UDP source-discovery queries we'll send to a
/// single server with no inbound UDP reply before treating it as
/// dead-for-UDP and skipping it. Distinct from [`MAX_FAIL_COUNT_FOR_UDP`]
/// (which counts TCP connect failures); a server can be perfectly
/// healthy on TCP and still completely silent on UDP because its
/// admin firewalled the UDP port, it doesn't index our specific file
/// hashes, or it requires UDP obfuscation we never negotiated.
///
/// Re-eligible the moment any inbound UDP reply arrives — the recv
/// path resets the per-server counter via `record_udp_reply`.
pub(super) const MAX_UDP_CONSECUTIVE_FAILURES: u32 = 5;
pub(super) const SERVER_UDP_SOURCE_REASK_SECS: i64 = 30 * 60;
pub(super) const SERVER_UDP_SOURCE_REPLY_TTL_SECS: i64 = 120;

pub(super) fn is_eligible_udp_server(
    server: &ed2k::server_list::ServerEntry,
    connected_addr: Option<SocketAddr>,
) -> bool {
    if server.fail_count >= MAX_FAIL_COUNT_FOR_UDP {
        return false;
    }
    if server.udp_consecutive_failures >= MAX_UDP_CONSECUTIVE_FAILURES {
        return false;
    }
    if let Some(conn_addr) = connected_addr {
        if let Ok(addr) = format!("{}:{}", server.ip, server.port).parse::<SocketAddr>() {
            if addr.ip() == conn_addr.ip() {
                return false;
            }
        }
    }
    true
}

/// KAD is actually usable for FindSource (not merely `Connecting` while
/// bootstrapping `nodes.dat`).
pub(super) fn kad_ready_for_sources(state: &NetworkState) -> bool {
    state.stats.status == NetworkStatus::Connected
}

/// At least one download source network is up: KAD Connected and/or an
/// eD2k server session. Used to defer warm-start dials and discovery on
/// launch so restored downloads do not search/dial during KAD Connecting.
pub(super) fn network_ready_for_sources(state: &NetworkState) -> bool {
    kad_ready_for_sources(state) || state.server_connected
}

/// Build UDP GETSOURCES packets for ALL eligible servers (single file).
pub(super) fn build_all_getsources_packets(
    state: &mut NetworkState,
    file_hash: &[u8; 16],
    file_size: u64,
) -> Vec<(Vec<u8>, SocketAddr)> {
    let servers: Vec<_> = state.server_list.servers().to_vec();
    if servers.is_empty() {
        return Vec::new();
    }

    let mut packets = Vec::with_capacity(servers.len());
    let now = std::time::Instant::now();
    // Only build (and stamp a 30-min reask time for) as many packets as will
    // actually fit in the send queue. We record `server_udp_source_reask_at`
    // the moment a packet is built, but the caller drops any packets past the
    // queue's remaining room — so stamping past `room` would suppress those
    // (server, file) pairs for SERVER_UDP_SOURCE_REASK_SECS without ever having
    // asked. That overflow is reachable when many downloads are added at once
    // (e.g. opening a large .emulecollection) and the burst exceeds
    // MAX_UDP_SOURCE_QUEUE. Capping here keeps the stamp in lockstep with what
    // we enqueue; the skipped servers stay un-stamped and are picked up by the
    // next sweep.
    let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
    for server in &servers {
        if packets.len() >= room {
            break;
        }
        if !is_eligible_udp_server(server, state.server_addr) {
            continue;
        }
        let key = (server.ip.clone(), server.port, *file_hash);
        if state.server_udp_source_reask_at.get(&key).is_some_and(|last| {
            now.saturating_duration_since(*last) < secs(SERVER_UDP_SOURCE_REASK_SECS)
        }) {
            continue;
        }
        if let Some(packet) =
            ServerUdpSocket::build_get_sources_packet(server, file_hash, file_size)
        {
            state.server_udp_source_reask_at.insert(key, now);
            packets.push(packet);
        }
    }
    packets
}

pub(super) fn is_recent_configured_server_source_reply(
    server_list: &ServerList,
    queries: &HashMap<(String, u16, [u8; 16]), std::time::Instant>,
    addr: SocketAddr,
    file_hash: &[u8; 16],
    now: std::time::Instant,
) -> bool {
    let tcp_port = addr.port().saturating_sub(4);
    let ip = addr.ip().to_string();
    let configured = server_list
        .servers()
        .iter()
        .any(|server| server.ip == ip && server.port == tcp_port);
    configured
        && queries
            .get(&(ip, tcp_port, *file_hash))
            .is_some_and(|sent_at| {
                now.saturating_duration_since(*sent_at) <= secs(SERVER_UDP_SOURCE_REPLY_TTL_SECS)
            })
}

/// Build UDP GETSOURCES packets for ALL eligible servers, packing multiple
/// file hashes per packet (eMule: up to 35 per server, max 510 bytes payload).
/// Used by the periodic sweep when multiple downloads are active.
pub(super) fn build_all_getsources_packets_multi(
    state: &mut NetworkState,
    files: &[([u8; 16], u64)],
) -> Vec<(Vec<u8>, SocketAddr)> {
    let servers: Vec<_> = state.server_list.servers().to_vec();
    if servers.is_empty() || files.is_empty() {
        return Vec::new();
    }

    let mut packets = Vec::with_capacity(servers.len());
    let now = std::time::Instant::now();
    // See `build_all_getsources_packets`: cap the number of packets at the
    // send queue's remaining room so we never stamp a reask time for a packet
    // the caller would drop (which would suppress those files on that server
    // for SERVER_UDP_SOURCE_REASK_SECS without ever asking).
    let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
    for server in &servers {
        if packets.len() >= room {
            break;
        }
        if !is_eligible_udp_server(server, state.server_addr) {
            continue;
        }
        let due: Vec<([u8; 16], u64)> = files
            .iter()
            .filter(|(fh, _)| {
                let key = (server.ip.clone(), server.port, *fh);
                state.server_udp_source_reask_at.get(&key).is_none_or(|last| {
                    now.saturating_duration_since(*last) >= secs(SERVER_UDP_SOURCE_REASK_SECS)
                })
            })
            .copied()
            .collect();
        if due.is_empty() {
            continue;
        }
        let file_refs: Vec<(&[u8; 16], u64)> = due.iter().map(|(h, s)| (h, *s)).collect();
        if let Some((wire_packet, wire_addr, included)) =
            ServerUdpSocket::build_multi_get_sources_packet(server, &file_refs)
        {
            // Stamp the reask time only for files actually packed into this
            // packet. A non-EXT_GETSOURCES server takes a single hash per
            // packet, so `included` can be a strict subset of `due`; stamping
            // all of `due` would suppress the un-asked files for 30 min.
            for fh in included {
                state
                    .server_udp_source_reask_at
                    .insert((server.ip.clone(), server.port, fh), now);
            }
            packets.push((wire_packet, wire_addr));
        }
    }
    packets
}

pub(super) fn inject_source_into_active_transfers(
    state: &mut NetworkState,
    file_hash: [u8; 16],
    transfer_ids: &[String],
    source: &DownloadSource,
    udp_port: u16,
) -> ActiveSourceInjectionStats {
    let mut stats = ActiveSourceInjectionStats {
        matched_transfers: transfer_ids.len(),
        ..Default::default()
    };
    let parsed_ip = source.peer_ip.parse::<Ipv4Addr>().ok();

    // Source-level filtering via the shared admissibility gate so UDP
    // server (`OP_GLOBFOUNDSOURCES`), KAD, StartDownload, and live-source
    // paths all refuse the same peers. Do not add a separate
    // `is_special_use_v4` gate here — that would permanently deny LAN
    // peers even when the user turned private blocking off.
    if let Some(v4) = parsed_ip {
        if !is_source_admissible(state, v4, source.peer_port, source.peer_user_hash.as_ref()) {
            stats.dropped_full += transfer_ids.len();
            return stats;
        }
    } else if source.peer_port == 0 {
        stats.dropped_full += transfer_ids.len();
        return stats;
    } else if let Some(ref uh) = source.peer_user_hash {
        // Non-IPv4 address: still honor reputation / self-hash bans.
        if state.reputation.is_banned(uh) || (*uh != [0u8; 16] && *uh == state.user_hash) {
            stats.dropped_full += transfer_ids.len();
            return stats;
        }
    }

    let mut stale_transfer_ids = Vec::new();

    for transfer_id in transfer_ids {
        let should_inject = if let Some(v4) = parsed_ip {
            let pfs = state
                .per_file_sources
                .entry(transfer_id.clone())
                .or_insert_with(|| {
                    ed2k::sources::PerFileSourceList::new(file_hash, state.max_sources_per_file)
                });
            let already_known = pfs.has_source(v4, source.peer_port);
            if already_known {
                // Worker may have soft-dropped this peer (no free parts).
                // Re-inject only when PFS says another attempt is due.
                pfs.is_eligible_for_reinject(v4, source.peer_port)
            } else {
                let added = pfs.add_source_full(v4, source.peer_port, udp_port);
                if added {
                    stats.persisted += 1;
                    state.ember_payload_dirty = true;
                }
                // At capacity, do not inject peers we could not store —
                // otherwise every rediscovery re-spams the same address.
                added
            }
        } else {
            // Non-IPv4 source: use sender channel state as a proxy for dedup.
            // If the channel is already full or closed, skip this source.
            match state.active_source_senders.get(transfer_id) {
                Some(tx) => tx.capacity() > 0,
                None => false,
            }
        };

        if !should_inject {
            continue;
        }

        match try_inject_source(state.active_source_senders.get(transfer_id), source) {
            SourceInjectionResult::Injected => {
                stats.injected += 1;
                // Claim the PFS slot so rediscovery does not re-spam until
                // the worker adopts or soft-drops the peer.
                if let Some(v4) = parsed_ip {
                    if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
                        pfs.set_connecting(v4, source.peer_port, None);
                    }
                }
            }
            SourceInjectionResult::Full => {
                stats.dropped_full += 1;
                if enqueue_overflow_source(state, transfer_id, source) {
                    stats.overflowed += 1;
                }
            }
            SourceInjectionResult::Closed => {
                stats.dropped_closed += 1;
                stale_transfer_ids.push(transfer_id.clone());
            }
        }
    }

    for transfer_id in &stale_transfer_ids {
        state.active_source_senders.remove(transfer_id);
        // Mirror the metadata sender's removal — see lockstep
        // rationale on `active_established_senders`.
        state.active_established_senders.remove(transfer_id);
        state.active_source_overflow.remove(transfer_id);
        state.active_kad_search_state.remove(transfer_id);
        state
            .download_source_searches
            .retain(|_, (tid, _)| tid != transfer_id);
    }

    let hash_hex = hex::encode(file_hash);
    if stats.injected > 0 {
        info!(
            "Source {}:{} injected into {} transfer(s) for {} (persisted={}, injected={})",
            source.peer_ip,
            source.peer_port,
            stats.injected,
            hash_hex,
            stats.persisted,
            stats.injected
        );
    }
    if stats.dropped_full > 0 || stats.dropped_closed > 0 {
        debug!(
            "Source {}:{} for {} had drops: full={}, overflowed={}, closed={} (stale: {:?})",
            source.peer_ip,
            source.peer_port,
            hash_hex,
            stats.dropped_full,
            stats.overflowed,
            stats.dropped_closed,
            stale_transfer_ids
        );
    }

    stats
}

/// Ask every network that has somewhere to send it for the sources of one file.
///
/// The four legs are independent, and a leg with no route is skipped rather
/// than allowed to hold up the others: KAD with no contacts or no session,
/// Ember disabled or with no overlay peers, no eD2K server session, no
/// eligible servers for the UDP fan-out. What comes back arrives on each
/// network's own schedule, through the same paths the periodic sweeps use.
///
/// The connected server is not asked here but put in line for its next source
/// frame, which also waits out the post-login settle. Its leg also reports
/// `server: false` for a file that server was asked about within
/// `SERVER_TCP_SRCREQ_FILE_REASK_SECS` (eMule's `SERVERREASKTIME`): asking
/// again that soon only spends the connection's request credit.
///
/// This is what a download's opening fan-out does and what the Transfers
/// "find sources" button does, which is the reason it is one function: three
/// call sites drifting apart is how a network quietly stops being asked.
/// Callers keep their own bookkeeping around it — `active_kad_search_state`,
/// `ember_source_search_state`, `PendingDownload::search_count` — which is what
/// the returned outcome is for.
pub(super) async fn ask_networks_for_sources(
    socket: &UdpSocket,
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
    transfer_id: &str,
    file_hash: [u8; 16],
    file_size: u64,
) -> crate::types::SourceAskOutcome {
    let mut outcome = crate::types::SourceAskOutcome::default();
    let kad_hash = md4_bytes_to_kad_id(&file_hash);

    // KAD: the closest contacts we know of, reachable ones first — a
    // firewalled contact can only answer through a callback, so it is the
    // least useful place to spend one of the opening queries.
    if kad_ready_for_sources(state) {
        let mut closest = state
            .routing_table
            .find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
        if closest.is_empty() {
            debug!(
                "No KAD contacts to ask for sources of {}",
                hex::encode(file_hash)
            );
        } else {
            closest.sort_by_key(|c| c.is_tcp_firewalled() as u8);
            let sid = start_kad_search(
                state,
                app_handle,
                kad_hash,
                SearchType::FindSource { file_size },
                closest,
            );
            if sid != SearchId(0) {
                // Filed under `download_source_searches`, which is the
                // completion branch that writes what it finds into the
                // transfer. A manual ask that resolved an IPC oneshot instead
                // told the user sources existed and left the download no
                // better off.
                state
                    .download_source_searches
                    .insert(sid, (transfer_id.to_string(), file_hash));
                info!(
                    "Started KAD source search {} for download {}",
                    sid.0, transfer_id
                );
                let _ = app_handle.emit(
                    "transfer:source-search",
                    serde_json::json!({
                        "transfer_id": transfer_id,
                        "kind": "kad_search",
                    }),
                );
                outcome.kad = true;
            }
        }
    }

    // Ember: independent of KAD, so it is asked even on a KAD-less network.
    if settings.ember_native_enabled && ember_overlay_contact_count(state) > 0 {
        outcome.ember = start_ember_source_search(socket, state, transfer_id, file_hash).await;
    }

    // The connected eD2K server, over TCP: in line for its next source frame,
    // which reports `server_query` for this transfer when it goes out.
    // `server` stays false when the file was asked within the last
    // `SERVER_TCP_SRCREQ_FILE_REASK_SECS`, the same as with no session.
    let now = std::time::Instant::now();
    outcome.server = queue_server_source_ask(state, transfer_id, file_hash, file_size, now);
    outcome.server_recent = !outcome.server
        && state.server_connected
        && !server_tcp_srcreq_file_due(&state.server_tcp_srcreq_file_at, &file_hash, now);

    // Every other eligible server, over UDP, paced through the queue so this
    // never becomes a burst of datagrams.
    if network_ready_for_sources(state) {
        let packets = build_all_getsources_packets(state, &file_hash, file_size);
        if !packets.is_empty() {
            let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
            let queued = packets.len().min(room);
            debug!(
                "Queuing {}/{} UDP source requests for download {}",
                queued,
                packets.len(),
                transfer_id
            );
            state
                .udp_source_queue
                .extend(packets.into_iter().take(room));
            outcome.server_udp = queued > 0;
        }
    }

    outcome
}

#[cfg(test)]
mod server_tcp_srcreq_file_floor_tests {
    use super::*;

    /// `t0` plus `s` seconds: every test time is after the first, so none has
    /// to subtract from a clock that may be young.
    fn at(t0: std::time::Instant, s: i64) -> std::time::Instant {
        t0 + secs(s)
    }

    #[test]
    fn a_file_is_not_asked_again_inside_serverreasktime() {
        let t0 = std::time::Instant::now();
        let mut asked = HashMap::new();
        let file = [0x11; 16];
        assert!(server_tcp_srcreq_file_due(&asked, &file, at(t0, 0)), "never asked");

        note_server_tcp_srcreq_file(&mut asked, file, at(t0, 0));
        assert!(!server_tcp_srcreq_file_due(&asked, &file, at(t0, 1)));
        assert!(!server_tcp_srcreq_file_due(
            &asked,
            &file,
            at(t0, SERVER_TCP_SRCREQ_FILE_REASK_SECS - 1)
        ));
        assert!(server_tcp_srcreq_file_due(
            &asked,
            &file,
            at(t0, SERVER_TCP_SRCREQ_FILE_REASK_SECS)
        ));
        assert!(
            server_tcp_srcreq_file_due(&asked, &[0x22; 16], at(t0, 1)),
            "the floor is per file"
        );
    }

    /// A 200-file collection used to send 200 `OP_GETSOURCES` at once. Queued,
    /// it goes out one frame at a time, oldest first.
    #[test]
    fn a_large_collection_waits_its_turn_in_frames() {
        let mut asks = VecDeque::new();
        let asked = HashMap::new();
        let file = |n: u32| {
            let mut hash = [0u8; 16];
            hash[..4].copy_from_slice(&n.to_le_bytes());
            hash
        };
        let now = std::time::Instant::now();
        for n in 0..200 {
            assert!(push_server_source_ask(&mut asks, &asked, &format!("t{n}"), file(n), 1_000, now));
        }

        let first = take_frame_source_asks(&mut asks, SERVER_TCP_SRCREQ_MAX_PER_FRAME, |_, _| true);
        assert_eq!(first.len(), SERVER_TCP_SRCREQ_MAX_PER_FRAME);
        assert_eq!(first[0].1, file(0));
        assert_eq!(asks.len(), 200 - SERVER_TCP_SRCREQ_MAX_PER_FRAME);
        assert_eq!(asks[0].1, file(SERVER_TCP_SRCREQ_MAX_PER_FRAME as u32));
    }

    #[test]
    fn an_ask_is_refused_inside_the_floor_and_queued_once() {
        let t0 = std::time::Instant::now();
        let mut asks = VecDeque::new();
        let mut asked = HashMap::new();
        note_server_tcp_srcreq_file(&mut asked, [1; 16], at(t0, 0));

        assert!(!push_server_source_ask(&mut asks, &asked, "recent", [1; 16], 10, at(t0, 60)));
        assert!(push_server_source_ask(&mut asks, &asked, "a", [2; 16], 10, at(t0, 60)));
        assert!(push_server_source_ask(&mut asks, &asked, "b", [2; 16], 10, at(t0, 61)));
        assert_eq!(asks.len(), 1, "one place in line per file");
    }

    #[test]
    fn a_frame_drops_asks_it_cannot_use_instead_of_carrying_them() {
        let mut asks: VecDeque<_> = [("gone", [1u8; 16]), ("live", [2u8; 16]), ("live2", [3u8; 16])]
            .into_iter()
            .map(|(tid, hash)| (tid.to_string(), hash, 10u64))
            .collect();

        let frame = take_frame_source_asks(&mut asks, SERVER_TCP_SRCREQ_MAX_PER_FRAME, |tid, _| {
            tid != "gone"
        });
        assert_eq!(
            frame.iter().map(|(tid, _, _)| tid.as_str()).collect::<Vec<_>>(),
            ["live", "live2"]
        );
        assert!(asks.is_empty(), "nothing is left to pull the next frame forward");
    }

    #[test]
    fn stale_stamps_are_pruned_and_live_ones_kept() {
        let t0 = std::time::Instant::now();
        let mut asked = HashMap::new();
        for n in 0..1024u32 {
            let mut file = [0u8; 16];
            file[..4].copy_from_slice(&n.to_le_bytes());
            // Half stale, half still inside the floor at t = 10_000.
            let stamp = if n % 2 == 0 { at(t0, 0) } else { at(t0, 10_000 - 60) };
            asked.insert(file, stamp);
        }
        let now = at(t0, 10_000);
        note_server_tcp_srcreq_file(&mut asked, [0xFF; 16], now);

        assert_eq!(asked.len(), 513);
        assert!(asked
            .values()
            .all(|stamp| now.duration_since(*stamp) < secs(SERVER_TCP_SRCREQ_FILE_REASK_SECS)));
    }
}

#[cfg(test)]
mod server_udp_source_admission_tests {
    use super::*;

    #[test]
    fn requires_configured_endpoint_and_recent_matching_query() {
        let mut servers = ServerList::new();
        servers.add(ServerEntry::new("198.51.100.10".to_string(), 4661));
        let addr: SocketAddr = "198.51.100.10:4665".parse().unwrap();
        let hash = [0x44; 16];
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + std::time::Duration::from_secs(s);
        let mut queries = HashMap::new();
        queries.insert(("198.51.100.10".to_string(), 4661, hash), at(0));

        assert!(is_recent_configured_server_source_reply(
            &servers, &queries, addr, &hash, at(100)
        ));
        // Correlation is non-destructive: duplicate replies remain valid in
        // the same response window.
        assert!(is_recent_configured_server_source_reply(
            &servers, &queries, addr, &hash, at(100)
        ));
        assert!(!is_recent_configured_server_source_reply(
            &servers, &queries, addr, &hash, at(121)
        ));
        assert!(!is_recent_configured_server_source_reply(
            &servers,
            &queries,
            "198.51.100.11:4665".parse().unwrap(),
            &hash,
            at(100)
        ));
        assert!(!is_recent_configured_server_source_reply(
            &servers,
            &queries,
            addr,
            &[0x45; 16],
            at(100)
        ));
    }
}
