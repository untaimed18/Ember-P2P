//! The shared UDP socket's packet dispatcher (KAD, eD2K server UDP, Ember).
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Serveable-parts bitmaps for downloads answering UDP reasks without a live
/// tracker (paused or queued), keyed by transfer id. Filled from the live
/// tracker while the download runs and from `.part.met` on the blocking pool
/// otherwise, so the reask path itself never reads the disk.
///
/// An entry is only as good as the [`ed2k::part_tracker::verification_epoch`]
/// it was built at: any tracker un-verifying a part bumps the epoch, and a
/// rebuild through `PartTracker::new` applies the process-wide
/// cleared-since-verified set, so a mismatched entry is never served.
#[derive(Default)]
struct ReaskPartsCache {
    entries: HashMap<String, ReaskPartsEntry>,
    refreshing: HashSet<String>,
}

struct ReaskPartsEntry {
    epoch: u64,
    built: std::time::Instant,
    total_size: u64,
    /// `None`: the download has no `.part` on disk.
    parts: Option<Vec<bool>>,
}

/// Refresh age for an entry. Parts a paused download already has stay valid
/// (the epoch covers un-verification), so an older bitmap can only
/// under-report, which is harmless; this bounds how far.
const REASK_PARTS_REFRESH_AFTER: std::time::Duration = std::time::Duration::from_secs(300);
const MAX_REASK_PARTS_ENTRIES: usize = 1024;

enum CachedReaskParts {
    Fresh(Option<Vec<bool>>),
    Aging(Option<Vec<bool>>),
    Unknown,
}

fn reask_parts_cache() -> &'static parking_lot::Mutex<ReaskPartsCache> {
    static CACHE: std::sync::OnceLock<parking_lot::Mutex<ReaskPartsCache>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn cached_reask_parts(transfer_id: &str, total_size: u64) -> CachedReaskParts {
    let epoch = ed2k::part_tracker::verification_epoch();
    let cache = reask_parts_cache().lock();
    match cache.entries.get(transfer_id) {
        Some(entry) if entry.epoch == epoch && entry.total_size == total_size => {
            if entry.built.elapsed() < REASK_PARTS_REFRESH_AFTER {
                CachedReaskParts::Fresh(entry.parts.clone())
            } else {
                CachedReaskParts::Aging(entry.parts.clone())
            }
        }
        _ => CachedReaskParts::Unknown,
    }
}

fn remember_reask_parts(transfer_id: &str, total_size: u64, epoch: u64, parts: Option<&[bool]>) {
    let mut cache = reask_parts_cache().lock();
    if !cache.entries.contains_key(transfer_id) && cache.entries.len() >= MAX_REASK_PARTS_ENTRIES {
        if let Some(oldest) = cache
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.built)
            .map(|(id, _)| id.clone())
        {
            cache.entries.remove(&oldest);
        }
    }
    cache.entries.insert(
        transfer_id.to_string(),
        ReaskPartsEntry {
            epoch,
            built: std::time::Instant::now(),
            total_size,
            parts: parts.map(<[bool]>::to_vec),
        },
    );
}

/// Rebuild one entry from disk on the blocking pool; at most one rebuild per
/// transfer is in flight, however many reasks arrive for it.
fn spawn_reask_parts_refresh(transfer_id: String, total_size: u64, part_path: PathBuf) {
    if !reask_parts_cache()
        .lock()
        .refreshing
        .insert(transfer_id.clone())
    {
        return;
    }
    struct RefreshDone(String);
    impl Drop for RefreshDone {
        fn drop(&mut self) {
            reask_parts_cache().lock().refreshing.remove(&self.0);
        }
    }
    tokio::task::spawn_blocking(move || {
        let _done = RefreshDone(transfer_id.clone());
        let epoch = ed2k::part_tracker::verification_epoch();
        let parts = part_path.exists().then(|| {
            ed2k::part_tracker::PartTracker::new(total_size, &part_path).serveable_parts()
        });
        remember_reask_parts(&transfer_id, total_size, epoch, parts.as_deref());
    });
}

/// eMule accepts one `OP_DIRECTCALLBACKREQ` per requester IP per 180 s
/// (`CClientList::AllowCalbackRequest`, ClientList.cpp:923-932).
const DIRECT_CALLBACK_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(180);
const MAX_DIRECT_CALLBACK_REQUESTERS: usize = 4096;
/// Callbacks we dial per second, from anyone. The source address is all that
/// identifies a requester and it is trivially spoofed, so without a global
/// ceiling each spoofed address bought one outbound connection. Also keeps
/// the per-IP table short of `MAX_DIRECT_CALLBACK_REQUESTERS`, where it would
/// refuse everyone until entries lapsed.
const MAX_DIRECT_CALLBACKS_PER_SEC: u32 = 10;

/// Arrival order of `NetworkState::direct_callback_requests`, so entries
/// lapse from the front instead of by a scan of the whole map per packet,
/// and the count against [`MAX_DIRECT_CALLBACKS_PER_SEC`].
#[derive(Default)]
struct DirectCallbackGate {
    order: VecDeque<(Ipv4Addr, std::time::Instant)>,
    second: Option<(std::time::Instant, u32)>,
}

impl DirectCallbackGate {
    /// Whether a request from `from` is accepted now; records it in `accepted`
    /// when it is.
    fn admit(
        &mut self,
        accepted: &mut HashMap<Ipv4Addr, std::time::Instant>,
        from: Ipv4Addr,
        now: std::time::Instant,
    ) -> bool {
        while let Some(&(ip, at)) = self.order.front() {
            if now.saturating_duration_since(at) < DIRECT_CALLBACK_MIN_INTERVAL {
                break;
            }
            self.order.pop_front();
            if accepted.get(&ip) == Some(&at) {
                accepted.remove(&ip);
            }
        }
        if accepted.contains_key(&from) || accepted.len() >= MAX_DIRECT_CALLBACK_REQUESTERS {
            return false;
        }
        let (started, count) = self.second.get_or_insert((now, 0));
        if now.saturating_duration_since(*started) >= std::time::Duration::from_secs(1) {
            *started = now;
            *count = 0;
        }
        if *count >= MAX_DIRECT_CALLBACKS_PER_SEC {
            return false;
        }
        *count += 1;
        accepted.insert(from, now);
        self.order.push_back((from, now));
        true
    }
}

fn direct_callback_gate() -> &'static parking_lot::Mutex<DirectCallbackGate> {
    static GATE: std::sync::OnceLock<parking_lot::Mutex<DirectCallbackGate>> =
        std::sync::OnceLock::new();
    GATE.get_or_init(Default::default)
}

/// eMule `OP_DIRECTCALLBACKREQ` (ClientUDPSocket.cpp:363-394): a downloader
/// that found us as a TCP-firewalled, UDP-reachable source — which our Hello
/// and KAD source type 6 advertise — asks us to dial it and be served.
/// Payload: its TCP port (u16), its user hash (16), its connect options (u8).
///
/// Left unanswered, the requester's connect attempt times out in
/// `CCS_DIRECTCALLBACK` and eMule dead-sources us for that file
/// (BaseClient.cpp:1188-1194).
fn accept_direct_callback_request(state: &mut NetworkState, from: Ipv4Addr, payload: &[u8]) {
    // eMule's own gate is "KAD running and firewalled": a reachable node has
    // no reason to be asked, and dialing out for strangers is not free.
    if !state.firewalled || payload.len() < 19 {
        return;
    }
    let now = std::time::Instant::now();
    if !direct_callback_gate()
        .lock()
        .admit(&mut state.direct_callback_requests, from, now)
    {
        debug!(
            "Ignoring direct callback request from {from}: one per {DIRECT_CALLBACK_MIN_INTERVAL:?} \
             per IP, {MAX_DIRECT_CALLBACKS_PER_SEC} a second overall"
        );
        return;
    }
    let mut user_hash = [0u8; 16];
    user_hash.copy_from_slice(&payload[2..18]);
    state
        .pending_direct_callbacks
        .push(ember::dht::engine::CallbackConnect {
            dest_ip: from,
            dest_port: u16::from_le_bytes([payload[0], payload[1]]),
            file_hash: [0u8; 16],
            crypt_options: payload[18],
            user_hash: Some(user_hash),
        });
}

/// The Hello we open a KAD TCP firewall connect-back with: the same identity
/// and capabilities as every other Hello we send.
fn fw_check_hello(state: &NetworkState, nickname: &str) -> Vec<u8> {
    let mut options = ed2k::messages::HelloOptions::default_for_udp_port(state.udp_port);
    options.supports_crypt_layer = state.obfuscation_enabled;
    options.requests_crypt_layer = state.obfuscation_enabled;
    options.supports_direct_udp_callback = can_advertise_direct_udp_callback(state);
    let client_id = state
        .external_ip
        .map(|ip| u32::from_le_bytes(ip.octets()))
        .unwrap_or(0);
    ed2k::messages::build_hello_with_buddy_opts(
        &state.user_hash,
        client_id,
        advertised_tcp_port(state),
        nickname,
        None,
        &options,
    )
}

/// Our half of a KAD TCP firewall check, as eMule does it once the
/// connection is up (`CClientList::Process`, `KS_CONNECTED_FWCHECK`,
/// ClientList.cpp:511-521): finish the Hello exchange, then send
/// `OP_KAD_FWTCPCHECK_ACK`. eMule throws on an extended packet from a socket
/// that never sent `OP_HELLO` (ListenSocket.cpp:1752-1757), so an ACK sent
/// straight after connecting never counted toward the peer's check.
///
/// Ends by half-closing and draining for a moment: the peer follows its
/// HelloAnswer with SecIdent packets, and dropping a socket with unread data
/// resets it, which can discard the ACK before the peer reads it.
async fn send_fw_tcp_check_ack<R, W>(reader: &mut R, writer: &mut W, hello: &[u8]) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut frame = Vec::with_capacity(6 + hello.len());
    frame.push(OP_EDONKEYHEADER);
    frame.extend_from_slice(&((1 + hello.len()) as u32).to_le_bytes());
    frame.push(ed2k::messages::OP_HELLO);
    frame.extend_from_slice(hello);
    writer.write_all(&frame).await?;
    writer.flush().await?;

    let answer = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let mut header = [0u8; 6];
        reader.read_exact(&mut header).await?;
        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if header[0] != OP_EDONKEYHEADER
            || header[5] != ed2k::messages::OP_HELLOANSWER
            || !(1..=64 * 1024).contains(&len)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "expected OP_HELLOANSWER",
            ));
        }
        let mut body = vec![0u8; len - 1];
        reader.read_exact(&mut body).await
    })
    .await;
    match answer {
        Ok(result) => {
            result?;
        }
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no OP_HELLOANSWER",
            ))
        }
    }

    writer
        .write_all(&[OP_EMULEPROT, 1, 0, 0, 0, ed2k::messages::OP_KAD_FWTCPCHECK_ACK])
        .await?;
    writer.flush().await?;
    let _ = writer.shutdown().await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let mut sink = [0u8; 1024];
        while matches!(reader.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
    Ok(())
}

/// Panic-isolating wrapper around [`handle_udp_packet_inner`]. Untrusted
/// network packets are the prime adversarial surface, so a panic here must be
/// contained rather than allowed to kill the network event loop.
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_udp_packet(
    socket: &UdpSocket,
    data: &[u8],
    from: SocketAddr,
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    db: &Arc<Database>,
    active_port_tests: &Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, mpsc::Sender<()>>>>,
    upload_queue: &ed2k::upload::UploadQueueRef,
    credit_manager: &Arc<RwLock<CreditManager>>,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    known_files: &KnownFileList,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    if let Err(p) = std::panic::AssertUnwindSafe(handle_udp_packet_inner(
        socket,
        data,
        from,
        state,
        app_handle,
        local_index,
        settings,
        db,
        active_port_tests,
        upload_queue,
        credit_manager,
        transfer_manager,
        source_manager,
        known_files,
        bandwidth_limiter,
    ))
    .catch_unwind()
    .await
    {
        error!(
            "UDP packet handler panicked (recovered, network loop continues): {}",
            describe_panic(&*p)
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_udp_packet_inner(
    socket: &UdpSocket,
    data: &[u8],
    from: SocketAddr,
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    db: &Arc<Database>,
    active_port_tests: &Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, mpsc::Sender<()>>>>,
    upload_queue: &ed2k::upload::UploadQueueRef,
    credit_manager: &Arc<RwLock<CreditManager>>,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    known_files: &KnownFileList,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    // Reject oversized packets (max 64 KiB for UDP)
    if data.len() > 65535 {
        debug!(
            "Dropping oversized packet from {from}: {} bytes",
            data.len()
        );
        return;
    }

    // Security: IP filter and ban check (applied to ALL incoming UDP, including ED2K peer messages).
    // Reject pure IPv6 — ed2k is IPv4-only and we cannot filter/ban non-v4 addresses.
    let from_ipv4 = match from.ip() {
        std::net::IpAddr::V4(v4) => v4,
        std::net::IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => {
                debug!("Dropping UDP packet from non-v4-mapped IPv6 {from}");
                return;
            }
        },
    };
    let udp_blocked = match data.first().copied() {
        Some(OP_EDONKEYHEADER) | Some(OP_EMULEPROT) => {
            state.ip_filter.is_blocked_readonly(from_ipv4)
        }
        _ => state.ip_filter.is_blocked_readonly_for_kad(from_ipv4),
    };
    if udp_blocked {
        debug!("Dropping UDP packet from blocked IP {from}");
        return;
    }
    if state.banned_ips.contains(&from_ipv4) {
        debug!("Dropping UDP packet from banned peer {from}");
        return;
    }

    // Ember-native UDP dispatch (feature-gated).
    //
    // KAD/eD2K packets begin with `OP_EDONKEYHEADER` (0xE3) or
    // `OP_EMULEPROT` (0xC5); the obfuscated KAD path uses other first
    // bytes too, but never the Ember magic `0xEB 0x3E`. Routing on the
    // magic prefix means we never accidentally divert real KAD traffic
    // to the Noise transport, even when the feature flag is on.
    //
    // When the flag is off, we silently drop the packet — this matches
    // the documented "designed but not yet integrated" behavior of any
    // future Ember-native peer that finds itself talking to a build
    // where the user hasn't opted in. We deliberately don't fall
    // through to KAD parsing (which would log "unknown packet type"
    // warnings and waste cycles parsing garbage).
    if ember::transport::EmberTransport::is_ember_packet(data) {
        if settings.ember_native_enabled {
            // Defense-in-depth: in practice the event loop's Ember
            // fast-path intercepts these packets before `handle_udp_packet`,
            // but if that ever changes, the shared gate (IP-filter + ban +
            // per-IP rate limit) still runs here. The IP-filter/ban checks
            // above already ran for KAD's sake; re-running them is two cheap
            // set lookups against a path that's normally unreached.
            if ember_udp_recv_allowed(state, from) {
                handle_ember_native_udp(
                    socket,
                    data,
                    from,
                    state,
                    transfer_manager,
                    source_manager,
                    local_index,
                    db,
                    app_handle,
                    bandwidth_limiter,
                )
                .await;
            }
        } else {
            debug!("Dropping Ember-magic UDP packet from {from}: ember_native_enabled=false");
        }
        return;
    }

    // Obfuscated eD2K client UDP: stock eMule encrypts its reasks to us, and
    // its answers to ours, whenever both sides support the crypt layer
    // (`ShouldReceiveCryptUDPPackets`, BaseClient.cpp:2588-2591), which is
    // the default. Decrypted, it is handled exactly like the plain form.
    let decrypted_client_packet =
        kad::obfuscation::try_decrypt_client_ed2k_packet(data, &state.user_hash, from_ipv4.octets())
            .filter(|plain| plain[0] == OP_EDONKEYHEADER || plain[0] == OP_EMULEPROT);
    let data: &[u8] = decrypted_client_packet.as_deref().unwrap_or(data);
    if decrypted_client_packet.is_some() && state.ip_filter.is_blocked_readonly(from_ipv4) {
        debug!("Dropping obfuscated eD2K UDP packet from blocked IP {from}");
        return;
    }

    // Handle eMule peer-to-peer and server UDP packets
    let header = data.first().copied().unwrap_or(0);
    if header == OP_EDONKEYHEADER || header == OP_EMULEPROT {
        if data.len() >= 2 {
            let opcode = data[1];
            let payload = &data[2..];
            let known_peer = state.routing_table.has_contact_ip(from_ipv4)
                || state.flood_protection.has_recent_ip(from.ip());
            if state
                .flood_protection
                .check_rate_limit_with_opcode(from.ip(), known_peer, opcode)
            {
                debug!(
                    "Rate limit exceeded for eD2K UDP opcode 0x{opcode:02X} from {from}, dropping packet"
                );
                return;
            }

            if opcode == OP_PORTTEST {
                debug!("Received UDP Port Test from {from}");
                let maybe_tx = {
                    let waiters = active_port_tests.lock().await;
                    waiters.get(&std::net::IpAddr::V4(from_ipv4)).cloned()
                };
                if let Some(tx) = maybe_tx {
                    let _ = tx.try_send(());
                }
                return;
            }

            if header == OP_EMULEPROT && opcode == ed2k::messages::OP_DIRECTCALLBACKREQ {
                accept_direct_callback_request(state, from_ipv4, payload);
                return;
            }

            // eMule UDP reask: peer asks if we still have a file and what their queue rank is
            if header == OP_EMULEPROT
                && opcode == ed2k::messages::OP_REASKFILEPING
                && payload.len() >= 16
            {
                let reask = match ed2k::messages::parse_reask_file_ping(payload) {
                    Ok(reask) => reask,
                    Err(e) => {
                        debug!("Ignoring malformed UDP reask from {from}: {e}");
                        return;
                    }
                };
                let file_hash = reask.file_hash;
                let hash_hex = hex::encode(file_hash);

                // Both inputs report "public" before the deferred known.met load
                // lands: hashing seeds index rows with `friends_only: false`,
                // and `find_by_hash` on the unabsorbed catalog returns `None`.
                // So an unauthenticated prober that knew the hash could get an
                // `OP_REASKACK` — file size, and for the enhanced form the whole
                // parts bitmap — confirming we hold a friends-only file. Fail
                // closed until the catalog is authoritative, matching the
                // partial branch below and the TCP serve path's
                // `!snapshot_ready` rule — closed means silent, not
                // `OP_FILENOTFOUND`: eMule answers that with `AddDeadSource` +
                // `RemoveSource` (DownloadClient.cpp:1309-1327), so every peer
                // queued on us would drop us while the catalog loads, while an
                // unanswered reask is simply retried.
                if !known_files.is_authoritative() {
                    debug!("UDP reask from {from} for {hash_hex}: file catalog not loaded; not answering");
                    return;
                }
                let restricted = {
                    let idx = local_index.read().await;
                    idx.get_by_hash(&hash_hex).is_some_and(|f| f.friends_only)
                        || known_files
                            .find_by_hash(&file_hash)
                            .is_some_and(|r| r.friends_only)
                };
                let local_file = {
                    let idx = local_index.read().await;
                    // UDP carries no authenticated peer identity, so this can
                    // only ever answer for public files. Index presence alone
                    // used to be enough, which confirmed possession of both
                    // unshared and friends-only files to any prober.
                    if restricted {
                        None
                    } else {
                        idx.get_by_hash(&hash_hex)
                            .filter(|file| file.is_public_listable())
                            .map(|file| {
                                (
                                    file.size,
                                    vec![
                                        true;
                                        ed2k::messages::ed2k_wire_part_count(file.size)
                                    ],
                                )
                            })
                    }
                };
                let partial_candidate = if local_file.is_none()
                    && !restricted
                    && known_files.is_authoritative()
                {
                    let mgr = transfer_manager.read().await;
                    mgr.active.values().chain(mgr.queue.iter()).find_map(|t| {
                        if t.direction != TransferDirection::Download
                            || t.file_hash != hash_hex
                            || t.friends_only
                            || matches!(
                                t.status,
                                TransferStatus::Completed | TransferStatus::Failed
                            )
                        {
                            return None;
                        }
                        Some((t.id.clone(), t.total_size))
                    })
                } else {
                    None
                };
                let partial_file = if let Some((transfer_id, total_size)) = partial_candidate {
                    // Before the read, so a clear that lands during it leaves
                    // the cached copy already stale.
                    let epoch = ed2k::part_tracker::verification_epoch();
                    // An active download already holds its tracker in memory, so
                    // ask that first. Nothing on this path touches the disk: the
                    // recv arm drains up to 20 datagrams per turn before it
                    // returns to `select!`, and anyone who knows a hash we
                    // advertise as partial can send them.
                    match udp_reask_serveable_parts(state, &transfer_id).await {
                        Some(parts) => {
                            remember_reask_parts(&transfer_id, total_size, epoch, Some(&parts));
                            Some((total_size, parts))
                        }
                        // Paused or queued: no live tracker, so answer from the
                        // cached bitmap and refresh it on the blocking pool.
                        None => {
                            let lookup = cached_reask_parts(&transfer_id, total_size);
                            if !matches!(lookup, CachedReaskParts::Fresh(_)) {
                                spawn_reask_parts_refresh(
                                    transfer_id.clone(),
                                    total_size,
                                    PathBuf::from(&settings.download_folder)
                                        .join("Temp")
                                        .join(format!("{transfer_id}.part")),
                                );
                            }
                            match lookup {
                                CachedReaskParts::Fresh(parts)
                                | CachedReaskParts::Aging(parts) => {
                                    parts.map(|parts| (total_size, parts))
                                }
                                // Silence rather than a guess: a wrong "not
                                // found" makes the peer drop us as a source,
                                // while an unanswered reask is simply retried.
                                CachedReaskParts::Unknown => {
                                    debug!(
                                        "UDP reask from {from} for {hash_hex}: no cached part map yet; not answering"
                                    );
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    None
                };
                let file_state = local_file.or(partial_file);

                if let Some((file_size, available_parts)) = file_state {
                    let queue_rank = ed2k::upload::udp_queue_rank_for_peer(
                        upload_queue,
                        credit_manager,
                        local_index,
                        from.ip(),
                        from.port(),
                        &file_hash,
                    )
                    .await;
                    // No row for this peer means it is not on our queue — it was
                    // purged at `MAX_PURGEQUEUETIME`, refused at the per-IP cap,
                    // or never admitted. eMule answers that case with silence,
                    // and the silence is load-bearing: `ClientUDPSocket.cpp:295`
                    // says "Don't answer him ... Force him to establish a TCP
                    // connection", because the peer's UDP ask timing out is the
                    // only thing that sends it back to TCP where it can re-enter
                    // the queue.
                    //
                    // Answering anyway with a rank was the bug. `u16::MAX` is
                    // not a "not queued" sentinel to the peer — `UDPReaskACK`
                    // (`DownloadClient.cpp:1302`) clears its pending flag,
                    // stores 65535 as a real position and stamps
                    // `SetLastAskedTime()`, so a stock eMule parks in
                    // `DS_ONQUEUE` believing it holds a place and will not
                    // reconnect for another `FILEREASKTIME` — 29 minutes, then
                    // the same again, forever. eMule never encodes "not queued"
                    // as a rank in either direction: `GetWaitingPosition`
                    // returns 0 for an absent client and `SendRankingInfo`
                    // refuses to transmit a zero rank.
                    let Some(rank) = queue_rank else {
                        // The one thing eMule does say, and only when its queue
                        // is nearly full, so the peer learns not to keep asking.
                        if upload_queue.lock().await.len() + ed2k::upload::QUEUE_FULL_HEADROOM
                            > ed2k::upload::MAX_UPLOAD_QUEUE_SIZE
                        {
                            let resp = vec![OP_EMULEPROT, ed2k::messages::OP_QUEUEFULL_UDP];
                            let _ = socket.send_to(&resp, from).await;
                            debug!("UDP reask from {from} for {hash_hex}: not queued, queue full");
                        } else {
                            debug!(
                                "UDP reask from {from} for {hash_hex}: not on our queue; \
                                 staying silent so it reconnects over TCP"
                            );
                        }
                        return;
                    };
                    let enhanced = reask.completed_parts.is_some();
                    let Some(ack_payload) = ed2k::messages::build_reask_ack(
                        file_size,
                        Some(rank),
                        enhanced.then_some(available_parts.as_slice()),
                    ) else {
                        let resp = vec![OP_EMULEPROT, ed2k::messages::OP_FILENOTFOUND_UDP];
                        let _ = socket.send_to(&resp, from).await;
                        debug!("Refused UDP reask from {from} for oversized {hash_hex}");
                        return;
                    };
                    let mut resp = vec![OP_EMULEPROT, ed2k::messages::OP_REASKACK];
                    resp.extend_from_slice(&ack_payload);
                    let _ = socket.send_to(&resp, from).await;
                    debug!(
                        "Answered UDP reask from {from} for {hash_hex}: file available, rank={rank}"
                    );
                } else {
                    let resp = vec![OP_EMULEPROT, ed2k::messages::OP_FILENOTFOUND_UDP];
                    let _ = socket.send_to(&resp, from).await;
                    ed2k::upload::note_reask_file_not_found();
                    debug!("Answered UDP reask from {from} for {hash_hex}: file not found");
                }
                return;
            }

            // eMule UDP reask response: source confirms it has the file.
            if header == OP_EMULEPROT && opcode == ed2k::messages::OP_REASKACK {
                let ack = match ed2k::messages::parse_reask_ack(payload) {
                    Ok(ack) => ack,
                    Err(e) => {
                        debug!("Ignoring malformed UDP reask ACK from {from}: {e}");
                        return;
                    }
                };
                // Accept both native IPv4 and IPv4-mapped IPv6 (::ffff:x.x.x.x)
                // so hosts that open IPv6 UDP sockets still get their queue
                // rank updated correctly.
                let v4_opt = match from.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                if let Some(v4) = v4_opt {
                    if let Some((file_hash, _)) =
                        state.pending_udp_reasks.remove(&(v4, from.port()))
                    {
                        if let Some(pfs) = state
                            .per_file_sources
                            .values_mut()
                            .find(|pfs| pfs.file_hash == file_hash)
                        {
                            pfs.apply_udp_reask_ack(v4, from.port(), ack.rank, ack.available_parts);
                        }
                    }
                }
                debug!("UDP reask ACK from {from} (source alive)");
                return;
            }

            // eMule UDP: queue full or file not found responses
            if header == OP_EMULEPROT
                && (opcode == ed2k::messages::OP_QUEUEFULL_UDP
                    || opcode == ed2k::messages::OP_FILEREQANSNOFIL
                    || opcode == ed2k::messages::OP_FILENOTFOUND_UDP)
            {
                let v4_opt = match from.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                if let Some(v4) = v4_opt {
                    // These opcodes answer one `OP_REASKFILEPING` about one file,
                    // and the wire message carries no hash — which is exactly why
                    // the ACK branch above resolves the file through the reask we
                    // tracked. Without that correlation this applied a peer's "I
                    // don't have *that* file" to every download it happens to be a
                    // source for (routine: A4AF exists because peers serve several
                    // of our files), demoting healthy sources on unrelated files
                    // and discarding queue ranks we had just learned. It also made
                    // a single unsolicited or source-spoofed datagram authoritative.
                    let Some((file_hash, _)) = state.pending_udp_reasks.remove(&(v4, from.port()))
                    else {
                        debug!(
                            "Ignoring unsolicited UDP reask negative response (opcode 0x{opcode:02X}) from {from}"
                        );
                        return;
                    };
                    let is_banned = state.banned_ips.contains(&v4);
                    // Dead-source entries and the registry are keyed on the
                    // source's TCP port, not the UDP port this came from.
                    let mut tcp_ports: Vec<u16> = Vec::new();
                    if let Some(pfs) = state
                        .per_file_sources
                        .values_mut()
                        .find(|pfs| pfs.file_hash == file_hash)
                    {
                        for src in &mut pfs.sources {
                            if src.ip == v4 && src.udp_port == from.port() {
                                if !tcp_ports.contains(&src.tcp_port) {
                                    tcp_ports.push(src.tcp_port);
                                }
                                if is_banned {
                                    src.state = ed2k::sources::DownloadSourceState::Banned;
                                    src.state_changed = std::time::Instant::now();
                                } else if opcode == ed2k::messages::OP_QUEUEFULL_UDP {
                                    src.state =
                                        ed2k::sources::DownloadSourceState::OnQueue { rank: None };
                                    src.state_changed = std::time::Instant::now();
                                } else {
                                    src.state = ed2k::sources::DownloadSourceState::Failed;
                                    src.state_changed = std::time::Instant::now();
                                    src.fail_count += 1;
                                }
                            }
                        }
                    }
                    // "I don't have that file" is a lasting answer about this
                    // file, not a transient error, so eMule writes the source off
                    // for the file and drops it: `UDPReaskFNF` calls
                    // `AddDeadSource` on the *file's* list and then `RemoveSource`
                    // (`DownloadClient.cpp:1316-1325`). Marking it `Failed` alone
                    // left it eligible again one `FILEREASKTIME` later, so we
                    // re-asked a peer that had already told us the answer, every
                    // 29 minutes, for as long as the download ran. `QUEUEFULL` is
                    // deliberately excluded: that peer *has* the file.
                    if !is_banned && opcode != ed2k::messages::OP_QUEUEFULL_UDP {
                        for tcp_port in tcp_ports {
                            state
                                .dead_sources
                                .add_dead_source_for_file(file_hash, u32::from(v4), tcp_port);
                            retire_dead_source_from_registry(
                                source_manager,
                                &file_hash,
                                v4,
                                tcp_port,
                            )
                            .await;
                        }
                        debug!(
                            "UDP reask: {v4} reports it does not have {} — written off for this file",
                            hex::encode(file_hash)
                        );
                    }
                }
                debug!("UDP reask negative response (opcode 0x{opcode:02X}) from {from}");
                return;
            }

            // eMule OP_REASKCALLBACKUDP (0x94): we are a Low-ID client
            // and some other peer's buddy has sent us a UDP packet
            // addressed to our buddy_id, asking us to relay a reask
            // through our own buddy over TCP. This is the UDP half of
            // the buddy-relay-reask flow; its TCP sibling
            // OP_REASKCALLBACKTCP is handled in
            // `kad::buddy::run_buddy_reader`, which sends a direct UDP
            // reask to the destination once we (acting as a buddy)
            // receive it.
            //
            // Wire format (matches eMule's CClientUDPSocket::ProcessPacket
            // case OP_REASKCALLBACKUDP):
            //   [our_buddy_id:16][trailing payload (>= 1 byte; the
            //    canonical shape is a 16-byte file_hash)]
            //
            // Outbound TCP payload we emit as OP_REASKCALLBACKTCP to
            // our buddy:
            //   [sender_ip:4][sender_port:2][trailing]
            //
            // Previously this path was a silent no-op: Low-ID peers
            // whose reasks were relayed through *their* buddy to us
            // got no answer at all and silently dropped off our
            // buddy-accessible queues.
            //
            // Security layering (defense in depth; the `buddy_id`
            // match is the primary gate):
            //   1. We only act on this opcode when we have an active
            //      buddy of our own — otherwise there is no TCP path
            //      to forward to, and accepting the packet would
            //      accomplish nothing except burn CPU.
            //   2. The first 16 bytes must match our buddy's KadID.
            //      Matching the 128-bit ID effectively requires the
            //      sender to either be our legitimate buddy-pair
            //      participant or to have observed our Kad traffic —
            //      it's not brute-forceable and rejects random
            //      scanning traffic.
            //   3. Special-use / private / loopback sources are
            //      refused (matches the `is_special_use_v4` policy
            //      used elsewhere in this file).
            //   4. Per-source rate limiting via `flood_protection`
            //      caps how fast a single IP can fan UDP→TCP
            //      amplification through our buddy connection — a
            //      single stray flooder cannot saturate the buddy
            //      writer.
            if header == OP_EMULEPROT && opcode == ed2k::messages::OP_REASKCALLBACKUDP {
                if payload.len() < 17 {
                    debug!(
                        "OP_REASKCALLBACKUDP from {from} too short ({} bytes, need >= 17)",
                        payload.len()
                    );
                    return;
                }
                if state.buddy_manager.state() != BuddyState::Connected {
                    debug!("OP_REASKCALLBACKUDP from {from} ignored: we have no active buddy to forward through");
                    return;
                }
                let our_buddy_id = match state.buddy_manager.buddy_id() {
                    Some(id) => *id,
                    None => {
                        debug!("OP_REASKCALLBACKUDP from {from} ignored: buddy connected but buddy_id unknown");
                        return;
                    }
                };
                if payload[..16] != our_buddy_id.0 {
                    debug!("OP_REASKCALLBACKUDP from {from} rejected: buddy_id mismatch");
                    return;
                }
                if crate::security::is_special_use_v4(from_ipv4) {
                    debug!("OP_REASKCALLBACKUDP from {from} rejected: special-use source IP");
                    return;
                }
                // The common eD2K UDP ingress gate above already applied
                // per-source flood protection for this opcode. Do not charge
                // the packet twice here; the remaining gates are semantic.
                let trailing = &payload[16..];
                let forwarded = state
                    .buddy_manager
                    .forward_reask_callback(from_ipv4, from.port(), trailing)
                    .await;
                if forwarded {
                    // On successful forward the buddy TCP connection has
                    // taken responsibility for relaying; drop the local
                    // buddy-info snapshot only if the forward failed and
                    // `forward_reask_callback` already torn down.
                    debug!(
                        "Forwarded OP_REASKCALLBACKUDP from {from} to buddy as OP_REASKCALLBACKTCP ({} trailing bytes)",
                        trailing.len()
                    );
                } else {
                    // `forward_reask_callback` already disconnected on
                    // write/timeout; clear shared state so the rest of
                    // the network task observes the disconnection.
                    state.buddy_event_rx = None;
                    *state.shared_buddy_info.write().await = None;
                }
                return;
            }
        }
        return;
    }

    // Everything above serves eD2K *peer* UDP — port test, queue reasks and
    // their acks, buddy reask relay — none of which involves KAD. Everything
    // below is KAD's, and an unsolicited KAD packet must not be parsed or folded
    // into the routing table while KAD is disconnected, so the gate belongs here
    // rather than around the whole handler. It used to sit at the call site,
    // which meant a session with KAD disconnected — eD2K-only, but still
    // transferring — discarded every inbound peer datagram while still sending
    // reasks, so queue ranks never updated, peers queued on us never got an
    // ack, and the UDP port test always failed.
    if state.stats.status == NetworkStatus::Disconnected {
        debug!("Dropping KAD UDP packet from {from}: KAD is not connected");
        return;
    }

    // Canonicalize IPv6-mapped-IPv4 addresses so all downstream handlers see IpAddr::V4
    let from = match from.ip() {
        std::net::IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), from.port())
            } else {
                from
            }
        }
        _ => from,
    };

    // PublishRes `plain_seen`: counted BEFORE any filtering (IP filter,
    // ban list, rate limit, decrypt). Only matches the plain-text wire
    // shape `[0xE4, 0x4B, ...]`. Obfuscated PublishRes cannot be
    // recognised here (byte 1 is ciphertext) and is counted later via
    // `publish_res_obf_decoded`. The point of this counter is to answer
    // one question unambiguously: "did any plain PublishRes reach our
    // socket at all?" If this stays at 0 while other plain traffic is
    // flowing, the remote simply isn't sending them.
    if data.len() >= 2 && data[0] == 0xE4 && data[1] == 0x4B {
        state.publish_res_plain_seen = state.publish_res_plain_seen.saturating_add(1);
    }

    // Security: IP filter and ban check
    if let std::net::IpAddr::V4(ipv4) = from.ip() {
        if state.ip_filter.is_blocked_readonly_for_kad(ipv4) {
            debug!("Dropping packet from blocked IP {from}");
            return;
        }
        if state.banned_ips.contains(&ipv4) {
            debug!("Dropping packet from banned peer {from}");
            return;
        }
    }

    // Flood protection - rate limit and port 53 rejection
    if FloodProtection::is_dns_port(&from) {
        let header = data.first().copied().unwrap_or(0);
        if header == 0xE4 || header == 0xE5 {
            debug!("Dropping unencrypted KAD packet from DNS port 53 ({from})");
            return;
        }
    }
    // last_kad_contact updated after successful decode, not here on raw receipt
    let known_peer = match from.ip() {
        std::net::IpAddr::V4(v4) => {
            state.routing_table.has_contact_ip(v4)
                || state.flood_protection.has_recent_ip(from.ip())
        }
        _ => state.flood_protection.has_recent_ip(from.ip()),
    };
    let header = data.first().copied().unwrap_or(0);
    let opcode_hint = if header == 0xE4 || header == 0xE5 {
        data.get(1).copied().unwrap_or(0xFF)
    } else {
        0xFF
    };
    if state
        .flood_protection
        .check_rate_limit_with_opcode(from.ip(), known_peer, opcode_hint)
    {
        debug!("Rate limit exceeded for {from} (opcode 0x{opcode_hint:02X}), dropping packet");
        return;
    }

    // K21: per-IP zlib-decompression budget. A malicious peer can send
    // compressed KAD packets all day and burn CPU on every one; the
    // per-packet MAX_DECOMPRESSED_SIZE caps one shot but nothing caps
    // aggregate throughput. Reject decompression when the IP is over its
    // 10-packets/sec budget for compressed traffic specifically.
    if data.first() == Some(&kad::messages::OP_KADEMLIAPACKEDPROT)
        && state
            .flood_protection
            .over_compressed_budget(from.ip(), opcode_hint, data.len())
    {
        debug!("Dropping compressed KAD packet from {from}: per-IP decompression budget exhausted");
        return;
    }

    let mut packet_sender_udp_key: Option<KadUDPKey> = None;
    let mut packet_valid_receiver_key = false;
    let msg = match messages::decode_packet(data) {
        Ok(m) => m,
        Err(_first_err) => {
            let receiver_vk = match from.ip() {
                std::net::IpAddr::V4(ip) => {
                    KadUDPKey::verify_key_for(state.udp_key_seed, u32::from(ip))
                }
                _ => 0,
            };
            let sender_ip_u32 = match from.ip() {
                std::net::IpAddr::V4(ip) => u32::from(ip),
                _ => 0,
            };
            if let Some(decrypted) = kad::obfuscation::try_decrypt_kad_packet(
                data,
                &state.local_id,
                &state.user_hash,
                receiver_vk,
                sender_ip_u32,
            ) {
                // The peer derived this key from our address, so bind it to our
                // current public IP: eMule's
                // `CKadUDPKey(nSenderVerifyKey, theApp.GetPublicIP())`. That
                // binding is what lets a key left over from a previous address
                // read as absent instead of as a hijack attempt.
                packet_sender_udp_key = decrypted
                    .sender_verify_key
                    .map(|key| KadUDPKey::received(key, state.external_ip.map_or(0, u32::from)));
                packet_valid_receiver_key = decrypted.valid_receiver_key;
                // Obfuscation hides the packed-protocol marker from the
                // pre-decrypt check. Charge the same CPU/byte budget now,
                // after authentication/deobfuscation but before zlib sees it.
                if decrypted.payload.first() == Some(&kad::messages::OP_KADEMLIAPACKEDPROT)
                    && state
                        .flood_protection
                        .over_compressed_budget(
                            from.ip(),
                            decrypted.payload.get(1).copied().unwrap_or(0),
                            decrypted.payload.len(),
                        )
                {
                    debug!(
                        "Dropping obfuscated compressed KAD packet from {from}: decompression budget exhausted"
                    );
                    return;
                }
                match messages::decode_packet(&decrypted.payload) {
                    Ok(m) => {
                        // The pre-decrypt rate check above necessarily used
                        // opcode_hint=0xFF and so skipped Layer 1 (the tight
                        // per-opcode request limits, e.g. SearchKeyReq's
                        // 5-per-15s) entirely — only the much looser Layer 2
                        // global-per-IP cap applied. Now that decryption +
                        // decode revealed the real opcode, close that gap by
                        // re-running Layer 1 alone (Layer 2 was already
                        // charged once for this packet and must not be
                        // charged twice). Without this, an attacker could
                        // obfuscate SearchKeyReq/PublishKeyReq/etc. floods to
                        // dodge the per-opcode limits that exist specifically
                        // to bound SearchRes reflection/amplification.
                        if let Some(real_opcode) = messages::request_wire_opcode(&m) {
                            if state.flood_protection.recheck_opcode_limit_post_decrypt(
                                from.ip(),
                                known_peer,
                                real_opcode,
                            ) {
                                debug!(
                                    "Rate limit exceeded for {from} (obfuscated opcode 0x{real_opcode:02X} revealed post-decrypt), dropping packet"
                                );
                                return;
                            }
                        }
                        // Diagnostic: classify every successful decrypt+decode
                        // so the `Publish cycle:` log can distinguish
                        // "obfuscated path is broken" from "PublishRes
                        // specifically is missing" from "remote never sent".
                        state.obf_decoded_total = state.obf_decoded_total.saturating_add(1);
                        if matches!(&m, KadMessage::PublishRes { .. }) {
                            state.publish_res_obf_decoded =
                                state.publish_res_obf_decoded.saturating_add(1);
                        }
                        debug!(
                            "Decrypted obfuscated KAD packet from {from} ({} bytes)",
                            data.len()
                        );
                        m
                    }
                    Err(e) => {
                        debug!("Decrypted obfuscated packet from {from} but failed to parse: {e}");
                        return;
                    }
                }
            } else {
                // Demoted from warn: a packet with a valid KAD header byte
                // (0xE4/0xE5) that we can't parse and can't decrypt as
                // obfuscated KAD is almost always a remote peer running an
                // exotic mod or sending malformed bytes — nothing we can act
                // on, and a single misbehaving peer can spam this for the
                // entire session. Match the non-KAD-header branch below and
                // log at debug only.
                let header = data.first().copied().unwrap_or(0);
                if header == 0xE4 || header == 0xE5 {
                    debug!(
                        "Failed to decode KAD packet from {from} ({} bytes): {_first_err}",
                        data.len()
                    );
                } else {
                    debug!(
                        "Unreadable packet from {from} ({} bytes, header 0x{header:02X})",
                        data.len()
                    );
                }
                return;
            }
        }
    };

    state.last_kad_contact = Some(chrono::Utc::now().timestamp());

    // Phase 4: validate responses against tracked outgoing requests
    let response_opcode = match &msg {
        KadMessage::BootstrapRes { .. } => Some(0x09u8),
        KadMessage::HelloRes { .. } => Some(0x19),
        KadMessage::HelloResAck { .. } => Some(0x22),
        KadMessage::KadRes { .. } => Some(0x29),
        KadMessage::SearchRes { .. } => Some(0x3B),
        KadMessage::PublishRes { .. } => Some(0x4B),
        // PublishResAck (0x4C) is intentionally NOT validated: we
        // emit PublishRes (0x4B) ourselves as a *response* to the
        // peer's PublishKeyReq, so we never have a tracked outgoing
        // 0x4B for the validator to consume — every PublishResAck
        // would otherwise be rejected as "unsolicited" and the
        // `stores_acknowledged` stat would stay at 0 forever. The
        // handler is a stat counter only (no state mutation, no
        // amplification surface), so skipping validation here is
        // safe.
        KadMessage::PublishResAck => None,
        KadMessage::FindBuddyRes { .. } => Some(0x5A),
        KadMessage::Pong { .. } => Some(0x61),
        KadMessage::FirewalledRes { .. } => Some(0x58),
        _ => None,
    };
    // PublishRes `wire` counter, after successful decode (so it counts
    // both plain and obfuscated replies). If this climbs while
    // `received` stays at 0, the drop is in `validate_response` (see
    // the `unmatched` counter below — which also tracks
    // validate_response drops for 0x4B).
    if matches!(&msg, KadMessage::PublishRes { .. }) {
        state.publish_res_wire = state.publish_res_wire.saturating_add(1);
    }
    if let Some(opcode) = response_opcode {
        if !state.flood_protection.validate_response(from, opcode) {
            if opcode == 0x3B {
                debug!("Dropping unsolicited SearchRes from {from} (no matching outgoing SearchKeyReq)");
            } else if opcode == 0x5A {
                debug!("Dropping unsolicited FindBuddyRes from {from} (no matching tracked FindBuddyReq)");
            } else if opcode == 0x4B {
                // Track PublishRes rejections separately so the Publish
                // cycle log can tell us whether the ack counter is being
                // starved by validate_response drops (upstream of the
                // handler) vs. handler-level match misses.
                state.publish_res_unmatched = state.publish_res_unmatched.saturating_add(1);
                debug!("Dropping unsolicited PublishRes from {from} (no matching tracked publish request)");
            } else {
                debug!("Dropping unsolicited response 0x{:02X} from {from}", opcode);
            }
            return;
        }
    }

    // eMule SetAlive: refresh the sender in the routing table on every valid message
    if let std::net::IpAddr::V4(ipv4) = from.ip() {
        state.routing_table.touch_contact_by_addr(ipv4, from.port());
    }

    match msg {
        KadMessage::BootstrapReq => {
            debug!("BootstrapReq from {from}");
            // The only KAD exchange where an unauthenticated 2-byte request
            // draws a fixed ~523-byte answer, so it is the one response worth
            // metering against a source address we cannot verify (~260x toward
            // a spoofable target). Solicited answers are deliberately left out
            // of this budget: a single page of SearchRes already fragments to
            // roughly 18 datagrams, so charging them here would silently
            // truncate legitimate paging — the very failure
            // `SEARCH_RES_BUDGET_PER_REQUEST` was widened to avoid.
            if state.flood_protection.check_outgoing_rate(from.ip()) {
                debug!("Throttling BootstrapRes to {from}");
                return;
            }
            // eMule: GetBootstrapContacts returns 20 contacts from top buckets
            let contacts = state.routing_table.export_bootstrap_contacts(20);
            let res = KadMessage::BootstrapRes {
                sender_id: state.local_id,
                tcp_port: advertised_tcp_port(state),
                version: KADEMLIA_VERSION,
                contacts,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ =
                    send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key)
                        .await;
            }
        }

        KadMessage::BootstrapRes {
            sender_id,
            tcp_port,
            version,
            contacts,
        } => {
            debug!("BootstrapRes from {from}: {} contacts", contacts.len());
            let ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            let now = chrono::Utc::now().timestamp();
            state.routing_table.insert(KadContact {
                id: sender_id,
                ip,
                udp_port: from.port(),
                tcp_port,
                version,
                last_seen: now,
                verified: packet_valid_receiver_key,
                contact_type: CONTACT_TYPE_NEW,
                udp_key: packet_sender_udp_key,
                kad_options: 0,
                created_at: now,
                expires_at: 0,
                last_type_set: 0,
                received_hello: false,
            });

            // K2: previously we blanket-marked every bootstrap-response
            // contact as `verified` when the local routing table was
            // empty. That let a single malicious bootstrap peer poison
            // the routing table end-to-end at first launch. Now we insert
            // them unverified and Hello the first 8 so the normal
            // handshake / UDP-key (or legacy challenge) path can promote
            // them. Remaining contacts wait to be verified lazily.
            let mut hello_addrs: Vec<(SocketAddr, KadId, u8)> = Vec::new();
            for (i, c) in contacts.into_iter().enumerate() {
                let addr = SocketAddr::new(c.ip.into(), c.udp_port);
                let id = c.id;
                let ver = c.version;
                if i < 8 {
                    hello_addrs.push((addr, id, ver));
                }
                state.routing_table.insert(c);
            }

            // Hello the bootstrap node itself, then the first returned contacts.
            let hello = KadMessage::HelloReq {
                sender_id: state.local_id,
                tcp_port: advertised_tcp_port(state),
                version: KADEMLIA_VERSION,
                tags: {
                    let mut tags = Vec::new();
                    if state.external_udp_port.unwrap_or(state.udp_port) == state.udp_port {
                        tags.push(KadTag {
                            name: TagName::Id(TAG_SOURCEUPORT),
                            value: TagValue::Uint16(state.udp_port),
                        });
                    }
                    if version >= KADEMLIA_VERSION8_49B {
                        let mut our_options: u8 = 0;
                        our_options |= 0x04;
                        if state.udp_firewalled {
                            our_options |= 0x01;
                        }
                        if state.firewalled {
                            our_options |= 0x02;
                        }
                        tags.push(KadTag {
                            name: TagName::Id(TAG_KADMISCOPTIONS),
                            value: TagValue::Uint8(our_options),
                        });
                    }
                    if !settings.nickname.is_empty() {
                        tags.push(KadTag {
                            name: TagName::Id(TAG_FILENAME),
                            value: TagValue::String(settings.nickname.clone()),
                        });
                    }
                    tags
                },
            };
            if let Ok(packet) = messages::encode_packet(&hello) {
                state.flood_protection.track_request(from, 0x11);
                let _ = send_kad_response(
                    socket,
                    &packet,
                    from,
                    state,
                    Some(&sender_id),
                    packet_sender_udp_key,
                )
                .await;
                debug!("Sent HelloReq to bootstrap node {from}");
            }

            if let Ok(packet) = messages::encode_packet(&hello) {
                for (addr, id, _ver) in hello_addrs {
                    state.flood_protection.track_request(addr, 0x11);
                    let _ = send_kad_packet(socket, &packet, addr, state, &id).await;
                }
            }

            let table_size = state.routing_table.len();
            debug!("Routing table now has {table_size} contacts");
            state.stats.connected_peers = table_size as u32;
            if state.stats.status != NetworkStatus::Connected
                && state.routing_table.verified_len() >= KAD_MIN_VERIFIED_FOR_CONNECTED
                && kad_has_fresh_contact(state)
            {
                promote_kad_connected_and_first_publish(
                    state,
                    app_handle,
                    local_index,
                    transfer_manager,
                    known_files,
                )
                .await;
            }

            // eMule: first FindNode(self) only after MIN2S(3) from KAD start (not on first packet).
            const SELF_LOOKUP_FIRST_DELAY_SECS: i64 = 3 * 60;
            let now_ts = chrono::Utc::now().timestamp();
            if !state.self_lookup_done
                && table_size >= 2
                && now_ts >= state.kad_started_at + SELF_LOOKUP_FIRST_DELAY_SECS
            {
                let closest = state
                    .routing_table
                    .find_closest(&state.local_id, SEARCH_INITIAL_CONTACTS);
                if !closest.is_empty() {
                    let self_id = state.local_id;
                    let sid =
                        start_kad_search(state, app_handle, self_id, SearchType::FindNode, closest);
                    if sid != SearchId(0) {
                        info!("Started self-lookup from BootstrapRes, search {}, {table_size} contacts", sid.0);
                        state.self_lookup_done = true;
                        state.last_self_lookup = now_ts;
                    }
                }
            }
        }

        KadMessage::HelloReq {
            sender_id,
            tcp_port,
            version,
            tags,
        } => {
            let ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };

            // eMule: reject Kad1 contacts
            if version <= 1 {
                debug!("HelloReq from {from}: rejecting Kad1 contact (version={version})");
                return;
            }

            // Parse TAG_KADMISCOPTIONS
            let kad_options = tags
                .iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_KADMISCOPTIONS)))
                .and_then(|t| {
                    t.uint8_value()
                        .or_else(|| t.uint16_value().map(|v| v as u8))
                        .or_else(|| t.uint32_value().map(|v| v as u8))
                })
                .unwrap_or(0);
            let peer_udp_firewalled = kad_options & 0x01 != 0;

            let valid_receiver_key = packet_valid_receiver_key;
            let received_hello_port = tags
                .iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_SOURCEUPORT)))
                .and_then(|t| t.uint16_value())
                .unwrap_or(from.port());

            let now = chrono::Utc::now().timestamp();
            if !peer_udp_firewalled {
                state.routing_table.insert(KadContact {
                    id: sender_id,
                    ip,
                    udp_port: received_hello_port,
                    tcp_port,
                    version,
                    last_seen: now,
                    verified: valid_receiver_key,
                    contact_type: CONTACT_TYPE_OPEN,
                    udp_key: packet_sender_udp_key,
                    kad_options,
                    created_at: now,
                    expires_at: 0,
                    last_type_set: 0,
                    received_hello: true,
                });
            } else {
                debug!(
                    "Not adding UDP-firewalled contact {} from {}",
                    sender_id, from
                );
            }

            if let Some(nick) = tags
                .iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_FILENAME)))
                .and_then(|t| t.string_value())
            {
                let sanitized = crate::security::sanitize_display_name(nick);
                if !sanitized.is_empty() {
                    state.peer_nicknames.insert(sender_id, sanitized);
                }
            }

            if valid_receiver_key && !peer_udp_firewalled {
                state.routing_table.mark_verified_from(&sender_id, ip);
            }

            // eMule: only request ACK when crypt is on and the peer is Kad ≥8.
            // When obfuscation is disabled, HelloResAck cannot carry a valid
            // receiver key, so we fall through to a plaintext legacy challenge.
            let needs_ack = !valid_receiver_key
                && version >= KADEMLIA_VERSION8_49B
                && state.obfuscation_enabled;
            let mut res_tags = Vec::new();
            if state.external_udp_port.unwrap_or(state.udp_port) == state.udp_port {
                res_tags.push(KadTag {
                    name: TagName::Id(TAG_SOURCEUPORT),
                    value: TagValue::Uint16(state.udp_port),
                });
            }
            if version >= KADEMLIA_VERSION8_49B
                && (needs_ack || state.udp_firewalled || state.firewalled)
            {
                let mut our_options: u8 = 0;
                if state.udp_firewalled {
                    our_options |= 0x01;
                }
                if state.firewalled {
                    our_options |= 0x02;
                }
                if needs_ack {
                    our_options |= 0x04;
                }
                res_tags.push(KadTag {
                    name: TagName::Id(TAG_KADMISCOPTIONS),
                    value: TagValue::Uint8(our_options),
                });
            }

            let res = KadMessage::HelloRes {
                sender_id: state.local_id,
                tcp_port: advertised_tcp_port(state),
                version: KADEMLIA_VERSION,
                tags: res_tags,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                state.flood_protection.track_request(from, 0x19);
                let _ = send_kad_response(
                    socket,
                    &packet,
                    from,
                    state,
                    Some(&sender_id),
                    packet_sender_udp_key,
                )
                .await;
            }

            // eMule Process_KADEMLIA2_HELLO_REQ challenge paths when the peer
            // was added/updated without a valid receiver key:
            //   <7  → SendLegacyChallenge (KADEMLIA2_REQ with random target)
            //   ==7 → Ping challenge
            //   ≥8 + crypt off → same Req challenge (plaintext verify path)
            if !peer_udp_firewalled && !valid_receiver_key {
                maybe_send_hello_challenge(
                    socket,
                    from,
                    ip,
                    sender_id,
                    version,
                    state,
                    packet_sender_udp_key,
                )
                .await;
            }
        }

        KadMessage::HelloRes {
            sender_id,
            tcp_port,
            version,
            tags,
        } => {
            let ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };

            // eMule: reject Kad1 contacts
            if version <= 1 {
                debug!("HelloRes from {from}: rejecting Kad1 contact (version={version})");
                return;
            }

            let kad_options = tags
                .iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_KADMISCOPTIONS)))
                .and_then(|t| {
                    t.uint8_value()
                        .or_else(|| t.uint16_value().map(|v| v as u8))
                        .or_else(|| t.uint32_value().map(|v| v as u8))
                })
                .unwrap_or(0);
            let peer_udp_firewalled = kad_options & 0x01 != 0;

            let valid_receiver_key = packet_valid_receiver_key;

            let now = chrono::Utc::now().timestamp();
            let received_hello_port = tags
                .iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_SOURCEUPORT)))
                .and_then(|t| t.uint16_value())
                .unwrap_or(from.port());
            if !peer_udp_firewalled {
                state.routing_table.insert(KadContact {
                    id: sender_id,
                    ip,
                    udp_port: received_hello_port,
                    tcp_port,
                    version,
                    last_seen: now,
                    verified: valid_receiver_key,
                    contact_type: CONTACT_TYPE_OPEN,
                    udp_key: packet_sender_udp_key,
                    kad_options,
                    created_at: now,
                    expires_at: 0,
                    last_type_set: 0,
                    received_hello: true,
                });
            } else {
                debug!(
                    "Not adding UDP-firewalled contact {} from HelloRes ({from})",
                    sender_id
                );
            }

            if valid_receiver_key && !peer_udp_firewalled {
                state.routing_table.mark_verified_from(&sender_id, ip);
            }
            state.stats.connected_peers = state.routing_table.len() as u32;

            let nick = tags
                .iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_FILENAME)))
                .and_then(|t| t.string_value())
                .map(crate::security::sanitize_display_name)
                .unwrap_or_default();

            if !nick.is_empty() {
                state.peer_nicknames.insert(sender_id, nick.clone());
            }

            // eMule: if the remote requested an ACK (bit 2 of kad_options), send HelloResAck
            let wants_ack = kad_options & 0x04 != 0;
            if wants_ack {
                if packet_sender_udp_key.is_none() {
                    debug!("Ignoring HelloRes ACK request from {from}: packet did not include a sender UDP key");
                }
                let ack = KadMessage::HelloResAck {
                    sender_id: state.local_id,
                    tags: Vec::new(),
                };
                if packet_sender_udp_key.is_some() {
                    if let Ok(packet) = messages::encode_packet(&ack) {
                        let _ = send_kad_response(
                            socket,
                            &packet,
                            from,
                            state,
                            Some(&sender_id),
                            packet_sender_udp_key,
                        )
                        .await;
                    }
                }
            } else if !peer_udp_firewalled && !valid_receiver_key {
                // eMule Process_KADEMLIA2_HELLO_RES: old peers (and crypt-off
                // modern peers) get a legacy challenge instead of ACK.
                maybe_send_hello_challenge(
                    socket,
                    from,
                    ip,
                    sender_id,
                    version,
                    state,
                    packet_sender_udp_key,
                )
                .await;
            }

            // Persist peer to database. This runs in the per-packet hot path
            // on the single-threaded network loop, so push the synchronous
            // SQLite write onto the blocking pool instead of stalling packet
            // processing on disk I/O. The write is an idempotent upsert and
            // already best-effort (errors were only logged), so fire-and-forget
            // semantics are unchanged.
            let peer_info = PeerInfo {
                id: hex::encode(sender_id.0),
                addresses: vec![format!("{}:{}", ip, tcp_port)],
                nickname: nick,
                last_seen: now,
                files_shared: 0,
                banned: false,
            };
            let db_for_peer = db.clone();
            tokio::task::spawn_blocking(move || {
                if let Err(e) = db_for_peer.save_peer(&peer_info) {
                    debug!("Failed to persist peer: {e}");
                }
            });
        }

        KadMessage::HelloResAck { sender_id, tags: _ } => {
            let sender_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            if !packet_valid_receiver_key {
                debug!("Ignoring HelloResAck from {from}: invalid receiver key");
                return;
            }
            let valid_sender = state
                .routing_table
                .get_contact(&sender_id)
                .map(|contact| contact.ip == sender_ip)
                .unwrap_or(false);
            if !valid_sender {
                debug!(
                    "Ignoring HelloResAck from {from}: sender {} does not match routing table",
                    sender_id
                );
                return;
            }

            debug!("HelloResAck from {from} - contact {} verified", sender_id);
            state.routing_table.mark_verified(&sender_id);
            if let Some(peer_udp_key) = packet_sender_udp_key {
                if let Some(contact) = state.routing_table.get_contact_mut(&sender_id) {
                    contact.udp_key = Some(peer_udp_key);
                }
            }
        }

        KadMessage::KadReq {
            search_type,
            target,
            receiver,
        } => {
            if receiver != state.local_id {
                return;
            }
            // eMule Process_KADEMLIA2_REQ: the search_type byte (masked 0x1F) doubles
            // as the number of contacts to return. GetClosestTo(maxType=2, ..., count=byType)
            // only returns verified contacts with type <= 2 (ACTIVE/VERIFIED/OPEN).
            let requested_count = (search_type & 0x1F) as usize;
            if requested_count == 0 {
                debug!("KadReq from {from}: search_type 0 is invalid, ignoring");
            } else {
                let closest =
                    state
                        .routing_table
                        .find_closest_verified_by_type(&target, requested_count, 2);
                let res = KadMessage::KadRes {
                    target,
                    contacts: closest,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        None,
                        packet_sender_udp_key,
                    )
                    .await;
                }
            }
        }

        KadMessage::KadRes { target, contacts } => {
            debug!(
                "KadRes from {from}: {} contacts for target {target}",
                contacts.len()
            );

            // eMule Process_KADEMLIA2_RES: first check legacy Hello challenge.
            if let std::net::IpAddr::V4(v4) = from.ip() {
                if let Some(contact_id) = state.legacy_challenges.take_match(
                    &target,
                    v4,
                    LegacyChallengeTracker::OPCODE_REQ,
                ) {
                    if state
                        .routing_table
                        .get_contact(&contact_id)
                        .map(|c| c.ip == v4)
                        == Some(true)
                    {
                        state.routing_table.mark_verified(&contact_id);
                        debug!(
                            "Verified contact {contact_id} via legacy KadReq challenge from {from}"
                        );
                    } else {
                        debug!(
                            "Legacy KadReq challenge matched from {from} but contact {contact_id} missing/mismatched"
                        );
                    }
                    return;
                }
            }

            // eMule Process_KADEMLIA2_RES: verify we have an active search for this target.
            if !state.search_manager.has_active_search_for_target(&target) {
                debug!("  No active search for target {target}, ignoring response");
                return;
            }

            // Route the response to EVERY active same-target search that
            // actually queried this sender. eMule keeps at most one search per
            // target, but Ember can legitimately run two on the same KadID
            // (e.g. a `FindSource` download lookup and a `StoreFile` source
            // publish on the same file hash). Both walk the DHT with
            // `KADEMLIA2_REQ`; when both queried the same node, only one
            // identical `KadRes` arrives per request, so handing the contacts
            // to just the first search would starve the other of convergence
            // (K13 follow-up). Each search tracks its own lookup state, so
            // delivering the same validated contacts to several searches is
            // harmless. We still never route to a search that did NOT query
            // this sender (eMule's IsOnOutTrackList anti-injection rule).
            // Contact-count acceptance is per matched search (not max across
            // same-target searches) — see the check inside the loop below.
            let sender_ip_port: Option<(Ipv4Addr, u16)> = match from.ip() {
                std::net::IpAddr::V4(v4) => Some((v4, from.port())),
                _ => None,
            };

            let mut search_ids: Vec<SearchId> = sender_ip_port
                .map(|(ip, port)| {
                    state
                        .search_manager
                        .active
                        .iter()
                        .filter(|(_, s)| {
                            s.target == target && !s.completed && s.tried.contains_key(&(ip, port))
                        })
                        .map(|(id, _)| *id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if search_ids.is_empty() {
                // No active search queried this sender on the exact (ip, port).
                // Fall back to searches that queried this sender's *IP* (the
                // KAD UDP source port can be rewritten by carrier-grade NAT),
                // matching eMule's by-IP responder lookup. We do NOT fall back
                // to "any search with this target": accepting routing contacts
                // from a node no active search ever queried would let an
                // unsolicited peer inject contacts (eMule's IsOnOutTrackList).
                search_ids = sender_ip_port
                    .map(|(ip, _)| {
                        state
                            .search_manager
                            .active
                            .iter()
                            .filter(|(_, s)| {
                                s.target == target
                                    && !s.completed
                                    && s.tried.keys().any(|(tip, _)| *tip == ip)
                            })
                            .map(|(id, _)| *id)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
            }

            if search_ids.is_empty() {
                debug!("  KadRes from {from}: no search queried this sender for target {target}; ignoring unsolicited response");
            }

            for sid in search_ids {
                let sender_id = sender_ip_port
                    .and_then(|(ip, port)| {
                        state.search_manager.active.get(&sid).and_then(|s| {
                            // Exact (ip, port) first, then any contact from the
                            // same IP we queried (NAT port rewrite).
                            s.tried.get(&(ip, port)).copied().or_else(|| {
                                s.tried
                                    .iter()
                                    .find(|((tip, _), _)| *tip == ip)
                                    .map(|(_, id)| *id)
                            })
                        })
                    })
                    .or_else(|| {
                        sender_ip_port.and_then(|(ip, port)| {
                            state
                                .routing_table
                                .all_contacts()
                                .find(|c| c.ip == ip && c.udp_port == port)
                                .map(|c| c.id)
                        })
                    });

                // eMule drops the response for a search when contact count
                // exceeds what *that* search requested (GetRequestContactCount),
                // except FIND_VALUE_MORE from that search's re-ask contact
                // (≤ KADEMLIA_FIND_NODE). Never borrow a higher expected count
                // from a different same-target search, and never truncate.
                let max_accepted = state
                    .search_manager
                    .max_accepted_response_count_for(&sid, sender_id.as_ref());
                if contacts.len() > max_accepted as usize {
                    debug!(
                        "KadRes from {from}: contact count {} exceeds max {} for search {}, skipping",
                        contacts.len(),
                        max_accepted,
                        sid.0
                    );
                    continue;
                }
                // Buffer for eMule's immediate `SendFindValue` dispatch. Filled
                // while `search` (a &mut borrow of state.search_manager) is held,
                // then flushed after the block releases it — `send_kad_packet`
                // needs a whole-`state` immutable borrow that can't coexist with
                // the &mut search-manager borrow.
                let mut reactive_queries: Vec<(KadContact, KadMessage)> = Vec::new();
                // Deferred FindBuddyReq send — same borrow pattern as reactive_queries.
                let mut pending_find_buddy: Option<(Vec<u8>, KadId)> = None;
                if let (Some(search), Some(sender_id)) =
                    (state.search_manager.get_mut(&sid), sender_id)
                {
                    // eMule ProcessResponse: validate contacts
                    // - No blocked/banned IPs
                    // - No duplicate IPs (including sender IP)
                    // - No more than 2 IPs from same /24 subnet
                    let sender_ip = match from.ip() {
                        std::net::IpAddr::V4(v4) => v4,
                        _ => Ipv4Addr::UNSPECIFIED,
                    };
                    let mut seen_ips: HashSet<Ipv4Addr> = HashSet::new();
                    seen_ips.insert(sender_ip);
                    let mut subnet_counts: HashMap<u32, u32> = HashMap::new();
                    let sender_subnet = {
                        let o = sender_ip.octets();
                        u32::from_be_bytes([o[0], o[1], o[2], 0])
                    };
                    *subnet_counts.entry(sender_subnet).or_insert(0) += 1;

                    let safe_contacts: Vec<KadContact> = contacts
                        .iter()
                        .filter(|c| {
                            // eMule: reject Kad1 contacts (version <= 1)
                            if !c.is_kad2() {
                                return false;
                            }
                            // eMule: reject DNS port 53 for old versions
                            if c.udp_port == 53 && c.version <= KADEMLIA_VERSION5_48A {
                                return false;
                            }
                            // Use KAD admission (not fail-closed peer gate) so
                            // bootstrap KadRes contacts aren't wiped while
                            // ipfilter.dat is still loading — matches RT insert.
                            if state.ip_filter.is_blocked_readonly_for_kad(c.ip)
                                || state.banned_ips.contains(&c.ip)
                            {
                                return false;
                            }
                            // eMule IsAcceptableContact: check routing table constraints
                            if !state.routing_table.is_acceptable_contact(c) {
                                return false;
                            }
                            if !seen_ips.insert(c.ip) {
                                debug!("KadRes: duplicate IP {} in response, ignoring", c.ip);
                                return false;
                            }
                            // eMule: LAN IPs are exempt from per-response subnet limits
                            if !kad::ip_filter::is_lan_ip(c.ip) {
                                let o = c.ip.octets();
                                let subnet = u32::from_be_bytes([o[0], o[1], o[2], 0]);
                                let count = subnet_counts.entry(subnet).or_insert(0);
                                *count += 1;
                                if *count > 2 {
                                    debug!(
                                        "KadRes: >2 contacts from subnet {}.{}.{}.0, ignoring {}",
                                        o[0], o[1], o[2], c.ip
                                    );
                                    return false;
                                }
                            }
                            true
                        })
                        .cloned()
                        .collect();
                    debug!(
                        "  Search {}: processing {} contacts from {} ({} filtered)",
                        sid.0,
                        safe_contacts.len(),
                        sender_id,
                        contacts.len() - safe_contacts.len()
                    );
                    search.handle_response(&sender_id, safe_contacts.clone());
                    let is_fw_probe_search = search.is_udp_fw_probe_search;
                    // eMule CSearch::ProcessResponse (SendFindValue): collect the
                    // queries for freshly-discovered top-ALPHA contacts now, then
                    // send them below once `search` is no longer borrowed. A UDP
                    // firewall probe search never populates priority_queries (it
                    // returns early in handle_response), so this is a no-op there.
                    reactive_queries = search.take_priority_queries();

                    // eMule behavior: for FindBuddy searches, send FindBuddyReq
                    // to EVERY node that responds during the lookup, not just the
                    // final closest at convergence. Reserve here; send after the
                    // search borrow ends (and only then track flood ack).
                    if matches!(search.search_type, SearchType::FindBuddy)
                        && search.phase == SearchPhase::Lookup
                        && state.buddy_manager.state() == BuddyState::FindingBuddy
                        && search.reserve_find_buddy_request(sender_id)
                    {
                        let buddy_target = state.buddy_manager.find_buddy_target();
                        let user_id = KadId(cuint128_swap(&state.user_hash));
                        let local_tcp = state.buddy_manager.tcp_port();
                        let msg = KadMessage::FindBuddyReq {
                            buddy_id: buddy_target,
                            user_id,
                            tcp_port: local_tcp,
                        };
                        match messages::encode_packet(&msg) {
                            Ok(packet) => {
                                pending_find_buddy = Some((packet, sender_id));
                            }
                            Err(_) => {
                                search.release_find_buddy_request(sender_id);
                            }
                        }
                    }

                    if is_fw_probe_search {
                        // eMule CUDPFirewallTester::AddPossibleTestContact: keep
                        // these discovered nodes OUT of the routing table (so we
                        // never send them a KAD UDP packet) and stash them as
                        // fresh UDP-firewall probe candidates instead.
                        let mut gained_candidate = false;
                        for c in &safe_contacts {
                            if c.version > KADEMLIA_VERSION5_48A
                                && c.tcp_port > 0
                                && state.routing_table.get_contact(&c.id).is_none()
                                && !state.udp_fw_candidate_pool.iter().any(|x| x.ip == c.ip)
                                && state.udp_fw_candidate_pool.len() < UDP_FW_CANDIDATE_POOL_MAX
                            {
                                state.udp_fw_candidate_pool.push_back(c.clone());
                                gained_candidate = true;
                            }
                        }
                        // Drain the pool the instant fresh candidates land instead
                        // of waiting for the next incidental Pong to trigger
                        // `dispatch_udp_firewall_probe_requests`. On a just-started
                        // routing table the handful of contacts pinged for port
                        // discovery at `start_check()` time are often stale and
                        // never reply, so without this the fresh-node lookup could
                        // finish populating the pool well inside the 30s response
                        // window yet no probe would ever actually be sent this
                        // cycle — the classic "TCP: Open / UDP: Unknown until you
                        // click Recheck" symptom (the manual recheck merely gets
                        // lucky with an unrelated Pong arriving in time).
                        if gained_candidate {
                            dispatch_udp_firewall_probe_requests(state, app_handle, settings);
                        }
                    } else {
                        for c in &safe_contacts {
                            state.routing_table.insert(c.clone());
                        }
                    }
                }

                if let Some((packet, sender_id)) = pending_find_buddy {
                    if send_kad_packet(socket, &packet, from, state, &sender_id)
                        .await
                        .is_ok()
                    {
                        state.flood_protection.track_request(from, 0x51);
                    } else if let Some(search) = state.search_manager.get_mut(&sid) {
                        search.release_find_buddy_request(sender_id);
                    }
                }

                // eMule CSearch::ProcessResponse SendFindValue: the &mut
                // state.search_manager borrow above is now released, so fire the
                // queued top-ALPHA queries immediately over UDP. This removes up
                // to ~1s of per-hop latency versus deferring every query to the
                // periodic poll_queries tick; the poll still drives the rest of
                // the contact pool (eMule JumpStart). Marking already happened in
                // take_priority_queries, so the next poll won't re-send these.
                for (contact, msg) in reactive_queries {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    if state.flood_protection.check_outgoing_rate(addr.ip()) {
                        debug!("Throttling reactive search packet to {addr}");
                        if let Some(search) = state.search_manager.get_mut(&sid) {
                            search.rollback_unsent_query(contact.id, &msg);
                        }
                        continue;
                    }
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        let opcode = packet.get(1).copied().unwrap_or(0);
                        match send_kad_packet(socket, &packet, addr, state, &contact.id).await {
                            Ok(_) => {
                                if let Some(search) = state.search_manager.get_mut(&sid) {
                                    search.commit_query_sent(contact.id, addr);
                                }
                                state.flood_protection.track_request(addr, opcode);
                            }
                            Err(e) => {
                                if let Some(search) = state.search_manager.get_mut(&sid) {
                                    if is_kad_request_paced(&e) {
                                        search.skip_paced_query(contact.id, &msg);
                                    } else {
                                        search.rollback_unsent_query(contact.id, &msg);
                                    }
                                }
                            }
                        }
                    } else if let Some(search) = state.search_manager.get_mut(&sid) {
                        search.rollback_unsent_query(contact.id, &msg);
                    }
                }
            }
        }

        KadMessage::SearchRes {
            sender_id,
            target,
            results,
        } => {
            debug!(
                "SearchRes from {} for target {}: {} entries",
                from,
                target,
                results.len()
            );
            // Log first few entries with their tag details for debugging
            for (i, entry) in results.iter().take(3).enumerate() {
                let raw_md4 = kad_id_to_md4_bytes(&entry.id);
                let mut sources_val = 0u32;
                let mut has_name = false;
                let mut src_ip = 0u32;
                for tag in &entry.tags {
                    if matches!(&tag.name, TagName::Id(TAG_SOURCES)) {
                        sources_val = tag.uint32_value().unwrap_or(0);
                    }
                    if matches!(&tag.name, TagName::Id(TAG_FILENAME)) {
                        has_name = true;
                    }
                    if matches!(&tag.name, TagName::Id(TAG_SOURCEIP)) {
                        src_ip = tag.uint32_value().unwrap_or(0);
                    }
                }
                debug!(
                    "  Entry[{}]: hash={}, tags={}, TAG_SOURCES={}, has_name={}, src_ip={}",
                    i,
                    hex::encode(raw_md4),
                    entry.tags.len(),
                    sources_val,
                    has_name,
                    src_ip
                );
            }

            // Route the result to active same-target searches that actually
            // queried this sender AND expect SEARCH_RES — i.e. the
            // fetch-capable `Find*` kinds. This matters when a `Find*` and a
            // `Store*` share a target (e.g. FindSource + StoreFile on one file
            // hash): the `Store*` search never issues a SEARCH_*_REQ, so
            // delivering a SEARCH_RES to it would silently swallow results the
            // real `Find*` search needs. We still never route to a search that
            // did not query this sender (anti-poisoning, eMule's
            // IsOnOutTrackList), and we deliver to every qualifying search so
            // duplicate UI searches on the same keyword don't starve.
            let sender_ip_port: Option<(Ipv4Addr, u16)> = match from.ip() {
                std::net::IpAddr::V4(v4) => Some((v4, from.port())),
                _ => None,
            };

            let mut search_ids: Vec<SearchId> = sender_ip_port
                .map(|(ip, port)| {
                    state
                        .search_manager
                        .active
                        .iter()
                        .filter(|(_, s)| {
                            s.target == target
                                && !s.completed
                                && s.search_type.accepts_search_results()
                                && s.tried.contains_key(&(ip, port))
                        })
                        .map(|(id, _)| *id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            if search_ids.is_empty() {
                // NAT port-rewrite fallback: match by sender IP only. Same
                // anti-poisoning and fetch-kind constraints as above.
                search_ids = sender_ip_port
                    .map(|(ip, _)| {
                        state
                            .search_manager
                            .active
                            .iter()
                            .filter(|(_, s)| {
                                s.target == target
                                    && !s.completed
                                    && s.search_type.accepts_search_results()
                                    && s.tried.keys().any(|(tip, _)| *tip == ip)
                            })
                            .map(|(id, _)| *id)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
            }

            if search_ids.is_empty() {
                debug!("  No active search queried this sender for this target");
            }

            for sid in search_ids {
                let resolved_sender_id = sender_ip_port
                    .and_then(|(ip, port)| {
                        state.search_manager.active.get(&sid).and_then(|s| {
                            // Exact (ip, port) first, then any contact from the
                            // same IP we queried (NAT port rewrite).
                            s.tried.get(&(ip, port)).copied().or_else(|| {
                                s.tried
                                    .iter()
                                    .find(|((tip, _), _)| *tip == ip)
                                    .map(|(_, id)| *id)
                            })
                        })
                    })
                    .or_else(|| {
                        sender_ip_port.and_then(|(ip, port)| {
                            state
                                .routing_table
                                .all_contacts()
                                .find(|c| c.ip == ip && c.udp_port == port)
                                .map(|c| c.id)
                        })
                    });

                if let (Some(search), Some(resolved_sender_id)) =
                    (state.search_manager.get_mut(&sid), resolved_sender_id)
                {
                    if sender_id != resolved_sender_id {
                        debug!(
                            "SearchRes sender_id mismatch from {from}: embedded={}, resolved={}",
                            sender_id, resolved_sender_id
                        );
                    }
                    search.handle_search_results(&resolved_sender_id, results.clone());
                    let unique: std::collections::HashSet<&kad::types::KadId> =
                        search.results.iter().map(|r| &r.id).collect();
                    debug!(
                        "  Search {} now has {} raw / {} unique results (phase={:?})",
                        sid.0,
                        search.results.len(),
                        unique.len(),
                        search.phase
                    );
                } else {
                    debug!("Ignoring SearchRes from {from}: sender could not be resolved from queried contacts");
                }
            }
        }

        KadMessage::PublishRes {
            target,
            load,
            request_ack,
        } => {
            // Diagnostic: count every PublishRes that reaches the
            // handler. If this stays at 0 while Publish cycles show
            // `N outstanding pending ack`, the packets are being
            // dropped upstream (rate-limit / validate_response /
            // obfuscation-decrypt). If this climbs but `matched`
            // stays flat, the handler is running but the pending
            // map's target key doesn't match the wire target.
            state.publish_res_received = state.publish_res_received.saturating_add(1);
            // Match on `(target, peer_addr)` first (exact path). If that
            // misses, fall back to `(target, any-entry-with-same-IP)` —
            // peers behind carrier-grade NAT sometimes reply from a
            // different source *port* than the one we sent to because the
            // router rewrites the mapping; the IP stays stable. We deliberately
            // do NOT fall back to matching the target alone: keyword/source
            // publishes have many distinct peers under one target, so
            // consuming "any pending entry for this target" would decrement an
            // unrelated peer's outstanding-ack count (and could remove a
            // genuinely-pending slot), corrupting the per-peer confirmation
            // accounting. An ack we cannot attribute to a peer we actually
            // published to is left unmatched.
            let matched_key: Option<(KadId, SocketAddr)> =
                if state.publish_pending.contains_key(&(target, from)) {
                    Some((target, from))
                } else {
                    let from_ip = from.ip();
                    state
                        .publish_pending
                        .keys()
                        .find(|(t, a)| *t == target && a.ip() == from_ip)
                        .copied()
                };
            let matched_pending = matched_key.and_then(|key| {
                let mut remove_entry = false;
                let matched = state.publish_pending.get_mut(&key).map(|pending| {
                    if pending.3 > 1 {
                        pending.3 -= 1;
                    } else {
                        remove_entry = true;
                    }
                    (key, pending.0, pending.2)
                });
                if remove_entry {
                    state.publish_pending.remove(&key);
                }
                matched
            });
            if let Some((key, publish_file_hash, is_source_publish)) = matched_pending {
                state.publish_confirmed += 1;
                debug!(
                    "Publish confirmed for {target} from {from} (orig_key={:?}, load={load}, total_confirmed={})",
                    key, state.publish_confirmed
                );
                // eMule `CSearchManager::ProcessPublishResult`: every ack
                // increments the owning search's answer count so it can end
                // early (`record_publish_ack`) instead of waiting out its
                // full lifetime once enough nodes have confirmed. Look the
                // search up by the hash it was tracking under rather than
                // `target` directly — for source/keyword/notes publishes
                // that's the same value, but going through the small
                // in-flight maps avoids assuming that equivalence here.
                let ack_sid = if is_source_publish {
                    state
                        .store_source_searches
                        .iter()
                        .find(|(_, (file_hash, _))| *file_hash == publish_file_hash)
                        .map(|(sid, _)| *sid)
                } else {
                    state
                        .store_keyword_searches
                        .iter()
                        .find(|(_, batch)| batch.keyword_hash == publish_file_hash)
                        .map(|(sid, _)| *sid)
                        .or_else(|| {
                            state
                                .pending_note_publishes
                                .iter()
                                .find(|(_, pending)| pending.file_hash == publish_file_hash)
                                .map(|(sid, _)| *sid)
                        })
                };
                if let Some(sid) = ack_sid {
                    if let Some(search) = state.search_manager.get_mut(&sid) {
                        search.record_publish_ack();
                    }
                }
                if is_source_publish {
                    if let Some(count) = state.source_publish_acks.get_mut(&publish_file_hash) {
                        *count = count.saturating_add(1);
                    }
                    // The one place the rendezvous key's occupancy is
                    // observable. Sharding it is meant to happen "once one
                    // bucket's 1000-entry cap is in sight", and nothing local
                    // can see that: `ember_dht_rendezvous_last_peers` counts
                    // what a lookup *returned*, and a source search stops
                    // querying at `SOURCE_SEARCH_STOP_THRESHOLD` (20), so it
                    // saturates two orders of magnitude below the cap and can
                    // never report approaching it.
                    //
                    // A storer's load byte can. It is that node's own answer to
                    // "how full am I for this key", already the signal the
                    // keyword path backs off on at 90, and it arrives on every
                    // advert we place. Highest rather than latest: the twenty
                    // nodes closest to the key fill at different rates, and the
                    // first one to run out is what decides whether the advert
                    // still lands.
                    if target == kad::publish::ember_rendezvous_key() {
                        let seen = &mut state.ember_diagnostics.ember_dht_rendezvous_key_load;
                        *seen = (*seen).max(load as u32);
                    }
                } else {
                    state
                        .publish_manager
                        .record_keyword_publish_load(&target, load);
                }
            } else {
                state.publish_res_unmatched = state.publish_res_unmatched.saturating_add(1);
                debug!(
                    "PublishRes from {from} for {target} matched no pending entry (load={load})"
                );
            }
            // Acknowledge the PublishRes only when the sender explicitly
            // asked for it (options-byte bit0) AND we hold its UDP key, exactly
            // mirroring eMule's `Process_KADEMLIA2_PUBLISH_RES`. eMule never
            // sets that bit (it is "for future use") and neither do we, so in
            // practice no ack is sent. Emitting one unconditionally — as we
            // used to — sends vanilla eMule an unrequested KADEMLIA2_PUBLISH_RES_ACK.
            if request_ack && packet_sender_udp_key.is_some() {
                let ack = KadMessage::PublishResAck;
                if let Ok(packet) = messages::encode_packet(&ack) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        None,
                        packet_sender_udp_key,
                    )
                    .await;
                }
            }
            if load >= 100 {
                if let std::net::IpAddr::V4(ipv4) = from.ip() {
                    let now = chrono::Utc::now().timestamp();
                    state.overloaded_nodes.insert(ipv4, now);
                    info!("Node {from} reported full load, will avoid publishing to it for 10 min");
                }
            } else if load > 80 {
                debug!("High DHT load ({load}) from {from} for target {target}");
            }
        }

        KadMessage::Ping => {
            let pong = KadMessage::Pong {
                udp_port: from.port(),
            };
            if let Ok(packet) = messages::encode_packet(&pong) {
                let _ =
                    send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key)
                        .await;
            }
        }

        KadMessage::Pong { udp_port } => {
            debug!("Pong from {from} (reported udp_port={})", udp_port);
            if udp_port > 0 {
                // Weight the external-UDP-port vote by the reporter's /24
                // (handle_pong, K7). KAD is IPv4-only, so a non-V4 source here
                // would be anomalous — skip it rather than guess a subnet.
                if let std::net::IpAddr::V4(reporter) = from.ip() {
                    state.firewall_checker.handle_pong(udp_port, reporter);
                    // Record the vote, but don't let it override a live
                    // STUN-confirmed remap (see stun_udp_mapping_active).
                    if !stun_udp_mapping_active(state) {
                        if let Some(ext_port) = state.firewall_checker.external_udp_port() {
                            if state.external_udp_port != Some(ext_port) {
                                state.external_udp_port = Some(ext_port);
                                // Keep advertise_udp_port/publish_manager in
                                // sync immediately — otherwise a peer we
                                // Hello/publish to before the next periodic
                                // refresh (~5s) gets the stale port baked
                                // into that handshake.
                                update_publish_manager_state(state);
                            }
                        }
                    }
                    dispatch_udp_firewall_probe_requests(state, app_handle, settings);
                }
            }
            // eMule Process_KADEMLIA2_PONG: legacy Ping challenge verifies
            // without requiring a valid receiver key.
            if let std::net::IpAddr::V4(v4) = from.ip() {
                if let Some(contact_id) = state.legacy_challenges.take_match(
                    &KadId::zero(),
                    v4,
                    LegacyChallengeTracker::OPCODE_PING,
                ) {
                    if state
                        .routing_table
                        .get_contact(&contact_id)
                        .map(|c| c.ip == v4)
                        == Some(true)
                    {
                        state.routing_table.mark_verified(&contact_id);
                        debug!(
                            "Verified contact {contact_id} via legacy Ping challenge from {from}"
                        );
                    }
                } else if packet_valid_receiver_key {
                    // K22: only promote a contact to verified when the Pong
                    // carried our correct per-receiver UDP key (proves the sender
                    // could decrypt/compose against our current key seed, not
                    // just that their source address is reachable). This matches
                    // eMule's own check before accepting an identity claim.
                    let contact_id = state
                        .routing_table
                        .all_contacts()
                        .find(|c| c.ip == v4 && c.udp_port == from.port())
                        .map(|c| c.id);
                    if let Some(contact) = contact_id {
                        state.routing_table.mark_verified(&contact);
                    }
                }
            }
            // USS RTT measurement: only accept a Pong from the *current* USS
            // host while USS is enabled. Unrelated KAD Ping/Pong traffic
            // (firewall checks, legacy challenges) must not clear pending or
            // feed the RTT queue, and a late pong from a rotated host must
            // not reset the new host's miss counter.
            if state
                .uss_enabled_flag
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                let is_current_uss_host = state
                    .uss_host
                    .as_ref()
                    .is_some_and(|(addr, _)| *addr == from);
                if is_current_uss_host {
                    if let Some(sent_at) = state.pending_uss_pings.remove(&from) {
                        let rtt_ms = sent_at.elapsed().as_secs_f64() * 1000.0;
                        let mut queue = state
                            .uss_rtt_queue
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        if queue.len() >= 128 {
                            queue.pop_front();
                        }
                        queue.push_back(crate::bandwidth::UssRttSample { host: from, rtt_ms });
                        state.uss_missed_pongs = 0;
                        debug!("USS RTT from {from}: {rtt_ms:.1}ms");
                    }
                }
            } else {
                state.pending_uss_pings.remove(&from);
            }
        }

        KadMessage::SearchKeyReq {
            target,
            start_position,
            search_terms,
        } => {
            let search_expr = if search_terms.is_empty() {
                None
            } else {
                match parse_kad_search_expression(&search_terms) {
                    Some(expr) => Some(expr),
                    None => {
                        debug!("Ignoring SearchKeyReq from {from}: invalid restrictive search expression");
                        return;
                    }
                }
            };

            // eMule answers keyword search from the indexed store only.
            // Mixing in local share answers inflated reflection volume vs
            // stock peers; publish_manager indexing already feeds the DHT
            // via PublishKeyReq when we are a responsible node.
            let start = (start_position & 0x7FFF) as usize;
            let page = state
                .dht_store
                .search_keywords_page(&target, start, 200, |_, tags| {
                    search_expr
                        .as_ref()
                        .is_none_or(|expr| matches_search_expr_for_tags(expr, tags))
                });

            if !page.is_empty() {
                let local_id = state.local_id;
                send_kad_search_results(
                    socket,
                    from,
                    state,
                    local_id,
                    target,
                    &page,
                    packet_sender_udp_key,
                )
                .await;
            }
        }

        KadMessage::SearchSourceReq {
            target,
            start_position,
            file_size,
        } => {
            let start = (start_position & 0x7FFF) as usize;
            let page = state
                .dht_store
                .search_sources_page(&target, start, 200, |_, tags| {
                    matches_requested_file_size_tags(tags, file_size)
                });

            // eMule behavior: do not send SearchRes when there are no results.
            if !page.is_empty() {
                let local_id = state.local_id;
                send_kad_search_results(
                    socket,
                    from,
                    state,
                    local_id,
                    target,
                    &page,
                    packet_sender_udp_key,
                )
                .await;
            }
        }

        KadMessage::PublishKeyReq { target, entries } => {
            if state.udp_firewalled {
                // K14: we can't be a reliable DHT storage node while
                // firewalled, but silently dropping publishes makes the
                // publisher retry us forever. Send an explicit reject
                // with load=100 so they mark us "done" and move on.
                let res = KadMessage::PublishRes {
                    target,
                    load: 100,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        None,
                        packet_sender_udp_key,
                    )
                    .await;
                }
                return;
            }
            if !state
                .dht_store
                .is_within_tolerance_for(&target, from_ip_v4(from))
            {
                debug!("PublishKeyReq for {target} rejected - outside tolerance zone");
                let res = KadMessage::PublishRes {
                    target,
                    load: 100,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        None,
                        packet_sender_udp_key,
                    )
                    .await;
                }
            } else {
                // Keyword publishes have no wire client hash; account by a
                // stable (ip,port)-derived publisher id for per-sender caps.
                // The global per-publisher budget is charged to the source
                // address instead, which a port rotation can't shed.
                let sender_kad_id = resolve_keyword_publisher_id(state, from);
                let load = state.dht_store.store_keyword_entries(
                    &target,
                    entries,
                    &sender_kad_id,
                    from_ip_v4(from),
                );
                let res = KadMessage::PublishRes {
                    target,
                    load,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        Some(&sender_kad_id),
                        packet_sender_udp_key,
                    )
                    .await;
                }
            }
        }

        KadMessage::PublishSourceReq {
            target,
            sender_id,
            tags,
        } => {
            if state.udp_firewalled {
                // K14: see PublishKeyReq for the rationale; also emit a
                // reject PublishRes so the publisher stops retrying us.
                let res = KadMessage::PublishRes {
                    target,
                    load: 100,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        Some(&sender_id),
                        packet_sender_udp_key,
                    )
                    .await;
                }
                return;
            }
            // eMule stores the wire client hash as m_uSourceID. Keep IP
            // overwrite / per-IP caps in store_source_entry for anti-Sybil.
            if !state
                .dht_store
                .is_within_tolerance_for(&target, from_ip_v4(from))
            {
                debug!("PublishSourceReq for {target} rejected - outside tolerance zone");
                let res = KadMessage::PublishRes {
                    target,
                    load: 100,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        Some(&sender_id),
                        packet_sender_udp_key,
                    )
                    .await;
                }
            } else {
                let sender_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let load = state.dht_store.store_source_entry(
                    &target,
                    sender_id,
                    tags,
                    sender_ip,
                    from.port(),
                );
                let res = KadMessage::PublishRes {
                    target,
                    load,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        Some(&sender_id),
                        packet_sender_udp_key,
                    )
                    .await;
                }
            }
        }

        KadMessage::PublishNotesReq {
            target,
            sender_id,
            ref tags,
        } => {
            if state.udp_firewalled {
                // K14: emit a reject PublishRes so the publisher stops.
                let res = KadMessage::PublishRes {
                    target,
                    load: 100,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        Some(&sender_id),
                        packet_sender_udp_key,
                    )
                    .await;
                }
                return;
            }
            // eMule: wire source id + SEARCHTOLERANCE or LAN.
            // Tolerance check FIRST: if we're not responsible for this hash we
            // must not absorb the comment into our local view either. Letting
            // peers dump arbitrary per-hash comments into our UI without the
            // tolerance gate makes us a spam/comment-poisoning amplifier.
            if !state
                .dht_store
                .is_within_tolerance_for(&target, from_ip_v4(from))
            {
                let res = KadMessage::PublishRes {
                    target,
                    load: 100,
                    request_ack: false,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        Some(&sender_id),
                        packet_sender_udp_key,
                    )
                    .await;
                }
                return;
            }
            let mut note_rating = 0u8;
            let mut note_comment = String::new();
            for tag in tags {
                match &tag.name {
                    TagName::Id(TAG_DESCRIPTION) => {
                        if let TagValue::String(s) = &tag.value {
                            note_comment = s.clone();
                        }
                    }
                    TagName::Id(TAG_FILERATING) => {
                        if let Some(r) = kad_tag_file_rating(tag) {
                            note_rating = r;
                        }
                    }
                    _ => {}
                }
            }
            // Same treatment the KAD search-result path gives a remote
            // TAG_DESCRIPTION: `add_peer_comment` caps length but filters no
            // characters, so controls and bidi overrides would otherwise reach
            // the comment UI verbatim. Sanitized before the emptiness test so a
            // comment that is nothing but formatting characters is not stored
            // as a blank one.
            note_comment = crate::security::sanitize_remote_text(&note_comment, 4096);
            let tags_owned = tags.clone();
            let load = state
                .dht_store
                .store_notes_entry(&target, sender_id, tags_owned);
            // Storing for the DHT is our duty as a node near `target`; showing
            // the note in our own comment UI is not. Only files we share or are
            // downloading have a comment view, and only a note the DHT store
            // actually kept has passed its per-file and byte caps — anything
            // else here let any peer fill the comment store for the session.
            let stored = !state
                .dht_store
                .search_notes_page(&target, 0, 1, |id, _| *id == sender_id)
                .is_empty();
            if stored && (note_rating > 0 || !note_comment.is_empty()) {
                if let Some(source_ip) = from_ip_v4(from) {
                    let hash_hex = hex::encode(kad_id_to_md4_bytes(&target));
                    let shared = local_index.read().await.get_by_hash(&hash_hex).is_some();
                    let relevant = shared || {
                        let mgr = transfer_manager.read().await;
                        mgr.active.values().chain(mgr.queue.iter()).any(|t| {
                            t.direction == TransferDirection::Download
                                && t.file_hash.eq_ignore_ascii_case(&hash_hex)
                        })
                    };
                    if relevant {
                        use ed2k::comments::rating_name;
                        debug!(
                            "Received peer note for {}: rating={} ({})",
                            hash_hex,
                            note_rating,
                            rating_name(note_rating)
                        );
                        state.comment_manager.write().await.add_kad_note(
                            &hash_hex,
                            source_ip,
                            sender_id.to_hex(),
                            note_rating,
                            note_comment,
                        );
                    }
                }
            }
            let res = KadMessage::PublishRes {
                target,
                load,
                request_ack: false,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = send_kad_response(
                    socket,
                    &packet,
                    from,
                    state,
                    Some(&sender_id),
                    packet_sender_udp_key,
                )
                .await;
            }
        }

        KadMessage::SearchNotesReq { target, file_size } => {
            let results = state
                .dht_store
                .search_notes_page(&target, 0, 200, |_, tags| {
                    matches_requested_file_size_tags(tags, file_size)
                });
            // eMule behavior: do not send SearchRes when there are no results.
            if !results.is_empty() {
                let local_id = state.local_id;
                send_kad_search_results(
                    socket,
                    from,
                    state,
                    local_id,
                    target,
                    &results,
                    packet_sender_udp_key,
                )
                .await;
            }
        }

        KadMessage::PublishResAck => {
            state.stats.stores_acknowledged += 1;
            debug!(
                "PublishResAck from {from} (total stores acked: {})",
                state.stats.stores_acknowledged
            );
        }

        KadMessage::FirewalledReq {
            tcp_port: peer_tcp_port,
        } => {
            // Return the requester's external IP as we see it
            let peer_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            // Modern obfuscated requests prove receiver-key context. Plain
            // legacy eMule probes remain interoperable when they come from a
            // live, verified routing-table contact.
            let verified_contact = state
                .routing_table
                .all_contacts()
                .any(|contact| contact.ip == peer_ip && contact.verified && !contact.is_dead());
            // Under response-budget stress, require modern receiver-key proof so
            // spoofed UDP from verified contacts cannot burn the remaining budget.
            let under_load = state.firewall_req_response_bucket.available_tokens() < 8.0;
            if !packet_valid_receiver_key && (under_load || !verified_contact) {
                debug!("Ignoring unverified FirewalledReq context from {from}");
                return;
            }
            if !state.firewall_req_response_bucket.try_take() {
                debug!("Dropping FirewalledReq from {from}: global response budget exhausted");
                return;
            }
            let ip_raw = u32::from_be_bytes(peer_ip.octets());
            let res = KadMessage::FirewalledRes { ip: ip_raw };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ =
                    send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key)
                        .await;
            }

            // K18: per-IP cooldown for the (expensive) TCP connect-back.
            // 60s is generous vs. eMule's 1-hour self-recheck cadence.
            // Also reject special-use / port-0 / port-53 destinations
            // so the connect-back path can't be abused as a reflective
            // TCP probe at arbitrary private hosts or DNS resolvers.
            if peer_tcp_port == 0
                || peer_tcp_port == 53
                || crate::security::is_special_use_v4(peer_ip)
            {
                return;
            }
            let now = chrono::Utc::now().timestamp();
            if !admit_firewall_request_ip(&mut state.firewall_req_cooldown, peer_ip, now) {
                debug!(
                    "Skipping FirewalledReq connect-back to {peer_ip}: cooldown/map cap reached"
                );
                return;
            }
            if !state.firewall_req_connect_bucket.try_take() {
                debug!("Skipping FirewalledReq connect-back: global connect budget exhausted");
                return;
            }

            if let Ok(permit) = state.firewall_connect_semaphore.clone().try_acquire_owned() {
                let tcp_addr = SocketAddr::new(peer_ip.into(), peer_tcp_port);
                let hello = fw_check_hello(state, &settings.nickname);
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::net::TcpStream::connect(tcp_addr),
                    )
                    .await;
                    match result {
                        Ok(Ok(stream)) => {
                            debug!("Peer {tcp_addr} is reachable on TCP");
                            let (r, w) = stream.into_split();
                            let mut reader = tokio::io::BufReader::new(r);
                            let mut writer = tokio::io::BufWriter::new(w);
                            if let Err(e) =
                                send_fw_tcp_check_ack(&mut reader, &mut writer, &hello).await
                            {
                                debug!("Failed sending OP_KAD_FWTCPCHECK_ACK to {tcp_addr}: {e}");
                            }
                        }
                        _ => debug!("Peer {tcp_addr} is NOT reachable on TCP"),
                    }
                });
            } else {
                debug!("Skipping FirewalledReq connect-back: all connect slots busy");
            }
        }

        KadMessage::FirewalledRes { ip } => {
            let sender_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            if !state.firewall_checker.is_firewall_check_ip(sender_ip) {
                tracing::debug!("Ignoring unrequested FirewalledRes from {from}");
                return;
            }
            let external_ip = Ipv4Addr::from(ip.to_be_bytes());
            // Each firewall check dispatches probes to several peers and
            // we routinely get 4-6 confirming responses in a tight burst.
            // Per-vote info logs were just N copies of the same line at
            // INFO. Detail stays at debug; mismatches and confirmations
            // are surfaced separately below (the "External IP changed"
            // log fires once per actual change, and a disagreement
            // between this report and our already-confirmed IP
            // promotes back to info because that *is* worth knowing).
            if state.external_ip == Some(external_ip) {
                debug!("FirewalledRes from {sender_ip}: confirms our IP {external_ip}");
            } else if let Some(known) = state.external_ip {
                info!(
                    "FirewalledRes from {sender_ip}: reports our IP as {external_ip} (differs from confirmed {known})",
                );
            } else {
                debug!("FirewalledRes from {sender_ip}: reports our IP as {external_ip} (no confirmed IP yet)");
            }
            // K7: pass the reporter IP so the firewall checker can count
            // distinct /24 networks instead of raw vote counts.
            state
                .firewall_checker
                .handle_firewalled_response(external_ip, sender_ip);

            // K8: only write state.external_ip once the firewall checker
            // has confirmed it (≥3 distinct /24 voters). The prior
            // "tentative" path let a single report write the global
            // external_ip, which propagates through credits, friend
            // payloads, logs — a Sybil-trivial vector. Downstream code
            // that needs a best-effort IP can still read
            // `firewall_checker.tentative_ip()` (see below) without
            // mutating shared state.
            let prev_ip = state.external_ip;
            if state.external_ip.is_none() {
                if let Some(confirmed) = state.firewall_checker.external_ip() {
                    set_external_ip(state, Some(confirmed));
                    state.stats.external_ip = confirmed.to_string();
                    if prev_ip != Some(confirmed) {
                        info!(
                            "External IP changed: {:?} -> {} (KAD confirmed, {} votes)",
                            prev_ip,
                            confirmed,
                            state.firewall_checker.ip_vote_count()
                        );
                    }
                }
            }

            if prev_ip.is_none()
                && state.external_ip.is_some()
                && state.nat_info.nat_type == ember::nat::NatType::Unknown
            {
                info!(
                    "External IP discovered via KAD; NAT probe will be scheduled by the main UDP loop"
                );
            }

            if state.external_ip.is_some() {
                // Sync before emit so a FirewalledRes that arrives after TCP
                // connect-backs already proved Open doesn't push a stale
                // stats.tcp_status string (often still "Unknown") to the UI.
                state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
                state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
                let _ = app_handle.emit(
                    "firewall-status",
                    serde_json::json!({
                        "firewalled": state.firewalled,
                        "external_ip": state.stats.external_ip,
                        "tcp_status": state.stats.tcp_status,
                        "udp_status": state.stats.udp_status,
                    }),
                );
            }
        }

        KadMessage::Firewalled2Req {
            tcp_port: peer_tcp_port,
            user_hash,
            connect_options,
        } => {
            let requester_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            let verified_contact = state.routing_table.all_contacts().any(|contact| {
                contact.ip == requester_ip && contact.verified && !contact.is_dead()
            });
            let under_load = state.firewall_req_response_bucket.available_tokens() < 8.0;
            if !packet_valid_receiver_key && (under_load || !verified_contact) {
                debug!("Ignoring unverified Firewalled2Req context from {from}");
                return;
            }
            if !state.firewall_req_response_bucket.try_take() {
                debug!("Dropping Firewalled2Req from {from}: global response budget exhausted");
                return;
            }
            let ip_raw = u32::from_be_bytes(requester_ip.octets());
            let res = KadMessage::FirewalledRes { ip: ip_raw };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ =
                    send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key)
                        .await;
            }

            // Same connect-back guards as KADEMLIA_FIREWALLED_REQ (v1): the TCP
            // connect-back is expensive and otherwise abusable as a reflective
            // probe, so reject port 0/53 and special-use destinations and
            // rate-limit per requester IP (shared cooldown map) before
            // spending a connection on it.
            if peer_tcp_port == 0
                || peer_tcp_port == 53
                || crate::security::is_special_use_v4(requester_ip)
            {
                return;
            }
            let now = chrono::Utc::now().timestamp();
            if !admit_firewall_request_ip(&mut state.firewall_req_cooldown, requester_ip, now) {
                debug!(
                    "Skipping Firewalled2 connect-back to {requester_ip}: cooldown/map cap reached"
                );
                return;
            }
            if !state.firewall_req_connect_bucket.try_take() {
                debug!("Skipping Firewalled2 connect-back: global connect budget exhausted");
                return;
            }

            if let Ok(permit) = state.firewall_connect_semaphore.clone().try_acquire_owned() {
                let tcp_addr = SocketAddr::new(requester_ip.into(), peer_tcp_port);
                let allow_obf = state.obfuscation_enabled && (connect_options & 0x01) != 0;
                let hello = fw_check_hello(state, &settings.nickname);
                tokio::spawn(async move {
                    let _permit = permit;
                    let connect_result = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::net::TcpStream::connect(tcp_addr),
                    )
                    .await;
                    match connect_result {
                        Ok(Ok(stream)) => {
                            debug!("Peer {tcp_addr} is reachable on TCP (Firewalled2)");
                            let (r, w) = stream.into_split();
                            let mut reader = tokio::io::BufReader::new(r);
                            let mut writer = tokio::io::BufWriter::new(w);
                            let write_res = if allow_obf && user_hash != [0u8; 16] {
                                match ed2k::tcp_obfuscation::negotiate_outgoing(
                                    &mut reader,
                                    &mut writer,
                                    &user_hash,
                                )
                                .await
                                {
                                    Ok((recv_key, send_key)) => {
                                        let mut obf_reader = tokio::io::BufReader::new(
                                            ed2k::tcp_obfuscation::Rc4Reader::new(reader, recv_key),
                                        );
                                        let mut obf_writer = tokio::io::BufWriter::new(
                                            ed2k::tcp_obfuscation::Rc4Writer::new(writer, send_key),
                                        );
                                        send_fw_tcp_check_ack(&mut obf_reader, &mut obf_writer, &hello)
                                            .await
                                    }
                                    Err(e) if (connect_options & 0x04) != 0 => Err(e),
                                    Err(_) => {
                                        drop(writer);
                                        drop(reader);
                                        match tokio::time::timeout(
                                            std::time::Duration::from_secs(5),
                                            tokio::net::TcpStream::connect(tcp_addr),
                                        )
                                        .await
                                        {
                                            Ok(Ok(plain_stream)) => {
                                                let (pr, pw) = plain_stream.into_split();
                                                let mut pr = tokio::io::BufReader::new(pr);
                                                let mut pw = tokio::io::BufWriter::new(pw);
                                                send_fw_tcp_check_ack(&mut pr, &mut pw, &hello).await
                                            }
                                            Ok(Err(e)) => Err(e),
                                            Err(_) => Err(std::io::Error::new(
                                                std::io::ErrorKind::TimedOut,
                                                "plain fallback connect timeout",
                                            )),
                                        }
                                    }
                                }
                            } else {
                                send_fw_tcp_check_ack(&mut reader, &mut writer, &hello).await
                            };
                            if let Err(e) = write_res {
                                debug!("Failed sending OP_KAD_FWTCPCHECK_ACK to {tcp_addr}: {e}");
                            }
                        }
                        _ => {
                            debug!("Peer {tcp_addr} is NOT reachable on TCP (Firewalled2)");
                        }
                    }
                });
            } else {
                debug!("Skipping Firewalled2 connect-back: all connect slots busy");
            }
        }

        KadMessage::FirewallUdp {
            error_code,
            udp_port,
        } => {
            debug!("FirewallUdp from {from}: error={error_code}, port={udp_port}");
            let sender_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            if !state.firewall_checker.is_checking() {
                debug!("Ignoring late FirewallUdp from {from}: no active firewall check");
                return;
            }
            if !state.firewall_checker.is_udp_firewall_check_ip(sender_ip) {
                debug!("Ignoring unsolicited FirewallUdp from {from}");
                return;
            }
            let expected_internal = state.udp_port;
            let expected_external = state
                .firewall_checker
                .external_udp_port()
                .or(state.external_udp_port)
                .unwrap_or(0);
            if udp_port == 0 || (udp_port != expected_internal && udp_port != expected_external) {
                debug!(
                    "Ignoring FirewallUdp from {from}: unexpected incoming port {} (internal={}, external={})",
                    udp_port, expected_internal, expected_external
                );
                return;
            }
            if error_code == 0 {
                // Multiple peers may answer the same UDP firewall probe
                // (we dispatch ~4 per cycle and need only one to declare
                // the port reachable). Capture the prior verified state
                // so we only emit the "passed" log on the *first*
                // confirming response — subsequent confirmations from
                // other peers are redundant for the user.
                let was_already_verified = state.udp_fw_verified;
                state.firewall_checker.handle_udp_firewall_result(true);
                state.udp_firewalled = false;
                state.udp_fw_verified = true;
                kad::firewall::publish_local_firewall(state.firewalled, state.udp_firewalled);
                state.stats.firewalled = state.firewalled;
                if udp_port > 0
                    && !stun_udp_mapping_active(state)
                    && state.external_udp_port != Some(udp_port)
                {
                    state.external_udp_port = Some(udp_port);
                }
                // Type-6 source publish keys off `udp_fw_verified`, not the
                // port changing. Skipping this when the port was already known
                // (STUN, a prior probe, settings) left LowID+UDP-open clients
                // with firewalled=true, no buddy, and no callback — so every
                // source publish returned None until the next firewall evaluate.
                update_publish_manager_state(state);
                state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
                state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
                let _ = app_handle.emit(
                    "firewall-status",
                    serde_json::json!({
                        "firewalled": state.firewalled,
                        "external_ip": state.stats.external_ip,
                        "tcp_status": state.stats.tcp_status,
                        "udp_status": state.stats.udp_status,
                    }),
                );
                if !was_already_verified {
                    info!("UDP firewall test passed - UDP port {udp_port} is reachable, not UDP-firewalled");
                } else {
                    debug!(
                        "UDP firewall test: additional confirmation on port {udp_port} from {from}"
                    );
                }
            } else {
                state.firewall_checker.handle_udp_firewall_result(false);
                info!("UDP firewall test returned remote error from {from} on port {udp_port} (error={error_code})");
            }
        }

        KadMessage::FindBuddyReq {
            buddy_id,
            user_id,
            tcp_port: peer_tcp_port,
        } => {
            debug!("FindBuddyReq from {from}: buddy_id={buddy_id}, user_id={user_id}");
            if !state.firewalled
                && !state.udp_firewalled
                && state.udp_fw_verified
                && !state.buddy_manager.is_serving()
            {
                let res = KadMessage::FindBuddyRes {
                    buddy_id,
                    user_hash: state.user_hash,
                    tcp_port: advertised_tcp_port(state),
                    connect_options: build_kad_connect_options(state),
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(
                        socket,
                        &packet,
                        from,
                        state,
                        None,
                        packet_sender_udp_key,
                    )
                    .await;
                }
                info!(
                    "Offered to be buddy for {user_id} (tcp_port={})",
                    peer_tcp_port
                );

                // Register this user's hash so the upload listener recognizes the incoming
                // buddy TCP connection (the firewalled client will connect to us).
                state
                    .buddy_manager
                    .register_pending_buddy(cuint128_swap(&user_id.0), buddy_id)
                    .await;
            }
        }

        KadMessage::FindBuddyRes {
            buddy_id,
            user_hash,
            tcp_port: peer_tcp_port,
            connect_options,
        } => {
            info!("FindBuddyRes from {from}: buddy_id={buddy_id}, tcp_port={peer_tcp_port}, connect_options=0x{connect_options:02X}");
            let search_expected_target = state
                .search_manager
                .active
                .values()
                .find(|s| matches!(s.search_type, SearchType::FindBuddy) && !s.completed)
                .map(|s| s.target);
            // FindBuddy searches are removed right after convergence and request dispatch,
            // so responses often arrive when there is no active search entry anymore.
            // In that case, accept responses matching our deterministic local buddy target.
            let expected_buddy_target = if search_expected_target.is_some() {
                search_expected_target
            } else if state.buddy_manager.state() == BuddyState::FindingBuddy {
                Some(state.buddy_manager.find_buddy_target())
            } else {
                None
            };
            if expected_buddy_target != Some(buddy_id) {
                debug!(
                    "Ignoring FindBuddyRes from {from}: unexpected buddy target {} (expected {:?})",
                    buddy_id, expected_buddy_target
                );
                return;
            }
            if peer_tcp_port == 0 {
                debug!("Ignoring FindBuddyRes from {from}: missing TCP port");
                return;
            }
            if state.buddy_manager.state() == BuddyState::FindingBuddy
                && state.pending_outgoing_buddy.is_none()
            {
                let buddy_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                // eMule's `Process_KADEMLIA_FINDBUDDY_RES` takes the buddy's
                // Kad UDP port from the datagram it arrived on, and nothing
                // later in the handshake carries it. Capture it here or lose it.
                let buddy_udp_port = from.port();
                let allow_obfuscation = settings.obfuscation_enabled;
                let mut mgr_clone = BuddyManager::new(
                    *state.buddy_manager.local_id(),
                    state.user_hash,
                    settings.nickname.clone(),
                    advertised_tcp_port(state),
                    advertised_udp_port(state),
                    state.pending_buddy_hashes.clone(),
                );
                state.pending_outgoing_buddy = Some(tokio::spawn(async move {
                    mgr_clone
                        .handle_findbuddy_response(
                            buddy_id,
                            buddy_ip,
                            peer_tcp_port,
                            buddy_udp_port,
                            user_hash,
                            connect_options,
                            allow_obfuscation,
                        )
                        .await
                }));
            }
        }

        KadMessage::CallbackReq {
            buddy_id,
            file_id,
            tcp_port: peer_tcp_port,
        } => {
            debug!("CallbackReq from {from}: buddy_id={buddy_id}, file_id={file_id}");
            // eMule Process_KADEMLIA_CALLBACK_REQ relays whenever we have a
            // serving buddy client; it does not verify the check token
            // (see the JOHNTODO in eMule's source).
            if state.buddy_manager.is_serving() {
                let client_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let relayed = state
                    .buddy_manager
                    .send_callback_relay(&buddy_id, client_ip, peer_tcp_port, file_id.0);
                if relayed {
                    debug!("Callback relayed via OP_CALLBACK to buddy");
                } else {
                    debug!("Failed to relay callback to buddy");
                }
            }
        }

        KadMessage::FirewalledAckRes => {
            debug!("FirewalledAckRes from {from} (peer acknowledged our firewall check response)");
        }

        KadMessage::IgnoredLegacy { opcode } => {
            // Match eMule behavior: silently ignore deprecated Kad1 opcodes.
            debug!("Ignoring deprecated Kad1 opcode 0x{opcode:02X} from {from}");
        }
    }
}

#[cfg(test)]
mod udp_reask_cache_tests {
    use super::*;

    fn unique_id(label: &str) -> String {
        format!("udp-reask-{label}-{}", rand::random::<u64>())
    }

    #[test]
    fn udp_reask_cache_serves_only_entries_built_at_the_current_epoch() {
        let id = unique_id("epoch");
        assert!(matches!(cached_reask_parts(&id, 100), CachedReaskParts::Unknown));

        // Other tests bump the process-wide epoch concurrently; retry until one
        // round runs without a bump in the middle.
        let (epoch, lookup) = loop {
            let epoch = ed2k::part_tracker::verification_epoch();
            remember_reask_parts(&id, 100, epoch, Some(&[true, false]));
            let lookup = cached_reask_parts(&id, 100);
            if ed2k::part_tracker::verification_epoch() == epoch {
                break (epoch, lookup);
            }
        };
        match lookup {
            CachedReaskParts::Fresh(Some(parts)) => assert_eq!(parts, vec![true, false]),
            _ => panic!("an entry built at the current epoch must be served"),
        }
        assert!(
            matches!(cached_reask_parts(&id, 101), CachedReaskParts::Unknown),
            "a size mismatch is not the same download"
        );

        remember_reask_parts(&id, 100, epoch.wrapping_sub(1), Some(&[true, true]));
        assert!(
            matches!(cached_reask_parts(&id, 100), CachedReaskParts::Unknown),
            "a bitmap from another epoch may still claim parts since un-verified"
        );
    }

    #[tokio::test]
    async fn udp_reask_refresh_runs_off_the_caller_and_records_a_missing_part() {
        let id = unique_id("missing");
        let part_path = std::env::temp_dir().join(format!("{id}.part"));
        spawn_reask_parts_refresh(id.clone(), 100, part_path.clone());
        // A second request while one is in flight must not queue another read.
        spawn_reask_parts_refresh(id.clone(), 100, part_path);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match cached_reask_parts(&id, 100) {
                CachedReaskParts::Fresh(None) => break,
                CachedReaskParts::Unknown => {
                    assert!(std::time::Instant::now() < deadline, "refresh never landed");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    // A concurrent epoch bump invalidates a landed entry.
                    spawn_reask_parts_refresh(
                        id.clone(),
                        100,
                        std::env::temp_dir().join(format!("{id}.part")),
                    );
                }
                _ => panic!("a download with no .part must cache as absent"),
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while reask_parts_cache().lock().refreshing.contains(&id) {
            assert!(std::time::Instant::now() < deadline, "in-flight marker never cleared");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod direct_callback_gate_tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn requester(n: u32) -> Ipv4Addr {
        Ipv4Addr::from(0x0A00_0000 | n)
    }

    #[test]
    fn one_callback_per_requester_per_interval() {
        let mut gate = DirectCallbackGate::default();
        let mut accepted = HashMap::new();
        let t0 = Instant::now();
        assert!(gate.admit(&mut accepted, requester(1), t0));
        assert!(!gate.admit(&mut accepted, requester(1), t0 + Duration::from_secs(179)));
        assert!(gate.admit(&mut accepted, requester(1), t0 + DIRECT_CALLBACK_MIN_INTERVAL));
        assert_eq!(accepted.len(), 1);
        assert_eq!(gate.order.len(), 1, "the lapsed entry left from the front");
    }

    /// Spoofed sources each look new, so only the global ceiling holds them.
    #[test]
    fn spoofed_requesters_are_held_to_the_global_rate() {
        let mut gate = DirectCallbackGate::default();
        let mut accepted = HashMap::new();
        let t0 = Instant::now();
        let admitted = (0..100)
            .filter(|n| gate.admit(&mut accepted, requester(*n), t0))
            .count();
        assert_eq!(admitted, MAX_DIRECT_CALLBACKS_PER_SEC as usize);
        assert!(gate.admit(&mut accepted, requester(500), t0 + Duration::from_secs(1)));
        let most_live = u64::from(MAX_DIRECT_CALLBACKS_PER_SEC) * DIRECT_CALLBACK_MIN_INTERVAL.as_secs();
        assert!(
            most_live < MAX_DIRECT_CALLBACK_REQUESTERS as u64,
            "the rate alone must keep the per-IP table from filling"
        );
    }
}
