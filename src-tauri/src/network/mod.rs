pub mod ed2k;
pub mod kad;
pub mod ember;
pub mod rendezvous;
pub mod upnp;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};
use tauri::{Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, RwLock};
use futures::FutureExt;
use tracing::{debug, error, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::search::index::LocalIndex;
use crate::sharing::manager::{TransferControl, TransferHealthUpdate, TransferManager};
use crate::storage::database::Database;
use crate::types::*;

use self::ed2k::a4af::A4AFManager;
use self::ed2k::comments::CommentManager;
use self::ed2k::credits::CreditManager;
use self::ed2k::corruption_blackbox::CorruptionBlackBox;
use self::ed2k::dead_sources::DeadSourceList;
use self::ed2k::server::{Ed2kServerConnection, ServerSession};
use self::ed2k::server_list::{ServerEntry, ServerList};
use self::ed2k::server_udp::{ServerUdpSocket, ServerUdpResponse};
use self::ed2k::sources::SourceManager;
use self::ed2k::upload::{self as upload_server, UploadEvent, UploadEventKind};
use self::ed2k::multi_source::{DownloadSource, MultiSourceDownload, SharedTrackerRegistry};
use self::ed2k::transfer::{classify_error, DownloadEvent, Ed2kDownload, SourceFailureKind};
use self::kad::bootstrap;
use self::kad::buddy::{BuddyManager, BuddyState, BuddyEvent, BuddyWriteStream, PendingBuddySet};
use self::kad::firewall::FirewallChecker;
use self::kad::ip_filter::{IpFilter, IpFilterStats};
use self::kad::messages::{self, KadMessage, KADEMLIA_FIND_NODE};
use self::ed2k::messages::{OP_EDONKEYHEADER, OP_EMULEPROT, OP_PORTTEST};
use self::kad::obfuscation;
use self::kad::protection::FloodProtection;
use self::kad::publish::{PublishManager, PublishableFile, md4_bytes_to_kad_id, kad_id_to_md4_bytes};
use self::kad::routing::RoutingTable;
use self::kad::search::{SearchId, SearchManager, SearchPhase, SearchType, SEARCH_INITIAL_CONTACTS};
use self::kad::store::DhtStore;
use self::kad::types::*;

use crate::storage::known_files::KnownFileList;
use crate::storage::statistics::{StatsManager, TransferStats};

struct ServerConnectResult {
    addr: SocketAddr,
    ip: String,
    port: u16,
    result: Result<(Ed2kServerConnection, ServerSession), String>,
}

/// Try to connect to a server, attempting the DH-encrypted connection first (for HighID),
/// then falling back to plain text (for LowID).
///
/// Many servers use the same port for both plain and obfuscated connections (the server
/// detects the mode from the first byte). If no dedicated obfuscation port is known,
/// we try DH on the regular port first.
fn emit_server_log(app: &tauri::AppHandle, message: &str) {
    let _ = app.emit("server-log", serde_json::json!({ "message": message }));
}

#[derive(Debug, Default)]
struct ActiveSourceInjectionStats {
    matched_transfers: usize,
    injected: usize,
    persisted: usize,
    dropped_full: usize,
    dropped_closed: usize,
    overflowed: usize,
}

/// Snapshot of the publish-ack diagnostic counters at a given time.
/// Used by the `publish_health_timer` arm to print **deltas** since
/// the last beat instead of monotonic totals — without this the
/// numbers look identical heartbeat after heartbeat once the system
/// has been running a while, and you can't tell whether the pipeline
/// is currently flowing or stuck.
#[derive(Debug, Default, Clone, Copy)]
struct PublishHealthSnapshot {
    confirmed: u32,
    pending: usize,
    plain_seen: u64,
    obf_decoded: u64,
    obf_total: u64,
    wire: u64,
    received: u64,
    unmatched: u64,
}

/// Snapshot of the UDP source-discovery diagnostic counters at a given
/// time. Same delta-style logging pattern as `PublishHealthSnapshot`:
/// the heartbeat arm only fires the log line when at least one counter
/// moved since the last beat. Lets the user verify "is UDP source
/// discovery happening at all" without flipping to debug logging.
#[derive(Debug, Default, Clone, Copy)]
struct UdpDiscoveryHealthSnapshot {
    sent: u64,
    send_errs: u64,
    replies: u64,
    sources_found: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceInjectionResult {
    Injected,
    Full,
    Closed,
}

fn matching_active_transfer_ids_for_hash(
    state: &NetworkState,
    transfer_manager: &TransferManager,
    file_hash_hex: &str,
) -> Vec<String> {
    state
        .active_source_senders
        .iter()
        .filter_map(|(tid, _)| {
            transfer_manager
                .get_transfer(tid)
                .filter(|transfer| transfer.file_hash == file_hash_hex)
                .map(|_| tid.clone())
        })
        .collect()
}

/// How long an Ember peer entry is considered fresh in `known_ember_peers`
/// before `prune_stale_ember_peers` evicts it. 24h gives enough headroom
/// that a peer who briefly went offline (NAT renewal, brief uptime gap)
/// is still in the mesh on their next visit, while keeping advertisements
/// from being polluted with weeks-old dead addresses.
const KNOWN_EMBER_PEER_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Hard cap on `known_ember_peers` size. Set to 10x `MAX_EPX_PEERS` so
/// rebuilds have a diverse pool to rotate from while still keeping
/// per-session memory bounded (≈12 KB worst case).
const MAX_KNOWN_EMBER_PEERS: usize = 500;

/// Insert or refresh an Ember peer in `known_ember_peers`. Returns true
/// when this is the first time we've seen the address (caller uses that
/// signal to mark `ember_payload_dirty`). When the map is at capacity
/// and we're inserting a brand-new entry, the oldest existing entry is
/// evicted to make room — matches the LRU-by-timestamp policy that the
/// pruner enforces against TTL.
fn record_known_ember_peer(
    map: &mut HashMap<(Ipv4Addr, u16), std::time::Instant>,
    ip: Ipv4Addr,
    port: u16,
) -> bool {
    let now = std::time::Instant::now();
    let key = (ip, port);
    if let Some(slot) = map.get_mut(&key) {
        *slot = now;
        return false;
    }
    if map.len() >= MAX_KNOWN_EMBER_PEERS {
        if let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, ts)| *ts)
            .map(|(k, _)| *k)
        {
            map.remove(&oldest_key);
        }
    }
    map.insert(key, now);
    true
}

/// Drop entries older than `KNOWN_EMBER_PEER_TTL`. Called lazily before
/// the EPX rebuild iterates the map so we never advertise a peer we
/// haven't heard about in a day.
fn prune_stale_ember_peers(map: &mut HashMap<(Ipv4Addr, u16), std::time::Instant>) {
    let now = std::time::Instant::now();
    map.retain(|_, ts| now.duration_since(*ts) < KNOWN_EMBER_PEER_TTL);
}

/// Shared EPX source injection logic used by both DownloadEvent::EmberSources
/// and UploadEventKind::EmberSources handlers.
async fn handle_epx_sources(
    state: &mut NetworkState,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    entries: &[([u8; 16], Vec<(Ipv4Addr, u16, u16, u8)>)],
    aich_roots: &[([u8; 16], [u8; 20])],
    ember_peers: &[(Ipv4Addr, u16)],
    label: &str,
) -> usize {
    let mut total_injected = 0usize;
    let mut total_sources_this_event = 0usize;
    let mut per_hash_persisted: HashMap<String, u32> = HashMap::new();

    for (file_hash, sources) in entries {
        let matching_ids = {
            let mgr = transfer_manager.read().await;
            let hash_hex = hex::encode(file_hash);
            matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex)
        };
        if matching_ids.is_empty() {
            continue;
        }
        for &(ip, port, udp_port, flags) in sources {
            if total_sources_this_event >= ember::MAX_EPX_TOTAL_SOURCES {
                break;
            }
            // Collect relay-capable peers for LowID-to-LowID broker
            if flags & ember::SOURCE_FLAG_RELAY_CAPABLE != 0 {
                if let Some(ref mut broker) = state.connection_broker {
                    broker.add_relay_candidate(ip, port);
                }
            }
            if flags & ember::SOURCE_FLAG_FIREWALLED != 0 && (state.firewalled || state.low_id) {
                continue;
            }
            if state.dead_sources.is_dead_source_for_file(file_hash, u32::from(ip), port) {
                continue;
            }
            if crate::security::is_special_use_v4(ip) || ip.is_multicast() {
                continue;
            }
            if state.banned_ips.contains(&ip) {
                continue;
            }
            let (peer_user_hash, peer_connect_options) = {
                let sm = source_manager.read().await;
                let uh = sm.get_user_hash(file_hash, ip, port);
                let co = sm.get_connect_options(file_hash, ip, port);
                if uh.is_some() || co.is_some() {
                    (uh, co)
                } else if flags & ember::SOURCE_FLAG_OBFUSCATION != 0 {
                    (None, Some(0x02))
                } else {
                    (None, None)
                }
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
            total_sources_this_event += 1;
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
        let matches_trusted = state.aich_hash_sets.iter().any(|hs| hs.root_hash == *aich_root);
        if matches_trusted {
            state.aich_root_map.insert(*file_hash, *aich_root);
            tracing::debug!(
                "EPX: pinned AICH root {} for file {} (matches known hashset)",
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
        if crate::security::is_special_use_v4(ip) {
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

    if total_injected > 0 {
        state.stats.epx_sources_received = state.stats.epx_sources_received.saturating_add(total_injected as u32);
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

fn try_inject_source(
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

const MAX_ACTIVE_SOURCE_OVERFLOW: usize = 128;
const MAX_UDP_SOURCE_QUEUE: usize = 500;

fn enqueue_overflow_source(
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

fn drain_active_source_overflow(
    state: &mut NetworkState,
) -> Vec<(String, usize, usize)> {
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
            state.download_source_searches.retain(|_, (tid, _)| tid != &transfer_id);
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

fn pending_download_retry_interval(search_count: u32) -> i64 {
    match search_count {
        0 => 0,
        1 => 5,
        2 => 10,
        3..=5 => 20,
        6..=10 => 60,
        11..=20 => 180,
        _ => 300,
    }
}

/// KAD re-search interval for active downloads that already have sources.
/// More relaxed than `pending_download_retry_interval` since these downloads
/// are already transferring — we're just looking for additional sources.
/// eMule uses KADEMLIAREASKTIME (1 hour) * m_TotalSearchesKad (up to 7).
fn active_download_kad_interval(search_count: u32) -> i64 {
    match search_count {
        0 => 15,
        1 => 30,
        2 => 60,
        3..=5 => 300,
        6..=10 => 900,
        _ => 3600,
    }
}

// Keep eDonkey UDP source lookups protocol-compatible while adapting fanout
// to runtime conditions so we stay fast without looking like a flooder.
// eMule: GetMaxSourcePerFileUDP() — skip UDP asks once we have enough sources
const MAX_SOURCES_FOR_UDP: usize = 50;

const MAX_FAIL_COUNT_FOR_UDP: u32 = 3;

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
const MAX_UDP_CONSECUTIVE_FAILURES: u32 = 5;

fn is_eligible_udp_server(server: &ed2k::server_list::ServerEntry, connected_addr: Option<SocketAddr>) -> bool {
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

/// Build UDP GETSOURCES packets for ALL eligible servers (single file).
fn build_all_getsources_packets(
    state: &NetworkState,
    file_hash: &[u8; 16],
    file_size: u64,
) -> Vec<(Vec<u8>, SocketAddr)> {
    let servers = state.server_list.servers();
    if servers.is_empty() {
        return Vec::new();
    }

    let mut packets = Vec::with_capacity(servers.len());
    for server in servers {
        if !is_eligible_udp_server(server, state.server_addr) {
            continue;
        }
        if let Some(packet) = ServerUdpSocket::build_get_sources_packet(server, file_hash, file_size) {
            packets.push(packet);
        }
    }
    packets
}

/// Build UDP GETSOURCES packets for ALL eligible servers, packing multiple
/// file hashes per packet (eMule: up to 35 per server, max 510 bytes payload).
/// Used by the periodic sweep when multiple downloads are active.
fn build_all_getsources_packets_multi(
    state: &NetworkState,
    files: &[([u8; 16], u64)],
) -> Vec<(Vec<u8>, SocketAddr)> {
    let servers = state.server_list.servers();
    if servers.is_empty() || files.is_empty() {
        return Vec::new();
    }

    let file_refs: Vec<(&[u8; 16], u64)> = files.iter().map(|(h, s)| (h, *s)).collect();
    let mut packets = Vec::with_capacity(servers.len());
    for server in servers {
        if !is_eligible_udp_server(server, state.server_addr) {
            continue;
        }
        if let Some(packet) = ServerUdpSocket::build_multi_get_sources_packet(server, &file_refs) {
            packets.push(packet);
        }
    }
    packets
}

fn inject_source_into_active_transfers(
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

    // Source-level filtering. The Ember EPX path applies the same
    // checks before calling its own injection helper; doing them here
    // too means the UDP server (`OP_GLOBFOUNDSOURCES`) and KAD source
    // paths inherit them automatically without each site having to
    // duplicate the gate. Order: cheap rejections first.
    //
    // 1. Special-use IPv4 (RFC 5735: loopback, link-local, multicast,
    //    documentation, etc.). These are never reachable peers.
    // 2. IP filter (`ipfilter.dat`). Drops emule-security-blocked
    //    ranges, optionally private IPs, etc.
    // 3. Banned IPs (live runtime banlist).
    // 4. Reputation-banned user hashes (existing check).
    if let Some(v4) = parsed_ip {
        if crate::security::is_special_use_v4(v4) || v4.is_multicast() {
            stats.dropped_full += transfer_ids.len();
            return stats;
        }
        if state.ip_filter.is_blocked(v4) {
            stats.dropped_full += transfer_ids.len();
            return stats;
        }
        if state.banned_ips.contains(&v4) {
            stats.dropped_full += transfer_ids.len();
            return stats;
        }
    }
    if let Some(ref uh) = source.peer_user_hash {
        if state.reputation.is_banned(uh) {
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
                .or_insert_with(|| ed2k::sources::PerFileSourceList::new(file_hash));
            let already_known = pfs.has_source(v4, source.peer_port);
            if already_known {
                false
            } else {
                let added = pfs.add_source_full(v4, source.peer_port, udp_port);
                if added {
                    stats.persisted += 1;
                    state.ember_payload_dirty = true;
                }
                true
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
            SourceInjectionResult::Injected => stats.injected += 1,
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
        state.download_source_searches.retain(|_, (tid, _)| tid != transfer_id);
    }

    let hash_hex = hex::encode(file_hash);
    if stats.injected > 0 {
        info!(
            "Source {}:{} injected into {} transfer(s) for {} (persisted={}, injected={})",
            source.peer_ip, source.peer_port, stats.injected, hash_hex, stats.persisted, stats.injected
        );
    }
    if stats.dropped_full > 0 || stats.dropped_closed > 0 {
        warn!(
            "Source {}:{} for {} had drops: full={}, overflowed={}, closed={} (stale: {:?})",
            source.peer_ip, source.peer_port, hash_hex,
            stats.dropped_full, stats.overflowed, stats.dropped_closed, stale_transfer_ids
        );
    }

    stats
}

async fn try_connect_server(ip: &str, port: u16, obf_port: u16, app: &tauri::AppHandle, force_plain: bool) -> anyhow::Result<(Ed2kServerConnection, SocketAddr)> {
    if !force_plain && obf_port != 0 {
        let obf_addr = tokio::net::lookup_host((ip, obf_port))
            .await?
            .find(|addr| addr.is_ipv4())
            .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {ip}:{obf_port}"))?;
        info!("Trying encrypted DH connection to server {ip}:{obf_port}");
        emit_server_log(app, &format!("Trying encrypted connection to {ip}:{obf_port}..."));
        match Ed2kServerConnection::connect_encrypted(obf_addr).await {
            Ok(conn) => {
                info!("Encrypted DH connection to server {ip}:{obf_port} established");
                emit_server_log(app, "Encrypted connection established");
                return Ok((conn, obf_addr));
            }
            Err(e) => {
                warn!("Encrypted DH connection to server {ip}:{obf_port} failed: {e}, falling back to plain");
                emit_server_log(app, &format!("Encrypted connection failed, trying plain TCP on port {port}..."));
            }
        }
    } else if force_plain {
        info!("Skipping encryption (force_plain) for server {ip}:{port}");
    } else {
        info!("No obfuscation port known for server {ip}:{port}, using plain TCP");
    }
    let addr = tokio::net::lookup_host((ip, port))
        .await?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for {ip}:{port}"))?;
    let conn = Ed2kServerConnection::connect(addr).await?;
    info!("Plain TCP connection to server {ip}:{port} established");
    emit_server_log(app, "TCP connection established");
    Ok((conn, addr))
}

/// Spawn a rendezvous lookup for a single friend and attempt to connect if found.
fn spawn_rendezvous_friend_lookup(
    settings: &AppSettings,
    state: &NetworkState,
    ember_hash: [u8; 16],
    target_hash: [u8; 16],
    _db: &Arc<crate::storage::database::Database>,
    app_handle: &tauri::AppHandle,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ul_event_tx: &mpsc::Sender<upload_server::UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
) {
    // _db is kept in the signature for future authenticated-mutual promotion.
    let rv_url = settings.rendezvous_url.clone();
    let our_uh = state.user_hash;
    let our_eh = ember_hash;
    let nick = settings.nickname.clone();
    let cid = state.external_ip.map(|eip| u32::from_le_bytes(eip.octets())).unwrap_or(0);
    let tcp = settings.tcp_port;
    let udp = settings.udp_port;
    let obfuscate = settings.friend_session_encryption;
    let app_fc = app_handle.clone();
    let fh_fc = friend_hashes.clone();
    let sess_fc = state.ember_sessions.clone();
    let ultx_fc = ul_event_tx.clone();

    tokio::spawn(async move {
        match rendezvous::lookup(&rv_url, &target_hash).await {
            Ok(Some((ip, port))) => {
                info!("Rendezvous found friend {} at {}:{}", hex::encode(target_hash), ip, port);
                let addr = std::net::SocketAddr::new(ip.into(), port);
                match ed2k::friend_connect::connect_and_send_friend_request(
                    addr, &our_uh, &our_eh, &nick, cid, tcp, udp, obfuscate,
                    Some(ed25519_pubkey), Some(ed25519_secret_key),
                ).await {
                    Ok(Some(remote_eh)) => {
                        info!("Rendezvous friend connect to {} succeeded, remote={}", addr, hex::encode(remote_eh));
                        if fh_fc.read().await.contains(&remote_eh) {
                            // Do NOT auto-flip mutual: ember_hash in the remote handshake is
                            // self-reported and unverified (FUTURE_WORK.md F2). User must
                            // accept an inbound friend request before features unlock.
                            let _ = app_fc.emit("ember:friend-confirmed", serde_json::json!({
                                "user_hash": hex::encode(remote_eh),
                            }));
                            let _ = app_fc.emit("ember:friend-online", serde_json::json!({
                                "user_hash": hex::encode(remote_eh),
                            }));
                            if !sess_fc.read().await.contains_key(&remote_eh) {
                                info!("Opening persistent session to {} after rendezvous friend discovery", addr);
                                if let Err(e) = ed2k::friend_connect::open_and_run_friend_session(
                                    addr, our_uh, our_eh, nick,
                                    cid, tcp, udp, obfuscate, sess_fc, ultx_fc.clone(), fh_fc,
                                    Some(ed25519_pubkey), Some(ed25519_secret_key),
                                ).await {
                                    info!("Persistent session to {} failed: {e}", addr);
                                    let _ = ultx_fc.send(upload_server::UploadEvent {
                                        transfer_id: String::new(),
                                        kind: upload_server::UploadEventKind::EmberFriendDisconnected { ember_hash: remote_eh },
                                    }).await;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        info!("Rendezvous friend connect to {} succeeded (no reciprocal)", addr);
                    }
                    Err(e) => {
                        let emsg = format!("{e}");
                        let reason = if emsg.contains("timeout") { "timeout" }
                            else if emsg.contains("refused") { "refused" }
                            else { "error" };
                        info!("Rendezvous friend connect to {} failed: {e}", addr);
                        let _ = app_fc.emit("ember:friend-search-failed", serde_json::json!({
                            "user_hash": hex::encode(target_hash),
                            "reason": reason,
                        }));
                    }
                }
            }
            Ok(None) => {
                info!("Rendezvous lookup: friend {} not found", hex::encode(target_hash));
                let _ = app_fc.emit("ember:friend-search-failed", serde_json::json!({
                    "user_hash": hex::encode(target_hash),
                    "reason": "not_found",
                }));
            }
            Err(e) => {
                warn!("Rendezvous lookup failed for {}: {e}", hex::encode(target_hash));
                let _ = app_fc.emit("ember:friend-search-failed", serde_json::json!({
                    "user_hash": hex::encode(target_hash),
                    "reason": "error",
                }));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::kad::messages::SearchResultEntry;
    use crate::network::kad::types::{KadTag, TagName, TagValue, TAG_DESCRIPTION, TAG_FILENAME, TAG_FILERATING};

    fn sample_download_source() -> DownloadSource {
        DownloadSource {
            peer_ip: "127.0.0.1".to_string(),
            peer_port: 4662,
            available_parts: Vec::new(),
            peer_user_hash: None,
            peer_connect_options: None,
        }
    }

    #[test]
    fn source_injection_reports_full_channel() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(sample_download_source()).unwrap();

        assert_eq!(
            try_inject_source(Some(&tx), &sample_download_source()),
            SourceInjectionResult::Full,
        );
    }

    #[test]
    fn source_injection_reports_closed_channel() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        assert_eq!(
            try_inject_source(Some(&tx), &sample_download_source()),
            SourceInjectionResult::Closed,
        );
    }

    #[test]
    fn record_known_ember_peer_returns_true_for_new_entries() {
        let mut map = HashMap::new();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        assert!(record_known_ember_peer(&mut map, ip, 4662));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn record_known_ember_peer_refreshes_existing_timestamp() {
        let mut map = HashMap::new();
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        assert!(record_known_ember_peer(&mut map, ip, 4662));
        let first_ts = *map.get(&(ip, 4662)).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        // Re-recording the same address must NOT report it as new (so we
        // don't spuriously dirty the EPX payload), but it MUST move the
        // timestamp forward so the pruner doesn't evict an active peer.
        assert!(!record_known_ember_peer(&mut map, ip, 4662));
        let second_ts = *map.get(&(ip, 4662)).unwrap();
        assert!(second_ts > first_ts);
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn record_known_ember_peer_evicts_oldest_at_capacity() {
        let mut map = HashMap::new();
        // Fill exactly to the cap with sequentially-aged entries — the
        // first insert is the oldest by timestamp. Use the high two bytes
        // of the IPv4 address so we get enough unique addresses to
        // exceed `MAX_KNOWN_EMBER_PEERS` (500) without overflowing u8.
        for i in 0..MAX_KNOWN_EMBER_PEERS {
            let i = i as u16;
            let ip = Ipv4Addr::new(10, 0, (i >> 8) as u8, (i & 0xFF) as u8);
            assert!(record_known_ember_peer(&mut map, ip, 4662));
            std::thread::sleep(std::time::Duration::from_micros(50));
        }
        let oldest = (Ipv4Addr::new(10, 0, 0, 0), 4662u16);
        assert!(map.contains_key(&oldest));
        assert_eq!(map.len(), MAX_KNOWN_EMBER_PEERS);

        // Inserting one more brand-new address must evict the oldest
        // entry, not the new one or anything in between.
        let newcomer = Ipv4Addr::new(11, 0, 0, 1);
        assert!(record_known_ember_peer(&mut map, newcomer, 4662));
        assert_eq!(map.len(), MAX_KNOWN_EMBER_PEERS);
        assert!(!map.contains_key(&oldest));
        assert!(map.contains_key(&(newcomer, 4662)));
    }

    #[test]
    fn prune_stale_ember_peers_drops_expired_entries() {
        let mut map = HashMap::new();
        let fresh_ip = Ipv4Addr::new(1, 2, 3, 4);
        let stale_ip = Ipv4Addr::new(5, 6, 7, 8);
        let now = std::time::Instant::now();
        // Forge a stale entry by inserting with a timestamp older than
        // the TTL. We use checked_sub to avoid panicking on systems where
        // `Instant` was just initialised.
        let stale_ts = now
            .checked_sub(KNOWN_EMBER_PEER_TTL + std::time::Duration::from_secs(60))
            .expect("clock supports a backdated Instant");
        map.insert((fresh_ip, 4662), now);
        map.insert((stale_ip, 4662), stale_ts);

        prune_stale_ember_peers(&mut map);
        assert!(map.contains_key(&(fresh_ip, 4662)));
        assert!(!map.contains_key(&(stale_ip, 4662)));
    }

    #[test]
    fn ident_state_label_covers_every_variant() {
        // Lock the UI labels for the upload-pane Queued / Known Clients
        // tabs against accidental rename. eMule users recognise these
        // exact strings from the Identification row of their own client
        // details dialog.
        use ed2k::credits::IdentState;
        assert_eq!(ident_state_label(IdentState::Verified), "Verified");
        assert_eq!(ident_state_label(IdentState::Failed), "Failed");
        assert_eq!(ident_state_label(IdentState::BadGuy), "BadGuy");
        assert_eq!(ident_state_label(IdentState::Needed), "Needed");
        assert_eq!(ident_state_label(IdentState::Unknown), "Unknown");
        // Sanity: the lowercased form drives the `ident-*` CSS classes
        // in the transfers page; a label that lower-cases to a class
        // we don't have CSS for is rendered with the default text colour.
        for label in [
            ident_state_label(IdentState::Verified),
            ident_state_label(IdentState::Failed),
            ident_state_label(IdentState::BadGuy),
            ident_state_label(IdentState::Needed),
            ident_state_label(IdentState::Unknown),
        ] {
            assert!(label.chars().all(|c| c.is_ascii_alphanumeric()),
                "label {label} contains non-alphanumeric chars (would break ident-* class lookup)");
        }
    }

    #[test]
    fn note_results_keep_requested_file_hash() {
        let file_hash = KadId([0x11; 16]);
        let publisher = KadId([0x22; 16]);
        let entries = vec![SearchResultEntry {
            id: publisher,
            tags: vec![
                KadTag {
                    name: TagName::Id(TAG_FILENAME),
                    value: TagValue::String("example.bin".to_string()),
                },
                KadTag {
                    name: TagName::Id(TAG_FILERATING),
                    value: TagValue::Uint8(5),
                },
                KadTag {
                    name: TagName::Id(TAG_DESCRIPTION),
                    value: TagValue::String("Looks good".to_string()),
                },
            ],
        }];

        let results = convert_note_search_results(&entries, &file_hash);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].file.hash, hex::encode(kad_id_to_md4_bytes(&file_hash)));
        assert_eq!(results[0].peer_id, publisher.to_hex());
        assert_eq!(results[0].comment.as_deref(), Some("Looks good"));
        assert_eq!(results[0].rating, Some(5));
    }

    /// `extract_kad_sources` must read the `"ember"` capability tag we
    /// emit in `kad/publish.rs::build_source_publish` and surface it as
    /// `is_ember_capable`. This is the linchpin of the broker dispatch
    /// gate — if parsing breaks, every Ember peer silently regresses
    /// to "skip broker" and LowID-to-LowID becomes unreachable.
    #[test]
    fn extract_kad_sources_reads_ember_capability_tag() {
        use crate::network::kad::publish::EMBER_CAP_RELAY_PUNCH_V1;
        use crate::network::kad::types::{
            TAG_ENCRYPTION, TAG_FILESIZE, TAG_SOURCEIP, TAG_SOURCEPORT, TAG_SOURCETYPE,
        };

        // Ember-capable HighID source.
        let ember_entry = SearchResultEntry {
            id: KadId([0x33; 16]),
            tags: vec![
                KadTag {
                    name: TagName::Id(TAG_SOURCEIP),
                    // 1.2.3.4 in network byte order -> u32(0x01020304)
                    value: TagValue::Uint32(u32::from_be_bytes([1, 2, 3, 4])),
                },
                KadTag { name: TagName::Id(TAG_SOURCEPORT), value: TagValue::Uint16(4662) },
                KadTag { name: TagName::Id(TAG_SOURCETYPE), value: TagValue::Uint8(1) },
                KadTag { name: TagName::Id(TAG_FILESIZE), value: TagValue::Uint64(123) },
                KadTag { name: TagName::Id(TAG_ENCRYPTION), value: TagValue::Uint8(0) },
                KadTag {
                    name: TagName::Str("ember".to_string()),
                    value: TagValue::Uint8(EMBER_CAP_RELAY_PUNCH_V1),
                },
            ],
        };

        // Vanilla eMule source — no `"ember"` tag.
        let emule_entry = SearchResultEntry {
            id: KadId([0x44; 16]),
            tags: vec![
                KadTag {
                    name: TagName::Id(TAG_SOURCEIP),
                    value: TagValue::Uint32(u32::from_be_bytes([5, 6, 7, 8])),
                },
                KadTag { name: TagName::Id(TAG_SOURCEPORT), value: TagValue::Uint16(4663) },
                KadTag { name: TagName::Id(TAG_SOURCETYPE), value: TagValue::Uint8(1) },
            ],
        };

        let sources = extract_kad_sources(&[ember_entry, emule_entry]);
        assert_eq!(sources.len(), 2);

        let ember_src = sources
            .iter()
            .find(|s| s.tcp_port == 4662)
            .expect("ember source should be present");
        assert!(
            ember_src.is_ember_capable,
            "source carrying `ember` tag must be marked ember-capable",
        );

        let emule_src = sources
            .iter()
            .find(|s| s.tcp_port == 4663)
            .expect("emule source should be present");
        assert!(
            !emule_src.is_ember_capable,
            "source without `ember` tag must default to NOT ember-capable — \
             this is what guards the broker against wasting cycles on vanilla eMule",
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchMethod {
    Global,
    Server,
    Kad,
}

#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub struct SearchFilters {
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    pub file_type: Option<String>,
    pub file_extension: Option<String>,
    pub min_availability: Option<u32>,
}

#[derive(Debug)]
pub enum NetworkCommand {
    SearchFiles {
        query: String,
        method: SearchMethod,
        request_id: u64,
        tx: oneshot::Sender<Vec<SearchResult>>,
        search_filters: Option<SearchFilters>,
    },
    StartDownload {
        file_hash: String,
        file_name: String,
        file_size: u64,
        peer_ip: String,
        peer_port: u16,
        transfer_id: String,
        control: Arc<TransferControl>,
    },
    AnnounceFiles {
        files: Vec<FileInfo>,
    },
    /// Force an immediate re-publish of a single already-known file to KAD.
    /// The file must already be registered with the publish manager (e.g. via
    /// `AnnounceFiles`); this command just resets its source/keyword publish
    /// timestamps so the next publish cycle picks it up.
    RepublishFile {
        file_hash_hex: String,
    },
    FindSources {
        file_hash: KadId,
        file_size: u64,
        tx: oneshot::Sender<Vec<(String, u16)>>,
    },
    BanPeer {
        peer_id_hex: String,
    },
    UnbanPeer {
        peer_id_hex: String,
    },
    FindNotes {
        file_hash: KadId,
        file_size: u64,
        tx: oneshot::Sender<Vec<SearchResult>>,
    },
    PublishNote {
        file_hash: KadId,
        rating: u8,
        comment: String,
    },
    CancelSearch {
        request_id: u64,
    },
    CancelDownload {
        transfer_id: String,
        /// When set, the handler will skip saving .part.met (files are about to
        /// be deleted), await the task abort so file handles are released, remove
        /// the tracker from the registry, and signal the sender so the caller
        /// can safely delete the .part / .part.met files.
        cleanup_ack: Option<oneshot::Sender<()>>,
    },
    PauseDownload {
        transfer_id: String,
    },
    BootstrapContacts {
        contacts: Vec<kad::types::KadContact>,
    },
    ReloadIpFilter {
        path: PathBuf,
    },
    GetIpFilterStats {
        tx: oneshot::Sender<IpFilterStats>,
    },
    AddIpRange {
        start_ip: String,
        end_ip: String,
        description: String,
    },
    RemoveIpRange {
        start_ip: String,
        end_ip: String,
    },
    SetIpFilterEnabled {
        enabled: bool,
    },
    SetBlockPrivateIps {
        block_private: bool,
    },
    KadConnect,
    KadDisconnect,
    KadBootstrapIp {
        ip: String,
        port: u16,
        /// Result channel — `Ok(message)` with a human-readable success
        /// string on completion, or `Err(message)` describing the failure.
        /// Wire K0: the command must not return success until this
        /// resolves, otherwise the UI shows "Bootstrapping…" for a
        /// connection that never happened.
        tx: oneshot::Sender<Result<String, String>>,
    },
    KadBootstrapUrl {
        url: String,
        host: String,
        resolved_addrs: Vec<std::net::SocketAddr>,
        tx: oneshot::Sender<Result<String, String>>,
    },
    KadBootstrapClients {
        tx: oneshot::Sender<Result<usize, String>>,
    },
    /// K30: fire-and-forget cancellation of an active search by id.
    CancelKadSearch {
        id: u64,
    },
    RecheckFirewall {
        tx: oneshot::Sender<Result<usize, String>>,
    },
    GetPeersSnapshot {
        tx: oneshot::Sender<Vec<PeerInfo>>,
    },
    GetNetworkStatsSnapshot {
        tx: oneshot::Sender<NetworkStats>,
    },
    /// Snapshot of the current upload queue (peers waiting for an upload
    /// slot). Backs the "Queued" tab in the transfers/uploads pane.
    /// Returns rows with wait time, queue rank, and credit info already
    /// resolved so the UI doesn't need to invoke any further commands.
    GetUploadQueueSnapshot {
        tx: oneshot::Sender<Vec<crate::types::UploadQueueClient>>,
    },
    /// Snapshot of every persistent SecIdent credit record. Backs the
    /// "Known Clients" tab — this is the lifetime view from clients.met,
    /// independent of which peers are currently connected.
    GetKnownClientsSnapshot {
        tx: oneshot::Sender<Vec<crate::types::KnownClient>>,
    },
    /// Anti-leech client filter — read the current pattern list + flag
    /// for the Settings UI.
    GetAntiLeechSnapshot {
        tx: oneshot::Sender<crate::types::AntiLeechSnapshot>,
    },
    /// Anti-leech: replace the entire pattern list, persist to disk,
    /// recompile. Per-pattern compile errors come back via the result.
    SetAntiLeechPatterns {
        patterns: Vec<String>,
        tx: oneshot::Sender<Result<crate::types::AntiLeechReplaceResult, String>>,
    },
    /// Anti-leech: toggle on/off without modifying the pattern list.
    SetAntiLeechEnabled {
        enabled: bool,
        tx: oneshot::Sender<Result<(), String>>,
    },
    /// Anti-leech: discard the current list and reload built-in defaults.
    ResetAntiLeechToDefaults {
        tx: oneshot::Sender<Result<crate::types::AntiLeechSnapshot, String>>,
    },
    GetKadContactsSnapshot {
        tx: oneshot::Sender<Vec<KadContactInfo>>,
    },
    GetKadSearchesSnapshot {
        tx: oneshot::Sender<Vec<KadSearchInfo>>,
    },
    SharedFilesChanged,
    /// UI changed a file's upload priority. Pushes the new value into
    /// the in-memory `KnownFileList` so the upload server's per-request
    /// priority lookup sees it without waiting for a reload. Without
    /// this, priority changes only took effect after the next restart
    /// because `set_file_priority` only updated the live index, not the
    /// on-disk known-file record the upload handler reads.
    SetUploadPriority {
        file_hash_hex: String,
        priority: u8,
    },
    ConnectToServer {
        ip: String,
        port: u16,
    },
    DisconnectServer,
    AddServer {
        ip: String,
        port: u16,
        #[allow(dead_code)]
        name: String,
        tx: oneshot::Sender<Result<String, String>>,
    },
    RemoveServer {
        ip: String,
        port: u16,
        tx: oneshot::Sender<Result<String, String>>,
    },
    GetServerListSnapshot {
        tx: oneshot::Sender<Vec<ServerInfo>>,
    },
    GetConnectedServerSnapshot {
        tx: oneshot::Sender<Option<ServerInfo>>,
    },
    UpdateSettings {
        settings: AppSettings,
    },
    SetFileComment {
        file_hash: String,
        rating: u8,
        comment: String,
    },
    GetFileComments {
        file_hash: String,
        tx: oneshot::Sender<Option<ed2k::comments::FileCommentInfo>>,
    },
    MergeServerMet {
        data: Vec<u8>,
        tx: oneshot::Sender<anyhow::Result<ed2k::server_list::ServerMergeStats>>,
    },
    PreviewFile {
        transfer_id: String,
        tx: oneshot::Sender<Result<String, String>>,
    },
    SendChatMessage {
        ember_hash: [u8; 16],
        message: String,
        tx: oneshot::Sender<Result<(), String>>,
    },
    BrowseFriend {
        ember_hash: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    FriendRemoved {
        ember_hash: [u8; 16],
    },
    #[allow(dead_code)]
    ConnectForFriendRequest {
        ember_hash: [u8; 16],
        ip: std::net::Ipv4Addr,
        port: u16,
    },
    FindFriendAndConnect {
        ember_hash: [u8; 16],
    },
    EnsureFriendSession {
        ember_hash: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    RetryFriendSearch {
        ember_hash: [u8; 16],
        tx: oneshot::Sender<Result<(), String>>,
    },
    IsFriendDiscoverable {
        tx: oneshot::Sender<bool>,
    },
    GetPeerReputation {
        user_hash: [u8; 16],
        tx: oneshot::Sender<Option<PeerReputationInfo>>,
    },
    GetReputationStats {
        tx: oneshot::Sender<ReputationStatsInfo>,
    },
    Shutdown,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerReputationInfo {
    pub score: i32,
    pub successful_transfers: u64,
    pub failed_transfers: u64,
    pub is_banned: bool,
    pub first_seen: u64,
    pub last_interaction: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReputationStatsInfo {
    pub tracked_peers: usize,
    pub banned_peers: usize,
}

struct PendingDownload {
    transfer_id: String,
    file_hash: String,
    file_name: String,
    file_size: u64,
    control: Arc<TransferControl>,
    search_count: u32,
    last_search_at: i64,
    /// Download priority: 0 = low, 1 = normal, 2 = high
    priority: u32,
}

fn priority_str_to_u32(s: &str) -> u32 {
    match s {
        "release" => 3,
        "high" => 2,
        "low" | "verylow" => 0,
        _ => 1, // "normal", "auto", or unknown default to normal
    }
}

const DISK_SPACE_BUFFER: u64 = 50 * 1024 * 1024; // 50 MB safety margin

fn check_disk_space(download_dir: &std::path::Path, needed_bytes: u64) -> bool {
    match fs2::available_space(download_dir) {
        Ok(available) => {
            if available < needed_bytes.saturating_add(DISK_SPACE_BUFFER) {
                warn!(
                    "Insufficient disk space: need {} bytes (+ {} buffer), only {} available in {}",
                    needed_bytes,
                    DISK_SPACE_BUFFER,
                    available,
                    download_dir.display()
                );
                false
            } else {
                true
            }
        }
        Err(e) => {
            debug!("Could not check disk space on {}: {e}", download_dir.display());
            true
        }
    }
}

struct PendingKeywordSearch {
    tx: oneshot::Sender<Vec<SearchResult>>,
    local_results: Vec<SearchResult>,
    keywords: Vec<String>,
    request_id: u64,
    last_streamed_count: usize,
    file_type_filter: Option<String>,
}

struct PendingServerSearch {
    tx: Option<oneshot::Sender<Vec<SearchResult>>>,
    results: Vec<SearchResult>,
    request_id: u64,
}

#[derive(Clone)]
struct ActiveSearchRequest {
    request_id: u64,
    server_pending: bool,
    kad_pending: bool,
    udp_pending: bool,
    file_type_filter: Option<String>,
    /// Keywords extracted from the original query, used by the spam-filter
    /// scorer when streamed results arrive from the network event loop.
    /// Empty for queries where extraction yielded nothing (no spam scoring
    /// applied — those queries shouldn't reach the streaming paths anyway,
    /// since we early-return when `keywords.is_empty()` at request start).
    keywords: Vec<String>,
    /// Source IP of the connected eD2k server at request-start time, used
    /// as an extra signal by the spam filter (`spam_server_ips` set). Only
    /// meaningful for the TCP-server streaming path; the UDP-server and
    /// KAD paths pass `None` because results from those origins don't
    /// uniquely belong to one server / origin IP.
    server_ip: Option<String>,
}

#[derive(Clone, serde::Serialize)]
struct SearchResultsEvent {
    request_id: u64,
    results: Vec<SearchResult>,
}

#[derive(Clone, serde::Serialize)]
struct SearchProgressEvent {
    request_id: u64,
    nodes_contacted: usize,
    results_so_far: usize,
    phase: String,
}

#[derive(Clone, serde::Serialize)]
struct SearchCompleteEvent {
    request_id: u64,
}

struct NetworkState {
    local_id: KadId,
    user_hash: [u8; 16],
    routing_table: RoutingTable,
    search_manager: SearchManager,
    publish_manager: PublishManager,
    dht_store: DhtStore,
    stats: NetworkStats,
    pending_keyword_searches: HashMap<SearchId, PendingKeywordSearch>,
    /// Pending server TCP search: when we send OP_SEARCHREQUEST, store the results here
    /// until poll_messages() delivers OP_SEARCHRESULT.
    pending_server_search: Option<PendingServerSearch>,
    active_search_request: Option<ActiveSearchRequest>,
    /// eMule OP_QUERY_MORE_RESULT: request more search results from server
    server_search_more_needed: bool,
    /// Counter for throttling server keep-alive (sent every N poll ticks)
    server_poll_count: u32,
    /// Counter for pending server search timeout (in poll ticks)
    server_search_age: u32,
    /// Counter for pending server UDP search timeout (in poll ticks)
    server_udp_search_age: u32,
    /// Throttled UDP global search queue: packets to send one-at-a-time at
    /// 750ms intervals (eMule UDPSEARCHSPEED = SEC2MS(3)/4).
    udp_search_queue: VecDeque<(Vec<u8>, std::net::SocketAddr)>,
    pending_source_searches: HashMap<SearchId, oneshot::Sender<Vec<(String, u16)>>>,
    /// Source searches tied to pending downloads (search_id -> (transfer_id, file_hash_md4)).
    /// File hash is carried alongside so the search-completion handler can build
    /// CallbackReqs / inject sources without re-reading `pending_downloads`, which
    /// gets consumed the moment `try_start_from_known` promotes a transfer to
    /// active (server returned sources first).
    download_source_searches: HashMap<SearchId, (String, [u8; 16])>,
    /// Downloads waiting for sources (transfer_id -> PendingDownload)
    pending_downloads: HashMap<String, PendingDownload>,
    data_dir: PathBuf,
    external_ip: Option<Ipv4Addr>,
    external_udp_port: Option<u16>,
    firewalled: bool,
    firewall_checks_sent: u32,
    peer_nicknames: HashMap<KadId, String>,
    /// Outstanding publish requests awaiting `PublishRes` acks.
    ///
    /// Keyed by `(target_hash, peer_addr)` so each publish-to-peer
    /// pair is tracked individually — this lets the ack counter count
    /// *every* successful delivery instead of collapsing to one per
    /// target (fixes the long-standing 0-confirmed publish cycle bug
    /// where many peers acked but we silently dropped all but the first).
    /// Value carries the original file hash (for retry book-keeping),
    /// the send timestamp (for stale cleanup), and whether this is a
    /// source publish (vs keyword/notes).
    publish_pending: HashMap<(KadId, SocketAddr), (KadId, i64, bool)>,
    publish_confirmed: u32,
    /// Diagnostic counters for `PublishRes` packet accounting. These let
    /// the `Publish cycle:` log line surface exactly where packets are
    /// being dropped. Seen from newest (closest to the "packet leaves the
    /// wire") to oldest (closest to the handler):
    ///
    /// - `publish_res_plain_seen`: raw inbound with `data[0]==0xE4 &&
    ///   data[1]==0x4B`, counted **before** IP filter / rate limit /
    ///   decompress / decrypt. Obfuscated responses look like ciphertext
    ///   at byte 0 and are *not* counted here (they can't be — byte 1 is
    ///   random). Use this to tell whether plain PublishRes even reach
    ///   our socket.
    /// - `publish_res_obf_decoded`: obfuscated UDP packets that
    ///   successfully decrypt **and** decode as a `PublishRes`. Pairs
    ///   with `obf_decoded_total` so you can see whether the drop is
    ///   specific to PublishRes or general to our decrypt path.
    /// - `obf_decoded_total`: any obfuscated UDP packet that decrypted
    ///   and decoded. Baseline for the previous counter.
    /// - `publish_res_wire`: `PublishRes` reached the decoded-message
    ///   stage (plain or obfuscated), before `validate_response`.
    /// - `publish_res_received`: handler entered, any load value.
    /// - `publish_res_unmatched`: decoded but `validate_response` said
    ///   unsolicited, OR handler couldn't match `publish_pending`.
    publish_res_plain_seen: u64,
    publish_res_obf_decoded: u64,
    obf_decoded_total: u64,
    publish_res_wire: u64,
    publish_res_received: u64,
    publish_res_unmatched: u64,
    /// Per-file count of KAD peers that acknowledged the most recent source
    /// publish cycle with a `PublishRes`. Used as a crude "complete sources"
    /// estimate for files the user is purely sharing (where SourceManager
    /// has no entries because we never searched/downloaded them).
    /// Reset to 0 at the start of each source-publish cycle.
    source_publish_acks: HashMap<KadId, u32>,
    /// Store-keyword searches: search_id -> (file PublishableFile, keyword publish messages)
    store_keyword_searches: HashMap<SearchId, (PublishableFile, Vec<(KadId, KadMessage)>)>,
    /// Store-source searches: search_id -> (file_hash, publish message)
    store_source_searches: HashMap<SearchId, (KadId, KadMessage)>,
    /// Pending notes searches: search_id -> response sender
    pending_notes_searches: HashMap<SearchId, oneshot::Sender<Vec<SearchResult>>>,
    /// Pending note publishes: search_id -> (file_hash, rating, comment)
    pending_note_publishes: HashMap<SearchId, (KadId, u8, String)>,
    /// Nodes that reported load=100 -- avoid publishing to them for a while
    overloaded_nodes: HashMap<Ipv4Addr, i64>,
    flood_protection: FloodProtection,
    buddy_manager: BuddyManager,
    /// Our UDP verification key seed (random, stable for session)
    udp_key_seed: u32,
    tcp_port: u16,
    udp_port: u16,
    /// Actual UDP port the QUIC broker endpoint bound to. `None` until
    /// the broker is initialised, then set to the real `local_addr()`
    /// port — which may differ from `tcp_port` if the requested port
    /// was already in use (e.g. when `tcp_port == udp_port` and the Kad
    /// UDP socket got there first). Anything that advertises our QUIC
    /// reachability (rendezvous registration / heartbeat) must read
    /// from here, not from `settings.tcp_port`.
    quic_port: Option<u16>,
    upnp_mapped: bool,
    /// IP filter for blocking known-bad ranges (eMule ipfilter.dat compatible)
    ip_filter: IpFilter,
    /// Cached set of banned peer IPs for fast lookup at network level
    banned_ips: HashSet<Ipv4Addr>,
    /// Whether to use protocol obfuscation (RC4 encryption) for outgoing KAD packets
    obfuscation_enabled: bool,
    /// Shared firewall status that can be updated from spawned tasks
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Shared external IPv4 encoded as a little-endian u32 — the same
    /// layout ed2k uses for a HighID `client_id` on the wire.
    /// `0` means unknown (no trusted source has reported our public IP yet);
    /// any non-zero value is our public IPv4 confirmed by a trusted source
    /// (ed2k server HighID, multi-reporter KAD consensus, or UPnP→firewall
    /// re-verification). The upload listener reads this atomic when building
    /// an outgoing `OP_HELLOANSWER`: advertising our real ID here instead
    /// of a hardcoded `0` lets strict eMule forks and older clients
    /// correctly treat us as HighID in their queue scoring and callback
    /// logic, rather than relying on BaseClient.cpp's forgiving
    /// `m_nUserIDHybrid == 0 → use connect IP` auto-heal. Keeps this in
    /// sync with `external_ip` via `set_external_ip` below so there is no
    /// way to update one without the other.
    external_ip_shared: Arc<std::sync::atomic::AtomicU32>,
    /// Whether we've done the initial self-lookup (FindNode for own ID)
    self_lookup_done: bool,
    /// Timestamp of last self-lookup (eMule repeats every 4 hours)
    last_self_lookup: i64,
    /// When the KAD stack was started (eMule: first self FindNode after MIN2S(3))
    kad_started_at: i64,
    /// eMule `CPrefs::m_tLastContact` — updated on each accepted incoming KAD UDP packet.
    last_kad_contact: Option<i64>,
    /// Whether UDP is firewalled (separate from TCP, like eMule)
    udp_firewalled: bool,
    /// Whether UDP firewall status has been verified
    udp_fw_verified: bool,
    /// Whether the initial post-bootstrap publish has been done
    first_publish_done: bool,
    /// Whether the initial KAD source search burst for pending downloads has been done
    kad_initial_source_burst_done: bool,
    /// Whether the immediate friend presence publish has fired after IP discovery
    friend_presence_initial_done: bool,
    /// ed2k server list
    server_list: ServerList,
    /// Whether we're connected to an ed2k server
    server_connected: bool,
    /// Active ed2k server connection (kept for keep-alive and source requests)
    server_connection: Option<Ed2kServerConnection>,
    /// Address of the currently connected server
    server_addr: Option<SocketAddr>,
    /// Throttled UDP source-request queue: packets paced at ~1 per second
    /// (eMule sends one per ~1s during its global sweep).
    udp_source_queue: VecDeque<(Vec<u8>, std::net::SocketAddr)>,
    /// Round-robin cursor for TCP OP_GETSOURCES batching across downloads.
    server_tcp_getsources_cursor: usize,
    /// Round-robin cursor for fair KAD search slot distribution across downloads.
    kad_source_search_cursor: usize,
    /// Dead source tracking (prevents reconnecting to failing sources)
    dead_sources: DeadSourceList,
    /// Tracks which IP sent each byte range for corruption blame attribution
    corruption_blackbox: CorruptionBlackBox,
    /// Pending AICH recovery retries: (file_hash, part_index) -> (failed_ips, retry_count)
    aich_recovery_pending: ed2k::transfer::SharedAichPending,
    /// eMule-style persistent source lists per download (survives connection failures)
    per_file_sources: HashMap<String, ed2k::sources::PerFileSourceList>,
    /// KAD search state for active downloads not in pending_downloads.
    /// Tracks (last_kad_search_at, search_count) so we periodically search
    /// for additional sources via KAD even while the download is running.
    active_kad_search_state: HashMap<String, (i64, u32)>,
    /// Senders for injecting new sources into active multi-source downloads
    active_source_senders: HashMap<String, mpsc::Sender<DownloadSource>>,
    /// UDP source-discovery diagnostic counters. Surfaced in the
    /// periodic discovery health log so the user can verify UDP
    /// source-asking is actually flowing (vs silently broken by
    /// firewall, missing obfuscation, dead servers, etc.). All four
    /// are monotonic since process start; the health log prints
    /// deltas. Saturating arithmetic so a long-running session can't
    /// overflow `u64`.
    udp_discovery_sent: u64,
    udp_discovery_send_errs: u64,
    udp_discovery_replies: u64,
    udp_discovery_sources_found: u64,
    /// Senders for injecting *pre-handshaked* peer streams into active
    /// multi-source downloads. Distinct from `active_source_senders`
    /// because the payload (`EstablishedSource`) carries an
    /// already-adopted reader/writer pair — used by the LowID-callback
    /// fast path to avoid the wasted-redial bug where we'd otherwise
    /// metadata-inject the peer and then try a fresh outbound connect
    /// to a NAT'd address. Mirrors `active_source_senders` in
    /// lifecycle: created at MultiSourceDownload construction, removed
    /// when the download completes / fails / is cancelled. Always
    /// registered/removed in lockstep with `active_source_senders` so
    /// neither leaks past the other.
    active_established_senders: HashMap<String, mpsc::Sender<ed2k::multi_source::EstablishedSource>>,
    /// Overflow queue for sources discovered faster than the active download can accept them
    active_source_overflow: HashMap<String, VecDeque<DownloadSource>>,
    /// JoinHandles for spawned download tasks, keyed by transfer_id
    download_handles: HashMap<String, tokio::task::JoinHandle<()>>,
    /// Comment/rating manager
    comment_manager: Arc<RwLock<CommentManager>>,
    firewall_checker: FirewallChecker,
    /// Whether we have LowID from the server
    low_id: bool,
    /// Our server-assigned client ID
    server_client_id: u32,
    /// Background server connection task (non-blocking)
    pending_server_connect: Option<tokio::task::JoinHandle<ServerConnectResult>>,
    /// Shared set of user hashes expected as incoming buddy connections (checked by upload listener)
    pending_buddy_hashes: PendingBuddySet,
    /// Shared buddy info for Hello tags (updated when buddy connects/disconnects)
    shared_buddy_info: upload_server::SharedBuddyInfo,
    /// Shared IP filter snapshot for the upload handler
    shared_ip_filter: kad::ip_filter::SharedIpFilter,
    /// Event receiver for our buddy connection (we are firewalled)
    buddy_event_rx: Option<mpsc::Receiver<BuddyEvent>>,
    /// Event receiver for the client we're serving as buddy for
    serving_event_rx: Option<mpsc::Receiver<BuddyEvent>>,
    /// Background buddy outgoing connect+handshake task
    pending_outgoing_buddy: Option<tokio::task::JoinHandle<Option<(KadId, std::net::Ipv4Addr, u16, mpsc::Receiver<BuddyEvent>, BuddyWriteStream, tokio::task::JoinHandle<()>)>>>,
    /// Whether the server auto-reconnect loop is allowed to run.
    /// Starts from settings; enabled on manual connect, disabled on manual disconnect.
    server_auto_reconnect: bool,
    /// Consecutive server connection failures for exponential backoff (reset on success)
    server_reconnect_failures: u32,
    /// Instant when the last server connect attempt was started
    server_last_connect_attempt: Option<std::time::Instant>,
    /// Pending USS ping timestamps for RTT measurement
    pending_uss_pings: HashMap<SocketAddr, std::time::Instant>,
    /// Currently selected USS ping target
    uss_host: Option<(SocketAddr, KadId)>,
    /// Consecutive missed USS pongs (rotate host after 3)
    uss_missed_pongs: u32,
    /// When the current USS host was selected
    uss_host_selected_at: i64,
    /// Shared RTT queue for feeding latency samples to the limiter loop
    uss_rtt_queue: crate::bandwidth::UssRttQueue,
    /// Shared USS enabled flag
    uss_enabled_flag: crate::bandwidth::UssEnabledFlag,
    /// AICH recovery hash sets loaded from known2_64.met (saved on shutdown)
    aich_hash_sets: Vec<ed2k::aich::AICHRecoveryHashSet>,
    /// Shared max upload slots (updated on settings change, read by upload handler)
    upload_max_slots: Arc<std::sync::atomic::AtomicUsize>,
    /// Whether the EPX payload needs rebuilding (set on source changes, cleared after rebuild)
    ember_payload_dirty: bool,
    /// Known Ember peer addresses for peer discovery mesh building.
    /// Value is the last time we saw this peer (either by direct connect or
    /// via EPX from another peer). Stale entries are pruned by
    /// `prune_stale_ember_peers` against `KNOWN_EMBER_PEER_TTL` and the
    /// total set is capped at `MAX_KNOWN_EMBER_PEERS` to prevent unbounded
    /// growth on long-running sessions. The wire cap is much smaller
    /// (`ember::MAX_EPX_PEERS = 50`); the in-memory headroom exists so we
    /// can rotate which subset gets advertised across rebuilds.
    known_ember_peers: HashMap<(Ipv4Addr, u16), std::time::Instant>,
    /// Shared anti-leech client-software filter. Held here so the
    /// settings command path can hot-swap the pattern list without the
    /// upload listener needing to re-subscribe; the upload server
    /// already holds an `Arc` clone of this same handle.
    antileech: crate::security::antileech::SharedAntiLeechFilter,
    /// Mapping of ed2k file hash → AICH root hash for EPX payload
    aich_root_map: HashMap<[u8; 16], [u8; 20]>,
    /// Tracks KAD callback attempts per (buddy_hash, file_hash) to avoid
    /// repeatedly contacting non-responsive buddies.
    /// Value is (attempt_count, first_attempt_timestamp) — resets after 10 minutes.
    callback_buddy_attempts: HashMap<([u8; 16], [u8; 16]), (u32, i64)>,
    /// Semaphore limiting concurrent outgoing TCP connections for firewall checks
    firewall_connect_semaphore: Arc<tokio::sync::Semaphore>,
    /// K18: per-IP cooldown timestamps for incoming FirewalledReq. An
    /// attacker with UDP spoof capability can send many FirewalledReq
    /// packets that each trigger an outgoing TCP connect-back attempt
    /// on our end (default 5s timeout, ~16 in flight). A simple 60s
    /// per-IP cooldown + compact size cap blocks that amplification
    /// without hurting legit peers (eMule only rechecks its firewall
    /// status once an hour).
    firewall_req_cooldown: HashMap<Ipv4Addr, i64>,
    /// Ember friends currently connected (ember_hash -> last_seen_timestamp)
    online_friends: HashMap<[u8; 16], i64>,
    /// Shared Ember session map for sending outbound packets to friend connections
    ember_sessions: upload_server::EmberSessionMap,
    /// Shared flag: set to true when network is disconnected so the upload
    /// listener rejects new connections and terminates active sessions.
    upload_disconnected: Arc<std::sync::atomic::AtomicBool>,
    /// Whether we have successfully registered with the rendezvous server
    rendezvous_registered: bool,
    /// Last time we registered with the rendezvous server (for heartbeat)
    rendezvous_last_register: Option<std::time::Instant>,
    /// Tracks active outbound friend session tasks to prevent duplicates.
    /// ember_hash -> Instant when the session was started.
    outbound_session_tasks: HashMap<[u8; 16], std::time::Instant>,
    /// Whether the initial friend search burst has fired after connect
    friend_search_initial_done: bool,
    /// When the initial friend search burst started (for 30-min auto-retry cutoff)
    friend_search_started_at: Option<std::time::Instant>,
    /// Backoff tracker for friend reconnection: ember_hash -> last attempt time.
    /// Prevents tight reconnect loops when sessions fail immediately.
    friend_reconnect_last: HashMap<[u8; 16], std::time::Instant>,
    /// Shared registry of active download trackers — the shutdown path iterates
    /// this to persist `.part.met` files when download tasks are aborted.
    tracker_registry: SharedTrackerRegistry,
    /// Cached NAT type info for LowID-to-LowID hole-punch decisions
    nat_info: ember::nat::NatInfo,
    /// Connection broker for LowID-to-LowID transfers via hole-punch/relay
    connection_broker: Option<ember::broker::ConnectionBroker>,
    /// Broker event receiver (fed by ConnectionBroker, consumed in main select loop)
    broker_event_rx: Option<mpsc::Receiver<ember::broker::BrokerEvent>>,
    /// Manages relay sessions when this node acts as a relay for other peers
    relay_manager: Arc<tokio::sync::Mutex<ember::relay::RelayManager>>,
    /// Peer reputation tracking (score, ban, decay)
    reputation: ember::reputation::ReputationManager,
    /// Set of peers `(ip, tcp_port)` we have observed advertising the
    /// `"ember"` capability tag (`EMBER_CAP_RELAY_PUNCH_V1`) in a KAD
    /// source publish. Both broker call sites gate on this — peers
    /// that haven't advertised the tag get marked `low_to_low` and
    /// skipped, instead of burning ~46 s of broker time per attempt
    /// trying to talk Ember relay protocol to a vanilla eMule client
    /// that doesn't understand it.
    ///
    /// Lazily populated by `extract_kad_sources` callers; cleared on
    /// process shutdown. KAD source publishes have a 5-hour TTL and
    /// our routing table is repopulated at startup, so the cache
    /// rebuilds quickly on each session.
    ember_capable_peers: HashSet<(Ipv4Addr, u16)>,
}

/// Filter search results by file type, matching eMule's AddToList behavior:
/// when a type filter is active, reject any result whose inferred type
/// doesn't match the requested type.
fn filter_results_by_type(mut results: Vec<SearchResult>, file_type_filter: &Option<String>) -> Vec<SearchResult> {
    if let Some(ref ft) = file_type_filter {
        results.retain(|r| {
            let inferred = crate::search::index::infer_file_type(&r.file.extension);
            let result_type = if !inferred.is_empty() {
                inferred
            } else {
                r.file_type.clone()
            };
            result_type == *ft
        });
    }
    results
}

fn emit_search_results(
    app_handle: &tauri::AppHandle,
    request_id: u64,
    results: Vec<SearchResult>,
    file_type_filter: &Option<String>,
) {
    let results = filter_results_by_type(results, file_type_filter);
    if results.is_empty() {
        return;
    }
    let _ = app_handle.emit(
        "search-results",
        SearchResultsEvent { request_id, results },
    );
}

/// Return true if `ip` is safe to surface as a candidate download source
/// in a streamed search result. Mirrors the gate used at
/// `inject_source_into_active_transfers` so the search UI never lists IPs
/// that we'd refuse to dial: special-use ranges, multicast, the user's
/// IP filter, and the live runtime banlist.
///
/// Uses the readonly form of `IpFilter::is_blocked` because we only have
/// `&NetworkState` at the call sites; the per-IP cache miss cost is
/// negligible compared to the per-result string formatting we're already
/// doing on the same path.
fn is_search_source_safe(state: &NetworkState, ip: Ipv4Addr) -> bool {
    if crate::security::is_special_use_v4(ip) || ip.is_multicast() {
        return false;
    }
    if state.ip_filter.is_blocked_readonly(ip) {
        return false;
    }
    if state.banned_ips.contains(&ip) {
        return false;
    }
    true
}

/// Apply spam scoring + filename cleanup + comment URL stripping to a
/// batch of streamed search results, then forward them to the existing
/// `emit_search_results` pipeline. This is the streaming counterpart to
/// `commands::search::enrich_results` (used by the synchronous local
/// search path).
///
/// Without this, network-discovered results — which is where spam
/// actually lives — would reach the UI with `spam_rating: 0` /
/// `is_spam: false` regardless of the user's spam-filter settings,
/// because the construction sites stub those fields and the frontend
/// trusts them.
///
/// Acquires only a read lock on `spam_filter`, so it's safe to call
/// from any event-loop arm. `keywords` and `server_ip` come from
/// `ActiveSearchRequest`, populated at request start.
#[allow(clippy::too_many_arguments)]
async fn enrich_and_emit_search_results(
    app_handle: &tauri::AppHandle,
    spam_filter: &Arc<RwLock<crate::search::spam::SpamFilter>>,
    settings: &AppSettings,
    request_id: u64,
    mut results: Vec<SearchResult>,
    file_type_filter: &Option<String>,
    keywords: &[String],
    server_ip: Option<&str>,
) {
    if results.is_empty() {
        return;
    }
    let spam_enabled = settings.spam_filter_enabled;
    let spam_profile = crate::search::spam::SpamFilterProfile::from_setting(
        &settings.spam_filter_profile,
    );
    let cleanup_strings =
        crate::search::cleanup::parse_cleanup_strings(&settings.filename_cleanups);

    let spam = spam_filter.read().await;
    crate::commands::search::apply_search_enrichment(
        &mut results,
        &spam,
        keywords,
        server_ip,
        spam_enabled,
        spam_profile,
        &cleanup_strings,
    );
    drop(spam);

    emit_search_results(app_handle, request_id, results, file_type_filter);
}

fn maybe_finish_active_search(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    request_id: u64,
) {
    let should_complete = state.active_search_request.as_ref().is_some_and(|active| {
        active.request_id == request_id
            && !active.server_pending
            && !active.kad_pending
            && !active.udp_pending
    });
    if should_complete {
        state.active_search_request = None;
        state.server_search_age = 0;
        state.server_udp_search_age = 0;
        let _ = app_handle.emit(
            "search-complete",
            SearchCompleteEvent { request_id },
        );
    }
}

fn cancel_search_request(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    request_id: u64,
) {
    let cancelled: Vec<SearchId> = state
        .pending_keyword_searches
        .iter()
        .filter(|(_, pending)| pending.request_id == request_id)
        .map(|(sid, _)| *sid)
        .collect();

    for sid in &cancelled {
        if let Some(search) = state.search_manager.get_mut(sid) {
            search.completed = true;
        }
    }

    for sid in &cancelled {
        if let Some(PendingKeywordSearch { tx, local_results, .. }) =
            state.pending_keyword_searches.remove(sid)
        {
            let _ = tx.send(local_results);
        }
        if let Some(removed) = state.search_manager.remove(sid) {
            state.routing_table.release_contacts_in_use(&removed.in_use_ids);
        }
    }

    if state
        .pending_server_search
        .as_ref()
        .is_some_and(|pending| pending.request_id == request_id)
    {
        if let Some(mut pending) = state.pending_server_search.take() {
            if let Some(tx) = pending.tx.take() {
                let _ = tx.send(pending.results);
            }
        }
        state.server_search_age = 0;
    }

    if state
        .active_search_request
        .as_ref()
        .is_some_and(|active| active.request_id == request_id)
    {
        state.active_search_request = None;
        state.server_search_age = 0;
        state.server_udp_search_age = 0;
        state.udp_search_queue.clear();
        let _ = app_handle.emit(
            "search-complete",
            SearchCompleteEvent { request_id },
        );
    }
}

fn emit_transfer_health(app_handle: &tauri::AppHandle, update: &TransferHealthUpdate) {
    let _ = app_handle.emit(
        "transfer-health",
        serde_json::json!({
            "id": update.id,
            "health": update.health,
            "health_reason": update.health_reason,
            "stalled_since": update.stalled_since,
            "failure_reason": update.failure_reason,
            "failure_kind": update.failure_kind,
            "failure_stage": update.failure_stage,
        }),
    );
}

async fn handle_server_disconnect(
    state: &mut NetworkState,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    app_handle: &tauri::AppHandle,
    reason: &str,
) {
    warn!("Server connection lost: {reason}");
    emit_server_log(app_handle, &format!("Server disconnected: {reason}"));
    if let Some(handle) = state.pending_server_connect.take() {
        handle.abort();
    }
    state.server_poll_count = 0;
    state.server_search_more_needed = false;
    state.udp_search_queue.clear();
    state.server_connected = false;
    state.server_connection = None;
    state.server_addr = None;
    state.low_id = false;
    state.server_client_id = 0;
    *shared_server_addr.write().await = None;
    if let Some(mut pending) = state.pending_server_search.take() {
        let request_id = pending.request_id;
        if let Some(tx) = pending.tx.take() {
            let _ = tx.send(pending.results);
        }
        if let Some(active) = state.active_search_request.as_mut() {
            if active.request_id == request_id {
                active.server_pending = false;
            }
        }
        maybe_finish_active_search(state, app_handle, request_id);
    }
    if let Some(active) = state.active_search_request.as_mut() {
        let rid = active.request_id;
        let mut changed = false;
        if active.udp_pending {
            active.udp_pending = false;
            state.server_udp_search_age = 0;
            changed = true;
        }
        if active.server_pending {
            active.server_pending = false;
            changed = true;
        }
        if changed {
            maybe_finish_active_search(state, app_handle, rid);
        }
    }
    state.stats.server_status = "disconnected".to_string();
    let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
}

async fn flush_credit_state(
    credit_manager: &Arc<RwLock<CreditManager>>,
    db: &Arc<Database>,
    data_dir: &std::path::Path,
    cleanup_stale: bool,
) {
    if cleanup_stale {
        let mut cm_w = credit_manager.write().await;
        cm_w.cleanup_stale(90);
    }

    let (serialized_bytes, owned) = {
        let cm = credit_manager.read().await;
        let bytes = cm.serialize();
        let records: Vec<([u8; 16], u64, u64, i64, Vec<u8>)> = cm
            .all_records()
            .iter()
            .map(|r| (r.user_hash, r.uploaded, r.downloaded, r.last_seen, r.public_key.clone()))
            .collect();
        (bytes, records)
    };
    // Ordering note: persist credits to the SQLite database *first* (the
    // authoritative source on load — see `CreditManager` loader, which
    // only falls back to `clients.met` when the DB has no rows) and only
    // afterwards write the `clients.met` cache copy. If a crash happens
    // between the two writes, the next launch still sees the latest credits
    // via the DB; the on-disk cache may lag but does not clobber fresh data.
    let db_ref = db.clone();
    let db_save = tokio::task::spawn_blocking(move || {
        let refs: Vec<(&[u8; 16], u64, u64, i64, &[u8])> = owned
            .iter()
            .map(|(h, u, d, l, p)| (h, *u, *d, *l, p.as_slice()))
            .collect();
        let result = db_ref.save_all_credits(&refs);
        db_ref.incremental_vacuum();
        result
    })
    .await;
    match db_save {
        Ok(Ok(())) => {}
        Ok(Err(e)) => error!("Failed to save credits: {e}"),
        Err(e) => error!("Credit save task failed: {e}"),
    }

    let clients_met = data_dir.join("clients.met");
    let clients_bak = data_dir.join("clients.met.bak");
    if clients_met.exists() {
        if let Err(e) = std::fs::copy(&clients_met, &clients_bak) {
            debug!("Failed to create clients.met backup: {e}");
        }
    }
    if let Err(e) = crate::security::atomic_write(&clients_met, &serialized_bytes, false) {
        debug!("Failed to finalize clients.met: {e}");
    }
}

fn server_entry_to_info(server: &ServerEntry) -> ServerInfo {
    ServerInfo {
        ip: server.ip.clone(),
        port: server.port,
        name: server.name.clone(),
        description: server.description.clone(),
        user_count: server.user_count,
        file_count: server.file_count,
        max_users: server.max_users,
        soft_files: server.soft_files,
        hard_files: server.hard_files,
        is_static: server.is_static,
        fail_count: server.fail_count,
        client_id: 0,
        is_low_id: false,
    }
}

fn connected_server_info(state: &NetworkState) -> Option<ServerInfo> {
    let conn = state.server_connection.as_ref()?;
    let session = conn.session.as_ref()?;
    let addr = state.server_addr?;
    Some(ServerInfo {
        ip: addr.ip().to_string(),
        port: addr.port(),
        name: session.server_name.clone(),
        description: String::new(),
        user_count: session.user_count,
        file_count: session.file_count,
        max_users: 0,
        soft_files: 0,
        hard_files: 0,
        is_static: false,
        fail_count: 0,
        client_id: state.server_client_id,
        is_low_id: state.low_id,
    })
}

async fn try_start_pending_download_from_known_sources(
    state: &mut NetworkState,
    transfer_id: &str,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    shared_banned_ips: &ed2k::upload::SharedBannedIps,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    sx_overhead: &crate::storage::statistics::SharedSxOverheadCounters,
) -> bool {
    if let Some(pd) = state.pending_downloads.get(transfer_id) {
        if pd.control.is_paused() || pd.control.is_cancelled() {
            return false;
        }
    }

    // Only start transfers that are in the active set. Downloads still in
    // the queue participate in source discovery (they live in
    // pending_downloads) but must wait for promotion before connecting.
    {
        let mgr = transfer_manager.read().await;
        let is_active = mgr.get_transfer(transfer_id)
            .map(|t| !matches!(t.status, TransferStatus::Queued))
            .unwrap_or(false);
        if !is_active {
            return false;
        }
    }

    let Some(pending) = state.pending_downloads.remove(transfer_id) else {
        return false;
    };

    let hash_bytes = match hex::decode(&pending.file_hash) {
        Ok(b) if b.len() == 16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            state.pending_downloads.insert(transfer_id.to_string(), pending);
            return false;
        }
    };

    let sm_sources = {
        let sm = source_manager.read().await;
        sm.get_sources(&hash_bytes)
    };
    let live_sources: Vec<(String, u16)> = sm_sources
        .into_iter()
        .filter(|(ip, port)| !state.dead_sources.is_dead_source_for_file(&hash_bytes, u32::from(*ip), *port))
        .map(|(ip, port)| (ip.to_string(), port))
        .collect();

    if live_sources.is_empty() {
        state.pending_downloads.insert(transfer_id.to_string(), pending);
        return false;
    }

    let source_count = live_sources.len() as u32;
    {
        let mut mgr = transfer_manager.write().await;
        mgr.update_status(transfer_id, TransferStatus::Active);
        mgr.update_sources(transfer_id, source_count, 0, 0);
    }
    let _ = app_handle.emit("transfer-status", serde_json::json!({
        "id": transfer_id,
        "status": "active",
        "sources": source_count,
        "active_sources": 0,
        "queued_sources": 0,
    }));

    {
        let pfs = state
            .per_file_sources
            .entry(transfer_id.to_string())
            .or_insert_with(|| ed2k::sources::PerFileSourceList::new(hash_bytes));
        let udp_sources = {
            let sm = source_manager.read().await;
            sm.get_udp_sources(&hash_bytes)
        };
        for (ip_s, port) in &live_sources {
            if let Ok(v4) = ip_s.parse::<Ipv4Addr>() {
                let udp_port = udp_sources
                    .iter()
                    .find(|(ip, tcp_port, _)| ip == &v4 && tcp_port == port)
                    .map(|(_, _, udp)| *udp)
                    .unwrap_or(0);
                if pfs.add_source_full(v4, *port, udp_port) {
                    state.ember_payload_dirty = true;
                }
            }
        }
    }

    {
        let mut sm = source_manager.write().await;
        for (ip, port) in &live_sources {
            if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                sm.register_source(hash_bytes, v4, *port);
            }
        }
    }
    // D9: dedup by (ip, port) before handing sources to the downloader so
    // we don't spawn two concurrent handshakes to the same peer (common
    // when a source is discovered via both the server list and SX/KAD).
    let download_sources: Vec<DownloadSource> = {
        let sm = source_manager.read().await;
        let mut seen: HashSet<(String, u16)> = HashSet::new();
        let mut out: Vec<DownloadSource> = Vec::with_capacity(live_sources.len());
        for (ip, port) in &live_sources {
            if !seen.insert((ip.clone(), *port)) {
                continue;
            }
            let uh = ip.parse::<Ipv4Addr>().ok()
                .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
            let co = ip.parse::<Ipv4Addr>().ok()
                .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
            out.push(DownloadSource {
                peer_ip: ip.clone(),
                peer_port: *port,
                available_parts: Vec::new(),
                peer_user_hash: uh,
                peer_connect_options: co,
            });
        }
        out
    };
    let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
    // Parallel channel for pre-handshaked peer streams. Sized small —
    // it only sees inbound LowID callbacks for files we're actively
    // downloading, which is naturally rate-limited by NAT-traversal
    // round-trips.
    let (est_inject_tx, est_inject_rx) =
        mpsc::channel::<ed2k::multi_source::EstablishedSource>(8);
    let ms_download = MultiSourceDownload {
        transfer_id: pending.transfer_id,
        file_hash: hash_bytes,
        file_name: pending.file_name,
        file_size: pending.file_size,
        sources: download_sources,
        download_dir: PathBuf::from(&settings.download_folder),
        user_hash: state.user_hash,
        nickname: settings.nickname.clone(),
        tcp_port: settings.tcp_port,
        udp_port: settings.udp_port,
        bandwidth_limiter: bandwidth_limiter.clone(),
        control: pending.control,
        source_manager: Some(source_manager.clone()),
        comment_manager: Some(state.comment_manager.clone()),
        credit_manager: Some(credit_manager.clone()),
        shared_buddy_info: Some(state.shared_buddy_info.clone()),
        obfuscation_enabled: state.obfuscation_enabled,
        server_addr: state.server_addr,
        new_source_rx: Some(src_inject_rx),
        new_established_rx: Some(est_inject_rx),
                        ed2k_limits: settings.ed2k_download_limits(),
                        ember_hash,
                        friend_hashes: Some(friend_hashes.clone()),
        ember_payload: shared_ember_payload.clone(),
        ember_payload_generation: ember_payload_generation.clone(),
        ip_filter: Some(state.shared_ip_filter.clone()),
        banned_ips: Some(shared_banned_ips.clone()),
        external_ip: state.external_ip,
        aich_pending: Some(state.aich_recovery_pending.clone()),
        geoip: geoip.clone(),
        tracker_registry: Some(state.tracker_registry.clone()),
        sx_overhead: sx_overhead.clone(),
    };
    let dl_tid = ms_download.transfer_id.clone();
    let dl_tid2 = dl_tid.clone();
    info!(
        "Starting download {} ({}) with {} source(s) [try_start_from_known]",
        dl_tid, hex::encode(hash_bytes), live_sources.len()
    );
    state.active_source_senders.insert(dl_tid.clone(), src_inject_tx);
    state.active_established_senders.insert(dl_tid.clone(), est_inject_tx);
    let tx = dl_event_tx.clone();
    let tx2 = tx.clone();
    if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
        warn!("Aborting existing download task for {dl_tid2} before starting multi-source download");
        old_handle.abort();
    }
    let handle = tokio::spawn(async move {
        if let Err(e) = ms_download.run(tx).await {
            error!("Multi-source download failed: {e}");
            let kind = classify_error(&e.to_string());
            let _ = tx2.send(DownloadEvent::Failed { transfer_id: dl_tid, error: e.to_string(), failure_kind: kind }).await;
        }
    });
    state.download_handles.insert(dl_tid2, handle);

    true
}

fn kad_contacts_snapshot(state: &NetworkState, local_id: KadId) -> Vec<KadContactInfo> {
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

fn kad_searches_snapshot(state: &NetworkState) -> Vec<KadSearchInfo> {
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
                    .and_then(|(tid, _)| state.pending_downloads.get(tid).map(|pd| pd.file_name.clone()))
                    .unwrap_or_else(|| "Source Search".to_string()),
                SearchType::FindBuddy => "Find Buddy".to_string(),
                _ => String::new(),
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
            let load_pct = if queried == 0 { 0 } else { (responded * 100) / queried };
            KadSearchInfo {
                id: sid.0,
                target: search.target.to_hex(),
                search_type: type_name.to_string(),
                name,
                status: if search.completed { "stopping".to_string() } else { "active".to_string() },
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

async fn peers_snapshot(state: &NetworkState, db: &Arc<Database>) -> Vec<PeerInfo> {
    let mut peers: Vec<PeerInfo> = state
        .routing_table
        .all_contacts()
        .take(200)
        .map(|contact| PeerInfo {
            id: contact.id.to_hex(),
            addresses: vec![format!("{}:{}", contact.ip, contact.udp_port)],
            nickname: state.peer_nicknames.get(&contact.id).cloned().unwrap_or_default(),
            last_seen: contact.last_seen,
            files_shared: 0,
            banned: false,
        })
        .collect();

    let saved_peers = tokio::task::spawn_blocking({
        let db = db.clone();
        move || db.get_peers().unwrap_or_default()
    })
    .await
    .unwrap_or_default();

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
fn ident_state_label(state: ed2k::credits::IdentState) -> &'static str {
    use ed2k::credits::IdentState;
    match state {
        IdentState::Verified => "Verified",
        IdentState::Failed => "Failed",
        IdentState::BadGuy => "BadGuy",
        IdentState::Needed => "Needed",
        IdentState::Unknown => "Unknown",
    }
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
async fn upload_queue_snapshot(
    queue: &ed2k::upload::UploadQueueRef,
    credit_manager: &Arc<RwLock<ed2k::credits::CreditManager>>,
    local_index: &Arc<RwLock<LocalIndex>>,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    geoip: &crate::geoip::GeoIpReader,
) -> Vec<crate::types::UploadQueueClient> {
    // Snapshot the queue under a short-lived lock so we don't hold the
    // upload server's mutex while we're awaiting other RwLocks (which
    // could otherwise deadlock against `start_uploading_to_peer`).
    let queue_snapshot: Vec<ed2k::upload::QueueEntry> = {
        let q = queue.lock().await;
        q.clone()
    };
    if queue_snapshot.is_empty() {
        return Vec::new();
    }
    let cm = credit_manager.read().await;
    let idx = local_index.read().await;
    let friends = friend_hashes.read().await;

    let mut out = Vec::with_capacity(queue_snapshot.len());
    for entry in &queue_snapshot {
        let wait_secs = entry.join_time.elapsed().as_secs();
        let score = ed2k::upload::score_queue_entry(
            &cm,
            &idx,
            &entry.user_hash,
            entry.file_hash,
            wait_secs,
            entry.current_addr,
            entry.emule_version,
            entry.is_friend_slot,
        );
        let rank = ed2k::upload::compute_queue_rank(
            &cm,
            &idx,
            &queue_snapshot,
            &entry.identity,
            score,
            entry.join_time,
        );
        // Treat "no current connection" as no rank — matches eMule's UI
        // where a queued LowID waiting for callback shows '?' instead of
        // a number until they reconnect.
        let queue_rank: Option<u32> = if entry.current_addr.is_some() {
            Some(rank as u32)
        } else {
            None
        };

        let (peer_ip_str, peer_port, peer_ip_v4) = match entry.current_addr {
            Some(addr) => {
                let v4 = match addr.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                (addr.ip().to_string(), addr.port(), v4)
            }
            None => match &entry.identity {
                ed2k::upload::QueueIdentity::Ip(ip) => {
                    let v4 = match ip {
                        std::net::IpAddr::V4(v4) => Some(*v4),
                        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                    };
                    (ip.to_string(), 0u16, v4)
                }
                ed2k::upload::QueueIdentity::UserHash(_) => (String::new(), 0u16, None),
            },
        };
        let peer_ip_u32 = peer_ip_v4
            .map(|v4| u32::from_be_bytes(v4.octets()))
            .unwrap_or(0);
        let credit_ratio = cm.get_score_ratio(&entry.user_hash, peer_ip_u32);
        let ident_state = ident_state_label(
            cm.get_current_ident_state(&entry.user_hash, peer_ip_u32),
        ).to_string();
        let (uploaded, downloaded) = cm
            .get_record(&entry.user_hash)
            .map(|r| (r.uploaded, r.downloaded))
            .unwrap_or((0, 0));

        let file_hash_hex = hex::encode(entry.file_hash);
        let file_name = idx
            .get_by_hash(&file_hash_hex)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| String::from("(unknown file)"));

        let country_code = peer_ip_v4
            .map(|v4| std::net::IpAddr::V4(v4))
            .and_then(|ip| crate::geoip::lookup_country(geoip, ip));

        let user_hash_hex = if entry.user_hash == [0u8; 16] {
            String::new()
        } else {
            hex::encode(entry.user_hash)
        };
        let is_friend = entry.user_hash != [0u8; 16] && friends.contains(&entry.user_hash);

        out.push(crate::types::UploadQueueClient {
            user_hash: user_hash_hex,
            peer_ip: peer_ip_str,
            peer_port,
            file_hash: file_hash_hex,
            file_name,
            wait_seconds: wait_secs,
            queue_rank,
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
/// connected right now.
async fn known_clients_snapshot(
    credit_manager: &Arc<RwLock<ed2k::credits::CreditManager>>,
    geoip: &crate::geoip::GeoIpReader,
) -> Vec<crate::types::KnownClient> {
    let cm = credit_manager.read().await;
    let mut out: Vec<crate::types::KnownClient> = cm
        .all_records()
        .iter()
        .map(|record| {
            let ident_state = ident_state_label(
                cm.get_current_ident_state(&record.user_hash, record.ident_ip),
            ).to_string();
            let credit_ratio = cm.get_score_ratio(&record.user_hash, record.ident_ip);
            let last_known_ip = if record.ident_ip != 0 {
                let octets = record.ident_ip.to_be_bytes();
                Some(std::net::Ipv4Addr::from(octets).to_string())
            } else {
                None
            };
            let country_code = if record.ident_ip != 0 {
                let octets = record.ident_ip.to_be_bytes();
                let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets));
                crate::geoip::lookup_country(geoip, ip)
            } else {
                None
            };
            crate::types::KnownClient {
                user_hash: hex::encode(record.user_hash),
                downloaded: record.downloaded,
                uploaded: record.uploaded,
                credit_ratio,
                last_seen: record.last_seen,
                ident_state,
                last_known_ip,
                country_code,
                has_public_key: !record.public_key.is_empty(),
            }
        })
        .collect();
    // Stable, useful default order: most-recently-seen first. The UI
    // can re-sort by any column.
    out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    out
}

// ----- AntiLeech filter command helpers ----------------------------
//
// All four helpers run on the network task (synchronous; the
// `parking_lot` lock around the filter is non-blocking) so the upload
// hot path can never observe a half-applied state.

fn antileech_file_path(state: &NetworkState) -> std::path::PathBuf {
    state
        .data_dir
        .join(crate::security::antileech::DEFAULT_FILE_NAME)
}

fn antileech_snapshot(state: &NetworkState) -> crate::types::AntiLeechSnapshot {
    let f = state.antileech.read();
    crate::types::AntiLeechSnapshot {
        enabled: f.enabled(),
        patterns: f.patterns().to_vec(),
        file_path: antileech_file_path(state).to_string_lossy().to_string(),
        pattern_count: f.pattern_count() as u32,
    }
}

fn antileech_set_patterns(
    state: &NetworkState,
    patterns: Vec<String>,
) -> Result<crate::types::AntiLeechReplaceResult, String> {
    let errors = {
        let mut f = state.antileech.write();
        f.replace_patterns(patterns)
    };
    {
        let f = state.antileech.read();
        if let Err(e) = f.save_to_file(&antileech_file_path(state)) {
            return Err(format!("Filter updated in memory but persist failed: {e}"));
        }
    }
    Ok(crate::types::AntiLeechReplaceResult {
        snapshot: antileech_snapshot(state),
        compile_errors: errors
            .into_iter()
            .map(|(p, e)| (p, e.to_string()))
            .collect(),
    })
}

fn antileech_set_enabled(state: &NetworkState, enabled: bool) -> Result<(), String> {
    {
        let mut f = state.antileech.write();
        f.set_enabled(enabled);
    }
    Ok(())
}

fn antileech_reset_defaults(
    state: &NetworkState,
) -> Result<crate::types::AntiLeechSnapshot, String> {
    let was_enabled = state.antileech.read().enabled();
    let defaults = crate::security::antileech::AntiLeechFilter::with_defaults(was_enabled);
    {
        let mut f = state.antileech.write();
        *f = defaults;
    }
    {
        let f = state.antileech.read();
        if let Err(e) = f.save_to_file(&antileech_file_path(state)) {
            return Err(format!("Defaults restored in memory but persist failed: {e}"));
        }
    }
    Ok(antileech_snapshot(state))
}

pub async fn start_network(
    app_handle: tauri::AppHandle,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    mut settings: AppSettings,
    local_index: Arc<RwLock<LocalIndex>>,
    db: Arc<Database>,
    transfer_manager: Arc<RwLock<TransferManager>>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    shared_peers: Arc<RwLock<Vec<PeerInfo>>>,
    shared_stats: Arc<RwLock<NetworkStats>>,
    shared_contacts: Arc<RwLock<Vec<KadContactInfo>>>,
    shared_searches: Arc<RwLock<Vec<KadSearchInfo>>>,
    shared_servers: Arc<RwLock<Vec<ServerInfo>>>,
    shared_connected_server: Arc<RwLock<Option<ServerInfo>>>,
    shared_transfer_stats: Arc<RwLock<TransferStats>>,
    shared_files: Arc<RwLock<Vec<FileInfo>>>,
    upload_shared_folders: crate::app_state::SharedFolderList,
    friend_hashes: crate::app_state::SharedFriendHashes,
    uss_rtt_queue: crate::bandwidth::UssRttQueue,
    uss_enabled_flag: crate::bandwidth::UssEnabledFlag,
    spam_filter: Arc<RwLock<crate::search::spam::SpamFilter>>,
) -> anyhow::Result<()> {
    let data_dir = directories::ProjectDirs::from("com", "ember", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&data_dir)?;

    let geoip = {
        let resource_dir = app_handle.path().resource_dir().unwrap_or_else(|_| PathBuf::from("."));
        crate::geoip::load(&resource_dir)
    };

    let identity = crate::storage::identity::NodeIdentity::load_or_create(&data_dir)?;
    let local_id = identity.kad_id();
    let user_hash = identity.user_hash;
    let ember_hash = identity.ember_hash;
    let ed25519_pubkey = identity.ed25519_public_key;
    let ed25519_secret_key = identity.ed25519_secret_key;
    info!("Local KAD ID: {}…", &local_id.to_hex()[..8]);

    let tcp_port = settings.tcp_port;
    let udp_port = settings.udp_port;

    let candidate_ports: Vec<u16> = {
        let mut ports = vec![udp_port];
        for offset in 1..=4u16 {
            let p = udp_port.saturating_add(offset);
            if p != udp_port && p != 0 {
                ports.push(p);
            }
        }
        ports.push(0); // OS-assigned as last resort
        ports
    };
    let mut udp_socket: Option<UdpSocket> = None;
    let mut bound_udp_port = udp_port;
    let mut last_bind_err = String::new();
    for &candidate in &candidate_ports {
        let sock2 = match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to create UDP socket: {e}");
                let _ = app_handle.emit("network-error", serde_json::json!({
                    "message": format!("Failed to create UDP socket: {e}"),
                }));
                anyhow::bail!("Failed to create UDP socket: {e}");
            }
        };
        let _ = sock2.set_recv_buffer_size(1024 * 1024);
        sock2.set_nonblocking(true)?;
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), candidate);
        if let Err(e) = sock2.bind(&socket2::SockAddr::from(addr)) {
            last_bind_err = format!("port {candidate}: {e}");
            if candidate == udp_port {
                warn!("UDP port {candidate} in use, trying fallback ports");
            } else {
                debug!("UDP fallback port {candidate} also in use: {e}");
            }
            continue;
        }
        let std_sock = std::net::UdpSocket::from(sock2);
        bound_udp_port = std_sock.local_addr().map(|a| a.port()).unwrap_or(candidate);
        udp_socket = Some(UdpSocket::from_std(std_sock)?);
        break;
    }
    let udp_socket = match udp_socket {
        Some(s) => s,
        None => {
            let msg = format!(
                "Could not bind any UDP port (tried {} through {}, then OS-assigned). Last error: {last_bind_err}",
                udp_port,
                udp_port.saturating_add(4),
            );
            error!("{msg}");
            let _ = app_handle.emit("network-error", serde_json::json!({ "message": msg }));
            anyhow::bail!("{msg}");
        }
    };
    let udp_port = bound_udp_port;
    if udp_port != settings.udp_port {
        warn!("Configured UDP port {} was unavailable, bound to port {} instead", settings.udp_port, udp_port);
        let _ = app_handle.emit("network-warning", serde_json::json!({
            "message": format!("UDP port {} was in use. Using port {} instead.", settings.udp_port, udp_port),
        }));
    }
    info!("UDP socket bound on port {udp_port}");

    // The connection broker binds a *second* UDP socket for QUIC on the
    // configured `tcp_port`. If the user happens to set `tcp_port ==
    // udp_port` (an easy mistake — old eMule habit, or copy-paste of
    // the same number into both fields), QUIC will fail to bind to that
    // port and `build_server_client_endpoint` will fall back to a
    // neighbour. Warn loudly here so the user can either tolerate the
    // fallback or pick distinct ports.
    if settings.tcp_port == settings.udp_port {
        warn!(
            "Configured tcp_port and udp_port are identical ({}). \
             QUIC will be unable to bind that port (Kad UDP got there first) \
             and will fall back to a neighbouring port. Set them to distinct \
             values in Settings to silence this warning.",
            settings.tcp_port,
        );
    }

    let mut routing_table = RoutingTable::new(local_id, settings.block_private_ips);
    let search_manager = SearchManager::new();
    let publish_manager = PublishManager::new(local_id, user_hash, tcp_port, udp_port);

    // Load bootstrap contacts from the app's own nodes.dat.
    // K3: if the file format is the older "no verified bit" variant we
    // can safely trust its contents (the user saved it from a previous
    // live session — not an attacker-supplied URL). For the modern
    // format, respect the per-contact verified byte on the wire.
    let nodes_dat_path = data_dir.join("nodes.dat");
    let mut boot_contacts = if nodes_dat_path.exists() {
        match bootstrap::load_nodes_dat_with_format(&nodes_dat_path) {
            Ok((mut cs, bootstrap::NodesDatFormat::LegacyNoVerified)) => {
                for c in &mut cs {
                    c.verified = true;
                }
                if !cs.is_empty() {
                    info!(
                        "Trusting {} contacts from legacy (no-verified-bit) on-disk nodes.dat",
                        cs.len()
                    );
                }
                cs
            }
            Ok((cs, bootstrap::NodesDatFormat::WithVerifiedBit)) => cs,
            Err(e) => {
                warn!("Failed to load nodes.dat: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Load saved peers from database to supplement contacts and extract banned IPs
    let saved_db_peers = db.get_peers().unwrap_or_default();
    {
        let peer_count = saved_db_peers.len();
        for peer in &saved_db_peers {
            if peer.banned {
                continue;
            }
            if let Some(addr_str) = peer.addresses.first() {
                if let Some((ip_str, port_str)) = addr_str.rsplit_once(':') {
                    if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                        if let Some(kad_id) = KadId::from_hex(&peer.id) {
                            boot_contacts.push(KadContact {
                                id: kad_id,
                                ip,
                                udp_port: port.saturating_add(10),
                                tcp_port: port,
                                version: KADEMLIA_VERSION,
                                last_seen: peer.last_seen,
                                verified: false,
                                contact_type: CONTACT_TYPE_NEW,
                                udp_key: None,
                                kad_options: 0,
                                created_at: peer.last_seen,
                                expires_at: 0,
                                last_type_set: 0,
                                received_hello: false,
                            });
                        }
                    }
                }
            }
        }
        if peer_count > 0 {
            info!("Loaded {peer_count} peers from database");
        }
    }

    if boot_contacts.is_empty() {
        info!("No nodes.dat found, using hardcoded bootstrap nodes");
        boot_contacts = bootstrap::default_bootstrap_contacts();
    }

    let now = chrono::Utc::now().timestamp();
    for c in &boot_contacts {
        let mut contact = c.clone();
        // Give loaded contacts a recent last_seen so remove_stale() doesn't
        // immediately discard them before they have a chance to respond.
        if contact.last_seen == 0 {
            contact.last_seen = now;
        }
        routing_table.insert(contact);
    }

    // K3: the earlier heuristic — "if no contact in the loaded file is
    // verified, mass-promote them all" — runs per-file without the caller
    // knowing whether the file format was capable of carrying verified
    // bits. That meant a handcrafted file (including one fetched via URL
    // bootstrap) could bypass verification entirely. We now gate this
    // promotion on the real format version; see `load_local_nodes_dat`
    // which does the load + format-aware promotion in one place for the
    // on-disk file, and URL-bootstrap paths never take this shortcut.

    info!(
        "Routing table initialized with {} contacts",
        routing_table.len()
    );

    let _ = app_handle.emit("network-status", NetworkStatus::Connecting);

    let upnp_enabled = settings.upnp_enabled;

    // Run UPnP setup and IP filter load concurrently since they're independent
    let mut upnp_mappings = upnp::UpnpMappings::new(tcp_port, udp_port);
    let ipfilter_path = data_dir.join("ipfilter.dat");
    let ipf_enabled = settings.ip_filter_enabled;
    let ipf_block_private = settings.block_private_ips;
    let ipf_path = ipfilter_path.clone();

    let (upnp_success, ip_filter) = tokio::join!(
        async {
            if upnp_enabled {
                upnp_mappings.setup().await;
                let mapped = upnp_mappings.is_mapped();
                if mapped {
                    info!("UPnP port mapping succeeded -- not firewalled");
                }
                mapped
            } else {
                info!("UPnP disabled by user -- skipping port mapping");
                false
            }
        },
        async {
            let mut filter = IpFilter::new(ipf_enabled, ipf_block_private);
            if ipf_enabled && ipf_path.exists() {
                filter.load_from_file(&ipf_path);
            }
            filter
        },
    );
    let shared_ip_filter = ip_filter.create_shared_snapshot();
    routing_table.set_ip_filter(shared_ip_filter.clone());

    let mut dht_store = DhtStore::new();
    dht_store.set_local_id(local_id);

    let udp_key_seed = identity.udp_key_seed;
    let pending_buddy_hashes: PendingBuddySet = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let buddy_manager = BuddyManager::new(local_id, user_hash, settings.nickname.clone(), tcp_port, udp_port, pending_buddy_hashes.clone());
    let shared_buddy_info: upload_server::SharedBuddyInfo = std::sync::Arc::new(tokio::sync::RwLock::new(None));
    info!(
        "IP filter: enabled={}, block_private={}, ranges={}",
        ip_filter.is_enabled(),
        ip_filter.blocks_private(),
        ip_filter.range_count(),
    );

    // Extract banned peer IPs from the already-loaded peer list
    let banned_ips: HashSet<Ipv4Addr> = saved_db_peers
        .iter()
        .filter(|p| p.banned)
        .filter_map(|p| {
            p.addresses.first().and_then(|addr| {
                addr.rsplit_once(':')
                    .and_then(|(ip, _)| ip.parse().ok())
            })
        })
        .collect();

    // Extract banned user hashes for upload-only enforcement
    let banned_hashes: HashSet<[u8; 16]> = saved_db_peers
        .iter()
        .filter(|p| p.banned && p.id.len() == 32 && p.id.chars().all(|c| c.is_ascii_hexdigit()))
        .filter_map(|p| {
            hex::decode(&p.id).ok().and_then(|bytes| {
                if bytes.len() == 16 {
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(&bytes);
                    Some(arr)
                } else {
                    None
                }
            })
        })
        .collect();

    drop(saved_db_peers);
    if !banned_ips.is_empty() {
        info!("Loaded {} banned peer IPs", banned_ips.len());
    }
    if !banned_hashes.is_empty() {
        info!("Loaded {} banned user hashes", banned_hashes.len());
    }

    let shared_banned_ips: ed2k::upload::SharedBannedIps =
        Arc::new(std::sync::RwLock::new(banned_ips.clone()));
    let shared_banned_hashes: ed2k::upload::SharedBannedHashes =
        Arc::new(std::sync::RwLock::new(banned_hashes));

    // AntiLeech client-software filter — eMule's `AntiLeech.dat`
    // equivalent. Loads from `<data_dir>/antileech.dat` (seeded with the
    // built-in defaults the first time the file doesn't exist), then
    // wraps in a `parking_lot::RwLock` so the upload server can hot-read
    // on every handshake while the settings UI hot-swaps the pattern
    // list. The filter is disabled by default — users have to opt in
    // via Settings — to avoid surprising regressions for anyone who
    // didn't ask for it. The defaults are conservative regardless.
    let shared_antileech: crate::security::antileech::SharedAntiLeechFilter = {
        let initial = crate::security::antileech::load_or_seed_defaults(
            &data_dir,
            settings.antileech_enabled,
        );
        Arc::new(parking_lot::RwLock::new(initial))
    };

    let comment_manager = Arc::new(RwLock::new(CommentManager::new()));

    // Load the persisted server list from `<data_dir>/server.met` so
    // servers discovered via OP_SERVERLIST, manually added, or merged
    // from a downloaded server.met survive across restarts. If the
    // file is missing (first launch) or fails to parse (corruption /
    // older format), fall back to the hardcoded seed list so the user
    // still has a working set of bootstrap servers. The seed is also
    // overlaid into the loaded list below so the well-known seeds
    // remain available even if a previous version saved a list that
    // didn't include them.
    let server_list = {
        let met_path = data_dir.join("server.met");
        let mut list = match ServerList::load_server_met(&met_path) {
            Ok(loaded) => loaded,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    info!("No persisted server.met at {:?} — seeding hardcoded list", met_path);
                } else {
                    warn!("Failed to load persisted server.met from {:?}: {} — seeding hardcoded list", met_path, e);
                }
                ServerList::hardcoded()
            }
        };
        // Overlay the hardcoded seeds (idempotent: `add` skips
        // duplicates by ip/port). Without this, a user whose
        // server.met was saved before a seed was added would never
        // see the new seed. The hardcoded list is only 4 entries so
        // the clone cost is negligible.
        let seeds = ServerList::hardcoded();
        for seed in seeds.servers().iter().cloned() {
            list.add(seed);
        }
        list
    };

    let mut state = NetworkState {
        local_id,
        user_hash,
        routing_table,
        search_manager,
        publish_manager,
        dht_store,
        stats: NetworkStats {
            status: if settings.auto_connect_kad { NetworkStatus::Connecting } else { NetworkStatus::Disconnected },
            ..Default::default()
        },
        pending_keyword_searches: HashMap::new(),
        pending_server_search: None,
        active_search_request: None,
        server_search_more_needed: false,
        server_poll_count: 0,
        server_search_age: 0,
        server_udp_search_age: 0,
        udp_search_queue: VecDeque::new(),
        pending_source_searches: HashMap::new(),
        download_source_searches: HashMap::new(),
        pending_downloads: HashMap::new(),
        data_dir: data_dir.clone(),
        external_ip: None,
        external_udp_port: None,
        firewalled: !upnp_success,
        firewall_checks_sent: 0,
        peer_nicknames: HashMap::new(),
        publish_pending: HashMap::new(),
        publish_confirmed: 0,
        publish_res_plain_seen: 0,
        publish_res_obf_decoded: 0,
        obf_decoded_total: 0,
        publish_res_wire: 0,
        publish_res_received: 0,
        publish_res_unmatched: 0,
        source_publish_acks: HashMap::new(),
        store_keyword_searches: HashMap::new(),
        store_source_searches: HashMap::new(),
        pending_notes_searches: HashMap::new(),
        pending_note_publishes: HashMap::new(),
        overloaded_nodes: HashMap::new(),
        flood_protection: FloodProtection::new(),
        buddy_manager,
        udp_key_seed,
        tcp_port,
        udp_port,
        quic_port: None,
        upnp_mapped: upnp_success,
        ip_filter,
        banned_ips,
        obfuscation_enabled: settings.obfuscation_enabled,
        firewalled_shared: Arc::new(std::sync::atomic::AtomicBool::new(!upnp_success)),
        external_ip_shared: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        self_lookup_done: false,
        last_self_lookup: 0,
        kad_started_at: chrono::Utc::now().timestamp(),
        last_kad_contact: None,
        udp_firewalled: true,
        udp_fw_verified: false,
        first_publish_done: false,
        kad_initial_source_burst_done: false,
        friend_presence_initial_done: false,
        server_list,
        server_connected: false,
        server_connection: None,
        server_addr: None,
        udp_source_queue: VecDeque::new(),
        server_tcp_getsources_cursor: 0,
        kad_source_search_cursor: 0,
        dead_sources: DeadSourceList::new(),
        corruption_blackbox: CorruptionBlackBox::new(),
        aich_recovery_pending: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        per_file_sources: HashMap::new(),
        active_kad_search_state: HashMap::new(),
        udp_discovery_sent: 0,
        udp_discovery_send_errs: 0,
        udp_discovery_replies: 0,
        udp_discovery_sources_found: 0,
        active_source_senders: HashMap::new(),
        active_established_senders: HashMap::new(),
        active_source_overflow: HashMap::new(),
        download_handles: HashMap::new(),
        comment_manager: comment_manager.clone(),
        firewall_checker: FirewallChecker::new(),
        low_id: false,
        server_client_id: 0,
        pending_server_connect: None,
        pending_buddy_hashes: pending_buddy_hashes.clone(),
        shared_buddy_info: shared_buddy_info.clone(),
        shared_ip_filter: shared_ip_filter.clone(),
        buddy_event_rx: None,
        serving_event_rx: None,
        pending_outgoing_buddy: None,
        server_auto_reconnect: true,
        server_reconnect_failures: 0,
        server_last_connect_attempt: None,
        pending_uss_pings: HashMap::new(),
        uss_host: None,
        uss_missed_pongs: 0,
        uss_host_selected_at: 0,
        uss_rtt_queue,
        uss_enabled_flag,
        aich_hash_sets: Vec::new(),
        upload_max_slots: Arc::new(std::sync::atomic::AtomicUsize::new(settings.max_concurrent_uploads as usize)),
        ember_payload_dirty: true,
        known_ember_peers: HashMap::new(),
        antileech: shared_antileech.clone(),
        aich_root_map: HashMap::new(),
        callback_buddy_attempts: HashMap::new(),
        firewall_connect_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        firewall_req_cooldown: HashMap::new(),
        online_friends: HashMap::new(),
        ember_sessions: Arc::new(RwLock::new(HashMap::new())),
        upload_disconnected: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        rendezvous_registered: false,
        rendezvous_last_register: None,
        outbound_session_tasks: HashMap::new(),
        friend_search_initial_done: false,
        friend_search_started_at: None,
        friend_reconnect_last: HashMap::new(),
        tracker_registry: Arc::new(std::sync::Mutex::new(HashMap::new())),
        nat_info: ember::nat::NatInfo::unknown(),
        connection_broker: None,
        broker_event_rx: None,
        relay_manager: Arc::new(tokio::sync::Mutex::new(ember::relay::RelayManager::new())),
        reputation: ember::reputation::ReputationManager::load(&data_dir.join("reputation.json")),
        ember_capable_peers: HashSet::new(),
    };

    // Load known files for hash cache
    let known_met_path = data_dir.join("known.met");
    let mut known_files = KnownFileList::load(&known_met_path);
    info!("Loaded {} known files", known_files.file_count());

    // Load AICH hash sets from known2_64.met (eMule SHAHashSet.cpp)
    let known2_met_path = data_dir.join("known2_64.met");
    match ed2k::aich::load_known2_met(&known2_met_path) {
        Ok(sets) => {
            info!("Loaded {} AICH hash sets from known2_64.met", sets.len());
            state.aich_hash_sets = sets.into_iter().map(|(root, leaves)| {
                ed2k::aich::AICHRecoveryHashSet {
                    root_hash: root,
                    leaf_hashes: leaves,
                }
            }).collect();
        }
        Err(e) => {
            if known2_met_path.exists() {
                warn!("Failed to load known2_64.met: {e}");
            }
        }
    };

    // Load ed2k hash → AICH root mapping from cache
    let aich_cache_path = data_dir.join("aich_cache.dat");
    if let Ok(contents) = std::fs::read_to_string(&aich_cache_path) {
        for line in contents.lines() {
            if let Some((ed2k_hex, aich_hex)) = line.split_once('=') {
                if let (Ok(ed2k_bytes), Ok(aich_bytes)) = (hex::decode(ed2k_hex.trim()), hex::decode(aich_hex.trim())) {
                    if ed2k_bytes.len() == 16 && aich_bytes.len() == 20 {
                        let mut fh = [0u8; 16];
                        let mut ah = [0u8; 20];
                        fh.copy_from_slice(&ed2k_bytes);
                        ah.copy_from_slice(&aich_bytes);
                        state.aich_root_map.insert(fh, ah);
                    }
                }
            }
        }
        info!("Loaded {} AICH root mappings from cache", state.aich_root_map.len());
    }

    // Initialize statistics manager
    let mut stats_manager = StatsManager::new();
    stats_manager.load_cumulative(&db);

    // Rate-limit DB persistence of download progress. DownloadEvent::Progress
    // fires many times per second per active download (one per block landing
    // across all sources); the old code ran a synchronous SQLite UPDATE per
    // event inside this main select! loop, serialising the entire network
    // task on the DB mutex. The persisted `transferred / progress / speed`
    // values have no operational use — crash recovery rebuilds them from the
    // `.part.met` via `PartTracker::new` at `start_network` resume, and the
    // live UI reads from `transfer_manager` (commands/transfers.rs).
    // Keep a per-transfer "last persisted at" map and only flush to SQLite
    // once per `DB_PROGRESS_PERSIST_INTERVAL`, plus always at terminal
    // state transitions (handled separately via `update_transfer_status`).
    const DB_PROGRESS_PERSIST_INTERVAL: std::time::Duration =
        std::time::Duration::from_secs(3);
    let mut db_progress_last_persist: HashMap<String, std::time::Instant> = HashMap::new();

    // Load comments from database
    if let Ok(rows) = db.load_file_comments() {
        state.comment_manager.write().await.load_from_db_rows(rows);
    }

    let firewall_probe_ips: upload_server::FirewallProbeSet =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));

    if settings.auto_connect_kad {
        // Send bootstrap requests to initial contacts
        for contact in &boot_contacts {
            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
            let msg = KadMessage::BootstrapReq;
            if let Ok(packet) = messages::encode_packet(&msg) {
                state.flood_protection.track_request(addr, 0x01);
                let _ = send_kad_packet(&udp_socket, &packet, addr, &state, &contact.id).await;
                debug!("Sent bootstrap req to {addr}");
            }
        }

        // Firewall check is deferred to the periodic bootstrap_timer recheck,
        // which fires once we have verified contacts (table_size >= 10).
    } else {
        info!("KAD auto-connect disabled, skipping bootstrap (use Connect to start KAD)");
    }

    // Download / upload event channels.
    //
    // Capacity bumped from 128 → 4096. Per-block events
    // (DownloadEvent::Progress and DataReceived) flow through this single
    // queue from every active source on every active transfer; with N
    // concurrent transfers and ~10 sources each, 128 was easily filled
    // while the consumer was awaiting `transfer_manager.write()` or the
    // Tauri webview emit, back-pressuring every download coroutine on
    // `dl_event_tx.send().await`. 4096 keeps the queue absorbent without
    // hiding a stuck consumer.
    let (dl_event_tx, mut dl_event_rx) = mpsc::channel::<DownloadEvent>(4096);

    let (ul_event_tx, mut ul_event_rx) = mpsc::channel::<UploadEvent>(4096);

    // Buddy connection channel (upload listener sends recognized buddy connections here)
    let (buddy_conn_tx, mut buddy_conn_rx) = mpsc::channel::<upload_server::BuddyConnectionParts>(4);

    // Callback connection channel: upload listener sends firewalled sources that
    // connected back (both KAD buddy callbacks and server LowID callbacks).
    let (kad_callback_tx, mut kad_callback_rx) = mpsc::channel::<upload_server::KadCallbackParts>(32);
    let (udp_fw_check_tx, mut udp_fw_check_rx) = mpsc::channel::<upload_server::UdpFirewallCheckRequest>(16);
    let pending_kad_callbacks: upload_server::PendingKadCallbacks =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let source_manager: Arc<RwLock<SourceManager>> = {
        let mut sm = SourceManager::new();
        sm.set_max_per_file(settings.max_sources_per_file);
        Arc::new(RwLock::new(sm))
    };

    // Load credits from DB (primary) and clients.met (fallback), persist RSA keypair
    let credit_manager: Arc<RwLock<CreditManager>> = {
        let mut cm = CreditManager::new();
        cm.load_or_create_keypair(&data_dir);
        if let Ok(records) = db.load_credits() {
            for (hash, uploaded, downloaded, last_seen, public_key) in records {
                // `get_or_create` bumps `last_seen` to "now" — the right
                // behaviour for live mutations but wrong on a startup
                // load. The explicit `record.last_seen = last_seen`
                // overwrite below restores the persisted timestamp
                // before the cleanup below so the 90-day prune sees the
                // real ages. Don't reorder these lines without also
                // splitting the helper.
                let record = cm.get_or_create(hash);
                record.uploaded = uploaded;
                record.downloaded = downloaded;
                record.last_seen = last_seen;
                record.public_key = public_key;
            }
            info!("Loaded {} credit records from database", cm.all_records().len());
        }
        let clients_met = data_dir.join("clients.met");
        if clients_met.exists() && cm.all_records().is_empty() {
            match cm.load_from_file(&clients_met) {
                Ok(n) => info!("Loaded {n} credit records from clients.met"),
                Err(e) => debug!("Could not load clients.met: {e}"),
            }
        }
        // Prune anything older than the 90-day cutoff right now instead
        // of waiting for the first `credit_save_timer` tick (60 s in).
        // Without this, the Known Clients tab would render with stale
        // rows for the first minute of every session — annoying when
        // the user just wants to see their current peer ledger. The
        // periodic prune at `credit_save_timer` still runs, but this
        // makes the steady state correct from second one.
        let pruned_before = cm.all_records().len();
        cm.cleanup_stale(90);
        let pruned_after = cm.all_records().len();
        if pruned_before != pruned_after {
            info!(
                "Pruned {} stale credit record(s) on startup (now {})",
                pruned_before - pruned_after,
                pruned_after
            );
        }
        Arc::new(RwLock::new(cm))
    };

    let a4af_shared: Arc<RwLock<A4AFManager>> = Arc::new(RwLock::new(A4AFManager::new()));
    let pending_dl_hashes: Arc<RwLock<Vec<[u8; 16]>>> = Arc::new(RwLock::new(Vec::new()));
    let active_port_tests: Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, mpsc::Sender<()>>>> = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let shared_server_addr: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));
    let shared_ember_payload: ember::SharedEmberPayload = Arc::new(RwLock::new(Arc::new(Vec::new())));
    let ember_payload_generation: ember::EmberPayloadGeneration = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Upload queue shared between the upload listener (owner/writer) and
    // the UDP reask-ack handler (reader that needs to answer the real queue
    // rank for a peer pinging us over UDP). Holding the shared handle here
    // avoids a placeholder 0 rank reply.
    let upload_queue_handle: ed2k::upload::UploadQueueRef =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // Start the peer-to-peer upload listener (accepts incoming file requests from other KAD peers)
    {
        let ul_tx = ul_event_tx.clone();
        let ul_index = local_index.clone();
        let ul_transfers = transfer_manager.clone();
        let ul_bw = bandwidth_limiter.clone();
        let ul_folders = upload_shared_folders.clone();
        let ul_nickname = settings.nickname.clone();
        let ul_app = app_handle.clone();
        let ul_max = state.upload_max_slots.clone();
        let ul_sm = source_manager.clone();
        let ul_comments = state.comment_manager.clone();
        let ul_cm = credit_manager.clone();
        let ul_a4af = a4af_shared.clone();
        let ul_pdh = pending_dl_hashes.clone();
        let ul_apt = active_port_tests.clone();
        let ul_buddy_hashes = pending_buddy_hashes.clone();
        let ul_buddy_tx = buddy_conn_tx.clone();
        let ul_buddy_info = shared_buddy_info.clone();
        let ul_ip_filter = shared_ip_filter.clone();
        let ul_banned = shared_banned_ips.clone();
        let ul_banned_hashes = shared_banned_hashes.clone();
        let ul_antileech = shared_antileech.clone();
        let ul_skip_compress = settings.skip_compress_video;
        let ul_download_folder = settings.download_folder.clone();
        let ul_fw_probes = firewall_probe_ips.clone();
        let ul_fw_shared = state.firewalled_shared.clone();
        let ul_ext_ip_shared = state.external_ip_shared.clone();
        let ul_kad_cbs = pending_kad_callbacks.clone();
        let ul_kad_cb_tx = kad_callback_tx.clone();
        let ul_udp_fw_tx = udp_fw_check_tx.clone();
        let ul_server_addr = shared_server_addr.clone();
        let ul_friends = friend_hashes.clone();
        let ul_ember = shared_ember_payload.clone();
        let ul_ember_gen = ember_payload_generation.clone();
        let ul_geoip = geoip.clone();
        let ul_ember_sessions = state.ember_sessions.clone();
        let ul_disconnected = state.upload_disconnected.clone();
        let ul_queue = upload_queue_handle.clone();
        let ul_sx_overhead = stats_manager.sx_counters.clone();
        tokio::spawn(async move {
            if let Err(e) = upload_server::start_upload_server(
                tcp_port,
                user_hash,
                ul_nickname,
                udp_port,
                ul_folders,
                PathBuf::from(&ul_download_folder),
                ul_index,
                ul_transfers,
                ul_bw,
                ul_tx,
                ul_max,
                ul_sm,
                ul_comments,
                ul_cm,
                ul_a4af,
                ul_pdh,
                ul_apt,
                ul_buddy_hashes,
                ul_buddy_tx,
                ul_buddy_info,
                ul_ip_filter,
                ul_banned,
                ul_banned_hashes,
                ul_antileech,
                ul_skip_compress,
                settings.filter_incoming_connections,
                ul_fw_probes,
                ul_fw_shared,
                ul_ext_ip_shared,
                ul_kad_cbs,
                ul_kad_cb_tx,
                ul_udp_fw_tx,
                settings.obfuscation_enabled,
                ul_server_addr,
                ul_friends,
                ul_ember,
                ul_ember_gen,
                ul_geoip,
                ul_ember_sessions,
                ember_hash,
                ul_disconnected,
                ul_queue,
                ul_sx_overhead,
            )
            .await
            {
                error!("Upload listener error: {e}");
                let _ = ul_app.emit("network-error", serde_json::json!({
                    "message": format!("TCP port {tcp_port} is already in use. Uploads will not work. Change the port in Settings or close the other application."),
                }));
            }
        });
    }

    let mut udp_buf = vec![0u8; 65535];

    // Bind a separate UDP socket for ed2k server status pings.
    // Servers respond on their TCP port + 4; we can use any local port.
    let mut server_udp = ServerUdpSocket::from_socket(
        tokio::net::UdpSocket::bind("0.0.0.0:0").await?,
    );
    let mut server_udp_ping_idx: usize = 0;

    // Use MissedTickBehavior::Skip on ALL timers so that slow loop iterations
    // (common in debug builds) never cause burst catch-up that starves other
    // tokio tasks (including Tauri IPC handlers → UI navigation freezes).
    use tokio::time::MissedTickBehavior;

    let mut bootstrap_timer = tokio::time::interval(std::time::Duration::from_secs(10));
    bootstrap_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut bootstrap_attempts: u32 = 0;
    let mut publish_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    publish_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Publish health heartbeat: 60s is too coarse to debug the publish
    // ack pipeline. The full `Publish cycle:` log fires *before* the
    // cycle's publishes are dispatched (it's the first thing the timer
    // arm does), so a single snapshot at the 60s mark always shows
    // "0 confirmed" even when acks are flowing fine — you have to wait
    // 120s for a useful number. This faster heartbeat fires every 10s
    // and only logs when at least one publish-related counter has
    // changed since the last beat, so it's quiet at idle but surfaces
    // problems in seconds during active publishing.
    let mut publish_health_timer = tokio::time::interval(std::time::Duration::from_secs(10));
    publish_health_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Snapshot of the diagnostic counters as of the last health log,
    // so we can print "since last beat" deltas instead of monotonic
    // totals (which look like the same number cycle after cycle).
    let mut last_publish_health: PublishHealthSnapshot = PublishHealthSnapshot::default();
    // UDP source-discovery heartbeat: same 30s cadence, only logs
    // when at least one counter has moved since the last beat. Lets
    // the user verify UDP source-asking is actually flowing instead
    // of having to enable debug logging.
    let mut udp_discovery_health_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    udp_discovery_health_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_udp_discovery_health: UdpDiscoveryHealthSnapshot = UdpDiscoveryHealthSnapshot::default();
    let mut search_poll_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    search_poll_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // eMule UDPSEARCHSPEED = SEC2MS(3)/4 = 750ms: send one UDP search per tick
    let mut udp_search_timer = tokio::time::interval(std::time::Duration::from_millis(750));
    udp_search_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Pacing for UDP source requests: eMule sends ~1 per second during its global sweep
    let mut udp_source_timer = tokio::time::interval(std::time::Duration::from_millis(1000));
    udp_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut cleanup_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    cleanup_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut small_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    small_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // eMule main loop calls Kademlia::Process very frequently; ~100ms matches typical tick cadence.
    let mut kad_process_timer = tokio::time::interval(std::time::Duration::from_millis(100));
    kad_process_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // eMule Kademlia::Process: Consolidate() every MIN2S(45), not 45 minutes
    let mut consolidate_timer = tokio::time::interval(std::time::Duration::from_secs(45));
    consolidate_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut buddy_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    buddy_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut flood_cleanup_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    flood_cleanup_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut source_retry_timer = tokio::time::interval(std::time::Duration::from_secs(5));
    source_retry_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut nodes_save_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    nodes_save_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut cache_refresh_timer = tokio::time::interval(std::time::Duration::from_secs(5));
    cache_refresh_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Persist credits every 60 s so a crash/OOM only loses the last minute
    // of upload credit accumulation instead of the previous 5 minutes. Each
    // save is a single DB transaction plus one atomic clients.met write,
    // which is cheap enough to run at this cadence.
    let mut credit_save_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    credit_save_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut a4af_timer = tokio::time::interval(std::time::Duration::from_secs(480));
    a4af_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut server_timer = tokio::time::interval(std::time::Duration::from_secs(2));
    server_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Was: 5s. Now 200ms. The same arm both (a) sends a status
    // ping to the next server in round-robin order and (b) drains
    // any queued UDP replies via `try_recv_with`. At 5s, replies to
    // a `OP_GLOBGETSOURCES` could sit in the kernel buffer for up
    // to 5 seconds before we noticed — bad latency for source
    // discovery. Pings remain rate-limited *per server* by
    // `MIN_PING_INTERVAL_SECS` (= 5s) inside `send_status_ping`,
    // so the higher tick rate doesn't increase ping traffic — it
    // just makes the recv drain feel like a real event-driven arm.
    // CPU cost per idle tick is one `try_recv_from` syscall (which
    // returns `WouldBlock` instantly when nothing's queued) plus a
    // hashmap lookup for the cooldown — negligible.
    let initial_ping_interval_ms = 200u64;
    let mut server_udp_ping_timer = tokio::time::interval(
        std::time::Duration::from_millis(initial_ping_interval_ms),
    );
    server_udp_ping_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut stats_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    stats_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Persist cumulative stats every minute so an OOM/crash only loses ~60s
    // of transfer counters instead of ~5 min. Writes are a single
    // transactional UPDATE — cheap to do more often.
    let mut stats_save_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    stats_save_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Flush known.met every 2 min when dirty. Previous 11-minute interval
    // left a long window where newly-indexed files / hash updates would be
    // lost on hard-kill.
    let mut known_met_save_timer = tokio::time::interval(std::time::Duration::from_secs(120));
    known_met_save_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut upnp_renew_timer = tokio::time::interval(std::time::Duration::from_secs(50 * 60));
    upnp_renew_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut dead_source_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    dead_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reputation_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    reputation_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reputation_save_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    reputation_save_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut watchdog_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    watchdog_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Broker tick + event drain. Runs at 200 ms so:
    //   * `BrokerEvent::StartPunch` / `StartRelay` posted by
    //     `attempt_low_to_low()` are dispatched into spawned tasks
    //     within a single tick, instead of waiting for the 5-minute
    //     `cleanup_timer` arm where this code used to live (which
    //     was longer than `PUNCH_TIMEOUT` / `RELAY_TIMEOUT`, making
    //     hole-punch and LowID-to-LowID effectively dead).
    //   * `broker.tick()` reaps expired in-flight attempts close to
    //     their nominal 20 s / 30 s timeouts.
    // Idle cost per tick is one `try_recv()` (returns `Empty` instantly)
    // plus a hashmap walk over at most `MAX_ACTIVE_ATTEMPTS` entries.
    let mut broker_timer = tokio::time::interval(std::time::Duration::from_millis(200));
    broker_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // UDP source sweep for active downloads (eMule UDPSERVERREASKTIME = 30 min)
    let mut server_udp_source_timer = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
    server_udp_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut uss_ping_timer = tokio::time::interval(std::time::Duration::from_secs(2));
    uss_ping_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Batch TCP OP_GETSOURCES to connected server (eMule ~4 min ProcessLocalRequests cycle)
    let mut server_tcp_source_timer = tokio::time::interval(std::time::Duration::from_secs(4 * 60));
    server_tcp_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut ember_refresh_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    ember_refresh_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut source_count_sync_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    source_count_sync_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut cache_write_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut last_server_activity_at = chrono::Utc::now().timestamp();
    let mut last_kad_activity_at = chrono::Utc::now().timestamp();
    let mut last_cache_refresh_started_at = 0i64;

    // Resume incomplete downloads from previous session
    if let Ok(incomplete) = db.get_incomplete_downloads() {
        let count = incomplete.len();
        if count > 0 {
            info!("Resuming {count} incomplete downloads from previous session");
            let dl_folder = settings.download_folder.clone();
            for mut transfer in incomplete {
                let control = TransferControl::new();
                if matches!(transfer.status, TransferStatus::Paused | TransferStatus::Stopped) {
                    control.pause();
                }

                // Check .part file for actual progress (part files live in Temp subdir)
                let part_path = PathBuf::from(&dl_folder)
                    .join("Temp")
                    .join(format!("{}.part", transfer.id));
                if part_path.exists() && transfer.total_size > 0 {
                    let tracker = crate::network::ed2k::part_tracker::PartTracker::new(
                        transfer.total_size, &part_path,
                    );
                    let completed_bytes = tracker.completed_bytes();
                    transfer.transferred = completed_bytes;
                    transfer.completed_size = transfer.transferred;
                    transfer.progress = ((transfer.transferred as f64 / transfer.total_size as f64) * 100.0)
                        .min(100.0);
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
                        info!(
                            "Restored download {} was Verifying but .part is gone and final file exists — marking completed",
                            transfer.id
                        );
                        transfer.status = TransferStatus::Completed;
                        transfer.progress = 100.0;
                        transfer.speed = 0;
                        if let Err(e) = db.save_transfer(&transfer) {
                            warn!("DB save_transfer failed for completed transfer {}: {e}", transfer.id);
                        }
                        let mut mgr = transfer_manager.write().await;
                        mgr.completed.push(transfer);
                        continue;
                    }

                    if part_path.exists() && transfer.total_size > 0 {
                        let tracker = crate::network::ed2k::part_tracker::PartTracker::new(
                            transfer.total_size, &part_path,
                        );
                        if tracker.all_complete() {
                            info!(
                                "Restored download {} was Verifying with complete .part — re-verifying locally",
                                transfer.id
                            );
                            let tid = transfer.id.clone();
                            let file_hash = transfer.file_hash.clone();
                            let file_name = transfer.file_name.clone();
                            let file_size = transfer.total_size;
                            let dl_dir = PathBuf::from(&dl_folder);
                            let tx = dl_event_tx.clone();
                            let dl_tid = tid.clone();
                            let dl_tid2 = tid.clone();

                            transfer.status = TransferStatus::Verifying;
                            transfer.speed = 0;
                            if let Err(e) = db.save_transfer(&transfer) {
                                warn!("DB save_transfer failed for verifying transfer {}: {e}", transfer.id);
                            }
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
                                    &dl_tid, &file_hash, &file_name, file_size, &dl_dir,
                                ).await;
                                match result {
                                    Ok(()) => {
                                        let _ = tx.send(DownloadEvent::Completed { transfer_id: dl_tid }).await;
                                    }
                                    Err(e) => {
                                        warn!("Re-verification of restored download failed: {e}");
                                        let kind = ed2k::transfer::classify_error(&e.to_string());
                                        let _ = tx.send(DownloadEvent::Failed {
                                            transfer_id: dl_tid,
                                            error: e.to_string(),
                                            failure_kind: kind,
                                        }).await;
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
                if let Err(e) = db.save_transfer(&transfer) {
                    tracing::warn!(
                        "Failed to persist normalized restored download {}: {e}",
                        transfer.id
                    );
                }

                let active_now = {
                    let mut mgr = transfer_manager.write().await;
                    let active_now = mgr.enqueue(transfer.clone());
                    mgr.register_control(&transfer.id, control.clone());
                    active_now
                };
                // Register in pending_downloads regardless of whether active
                // or queued. Queued downloads still need source discovery
                // (KAD searches, server queries, retry timer) so they have
                // sources ready when promoted.
                if active_now || matches!(transfer.status, TransferStatus::Searching | TransferStatus::Queued) {
                    state.pending_downloads.insert(transfer.id.clone(), PendingDownload {
                        transfer_id: transfer.id.clone(),
                        file_hash: transfer.file_hash.clone(),
                        file_name: transfer.file_name.clone(),
                        file_size: transfer.total_size,
                        control,
                        search_count: 0,
                        last_search_at: 0,
                        priority: priority_str_to_u32(&transfer.priority),
                    });
                }

                // Register partial download for KAD source publishing
                if let Ok(hash_bytes) = hex::decode(&transfer.file_hash) {
                    if hash_bytes.len() >= 16 {
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
                        });
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        crate::security::firewall::ensure_firewall_rules(tcp_port, udp_port);
    }

    ed2k::preview::cleanup_previews();

    // Remove servers blocked by IP filter (eMule: FilterServerByIP on startup)
    if settings.filter_servers_by_ip {
        let removed = state.server_list.remove_filtered(&mut state.ip_filter);
        if removed > 0 {
            let met_path = state.data_dir.join("server.met");
            let _ = state.server_list.save_server_met(&met_path);
            info!("Removed {removed} IP-filtered servers from server list");
        }
    }

    let (aich_set_tx, mut aich_set_rx) = tokio::sync::mpsc::channel::<ed2k::aich::AICHRecoveryHashSet>(128);

    info!("Network event loop starting");

    let loop_panic = std::panic::AssertUnwindSafe(async {
    loop {
        // Drain ALL pending commands first (priority over UDP) to prevent UI freezes.
        // Commands from the Tauri frontend must never be starved by high UDP traffic.
        let mut shutting_down = false;
        while let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                NetworkCommand::Shutdown => {
                    shutting_down = true;
                    break;
                }
                NetworkCommand::UpdateSettings { settings: new_settings } => {
                    state.obfuscation_enabled = new_settings.obfuscation_enabled;
                    state.uss_enabled_flag.store(new_settings.uss_enabled, std::sync::atomic::Ordering::Relaxed);
                    state.upload_max_slots.store(
                        new_settings.max_concurrent_uploads as usize,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    if !new_settings.uss_enabled {
                        state.uss_host = None;
                        state.pending_uss_pings.clear();
                    }
                    info!(
                        "Network settings updated: obfuscation={}, uss={}, nickname={}, max_uploads={}",
                        new_settings.obfuscation_enabled,
                        new_settings.uss_enabled,
                        new_settings.nickname,
                        new_settings.max_concurrent_uploads,
                    );
                    settings = new_settings;
                }
                cmd => {
                    handle_command(
                        &udp_socket,
                        cmd,
                        &mut state,
                        &local_index,
                        &settings,
                        &dl_event_tx,
                        &bandwidth_limiter,
                        &db,
                        &app_handle,
                        &transfer_manager,
                        &source_manager,
                        &credit_manager,
                        &mut stats_manager,
                        &mut known_files,
                        &server_udp,
                        &firewall_probe_ips,
                        &shared_banned_ips,
                        &shared_banned_hashes,
                        &shared_server_addr,
                        &shared_ember_payload,
                        &ember_payload_generation,
                        &geoip,
                        &friend_hashes,
                        ember_hash,
                        &ul_event_tx,
                        ed25519_pubkey,
                        ed25519_secret_key,
                        &upload_queue_handle,
                    ).await;
                }
            }
        }
        if shutting_down {
            info!("Network shutting down");
            break;
        }

        tokio::select! {
            // Incoming UDP packets: batch up to 20 per iteration so we re-check
            // commands and timers between batches
            result = udp_socket.recv_from(&mut udp_buf) => {
                if state.stats.status == NetworkStatus::Disconnected {
                    continue;
                }
                match result {
                    Ok((len, from)) => {
                        last_kad_activity_at = chrono::Utc::now().timestamp();
                        stats_manager.add_overhead(
                            crate::storage::statistics::OverheadCategory::Kad,
                            crate::storage::statistics::OverheadDirection::Download,
                            len as u64,
                        );
                        handle_udp_packet(
                            &udp_socket,
                            &udp_buf[..len],
                            from,
                            &mut state,
                            &app_handle,
                            &local_index,
                            &settings,
                            &db,
                            &active_port_tests,
                            &upload_queue_handle,
                            &credit_manager,
                        ).await;
                    }
                    Err(e) => {
                        warn!("UDP recv error: {e}");
                    }
                }
                // Process up to 19 more queued packets without re-entering select
                for _ in 0..19 {
                    match udp_socket.try_recv_from(&mut udp_buf) {
                        Ok((len, from)) => {
                            if state.stats.status != NetworkStatus::Disconnected {
                                last_kad_activity_at = chrono::Utc::now().timestamp();
                                stats_manager.add_overhead(
                                    crate::storage::statistics::OverheadCategory::Kad,
                                    crate::storage::statistics::OverheadDirection::Download,
                                    len as u64,
                                );
                                handle_udp_packet(
                                    &udp_socket,
                                    &udp_buf[..len],
                                    from,
                                    &mut state,
                                    &app_handle,
                            &local_index,
                            &settings,
                            &db,
                            &active_port_tests,
                            &upload_queue_handle,
                            &credit_manager,
                        ).await;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }

            // Commands from the frontend (also handled by try_recv drain above)
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetworkCommand::Shutdown) | None => {
                        info!("Network shutting down");
                        break;
                    }
                    // `UpdateSettings` mutates the loop-owned `settings` variable
                    // and several `state` fields the dispatched `handle_command`
                    // does not have access to. The try_recv drain above already
                    // handles this case inline; the dispatched `handle_command`
                    // arm for `UpdateSettings` is empty. Without this branch a
                    // settings update that arrives between `try_recv` returning
                    // empty and `select!` re-arming would be silently dropped
                    // (obfuscation toggle, USS toggle, max-uploads slider all
                    // had no effect until the next message woke the loop).
                    Some(NetworkCommand::UpdateSettings { settings: new_settings }) => {
                        state.obfuscation_enabled = new_settings.obfuscation_enabled;
                        state.uss_enabled_flag.store(
                            new_settings.uss_enabled,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        state.upload_max_slots.store(
                            new_settings.max_concurrent_uploads as usize,
                            std::sync::atomic::Ordering::Relaxed,
                        );
                        if !new_settings.uss_enabled {
                            state.uss_host = None;
                            state.pending_uss_pings.clear();
                        }
                        info!(
                            "Network settings updated (recv): obfuscation={}, uss={}, nickname={}, max_uploads={}",
                            new_settings.obfuscation_enabled,
                            new_settings.uss_enabled,
                            new_settings.nickname,
                            new_settings.max_concurrent_uploads,
                        );
                        settings = new_settings;
                    }
                    Some(cmd) => {
                        handle_command(
                            &udp_socket,
                            cmd,
                            &mut state,
                            &local_index,
                            &settings,
                            &dl_event_tx,
                            &bandwidth_limiter,
                            &db,
                            &app_handle,
                            &transfer_manager,
                            &source_manager,
                            &credit_manager,
                            &mut stats_manager,
                            &mut known_files,
                            &server_udp,
                            &firewall_probe_ips,
                            &shared_banned_ips,
                            &shared_banned_hashes,
                            &shared_server_addr,
                            &shared_ember_payload,
                            &ember_payload_generation,
                            &geoip,
                            &friend_hashes,
                            ember_hash,
                            &ul_event_tx,
                            ed25519_pubkey,
                            ed25519_secret_key,
                            &upload_queue_handle,
                        ).await;
                    }
                }
            }

            // Download progress events
            Some(event) = dl_event_rx.recv() => {
                if let DownloadEvent::PartFileReady { ref transfer_id, ref file_hash, file_size, ref file_name } = event {
                    info!("Part file ready for {} ({}) — offering to server and publishing to KAD",
                        transfer_id, hex::encode(file_hash));
                    if state.server_connected {
                        if let Some(conn) = state.server_connection.as_mut() {
                            let offer = vec![ed2k::server::OfferFile {
                                hash: *file_hash,
                                name: file_name.clone(),
                                size: file_size,
                                is_complete: false,
                                file_type: String::new(),
                            }];
                            if let Err(e) = conn.offer_files(&offer, settings.tcp_port).await {
                                warn!("Failed to offer new partial to server: {e}");
                            }
                        }
                    }
                    let kad_hash = md4_bytes_to_kad_id(file_hash);
                    let ext = std::path::Path::new(file_name.as_str())
                        .extension()
                        .map(|e| e.to_string_lossy().to_string())
                        .unwrap_or_default();
                    state.publish_manager.add_file(PublishableFile {
                        file_hash: kad_hash,
                        file_size,
                        file_name: file_name.clone(),
                        file_type: crate::search::index::infer_file_type(&ext),
                        complete_sources: 0,
                    });
                }
                if let DownloadEvent::Completed { ref transfer_id } = event {
                    {
                        let mgr_snap = transfer_manager.read().await;
                        if let Some(t) = mgr_snap.get_transfer(transfer_id) {
                            info!(
                                "Download COMPLETED: {} \"{}\" ({}, {:.1} MB)",
                                transfer_id, t.file_name, t.file_hash,
                                t.total_size as f64 / (1024.0 * 1024.0)
                            );
                        } else {
                            info!("Download COMPLETED: {}", transfer_id);
                        }
                    }
                    state.active_source_senders.remove(transfer_id);
                    state.active_established_senders.remove(transfer_id);
                    state.active_source_overflow.remove(transfer_id);
                    state.active_kad_search_state.remove(transfer_id);
                    state.per_file_sources.remove(transfer_id);
                    state.download_handles.remove(transfer_id);
                    {
                        let mgr_snap = transfer_manager.read().await;
                        if let Some(t) = mgr_snap.get_transfer(transfer_id) {
                            if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                if fh_bytes.len() == 16 {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&fh_bytes);
                                    if let Ok(mut map) = state.aich_recovery_pending.write() {
                                        map.retain(|&(ref h, _), _| *h != fh);
                                    }
                                }
                            }
                        }
                    }
                    let stale_sids: Vec<SearchId> = state.download_source_searches.iter()
                        .filter(|(_, (tid, _))| tid == transfer_id)
                        .map(|(sid, _)| *sid)
                        .collect();
                    for sid in &stale_sids {
                        state.download_source_searches.remove(sid);
                        if let Some(removed) = state.search_manager.remove(sid) {
                            state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                        }
                    }
                    let mgr = transfer_manager.read().await;
                    if let Some(t) = mgr.get_transfer(transfer_id) {
                        if let Some((ip_str, port_str)) = t.peer_id.split_once(':') {
                            if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                                state.dead_sources.remove(0, u32::from(ip), port);
                            }
                        }
                        // Clear all per-file dead source entries for this completed file
                        if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                            if fh_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&fh_bytes);
                                let sm = source_manager.read().await;
                                for (ip, port) in sm.get_sources(&fh) {
                                    state.dead_sources.remove_for_file(&fh, u32::from(ip), port);
                                }
                            }
                        }
                        let safe_name = crate::security::sanitize_filename(&t.file_name);
                        let completed_path = PathBuf::from(&settings.download_folder)
                            .join("Downloads")
                            .join(&safe_name);
                        let now = chrono::Utc::now().timestamp();
                        let file_hash = t.file_hash.clone();
                        let file_name = t.file_name.clone();
                        let file_size = t.total_size;
                        let transferred = t.transferred;

                        if let Ok(hash_bytes) = hex::decode(&file_hash) {
                            if hash_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&hash_bytes);
                                if known_files.find_by_hash(&fh).is_none() {
                                    use crate::storage::known_files::KnownFileRecord;
                                    let record = KnownFileRecord {
                                        file_hash: fh,
                                        part_hashes: Vec::new(),
                                        file_name: file_name.clone(),
                                        file_size,
                                        file_path: completed_path.to_string_lossy().to_string(),
                                        aich_hash: String::new(),
                                        modified_at: now,
                                        all_time_transferred: transferred,
                                        all_time_requested: 0,
                                        all_time_accepted: 0,
                                        upload_priority: 0,
                                        last_publish_src: 0,
                                        last_shared: 0,
                                    };
                                    known_files.add_or_update(record);
                                }

                                // Auto-share completed download (eMule: CPartFile::PerformFileCompleteEnd)
                                let ext = completed_path.extension()
                                    .map(|e| e.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                let folder = completed_path.parent()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                let shared_file = FileInfo {
                                    id: file_hash.clone(),
                                    name: safe_name,
                                    path: completed_path.to_string_lossy().to_string(),
                                    size: file_size,
                                    hash: file_hash,
                                    aich_hash: String::new(),
                                    extension: ext,
                                    modified_at: now,
                                    priority: "normal".to_string(),
                                    requests: 0,
                                    accepted: 0,
                                    bytes_transferred: 0,
                                    alltime_requests: 0,
                                    alltime_accepted: 0,
                                    alltime_transferred: 0,
                                    complete_sources: 0,
                                    folder,
                                    shared: true,
                                    shared_kad: false,
                                    shared_ed2k: false,
                                };
                                {
                                    let mut index = local_index.write().await;
                                    if index.get_by_path(&shared_file.path).is_none() {
                                        index.add_file(shared_file.clone());
                                    }
                                }
                                {
                                    let snap = local_index.read().await.all_files().to_vec();
                                    *shared_files.write().await = snap;
                                }

                                // Publish to KAD
                                state.publish_manager.add_file(PublishableFile {
                                    file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                                    file_name: shared_file.name.clone(),
                                    file_size: shared_file.size,
                                    file_type: crate::search::index::infer_file_type(&shared_file.extension),
                                    complete_sources: 0,
                                });

                                // Offer to eD2K server
                                if state.server_connected {
                                    if let Some(conn) = state.server_connection.as_mut() {
                                        let offer = vec![ed2k::server::OfferFile {
                                            hash: fh,
                                            name: shared_file.name.clone(),
                                            size: shared_file.size,
                                            is_complete: true,
                                            file_type: String::new(),
                                        }];
                                        if let Err(e) = conn.offer_files(&offer, state.tcp_port).await {
                                            warn!("Failed to offer completed download to server: {e}");
                                        }
                                    }
                                }

                                let _ = app_handle.emit("shared-files-changed", serde_json::json!({
                                    "phase": "download-complete",
                                    "count": 1,
                                }));
                                info!("Auto-shared completed download: {}", file_name);

                                // Build full AICH hash set for the completed file
                                // (enables AICH-based verification when serving to other peers)
                                let aich_path = completed_path.clone();
                                let aich_data_dir = state.data_dir.clone();
                                let aich_tx = aich_set_tx.clone();
                                tokio::task::spawn_blocking(move || {
                                    match ed2k::aich::AICHRecoveryHashSet::build_from_file(&aich_path) {
                                        Ok(hs) => {
                                            let aich_hex = hex::encode(hs.root_hash);
                                            let cache_path = aich_data_dir.join("aich_cache.dat");
                                            let entry = format!("{}={}\n", hex::encode(fh), aich_hex);
                                            let _ = std::fs::OpenOptions::new()
                                                .create(true)
                                                .append(true)
                                                .open(&cache_path)
                                                .and_then(|mut f| {
                                                    use std::io::Write;
                                                    f.write_all(entry.as_bytes())
                                                });
                                            tracing::info!("Computed AICH root for completed download: {aich_hex}");
                                            if let Err(e) = aich_tx.blocking_send(hs) {
                                                tracing::warn!("AICH channel closed, hash set not stored: {e}");
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Failed to compute AICH for completed download: {e}");
                                        }
                                    }
                                });
                            }
                        }
                    }
                    drop(mgr);
                }
                if let DownloadEvent::Failed { ref transfer_id, ref error, ref failure_kind } = event {
                    state.active_source_senders.remove(transfer_id);
                    state.active_established_senders.remove(transfer_id);
                    state.active_source_overflow.remove(transfer_id);
                    state.active_kad_search_state.remove(transfer_id);
                    state.download_handles.remove(transfer_id);
                    if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
                        pfs.reset_active_states();
                    }

                    // Cancel stale KAD source searches so they don't waste
                    // bandwidth while the download is re-queued.
                    let stale_sids: Vec<SearchId> = state.download_source_searches.iter()
                        .filter(|(_, (tid, _))| tid == transfer_id)
                        .map(|(sid, _)| *sid)
                        .collect();
                    for sid in &stale_sids {
                        state.download_source_searches.remove(sid);
                        if let Some(removed) = state.search_manager.remove(sid) {
                            state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                        }
                    }
                    let failure_stage = ed2k::transfer::infer_stage_from_error(error).to_string();
                    let failure_kind_name = ed2k::transfer::failure_kind_name(failure_kind);
                    let failure_summary = ed2k::transfer::summarize_error(error, failure_kind);

                    {
                        let peer_id_str = {
                            let mgr = transfer_manager.read().await;
                            mgr.get_transfer(transfer_id).map(|t| t.peer_id.clone()).unwrap_or_default()
                        };
                        let _ = app_handle.emit("transfer:source-failed", serde_json::json!({
                            "transfer_id": transfer_id,
                            "source": peer_id_str,
                            "stage": &failure_stage,
                            "kind": &failure_kind_name,
                            "reason": &failure_summary,
                        }));
                    }

                    // Dead source marking for individual sources is handled by
                    // SourceDetail "failed" events (which carry the actual IP/port).
                    // For single-source downloads that set peer_id, apply a
                    // belt-and-suspenders mark here as well.
                    {
                        let mgr = transfer_manager.read().await;
                        if let Some(t) = mgr.get_transfer(transfer_id) {
                            if let Some((ip_str, port_str)) = t.peer_id.split_once(':') {
                                if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                                    if *failure_kind == SourceFailureKind::Permanent {
                                        state.dead_sources.add_dead_source(0, u32::from(ip), port, state.firewalled);
                                        if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                            if fh_bytes.len() == 16 {
                                                let mut fh = [0u8; 16];
                                                fh.copy_from_slice(&fh_bytes);
                                                state.dead_sources.add_dead_source_for_file(fh, u32::from(ip), port);
                                            }
                                        }
                                        debug!("Marked source {}:{} as dead after permanent failure: {}", ip, port, error);
                                    } else {
                                        if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                            if fh_bytes.len() == 16 {
                                                let mut fh = [0u8; 16];
                                                fh.copy_from_slice(&fh_bytes);
                                                state.dead_sources.add_transient_dead_source_for_file(fh, u32::from(ip), port);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        drop(mgr);
                    }

                    // eMule-style: downloads never auto-fail. Re-queue for source
                    // retry unless the user explicitly cancelled.
                    let is_user_cancel = error.to_lowercase().contains("cancelled") || {
                        let mgr = transfer_manager.read().await;
                        mgr.is_control_cancelled(transfer_id)
                    };
                    if !is_user_cancel {
                        let transfer_info = {
                            let mgr = transfer_manager.read().await;
                            mgr.get_transfer(transfer_id).cloned()
                        };
                        if let Some(t) = transfer_info {
                            let control = TransferControl::new();
                            let health_update = {
                                let mut mgr = transfer_manager.write().await;
                                if let Some(active_t) = mgr.active.get_mut(transfer_id) {
                                    active_t.status = TransferStatus::Searching;
                                    active_t.speed = 0;
                                }
                                mgr.set_failure_context(
                                    transfer_id,
                                    Some(failure_summary.clone()),
                                    Some(failure_kind_name.clone()),
                                    Some(failure_stage.clone()),
                                );
                                let update = mgr.set_health_state(
                                    transfer_id,
                                    TransferHealth::Degraded,
                                    Some(format!("Retrying after {}", failure_summary.to_lowercase())),
                                    chrono::Utc::now().timestamp(),
                                );
                                mgr.register_control(transfer_id, control.clone());
                                update
                            };
                            {
                                if let Some(update) = health_update.as_ref() {
                                    emit_transfer_health(&app_handle, update);
                                }
                            }
                            let prev_search_count = state.pending_downloads
                                .get(transfer_id)
                                .map(|pd| pd.search_count)
                                .unwrap_or(0);
                            state.pending_downloads.insert(transfer_id.clone(), PendingDownload {
                                transfer_id: transfer_id.clone(),
                                file_hash: t.file_hash.clone(),
                                file_name: t.file_name.clone(),
                                file_size: t.total_size,
                                control,
                                search_count: prev_search_count.saturating_add(1),
                                last_search_at: 0,
                                priority: priority_str_to_u32(&t.priority),
                            });
                            info!("Re-queued failed download {} for source retry: {}", transfer_id, error);

                            // Attempt archive recovery if we have significant progress on an archive file
                            let ext = std::path::Path::new(&t.file_name)
                                .extension()
                                .map(|e| e.to_string_lossy().to_lowercase())
                                .unwrap_or_default();
                            let is_archive = matches!(ext.as_str(), "zip" | "rar" | "ace" | "7z");
                            if is_archive && t.progress > 50.0 {
                                let part_path = PathBuf::from(&settings.download_folder)
                                    .join("Temp")
                                    .join(format!("{}.part", t.id));
                                if part_path.exists() {
                                    let tracker = ed2k::part_tracker::PartTracker::new(t.total_size, &part_path);
                                    let filled = tracker.filled_ranges();
                                    if !filled.is_empty() {
                                        let fname = t.file_name.clone();
                                        let pp = part_path.clone();
                                        tokio::task::spawn_blocking(move || {
                                            match ed2k::archive_recovery::recover_archive(&pp, &fname, &filled) {
                                                Ok(recovered) => {
                                                    tracing::info!("Archive recovery successful: {}", recovered.display());
                                                }
                                                Err(e) => {
                                                    tracing::debug!("Archive recovery not possible: {e}");
                                                }
                                            }
                                        });
                                    }
                                }
                            }

                            let _ = app_handle.emit("transfer-status", serde_json::json!({
                                "id": transfer_id,
                                "status": "searching",
                                "failure_reason": failure_summary,
                                "failure_kind": failure_kind_name,
                                "failure_stage": failure_stage,
                                "health": "degraded",
                                "health_reason": format!("Retrying after {}", ed2k::transfer::summarize_error(error, failure_kind).to_lowercase()),
                            }));
                            continue;
                        }
                    }
                }
                // Inject source-exchange-discovered sources into the active download
                if let DownloadEvent::SourceExchange { ref transfer_id, ref file_hash, ref sources } = event {
                    let matching_ids = {
                        let mgr = transfer_manager.read().await;
                        let hash_hex = hex::encode(file_hash);
                        matching_active_transfer_ids_for_hash(&state, &mgr, &hash_hex)
                    };
                    let mut injected = 0usize;
                    for sx in sources {
                        if state.dead_sources.is_dead_source_for_file(file_hash, u32::from(sx.ip), sx.tcp_port) {
                            continue;
                        }
                        let uh = if sx.user_hash != [0u8; 16] { Some(sx.user_hash) } else { None };
                        let co = if sx.crypt_options != 0 { Some(sx.crypt_options) } else { None };
                        let ds = ed2k::multi_source::DownloadSource {
                            peer_ip: sx.ip.to_string(),
                            peer_port: sx.tcp_port,
                            available_parts: Vec::new(),
                            peer_user_hash: uh,
                            peer_connect_options: co,
                        };
                        let stats = inject_source_into_active_transfers(
                            &mut state,
                            *file_hash,
                            &matching_ids,
                            &ds,
                            0,
                        );
                        injected += stats.injected;
                    }
                    if injected > 0 {
                        info!(
                            "Source Exchange: injected {} sources into active download {}",
                            injected, transfer_id
                        );
                    }
                }
                // Inject Ember Peer Exchange sources into matching active downloads
                if let DownloadEvent::EmberSources { ref transfer_id, ref entries, ref aich_roots, ref ember_peers } = event {
                    handle_epx_sources(&mut state, &transfer_manager, &source_manager, entries, aich_roots, ember_peers, &format!("download {transfer_id}")).await;
                }

                if let DownloadEvent::EmberPeerDiscovered { ip, tcp_port } = event {
                    if !crate::security::is_special_use_v4(ip) && !ip.is_multicast() {
                        if record_known_ember_peer(&mut state.known_ember_peers, ip, tcp_port) {
                            state.stats.ember_peers = state.known_ember_peers.len() as u32;
                            state.ember_payload_dirty = true;
                        }
                    }
                }

                if let DownloadEvent::FriendSeen { ember_hash: friend_eh, ip, port } = event {
                    let hash_hex = hex::encode(friend_eh);
                    let now = chrono::Utc::now().timestamp();
                    state.online_friends.insert(friend_eh, now);
                    state.friend_reconnect_last.remove(&friend_eh);
                    let ip_str = match ip { std::net::IpAddr::V4(v4) => v4.to_string(), std::net::IpAddr::V6(v6) => v6.to_string() };
                    let db2 = db.clone();
                    let h2 = hash_hex.clone();
                    let ip2 = ip_str.clone();
                    let _ = tokio::task::spawn_blocking(move || db2.update_friend_address(&h2, &ip2, port));
                    let _ = app_handle.emit("ember:friend-online", serde_json::json!({
                        "user_hash": hash_hex,
                        "ip": ip_str,
                        "port": port,
                    }));
                    if !state.ember_sessions.read().await.contains_key(&friend_eh)
                        && !state.outbound_session_tasks.contains_key(&friend_eh)
                    {
                        if let std::net::IpAddr::V4(v4) = ip {
                            state.outbound_session_tasks.insert(friend_eh, std::time::Instant::now());
                            let our_uh = state.user_hash;
                            let our_eh = ember_hash;
                            let nick = settings.nickname.clone();
                            let cid = state.external_ip.map(|eip| u32::from_le_bytes(eip.octets())).unwrap_or(0);
                            let tcp = settings.tcp_port;
                            let udp = settings.udp_port;
                            let obfs = settings.friend_session_encryption;
                            let sess = state.ember_sessions.clone();
                            let ultx = ul_event_tx.clone();
                            let fh = friend_hashes.clone();
                            let friend_addr = SocketAddr::new(v4.into(), port);
                            info!("Proactively opening friend session to {} at {}", hex::encode(friend_eh), friend_addr);
                            let ultx2 = ul_event_tx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ed2k::friend_connect::open_and_run_friend_session(
                                    friend_addr, our_uh, our_eh, nick,
                                    cid, tcp, udp, obfs, sess, ultx, fh,
                                    Some(ed25519_pubkey), Some(ed25519_secret_key),
                                ).await {
                                    info!("Proactive friend session to {} failed: {e}", hex::encode(friend_eh));
                                    let _ = ultx2.send(upload_server::UploadEvent {
                                        transfer_id: String::new(),
                                        kind: upload_server::UploadEventKind::EmberFriendDisconnected { ember_hash: friend_eh },
                                    }).await;
                                }
                            });
                        }
                    }
                    continue;
                }

                if let DownloadEvent::EmberFriendRequest { ember_hash: req_hash, ref nickname, ref peer_ip, peer_port } = event {
                    let hash_hex = hex::encode(req_hash);
                    info!("Processing download-side friend request from {} (nick='{}', ip={}:{})", hash_hex, nickname, peer_ip, peer_port);
                    // Ember hash is self-reported in the EmuleInfo handshake and cannot be
                    // cryptographically verified (see FUTURE_WORK.md F2). Never auto-promote
                    // a peer to "mutual" based on that tag — require explicit user approval
                    // through the Friends UI. If the sender is already mutual, ignore; if
                    // they are in our list but not mutual, route through the request queue
                    // so the user sees "<nick> wants to confirm friendship" and must accept.
                    let db_q = db.clone();
                    let h_q = hash_hex.clone();
                    let already_mutual = tokio::task::spawn_blocking(move || {
                        db_q.get_friends_full()
                            .ok()
                            .and_then(|rows| rows.into_iter().find(|(h, ..)| h == &h_q).map(|(_, _, _, _, _, _, mutual)| mutual))
                            .unwrap_or(false)
                    })
                    .await
                    .unwrap_or(false);
                    if already_mutual {
                        info!("Friend {} already mutual — ignoring redundant EmberFriendRequest", hash_hex);
                    } else {
                        info!("Queuing friend request from {} for user approval", hash_hex);
                        let db2 = db.clone();
                        let h2 = hash_hex.clone();
                        let n2 = nickname.clone();
                        let ip2 = peer_ip.clone();
                        let _ = tokio::task::spawn_blocking(move || db2.add_friend_request(&h2, &n2, &ip2, peer_port));
                        let _ = app_handle.emit("ember:friend-request", serde_json::json!({
                            "sender_hash": hash_hex,
                            "nickname": nickname,
                        }));
                    }
                    continue;
                }

                // Inbound friend activity on download connections → mark online
                {
                    let activity_eh = match &event {
                        DownloadEvent::EmberChatMessage { ember_hash, .. }
                        | DownloadEvent::EmberBrowseResponse { ember_hash, .. } => Some(*ember_hash),
                        _ => None,
                    };
                    if let Some(eh) = activity_eh {
                        if !state.online_friends.contains_key(&eh) && friend_hashes.read().await.contains(&eh) {
                            state.online_friends.insert(eh, chrono::Utc::now().timestamp());
                            let _ = app_handle.emit("ember:friend-online", serde_json::json!({
                                "user_hash": hex::encode(eh),
                            }));
                        }
                    }
                }

                if let DownloadEvent::EmberChatMessage { ember_hash: chat_ember_hash, ref message } = event {
                    if !settings.friend_chat_disabled {
                        let hash_hex = hex::encode(chat_ember_hash);
                        let db2 = db.clone();
                        let h2 = hash_hex.clone();
                        let msg2 = message.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = db2.insert_chat_message(&h2, "received", &msg2) {
                                tracing::warn!("Failed to persist received chat message: {e}");
                            }
                        });
                        let _ = app_handle.emit("ember:chat-message", serde_json::json!({
                            "user_hash": hash_hex,
                            "message": message,
                            "direction": "received",
                            "timestamp": chrono::Utc::now().timestamp(),
                        }));
                    }
                    continue;
                }

                if let DownloadEvent::EmberBrowseResponse { ember_hash: browse_ember_hash, ref entries } = event {
                    let hash_hex = hex::encode(browse_ember_hash);
                    let files: Vec<serde_json::Value> = entries.iter().map(|(hash, size, name)| {
                        serde_json::json!({ "hash": hash, "size": size, "name": name })
                    }).collect();
                    let _ = app_handle.emit("ember:browse-result", serde_json::json!({
                        "user_hash": hash_hex,
                        "files": files,
                    }));
                    continue;
                }

                // eMule-style: only mark per-source connections dead for
                // permanent failures (FNF, hash mismatch).  Transient TCP
                // errors are expected in P2P and should not block the source.
                if let DownloadEvent::SourceDetail { ref transfer_id, ref ip, port, ref status, ref queue_rank, ref failure_kind, .. } = event {
                    // Update persistent per-file source state
                    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                        if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
                            match status.as_str() {
                                "connecting" => pfs.set_connecting(v4, port),
                                "queued" => pfs.set_on_queue(v4, port, *queue_rank),
                                "queue_full" => pfs.set_on_queue(v4, port, None),
                                "transferring" => pfs.set_downloading(v4, port),
                                "completed" => {}
                                "failed" => {
                                    if state.banned_ips.contains(&v4) {
                                        pfs.set_banned(v4, port);
                                    } else {
                                        let penalty = match failure_kind {
                                            Some(SourceFailureKind::Transient) => 1,
                                            Some(SourceFailureKind::DownloadTimeout) => 2,
                                            Some(SourceFailureKind::Permanent) => 4,
                                            None => 1,
                                        };
                                        pfs.set_failed_with_penalty(v4, port, penalty);
                                    }
                                }
                                "no_needed_parts" => pfs.set_none_needed_parts(v4, port),
                                "wait_callback" => pfs.set_wait_callback(v4, port),
                                "wait_callback_kad" => pfs.set_wait_callback_kad(v4, port),
                                "too_many_conns" => pfs.set_too_many_conns(v4, port),
                                "low_to_low" => {
                                    let file_hash = pfs.file_hash();
                                    // Gate the broker on prior Ember-capability evidence.
                                    // Vanilla eMule peers don't speak our relay protocol on
                                    // the other end, so attempting hole-punch + relay
                                    // burns ~16 s + 30 s with no possibility of success.
                                    // The `ember_capable_peers` set is populated by
                                    // `extract_kad_sources` whenever a peer publishes the
                                    // `"ember"` source tag (see `kad/publish.rs`). Peers
                                    // we've never seen a tag from get marked as plain
                                    // `low_to_low` and skipped — same outcome as before
                                    // these features existed, no time wasted.
                                    let ember_capable =
                                        state.ember_capable_peers.contains(&(v4, port));
                                    let broker_started = if !ember_capable {
                                        debug!(
                                            "Skipping LowID-to-LowID broker for {}:{} — \
                                             peer has not advertised Ember capability via KAD",
                                            v4, port,
                                        );
                                        false
                                    } else if let Some(ref mut broker) = state.connection_broker {
                                        let ext = state.nat_info.external_addr;
                                        broker.attempt_low_to_low(
                                            transfer_id, file_hash, v4, port,
                                            state.nat_info.nat_type, ext,
                                        ).await
                                    } else {
                                        false
                                    };
                                    if broker_started {
                                        pfs.set_ember_relay(v4, port);
                                    } else {
                                        pfs.set_low_to_low(v4, port);
                                    }
                                }
                                "banned" => pfs.set_banned(v4, port),
                                _ => {}
                            }
                        }
                    }

                    if status == "failed" {
                        let failure_kind_name = match failure_kind {
                            Some(SourceFailureKind::Permanent) => "permanent",
                            Some(SourceFailureKind::DownloadTimeout) => "timeout",
                            Some(SourceFailureKind::Transient) | None => "transient",
                        };
                        let _ = app_handle.emit("transfer:source-failed", serde_json::json!({
                            "transfer_id": transfer_id,
                            "source": format!("{}:{}", ip, port),
                            "kind": failure_kind_name,
                        }));
                        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                            let is_permanent = matches!(failure_kind, Some(SourceFailureKind::Permanent));
                            if is_permanent {
                                state.dead_sources.add_dead_source(0, u32::from(v4), port, state.firewalled);
                                let mgr = transfer_manager.read().await;
                                if let Some(t) = mgr.get_transfer(transfer_id) {
                                    if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                        if fh_bytes.len() == 16 {
                                            let mut fh = [0u8; 16];
                                            fh.copy_from_slice(&fh_bytes);
                                            state.dead_sources.add_dead_source_for_file(fh, u32::from(v4), port);
                                        }
                                    }
                                }
                                debug!("Marked source {}:{} as dead (permanent failure)", ip, port);
                            } else {
                                let mgr = transfer_manager.read().await;
                                if let Some(t) = mgr.get_transfer(transfer_id) {
                                    if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                        if fh_bytes.len() == 16 {
                                            let mut fh = [0u8; 16];
                                            fh.copy_from_slice(&fh_bytes);
                                            state.dead_sources.add_transient_dead_source_for_file(fh, u32::from(v4), port);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Reputation: record handshake success or failure
                    if status == "transferring" || status == "failed" {
                        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                            let sm = source_manager.read().await;
                            let maybe_uh = sm.find_user_hash_by_addr(v4, port);
                            drop(sm);
                            if let Some(uh) = maybe_uh {
                                let rep_event = if status == "transferring" {
                                    ember::reputation::ReputationEvent::SuccessfulHandshake
                                } else {
                                    ember::reputation::ReputationEvent::Timeout
                                };
                                let newly_banned = state.reputation.record_event(&uh, rep_event);
                                if newly_banned {
                                    if state.banned_ips.insert(v4) {
                                        warn!("Reputation ban: banning IP {} (user_hash {})", v4, hex::encode(&uh));
                                    }
                                    if let Ok(mut shared) = shared_banned_ips.write() {
                                        *shared = state.banned_ips.clone();
                                    }
                                }
                            }
                        }
                    }
                }
                if let DownloadEvent::DataReceived { ref file_hash, start, end, sender_ip, .. } = event {
                    state.corruption_blackbox.record_data(*file_hash, start, end, sender_ip);
                }
                if let DownloadEvent::PartVerified { ref file_hash, part_start, part_end, ref sender_user_hash, .. } = event {
                    state.corruption_blackbox.verified_part(file_hash, part_start, part_end);
                    if let Some(ref uh) = sender_user_hash {
                        state.reputation.record_event(uh, ember::reputation::ReputationEvent::SuccessfulChunk);
                    }
                }
                if let DownloadEvent::PartCorrupted { ref file_hash, part_start, part_end, ref sender_user_hash, .. } = event {
                    let ban_list = state.corruption_blackbox.corrupted_part(file_hash, part_start, part_end);
                    for ip in ban_list {
                        if state.banned_ips.insert(ip) {
                            warn!("Corruption blackbox: banning {} (high corruption ratio for file {})", ip, hex::encode(file_hash));
                        }
                    }
                    if !state.banned_ips.is_empty() {
                        if let Ok(mut shared) = shared_banned_ips.write() {
                            *shared = state.banned_ips.clone();
                        }
                    }
                    if let Some(ref uh) = sender_user_hash {
                        let newly_banned = state.reputation.record_event(uh, ember::reputation::ReputationEvent::CorruptData);
                        if newly_banned {
                            let sm = source_manager.read().await;
                            let ips = sm.find_ips_by_user_hash(uh);
                            drop(sm);
                            for ip in ips {
                                if state.banned_ips.insert(ip) {
                                    warn!("Reputation ban: banning IP {} (user_hash {})", ip, hex::encode(uh));
                                }
                            }
                            if let Ok(mut shared) = shared_banned_ips.write() {
                                *shared = state.banned_ips.clone();
                            }
                        }
                    }
                }
                if let DownloadEvent::AichRecoveryFailed { ref file_hash, part_index, failed_ip, .. } = event {
                    if let Ok(mut map) = state.aich_recovery_pending.write() {
                        let entry = map.entry((*file_hash, part_index)).or_insert_with(|| (Vec::new(), 0));
                        if !entry.0.contains(&failed_ip) {
                            entry.0.push(failed_ip);
                        }
                        entry.1 += 1;
                        let retry_count = entry.1;
                        let failed_ips = entry.0.clone();
                        drop(map);

                        if retry_count < 3 {
                            let hash_hex = hex::encode(file_hash);
                            let candidate = state.per_file_sources.values().find(|pfs| pfs.file_hash == *file_hash).and_then(|pfs| {
                                pfs.sources.iter().find(|s| {
                                    !failed_ips.contains(&s.ip)
                                        && matches!(
                                            s.state,
                                            ed2k::sources::DownloadSourceState::OnQueue { .. }
                                                | ed2k::sources::DownloadSourceState::New
                                        )
                                })
                            });
                            if let Some(src) = candidate {
                                debug!(
                                    "AICH retry {retry_count}/3 for file {} part {part_index}: next candidate {}:{}",
                                    hash_hex, src.ip, src.tcp_port
                                );
                            } else {
                                debug!(
                                    "AICH retry {retry_count}/3 for file {} part {part_index}: no eligible source yet, will try when one connects",
                                    hash_hex
                                );
                            }
                        } else {
                            debug!(
                                "AICH retries exhausted (3/3) for file {} part {part_index}",
                                hex::encode(file_hash)
                            );
                        }
                    }
                }
                if let DownloadEvent::Completed { ref transfer_id } | DownloadEvent::Failed { ref transfer_id, .. } = event {
                    let mgr = transfer_manager.read().await;
                    if let Some(t) = mgr.get_transfer(transfer_id) {
                        if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                            if fh_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&fh_bytes);
                                state.corruption_blackbox.remove_file(&fh);
                                if let Ok(mut map) = state.aich_recovery_pending.write() {
                                    map.retain(|(file_hash, _), _| *file_hash != fh);
                                }
                            }
                        }
                    }
                    drop(mgr);
                }
                let completed_file_hash = if let DownloadEvent::Completed { ref transfer_id } = event {
                    let mgr = transfer_manager.read().await;
                    mgr.get_transfer(transfer_id).map(|t| t.file_hash.clone())
                } else {
                    None
                };
                let was_completed = completed_file_hash.is_some();
                let mut promoted = Vec::new();
                handle_download_event(event, &app_handle, &transfer_manager, &db, &mut promoted, &mut stats_manager, settings.remove_finished_downloads, &a4af_shared, &settings.download_folder, &mut db_progress_last_persist, DB_PROGRESS_PERSIST_INTERVAL).await;

                if let Some(ref file_hash) = completed_file_hash {
                    let mut sf = spam_filter.write().await;
                    sf.auto_mark_not_spam(file_hash);
                }
                for t in promoted {
                    let control = TransferControl::new();
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.register_control(&t.id, control.clone());
                    }
                    handle_command(
                        &udp_socket,
                        NetworkCommand::StartDownload {
                            file_hash: t.file_hash.clone(),
                            file_name: t.file_name.clone(),
                            file_size: t.total_size,
                            peer_ip: t.peer_id.split(':').next().unwrap_or("").to_string(),
                            peer_port: t.peer_id.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(0),
                            transfer_id: t.id.clone(),
                            control,
                        },
                        &mut state,
                        &local_index,
                        &settings,
                        &dl_event_tx,
                        &bandwidth_limiter,
                        &db,
                        &app_handle,
                        &transfer_manager,
                        &source_manager,
                        &credit_manager,
                        &mut stats_manager,
                        &mut known_files,
                        &server_udp,
                        &firewall_probe_ips,
                        &shared_banned_ips,
                        &shared_banned_hashes,
                        &shared_server_addr,
                        &shared_ember_payload,
                        &ember_payload_generation,
                        &geoip,
                        &friend_hashes,
                        ember_hash,
                        &ul_event_tx,
                        ed25519_pubkey,
                        ed25519_secret_key,
                        &upload_queue_handle,
                    ).await;
                }

                // M10: auto-resume the highest-priority paused download
                if was_completed {
                    let resume_candidate = {
                        let mgr = transfer_manager.read().await;
                        let mut paused: Vec<_> = mgr.active.values()
                            .chain(mgr.queue.iter())
                            .filter(|t| {
                                t.direction == TransferDirection::Download
                                    && t.status == TransferStatus::Paused
                            })
                            .collect();
                        paused.sort_by(|a, b| {
                            priority_str_to_u32(&b.priority).cmp(&priority_str_to_u32(&a.priority))
                        });
                        paused.first().map(|t| (t.id.clone(), t.file_hash.clone(), t.file_name.clone(), t.total_size, t.priority.clone()))
                    };
                    if let Some((rid, fhash, fname, fsize, prio)) = resume_candidate {
                        let control = TransferControl::new();
                        {
                            let mut mgr = transfer_manager.write().await;
                            mgr.update_status(&rid, TransferStatus::Searching);
                            mgr.register_control(&rid, control.clone());
                        }
                        state.pending_downloads.insert(rid.clone(), PendingDownload {
                            transfer_id: rid.clone(),
                            file_hash: fhash.clone(),
                            file_name: fname.clone(),
                            file_size: fsize,
                            control,
                            search_count: 0,
                            last_search_at: 0,
                            priority: priority_str_to_u32(&prio),
                        });
                        if let Err(e) = db.update_transfer_status(&rid, "searching") {
                            warn!("DB update_transfer_status('searching') failed for {rid}: {e}");
                        }
                        let _ = app_handle.emit(
                            "transfer-status",
                            serde_json::json!({ "id": rid, "status": "searching" }),
                        );
                        info!("Auto-resumed paused download {} ({}) after completion", rid, fname);
                    }
                }
            }

            // Upload events from the peer-to-peer upload listener
            Some(event) = ul_event_rx.recv() => {
                if let UploadEventKind::ShareInterest {
                    ref file_hash,
                    inc_requests,
                    inc_accepted,
                } = event.kind
                {
                    if inc_requests > 0 || inc_accepted > 0 {
                        if let Ok(bytes) = hex::decode(file_hash) {
                            if bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&bytes);
                                known_files.bump_share_interest(&fh, inc_requests, inc_accepted);
                                {
                                    let mut idx = local_index.write().await;
                                    idx.apply_upload_share_deltas(file_hash, inc_requests, inc_accepted);
                                }
                                // Target-update only the matching rows in the
                                // cached snapshot rather than cloning the
                                // entire file list. The old `all_files().to_vec()`
                                // reallocated every FileInfo (often thousands
                                // of entries with strings) for every peer file
                                // request; counters on the one file that
                                // changed are all the UI needs.
                                {
                                    let mut cached = shared_files.write().await;
                                    for f in cached.iter_mut() {
                                        if f.hash == *file_hash {
                                            f.requests = f.requests.saturating_add(inc_requests);
                                            f.accepted = f.accepted.saturating_add(inc_accepted);
                                            f.alltime_requests = f.alltime_requests.saturating_add(inc_requests);
                                            f.alltime_accepted = f.alltime_accepted.saturating_add(inc_accepted);
                                        }
                                    }
                                }
                                let _ = app_handle.emit("shared-files-changed", serde_json::json!({
                                    "phase": "upload-stats",
                                    "count": 1,
                                }));
                            }
                        }
                    }
                }

                let completed_payload = if matches!(&event.kind, UploadEventKind::Completed) {
                    let mgr = transfer_manager.read().await;
                    let out = mgr
                        .get_transfer(&event.transfer_id)
                        .map(|t| (t.file_hash.clone(), t.transferred));
                    drop(mgr);
                    out
                } else {
                    None
                };
                if let Some((hash_hex, uploaded_bytes)) = completed_payload {
                    if uploaded_bytes > 0 {
                        if let Ok(v) = hex::decode(&hash_hex) {
                            if v.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&v);
                                known_files.add_all_time_transferred(&fh, uploaded_bytes);
                                {
                                    let mut idx = local_index.write().await;
                                    idx.apply_upload_completed_bytes(&hash_hex, uploaded_bytes);
                                }
                                // Target-update the cached snapshot in place
                                // (see ShareInterest above for rationale).
                                {
                                    let mut cached = shared_files.write().await;
                                    for f in cached.iter_mut() {
                                        if f.hash == hash_hex {
                                            f.bytes_transferred = f.bytes_transferred.saturating_add(uploaded_bytes);
                                            f.alltime_transferred = f.alltime_transferred.saturating_add(uploaded_bytes);
                                        }
                                    }
                                }
                                let _ = app_handle.emit("shared-files-changed", serde_json::json!({
                                    "phase": "upload-complete",
                                    "count": 1,
                                }));
                            }
                        }
                    }
                }

                // Inject Ember Peer Exchange sources from upload-side peers
                if let UploadEventKind::EmberSources { ref entries, ref aich_roots, ref ember_peers } = event.kind {
                    handle_epx_sources(&mut state, &transfer_manager, &source_manager, entries, aich_roots, ember_peers, "upload").await;
                }

                if let UploadEventKind::EmberPeerDiscovered { ip, tcp_port } = event.kind {
                    if !crate::security::is_special_use_v4(ip) && !ip.is_multicast() {
                        if record_known_ember_peer(&mut state.known_ember_peers, ip, tcp_port) {
                            state.stats.ember_peers = state.known_ember_peers.len() as u32;
                            state.ember_payload_dirty = true;
                        }
                    }
                }

                // Any inbound friend activity implies they're online — update
                // status if we haven't already so the UI card flips immediately.
                {
                    let activity_eh = match &event.kind {
                        UploadEventKind::EmberChatMessage { ember_hash, .. }
                        | UploadEventKind::EmberBrowseRequest { ember_hash, .. }
                        | UploadEventKind::EmberBrowseResponse { ember_hash, .. }
                        | UploadEventKind::EmberFriendRequest { ember_hash, .. } => Some(*ember_hash),
                        _ => None,
                    };
                    if let Some(eh) = activity_eh {
                        if !state.online_friends.contains_key(&eh) && friend_hashes.read().await.contains(&eh) {
                            state.online_friends.insert(eh, chrono::Utc::now().timestamp());
                            let _ = app_handle.emit("ember:friend-online", serde_json::json!({
                                "user_hash": hex::encode(eh),
                            }));
                        }
                    }
                }

                if let UploadEventKind::FriendSeen { ember_hash, ip, port } = event.kind {
                    let hash_hex = hex::encode(ember_hash);
                    let now = chrono::Utc::now().timestamp();
                    state.online_friends.insert(ember_hash, now);
                    let ip_str = match ip { std::net::IpAddr::V4(v4) => v4.to_string(), std::net::IpAddr::V6(v6) => v6.to_string() };
                    let db2 = db.clone();
                    let h2 = hash_hex.clone();
                    let ip2 = ip_str.clone();
                    let _ = tokio::task::spawn_blocking(move || db2.update_friend_address(&h2, &ip2, port));
                    let _ = app_handle.emit("ember:friend-online", serde_json::json!({
                        "user_hash": hash_hex,
                        "ip": ip_str,
                        "port": port,
                    }));
                }

                if let UploadEventKind::EmberFriendRequest { ember_hash: req_hash, ref nickname, ref peer_ip, peer_port } = event.kind {
                    let hash_hex = hex::encode(req_hash);
                    info!("Processing upload-side friend request from {} (nick='{}', ip={}:{})", hash_hex, nickname, peer_ip, peer_port);
                    // See the download-side handler above: never auto-mutual based on an
                    // unauthenticated ember_hash tag. Always require explicit user approval.
                    let db_q = db.clone();
                    let h_q = hash_hex.clone();
                    let already_mutual = tokio::task::spawn_blocking(move || {
                        db_q.get_friends_full()
                            .ok()
                            .and_then(|rows| rows.into_iter().find(|(h, ..)| h == &h_q).map(|(_, _, _, _, _, _, mutual)| mutual))
                            .unwrap_or(false)
                    })
                    .await
                    .unwrap_or(false);
                    if already_mutual {
                        info!("Friend {} already mutual — ignoring redundant EmberFriendRequest", hash_hex);
                    } else {
                        info!("Queuing friend request from {} for user approval", hash_hex);
                        let db2 = db.clone();
                        let h2 = hash_hex.clone();
                        let n2 = nickname.clone();
                        let ip2 = peer_ip.clone();
                        let _ = tokio::task::spawn_blocking(move || db2.add_friend_request(&h2, &n2, &ip2, peer_port));
                        let _ = app_handle.emit("ember:friend-request", serde_json::json!({
                            "sender_hash": hash_hex,
                            "nickname": nickname,
                        }));
                    }
                }

                if let UploadEventKind::EmberChatMessage { ember_hash: chat_eh, ref message } = event.kind {
                    if !settings.friend_chat_disabled {
                        let hash_hex = hex::encode(chat_eh);
                        let db2 = db.clone();
                        let h2 = hash_hex.clone();
                        let msg2 = message.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = db2.insert_chat_message(&h2, "received", &msg2) {
                                tracing::warn!("Failed to persist received chat message: {e}");
                            }
                        });
                        let _ = app_handle.emit("ember:chat-message", serde_json::json!({
                            "user_hash": hash_hex,
                            "message": message,
                            "direction": "received",
                            "timestamp": chrono::Utc::now().timestamp(),
                        }));
                    }
                }

                if let UploadEventKind::EmberBrowseRequest { ember_hash: browse_eh } = event.kind {
                    if !settings.friend_browse_disabled {
                        let hash_hex = hex::encode(browse_eh);
                        let files = {
                            let idx = local_index.read().await;
                            idx.all_files().to_vec()
                        };
                        let mut res_payload = Vec::new();
                        let count_offset = res_payload.len();
                        res_payload.extend_from_slice(&0u32.to_le_bytes());
                        let mut actual_count = 0u32;
                        for f in files.iter().take(5000) {
                            if let Ok(hash_bytes) = hex::decode(&f.hash) {
                                if hash_bytes.len() == 16 {
                                    res_payload.extend_from_slice(&hash_bytes);
                                    res_payload.extend_from_slice(&f.size.to_le_bytes());
                                    let name_bytes = f.name.as_bytes();
                                    let name_len = name_bytes.len().min(u16::MAX as usize) as u16;
                                    res_payload.extend_from_slice(&name_len.to_le_bytes());
                                    res_payload.extend_from_slice(&name_bytes[..name_len as usize]);
                                    actual_count += 1;
                                }
                            }
                        }
                        res_payload[count_offset..count_offset + 4]
                            .copy_from_slice(&actual_count.to_le_bytes());
                        let mut packet = Vec::with_capacity(6 + res_payload.len());
                        packet.push(OP_EMULEPROT);
                        let size = (1 + res_payload.len()) as u32;
                        packet.extend_from_slice(&size.to_le_bytes());
                        packet.push(ed2k::messages::OP_EMBER_BROWSE_RES);
                        packet.extend_from_slice(&res_payload);
                        let sessions = state.ember_sessions.read().await;
                        if let Some(sender) = sessions.get(&browse_eh) {
                            if let Err(e) = sender.try_send(packet) {
                                tracing::warn!("Browse response to {} dropped: {e}", hex::encode(browse_eh));
                            }
                        }
                        let _ = app_handle.emit("ember:browse-request", serde_json::json!({
                            "user_hash": hash_hex,
                        }));
                    }
                }

                if let UploadEventKind::EmberBrowseResponse { ember_hash: browse_eh, ref entries } = event.kind {
                    let hash_hex = hex::encode(browse_eh);
                    let files: Vec<serde_json::Value> = entries.iter().map(|(hash, size, name)| {
                        serde_json::json!({ "hash": hash, "size": size, "name": name })
                    }).collect();
                    let _ = app_handle.emit("ember:browse-result", serde_json::json!({
                        "user_hash": hash_hex,
                        "files": files,
                    }));
                }

                if let UploadEventKind::EmberFriendDisconnected { ember_hash: dc_eh } = event.kind {
                    let hash_hex = hex::encode(dc_eh);
                    state.online_friends.remove(&dc_eh);
                    state.outbound_session_tasks.remove(&dc_eh);
                    let _ = app_handle.emit("ember:friend-offline", serde_json::json!({
                        "user_hash": hash_hex,
                    }));
                    let _ = app_handle.emit("ember:browse-error", serde_json::json!({
                        "user_hash": hash_hex,
                        "reason": "Friend disconnected",
                    }));

                    if friend_hashes.read().await.contains(&dc_eh)
                        && !state.ember_sessions.read().await.contains_key(&dc_eh)
                    {
                        let now_inst = std::time::Instant::now();
                        let can_reconnect = match state.friend_reconnect_last.get(&dc_eh) {
                            Some(last) => now_inst.saturating_duration_since(*last).as_secs() >= 60,
                            None => true,
                        };
                        if can_reconnect {
                            state.friend_reconnect_last.insert(dc_eh, now_inst);
                            state.outbound_session_tasks.insert(dc_eh, now_inst);
                            info!("Friend {} disconnected, reconnect via rendezvous", hash_hex);
                            let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                                "user_hash": hash_hex,
                            }));
                            spawn_rendezvous_friend_lookup(
                                &settings, &state, ember_hash, dc_eh,
                                &db, &app_handle, &friend_hashes, &ul_event_tx,
                                ed25519_pubkey, ed25519_secret_key,
                            );
                        } else {
                            debug!("Friend {} reconnect skipped (backoff cooldown)", hash_hex);
                        }
                    }
                }

                // Reputation: record upload-side events
                match &event.kind {
                    UploadEventKind::Started { user_hash: Some(ref uh_hex), .. } => {
                        if let Ok(bytes) = hex::decode(uh_hex) {
                            if bytes.len() == 16 {
                                let mut uh = [0u8; 16];
                                uh.copy_from_slice(&bytes);
                                state.reputation.record_event(&uh, ember::reputation::ReputationEvent::SuccessfulHandshake);
                            }
                        }
                    }
                    UploadEventKind::Completed => {
                        let mgr = transfer_manager.read().await;
                        if let Some(t) = mgr.get_transfer(&event.transfer_id) {
                            if let Some(ref uh_hex) = t.user_hash {
                                if let Ok(bytes) = hex::decode(uh_hex) {
                                    if bytes.len() == 16 {
                                        let mut uh = [0u8; 16];
                                        uh.copy_from_slice(&bytes);
                                        state.reputation.record_event(&uh, ember::reputation::ReputationEvent::SuccessfulChunk);
                                    }
                                }
                            }
                        }
                        drop(mgr);
                    }
                    UploadEventKind::Failed { .. } => {
                        let mgr = transfer_manager.read().await;
                        if let Some(t) = mgr.get_transfer(&event.transfer_id) {
                            if let Some(ref uh_hex) = t.user_hash {
                                if let Ok(bytes) = hex::decode(uh_hex) {
                                    if bytes.len() == 16 {
                                        let mut uh = [0u8; 16];
                                        uh.copy_from_slice(&bytes);
                                        let newly_banned = state.reputation.record_event(&uh, ember::reputation::ReputationEvent::FailedChunk);
                                        if newly_banned {
                                            if let Ok(peer_ip) = t.peer_id.split(':').next().unwrap_or("").parse::<Ipv4Addr>() {
                                                if state.banned_ips.insert(peer_ip) {
                                                    warn!("Reputation ban: banning IP {} (user_hash {})", peer_ip, uh_hex);
                                                }
                                                if let Ok(mut shared) = shared_banned_ips.write() {
                                                    *shared = state.banned_ips.clone();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        drop(mgr);
                    }
                    _ => {}
                }

                let mut promoted = Vec::new();
                handle_upload_event(event, &app_handle, &transfer_manager, &mut promoted, &mut stats_manager).await;
                for t in promoted {
                    let control = TransferControl::new();
                    {
                        let mut mgr = transfer_manager.write().await;
                        mgr.register_control(&t.id, control.clone());
                    }
                    handle_command(
                        &udp_socket,
                        NetworkCommand::StartDownload {
                            file_hash: t.file_hash.clone(),
                            file_name: t.file_name.clone(),
                            file_size: t.total_size,
                            peer_ip: t.peer_id.split(':').next().unwrap_or("").to_string(),
                            peer_port: t.peer_id.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(0),
                            transfer_id: t.id.clone(),
                            control,
                        },
                        &mut state,
                        &local_index,
                        &settings,
                        &dl_event_tx,
                        &bandwidth_limiter,
                        &db,
                        &app_handle,
                        &transfer_manager,
                        &source_manager,
                        &credit_manager,
                        &mut stats_manager,
                        &mut known_files,
                        &server_udp,
                        &firewall_probe_ips,
                        &shared_banned_ips,
                        &shared_banned_hashes,
                        &shared_server_addr,
                        &shared_ember_payload,
                        &ember_payload_generation,
                        &geoip,
                        &friend_hashes,
                        ember_hash,
                        &ul_event_tx,
                        ed25519_pubkey,
                        ed25519_secret_key,
                        &upload_queue_handle,
                    ).await;
                }
            }

            // Periodic search polling
            _ = search_poll_timer.tick() => {
                let mut udp_finished_request = None;
                if let Some(active) = state.active_search_request.as_mut() {
                    if active.udp_pending {
                        // Only start the timeout countdown after the throttled
                        // queue is fully drained (all servers queried).
                        if state.udp_search_queue.is_empty() {
                            state.server_udp_search_age += 1;
                        }
                        if state.server_udp_search_age > 10 {
                            active.udp_pending = false;
                            udp_finished_request = Some(active.request_id);
                            state.udp_search_queue.clear();
                        }
                    } else {
                        state.server_udp_search_age = 0;
                    }
                } else {
                    state.server_udp_search_age = 0;
                }
                if let Some(request_id) = udp_finished_request {
                    maybe_finish_active_search(&mut state, &app_handle, request_id);
                }
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let new_in_use = state.search_manager.drain_pending_in_use();
                if !new_in_use.is_empty() {
                    state.routing_table.mark_contacts_in_use(&new_in_use);
                }
                let queries = state.search_manager.poll_queries();
                for (sid, addr, msg, contact_id) in &queries {
                    if state.flood_protection.check_outgoing_rate(addr.ip()) {
                        debug!("Throttling outgoing search {} packet to {addr}", sid.0);
                        continue;
                    }
                    if let Ok(packet) = messages::encode_packet(msg) {
                        let opcode = packet.get(1).copied().unwrap_or(0);
                        state.flood_protection.track_request(*addr, opcode);
                        let _ = send_kad_packet(
                            &udp_socket, &packet, *addr, &state, contact_id,
                        ).await;
                        // Track publish requests for ack matching. poll_queries
                        // can return KadReq (routing lookup) or Publish* (store
                        // phase); only the latter expect a PublishRes so only
                        // those need an entry. Insert at send-time (not at
                        // search completion) — peers ack within milliseconds
                        // and we used to miss every single lookup-phase ack.
                        let (publish_target, is_source) = match msg {
                            KadMessage::PublishSourceReq { target, .. } => (Some(*target), true),
                            KadMessage::PublishKeyReq { target, .. } => (Some(*target), false),
                            KadMessage::PublishNotesReq { target, .. } => (Some(*target), false),
                            _ => (None, false),
                        };
                        if let Some(target) = publish_target {
                            let file_hash = state
                                .store_source_searches
                                .get(sid)
                                .map(|(fh, _)| *fh)
                                .unwrap_or(target);
                            state
                                .publish_pending
                                .insert((target, *addr), (file_hash, chrono::Utc::now().timestamp(), is_source));
                        }
                    }
                }

                // eMule StorePacket: send publish messages to within-tolerance
                // contacts DURING Lookup (not just at completion). This ensures
                // the data reaches the same live nodes that searchers discover.
                {
                    let store_sids: Vec<SearchId> = state.store_source_searches.keys().copied().collect();
                    for sid in store_sids {
                        if let Some(search) = state.search_manager.get_mut(&sid) {
                            let candidates = search.next_publish_candidates();
                            if !candidates.is_empty() {
                                if let Some((file_hash, ref msg)) = state.store_source_searches.get(&sid).cloned() {
                                    let opcode = kad_request_opcode(&msg).unwrap_or(0);
                                    // Snapshot publish target for ack tracking
                                    // before the send loop (can't borrow msg
                                    // across the loop otherwise).
                                    let publish_target = match &msg {
                                        KadMessage::PublishSourceReq { target, .. } => Some(*target),
                                        KadMessage::PublishKeyReq { target, .. } => Some(*target),
                                        KadMessage::PublishNotesReq { target, .. } => Some(*target),
                                        _ => None,
                                    };
                                    for contact in &candidates {
                                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                        if let Ok(packet) = messages::encode_packet(&msg) {
                                            state.flood_protection.track_request(addr, opcode);
                                            let _ = send_kad_packet(&udp_socket, &packet, addr, &state, &contact.id).await;
                                            if let Some(target) = publish_target {
                                                state.publish_pending.insert(
                                                    (target, addr),
                                                    (file_hash, chrono::Utc::now().timestamp(), true),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Check for completed searches
                let completed_ids: Vec<SearchId> = state.search_manager.active
                    .iter()
                    .filter(|(_, s)| s.completed)
                    .map(|(id, _)| *id)
                    .collect();

                if !state.pending_keyword_searches.is_empty() {
                    let sids: Vec<SearchId> = state.pending_keyword_searches.keys().cloned().collect();
                    for sid in sids {
                        let Some(search) = state.search_manager.get(&sid) else { continue; };
                        if search.completed { continue; }
                        let Some(pending) = state.pending_keyword_searches.get(&sid) else { continue; };
                        let unique_count = {
                            let unique: std::collections::HashSet<&kad::types::KadId> =
                                search.results.iter().map(|r| &r.id).collect();
                            unique.len()
                        };
                        let _ = app_handle.emit(
                            "search-progress",
                            SearchProgressEvent {
                                request_id: pending.request_id,
                                nodes_contacted: search.queried.len(),
                                results_so_far: unique_count,
                                phase: format!("{:?}", search.phase),
                            },
                        );

                        let new_results = search.results.len();
                        let stream_threshold = if pending.last_streamed_count == 0 { 1 } else { 20 };
                        if new_results > pending.last_streamed_count + stream_threshold {
                            let new_entries = &search.results[pending.last_streamed_count..];
                            let mut batch = convert_search_results(new_entries);
                            // Pull the per-pending data out by value so we
                            // don't hold an immutable borrow of
                            // `state.pending_keyword_searches` across the
                            // `await` below — the next statement re-borrows
                            // it mutably (`get_mut`).
                            let pending_request_id = pending.request_id;
                            let pending_file_type_filter = pending.file_type_filter.clone();
                            let pending_keywords = pending.keywords.clone();
                            if pending_keywords.len() > 1 {
                                batch.retain(|r| {
                                    let name_lower = r.file.name.to_lowercase();
                                    pending_keywords.iter().all(|kw| name_lower.contains(kw))
                                });
                            }
                            if !batch.is_empty() {
                                enrich_and_emit_search_results(
                                    &app_handle,
                                    &spam_filter,
                                    &settings,
                                    pending_request_id,
                                    batch,
                                    &pending_file_type_filter,
                                    &pending_keywords,
                                    None,
                                ).await;
                            }
                            if let Some(p) = state.pending_keyword_searches.get_mut(&sid) {
                                p.last_streamed_count = new_results;
                            }
                        }
                    }
                }

                for sid in completed_ids {
                    if let Some(PendingKeywordSearch { tx, mut local_results, keywords, request_id, file_type_filter, .. }) = state.pending_keyword_searches.remove(&sid) {
                        let network_results = if let Some(search) = state.search_manager.get(&sid) {
                            let unique: std::collections::HashSet<&kad::types::KadId> =
                                search.results.iter().map(|r| &r.id).collect();
                            info!(
                                "Keyword search {} completed: {} unique files ({} raw entries from KAD), {} local results",
                                sid.0, unique.len(), search.results.len(), local_results.len()
                            );
                            let all_results = convert_search_results(&search.results);
                            if keywords.len() > 1 {
                                let before = all_results.len();
                                let filtered: Vec<SearchResult> = all_results.into_iter().filter(|r| {
                                    let name_lower = r.file.name.to_lowercase();
                                    keywords.iter().all(|kw| name_lower.contains(kw))
                                }).collect();
                                info!("Keyword filter: {before} -> {} results (matched all {} keywords)", filtered.len(), keywords.len());
                                filtered
                            } else {
                                all_results
                            }
                        } else {
                            Vec::new()
                        };
                        local_results.extend(network_results);
                        local_results = filter_results_by_type(local_results, &file_type_filter);
                        local_results.sort_by(|a, b| b.availability.cmp(&a.availability));
                        local_results.truncate(2000);
                        let _ = tx.send(local_results);
                        if let Some(active) = state.active_search_request.as_mut() {
                            if active.request_id == request_id {
                                active.kad_pending = false;
                            }
                        }
                        maybe_finish_active_search(&mut state, &app_handle, request_id);
                    } else if let Some(tx) = state.pending_source_searches.remove(&sid) {
                        let sources = if let Some(search) = state.search_manager.get(&sid) {
                            let all = extract_kad_sources(&search.results);
                            // Remember any peer that advertised Ember capability so
                            // future broker attempts for them are unlocked. We update
                            // the cache *before* filtering self-sources because we want
                            // to learn about peers from every search response, not just
                            // ones we end up handing back to the caller.
                            for s in &all {
                                if s.is_ember_capable && !s.ip.is_unspecified() && s.tcp_port != 0 {
                                    state.ember_capable_peers.insert((s.ip, s.tcp_port));
                                }
                            }
                            let before = all.len();
                            let filtered: Vec<(String, u16)> = all
                                .into_iter()
                                .filter(|s| !is_self_source(s, &state))
                                .map(|s| (s.ip.to_string(), s.tcp_port))
                                .collect();
                            if filtered.len() != before {
                                debug!(
                                    "Source search {}: dropped {} self-sources",
                                    sid.0,
                                    before - filtered.len()
                                );
                            }
                            filtered
                        } else {
                            Vec::new()
                        };
                        info!("Source search {} completed: {} sources found", sid.0, sources.len());
                        let _ = tx.send(sources.clone());

                        // Connect found sources to any pending download with a
                        // matching file hash so "Find More Sources" actually
                        // starts the download instead of discarding results.
                        if !sources.is_empty() {
                            if let Some(search) = state.search_manager.get(&sid) {
                                let raw_hash = kad_id_to_md4_bytes(&search.target);
                                let hash_hex = hex::encode(raw_hash);
                                let matching_tid = state.pending_downloads.iter()
                                    .find(|(_, pd)| pd.file_hash == hash_hex)
                                    .map(|(tid, _)| tid.clone());
                                if let Some(transfer_id) = matching_tid {
                                    // Re-insert as a download_source_searches so
                                    // the normal download-start logic handles it
                                    // on the next search completion or trigger an
                                    // immediate retry by resetting the search timer.
                                    if let Some(pd) = state.pending_downloads.get_mut(&transfer_id) {
                                        pd.last_search_at = 0;
                                        info!(
                                            "Find More Sources found {} sources for pending download {}, triggering immediate retry",
                                            sources.len(), transfer_id
                                        );
                                        // Register sources in SourceManager so the
                                        // periodic retry loop picks them up.
                                        let mut sm = source_manager.write().await;
                                        for (ip_str, port) in &sources {
                                            if let Ok(v4) = ip_str.parse::<Ipv4Addr>() {
                                                sm.register_source(raw_hash, v4, *port);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if let Some((transfer_id, search_file_hash)) = state.download_source_searches.remove(&sid) {
                        let kad_sources = if let Some(search) = state.search_manager.get(&sid) {
                            let all = extract_kad_sources(&search.results);
                            // Same cache update as the pending_source_searches branch:
                            // record every peer that advertised Ember capability so the
                            // broker dispatch sites can unblock them. Doing this in both
                            // branches (rather than once inside `extract_kad_sources`)
                            // keeps that helper a pure function with no `state`
                            // dependency.
                            for s in &all {
                                if s.is_ember_capable && !s.ip.is_unspecified() && s.tcp_port != 0 {
                                    state.ember_capable_peers.insert((s.ip, s.tcp_port));
                                }
                            }
                            let before = all.len();
                            let filtered: Vec<KadSource> = all
                                .into_iter()
                                .filter(|s| !is_self_source(s, &state))
                                .collect();
                            if filtered.len() != before {
                                debug!(
                                    "Download source search {} for {}: dropped {} self-sources",
                                    sid.0,
                                    transfer_id,
                                    before - filtered.len()
                                );
                            }
                            filtered
                        } else {
                            Vec::new()
                        };

                        // Real-world compatibility: many clients mix source-type semantics.
                        // Treat entries without buddy info as direct candidates and entries
                        // with buddy info as callback candidates.
                        // Type-6 sources that qualify for direct UDP callback go into
                        // direct_callback_sources; remaining type-6 with valid TCP info
                        // are treated as regular direct sources (eMule fallback).
                        let direct_callback_sources: Vec<&KadSource> = kad_sources.iter()
                            .filter(|s| s.source_type == 6 && s.udp_port != 0 && (s.connect_options & 0x08) != 0)
                            .collect();
                        let direct_sources: Vec<&KadSource> = kad_sources.iter()
                            .filter(|s| {
                                s.buddy_ip.is_none()
                                    && s.tcp_port != 0
                                    && !s.ip.is_unspecified()
                                    && s.lowid == 0
                                    && (s.source_type != 6
                                        || !direct_callback_sources.iter().any(|dc| dc.ip == s.ip && dc.tcp_port == s.tcp_port))
                            })
                            .collect();
                        let callback_sources: Vec<&KadSource> = kad_sources.iter()
                            .filter(|s| s.buddy_ip.is_some() && matches!(s.source_type, 3 | 5))
                            .collect();
                        let lowid_sources: Vec<&KadSource> = kad_sources.iter()
                            .filter(|s| s.source_type == 2 && s.lowid > 0 && s.ed2k_server_ip != 0)
                            .collect();
                        let type6_count = direct_callback_sources.len();

                        let total_kad_sources = direct_sources.len() + callback_sources.len() + type6_count + lowid_sources.len();
                        info!(
                            "Download source search {} completed for {}: {} direct, {} callback, {} direct-callback (type 6), {} lowid (type 2)",
                            sid.0, transfer_id, direct_sources.len(), callback_sources.len(), type6_count, lowid_sources.len()
                        );
                        let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                            "transfer_id": &transfer_id,
                            "kind": if total_kad_sources == 0 { "kad_empty" }
                                    else if direct_sources.is_empty() { "kad_indirect" }
                                    else { "kad_found" },
                            "count": total_kad_sources,
                        }));

                        // File hash is carried in `download_source_searches`
                        // alongside the transfer_id — it was captured when
                        // the search was started and no longer depends on
                        // `pending_downloads` (which is consumed by
                        // `try_start_from_known` the moment server-side
                        // sources arrive, leaving in-flight KAD searches
                        // orphaned under the old design).
                        let resolved_file_hash: Option<[u8; 16]> = Some(search_file_hash);

                        // Send KADEMLIA_CALLBACK_REQ for buddy-backed callback sources.
                        if !callback_sources.is_empty() {
                            let file_hash_bytes = resolved_file_hash;

                            if let Some(fh) = file_hash_bytes {
                                for cb_src in &callback_sources {
                                    let Some(buddy_ip) = cb_src.buddy_ip else {
                                        debug!("Skipping callback source: no buddy IP");
                                        continue;
                                    };
                                    if kad::ip_filter::is_private_or_reserved(buddy_ip) {
                                        debug!("Skipping callback source: buddy IP {} is private/unroutable", buddy_ip);
                                        continue;
                                    }
                                    // Per eMule `Search.cpp:669`,
                                    // `TAG_SERVERPORT` is declared as
                                    // `theApp.clientlist->GetBuddy()->GetUDPPort()` —
                                    // i.e. the buddy's eMule UDP listen
                                    // port. In practice the field gets
                                    // published inconsistently in the
                                    // wild: some clients (modern eMule
                                    // on a classic setup) publish the
                                    // UDP port (e.g. 4675), others
                                    // (aMule, several eMule mods, and
                                    // clients whose buddy record came
                                    // from KAD `IncomingBuddy` which
                                    // only calls `SetKadPort` and
                                    // leaves `m_nUDPPort == 0` until a
                                    // subsequent Hello fills it) end up
                                    // publishing a value that's really
                                    // the buddy's TCP port (e.g. 4672),
                                    // expecting callers to apply the
                                    // `UDP = TCP + 3` convention.
                                    //
                                    // We can't tell which flavour a
                                    // given source record uses without
                                    // probing. The packet is ~40 bytes;
                                    // rather than guess wrong half the
                                    // time and send every
                                    // `KADEMLIA_CALLBACK_REQ` to the
                                    // void (the pre-fix bug shipped
                                    // `port + 3` unconditionally; the
                                    // post-fix bug shipped `port`
                                    // unconditionally — both failed ~100%
                                    // of the time against the
                                    // opposite-flavour publishers),
                                    // fire the callback at **both**
                                    // `TAG_SERVERPORT` and
                                    // `TAG_SERVERPORT + 3`. Exactly one
                                    // of the two lands on the buddy's
                                    // actual UDP listener; the other is
                                    // dropped by the OS as "no such
                                    // socket" with zero protocol
                                    // impact. Tracking the attempt as a
                                    // single logical attempt (not two)
                                    // is correct — the peer only sees
                                    // one.
                                    let buddy_port_raw = cb_src.buddy_port.unwrap_or(0);
                                    if buddy_port_raw == 0 {
                                        debug!("Skipping callback source: no buddy UDP port in TAG_SERVERPORT");
                                        continue;
                                    }
                                    let buddy_port_alt = buddy_port_raw.saturating_add(3);
                                    // `cb_src.buddy_hash` is the
                                    // `TAG_BUDDYHASH` value published by
                                    // the LowID peer, which eMule
                                    // `Search.cpp:665-670` computes as
                                    // `NOT(LowID_peer_kad_id)` — a
                                    // verification token, NOT the
                                    // buddy's actual KAD ID. The LowID
                                    // peer's `OP_CALLBACK` handler
                                    // (`ListenSocket.cpp:1337-1358`)
                                    // accepts the callback iff
                                    // `received_token XOR all_ones ==
                                    // my_kad_id`. We forward this
                                    // token unmodified as the first
                                    // 128-bit field of
                                    // `KADEMLIA_CALLBACK_REQ` so the
                                    // buddy relays it to its LowID
                                    // client via `OP_CALLBACK` with
                                    // `uCheck` intact.
                                    //
                                    // Looking this hash up in our
                                    // routing table to resolve the
                                    // buddy's UDP port was always
                                    // wrong — there's no contact with
                                    // ID = NOT(LowID_peer_kad_id) in
                                    // the routing table except by
                                    // astronomical coincidence.
                                    let buddy_hash = match &cb_src.buddy_hash {
                                        Some(h) => *h,
                                        None => {
                                            debug!("Skipping callback source {}: no buddy hash", buddy_ip);
                                            continue;
                                        }
                                    };

                                    let cb_key = (buddy_hash.0, fh);
                                    const MAX_CALLBACK_ATTEMPTS_PER_BUDDY: u32 = 3;
                                    const CALLBACK_ATTEMPT_RESET_SECS: i64 = 600; // 10 minutes
                                    let now_ts = chrono::Utc::now().timestamp();
                                    let attempts = match state.callback_buddy_attempts.get(&cb_key) {
                                        Some(&(count, first_ts)) if now_ts - first_ts < CALLBACK_ATTEMPT_RESET_SECS => count,
                                        Some(_) => {
                                            state.callback_buddy_attempts.remove(&cb_key);
                                            0
                                        }
                                        None => 0,
                                    };
                                    if attempts >= MAX_CALLBACK_ATTEMPTS_PER_BUDDY {
                                        debug!(
                                            "Skipping CallbackReq to buddy {} for file {} (already {} attempts)",
                                            hex::encode(buddy_hash.0), hex::encode(fh), attempts
                                        );
                                        continue;
                                    }

                                    let buddy_addr_raw = SocketAddr::new(buddy_ip.into(), buddy_port_raw);
                                    let buddy_addr_alt = SocketAddr::new(buddy_ip.into(), buddy_port_alt);
                                    let file_id = KadId(fh);
                                    let callback_req = KadMessage::CallbackReq {
                                        buddy_id: buddy_hash,
                                        file_id,
                                        tcp_port: state.tcp_port,
                                    };
                                    if let Ok(packet) = kad::messages::encode_packet(&callback_req) {
                                        // Fire both ports (see `buddy_port_raw`
                                        // comment above for rationale). The
                                        // second send is typically to a port
                                        // with no listener and silently fails
                                        // at the OS layer — zero protocol
                                        // impact but costs nothing to try.
                                        let _ = send_kad_packet(
                                            &udp_socket, &packet, buddy_addr_raw, &state, &buddy_hash,
                                        ).await;
                                        let _ = send_kad_packet(
                                            &udp_socket, &packet, buddy_addr_alt, &state, &buddy_hash,
                                        ).await;
                                        let entry = state.callback_buddy_attempts.entry(cb_key).or_insert((0, now_ts));
                                        entry.0 += 1;
                                        info!(
                                            "Sent KAD CallbackReq to buddy {} at {}/{} for file {} (attempt {})",
                                            buddy_hash, buddy_addr_raw, buddy_port_alt, hex::encode(fh), attempts + 1
                                        );
                                    }

                                    // Track source state in per-file list
                                    {
                                        let pfs = state.per_file_sources
                                            .entry(transfer_id.clone())
                                            .or_insert_with(|| ed2k::sources::PerFileSourceList::new(fh));
                                        if pfs.add_source_full(cb_src.ip, cb_src.tcp_port, 0) {
                                            state.ember_payload_dirty = true;
                                        }
                                        if state.firewalled || state.low_id {
                                            // Try broker only for peers that have advertised
                                            // Ember capability. `cb_src.is_ember_capable` was
                                            // set by `extract_kad_sources` when this entry
                                            // came back from the KAD search — see the parse
                                            // site in this file and the publish site in
                                            // `kad/publish.rs::build_source_publish`.
                                            let broker_started = if !cb_src.is_ember_capable {
                                                debug!(
                                                    "Skipping LowID-to-LowID broker for {}:{} — \
                                                     no Ember capability advertised in KAD record",
                                                    cb_src.ip, cb_src.tcp_port,
                                                );
                                                false
                                            } else if let Some(ref mut broker) = state.connection_broker {
                                                let ext = state.nat_info.external_addr;
                                                broker.attempt_low_to_low(
                                                    &transfer_id, fh, cb_src.ip, cb_src.tcp_port,
                                                    state.nat_info.nat_type, ext,
                                                ).await
                                            } else {
                                                false
                                            };
                                            if broker_started {
                                                pfs.set_ember_relay(cb_src.ip, cb_src.tcp_port);
                                            } else {
                                                pfs.set_low_to_low(cb_src.ip, cb_src.tcp_port);
                                            }
                                        } else {
                                            pfs.set_wait_callback_kad(cb_src.ip, cb_src.tcp_port);
                                        }
                                    }

                                    // Register expected callback so upload handler recognizes it
                                    let now = chrono::Utc::now().timestamp();
                                    let mut cbs = pending_kad_callbacks.lock().await;
                                    cbs.entry(cb_src.ip)
                                        .or_default()
                                        .push((fh, cb_src.source_user_hash, now));
                                }
                            }
                        }

                        // Send OP_DIRECTCALLBACKREQ for direct-callback sources.
                        if !direct_callback_sources.is_empty() {
                            for ds in &direct_callback_sources {
                                let addr = SocketAddr::new(ds.ip.into(), ds.udp_port);
                                let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_DIRECTCALLBACKREQ];
                                pkt.extend_from_slice(&state.tcp_port.to_le_bytes());
                                pkt.extend_from_slice(&state.user_hash);
                                pkt.push(build_kad_connect_options(&state) & 0x07);
                                let _ = udp_socket.send_to(&pkt, addr).await;
                                if let Some(fh) = resolved_file_hash {
                                    let now = chrono::Utc::now().timestamp();
                                    let mut cbs = pending_kad_callbacks.lock().await;
                                    cbs.entry(ds.ip)
                                        .or_default()
                                        .push((fh, ds.source_user_hash, now));
                                }
                            }
                        }

                        let sources: Vec<(String, u16)> = direct_sources.iter()
                            .map(|s| (s.ip.to_string(), s.tcp_port))
                            .collect();

                        // For KAD source-search results, the entry ID carries the source's
                        // ED2K user hash (eMule Search.cpp STOREFILE sender_id).
                        if let Some(fh) = resolved_file_hash {
                            let mut sm = source_manager.write().await;
                            for ds in &direct_sources {
                                sm.register_source_full_opts(
                                    fh,
                                    ds.ip,
                                    ds.tcp_port,
                                    ds.udp_port,
                                    ds.source_user_hash.unwrap_or([0u8; 16]),
                                    ds.connect_options,
                                );
                            }
                        }

                        // Register Type-2 (eD2K LowID) sources in the source manager;
                        // the existing server poll loop will send OP_CALLBACKREQUEST.
                        // Without a server connection these sources are unreachable,
                        // so skip registration and don't count them.
                        let effective_lowid = if !lowid_sources.is_empty() && state.server_connected {
                            if let Some(fh) = resolved_file_hash {
                                let mut sm = source_manager.write().await;
                                for ls in &lowid_sources {
                                    sm.register_lowid_source(
                                        fh,
                                        ls.lowid,
                                        ls.tcp_port,
                                        ls.ed2k_server_ip,
                                        ls.ed2k_server_port,
                                        ls.source_user_hash.unwrap_or([0u8; 16]),
                                        ls.connect_options,
                                    );
                                }
                                info!(
                                    "Registered {} Type-2 LowID sources for {}, server callbacks will be sent on next poll",
                                    lowid_sources.len(), transfer_id
                                );
                            }
                            lowid_sources.len()
                        } else {
                            if !lowid_sources.is_empty() {
                                info!(
                                    "Skipping {} Type-2 LowID sources for {} (no server connected, cannot relay callback)",
                                    lowid_sources.len(), transfer_id
                                );
                            }
                            0
                        };

                        let total_found = sources.len() + callback_sources.len() + effective_lowid;

                        if let Some(pending) = state.pending_downloads.remove(&transfer_id) {
                            if sources.is_empty() && callback_sources.is_empty() && effective_lowid == 0 {
                                info!("No sources found yet for {transfer_id}, will retry later");
                                state.pending_downloads.insert(transfer_id, pending);
                            } else if sources.is_empty() {
                                // Only callback/LowID sources — keep pending; callbacks
                                // will arrive via kad_callback_rx or server poll.
                                let indirect_count = callback_sources.len() + effective_lowid + type6_count;
                                info!(
                                    "Only indirect sources for {transfer_id}: {} callback, {} lowid, {} type6 — waiting for callbacks",
                                    callback_sources.len(), effective_lowid, type6_count
                                );
                                {
                                    let mut mgr = transfer_manager.write().await;
                                    mgr.update_sources(&transfer_id, indirect_count as u32, 0, 0);
                                    for cb_src in &callback_sources {
                                        mgr.update_source_detail(
                                            &transfer_id,
                                            crate::types::SourceInfo {
                                                ip: cb_src.ip.to_string(),
                                                port: cb_src.tcp_port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: "KAD Callback".to_string(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: crate::geoip::lookup_country(&geoip, std::net::IpAddr::V4(cb_src.ip)),
                                                source_origin: Some("kad".into()),
                                            },
                                        );
                                    }
                                    for dc_src in &direct_callback_sources {
                                        mgr.update_source_detail(
                                            &transfer_id,
                                            crate::types::SourceInfo {
                                                ip: dc_src.ip.to_string(),
                                                port: dc_src.tcp_port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: "KAD Direct Callback".to_string(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: crate::geoip::lookup_country(&geoip, std::net::IpAddr::V4(dc_src.ip)),
                                                source_origin: Some("kad".into()),
                                            },
                                        );
                                    }
                                    for ls in &lowid_sources {
                                        if state.server_connected {
                                            let ip_str = Ipv4Addr::from(ls.ed2k_server_ip).to_string();
                                            mgr.update_source_detail(
                                                &transfer_id,
                                                crate::types::SourceInfo {
                                                    ip: ip_str,
                                                    port: ls.ed2k_server_port,
                                                    status: crate::types::SourceStatus::Connecting,
                                                    queue_rank: None,
                                                    speed: 0,
                                                    transferred: 0,
                                                    client_software: "Low ID (Server Relay)".to_string(),
                                                    peer_name: String::new(),
                                                    available_parts: None,
                                                    total_parts: None,
                                                    country_code: crate::geoip::lookup_country(&geoip, std::net::IpAddr::V4(ls.ip)),
                                                    source_origin: Some("kad".into()),
                                                },
                                            );
                                        }
                                    }
                                }
                                let _ = app_handle.emit("transfer-status", serde_json::json!({
                                    "id": &transfer_id,
                                    "status": "searching",
                                    "sources": indirect_count,
                                    "active_sources": 0,
                                    "queued_sources": 0,
                                }));
                                state.pending_downloads.insert(transfer_id, pending);
                            } else {
                                let hash_bytes = match hex::decode(&pending.file_hash) {
                                    Ok(b) if b.len() == 16 => {
                                        let mut arr = [0u8; 16];
                                        arr.copy_from_slice(&b);
                                        arr
                                    }
                                    _ => {
                                        error!("Bad hash in pending download, re-queuing for retry");
                                        state.pending_downloads.insert(transfer_id, pending);
                                        continue;
                                    }
                                };

                                let sm_known = {
                                    let sm = source_manager.read().await;
                                    sm.source_count(&hash_bytes) as u32
                                };
                                // Include type-6 (direct-callback) in the
                                // visible-sources count. `total_found`
                                // is derived from
                                // `sources.len() + callback_sources.len()
                                //  + effective_lowid`, which deliberately
                                // omits type-6 because direct-callback is
                                // handled via a separate code path. But
                                // from the user's perspective a type-6
                                // source is "a source for this file that
                                // we're trying to reach" and must show
                                // up in the transfer's source count —
                                // otherwise sessions with several type-6
                                // peers display a source count
                                // significantly lower than eMule's for
                                // the same file.
                                let visible_total = (total_found as u32).saturating_add(type6_count as u32);
                                let source_count = visible_total.max(sm_known);
                                {
                                    let mut mgr = transfer_manager.write().await;
                                    mgr.update_status(&transfer_id, TransferStatus::Active);
                                    mgr.update_sources(&transfer_id, source_count, 0, 0);
                                    for (ip_s, port) in &sources {
                                        let cc = ip_s.parse::<std::net::IpAddr>().ok()
                                            .and_then(|ip| crate::geoip::lookup_country(&geoip, ip));
                                        mgr.update_source_detail(
                                            &transfer_id,
                                            crate::types::SourceInfo {
                                                ip: ip_s.clone(),
                                                port: *port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: String::new(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: cc,
                                                source_origin: Some("kad".into()),
                                            },
                                        );
                                    }
                                    // Also populate the per-source detail
                                    // rows for callback and type-6
                                    // (direct-callback) sources. These
                                    // are REAL sources we're actively
                                    // trying to reach — the CallbackReq
                                    // has already been sent to each
                                    // buddy (see `callback_sources` loop
                                    // earlier in this function) and
                                    // DIRECTCALLBACKREQ to each type-6
                                    // peer — so they belong in the
                                    // transfer's source table just as
                                    // much as HighID direct sources.
                                    // The previously-existing code only
                                    // registered these rows in the
                                    // "indirect-only" branch (when
                                    // `sources.is_empty()`); the same
                                    // sources being ALSO present as
                                    // direct candidates caused the
                                    // branch above to be taken, which
                                    // silently dropped the callback /
                                    // type-6 rows from the UI. Status
                                    // starts as `Connecting` for both
                                    // — the callback branch transitions
                                    // to `Queued` / `Transferring` once
                                    // the buddy relays and the LowID
                                    // peer connects back to us; the
                                    // type-6 branch transitions on the
                                    // UDP punch-response.
                                    for cb_src in &callback_sources {
                                        let cc = crate::geoip::lookup_country(
                                            &geoip, std::net::IpAddr::V4(cb_src.ip),
                                        );
                                        mgr.update_source_detail(
                                            &transfer_id,
                                            crate::types::SourceInfo {
                                                ip: cb_src.ip.to_string(),
                                                port: cb_src.tcp_port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: "KAD Callback".to_string(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: cc,
                                                source_origin: Some("kad".into()),
                                            },
                                        );
                                    }
                                    for dc_src in &direct_callback_sources {
                                        let cc = crate::geoip::lookup_country(
                                            &geoip, std::net::IpAddr::V4(dc_src.ip),
                                        );
                                        mgr.update_source_detail(
                                            &transfer_id,
                                            crate::types::SourceInfo {
                                                ip: dc_src.ip.to_string(),
                                                port: dc_src.tcp_port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: "KAD Direct Callback".to_string(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: cc,
                                                source_origin: Some("kad".into()),
                                            },
                                        );
                                    }
                                }
                                let peer_desc = sources.iter()
                                    .map(|(ip, port)| format!("{ip}:{port}"))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                let _ = app_handle.emit("transfer-status", serde_json::json!({
                                    "id": transfer_id,
                                    "status": "active",
                                    "peer_id": peer_desc,
                                    "sources": source_count,
                                    "active_sources": 0,
                                    "queued_sources": 0,
                                }));

                                // Populate persistent per-file source list
                                {
                                    let pfs = state.per_file_sources
                                        .entry(transfer_id.clone())
                                        .or_insert_with(|| ed2k::sources::PerFileSourceList::new(hash_bytes));
                                    for (ip_s, port) in &sources {
                                        if let Ok(v4) = ip_s.parse::<Ipv4Addr>() {
                                            let udp_port = {
                                                let sm = source_manager.read().await;
                                                sm.get_udp_sources(&hash_bytes)
                                                    .into_iter()
                                                    .find(|(ip, tcp_port, _)| ip == &v4 && tcp_port == port)
                                                    .map(|(_, _, udp)| udp)
                                                    .unwrap_or(0)
                                            };
                                            if pfs.add_source_full(v4, *port, udp_port) {
                                                state.ember_payload_dirty = true;
                                            }
                                        }
                                    }
                                }

                                {
                                    let live_sources: Vec<&(String, u16)> = sources
                                        .iter()
                                        .filter(|(ip, port)| {
                                            if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                                                !state.dead_sources.is_dead_source_for_file(&hash_bytes, u32::from(v4), *port)
                                            } else {
                                                true
                                            }
                                        })
                                        .collect();
                                    if live_sources.is_empty() {
                                        debug!("All {} sources are dead for {transfer_id}, re-queuing", sources.len());
                                        state.pending_downloads.insert(transfer_id, pending);
                                        continue;
                                    }
                                    info!(
                                        "Starting multi-source download {transfer_id} from {} sources ({} dead filtered)",
                                        live_sources.len(), sources.len() - live_sources.len()
                                    );
                                    {
                                        let mut sm = source_manager.write().await;
                                        for (ip, port) in &sources {
                                            if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                                                sm.register_source(hash_bytes, v4, *port);
                                            }
                                        }
                                    }
                                    // D9: dedup (ip, port) — see the
                                    // equivalent block in the initial-start
                                    // path for rationale.
                                    let download_sources: Vec<DownloadSource> = {
                                        let sm = source_manager.read().await;
                                        let mut seen: HashSet<(String, u16)> = HashSet::new();
                                        let mut out: Vec<DownloadSource> = Vec::with_capacity(live_sources.len());
                                        for (ip, port) in live_sources {
                                            if !seen.insert((ip.clone(), *port)) { continue; }
                                            let uh = ip.parse::<Ipv4Addr>().ok()
                                                .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
                                            let co = ip.parse::<Ipv4Addr>().ok()
                                                .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
                                            out.push(DownloadSource {
                                                peer_ip: ip.clone(),
                                                peer_port: *port,
                                                available_parts: Vec::new(),
                                                peer_user_hash: uh,
                                                peer_connect_options: co,
                                            });
                                        }
                                        out
                                    };
                                    let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
                                    let (est_inject_tx, est_inject_rx) =
                                        mpsc::channel::<ed2k::multi_source::EstablishedSource>(8);
                                    let ms_download = MultiSourceDownload {
                                        transfer_id: pending.transfer_id,
                                        file_hash: hash_bytes,
                                        file_name: pending.file_name,
                                        file_size: pending.file_size,
                                        sources: download_sources,
                                        download_dir: PathBuf::from(&settings.download_folder),
                                        user_hash: state.user_hash,
                                        nickname: settings.nickname.clone(),
                                        tcp_port: settings.tcp_port,
                                        udp_port: settings.udp_port,
                                        bandwidth_limiter: bandwidth_limiter.clone(),
                                        control: pending.control,
                                        source_manager: Some(source_manager.clone()),
                                        comment_manager: Some(state.comment_manager.clone()),
                                        credit_manager: Some(credit_manager.clone()),
                                        shared_buddy_info: Some(state.shared_buddy_info.clone()),
                                        obfuscation_enabled: state.obfuscation_enabled,
                                        server_addr: state.server_addr,
                                        new_source_rx: Some(src_inject_rx),
                                        new_established_rx: Some(est_inject_rx),
                        ed2k_limits: settings.ed2k_download_limits(),
                        ember_hash,
                        friend_hashes: Some(friend_hashes.clone()),
                                        ember_payload: shared_ember_payload.clone(),
                                        ember_payload_generation: ember_payload_generation.clone(),
                                        ip_filter: Some(state.shared_ip_filter.clone()),
                                        banned_ips: Some(shared_banned_ips.clone()),
                                        external_ip: state.external_ip,
                                        aich_pending: Some(state.aich_recovery_pending.clone()),
                                        geoip: geoip.clone(),
                                        tracker_registry: Some(state.tracker_registry.clone()),
                                        sx_overhead: stats_manager.sx_counters.clone(),
                                    };
                                    let tid = ms_download.transfer_id.clone();
                                    let tid2 = tid.clone();
                                    state.active_source_senders.insert(tid.clone(), src_inject_tx);
                                    state.active_established_senders.insert(tid.clone(), est_inject_tx);
                                    let tx = dl_event_tx.clone();
                                    let tx2 = tx.clone();
                                    if let Some(old_handle) = state.download_handles.remove(&tid2) {
                                        old_handle.abort();
                                    }
                                    let handle = tokio::spawn(async move {
                                        if let Err(e) = ms_download.run(tx).await {
                                            error!("Multi-source download failed: {e}");
                                            let kind = classify_error(&e.to_string());
                                            let _ = tx2.send(DownloadEvent::Failed { transfer_id: tid, error: e.to_string(), failure_kind: kind }).await;
                                        }
                                    });
                                    state.download_handles.insert(tid2, handle);
                                }
                            }
                        } else if let Some(fh) = resolved_file_hash {
                            // Download is already active — inject KAD sources into it
                            if !sources.is_empty() {
                                let matching_ids = vec![transfer_id.clone()];
                                let sm = source_manager.read().await;
                                let mut injected = 0usize;
                                for (ip_s, port) in &sources {
                                    let uh = ip_s.parse::<Ipv4Addr>().ok()
                                        .and_then(|v4| sm.get_user_hash(&fh, v4, *port));
                                    let co = ip_s.parse::<Ipv4Addr>().ok()
                                        .and_then(|v4| sm.get_connect_options(&fh, v4, *port));
                                    let ds = DownloadSource {
                                        peer_ip: ip_s.clone(),
                                        peer_port: *port,
                                        available_parts: Vec::new(),
                                        peer_user_hash: uh,
                                        peer_connect_options: co,
                                    };
                                    let stats = inject_source_into_active_transfers(
                                        &mut state, fh, &matching_ids, &ds, 0,
                                    );
                                    injected += stats.injected;
                                }
                                drop(sm);
                                if injected > 0 {
                                    info!(
                                        "Injected {} KAD sources into already-active download {}",
                                        injected, transfer_id
                                    );
                                    let sm_known = {
                                        let sm2 = source_manager.read().await;
                                        sm2.source_count(&fh) as u32
                                    };
                                    // Include type-6 in the visible total
                                    // — see the parallel fix at the
                                    // `sources.is_empty() == false` branch
                                    // above for the full rationale.
                                    let visible_total = (total_found as u32).saturating_add(type6_count as u32);
                                    let source_count = visible_total.max(sm_known);
                                    let mut mgr = transfer_manager.write().await;
                                    mgr.update_sources(&transfer_id, source_count, 0, 0);
                                    // Populate UI source-detail rows for
                                    // callback and type-6 sources so the
                                    // transfer's Sources tab reflects
                                    // what's actually being pursued. The
                                    // CallbackReq / DIRECTCALLBACKREQ
                                    // was already dispatched earlier in
                                    // this function; these rows tell
                                    // the user "we're waiting on these
                                    // peers to connect back to us".
                                    // Without them the user only sees
                                    // the ~4-6 direct sources and
                                    // thinks Ember is finding half what
                                    // eMule finds for the same file.
                                    for cb_src in &callback_sources {
                                        let cc = crate::geoip::lookup_country(
                                            &geoip, std::net::IpAddr::V4(cb_src.ip),
                                        );
                                        mgr.update_source_detail(
                                            &transfer_id,
                                            crate::types::SourceInfo {
                                                ip: cb_src.ip.to_string(),
                                                port: cb_src.tcp_port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: "KAD Callback".to_string(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: cc,
                                                source_origin: Some("kad".into()),
                                            },
                                        );
                                    }
                                    for dc_src in &direct_callback_sources {
                                        let cc = crate::geoip::lookup_country(
                                            &geoip, std::net::IpAddr::V4(dc_src.ip),
                                        );
                                        mgr.update_source_detail(
                                            &transfer_id,
                                            crate::types::SourceInfo {
                                                ip: dc_src.ip.to_string(),
                                                port: dc_src.tcp_port,
                                                status: crate::types::SourceStatus::Connecting,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: "KAD Direct Callback".to_string(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: cc,
                                                source_origin: Some("kad".into()),
                                            },
                                        );
                                    }
                                }
                            }
                        }
                    } else if let Some(tx) = state.pending_notes_searches.remove(&sid) {
                        let results = if let Some(search) = state.search_manager.get(&sid) {
                            info!(
                                "Notes search {} completed: {} results",
                                sid.0, search.results.len()
                            );
                            convert_note_search_results(&search.results, &search.target)
                        } else {
                            Vec::new()
                        };
                        let _ = tx.send(results);
                    } else if let Some((file, kw_publishes)) = state.store_keyword_searches.remove(&sid) {
                        // StoreKeyword search completed - send publish messages to the closest nodes found
                        if let Some(search) = state.search_manager.get(&sid) {
                            let now = chrono::Utc::now().timestamp();
                            let mut sent_any = false;
                            for (kw_hash, msg) in &kw_publishes {
                                for contact in search.closest.iter()
                                    .filter(|c| !state.overloaded_nodes.contains_key(&c.ip))
                                    .take(10)
                                {
                                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                    if let Ok(packet) = messages::encode_packet(msg) {
                                        state.flood_protection.track_request(addr, kad_request_opcode(msg).unwrap_or(0));
                                        let _ = send_kad_packet(&udp_socket, &packet, addr, &state, &contact.id).await;
                                        // Per-peer pending entry so every ack counts.
                                        state.publish_pending.insert(
                                            (*kw_hash, addr),
                                            (file.file_hash, now, false),
                                        );
                                        sent_any = true;
                                    }
                                }
                            }
                            if sent_any {
                                state.publish_manager.mark_keyword_published(&file.file_hash);
                                info!(
                                    "StoreKeyword search {} completed: published {} keywords to {} closest nodes",
                                    sid.0, kw_publishes.len(), search.closest.len().min(3)
                                );
                            }
                        }
                    } else if let Some((file_hash, msg)) = state.store_source_searches.remove(&sid) {
                        // StoreSource search completed - send source publish to remaining
                        // within-tolerance responded contacts not already published during Lookup.
                        if let Some(search) = state.search_manager.get(&sid) {
                            let now = chrono::Utc::now().timestamp();
                            let mut sent = 0;
                            let already_published = &search.store_sent;
                            let responded = &search.responded_during_lookup;
                            let candidates: Vec<&kad::types::KadContact> = search.closest.iter()
                                .filter(|c| {
                                    !already_published.contains(&c.id)
                                        && !state.overloaded_nodes.contains_key(&c.ip)
                                        && responded.contains(&c.id)
                                        && kad::search::within_search_tolerance_pub(&search.target, &c.id)
                                })
                                .collect();
                            for contact in candidates {
                                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                if let Ok(packet) = messages::encode_packet(&msg) {
                                    state.flood_protection.track_request(addr, kad_request_opcode(&msg).unwrap_or(0));
                                    let _ = send_kad_packet(&udp_socket, &packet, addr, &state, &contact.id).await;
                                    // Per-peer pending entry — we track the
                                    // store's target rather than `file_hash` so
                                    // remove-on-ack matches the target echoed
                                    // in PublishRes (for source publishes these
                                    // are the same value, but keyword/notes
                                    // would differ).
                                    state.publish_pending.insert(
                                        (search.target, addr),
                                        (file_hash, now, true),
                                    );
                                    sent += 1;
                                }
                            }
                            let total_published = already_published.len() + sent;
                            if total_published > 0 {
                                state.publish_manager.mark_source_published(&file_hash);
                                // Fresh publish cycle: reset ack counter so the
                                // Sources column reflects acks from THIS cycle only.
                                state.source_publish_acks.insert(file_hash, 0);
                                info!("StoreSource search {} completed: published to {} nodes ({} during lookup, {} at completion)",
                                    sid.0, total_published, already_published.len(), sent);
                            }
                        }
                    } else if let Some((file_hash, rating, comment)) = state.pending_note_publishes.remove(&sid) {
                        // StoreNotes search completed - send PublishNotesReq to closest nodes
                        if let Some(search) = state.search_manager.get(&sid) {
                            let local_note_file = {
                                let index = local_index.read().await;
                                index.get_by_hash(&file_hash.to_hex()).cloned()
                            };
                            let mut note_tags = Vec::new();
                            if let Some(file) = local_note_file {
                                note_tags.push(KadTag {
                                    name: TagName::Id(TAG_FILENAME),
                                    value: TagValue::String(file.name),
                                });
                                note_tags.push(KadTag {
                                    name: TagName::Id(TAG_FILESIZE),
                                    value: TagValue::Uint64(file.size),
                                });
                            }
                            if !comment.is_empty() {
                                note_tags.push(KadTag {
                                    name: TagName::Id(TAG_DESCRIPTION),
                                    value: TagValue::String(comment),
                                });
                            }
                            if rating > 0 {
                                note_tags.push(KadTag {
                                    name: TagName::Id(TAG_FILERATING),
                                    value: TagValue::Uint8(rating),
                                });
                            }
                            let msg = KadMessage::PublishNotesReq {
                                target: file_hash,
                                sender_id: state.local_id,
                                tags: note_tags,
                            };
                            let now = chrono::Utc::now().timestamp();
                            let mut sent = 0;
                            for contact in search.closest.iter().take(10) {
                                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                if let Ok(packet) = messages::encode_packet(&msg) {
                                    state.flood_protection.track_request(addr, kad_request_opcode(&msg).unwrap_or(0));
                                    let _ = send_kad_packet(&udp_socket, &packet, addr, &state, &contact.id).await;
                                    // Track per-peer pending entry so the
                                    // PublishRes handler can match and bump
                                    // `publish_confirmed`. The Source and
                                    // Keyword paths already do this; the
                                    // Notes path used to skip it, which made
                                    // every notes ack show up as
                                    // `publish_res_unmatched` in diagnostics
                                    // even when the publish succeeded.
                                    state.publish_pending.insert(
                                        (file_hash, addr),
                                        (file_hash, now, false),
                                    );
                                    sent += 1;
                                }
                            }
                            if sent > 0 {
                                info!(
                                    "StoreNotes search {} completed: published note (rating={}) to {} closest nodes",
                                    sid.0, rating, sent
                                );
                            }
                        }
                    }

                    // FindBuddy convergence sweep: send FindBuddyReq to all closest
                    // contacts discovered during the DHT walk. We already sent to
                    // each responding node during lookup (eMule behavior), but this
                    // final sweep catches any contacts that were discovered but not
                    // yet directly queried.
                    if let Some(search) = state.search_manager.get(&sid) {
                        if matches!(search.search_type, SearchType::FindBuddy) {
                            if state.buddy_manager.state() == BuddyState::FindingBuddy {
                                let target = search.target;
                                let already_sent: HashSet<KadId> = search.responded_during_lookup.clone();
                                let extra_contacts: Vec<KadContact> = search.closest.iter()
                                    .filter(|c| !already_sent.contains(&c.id))
                                    .take(20)
                                    .cloned()
                                    .collect();

                                if !extra_contacts.is_empty() {
                                    let user_id = KadId(cuint128_swap(&state.user_hash));
                                    let local_tcp = state.buddy_manager.tcp_port();
                                    let mut sent = 0;
                                    for contact in &extra_contacts {
                                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                        let msg = KadMessage::FindBuddyReq {
                                            buddy_id: target,
                                            user_id,
                                            tcp_port: local_tcp,
                                        };
                                        if let Ok(packet) = messages::encode_packet(&msg) {
                                            state.flood_protection.track_request(addr, 0x51);
                                            let _ = send_kad_packet(&udp_socket, &packet, addr, &state, &contact.id).await;
                                            sent += 1;
                                        }
                                    }
                                    info!(
                                        "FindBuddy search {} converged: sent FindBuddyReq to {} additional contacts (already sent to {} during lookup)",
                                        sid.0, sent, already_sent.len()
                                    );
                                } else if already_sent.is_empty() {
                                    state.buddy_manager.find_failed();
                                    info!("FindBuddy search {} completed without finding any reachable contacts", sid.0);
                                } else {
                                    info!(
                                        "FindBuddy search {} converged: already sent FindBuddyReq to {} nodes during lookup",
                                        sid.0, already_sent.len()
                                    );
                                }
                            }
                        }
                    }

                    if let Some(removed) = state.search_manager.remove(&sid) {
                        state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                    }
                }
            }

            // Periodic bootstrap (eMule BigTimer style)
            _ = bootstrap_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let table_size = state.routing_table.len();

                if table_size == 0 {
                    bootstrap_attempts += 1;
                    if bootstrap_attempts == 5 {
                        warn!("No peers found after {} bootstrap attempts", bootstrap_attempts);
                        let _ = app_handle.emit("network-error", serde_json::json!({
                            "message": "Unable to connect to the KAD network. Try downloading the latest nodes.dat from Settings > Network.",
                        }));
                    }
                } else {
                    bootstrap_attempts = 0;
                }

                // Self-lookup: FindNode for our own ID to populate close-to-home buckets.
                // eMule: m_tNextSelfLookup = start + MIN2S(3), then + HR2S(4) after each run.
                const SELF_LOOKUP_FIRST_DELAY_SECS: i64 = 3 * 60;
                const SELF_LOOKUP_REPEAT_SECS: i64 = 4 * 3600;
                let now_ts = chrono::Utc::now().timestamp();
                let self_lookup_due = if !state.self_lookup_done {
                    now_ts >= state.kad_started_at + SELF_LOOKUP_FIRST_DELAY_SECS
                } else {
                    now_ts - state.last_self_lookup >= SELF_LOOKUP_REPEAT_SECS
                };
                if table_size >= 2 && self_lookup_due {
                    let closest = state.routing_table.find_closest(&state.local_id, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        let sid = state.search_manager.start_search(
                            state.local_id,
                            SearchType::FindNode,
                            closest,
                        );
                        if sid != SearchId(0) {
                            info!("Started self-lookup (FindNode for own ID), search {}, table has {table_size} contacts", sid.0);
                            state.self_lookup_done = true;
                            state.last_self_lookup = now_ts;
                        }
                    }
                }

                // Yield between major bootstrap sections so Tauri IPC handlers
                // aren't starved in debug builds where this work is slow.
                tokio::task::yield_now().await;

                // Keep bootstrapping until we have a healthy routing table (~200 contacts)
                if table_size < 200 {
                    // eMule: only send BootstrapReq to hardcoded nodes while NOT connected.
                    // Once connected, rely on FindNode searches and eMule big-timer RandomLookup for growth.
                    if state.stats.status != NetworkStatus::Connected {
                        for contact in &bootstrap::default_bootstrap_contacts() {
                            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                            let msg = KadMessage::BootstrapReq;
                            if let Ok(packet) = messages::encode_packet(&msg) {
                                let _ = udp_socket.send_to(&packet, addr).await;
                            }
                        }
                    }

                    // Query a sample of known contacts with BootstrapReq to discover
                    // new peers from their routing tables.
                    let bootstrap_sample_size = if table_size < 50 { 10 } else { 5 };
                    let sample: Vec<KadContact> = {
                        let target = KadId::random();
                        state.routing_table.find_closest(&target, bootstrap_sample_size)
                    };
                    for contact in &sample {
                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                        let msg = KadMessage::BootstrapReq;
                        if let Ok(packet) = messages::encode_packet(&msg) {
                            state.flood_protection.track_request(addr, 0x01);
                            let _ = send_kad_packet(
                                &udp_socket,
                                &packet,
                                addr,
                                &state,
                                &contact.id,
                            )
                            .await;
                        }
                    }
                }

                tokio::task::yield_now().await;

                // Firewall detection using FirewallChecker
                if !state.firewall_checker.is_checking() && state.firewall_checker.should_recheck() && table_size >= 10 {
                    state.firewall_checker.start_check();
                    state.external_udp_port = None;
                    if let Ok(mut probes) = firewall_probe_ips.lock() { probes.clear(); }
                    let checks = state.firewall_checker.checks_to_send() as usize;

                    let fw_contacts: Vec<KadContact> = state
                        .routing_table
                        .all_contacts()
                        .filter(|c| c.verified && !c.is_dead())
                        .take(checks)
                        .cloned()
                        .collect();
                    for contact in &fw_contacts {
                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                        let (msg, track_opcode) = if contact.version > KADEMLIA_VERSION6_49ABETA {
                            (KadMessage::Firewalled2Req {
                                tcp_port: state.tcp_port,
                                user_hash: state.user_hash,
                                connect_options: build_kad_connect_options(&state),
                            }, 0x53u8)
                        } else {
                            (KadMessage::FirewalledReq { tcp_port: state.tcp_port }, 0x50u8)
                        };
                        if let Ok(packet) = messages::encode_packet(&msg) {
                            state.flood_protection.track_request(addr, track_opcode);
                            if let Ok(mut probes) = firewall_probe_ips.lock() { probes.insert(contact.ip); }
                            let _ = send_kad_packet(
                                &udp_socket, &packet, addr, &state, &contact.id,
                            ).await;
                            state.firewall_checker.record_tcp_request_sent(contact.ip);
                        }
                    }
                    let udp_contacts: Vec<KadContact> = state
                        .routing_table
                        .all_contacts()
                        .filter(|c| c.verified && !c.is_dead())
                        .skip(checks)
                        .take(checks)
                        .cloned()
                        .collect();
                    for contact in &udp_contacts {
                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                        let msg = KadMessage::Ping;
                        if let Ok(packet) = messages::encode_packet(&msg) {
                            state.flood_protection.track_request(addr, 0x60);
                            let _ = send_kad_packet(
                                &udp_socket, &packet, addr, &state, &contact.id,
                            ).await;
                            state.firewall_checker.record_udp_port_probe_sent();
                        }
                    }
                    // Eagerly dispatch UDP firewall probes now. If a previous
                    // cycle already learned the external UDP port it is still
                    // available in firewall_checker; otherwise the function
                    // falls back to settings.udp_port.  The Pong handler will
                    // also call dispatch again once fresh pongs refine the port.
                    dispatch_udp_firewall_probe_requests(&mut state, &settings);
                }

                if state.firewall_checker.evaluate() {
                    let was_udp_fw = state.udp_firewalled;
                    let was_tcp_fw = state.firewalled;
                    let had_ip = state.external_ip.is_some();
                    state.firewalled = state.firewall_checker.tcp_firewalled();
                    state.udp_firewalled = state.firewall_checker.udp_firewalled();
                    // The UI "Firewalled" badge reflects TCP reachability (HighID vs LowID),
                    // matching eMule's traditional meaning.  TCP/UDP Reachability are shown
                    // separately in the UI for detailed status.
                    state.stats.firewalled = state.firewalled;
                    state.firewalled_shared.store(state.firewalled, std::sync::atomic::Ordering::Relaxed);
                    update_publish_manager_state(&mut state);
                    let tcp_status = state.firewall_checker.tcp_status();
                    let udp_status = state.firewall_checker.udp_status();
                    state.stats.tcp_status = format!("{:?}", tcp_status);
                    state.stats.udp_status = format!("{:?}", udp_status);
                    if let Some(ip) = state.firewall_checker.external_ip() {
                        set_external_ip(&mut state, Some(ip));
                        state.stats.external_ip = ip.to_string();
                        state.routing_table.set_external_ip(ip);
                    }
                    info!("Firewall check result: TCP={:?} UDP={:?} (ports tcp={} udp={})",
                        tcp_status, udp_status, state.tcp_port, state.udp_port);
                    // Initial NAT probe as soon as we learn our external IP
                    if !had_ip && state.external_ip.is_some() && state.nat_info.nat_type == ember::nat::NatType::Unknown {
                        info!("External IP discovered via firewall check — running initial NAT probe");
                        state.nat_info = ember::nat::probe_nat(&udp_socket).await;
                        // Same HighID fallback as the KAD-discovery and
                        // server-HighID paths: STUN can fail wholesale
                        // even when we know our external IP. Without
                        // this, `nat_info.nat_type` stays `Unknown`,
                        // `is_punchable()` returns false, and every
                        // LowID-to-LowID attempt is forced into the
                        // relay path instead of trying hole-punch first.
                        if let Some(ext_ip) = state.external_ip {
                            if state.nat_info.apply_highid_fallback(
                                std::net::IpAddr::V4(ext_ip),
                                state.udp_port,
                            ) {
                                info!(
                                    "NAT probe failed but firewall check confirmed external IP {} — assuming PortRestricted (mapped {}:{})",
                                    ext_ip, ext_ip, state.udp_port,
                                );
                            }
                        }
                    }
                    let status_changed = was_udp_fw != state.udp_firewalled
                        || was_tcp_fw != state.firewalled
                        || (!had_ip && state.external_ip.is_some());
                    if status_changed {
                        let _ = app_handle.emit("firewall-status", serde_json::json!({
                            "firewalled": state.firewalled,
                            "external_ip": state.stats.external_ip,
                            "tcp_status": format!("{:?}", tcp_status),
                            "udp_status": format!("{:?}", udp_status),
                        }));
                    }
                    if was_tcp_fw && !state.firewalled {
                        if state.buddy_manager.state() == BuddyState::FindingBuddy {
                            state.buddy_manager.find_failed();
                            info!("Cancelled buddy search: TCP firewall is open, no buddy needed");
                        }
                    }
                }

                tokio::task::yield_now().await;

                // Sync firewalled status from TCP connect-back detection or UPnP.
                // Only allow the atomic to CLEAR the firewalled flag, never re-assert it,
                // so it doesn't overwrite the FirewallChecker's determination.
                let fw_from_shared = state.firewalled_shared.load(std::sync::atomic::Ordering::Relaxed);
                if state.firewalled && !fw_from_shared {
                    info!("TCP confirmed open (connect-back or UPnP), clearing TCP firewalled status");
                    state.firewalled = false;
                    state.firewall_checker.handle_tcp_connect_back();
                    update_publish_manager_state(&mut state);
                    state.stats.firewalled = state.firewalled;
                    if let Some(ip) = state.external_ip {
                        state.stats.external_ip = ip.to_string();
                    }
                    state.stats.upnp_mapped = state.upnp_mapped;
                    let tcp_status = state.firewall_checker.tcp_status();
                    let udp_status = state.firewall_checker.udp_status();
                    state.stats.tcp_status = format!("{:?}", tcp_status);
                    state.stats.udp_status = format!("{:?}", udp_status);
                    let _ = app_handle.emit("firewall-status", serde_json::json!({
                        "firewalled": state.firewalled,
                        "external_ip": state.stats.external_ip,
                        "tcp_status": format!("{:?}", tcp_status),
                        "udp_status": format!("{:?}", udp_status),
                    }));
                }

                let count = state.routing_table.len() as u32;
                info!("Routing table: {count} contacts");
                if count > 0 && state.stats.status != NetworkStatus::Connected {
                    state.stats.status = NetworkStatus::Connected;
                    let _ = app_handle.emit("network-status", NetworkStatus::Connected);

                    // Populate publish manager with all shared files on first connect
                    if !state.first_publish_done {
                        state.first_publish_done = true;
                        let files: Vec<PublishableFile> = {
                            let index = local_index.read().await;
                            index.all_files()
                                .iter()
                                .filter(|f| f.shared)
                                .filter_map(|f| {
                                    let hash_bytes = hex::decode(&f.hash).ok()?;
                                    if hash_bytes.len() < 16 { return None; }
                                    Some(PublishableFile {
                                        file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                                        file_name: f.name.clone(),
                                        file_size: f.size,
                                        file_type: crate::search::index::infer_file_type(&f.extension),
                                        complete_sources: f.complete_sources,
                                    })
                                })
                                .collect()
                        };
                        let shared_count = files.len();
                        state.publish_manager.add_files_batch(files);

                        let mut partial_count = 0u32;
                        {
                            let mgr = transfer_manager.read().await;
                            for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                                if transfer.direction != TransferDirection::Download { continue; }
                                if matches!(transfer.status, TransferStatus::Completed | TransferStatus::Failed) { continue; }
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
                                });
                                partial_count += 1;
                            }
                        }
                        info!("Populated publish manager with {shared_count} shared files + {partial_count} partial downloads after bootstrap");
                    }

                }

                // Start initial KAD source searches for pending downloads once KAD
                // is connected (separate from the status transition above because
                // the KAD response handler may set Connected before this timer fires).
                if count > 0 && !state.kad_initial_source_burst_done && !state.pending_downloads.is_empty() {
                    state.kad_initial_source_burst_done = true;
                    {
                        let pending_count = state.pending_downloads.len();
                        info!("KAD connected: triggering source search for {pending_count} pending downloads");
                        let now = chrono::Utc::now().timestamp();
                        let mut tids: Vec<String> = state.pending_downloads.keys().cloned().collect();
                        let mut kad_started = 0usize;
                        const MAX_INITIAL_KAD: usize = 20;
                        if tids.len() > MAX_INITIAL_KAD {
                            let rotate_by = state.kad_source_search_cursor % tids.len();
                            tids.rotate_left(rotate_by);
                            state.kad_source_search_cursor = state.kad_source_search_cursor.wrapping_add(MAX_INITIAL_KAD);
                        }
                        for tid in tids {
                            let (hash_bytes, file_size) = {
                                let Some(pd) = state.pending_downloads.get_mut(&tid) else { continue; };
                                if pd.control.is_cancelled() || pd.control.is_paused() { continue; }
                                let hash_bytes = match hex::decode(&pd.file_hash) {
                                    Ok(b) if b.len() == 16 => b,
                                    _ => continue,
                                };
                                (hash_bytes, pd.file_size)
                            };

                            let mut did_search = false;
                            let mut file_hash_arr = [0u8; 16];
                            file_hash_arr.copy_from_slice(&hash_bytes[..16]);

                            if kad_started < MAX_INITIAL_KAD {
                                let kad_hash = md4_bytes_to_kad_id(&hash_bytes);
                                let closest = state.routing_table.find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                                if !closest.is_empty() {
                                    let sid = state.search_manager.start_search(
                                        kad_hash,
                                        SearchType::FindSource { file_size },
                                        closest,
                                    );
                                    if sid != SearchId(0) {
                                        state.download_source_searches.insert(sid, (tid.clone(), file_hash_arr));
                                        kad_started += 1;
                                        did_search = true;
                                    }
                                }
                            }

                            let mut fh = [0u8; 16];
                            fh.copy_from_slice(&hash_bytes);
                            let src_count = {
                                let sm = source_manager.read().await;
                                sm.source_count(&fh)
                            };
                            if src_count < MAX_SOURCES_FOR_UDP {
                                let packets = build_all_getsources_packets(
                                    &state,
                                    &fh,
                                    file_size,
                                );
                                if !packets.is_empty() {
                                    let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                                    let to_queue: Vec<_> = packets.into_iter().take(room).collect();
                                    if !to_queue.is_empty() { did_search = true; }
                                    state.udp_source_queue.extend(to_queue);
                                }
                            }

                            if did_search {
                                if let Some(pd) = state.pending_downloads.get_mut(&tid) {
                                    pd.search_count += 1;
                                    pd.last_search_at = now;
                                }
                            }
                        }
                        if pending_count > MAX_INITIAL_KAD {
                            info!("Started {kad_started} KAD searches initially; remaining {} will search on next retry cycle", pending_count - kad_started);
                        }
                    }
                }
                // Register with the rendezvous server as soon as we have a
                // confirmed external IP so other Ember clients can find us.
                if !state.friend_presence_initial_done
                    && state.external_ip.is_some()
                {
                    state.friend_presence_initial_done = true;

                    // Initialize the LowID-to-LowID connection broker
                    // **before** registering with rendezvous. Rendezvous
                    // advertises the port other clients should QUIC-dial,
                    // so we have to know the QUIC endpoint's actual bound
                    // port first — `build_server_client_endpoint` may
                    // fall back from `tcp_port` if it's already in use
                    // (e.g. tcp_port == udp_port).
                    if state.connection_broker.is_none() {
                        let (broker_tx, broker_rx) = mpsc::channel(32);
                        let mut broker = ember::broker::ConnectionBroker::new(
                            settings.rendezvous_url.clone(),
                            broker_tx,
                        );

                        match ember::quic::generate_self_signed_cert(&ember_hash) {
                            Ok((cert_der, key_der)) => {
                                match ember::quic::build_server_client_endpoint(
                                    &cert_der,
                                    &key_der,
                                    state.tcp_port,
                                ) {
                                    Ok(ep) => {
                                        let bound_port = ep
                                            .local_addr()
                                            .map(|a| a.port())
                                            .unwrap_or(state.tcp_port);
                                        state.quic_port = Some(bound_port);
                                        let ep_arc = std::sync::Arc::new(ep);
                                        broker.set_quic_endpoint(ep_arc.clone());
                                        tracing::info!(
                                            "Broker: QUIC server+client endpoint ready on UDP port {bound_port}",
                                        );

                                        let relay_mgr = state.relay_manager.clone();
                                        let quic_cb_tx = kad_callback_tx.clone();
                                        tokio::spawn(ember::relay::run_quic_accept_loop(
                                            ep_arc,
                                            relay_mgr,
                                            quic_cb_tx,
                                        ));
                                        tracing::info!("QUIC accept loop spawned");
                                    }
                                    Err(e) => {
                                        tracing::warn!("Broker: failed to create QUIC endpoint: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Broker: failed to generate QUIC cert: {e}");
                            }
                        }

                        state.connection_broker = Some(broker);
                        state.broker_event_rx = Some(broker_rx);
                    }

                    // Use the *actual* QUIC port if the broker bound one,
                    // otherwise fall back to the configured tcp_port (so
                    // we still register even if QUIC failed entirely —
                    // friend presence works without QUIC).
                    let rv_url = settings.rendezvous_url.clone();
                    let rv_port = state.quic_port.unwrap_or(settings.tcp_port);
                    let rv_hash = ember_hash;
                    let rv_ip = state.external_ip;
                    let app_rv = app_handle.clone();
                    tokio::spawn(async move {
                        match rendezvous::register(&rv_url, &rv_hash, rv_port, rv_ip).await {
                            Ok(()) => {
                                let _ = app_rv.emit("ember:friend-discoverable", serde_json::json!({
                                    "discoverable": true,
                                }));
                            }
                            Err(e) => {
                                warn!("Initial rendezvous register failed: {e}");
                                let _ = app_rv.emit("ember:friend-discoverable", serde_json::json!({
                                    "discoverable": false,
                                    "reason": "rendezvous_error",
                                }));
                            }
                        }
                    });
                    state.rendezvous_registered = true;
                    state.rendezvous_last_register = Some(std::time::Instant::now());
                }

                // Initial friend search burst: look up all offline friends
                // via the rendezvous server as soon as we have a known IP.
                if !state.friend_search_initial_done
                    && state.external_ip.is_some()
                {
                    state.friend_search_initial_done = true;
                    state.friend_search_started_at = Some(std::time::Instant::now());

                    let all_friends: Vec<[u8; 16]> = friend_hashes.read().await.iter().copied().collect();
                    let sessions = state.ember_sessions.read().await;

                    let mut search_targets: Vec<[u8; 16]> = Vec::new();
                    for fh in &all_friends {
                        if state.online_friends.contains_key(fh) { continue; }
                        if sessions.contains_key(fh) { continue; }
                        if state.outbound_session_tasks.contains_key(fh) { continue; }
                        search_targets.push(*fh);
                    }
                    drop(sessions);

                    if !search_targets.is_empty() {
                        info!("Initial friend search burst: looking up {} offline friend(s) via rendezvous", search_targets.len());
                    }
                    for target_hash in search_targets.iter().take(3) {
                        state.outbound_session_tasks.insert(*target_hash, std::time::Instant::now());
                        let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                            "user_hash": hex::encode(target_hash),
                        }));
                        spawn_rendezvous_friend_lookup(
                            &settings, &state, ember_hash, *target_hash,
                            &db, &app_handle, &friend_hashes, &ul_event_tx,
                            ed25519_pubkey, ed25519_secret_key,
                        );
                    }
                }

                state.stats.connected_peers = count;
            }

            // Periodic publishing
            _ = publish_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                if state.routing_table.is_empty() {
                    debug!("Skipping publish cycle: routing table is empty");
                } else {
                let total_files = state.publish_manager.file_count();
                let needing_source = state.publish_manager.files_needing_source_publish().len();
                let needing_keyword = state.publish_manager.files_needing_keyword_publish().len();
                info!(
                    "Publish cycle: {total_files} files registered, {needing_source} need source publish, \
                     {needing_keyword} need keyword publish, {} confirmed, {} outstanding pending ack, \
                     PublishRes plain_seen={} obf_decoded={}/{} wire={} received={} unmatched={}, \
                     firewalled={}, routing_table={}",
                    state.publish_confirmed,
                    state.publish_pending.len(),
                    state.publish_res_plain_seen,
                    state.publish_res_obf_decoded,
                    state.obf_decoded_total,
                    state.publish_res_wire,
                    state.publish_res_received,
                    state.publish_res_unmatched,
                    state.publish_manager.firewalled,
                    state.routing_table.len(),
                );
                // Rendezvous heartbeat: re-register every 2 minutes to keep
                // our presence alive on the rendezvous server.
                if state.rendezvous_registered {
                    let needs_heartbeat = state.rendezvous_last_register
                        .map(|t| t.elapsed() >= std::time::Duration::from_secs(120))
                        .unwrap_or(true);
                    if needs_heartbeat {
                        state.rendezvous_last_register = Some(std::time::Instant::now());
                        let rv_url = settings.rendezvous_url.clone();
                        // Heartbeat must advertise the same port we
                        // registered with — i.e. the QUIC bind port,
                        // which can differ from `tcp_port` when QUIC
                        // had to fall back.
                        let rv_port = state.quic_port.unwrap_or(settings.tcp_port);
                        let rv_hash = ember_hash;
                        let rv_ip = state.external_ip;
                        let app_rv = app_handle.clone();
                        tokio::spawn(async move {
                            match rendezvous::register(&rv_url, &rv_hash, rv_port, rv_ip).await {
                                Ok(()) => {
                                    let _ = app_rv.emit("ember:friend-discoverable", serde_json::json!({
                                        "discoverable": true,
                                    }));
                                }
                                Err(e) => {
                                    warn!("Rendezvous heartbeat failed: {e}");
                                }
                            }
                        });
                    }
                }

                // Poll for incoming server-relay invitations (if registered & have external IP).
                // Use the QUIC port we actually registered with — peers
                // construct the relay-invite key as `(our_ip, our_quic_port)`
                // since that's what they read from rendezvous.
                if state.rendezvous_registered {
                    if let Some(ext_ip) = state.external_ip {
                        let advertised_port = state.quic_port.unwrap_or(state.tcp_port);
                        let our_relay_id = format!("{:0>64}", format!("{:08x}{:04x}", u32::from(ext_ip), advertised_port));
                        let rv_url = settings.rendezvous_url.clone();
                        let relay_cb_tx = kad_callback_tx.clone();
                        tokio::spawn(async move {
                            match ember::relay::poll_relay_invites(&rv_url, &our_relay_id).await {
                                Ok(session_ids) => {
                                    for sid in session_ids {
                                        tracing::info!("Relay invite received, connecting to session {}", &sid[..16.min(sid.len())]);
                                        let cb_tx = relay_cb_tx.clone();
                                        let url = rv_url.clone();
                                        tokio::spawn(async move {
                                            match ember::relay::connect_server_relay(&url, &sid).await {
                                                Ok(ws) => {
                                                    let (reader, writer) = tokio::io::split(ws);
                                                    let parts = crate::network::ed2k::upload::KadCallbackParts {
                                                        peer_ip: std::net::Ipv4Addr::UNSPECIFIED,
                                                        peer_port: 0,
                                                        peer_user_hash: [0u8; 16],
                                                        file_hash: [0u8; 16],
                                                        reader: Box::new(reader),
                                                        writer: Box::new(writer),
                                                        emule_info_done: false,
                                                    };
                                                    let _ = cb_tx.send(parts).await;
                                                }
                                                Err(e) => {
                                                    tracing::debug!("Relay invite connect failed for session: {e}");
                                                }
                                            }
                                        });
                                    }
                                }
                                Err(e) => {
                                    tracing::trace!("Relay invite poll: {e}");
                                }
                            }
                        });
                    }
                }

                // Limit publishes per cycle; use higher limits for the first burst after connect
                let max_source_per_cycle: usize = if !state.first_publish_done || state.publish_confirmed == 0 { 10 } else { 3 };
                let max_keyword_per_cycle: usize = if !state.first_publish_done || state.publish_confirmed == 0 { 5 } else { 2 };

                let source_files = state.publish_manager.files_needing_source_publish()
                    .into_iter().take(max_source_per_cycle).cloned().collect::<Vec<_>>();
                for file in &source_files {
                    let Some(msg) = state.publish_manager.build_source_publish(file) else {
                        warn!(
                            "Skipping source publish for {} — firewalled={} buddy={} direct_udp_cb={}",
                            file.file_hash,
                            state.publish_manager.firewalled,
                            state.publish_manager.buddy_id.is_some(),
                            state.publish_manager.direct_udp_callback,
                        );
                        continue;
                    };
                    let closest = state.routing_table.find_closest_prefer_verified(&file.file_hash, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        let sid = state.search_manager.start_search(
                            file.file_hash,
                            SearchType::StoreFile,
                            closest,
                        );
                        if sid != SearchId(0) {
                            state.store_source_searches.insert(sid, (file.file_hash, msg));
                        }
                    }
                }

                // K4: files is capped by `max_keyword_per_cycle`, but each
                // file can contain many keywords and each keyword starts a
                // fresh DHT walk. A single pathological filename with
                // dozens of tokens would fire dozens of parallel
                // `StoreKeyword` searches per cycle — a self-DoS. Cap the
                // *total* searches launched this cycle too so egress stays
                // predictable regardless of tokenization.
                let max_keyword_searches_per_cycle: usize =
                    if !state.first_publish_done || state.publish_confirmed == 0 { 20 } else { 8 };
                let mut keyword_searches_started: usize = 0;
                let keyword_files = state.publish_manager.files_needing_keyword_publish()
                    .into_iter().take(max_keyword_per_cycle).cloned().collect::<Vec<_>>();
                'kwfiles: for file in &keyword_files {
                    let publishes = state.publish_manager.build_keyword_publishes(&file);
                    if publishes.is_empty() { continue; }
                    let mut any_started = false;
                    for (kw_hash, msg) in publishes {
                        if keyword_searches_started >= max_keyword_searches_per_cycle {
                            debug!(
                                "Keyword publish cycle hit cap ({}); deferring remaining keywords",
                                max_keyword_searches_per_cycle
                            );
                            break 'kwfiles;
                        }
                        let closest = state.routing_table.find_closest_prefer_verified(&kw_hash, SEARCH_INITIAL_CONTACTS);
                        if closest.is_empty() { continue; }
                        let sid = state.search_manager.start_search(
                            kw_hash,
                            SearchType::StoreKeyword,
                            closest,
                        );
                        if sid == SearchId(0) { continue; }
                        state.store_keyword_searches.insert(sid, (file.clone(), vec![(kw_hash, msg)]));
                        any_started = true;
                        keyword_searches_started += 1;
                    }
                    if !any_started {
                        // No search started for any keyword — don't mark as published
                    }
                }

                } // end is_empty guard
            }

            // Publish-pipeline health heartbeat (10s). Only logs when at
            // least one diagnostic counter has moved since the last beat,
            // so it stays quiet at idle. Crucially this fires *between*
            // the 60s `Publish cycle:` lines, so the user can see whether
            // PublishRes packets are flowing seconds after publishes are
            // sent — not 60s later.
            _ = publish_health_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let cur = PublishHealthSnapshot {
                    confirmed: state.publish_confirmed,
                    pending: state.publish_pending.len(),
                    plain_seen: state.publish_res_plain_seen,
                    obf_decoded: state.publish_res_obf_decoded,
                    obf_total: state.obf_decoded_total,
                    wire: state.publish_res_wire,
                    received: state.publish_res_received,
                    unmatched: state.publish_res_unmatched,
                };
                let prev = last_publish_health;
                let any_change = cur.confirmed != prev.confirmed
                    || cur.pending != prev.pending
                    || cur.plain_seen != prev.plain_seen
                    || cur.obf_decoded != prev.obf_decoded
                    || cur.wire != prev.wire
                    || cur.received != prev.received
                    || cur.unmatched != prev.unmatched;
                if any_change {
                    let d_confirmed = cur.confirmed.saturating_sub(prev.confirmed);
                    let d_plain = cur.plain_seen.saturating_sub(prev.plain_seen);
                    let d_obf_decoded = cur.obf_decoded.saturating_sub(prev.obf_decoded);
                    let d_obf_total = cur.obf_total.saturating_sub(prev.obf_total);
                    let d_wire = cur.wire.saturating_sub(prev.wire);
                    let d_received = cur.received.saturating_sub(prev.received);
                    let d_unmatched = cur.unmatched.saturating_sub(prev.unmatched);
                    info!(
                        "Publish health (10s): pending={} confirmed=+{} (total {}), \
                         PublishRes plain=+{} obf_decoded=+{}/+{} wire=+{} received=+{} unmatched=+{}",
                        cur.pending,
                        d_confirmed, cur.confirmed,
                        d_plain, d_obf_decoded, d_obf_total,
                        d_wire, d_received, d_unmatched,
                    );
                }
                last_publish_health = cur;
            }

            // UDP source-discovery health heartbeat (30s). Like the
            // publish heartbeat above, only emits a log line when at
            // least one counter has changed since the last beat. Lets
            // the user verify that UDP source-asking is actually
            // flowing in real time without enabling debug logging:
            // a steady "sent=+N replies=+M sources=+K" stream means
            // healthy discovery; "sent=+N replies=+0 sources=+0" for
            // many beats means servers aren't replying (firewall,
            // missing UDP obfuscation, dead servers).
            _ = udp_discovery_health_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let cur = UdpDiscoveryHealthSnapshot {
                    sent: state.udp_discovery_sent,
                    send_errs: state.udp_discovery_send_errs,
                    replies: state.udp_discovery_replies,
                    sources_found: state.udp_discovery_sources_found,
                };
                let prev = last_udp_discovery_health;
                let any_change = cur.sent != prev.sent
                    || cur.send_errs != prev.send_errs
                    || cur.replies != prev.replies
                    || cur.sources_found != prev.sources_found;
                if any_change {
                    let d_sent = cur.sent.saturating_sub(prev.sent);
                    let d_errs = cur.send_errs.saturating_sub(prev.send_errs);
                    let d_replies = cur.replies.saturating_sub(prev.replies);
                    let d_sources = cur.sources_found.saturating_sub(prev.sources_found);
                    // `ok` and `fail` are disjoint counts of the
                    // **attempted** sends since the last beat (each
                    // `send_to` call bumps exactly one). The totals
                    // are cumulative since process start (each kind
                    // separately). Earlier wording put them in the
                    // same paren which read as "errs are a subset
                    // of sent" — they aren't.
                    info!(
                        "UDP source-discovery health (30s): sends ok=+{d_sent} fail=+{d_errs} (totals ok={} fail={}), replies=+{d_replies} (total {}), sources_found=+{d_sources} (total {})",
                        cur.sent, cur.send_errs,
                        cur.replies,
                        cur.sources_found,
                    );

                    // Per-server breakdown so the user can see which
                    // entries in their server.met are actually
                    // useful for source discovery. Three categories:
                    //   * source-responsive: ever returned
                    //     OP_GLOBFOUNDSOURCES (= actually has source
                    //     data we can use). The good column.
                    //   * status-only: responds to status pings but
                    //     never to GETSOURCES — server is alive but
                    //     doesn't index our specific file hashes.
                    //     Most servers fall here for any given user
                    //     because the long tail of file hashes is
                    //     vast and individual servers index small
                    //     subsets.
                    //   * silent: never replied to anything.
                    //   * pruned: > MAX_UDP_CONSECUTIVE_FAILURES
                    //     consecutive unanswered queries.
                    //
                    // Previously this was one "alive" bucket which
                    // misled readers into thinking source discovery
                    // was working when servers were just answering
                    // status pings.
                    let now_ts = chrono::Utc::now().timestamp();
                    let mut source_responsive: Vec<String> = Vec::new();
                    let mut status_only: Vec<String> = Vec::new();
                    let mut silent: Vec<String> = Vec::new();
                    let mut pruned: Vec<String> = Vec::new();
                    for s in state.server_list.servers().iter() {
                        let label = if s.name.is_empty() {
                            format!("{}:{}", s.ip, s.port)
                        } else {
                            format!("{} ({}:{})", s.name, s.ip, s.port)
                        };
                        if s.udp_consecutive_failures >= MAX_UDP_CONSECUTIVE_FAILURES {
                            pruned.push(label);
                        } else if s.last_udp_source_reply_at > 0 {
                            let ago = (now_ts - s.last_udp_source_reply_at).max(0);
                            source_responsive.push(format!("{label} (last sources {ago}s ago)"));
                        } else if s.last_udp_reply_at > 0 {
                            let ago = (now_ts - s.last_udp_reply_at).max(0);
                            status_only.push(format!("{label} (status reply {ago}s ago, never returned sources)"));
                        } else {
                            silent.push(format!("{label} (fails={})", s.udp_consecutive_failures));
                        }
                    }
                    info!(
                        "UDP server health: {} source-responsive, {} status-only (alive but never returned sources), {} silent, {} pruned (>= {MAX_UDP_CONSECUTIVE_FAILURES} unanswered queries)",
                        source_responsive.len(), status_only.len(), silent.len(), pruned.len(),
                    );
                    if !source_responsive.is_empty() {
                        info!("UDP source-responsive servers: {}", source_responsive.join("; "));
                    }
                    if !status_only.is_empty() {
                        info!("UDP status-only servers: {}", status_only.join("; "));
                    }
                    if !silent.is_empty() {
                        info!("UDP silent servers: {}", silent.join("; "));
                    }
                    if !pruned.is_empty() {
                        info!("UDP pruned servers (re-eligible on any inbound UDP): {}", pruned.join("; "));
                    }
                }
                last_udp_discovery_health = cur;
            }

            // Cleanup stale searches, expired DHT entries, and unconfirmed publishes
            _ = cleanup_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let (removed_sids, released_in_use) = state.search_manager.cleanup(120);
                if !released_in_use.is_empty() {
                    state.routing_table.release_contacts_in_use(&released_in_use);
                }
                for sid in &removed_sids {
                    if let Some(PendingKeywordSearch { tx, local_results, request_id, .. }) = state.pending_keyword_searches.remove(sid) {
                        let _ = tx.send(local_results);
                        if let Some(active) = state.active_search_request.as_mut() {
                            if active.request_id == request_id {
                                active.kad_pending = false;
                            }
                        }
                        maybe_finish_active_search(&mut state, &app_handle, request_id);
                    }
                    if let Some(tx) = state.pending_source_searches.remove(sid) {
                        let _ = tx.send(Vec::new());
                    }
                    if let Some(tx) = state.pending_notes_searches.remove(sid) {
                        let _ = tx.send(Vec::new());
                    }
                    state.download_source_searches.remove(sid);
                    state.store_keyword_searches.remove(sid);
                    state.store_source_searches.remove(sid);
                    state.pending_note_publishes.remove(sid);
                }
                state.dht_store.cleanup_expired();

                // Prune stale pending KAD callbacks (older than 2 minutes)
                // and mark the corresponding source details as Failed so the
                // UI no longer shows them stuck in "Connecting".
                {
                    let now = chrono::Utc::now().timestamp();
                    let mut expired_ips: Vec<std::net::Ipv4Addr> = Vec::new();
                    let mut cbs = pending_kad_callbacks.lock().await;
                    for (ip, entries) in cbs.iter_mut() {
                        let before = entries.len();
                        entries.retain(|&(_, _, ts)| now - ts < 120);
                        if entries.len() < before {
                            expired_ips.push(*ip);
                        }
                    }
                    cbs.retain(|_, v| !v.is_empty());
                    drop(cbs);

                    if !expired_ips.is_empty() {
                        let mut mgr = transfer_manager.write().await;
                        for ip in &expired_ips {
                            let ip_str = ip.to_string();
                            for tid in state.pending_downloads.keys() {
                                let sources = mgr.get_source_details(tid);
                                for src in &sources {
                                    if src.ip == ip_str
                                        && src.status == crate::types::SourceStatus::Connecting
                                        && (src.client_software == "KAD Callback"
                                            || src.client_software == "KAD Direct Callback")
                                    {
                                        mgr.update_source_detail(
                                            tid,
                                            crate::types::SourceInfo {
                                                ip: ip_str.clone(),
                                                port: src.port,
                                                status: crate::types::SourceStatus::Failed,
                                                queue_rank: None,
                                                speed: 0,
                                                transferred: 0,
                                                client_software: src.client_software.clone(),
                                                peer_name: String::new(),
                                                available_parts: None,
                                                total_parts: None,
                                                country_code: None,
                                                source_origin: src.source_origin.clone(),
                                            },
                                        );
                                        let _ = app_handle.emit(
                                            "transfer-source-detail",
                                            serde_json::json!({
                                                "transfer_id": tid,
                                                "ip": ip_str,
                                                "port": src.port,
                                                "status": "failed",
                                                "client_software": src.client_software,
                                            }),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                // Prune stale outbound session tasks (older than 10 minutes)
                {
                    let now = std::time::Instant::now();
                    state.outbound_session_tasks.retain(|_, started| now.duration_since(*started).as_secs() < 600);
                }

                // (broker.tick() and broker event drain are now handled
                // by their own 200 ms `broker_timer` arm — the 5-minute
                // cadence here was longer than PUNCH_TIMEOUT/RELAY_TIMEOUT
                // and effectively disabled hole-punch + LowID-to-LowID.)

                // Clean up expired relay sessions
                {
                    let mut relay_mgr = state.relay_manager.lock().await;
                    let expired = relay_mgr.cleanup();
                    if !expired.is_empty() {
                        tracing::debug!("Relay cleanup: expired {} sessions", expired.len());
                    }
                }

                // (broker event drain moved to its own 200ms `broker_timer`
                // arm — see below. Leaving it on cleanup_timer's 5-min
                // cadence made every queued punch/relay event obsolete
                // before it was ever processed.)

                // Periodic NAT reprobe (every 5 minutes)
                if state.nat_info.needs_reprobe() && state.external_ip.is_some() {
                    let nat_info = ember::nat::probe_nat(&udp_socket).await;
                    state.nat_info = nat_info;
                    // Same HighID fallback as the initial probe: if STUN
                    // is still down but we know our external IP, don't
                    // regress to `Unknown` / no-punch.
                    if let Some(ext_ip) = state.external_ip {
                        let _ = state.nat_info.apply_highid_fallback(
                            std::net::IpAddr::V4(ext_ip),
                            state.udp_port,
                        );
                    }
                }

                // Auto-retry offline friends via rendezvous for the
                // entire session. First 30 min: every tick (5 min).
                // After that: every other tick (10 min) to reduce load.
                if let Some(started) = state.friend_search_started_at {
                    let elapsed = std::time::Instant::now().duration_since(started).as_secs();
                    let should_retry = if elapsed <= 1800 {
                        true
                    } else {
                        (elapsed / 300) % 2 == 0
                    };
                    if should_retry {
                        let all_friends: Vec<[u8; 16]> = friend_hashes.read().await.iter().copied().collect();
                        let sessions = state.ember_sessions.read().await;

                        let mut retry_targets: Vec<[u8; 16]> = Vec::new();
                        for fh in &all_friends {
                            if state.online_friends.contains_key(fh) { continue; }
                            if sessions.contains_key(fh) { continue; }
                            if state.outbound_session_tasks.contains_key(fh) { continue; }
                            retry_targets.push(*fh);
                        }
                        drop(sessions);

                        if !retry_targets.is_empty() {
                            info!("Friend auto-retry ({:.0}s since connect): looking up {} offline friend(s) via rendezvous",
                                elapsed as f64, retry_targets.len());
                        }
                        for target_hash in retry_targets.iter().take(10) {
                            state.outbound_session_tasks.insert(*target_hash, std::time::Instant::now());
                            let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                                "user_hash": hex::encode(target_hash),
                            }));
                            spawn_rendezvous_friend_lookup(
                                &settings, &state, ember_hash, *target_hash,
                                &db, &app_handle, &friend_hashes, &ul_event_tx,
                                ed25519_pubkey, ed25519_secret_key,
                            );
                        }
                    }
                }

                // Prune callback buddy attempts for files no longer pending or active
                {
                    let mut live_hashes: HashSet<[u8; 16]> = state.pending_downloads.values()
                        .filter_map(|pd| hex::decode(&pd.file_hash).ok())
                        .filter(|b| b.len() == 16)
                        .map(|b| { let mut a = [0u8; 16]; a.copy_from_slice(&b); a })
                        .collect();
                    for pfs in state.per_file_sources.values() {
                        live_hashes.insert(pfs.file_hash);
                    }
                    state.callback_buddy_attempts.retain(|&(_, fh), _| live_hashes.contains(&fh));
                }

                // Prune expired sources (older than 1 hour)
                {
                    let mut sm = source_manager.write().await;
                    sm.cleanup_expired();
                }

                // Prune stale credit records (older than 90 days)
                {
                    let mut cm = credit_manager.write().await;
                    cm.cleanup_stale(90);
                }

                // Remove contacts not seen in 2 hours
                let stale_removed = state.routing_table.remove_stale(7200);
                if stale_removed > 0 {
                    debug!("Removed {stale_removed} stale contacts from routing table");
                    state.stats.connected_peers = state.routing_table.len() as u32;
                }

                let now = chrono::Utc::now().timestamp();
                // Collect stale per-(target, peer) entries, then dedupe by
                // file_hash so we reset publish_manager at most once per
                // file regardless of how many peers we had outstanding.
                let stale_keys: Vec<((KadId, SocketAddr), KadId, bool)> = state.publish_pending
                    .iter()
                    .filter(|(_, (_, sent_at, _))| now - sent_at > 120)
                    .map(|(k, (file_hash, _, is_source))| (*k, *file_hash, *is_source))
                    .collect();
                let mut retried_files: std::collections::HashSet<(KadId, bool)> = std::collections::HashSet::new();
                for (key, file_hash, is_source) in &stale_keys {
                    state.publish_pending.remove(key);
                    // Skip stale-retry bookkeeping if any peer for this file
                    // has already succeeded (file_hash still in
                    // publish_pending under a different key → recently acked).
                    // The dedupe set covers the common "all peers timed out"
                    // path.
                    if retried_files.insert((*file_hash, *is_source)) {
                        if *is_source {
                            state.publish_manager.reset_source_publish(file_hash);
                        } else {
                            state.publish_manager.reset_keyword_publish(file_hash);
                        }
                        debug!("Retrying unconfirmed publish for target {} (peer {})", key.0, key.1);
                    }
                }
            }

            // Broker tick + event drain. Used to live inside the
            // `cleanup_timer` arm (5-minute cadence), which made every
            // `BrokerEvent::StartPunch` / `StartRelay` posted by
            // `attempt_low_to_low()` sit in the channel for minutes —
            // long past the per-attempt PUNCH_TIMEOUT (20s) and
            // RELAY_TIMEOUT (30s), and `broker.tick()` would then GC
            // the matching attempt before the event was even dispatched.
            // Net effect: hole-punch and LowID-to-LowID never fired in
            // any session shorter than 5 minutes. 200 ms cadence is
            // small enough that punch/relay scheduling is effectively
            // event-driven and large enough that an idle tick costs
            // one `try_recv()` (returns `Empty` instantly) plus a
            // hashmap walk over at most `MAX_ACTIVE_ATTEMPTS` entries.
            _ = broker_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }

                if let Some(ref mut broker) = state.connection_broker {
                    broker.tick().await;
                }

                if let Some(ref mut rx) = state.broker_event_rx {
                    while let Ok(event) = rx.try_recv() {
                        match event {
                            ember::broker::BrokerEvent::StartPunch { ref attempt_key, source_ip, source_port, our_external_addr, our_nat_type, .. } => {
                                tracing::info!("Broker: initiating hole-punch for {} -> {}:{} (ext={})", attempt_key, source_ip, source_port, our_external_addr);
                                let rv_url = settings.rendezvous_url.clone();
                                // Both `from_id` and `target_id` MUST be 64 chars or
                                // the rendezvous server returns `400 Bad Request`
                                // (`punch_register` checks `len() != 64` for both).
                                // `ember_hash` is 16 bytes = 32 hex chars, so we
                                // need to left-pad it to 64. Previously this was
                                // sent unpadded, which made every single punch
                                // attempt fail at the register step before any
                                // hole-punch logic could run.
                                let our_id = format!("{:0>64}", hex::encode(ember_hash));
                                let target_id = format!("{:0>64}", format!("{:08x}{:04x}", u32::from(source_ip), source_port));
                                let port = our_external_addr.port();
                                let nat_type_val = our_nat_type.as_u8();
                                let attempt_key_owned = attempt_key.clone();

                                let (attempt_transfer_id, attempt_file_hash) = state.connection_broker.as_ref()
                                    .and_then(|b| b.get_attempt_info(&attempt_key_owned))
                                    .map(|(tid, fh, _, _)| (tid, fh))
                                    .unwrap_or_default();

                                let broker_tx = state.connection_broker.as_ref()
                                    .map(|b| b.event_sender());
                                let quic_ep = state.connection_broker.as_ref()
                                    .and_then(|b| b.quic_endpoint().cloned());

                                tokio::spawn(async move {
                                    let Some(broker_tx) = broker_tx else { return; };

                                    if let Err(e) = ember::relay::register_punch(
                                        &rv_url, &our_id, &target_id, port, nat_type_val,
                                    ).await {
                                        tracing::warn!("Broker: punch register failed for {attempt_key_owned}: {e}");
                                        let _ = broker_tx.send(ember::broker::BrokerEvent::PunchFailed {
                                            attempt_key: attempt_key_owned,
                                            reason: format!("register failed: {e}"),
                                        }).await;
                                        return;
                                    }

                                    let mut remote_addr = None;
                                    for _ in 0..8 {
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        match ember::relay::poll_punch(&rv_url, &our_id).await {
                                            Ok(Some(info)) => {
                                                if let Ok(ip) = info.ip.parse::<std::net::IpAddr>() {
                                                    remote_addr = Some(SocketAddr::new(ip, info.port));
                                                    break;
                                                }
                                            }
                                            Ok(None) => {}
                                            Err(e) => {
                                                tracing::debug!("Broker: punch poll error: {e}");
                                            }
                                        }
                                    }

                                    let Some(addr) = remote_addr else {
                                        tracing::info!("Broker: punch timed out waiting for peer {attempt_key_owned}");
                                        let _ = broker_tx.send(ember::broker::BrokerEvent::PunchFailed {
                                            attempt_key: attempt_key_owned,
                                            reason: "peer not found via rendezvous".into(),
                                        }).await;
                                        return;
                                    };

                                    let Some(endpoint) = quic_ep else {
                                        tracing::warn!("Broker: no QUIC endpoint for punch {attempt_key_owned}");
                                        let _ = broker_tx.send(ember::broker::BrokerEvent::PunchFailed {
                                            attempt_key: attempt_key_owned,
                                            reason: "no QUIC endpoint".into(),
                                        }).await;
                                        return;
                                    };

                                    tracing::info!("Broker: attempting QUIC connect to {addr} for {attempt_key_owned}");
                                    match ember::broker::punch_quic(&endpoint, addr).await {
                                        Ok((send, recv)) => {
                                            tracing::info!("Broker: hole-punch succeeded to {addr}");
                                            let _ = broker_tx.send(ember::broker::BrokerEvent::ConnectionReady(
                                                ember::broker::BrokerConnection {
                                                    transfer_id: attempt_transfer_id,
                                                    file_hash: attempt_file_hash,
                                                    source_ip,
                                                    source_port,
                                                    method: ember::broker::ConnectionMethod::HolePunch,
                                                    relay_addr: None,
                                                    reader: Box::new(recv),
                                                    writer: Box::new(send),
                                                },
                                            )).await;
                                        }
                                        Err(e) => {
                                            tracing::warn!("Broker: QUIC punch failed for {attempt_key_owned}: {e}");
                                            let _ = broker_tx.send(ember::broker::BrokerEvent::PunchFailed {
                                                attempt_key: attempt_key_owned,
                                                reason: e,
                                            }).await;
                                        }
                                    }
                                });
                            }
                            ember::broker::BrokerEvent::StartRelay { ref attempt_key, source_ip, source_port, file_hash, relay_addr, .. } => {
                                tracing::info!("Broker: initiating relay for {} -> {}:{} (relay={:?})", attempt_key, source_ip, source_port, relay_addr);

                                let attempt_key_owned = attempt_key.clone();
                                let rv_url = settings.rendezvous_url.clone();

                                let (attempt_transfer_id, _) = state.connection_broker.as_ref()
                                    .and_then(|b| b.get_attempt_info(&attempt_key_owned))
                                    .map(|(tid, _, _, _)| (tid, ()))
                                    .unwrap_or_default();

                                let broker_tx = state.connection_broker.as_ref()
                                    .map(|b| b.event_sender());

                                if let Some(ref mut broker) = state.connection_broker {
                                    broker.set_relay_phase(&attempt_key_owned);
                                }

                                if let Some((relay_ip, relay_port)) = relay_addr {
                                    let quic_ep = state.connection_broker.as_ref()
                                        .and_then(|b| b.quic_endpoint().cloned());
                                    let transfer_id = attempt_transfer_id.clone();

                                    tokio::spawn(async move {
                                        let Some(broker_tx) = broker_tx else { return; };
                                        let Some(endpoint) = quic_ep else {
                                            tracing::warn!("Broker: no QUIC endpoint for relay {attempt_key_owned}");
                                            let _ = broker_tx.send(ember::broker::BrokerEvent::RelayFailed {
                                                attempt_key: attempt_key_owned,
                                                reason: "no QUIC endpoint".into(),
                                            }).await;
                                            return;
                                        };

                                        let relay_addr = SocketAddr::new(
                                            std::net::IpAddr::V4(relay_ip), relay_port,
                                        );

                                        match ember::relay::connect_to_peer_relay(
                                            &endpoint, relay_addr, source_ip, source_port, &file_hash,
                                        ).await {
                                            Ok((send, recv)) => {
                                                tracing::info!("Broker: peer relay connected via {relay_addr}");
                                                let _ = broker_tx.send(ember::broker::BrokerEvent::ConnectionReady(
                                                    ember::broker::BrokerConnection {
                                                        transfer_id,
                                                        file_hash,
                                                        source_ip,
                                                        source_port,
                                                        method: ember::broker::ConnectionMethod::PeerRelay,
                                                        relay_addr: Some((relay_ip, relay_port)),
                                                        reader: Box::new(recv),
                                                        writer: Box::new(send),
                                                    },
                                                )).await;
                                            }
                                            Err(e) => {
                                                tracing::warn!("Broker: peer relay failed: {e}");
                                                let _ = broker_tx.send(ember::broker::BrokerEvent::RelayFailed {
                                                    attempt_key: attempt_key_owned,
                                                    reason: e,
                                                }).await;
                                            }
                                        }
                                    });
                                } else if !rv_url.is_empty() {
                                    let target_id = format!("{:0>64}", format!("{:08x}{:04x}", u32::from(source_ip), source_port));
                                    // Session id MUST be unique per (us, file, peer)
                                    // triple. Previously we used `{user}-{file}` which
                                    // collided whenever multiple LowID peers wanted the
                                    // same file: the rendezvous server pairs WebSockets
                                    // two at a time per session_id, so the second
                                    // connection would tear down the first peer's
                                    // socket via the `sessions.remove(&session_id)` →
                                    // bridge_relay path. Our adopted callback streams
                                    // would then immediately fail on the next send
                                    // with `WebSocket protocol error: Sending after
                                    // closing is not allowed`. Including `target_id`
                                    // gives each LowID peer its own room. The peer side
                                    // gets the matching session_id via the relay-invite
                                    // we POST below, so it will dial the right room.
                                    //
                                    // Use the *trailing* portion of target_id, not
                                    // the leading slice — `target_id` is `{:0>64}`
                                    // formatted (52 leading zeros + 12 chars of
                                    // ip:port hex). Slicing `[..16]` would give us
                                    // 16 zeros for every peer, which is exactly the
                                    // bug we just hit (every session_id ended in
                                    // `-0000000000000000-` and collided again).
                                    let peer_tag = &target_id[target_id.len().saturating_sub(12)..];
                                    let session_id = format!(
                                        "{}-{}-{}",
                                        hex::encode(ember_hash),
                                        peer_tag,
                                        hex::encode(file_hash),
                                    );
                                    let transfer_id = attempt_transfer_id;

                                    let invite_rv_url = rv_url.clone();
                                    let invite_sid = session_id.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = ember::relay::post_relay_invite(&invite_rv_url, &target_id, &invite_sid).await {
                                            tracing::debug!("Broker: relay invite post failed: {e}");
                                        }
                                    });

                                    tokio::spawn(async move {
                                        use futures::FutureExt;
                                        let Some(broker_tx) = broker_tx else { return; };
                                        // Wrap in `catch_unwind`. `tokio_tungstenite::connect_async`
                                        // dispatches into rustls, which `panic!`s on the worker
                                        // thread if the process-wide CryptoProvider isn't
                                        // installed. We DO install it in `lib.rs::run()` now,
                                        // but if any future code path (test binary, alternate
                                        // entry point, third-party plugin) ever lands without
                                        // doing so, an uncaught panic would kill this spawned
                                        // task, no `RelayFailed` event would ever be sent, and
                                        // the broker entry would sit stuck at `RelayConnect`
                                        // until `RELAY_TIMEOUT` (30 s) reaped it via
                                        // `broker.tick()`. Catching the panic here keeps the
                                        // broker state machine driven by explicit events
                                        // regardless.
                                        let result = std::panic::AssertUnwindSafe(
                                            ember::relay::connect_server_relay(&rv_url, &session_id),
                                        ).catch_unwind().await;
                                        match result {
                                            Ok(Ok(ws_stream)) => {
                                                tracing::info!("Broker: server relay connected for {attempt_key_owned}");
                                                let (reader, writer) = tokio::io::split(ws_stream);
                                                let _ = broker_tx.send(ember::broker::BrokerEvent::ConnectionReady(
                                                    ember::broker::BrokerConnection {
                                                        transfer_id,
                                                        file_hash,
                                                        source_ip,
                                                        source_port,
                                                        method: ember::broker::ConnectionMethod::ServerRelay,
                                                        relay_addr: None,
                                                        reader: Box::new(reader),
                                                        writer: Box::new(writer),
                                                    },
                                                )).await;
                                            }
                                            Ok(Err(e)) => {
                                                tracing::warn!("Broker: server relay failed: {e}");
                                                let _ = broker_tx.send(ember::broker::BrokerEvent::RelayFailed {
                                                    attempt_key: attempt_key_owned,
                                                    reason: e,
                                                }).await;
                                            }
                                            Err(panic) => {
                                                let msg = if let Some(s) = panic.downcast_ref::<&'static str>() {
                                                    (*s).to_string()
                                                } else if let Some(s) = panic.downcast_ref::<String>() {
                                                    s.clone()
                                                } else {
                                                    "non-string panic payload".to_string()
                                                };
                                                tracing::error!("Broker: server relay panicked: {msg}");
                                                let _ = broker_tx.send(ember::broker::BrokerEvent::RelayFailed {
                                                    attempt_key: attempt_key_owned,
                                                    reason: format!("panic: {msg}"),
                                                }).await;
                                            }
                                        }
                                    });
                                } else {
                                    tracing::warn!("Broker: no peer relay candidate and no rendezvous URL for {attempt_key_owned}");
                                    tokio::spawn(async move {
                                        let Some(broker_tx) = broker_tx else { return; };
                                        let _ = broker_tx.send(ember::broker::BrokerEvent::RelayFailed {
                                            attempt_key: attempt_key_owned,
                                            reason: "no relay candidate and no rendezvous URL".into(),
                                        }).await;
                                    });
                                }
                            }
                            ember::broker::BrokerEvent::ConnectionReady(conn) => {
                                tracing::info!("Broker: connection ready for transfer {} from {}:{} via {:?}", conn.transfer_id, conn.source_ip, conn.source_port, conn.method);
                                let parts = upload_server::KadCallbackParts {
                                    peer_ip: conn.source_ip,
                                    peer_port: conn.source_port,
                                    peer_user_hash: [0u8; 16],
                                    file_hash: conn.file_hash,
                                    reader: conn.reader,
                                    writer: conn.writer,
                                    emule_info_done: true,
                                };
                                let _ = kad_callback_tx.send(parts).await;
                                if let Some(ref mut broker) = state.connection_broker {
                                    let key = format!("{}:{}:{}", conn.transfer_id, conn.source_ip, conn.source_port);
                                    broker.mark_succeeded(&key);
                                    if conn.method == ember::broker::ConnectionMethod::PeerRelay {
                                        if let Some((relay_ip, relay_port)) = conn.relay_addr {
                                            broker.increment_relay_sessions(relay_ip, relay_port);
                                        }
                                    }
                                }
                            }
                            ember::broker::BrokerEvent::ConnectionFailed { ref transfer_id, source_ip, source_port, ref reason } => {
                                tracing::warn!("Broker: all methods failed for {}:{} (transfer {}): {}", source_ip, source_port, transfer_id, reason);
                                if let Some(pfs) = state.per_file_sources.get_mut(transfer_id) {
                                    pfs.set_low_to_low(source_ip, source_port);
                                }
                            }
                            ember::broker::BrokerEvent::PunchFailed { ref attempt_key, ref reason } => {
                                if let Some(ref mut broker) = state.connection_broker {
                                    broker.punch_failed(attempt_key, reason).await;
                                }
                            }
                            ember::broker::BrokerEvent::RelayFailed { ref attempt_key, ref reason } => {
                                if let Some(ref mut broker) = state.connection_broker {
                                    broker.relay_failed(attempt_key, reason).await;
                                }
                            }
                        }
                    }
                }
            }

            // eMule Consolidate: merge sparse sibling leaf zones every 45 seconds
            _ = consolidate_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let merged = state.routing_table.consolidate();
                if merged > 0 {
                    debug!("Consolidated {merged} zone pairs");
                }
            }

            // eMule CKademlia::Process big timer: RandomLookup at most once per tick (~100ms cadence).
            _ = kad_process_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let now_bt = chrono::Utc::now().timestamp();
                if let Some(target) =
                    state
                        .routing_table
                        .try_fire_big_timer(now_bt, state.last_kad_contact)
                {
                    let closest = state
                        .routing_table
                        .find_closest(&target, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        let sid = state.search_manager.start_search(
                            target,
                            SearchType::FindNode,
                            closest,
                        );
                        if sid != SearchId(0) {
                            debug!(
                                "BigTimer: started FindNode search {} (eMule RandomLookup)",
                                sid.0
                            );
                        }
                    }
                }
            }

            // Throttled UDP global search: send one packet per 750ms tick
            _ = udp_search_timer.tick() => {
                if let Some((packet, addr)) = state.udp_search_queue.pop_front() {
                    let sock = server_udp.socket_handle();
                    if let Err(e) = sock.send_to(&packet, addr).await {
                        // Most common failures are transient ICMP-unreachable
                        // (Windows: WSAECONNRESET = "An existing connection
                        // was forcibly closed") from a previous packet to a
                        // dead server. Log at debug to avoid spam; aggregate
                        // visibility is in the periodic discovery health log.
                        debug!("UDP global search send_to {addr} failed: {e}");
                    } else if state.udp_search_queue.is_empty() {
                        debug!("UDP global search: all servers queried");
                    }
                }
            }

            // Throttled UDP source requests: send one packet per ~1s tick (eMule pacing)
            _ = udp_source_timer.tick() => {
                if let Some((packet, addr)) = state.udp_source_queue.pop_front() {
                    let sock = server_udp.socket_handle();
                    let pkt_len = packet.len() as u64;
                    // Compute the canonical (TCP_port) lookup key from the
                    // wire dest port (TCP+4 for plain, obfuscation_port_udp
                    // for obfuscated). The recv path canonicalises to the
                    // TCP+4 port; we mirror that so per-server pruning
                    // tracks the right entry.
                    let server_tcp_port = state
                        .server_list
                        .lookup_for_udp_addr(
                            match addr.ip() {
                                std::net::IpAddr::V4(v4) => v4,
                                _ => std::net::Ipv4Addr::UNSPECIFIED,
                            },
                            addr.port(),
                        )
                        .map(|(_key, tcp_port)| tcp_port);
                    match sock.send_to(&packet, addr).await {
                        Ok(_) => {
                            // Outbound source-asking traffic to non-connected
                            // servers. The queue is exclusively populated by
                            // `build_all_getsources_packets[_multi]`, so every
                            // byte that leaves here is `OP_GLOBGETSOURCES`
                            // (or `OP_GLOBGETSOURCES2`) for source discovery.
                            stats_manager.add_overhead(
                                crate::storage::statistics::OverheadCategory::SourceExchange,
                                crate::storage::statistics::OverheadDirection::Upload,
                                pkt_len,
                            );
                            state.udp_discovery_sent = state.udp_discovery_sent.saturating_add(1);
                            // Per-server pruning: bump
                            // udp_consecutive_failures. The recv path
                            // resets it on any inbound UDP reply, so a
                            // genuinely responsive server ratchets back
                            // to zero immediately. Servers that never
                            // reply hit MAX_UDP_CONSECUTIVE_FAILURES
                            // and get excluded from future UDP queries
                            // by `is_eligible_udp_server`.
                            if let Some(tcp_port) = server_tcp_port {
                                let ip_str = addr.ip().to_string();
                                state.server_list.record_udp_query_sent(&ip_str, tcp_port);
                            }
                        }
                        Err(e) => {
                            // Don't double-count failed sends in stats.
                            // Failed sends to dead/unreachable servers are
                            // expected (each cycle queues to *every*
                            // eligible server in `server.met`, many of
                            // which are stale). Per-server failure is
                            // tracked via `state.udp_discovery_send_errs`
                            // for the periodic health log; debug here
                            // gives detail when needed without spamming.
                            debug!("UDP source send_to {addr} failed: {e}");
                            state.udp_discovery_send_errs = state.udp_discovery_send_errs.saturating_add(1);
                        }
                    }
                }
            }

            // SmallTimer (eMule): probe expired contacts with HELLO_REQ, remove dead
            _ = small_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }

                // eMule KADEMLIADISCONNECTDELAY: if no valid KAD contact for 20 minutes,
                // transition back to Connecting so bootstrap re-engages.
                const KAD_DISCONNECT_DELAY_SECS: i64 = 1200;
                if state.stats.status == NetworkStatus::Connected {
                    if let Some(last_contact) = state.last_kad_contact {
                        let now_dc = chrono::Utc::now().timestamp();
                        if now_dc - last_contact > KAD_DISCONNECT_DELAY_SECS {
                            warn!(
                                "No KAD contact for {}s, resetting to Connecting (eMule KADEMLIADISCONNECTDELAY)",
                                now_dc - last_contact
                            );
                            state.stats.status = NetworkStatus::Connecting;
                            state.self_lookup_done = false;
                            state.last_self_lookup = 0;
                            state.routing_table.reset_big_timer_global(now_dc);
                            let _ = app_handle.emit("network-status", NetworkStatus::Connecting);

                            // Tear down eD2K server — it should only be up while KAD is connected
                            if let Some(handle) = state.pending_server_connect.take() {
                                handle.abort();
                            }
                            if state.server_connected || state.server_connection.is_some() {
                                if let Some(conn) = state.server_connection.take() {
                                    conn.disconnect().await;
                                }
                                handle_server_disconnect(
                                    &mut state,
                                    &shared_server_addr,
                                    &app_handle,
                                    "KAD lost connection",
                                ).await;
                            }
                        }
                    }
                }

                let dead_removed = state.routing_table.remove_dead_contacts();
                if dead_removed > 0 {
                    debug!("SmallTimer: removed {dead_removed} dead contacts");
                    state.stats.connected_peers = state.routing_table.len() as u32;
                }

                let to_probe = state.routing_table.get_contacts_to_probe();
                for contact in to_probe {
                    let our_options: u8 = 0x04
                        | if state.udp_firewalled { 0x01 } else { 0 }
                        | if state.firewalled { 0x02 } else { 0 };
                    let mut hello_tags = vec![
                        KadTag {
                            name: TagName::Id(TAG_KADMISCOPTIONS),
                            value: TagValue::Uint8(our_options),
                        },
                    ];
                    if !settings.nickname.is_empty() {
                        hello_tags.push(KadTag {
                            name: TagName::Id(TAG_FILENAME),
                            value: TagValue::String(settings.nickname.clone()),
                        });
                    }
                    let msg = match messages::build_hello_req(
                        &state.local_id,
                        settings.tcp_port,
                        KADEMLIA_VERSION,
                        &hello_tags,
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            error!("Failed to encode hello req: {e}");
                            continue;
                        }
                    };
                    let dest = std::net::SocketAddr::new(
                        std::net::IpAddr::V4(contact.ip),
                        contact.udp_port,
                    );
                    state.flood_protection.track_request(dest, 0x11);
                    let _ = send_kad_packet(
                        &udp_socket,
                        &msg,
                        dest,
                        &state,
                        &contact.id,
                    )
                    .await;
                }

            }

            // Buddy system: find a relay buddy if firewalled (always-on, like eMule)
            _ = buddy_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let buddy_state = state.buddy_manager.state();
                let tcp_fw = state.firewall_checker.tcp_status();
                if buddy_state != BuddyState::Connected {
                    debug!("Buddy tick: state={:?}, tcp_fw={:?}, routing_table={}", buddy_state, tcp_fw, state.routing_table.len());
                }
                if buddy_state == BuddyState::Connected {
                    state.buddy_manager.send_buddy_ping().await;
                }
                if state.buddy_manager.finding_timed_out() {
                    state.buddy_manager.find_failed();
                    info!("Buddy search timed out waiting for FindBuddyRes");
                }
                // While in FindingBuddy with no active search, keep probing
                // fresh random contacts every tick (60s) until timeout.
                if state.buddy_manager.state() == BuddyState::FindingBuddy
                    && state.pending_outgoing_buddy.is_none()
                    && !state.search_manager.active.values().any(|s| matches!(s.search_type, SearchType::FindBuddy) && !s.completed)
                {
                    let target = state.buddy_manager.find_buddy_target();
                    let user_id = KadId(cuint128_swap(&state.user_hash));
                    let local_tcp = state.buddy_manager.tcp_port();
                    let resend_contacts: Vec<KadContact> = {
                        let all_contacts: Vec<_> = state.routing_table.all_contacts()
                            .filter(|c| c.verified && !c.is_dead() && !c.is_udp_firewalled())
                            .collect();
                        use rand::seq::SliceRandom;
                        let mut rng = rand::thread_rng();
                        let mut shuffled: Vec<_> = all_contacts.into_iter().collect::<Vec<_>>();
                        shuffled.shuffle(&mut rng);
                        shuffled.into_iter().take(20).cloned().collect()
                    };
                    let mut resent = 0u32;
                    for contact in &resend_contacts {
                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                        let msg = KadMessage::FindBuddyReq {
                            buddy_id: target,
                            user_id,
                            tcp_port: local_tcp,
                        };
                        if let Ok(packet) = messages::encode_packet(&msg) {
                            state.flood_protection.track_request(addr, 0x51);
                            let _ = send_kad_packet(
                                &udp_socket, &packet, addr, &state, &contact.id,
                            ).await;
                            resent += 1;
                        }
                    }
                    if resent > 0 {
                        info!("FindBuddy: still waiting, resent FindBuddyReq to {} random contacts", resent);
                    }
                }
                if state.buddy_manager.should_find_buddy(state.firewall_checker.tcp_status()) {
                    state.buddy_manager.start_finding();
                    let target = state.buddy_manager.find_buddy_target();
                    let local_tcp = state.buddy_manager.tcp_port();
                    let user_id_for_buddy = KadId(cuint128_swap(&state.user_hash));
                    info!(
                        "FindBuddy identities: local_kad_id={}, buddy_target={}, user_hash_wire={}, tcp_port={}, obfuscation={}",
                        state.local_id, target, user_id_for_buddy, local_tcp, state.obfuscation_enabled
                    );
                    let closest = state.routing_table.find_closest(&target, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        let _sid = state.search_manager.start_search(
                            target,
                            SearchType::FindBuddy,
                            closest,
                        );

                        // Send FindBuddyReq to a broad sample of verified contacts.
                        // Any non-firewalled node can be buddy, so sample from across
                        // the entire routing table, not just close to the target.
                        let mut sent_addrs = std::collections::HashSet::new();
                        let mut initial_sent = 0u32;

                        // 1) 10 contacts closest to the inverted-ID target
                        let target_contacts = state.routing_table.find_closest_verified(&target, 10);
                        let mut logged_wire = false;
                        let mut obf_count = 0u32;
                        let mut plain_count = 0u32;
                        for contact in &target_contacts {
                            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                            let msg = KadMessage::FindBuddyReq {
                                buddy_id: target,
                                user_id: user_id_for_buddy,
                                tcp_port: local_tcp,
                            };
                            if let Ok(packet) = messages::encode_packet(&msg) {
                                if !logged_wire {
                                    let preview: Vec<u8> = packet.iter().take(10).copied().collect();
                                    info!(
                                        "FindBuddyReq wire: {:02X?} (len={}, buddy_target={}, user_id={}, tcp={})",
                                        preview, packet.len(), target, user_id_for_buddy, local_tcp
                                    );
                                    logged_wire = true;
                                }
                                let c_obf = state.obfuscation_enabled
                                    && state.routing_table.get_contact(&contact.id)
                                        .map_or(false, |c| c.supports_obfuscation());
                                if c_obf { obf_count += 1; } else { plain_count += 1; }
                                state.flood_protection.track_request(addr, 0x51);
                                let _ = send_kad_packet(
                                    &udp_socket, &packet, addr, &state, &contact.id,
                                ).await;
                                sent_addrs.insert(addr);
                                initial_sent += 1;
                            }
                        }

                        // 2) Up to 20 random verified contacts from across the
                        //    routing table (different part of keyspace).
                        let all_contacts: Vec<_> = state.routing_table.all_contacts()
                            .filter(|c| c.verified && !c.is_dead() && !c.is_udp_firewalled())
                            .collect();
                        let random_contacts: Vec<KadContact> = {
                            use rand::seq::SliceRandom;
                            let mut rng = rand::thread_rng();
                            let mut shuffled: Vec<_> = all_contacts.iter().collect();
                            shuffled.shuffle(&mut rng);
                            shuffled.into_iter().take(20).cloned().cloned().collect()
                        };
                        for contact in &random_contacts {
                            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                            if sent_addrs.contains(&addr) { continue; }
                            let msg = KadMessage::FindBuddyReq {
                                buddy_id: target,
                                user_id: user_id_for_buddy,
                                tcp_port: local_tcp,
                            };
                            if let Ok(packet) = messages::encode_packet(&msg) {
                                let c_obf = state.obfuscation_enabled
                                    && state.routing_table.get_contact(&contact.id)
                                        .map_or(false, |c| c.supports_obfuscation());
                                if c_obf { obf_count += 1; } else { plain_count += 1; }
                                state.flood_protection.track_request(addr, 0x51);
                                let _ = send_kad_packet(
                                    &udp_socket, &packet, addr, &state, &contact.id,
                                ).await;
                                sent_addrs.insert(addr);
                                initial_sent += 1;
                            }
                        }

                        if initial_sent > 0 {
                            info!("Sent initial FindBuddyReq to {} contacts ({} target-close + random from {} verified, {} obfuscated/{} plaintext)",
                                initial_sent, target_contacts.len(), all_contacts.len(), obf_count, plain_count);
                        }
                    }
                }

            }

            // Cleanup flood protection tracking and cap peer nicknames
            _ = flood_cleanup_timer.tick() => {
                state.flood_protection.cleanup();

                // Prevent unbounded growth of peer_nicknames
                const MAX_NICKNAME_ENTRIES: usize = 500;
                if state.peer_nicknames.len() > MAX_NICKNAME_ENTRIES {
                    let current_contacts: HashSet<KadId> = state.routing_table
                        .all_contacts()
                        .map(|c| c.id)
                        .collect();
                    state.peer_nicknames.retain(|id, _| current_contacts.contains(id));
                }

                // Expire overloaded node entries after 10 minutes
                let now = chrono::Utc::now().timestamp();
                state.overloaded_nodes.retain(|_, &mut ts| now - ts < 600);

                // Expire online_friends entries not seen in 5 minutes (aligned with session idle timeout)
                {
                    let expired: Vec<[u8; 16]> = state.online_friends.iter()
                        .filter(|(_, &ts)| now - ts >= 300)
                        .map(|(k, _)| *k)
                        .collect();
                    for eh in &expired {
                        state.online_friends.remove(eh);
                        let _ = app_handle.emit("ember:friend-offline", serde_json::json!({
                            "user_hash": hex::encode(eh),
                        }));
                    }
                }

                // Cap banned_ips to prevent unbounded growth: keep only IPs
                // still in the database. The full ban persists in the DB.
                const MAX_BANNED_IPS: usize = 10_000;
                if state.banned_ips.len() > MAX_BANNED_IPS {
                    let db_banned: HashSet<Ipv4Addr> = db.get_peers()
                        .unwrap_or_default()
                        .iter()
                        .filter(|p| p.banned)
                        .filter_map(|p| p.addresses.first().and_then(|a| a.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok())))
                        .collect();
                    state.banned_ips = db_banned;
                }
            }

            // Retry source search for pending downloads (eMule: never auto-fail, search forever)
            _ = source_retry_timer.tick() => {
                let now = chrono::Utc::now().timestamp();
                let kad_available = state.stats.status != NetworkStatus::Disconnected;
                let server_connected = state.server_connected;

                // Always process cancellations even when offline.
                {
                    let to_cancel: Vec<String> = state.pending_downloads.iter()
                        .filter(|(_, pd)| pd.control.is_cancelled())
                        .map(|(tid, _)| tid.clone())
                        .collect();
                    for tid in &to_cancel {
                        if let Some(_pending) = state.pending_downloads.remove(tid) {
                            let stale_sids: Vec<SearchId> = state.download_source_searches.iter()
                                .filter(|(_, (t, _))| t == tid)
                                .map(|(sid, _)| *sid)
                                .collect();
                            for sid in &stale_sids {
                                state.download_source_searches.remove(sid);
                                if let Some(removed) = state.search_manager.remove(sid) {
                                    state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                                }
                            }

                            let mut mgr = transfer_manager.write().await;
                            mgr.update_status(tid, TransferStatus::Failed);
                            mgr.fail(
                                tid,
                                "Cancelled",
                                Some("transient".to_string()),
                                Some("cancelled".to_string()),
                            );
                            if let Err(e) = db.update_transfer_status(tid, "failed") {
                                warn!("DB update_transfer_status('failed') failed for {tid}: {e}");
                            }
                            let _ = app_handle.emit("transfer-status", serde_json::json!({
                                "id": tid,
                                "status": "failed",
                                "error": "Cancelled by user",
                            }));
                        }
                    }
                }

                // Skip source searches when neither KAD nor a server is connected --
                // there is no network to search. Avoids burning retry budget on startup
                // before any connection is established.
                if !kad_available && !server_connected {
                    continue;
                }

                let mut to_retry: Vec<(String, u32)> = Vec::new();

                let dl_dir = PathBuf::from(&settings.download_folder);
                for (tid, pd) in &state.pending_downloads {
                    if pd.control.is_cancelled() || pd.control.is_paused() {
                        continue;
                    }
                    if !check_disk_space(&dl_dir, pd.file_size) {
                        debug!("Skipping source retry for {} ({}): insufficient disk space", tid, pd.file_name);
                        continue;
                    }
                    let retry_interval = pending_download_retry_interval(pd.search_count);
                    if now.saturating_sub(pd.last_search_at) >= retry_interval {
                        to_retry.push((tid.clone(), pd.priority));
                    }
                }

                // High-priority downloads get processed first
                to_retry.sort_by(|a, b| b.1.cmp(&a.1));

                // eMule-style: check persistent per-file source lists for sources
                // whose reask timer has expired. These are sources we already know
                // about from previous connection attempts -- much cheaper than a
                // new KAD search.
                let mut started_from_persistent: Vec<String> = Vec::new();
                let a4af_snap = a4af_shared.read().await;
                for (tid, _) in &to_retry {
                    if let Some(pfs) = state.per_file_sources.get_mut(tid) {
                        pfs.purge_dead_sources();
                        let sm_guard = source_manager.read().await;
                        let ready = pfs.sources_ready_for_reask_with_reputation(
                            |ip, port| {
                                sm_guard.find_user_hash_by_addr(ip, port)
                                    .map_or(false, |uh| state.reputation.is_banned(&uh))
                            },
                            |ip, port| {
                                sm_guard.find_user_hash_by_addr(ip, port)
                                    .map_or(0, |uh| state.reputation.score(&uh))
                            },
                        );
                        drop(sm_guard);
                        if !ready.is_empty() {
                            let live: Vec<(String, u16)> = ready.into_iter()
                                .filter(|(ip, port)| {
                                    !state.dead_sources.is_dead_source_for_file(&pfs.file_hash, u32::from(*ip), *port)
                                })
                                .filter(|(ip, port)| {
                                    let addr = SocketAddr::new((*ip).into(), *port);
                                    !a4af_snap.is_swap_candidate(addr, &pfs.file_hash)
                                })
                                .map(|(ip, port)| (ip.to_string(), port))
                                .collect();
                            if !live.is_empty() {
                                debug!(
                                    "Persistent source list has {} sources ready for reask for {}",
                                    live.len(), tid
                                );
                                started_from_persistent.push(tid.clone());
                            }
                        }
                    }
                }
                drop(a4af_snap);

                // First pass: check if SourceManager has accumulated sources for
                // any pending download (from server TCP/UDP responses). If so, start
                // the download immediately instead of waiting for a new Kad search.
                let mut started_from_sm: Vec<String> = Vec::new();
                {
                    let sm = source_manager.read().await;
                    for (tid, _) in &to_retry {
                        if started_from_persistent.contains(tid) { continue; }
                        if let Some(pd) = state.pending_downloads.get(tid) {
                            if let Ok(hash_bytes) = hex::decode(&pd.file_hash) {
                                if hash_bytes.len() == 16 {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&hash_bytes);
                                    let sm_sources = sm.get_sources(&fh);
                                    let live_sources: Vec<(String, u16)> = sm_sources.into_iter()
                                        .filter(|(ip, port)| !state.dead_sources.is_dead_source_for_file(&fh, u32::from(*ip), *port))
                                        .map(|(ip, port)| (ip.to_string(), port))
                                        .collect();
                                    if !live_sources.is_empty() {
                                        started_from_sm.push(tid.clone());
                                    }
                                }
                            }
                        }
                    }
                }
                // Handle downloads from persistent source list
                for tid in &started_from_persistent {
                    if let Some(pending) = state.pending_downloads.remove(tid) {
                        let hash_bytes = match hex::decode(&pending.file_hash) {
                            Ok(b) if b.len() == 16 => {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(&b);
                                arr
                            }
                            _ => {
                                state.pending_downloads.insert(tid.clone(), pending);
                                continue;
                            }
                        };
                        let sm_guard2 = source_manager.read().await;
                        let ready_sources: Vec<(String, u16)> = state.per_file_sources
                            .get(tid)
                            .map(|pfs| pfs.sources_ready_for_reask_with_reputation(
                                |ip, port| {
                                    sm_guard2.find_user_hash_by_addr(ip, port)
                                        .map_or(false, |uh| state.reputation.is_banned(&uh))
                                },
                                |ip, port| {
                                    sm_guard2.find_user_hash_by_addr(ip, port)
                                        .map_or(0, |uh| state.reputation.score(&uh))
                                },
                            ).into_iter()
                                .filter(|(ip, port)| !state.dead_sources.is_dead_source_for_file(&hash_bytes, u32::from(*ip), *port))
                                .map(|(ip, port)| (ip.to_string(), port))
                                .collect())
                            .unwrap_or_default();
                        drop(sm_guard2);
                        if ready_sources.is_empty() {
                            state.pending_downloads.insert(tid.clone(), pending);
                            continue;
                        }
                        let dl_dir = PathBuf::from(&settings.download_folder);
                        if !check_disk_space(&dl_dir, pending.file_size) {
                            warn!("Skipping download {} ({}): insufficient disk space", tid, pending.file_name);
                            state.pending_downloads.insert(tid.clone(), pending);
                            continue;
                        }
                        let source_count = ready_sources.len() as u32;
                        {
                            let sm = source_manager.read().await;
                            let mut mgr = transfer_manager.write().await;
                            mgr.update_status(tid, TransferStatus::Active);
                            mgr.update_sources(tid, source_count, 0, 0);
                            for (ip_s, port) in &ready_sources {
                                let cc = ip_s.parse::<std::net::IpAddr>().ok()
                                    .and_then(|ip| crate::geoip::lookup_country(&geoip, ip));
                                let origin = ip_s.parse::<Ipv4Addr>().ok()
                                    .and_then(|v4| sm.get_source_origin(&hash_bytes, v4, *port))
                                    .map(|s| s.to_string());
                                mgr.update_source_detail(
                                    tid,
                                    crate::types::SourceInfo {
                                        ip: ip_s.clone(),
                                        port: *port,
                                        status: crate::types::SourceStatus::Connecting,
                                        queue_rank: None,
                                        speed: 0,
                                        transferred: 0,
                                        client_software: String::new(),
                                        peer_name: String::new(),
                                        available_parts: None,
                                        total_parts: None,
                                        country_code: cc,
                                        source_origin: origin,
                                    },
                                );
                            }
                        }
                        let _ = app_handle.emit("transfer-status", serde_json::json!({
                            "id": tid,
                            "status": "active",
                            "sources": source_count,
                            "active_sources": 0,
                            "queued_sources": 0,
                        }));
                        info!("Reasking {} persistent sources for download {}", source_count, tid);
                        let download_sources: Vec<DownloadSource> = {
                            let sm = source_manager.read().await;
                            ready_sources.iter()
                                .map(|(ip, port)| {
                                    let uh = ip.parse::<Ipv4Addr>().ok()
                                        .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
                                    let co = ip.parse::<Ipv4Addr>().ok()
                                        .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
                                    DownloadSource {
                                        peer_ip: ip.clone(),
                                        peer_port: *port,
                                        available_parts: vec![],
                                        peer_user_hash: uh,
                                        peer_connect_options: co,
                                    }
                                })
                                .collect()
                        };
                        let (new_source_tx, new_source_rx) = mpsc::channel::<DownloadSource>(64);
                        let (new_established_tx, new_established_rx) =
                            mpsc::channel::<ed2k::multi_source::EstablishedSource>(8);
                        state.active_source_senders.insert(tid.clone(), new_source_tx);
                        state.active_established_senders.insert(tid.clone(), new_established_tx);
                        let ms_download = MultiSourceDownload {
                            transfer_id: pending.transfer_id,
                            file_hash: hash_bytes,
                            file_name: pending.file_name,
                            file_size: pending.file_size,
                            sources: download_sources,
                            download_dir: PathBuf::from(&settings.download_folder),
                            user_hash: state.user_hash,
                            nickname: settings.nickname.clone(),
                            tcp_port: settings.tcp_port,
                            udp_port: settings.udp_port,
                            bandwidth_limiter: bandwidth_limiter.clone(),
                            control: pending.control,
                            source_manager: Some(source_manager.clone()),
                            comment_manager: Some(state.comment_manager.clone()),
                            credit_manager: Some(credit_manager.clone()),
                            shared_buddy_info: Some(state.shared_buddy_info.clone()),
                            obfuscation_enabled: state.obfuscation_enabled,
                            server_addr: state.server_addr,
                            new_source_rx: Some(new_source_rx),
                            new_established_rx: Some(new_established_rx),
                        ed2k_limits: settings.ed2k_download_limits(),
                        ember_hash,
                        friend_hashes: Some(friend_hashes.clone()),
                            ember_payload: shared_ember_payload.clone(),
                            ember_payload_generation: ember_payload_generation.clone(),
                            ip_filter: Some(state.shared_ip_filter.clone()),
                            banned_ips: Some(shared_banned_ips.clone()),
                            external_ip: state.external_ip,
                            aich_pending: Some(state.aich_recovery_pending.clone()),
                            geoip: geoip.clone(),
                            tracker_registry: Some(state.tracker_registry.clone()),
                            sx_overhead: stats_manager.sx_counters.clone(),
                        };
                        let tx = dl_event_tx.clone();
                        let dl_tid = ms_download.transfer_id.clone();
                        let dl_tid2 = dl_tid.clone();
                        let tx2 = tx.clone();
                        if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
                            old_handle.abort();
                        }
                        let handle = tokio::spawn(async move {
                            if let Err(e) = ms_download.run(tx).await {
                                error!("Persistent source download failed: {e}");
                                let kind = classify_error(&e.to_string());
                                let _ = tx2.send(DownloadEvent::Failed { transfer_id: dl_tid, error: e.to_string(), failure_kind: kind }).await;
                            }
                        });
                        state.download_handles.insert(dl_tid2, handle);
                    }
                }

                for tid in &started_from_sm {
                    if started_from_persistent.contains(tid) { continue; }
                    if let Some(pending) = state.pending_downloads.remove(tid) {
                        let hash_bytes = match hex::decode(&pending.file_hash) {
                            Ok(b) if b.len() == 16 => {
                                let mut arr = [0u8; 16];
                                arr.copy_from_slice(&b);
                                arr
                            }
                            _ => {
                                state.pending_downloads.insert(tid.clone(), pending);
                                continue;
                            }
                        };
                        let (sm_sources, sm_origins): (Vec<(Ipv4Addr, u16)>, Vec<Option<&str>>) = {
                            let sm = source_manager.read().await;
                            let srcs = sm.get_sources(&hash_bytes);
                            let origins: Vec<Option<&str>> = srcs.iter()
                                .map(|(ip, port)| sm.get_source_origin(&hash_bytes, *ip, *port))
                                .collect();
                            (srcs, origins)
                        };
                        let live_sources: Vec<(String, u16, Option<String>)> = sm_sources.into_iter()
                            .zip(sm_origins)
                            .filter(|((ip, port), _)| !state.dead_sources.is_dead_source_for_file(&hash_bytes, u32::from(*ip), *port))
                            .map(|((ip, port), origin)| (ip.to_string(), port, origin.map(|s| s.to_string())))
                            .collect();
                        if live_sources.is_empty() {
                            state.pending_downloads.insert(tid.clone(), pending);
                            continue;
                        }
                        let dl_dir = PathBuf::from(&settings.download_folder);
                        if !check_disk_space(&dl_dir, pending.file_size) {
                            warn!("Skipping download {} ({}): insufficient disk space", tid, pending.file_name);
                            state.pending_downloads.insert(tid.clone(), pending);
                            continue;
                        }
                        let source_count = live_sources.len() as u32;
                        {
                            let mut mgr = transfer_manager.write().await;
                            mgr.update_status(tid, TransferStatus::Active);
                            mgr.update_sources(tid, source_count, 0, 0);
                            for (ip_s, port, origin) in &live_sources {
                                let cc = ip_s.parse::<std::net::IpAddr>().ok()
                                    .and_then(|ip| crate::geoip::lookup_country(&geoip, ip));
                                mgr.update_source_detail(
                                    tid,
                                    crate::types::SourceInfo {
                                        ip: ip_s.clone(),
                                        port: *port,
                                        status: crate::types::SourceStatus::Connecting,
                                        queue_rank: None,
                                        speed: 0,
                                        transferred: 0,
                                        client_software: String::new(),
                                        peer_name: String::new(),
                                        available_parts: None,
                                        total_parts: None,
                                        country_code: cc,
                                        source_origin: origin.clone(),
                                    },
                                );
                            }
                        }
                        let _ = app_handle.emit("transfer-status", serde_json::json!({
                            "id": tid,
                            "status": "active",
                            "sources": source_count,
                            "active_sources": 0,
                            "queued_sources": 0,
                        }));
                        info!("Starting download {} from {} accumulated sources", tid, source_count);
                        {
                            let pfs = state.per_file_sources
                                .entry(tid.clone())
                                .or_insert_with(|| ed2k::sources::PerFileSourceList::new(hash_bytes));
                            let udp_sources = {
                                let sm = source_manager.read().await;
                                sm.get_udp_sources(&hash_bytes)
                            };
                            for (ip_s, port, _) in &live_sources {
                                if let Ok(v4) = ip_s.parse::<Ipv4Addr>() {
                                    let udp_port = udp_sources
                                        .iter()
                                        .find(|(ip, tcp_port, _)| ip == &v4 && tcp_port == port)
                                        .map(|(_, _, udp)| *udp)
                                        .unwrap_or(0);
                                    if pfs.add_source_full(v4, *port, udp_port) {
                                        state.ember_payload_dirty = true;
                                    }
                                }
                            }
                        }
                        {
                            let mut sm = source_manager.write().await;
                            for (ip, port, _) in &live_sources {
                                if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                                    sm.register_source(hash_bytes, v4, *port);
                                }
                            }
                        }
                        let download_sources: Vec<DownloadSource> = {
                            let sm = source_manager.read().await;
                            live_sources.iter()
                                .map(|(ip, port, _)| {
                                    let uh = ip.parse::<Ipv4Addr>().ok()
                                        .and_then(|v4| sm.get_user_hash(&hash_bytes, v4, *port));
                                    let co = ip.parse::<Ipv4Addr>().ok()
                                        .and_then(|v4| sm.get_connect_options(&hash_bytes, v4, *port));
                                    DownloadSource {
                                        peer_ip: ip.clone(),
                                        peer_port: *port,
                                        available_parts: Vec::new(),
                                        peer_user_hash: uh,
                                        peer_connect_options: co,
                                    }
                                })
                                .collect()
                        };
                        let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
                        let (est_inject_tx, est_inject_rx) =
                            mpsc::channel::<ed2k::multi_source::EstablishedSource>(8);
                        let ms_download = MultiSourceDownload {
                            transfer_id: pending.transfer_id,
                            file_hash: hash_bytes,
                            file_name: pending.file_name,
                            file_size: pending.file_size,
                            sources: download_sources,
                            download_dir: PathBuf::from(&settings.download_folder),
                            user_hash: state.user_hash,
                            nickname: settings.nickname.clone(),
                            tcp_port: settings.tcp_port,
                            udp_port: settings.udp_port,
                            bandwidth_limiter: bandwidth_limiter.clone(),
                            control: pending.control,
                            source_manager: Some(source_manager.clone()),
                            comment_manager: Some(state.comment_manager.clone()),
                            credit_manager: Some(credit_manager.clone()),
                            shared_buddy_info: Some(state.shared_buddy_info.clone()),
                            obfuscation_enabled: state.obfuscation_enabled,
                            server_addr: state.server_addr,
                            new_source_rx: Some(src_inject_rx),
                            new_established_rx: Some(est_inject_rx),
                        ed2k_limits: settings.ed2k_download_limits(),
                        ember_hash,
                        friend_hashes: Some(friend_hashes.clone()),
                            ember_payload: shared_ember_payload.clone(),
                            ember_payload_generation: ember_payload_generation.clone(),
                            ip_filter: Some(state.shared_ip_filter.clone()),
                            banned_ips: Some(shared_banned_ips.clone()),
                            external_ip: state.external_ip,
                            aich_pending: Some(state.aich_recovery_pending.clone()),
                            geoip: geoip.clone(),
                            tracker_registry: Some(state.tracker_registry.clone()),
                            sx_overhead: stats_manager.sx_counters.clone(),
                        };
                        let dl_tid = ms_download.transfer_id.clone();
                        let dl_tid2 = dl_tid.clone();
                        state.active_source_senders.insert(dl_tid.clone(), src_inject_tx);
                        state.active_established_senders.insert(dl_tid.clone(), est_inject_tx);
                        let tx = dl_event_tx.clone();
                        let tx2 = tx.clone();
                        if let Some(old_handle) = state.download_handles.remove(&dl_tid2) {
                            old_handle.abort();
                        }
                        let handle = tokio::spawn(async move {
                            if let Err(e) = ms_download.run(tx).await {
                                error!("Multi-source download failed: {e}");
                                let kind = classify_error(&e.to_string());
                                let _ = tx2.send(DownloadEvent::Failed { transfer_id: dl_tid, error: e.to_string(), failure_kind: kind }).await;
                            }
                        });
                        state.download_handles.insert(dl_tid2, handle);
                    }
                }
                let mut to_retry: Vec<String> = to_retry.into_iter()
                    .filter(|(tid, _)| !started_from_sm.contains(tid) && !started_from_persistent.contains(tid))
                    .map(|(tid, _)| tid)
                    .collect();

                // UDP reask pass: for sources with known UDP ports, send enhanced
                // OP_REASKFILEPING with part status bitmap + complete source count
                // (eMule udp_ver > 3 format). Sources whose SX is due are skipped
                // so the normal TCP reask path can carry OP_REQUESTSOURCES.
                {
                    let reask_interval = ed2k::dead_sources::FILEREASKTIME_SECS;
                    let mut sm = source_manager.write().await;
                    for tid in &to_retry {
                        let (fh, file_size) = match state.pending_downloads.get(tid) {
                            Some(pd) => match hex::decode(&pd.file_hash) {
                                Ok(b) if b.len() == 16 => {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&b);
                                    (fh, pd.file_size)
                                }
                                _ => continue,
                            },
                            None => continue,
                        };

                        let complete_sources = state.per_file_sources
                            .get(tid)
                            .map(|pfs| pfs.complete_source_count())
                            .unwrap_or(0);

                        let reask_payload = ed2k::messages::build_reask_file_ping(
                            &fh, file_size, complete_sources, None,
                        );

                        let total_udp = sm.get_udp_sources(&fh).len();
                        let udp_sources = sm.get_udp_sources_due_for_reask(&fh, reask_interval);
                        // Track which (ip, tcp_port) pairs we sent to in this
                        // tick so the persistent-list pass below doesn't
                        // double-fire to the same peer (the SM cooldown is
                        // already active from the `mark_asked` call below,
                        // but `can_request_sources_for` returning false is
                        // *exactly* the gate the persistent loop currently
                        // proceeds past — so without an explicit set we'd
                        // emit two identical OP_REASKFILEPING in one tick).
                        let mut sent_this_tick: HashSet<(Ipv4Addr, u16)> =
                            HashSet::with_capacity(udp_sources.len());
                        let mut sent = 0usize;
                        for (ip, tcp_port, udp_port) in &udp_sources {
                            if state.dead_sources.is_dead_source_for_file(&fh, u32::from(*ip), *tcp_port) {
                                continue;
                            }
                            if sm.can_request_sources_for(&fh, *ip, *tcp_port) {
                                continue;
                            }
                            let addr = SocketAddr::new((*ip).into(), *udp_port);
                            let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
                            pkt.extend_from_slice(&reask_payload);
                            let _ = udp_socket.send_to(&pkt, addr).await;
                            sm.mark_asked(&fh, *ip, *tcp_port);
                            sent_this_tick.insert((*ip, *tcp_port));
                            sent += 1;
                        }
                        if sent > 0 {
                            debug!(
                                "Sent UDP reask to {}/{} UDP sources for pending download {}",
                                sent, total_udp, tid
                            );
                        }

                        // Also check persistent per-file source list for UDP reask candidates.
                        if let Some(pfs) = state.per_file_sources.get_mut(tid) {
                            let udp_due = pfs.sources_needing_udp_reask();
                            let mut pfs_sent = 0usize;
                            for (ip, tcp_port, udp_port) in &udp_due {
                                if sent_this_tick.contains(&(*ip, *tcp_port)) {
                                    // Already pinged via SourceManager this tick.
                                    continue;
                                }
                                if state.dead_sources.is_dead_source_for_file(&pfs.file_hash, u32::from(*ip), *tcp_port) {
                                    continue;
                                }
                                if sm.can_request_sources_for(&pfs.file_hash, *ip, *tcp_port) {
                                    continue;
                                }
                                let addr = SocketAddr::new((*ip).into(), *udp_port);
                                let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
                                pkt.extend_from_slice(&reask_payload);
                                if udp_socket.send_to(&pkt, addr).await.is_ok() {
                                    // Bump last_asked so this entry isn't
                                    // "due" again until the next full
                                    // FILEREASKTIME window — without this
                                    // the 5s timer pings the same peer
                                    // every tick forever.
                                    pfs.mark_udp_reask_sent(*ip, *tcp_port);
                                    pfs_sent += 1;
                                }
                            }
                            if pfs_sent > 0 {
                                debug!("Sent UDP reask to {} persistent sources for {}", pfs_sent, tid);
                            }
                        }
                    }
                }

                // Second pass: for remaining pending downloads, start new Kad + server searches.
                // Limit KAD searches per tick to avoid overwhelming the routing table when
                // many downloads are queued (eMule staggers source searches).
                const MAX_KAD_SEARCHES_PER_TICK: usize = 8;
                let mut kad_searches_started = 0usize;
                // Rotate the list so different downloads get the limited KAD search
                // slots each tick instead of the same ones always winning.
                if to_retry.len() > MAX_KAD_SEARCHES_PER_TICK {
                    let rotate_by = state.kad_source_search_cursor % to_retry.len();
                    to_retry.rotate_left(rotate_by);
                }
                let to_retry_len = to_retry.len();
                for tid in to_retry {
                    let (hash_bytes, file_size) = {
                        let Some(pd) = state.pending_downloads.get_mut(&tid) else { continue; };
                        if pd.control.is_cancelled() || pd.control.is_paused() {
                            continue;
                        }
                        let hash_bytes = match hex::decode(&pd.file_hash) {
                            Ok(b) if b.len() == 16 => b,
                            _ => continue,
                        };
                        (hash_bytes, pd.file_size)
                    };

                    let mut did_search = false;
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&hash_bytes);

                    if kad_available && kad_searches_started < MAX_KAD_SEARCHES_PER_TICK {
                        let kad_hash = md4_bytes_to_kad_id(&hash_bytes);
                        let closest = state.routing_table.find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                        if !closest.is_empty() {
                            let sid = state.search_manager.start_search(
                                kad_hash,
                                SearchType::FindSource { file_size },
                                closest,
                            );
                            if sid != SearchId(0) {
                                state.download_source_searches.insert(sid, (tid.clone(), fh));
                                kad_searches_started += 1;
                                did_search = true;
                            }
                        } else {
                            debug!("Routing table empty for retry of {tid}, continuing with server-only source refresh");
                        }
                    }
                    let src_count = {
                        let sm = source_manager.read().await;
                        sm.source_count(&fh)
                    };
                    if src_count < MAX_SOURCES_FOR_UDP {
                        let packets = build_all_getsources_packets(
                            &state,
                            &fh,
                            file_size,
                        );
                        if !packets.is_empty() {
                            let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                            let to_queue: Vec<_> = packets.into_iter().take(room).collect();
                            if !to_queue.is_empty() { did_search = true; }
                            state.udp_source_queue.extend(to_queue);
                        }
                    }

                        if !state.low_id && state.server_connected {
                            if let Some(conn) = &mut state.server_connection {
                                let current_server = state.server_addr.and_then(|addr| {
                                    match addr.ip() {
                                        std::net::IpAddr::V4(v4) => {
                                            Some((u32::from_le_bytes(v4.octets()), addr.port()))
                                        }
                                        _ => None,
                                    }
                                });
                                if let Some((srv_ip, srv_port)) = current_server {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&hash_bytes);
                                    let needing_callback = {
                                        let sm = source_manager.read().await;
                                        sm.get_lowid_sources_needing_callback(
                                            &fh,
                                            srv_ip,
                                            srv_port,
                                            ed2k::dead_sources::FILEREASKTIME_SECS,
                                        )
                                    };
                                    if !needing_callback.is_empty() {
                                        let mut sm = source_manager.write().await;
                                        for cid in &needing_callback {
                                            if conn.request_callback(*cid).await.is_ok() {
                                                sm.mark_callback_sent(&fh, *cid);
                                            }
                                        }
                                        did_search = true;
                                        debug!("Sent {} LowID callback requests for pending download", needing_callback.len());
                                    }
                                }
                            }
                        }

                    if did_search {
                        if let Some(pd) = state.pending_downloads.get_mut(&tid) {
                            pd.search_count += 1;
                            pd.last_search_at = now;
                        }
                    }

                    let search_count = state.pending_downloads.get(&tid).map(|pd| pd.search_count).unwrap_or(0);
                    info!(
                        "Retrying source search for {} (attempt {})",
                        tid, search_count
                    );
                }
                if to_retry_len > MAX_KAD_SEARCHES_PER_TICK {
                    state.kad_source_search_cursor = state.kad_source_search_cursor.wrapping_add(MAX_KAD_SEARCHES_PER_TICK);
                }

                // eMule: every downloading file periodically searches KAD for
                // additional sources, not just files waiting for their first
                // source.  Use remaining budget from MAX_KAD_SEARCHES_PER_TICK.
                let mut active_kad_started = 0usize;
                if kad_available && kad_searches_started < MAX_KAD_SEARCHES_PER_TICK {
                    let mut active_needing_kad: Vec<(String, [u8; 16], u64)> = Vec::new();
                    {
                        let mgr = transfer_manager.read().await;
                        let sm = source_manager.read().await;
                        for (tid, _sender) in &state.active_source_senders {
                            if state.pending_downloads.contains_key(tid) { continue; }
                            let (last_at, count) = state.active_kad_search_state
                                .get(tid)
                                .copied()
                                .unwrap_or((0, 0));
                            let interval = active_download_kad_interval(count);
                            if now.saturating_sub(last_at) < interval { continue; }
                            if let Some(transfer) = mgr.get_transfer(tid) {
                                if let Ok(raw) = hex::decode(&transfer.file_hash) {
                                    if raw.len() == 16 {
                                        let mut fh = [0u8; 16];
                                        fh.copy_from_slice(&raw[..16]);
                                        if sm.source_count(&fh) >= MAX_SOURCES_FOR_UDP { continue; }
                                        active_needing_kad.push((tid.clone(), fh, transfer.total_size));
                                    }
                                }
                            }
                        }
                    }
                    for (tid, fh, file_size) in active_needing_kad {
                        if kad_searches_started >= MAX_KAD_SEARCHES_PER_TICK { break; }
                        let kad_hash = md4_bytes_to_kad_id(&fh);
                        let closest = state.routing_table.find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                        if !closest.is_empty() {
                            let sid = state.search_manager.start_search(
                                kad_hash,
                                SearchType::FindSource { file_size },
                                closest,
                            );
                            if sid != SearchId(0) {
                                state.download_source_searches.insert(sid, (tid.clone(), fh));
                                kad_searches_started += 1;
                                active_kad_started += 1;
                                let entry = state.active_kad_search_state.entry(tid.clone()).or_insert((0, 0));
                                entry.0 = now;
                                entry.1 += 1;
                                debug!("Started KAD source search for active download {} (attempt {})", tid, entry.1);
                            }
                        }
                    }
                }

                {
                    let total_pending = state.pending_downloads.len();
                    let active_downloads = state.download_handles.len();
                    if total_pending > 0 || kad_searches_started > 0 {
                        info!(
                            "Source retry tick: {} pending, {} active, {} started(persistent={}, sm={}), {} KAD searches ({}+{} active), server={}",
                            total_pending, active_downloads,
                            started_from_persistent.len() + started_from_sm.len(),
                            started_from_persistent.len(), started_from_sm.len(),
                            kad_searches_started, kad_searches_started - active_kad_started, active_kad_started,
                            if server_connected { "yes" } else { "no" }
                        );
                    }
                }

                // Auto-priority adjustment (eMule: CPartFile::UpdateAutoDownPriority)
                {
                    let mgr = transfer_manager.read().await;
                    let auto_tids: Vec<(String, [u8; 16])> = state.pending_downloads.iter()
                        .filter_map(|(tid, pd)| {
                            let t = mgr.active.get(tid)?;
                            if t.priority != "auto" { return None; }
                            let raw = hex::decode(&pd.file_hash).ok()?;
                            if raw.len() < 16 { return None; }
                            let mut fh = [0u8; 16];
                            fh.copy_from_slice(&raw[..16]);
                            Some((tid.clone(), fh))
                        })
                        .collect();
                    drop(mgr);
                    if !auto_tids.is_empty() {
                        let sm = source_manager.read().await;
                        for (tid, fh) in &auto_tids {
                            let src_count = sm.source_count(fh);
                            let effective = if src_count > 100 { "low" } else if src_count > 20 { "normal" } else { "high" };
                            let effective_u32 = priority_str_to_u32(effective);
                            if let Some(pd) = state.pending_downloads.get_mut(tid) {
                                pd.priority = effective_u32;
                            }
                            debug!("Auto-priority for {tid}: {src_count} sources -> {effective} ({})", effective_u32);
                        }
                    }
                }
            }

            // Periodic credit save to database (with stale record cleanup)
            _ = credit_save_timer.tick() => {
                flush_credit_state(&credit_manager, &db, &state.data_dir, true).await;
            }

            // A4AF swap evaluation every 8 minutes
            _ = a4af_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                let mut file_priorities: HashMap<[u8; 16], ed2k::a4af::FileSwapInfo> = HashMap::new();
                let mut dl_hashes_vec: Vec<[u8; 16]> = Vec::new();
                for (tid, pd) in &state.pending_downloads {
                    let hash_hex = &pd.file_hash;
                    if let Ok(raw) = hex::decode(hash_hex) {
                        if raw.len() >= 16 {
                            let mut hash = [0u8; 16];
                            hash.copy_from_slice(&raw[..16]);
                            let active_sources = state.active_source_senders
                                .get(tid)
                                .map(|s| s.max_capacity().saturating_sub(s.capacity()))
                                .unwrap_or(0);
                            let has_active = state.active_source_senders.contains_key(tid);
                            let priority = {
                                let mgr = transfer_manager.read().await;
                                let prio_str = mgr.active.get(tid)
                                    .map(|t| t.priority.as_str())
                                    .unwrap_or("normal");
                                if prio_str == "auto" {
                                    let sm = source_manager.read().await;
                                    let src_count = sm.source_count(&hash);
                                    if src_count > 100 { 2 } else if src_count > 20 { 7 } else { 9 }
                                } else {
                                    match prio_str {
                                        "release" => 10,
                                        "high" => 9,
                                        "low" => 2,
                                        "verylow" => 1,
                                        _ => 7,
                                    }
                                }
                            };
                            file_priorities.insert(hash, ed2k::a4af::FileSwapInfo {
                                priority,
                                active_source_count: if has_active { active_sources.max(1) } else { 0 },
                                has_needed_parts: true,
                            });
                            dl_hashes_vec.push(hash);
                        }
                    }
                }

                {
                    let mut pdh = pending_dl_hashes.write().await;
                    *pdh = dl_hashes_vec;
                }

                // Feed NNP sources from persistent per-file lists into A4AF.
                // A source with NNP on file X should be offered to all OTHER
                // active downloads, not back to file X itself.
                {
                    let all_file_hashes: Vec<[u8; 16]> = state.per_file_sources
                        .values()
                        .map(|pfs| pfs.file_hash)
                        .collect();
                    let mut a4af = a4af_shared.write().await;
                    for (_tid, pfs) in &state.per_file_sources {
                        for src in &pfs.sources {
                            if matches!(src.state, ed2k::sources::DownloadSourceState::NoneNeededParts) {
                                let addr = SocketAddr::new(src.ip.into(), src.tcp_port);
                                for &other_hash in &all_file_hashes {
                                    if other_hash != pfs.file_hash {
                                        a4af.add_a4af_source(
                                            other_hash,
                                            addr,
                                            pfs.file_hash,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }

                let swaps = {
                    let a4af = a4af_shared.read().await;
                    a4af.process_swaps(&file_priorities)
                };
                if !swaps.is_empty() {
                    info!("A4AF: {} swap actions to execute", swaps.len());
                    for swap in &swaps {
                        debug!("A4AF swap: {} -> {}", hex::encode(swap.from_file), hex::encode(swap.to_file));
                        let mut sm = source_manager.write().await;
                        if let std::net::IpAddr::V4(v4) = swap.peer_addr.ip() {
                            sm.remove_source(&swap.from_file, &v4, swap.peer_addr.port());
                            sm.register_source(swap.to_file, v4, swap.peer_addr.port());
                        }

                        // Inject source into active download if one exists for the target file
                        let target_hex = hex::encode(swap.to_file);
                        let matching_transfer_ids = {
                            let mgr = transfer_manager.read().await;
                            matching_active_transfer_ids_for_hash(&state, &mgr, &target_hex)
                        };
                        if !matching_transfer_ids.is_empty() {
                            let uh = if let std::net::IpAddr::V4(v4) = swap.peer_addr.ip() {
                                sm.get_user_hash(&swap.to_file, v4, swap.peer_addr.port())
                            } else { None };
                            let co = if let std::net::IpAddr::V4(v4) = swap.peer_addr.ip() {
                                sm.get_connect_options(&swap.to_file, v4, swap.peer_addr.port())
                            } else { None };
                            let new_source = ed2k::multi_source::DownloadSource {
                                peer_ip: swap.peer_addr.ip().to_string(),
                                peer_port: swap.peer_addr.port(),
                                available_parts: Vec::new(),
                                peer_user_hash: uh,
                                peer_connect_options: co,
                            };
                            let stats = inject_source_into_active_transfers(
                                &mut state,
                                swap.to_file,
                                &matching_transfer_ids,
                                &new_source,
                                0,
                            );
                            if stats.dropped_full > 0 || stats.dropped_closed > 0 {
                                warn!(
                                    "A4AF swap: source {} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
                                    swap.peer_addr,
                                    target_hex,
                                    stats.matched_transfers,
                                    stats.injected,
                                    stats.persisted,
                                    stats.dropped_full,
                                    stats.overflowed,
                                    stats.dropped_closed,
                                );
                            } else {
                                info!(
                                    "A4AF swap: injected {} into {} active download(s) for {}",
                                    swap.peer_addr,
                                    stats.injected,
                                    target_hex,
                                );
                            }
                        } else {
                            // No active download — check pending downloads and reset search timer
                            for pd in state.pending_downloads.values_mut() {
                                if pd.file_hash == target_hex {
                                    pd.last_search_at = 0;
                                    break;
                                }
                            }
                            info!(
                                "A4AF swap: registered {} for pending download {}",
                                swap.peer_addr, target_hex,
                            );
                        }

                        // Move source between per-file source lists so the
                        // persistent reask state follows the swap.
                        if let std::net::IpAddr::V4(v4) = swap.peer_addr.ip() {
                            let port = swap.peer_addr.port();
                            for pfs in state.per_file_sources.values_mut() {
                                if pfs.file_hash == swap.from_file {
                                    pfs.sources.retain(|s| !(s.ip == v4 && s.tcp_port == port));
                                    break;
                                }
                            }
                            for pfs in state.per_file_sources.values_mut() {
                                if pfs.file_hash == swap.to_file {
                                    if pfs.add_source_full(v4, port, 0) {
                                        state.ember_payload_dirty = true;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    let mut a4af = a4af_shared.write().await;
                    for swap in &swaps {
                        a4af.mark_swapped(swap.peer_addr);
                        a4af.remove_source(swap.peer_addr);
                    }
                }
                {
                    let mut a4af = a4af_shared.write().await;
                    a4af.cleanup_stale(3600);
                }
            }

            // ed2k server keep-alive, message polling, and auto-reconnect (non-blocking)
            _ = server_timer.tick() => {
                if state.server_connected {
                    let mut pending_lowid_callbacks: Vec<([u8; 16], u32)> = Vec::new();
                    let mut finished_search_requests: Vec<u64> = Vec::new();
                    let mut pending_source_start_tids: Vec<String> = Vec::new();
                    let mut server_disconnect_reason: Option<String> = None;
                    let mut conn_to_restore: Option<Ed2kServerConnection> = None;
                    if let Some(mut conn) = state.server_connection.take() {
                        // Poll for incoming messages (OP_SERVERLIST responses, status updates, etc.)
                        let poll_result = conn.poll_messages().await;
                        let events = match poll_result {
                            Ok(events) => events,
                            Err(e) => {
                                server_disconnect_reason = Some(e.to_string());
                                Vec::new()
                            }
                        };
                        if !events.is_empty() {
                            last_server_activity_at = chrono::Utc::now().timestamp();
                        }
                        for event in events {
                            match event {
                                ed2k::server::ServerEvent::ServerList { data } => {
                                    if settings.add_servers_from_server {
                                        let added = state.server_list.add_from_server_list_packet(
                                            &data,
                                            settings.filter_servers_by_ip,
                                            &mut state.ip_filter,
                                        );
                                        if added > 0 {
                                            emit_server_log(&app_handle, &format!("Added {added} servers from server list update"));
                                            let met_path = state.data_dir.join("server.met");
                                            if let Err(e) = state.server_list.save_server_met(&met_path) {
                                                warn!("Failed to save server.met after server list update: {e}");
                                            }
                                        }
                                    }
                                }
                                ed2k::server::ServerEvent::StatusUpdate { users, files } => {
                                    if let Some(addr) = state.server_addr {
                                        state.server_list.update_server_stats(
                                            &addr.ip().to_string(), addr.port(), users, files, 0,
                                        );
                                    }
                                    if let Some(session) = conn.session.as_mut() {
                                        session.user_count = users;
                                        session.file_count = files;
                                    }
                                }
                                ed2k::server::ServerEvent::ServerIdent { name } => {
                                    if let Some(session) = conn.session.as_mut() {
                                        session.server_name = name.clone();
                                    }
                                    if let Some(addr) = state.server_addr {
                                        if state.server_list.update_server_name_from_ident(
                                            &addr.ip().to_string(),
                                            addr.port(),
                                            &name,
                                        ) {
                                            let met_path = state.data_dir.join("server.met");
                                            let _ = state.server_list.save_server_met(&met_path);
                                        }
                                    }
                                }
                                ed2k::server::ServerEvent::SearchResult { results } => {
                                    let count = results.len();
                                    info!("Server returned {count} search results via poll");
                                    let search_results: Vec<SearchResult> = results.iter().map(|sr| {
                                        let hash_hex = hex::encode(sr.file_hash);
                                        let extension = sr.file_name
                                            .rsplit_once('.')
                                            .map(|(_, ext)| ext.to_string())
                                            .unwrap_or_default();
                                        let source_addresses = if sr.client_id >= ed2k::server::LOWID_THRESHOLD {
                                            let ip = Ipv4Addr::from(sr.client_id.to_le_bytes());
                                            if is_search_source_safe(&state, ip) {
                                                vec![format!("{}:{}", ip, sr.client_port)]
                                            } else {
                                                Vec::new()
                                            }
                                        } else {
                                            Vec::new()
                                        };
                                        SearchResult {
                                            file: FileInfo {
                                                id: hash_hex.clone(),
                                                name: sr.file_name.clone(),
                                                path: String::new(),
                                                size: sr.file_size,
                                                hash: hash_hex,
                                                aich_hash: String::new(),
                                                extension: extension.clone(),
                                                modified_at: 0,
                                                priority: "normal".to_string(),
                                                requests: 0,
                                                accepted: 0,
                                                bytes_transferred: 0,
                                                alltime_requests: 0,
                                                alltime_accepted: 0,
                                                alltime_transferred: 0,
                                                complete_sources: sr.complete_source_count,
                                                folder: String::new(),
                                                shared: false,
                                                shared_kad: false,
                                                shared_ed2k: false,
                                            },
                                            peer_id: String::new(),
                                            peer_name: String::new(),
                                            availability: sr.source_count,
                                            file_type: crate::search::index::infer_file_type(&extension),
                                            source_addresses,
                                            rating: None,
                                            comment: None,
                                            spam_rating: 0,
                                            is_spam: false,
                                            clean_name: String::new(),
                                            result_origin: crate::search::merge::ORIGIN_SERVER_TCP.to_string(),
                                        }
                                    }).collect();

                                    if let Some(mut pending) = state.pending_server_search.take() {
                                        let request_id = pending.request_id;
                                        state.server_search_age = 0;
                                        if let Some(tx) = pending.tx.take() {
                                            let mut local = pending.results;
                                            local.extend(search_results);
                                            if count >= 200 && local.len() < 1000 {
                                                state.server_search_more_needed = true;
                                                state.pending_server_search = Some(PendingServerSearch {
                                                    tx: Some(tx),
                                                    results: local,
                                                    request_id,
                                                });
                                            } else {
                                                let _ = tx.send(local);
                                                if let Some(active) = state.active_search_request.as_mut() {
                                                    if active.request_id == request_id {
                                                        active.server_pending = false;
                                                    }
                                                }
                                                finished_search_requests.push(request_id);
                                            }
                                        } else {
                                            let (ft_filter, kws, srv_ip) = state
                                                .active_search_request
                                                .as_ref()
                                                .map(|a| (a.file_type_filter.clone(), a.keywords.clone(), a.server_ip.clone()))
                                                .unwrap_or((None, Vec::new(), None));
                                            enrich_and_emit_search_results(
                                                &app_handle,
                                                &spam_filter,
                                                &settings,
                                                request_id,
                                                search_results,
                                                &ft_filter,
                                                &kws,
                                                srv_ip.as_deref(),
                                            ).await;
                                            if count >= 200 {
                                                state.server_search_more_needed = true;
                                                state.pending_server_search = Some(PendingServerSearch {
                                                    tx: None,
                                                    results: Vec::new(),
                                                    request_id,
                                                });
                                            } else {
                                                if let Some(active) = state.active_search_request.as_mut() {
                                                    if active.request_id == request_id {
                                                        active.server_pending = false;
                                                    }
                                                }
                                                finished_search_requests.push(request_id);
                                            }
                                        }
                                    }
                                }
                                ed2k::server::ServerEvent::FoundSources { file_hash, sources } => {
                                    let hash_hex_fs = hex::encode(file_hash);
                                    // Count the inbound TCP source-list reply
                                    // as SourceExchange overhead. The exact
                                    // wire size isn't carried through the
                                    // event, so we estimate from the eMule
                                    // OP_FOUNDSOURCES layout: 6-byte frame +
                                    // opcode + 16-byte hash + 2-byte count +
                                    // 6 bytes per source (IP/client_id + port).
                                    let est_bytes = (25 + sources.len() * 6) as u64;
                                    stats_manager.add_overhead(
                                        crate::storage::statistics::OverheadCategory::SourceExchange,
                                        crate::storage::statistics::OverheadDirection::Download,
                                        est_bytes,
                                    );
                                    {
                                        let matching: Vec<String> = state.pending_downloads.iter()
                                            .filter(|(_, pd)| pd.file_hash == hash_hex_fs)
                                            .map(|(_, pd)| pd.transfer_id.clone())
                                            .collect();
                                        for tid in &matching {
                                            let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                                                "transfer_id": tid,
                                                "kind": if sources.is_empty() { "server_empty" } else { "server_found" },
                                                "count": sources.len(),
                                            }));
                                        }
                                    }
                                    if sources.is_empty() {
                                        debug!("Server returned 0 sources for file {}", hash_hex_fs);
                                    }
                                    if !sources.is_empty() {
                                        let highid_count = sources.iter().filter(|s| s.client_id == 0).count();
                                        let lowid_count = sources.iter().filter(|s| s.client_id > 0).count();
                                        info!("Server found {} sources ({} HighID, {} LowID) for file {} via poll",
                                            sources.len(), highid_count, lowid_count, hex::encode(file_hash));
                                        let mut sm = source_manager.write().await;
                                        let (server_ip, server_port) = state.server_addr.and_then(|addr| {
                                            match addr.ip() {
                                                std::net::IpAddr::V4(v4) => Some((u32::from_le_bytes(v4.octets()), addr.port())),
                                                _ => None,
                                            }
                                        }).unwrap_or((0, 0));
                                        for src in &sources {
                                            if src.client_id == 0 {
                                                if let Ok(v4) = src.ip.parse::<Ipv4Addr>() {
                                                    // Mirror the gate the UDP source path applies
                                                    // (see `OP_FOUNDSOURCES` handler). Without
                                                    // this, banned/special-use IPs reported by
                                                    // the TCP-connected server would pollute
                                                    // `source_manager` (and from there our
                                                    // outbound Source Exchange) — the eventual
                                                    // download attempt is gated by
                                                    // `inject_source_into_active_transfers` so
                                                    // we don't actually connect, but we'd still
                                                    // forward the bad IP to other peers.
                                                    if crate::security::is_special_use_v4(v4)
                                                        || v4.is_multicast()
                                                        || state.ip_filter.is_blocked(v4)
                                                        || state.banned_ips.contains(&v4)
                                                    {
                                                        continue;
                                                    }
                                                    sm.register_source_full_server(
                                                        file_hash,
                                                        v4,
                                                        src.port,
                                                        0,
                                                        server_ip,
                                                        server_port,
                                                        src.user_hash.unwrap_or([0u8; 16]),
                                                        src.crypt_options.unwrap_or(0),
                                                    );
                                                }
                                            } else {
                                                sm.register_lowid_source(
                                                    file_hash,
                                                    src.client_id,
                                                    src.port,
                                                    server_ip,
                                                    server_port,
                                                    src.user_hash.unwrap_or([0u8; 16]),
                                                    src.crypt_options.unwrap_or(0),
                                                );
                                            }
                                        }
                                        drop(sm);
                                        // Collect LowID client IDs needing callbacks (dedup-aware)
                                        if !state.low_id {
                                            let sm = source_manager.read().await;
                                            let needing = sm.get_lowid_sources_needing_callback(
                                                &file_hash,
                                                server_ip,
                                                server_port,
                                                ed2k::dead_sources::FILEREASKTIME_SECS,
                                            );
                                            for cid in needing {
                                                pending_lowid_callbacks.push((file_hash, cid));
                                            }
                                        }
                                        let hash_hex = hex::encode(file_hash);
                                        let matching_transfer_ids = {
                                            let mgr = transfer_manager.read().await;
                                            matching_active_transfer_ids_for_hash(&state, &mgr, &hash_hex)
                                        };
                                        let mut server_source_ips: Vec<(String, u16)> = Vec::new();
                                        for src in &sources {
                                            if src.client_id == 0 && !src.ip.is_empty() {
                                                let v4_ip = src.ip.parse::<Ipv4Addr>().ok();
                                                if let Some(v4) = v4_ip {
                                                    if state.dead_sources.is_dead_source_for_file(&file_hash, u32::from(v4), src.port) {
                                                        continue;
                                                    }
                                                }
                                                server_source_ips.push((src.ip.clone(), src.port));
                                                let (uh, co) = if let Some(v4) = v4_ip {
                                                    let sm = source_manager.read().await;
                                                    (sm.get_user_hash(&file_hash, v4, src.port),
                                                     sm.get_connect_options(&file_hash, v4, src.port))
                                                } else {
                                                    (None, None)
                                                };
                                                let download_source = DownloadSource {
                                                    peer_ip: src.ip.clone(),
                                                    peer_port: src.port,
                                                    available_parts: Vec::new(),
                                                    peer_user_hash: uh,
                                                    peer_connect_options: co,
                                                };
                                                let stats = inject_source_into_active_transfers(
                                                    &mut state,
                                                    file_hash,
                                                    &matching_transfer_ids,
                                                    &download_source,
                                                    0,
                                                );
                                                if stats.dropped_full > 0 || stats.dropped_closed > 0 {
                                                    warn!(
                                                        "Server sources: source {}:{} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
                                                        src.ip,
                                                        src.port,
                                                        hash_hex,
                                                        stats.matched_transfers,
                                                        stats.injected,
                                                        stats.persisted,
                                                        stats.dropped_full,
                                                        stats.overflowed,
                                                        stats.dropped_closed,
                                                    );
                                                }
                                            }
                                        }
                                        if !server_source_ips.is_empty() {
                                            let mut mgr = transfer_manager.write().await;
                                            for tid in &matching_transfer_ids {
                                                for (ip_s, port) in &server_source_ips {
                                                    let cc = ip_s.parse::<std::net::IpAddr>().ok()
                                                        .and_then(|ip| crate::geoip::lookup_country(&geoip, ip));
                                                    mgr.update_source_detail(
                                                        tid,
                                                        crate::types::SourceInfo {
                                                            ip: ip_s.clone(),
                                                            port: *port,
                                                            status: crate::types::SourceStatus::Connecting,
                                                            queue_rank: None,
                                                            speed: 0,
                                                            transferred: 0,
                                                            client_software: String::new(),
                                                            peer_name: String::new(),
                                                            available_parts: None,
                                                            total_parts: None,
                                                            country_code: cc,
                                                            source_origin: Some("ed2k".into()),
                                                        },
                                                    );
                                                }
                                            }
                                        }
                                        for pd in state.pending_downloads.values_mut() {
                                            if pd.file_hash == hash_hex {
                                                pd.last_search_at = 0;
                                                debug!("Marked pending download {} for immediate retry (server sources)", pd.transfer_id);
                                            }
                                        }
                                        let matching_tids: Vec<String> = state.pending_downloads
                                            .iter()
                                            .filter(|(_, pd)| pd.file_hash == hash_hex)
                                            .map(|(tid, _)| tid.clone())
                                            .collect();
                                        for tid in matching_tids {
                                            if !pending_source_start_tids.contains(&tid) {
                                                pending_source_start_tids.push(tid);
                                            }
                                        }
                                    }
                                }
                                ed2k::server::ServerEvent::Message(msg) => {
                                    info!("Server message: {msg}");
                                    emit_server_log(&app_handle, &format!("Server: {msg}"));
                                }
                                ed2k::server::ServerEvent::CallbackRequested { ip, port, crypt_options, user_hash } => {
                                    info!("Server callback requested: peer at {ip}:{port}");
                                    if let Ok(peer_ip) = ip.parse::<std::net::Ipv4Addr>() {
                                        // Same IP-filter gate as the
                                        // UDP `OP_FOUNDSOURCES` path:
                                        // refuse to register a callback
                                        // peer whose announced IP is in
                                        // a special-use range, in our
                                        // ipfilter.dat blocklist, or
                                        // banned at runtime. A
                                        // misbehaving server could
                                        // otherwise sneak banned IPs
                                        // into source_manager and out
                                        // via Source Exchange.
                                        if crate::security::is_special_use_v4(peer_ip)
                                            || peer_ip.is_multicast()
                                            || state.ip_filter.is_blocked(peer_ip)
                                            || state.banned_ips.contains(&peer_ip)
                                        {
                                            debug!("Ignoring server callback for {peer_ip}:{port}: blocked by IP filter / banned / special-use");
                                            continue;
                                        }
                                        let matching_hashes = if let Some(addr) = state.server_addr {
                                            if let std::net::IpAddr::V4(v4) = addr.ip() {
                                                let sm = source_manager.read().await;
                                                sm.find_lowid_files_by_port(
                                                    u32::from_le_bytes(v4.octets()),
                                                    addr.port(),
                                                    port,
                                                    user_hash,
                                                )
                                            } else {
                                                Vec::new()
                                            }
                                        } else {
                                            Vec::new()
                                        };

                                        let (cb_server_ip, cb_server_port) = state.server_addr.and_then(|a| {
                                            match a.ip() {
                                                std::net::IpAddr::V4(v4) => Some((u32::from_le_bytes(v4.octets()), a.port())),
                                                _ => None,
                                            }
                                        }).unwrap_or((0, 0));
                                        let mut sm = source_manager.write().await;
                                        for fh in &matching_hashes {
                                            sm.register_source_full_server(
                                                *fh,
                                                peer_ip,
                                                port,
                                                0,
                                                cb_server_ip,
                                                cb_server_port,
                                                user_hash.unwrap_or([0u8; 16]),
                                                crypt_options.unwrap_or(0),
                                            );
                                        }
                                        drop(sm);
                                        let matching_hex: Vec<String> =
                                            matching_hashes.iter().map(hex::encode).collect();
                                        let mgr = transfer_manager.read().await;
                                        for file_hash in &matching_hashes {
                                            let hash_hex = hex::encode(file_hash);
                                            let matching_transfer_ids =
                                                matching_active_transfer_ids_for_hash(&state, &mgr, &hash_hex);
                                            let download_source = DownloadSource {
                                                peer_ip: ip.clone(),
                                                peer_port: port,
                                                available_parts: Vec::new(),
                                                peer_user_hash: user_hash,
                                                peer_connect_options: crypt_options,
                                            };
                                            let stats = inject_source_into_active_transfers(
                                                &mut state,
                                                *file_hash,
                                                &matching_transfer_ids,
                                                &download_source,
                                                0,
                                            );
                                            if stats.dropped_full > 0 || stats.dropped_closed > 0 {
                                                warn!(
                                                    "Callback source: peer {}:{} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
                                                    ip,
                                                    port,
                                                    hash_hex,
                                                    stats.matched_transfers,
                                                    stats.injected,
                                                    stats.persisted,
                                                    stats.dropped_full,
                                                    stats.overflowed,
                                                    stats.dropped_closed,
                                                );
                                            }
                                        }
                                        for pd in state.pending_downloads.values_mut() {
                                            if matching_hex.iter().any(|h| h == &pd.file_hash) {
                                                pd.last_search_at = 0;
                                            }
                                        }
                                        for hash_hex in &matching_hex {
                                            let matching_tids: Vec<String> = state.pending_downloads
                                                .iter()
                                                .filter(|(_, pd)| &pd.file_hash == hash_hex)
                                                .map(|(tid, _)| tid.clone())
                                                .collect();
                                            for tid in matching_tids {
                                                if !pending_source_start_tids.contains(&tid) {
                                                    pending_source_start_tids.push(tid);
                                                }
                                            }
                                        }
                                        info!(
                                            "Registered callback peer {ip}:{port} as source for {} matching downloads",
                                            matching_hex.len()
                                        );
                                    }
                                }
                                ed2k::server::ServerEvent::CallbackFailed => {
                                    debug!("Server reported callback failure");
                                }
                            }
                        }
                        if server_disconnect_reason.is_none() && state.server_search_more_needed {
                            state.server_search_more_needed = false;
                            let _ = conn.request_more_results().await;
                        }

                        if server_disconnect_reason.is_none() && state.server_connected {
                            state.server_poll_count += 1;
                            if state.server_poll_count >= 30 {
                                state.server_poll_count = 0;
                                if let Err(e) = conn.keep_alive().await {
                                    server_disconnect_reason = Some(e.to_string());
                                } else {
                                    last_server_activity_at = chrono::Utc::now().timestamp();
                                }
                            }
                        }
                        if server_disconnect_reason.is_none() && state.server_connected && !pending_lowid_callbacks.is_empty() && !state.low_id {
                            let mut sent_count = 0u32;
                            for (fh, cid) in &pending_lowid_callbacks {
                                if conn.request_callback(*cid).await.is_ok() {
                                    let mut sm = source_manager.write().await;
                                    sm.mark_callback_sent(fh, *cid);
                                    sent_count += 1;
                                }
                            }
                            if sent_count > 0 {
                                debug!("Sent {sent_count} LowID callback requests from server poll");
                            }
                        }
                        if state.server_connected {
                            conn_to_restore = Some(conn);
                        }
                    }
                    if let Some(reason) = server_disconnect_reason {
                        handle_server_disconnect(
                            &mut state,
                            &shared_server_addr,
                            &app_handle,
                            &reason,
                        ).await;
                    }
                    if state.server_connected {
                        state.server_connection = conn_to_restore;
                    }
                    for request_id in finished_search_requests {
                        maybe_finish_active_search(&mut state, &app_handle, request_id);
                    }
                    for tid in pending_source_start_tids {
                        let _ = try_start_pending_download_from_known_sources(
                            &mut state,
                            &tid,
                            &transfer_manager,
                            &source_manager,
                            &credit_manager,
                            &bandwidth_limiter,
                            &dl_event_tx,
                            &app_handle,
                            &settings,
                            &shared_ember_payload,
                            &ember_payload_generation,
                            &shared_banned_ips,
                            &geoip,
                            &friend_hashes,
                            ember_hash,
                            &stats_manager.sx_counters,
                        ).await;
                    }
                }

                // Timeout pending server search after 30 seconds
                if state.pending_server_search.is_some() {
                    state.server_search_age += 1;
                    if state.server_search_age > 15 {
                        if let Some(mut pending) = state.pending_server_search.take() {
                            let request_id = pending.request_id;
                            info!("Server search timed out, returning {} local results", pending.results.len());
                            if let Some(tx) = pending.tx.take() {
                                let _ = tx.send(pending.results);
                            }
                            if let Some(active) = state.active_search_request.as_mut() {
                                if active.request_id == request_id {
                                    active.server_pending = false;
                                }
                            }
                            maybe_finish_active_search(&mut state, &app_handle, request_id);
                        }
                        state.server_search_age = 0;
                    }
                } else {
                    state.server_search_age = 0;
                }

                if state.server_auto_reconnect
                    && !state.server_connected
                    && state.pending_server_connect.is_none()
                    && !state.server_list.is_empty()
                    && state.server_connection.is_none()
                    && state.stats.status == NetworkStatus::Connected
                {
                    let backoff_secs = match state.server_reconnect_failures {
                        0 => 0,
                        1 => 3,
                        2 => 5,
                        3 => 10,
                        4 => 20,
                        _ => 30,
                    };
                    let elapsed_ok = state.server_last_connect_attempt
                        .map(|t| t.elapsed().as_secs() >= backoff_secs)
                        .unwrap_or(true);
                    if elapsed_ok {
                    if let Some(server) = state.server_list.get_next_server() {
                        let addr_str = format!("{}:{}", server.ip, server.port);
                        let ip = server.ip.clone();
                        let port = server.port;
                        let obf_port = server.obfuscation_port_tcp;
                        let user_hash = state.user_hash;
                        let nickname = settings.nickname.clone();
                        let tcp_port = state.tcp_port;
                        let force_plain = state.server_reconnect_failures >= 3;
                        state.server_last_connect_attempt = Some(std::time::Instant::now());
                        // Pre-set server addr so upload handler can detect HighID port test callbacks
                        if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
                            *shared_server_addr.write().await = Some(SocketAddr::new(ip_addr, port));
                        }
                        info!("Auto-connecting to ed2k server {addr_str} (background, attempt {}, backoff {backoff_secs}s, plain={force_plain})",
                            state.server_reconnect_failures + 1);
                        emit_server_log(&app_handle, &format!("Connecting to {addr_str}..."));
                        state.stats.server_status = "connecting".to_string();
                        let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "connecting" }));
                        let app_for_auto = app_handle.clone();
                        state.pending_server_connect = Some(tokio::spawn(async move {
                            let result = async {
                                const MAX_LOGIN_ATTEMPTS: u32 = 3;
                                let mut last_err = String::new();
                                for attempt in 0..MAX_LOGIN_ATTEMPTS {
                                    if attempt > 0 {
                                        info!("Retrying server {ip}:{port} (attempt {})", attempt + 1);
                                        emit_server_log(&app_for_auto, &format!("Retrying ({})...", attempt + 1));
                                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                    }
                                    let (mut conn, resolved_addr) = match try_connect_server(&ip, port, obf_port, &app_for_auto, force_plain).await {
                                        Ok(r) => r,
                                        Err(e) => { last_err = format!("Connect failed: {e}"); continue; }
                                    };
                                    if attempt == 0 {
                                        emit_server_log(
                                            &app_for_auto,
                                            &format!("Sending login request (client TCP port {tcp_port})..."),
                                        );
                                    }
                                    match conn.login(&user_hash, &nickname, tcp_port).await {
                                        Ok(session) => return Ok((conn, session, resolved_addr)),
                                        Err(login_err) if conn.is_encrypted() => {
                                            warn!("Encrypted login to {ip}:{port} failed: {login_err}, falling back to plain TCP");
                                            emit_server_log(
                                                &app_for_auto,
                                                &format!("Encrypted login failed ({login_err}), trying plain TCP..."),
                                            );
                                            drop(conn);
                                            let plain_addr = tokio::net::lookup_host((ip.as_str(), port))
                                                .await
                                                .map_err(|e| format!("Plain fallback resolve failed: {e}"))?
                                                .find(|addr| addr.is_ipv4())
                                                .ok_or_else(|| format!("No IPv4 address for plain fallback {ip}:{port}"))?;
                                            let mut plain_conn = Ed2kServerConnection::connect(plain_addr)
                                                .await
                                                .map_err(|e| format!("Plain fallback connect failed: {e}"))?;
                                            emit_server_log(
                                                &app_for_auto,
                                                &format!("Sending login over plain TCP (port {tcp_port})..."),
                                            );
                                            match plain_conn.login(&user_hash, &nickname, tcp_port).await {
                                                Ok(session) => return Ok((plain_conn, session, plain_addr)),
                                                Err(e) => { last_err = format!("Plain TCP login failed: {e}"); continue; }
                                            }
                                        }
                                        Err(e) => { last_err = format!("Login failed: {e}"); continue; }
                                    }
                                }
                                Err(last_err)
                            }.await;
                            let addr = result
                                .as_ref()
                                .ok()
                                .map(|(_, _, resolved_addr)| *resolved_addr)
                                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
                            ServerConnectResult {
                                addr,
                                ip,
                                port,
                                result: result.map(|(conn, session, _)| (conn, session)),
                            }
                        }));
                    }
                    } // elapsed_ok
                }
            }

            // Ping the next server in the list via UDP to get user/file counts
            _ = server_udp_ping_timer.tick() => {
                let server_count = state.server_list.len();
                if server_count > 0 {
                    let idx = server_udp_ping_idx % server_count;
                    server_udp_ping_idx = server_udp_ping_idx.wrapping_add(1);
                    let server = state.server_list.servers()[idx].clone();
                    if let Err(e) = server_udp.send_status_ping(&server).await {
                        debug!("Server UDP ping to {}:{} failed: {e}", server.ip, server.port);
                    } else {
                        stats_manager.add_overhead(
                            crate::storage::statistics::OverheadCategory::Server,
                            crate::storage::statistics::OverheadDirection::Upload,
                            32,
                        );
                    }
                }
                while let Some((recv_len, resp)) = {
                    // Snapshot the server list reference so the
                    // closure (called possibly multiple times by
                    // `try_recv_with`) can do per-server lookups
                    // without borrowing `state` mutably across the
                    // await. Returns `(base_key, tcp_port)`: the
                    // first lets us decrypt obfuscated replies, the
                    // second lets `try_recv_with` canonicalise the
                    // emitted `addr` so downstream handlers'
                    // `addr.port() - 4 == tcp_port` math works
                    // regardless of whether the reply came from the
                    // standard UDP port or the server's
                    // `obfuscation_port_udp`.
                    let server_list = &state.server_list;
                    server_udp.try_recv_with(move |ip, port| {
                        server_list.lookup_for_udp_addr(ip, port)
                    }).await
                } {
                    // Attribute the actual wire bytes to the correct
                    // category. Previously every response paid a flat
                    // 64-byte "Server" charge AND `FoundSources`
                    // additionally paid `sources*10` "SourceExchange",
                    // so the same reply was double-counted under two
                    // categories — and the `SourceExchange` estimate
                    // missed the packet header and per-source overhead.
                    let recv_bytes = recv_len as u64;
                    let category = match &resp {
                        ServerUdpResponse::FoundSources { .. } =>
                            crate::storage::statistics::OverheadCategory::SourceExchange,
                        // Status pings and global search results are
                        // server-control traffic, not source-discovery.
                        ServerUdpResponse::StatusResponse { .. }
                        | ServerUdpResponse::SearchResult { .. } =>
                            crate::storage::statistics::OverheadCategory::Server,
                    };
                    stats_manager.add_overhead(
                        category,
                        crate::storage::statistics::OverheadDirection::Download,
                        recv_bytes,
                    );
                    // Reset the per-server UDP-failure counter on
                    // any inbound reply (status, sources, or search).
                    // The address is already canonicalised to the
                    // standard TCP+4 port by `try_recv_with`, so the
                    // server-list lookup uses `addr.port() - 4` for
                    // the matching TCP port.
                    {
                        let resp_addr = match &resp {
                            ServerUdpResponse::StatusResponse { addr, .. }
                            | ServerUdpResponse::FoundSources { addr, .. } => Some(*addr),
                            ServerUdpResponse::SearchResult { .. } => None,
                        };
                        if let Some(a) = resp_addr {
                            let ip_str = a.ip().to_string();
                            let tcp_port = a.port().saturating_sub(4);
                            state.server_list.record_udp_reply(&ip_str, tcp_port);
                        }
                    }
                    match resp {
                        ServerUdpResponse::StatusResponse { addr, challenge, user_count, file_count, obfuscation_port_tcp, obfuscation_port_udp, udp_flags, server_udp_key } => {
                            // eMule: verify challenge to prevent spoofed status responses
                            let expected = server_udp.take_challenge(&addr);
                            if expected != Some(challenge) {
                                debug!("Ignoring UDP status from {addr}: challenge mismatch or unexpected");
                            } else {
                                let tcp_port = addr.port().saturating_sub(4);
                                state.server_list.update_server_stats(
                                    &addr.ip().to_string(), tcp_port, user_count, file_count, obfuscation_port_tcp,
                                );
                                // L11: Store per-server UDP flags for feature gating
                                state.server_list.update_udp_flags(
                                    &addr.ip().to_string(), tcp_port, udp_flags,
                                );
                                // Persist UDP obfuscation crypto material so
                                // subsequent send / recv paths can wrap and
                                // unwrap packets for this server. Both fields
                                // come from the extended status payload —
                                // without storing them, V2 silently sends
                                // plaintext to obfuscation-only servers and
                                // they ignore us.
                                state.server_list.update_udp_obfuscation(
                                    &addr.ip().to_string(), tcp_port,
                                    obfuscation_port_udp, server_udp_key,
                                );
                            }
                        }
                        ServerUdpResponse::FoundSources { addr, files } => {
                            // Bump per-reply diagnostic ONCE per packet, not
                            // per file — `udp_discovery_replies` measures
                            // "server answered our UDP query at all", and
                            // a multi-file reply is still one packet on the
                            // wire. `udp_discovery_sources_found` aggregates
                            // sources across every file in the packet.
                            state.udp_discovery_replies = state.udp_discovery_replies.saturating_add(1);
                            let total_sources_in_packet: u64 = files.iter()
                                .map(|(_, srcs)| srcs.len() as u64)
                                .sum();
                            state.udp_discovery_sources_found = state
                                .udp_discovery_sources_found
                                .saturating_add(total_sources_in_packet);
                            // Distinct from `record_udp_reply` (which
                            // fires above for ANY UDP reply): this
                            // marks the server as actually USEFUL for
                            // source discovery, not just reachable.
                            // Lets the per-server health log
                            // distinguish "alive" from "alive AND has
                            // returned source data".
                            {
                                let ip_str = addr.ip().to_string();
                                let tcp_port = addr.port().saturating_sub(4);
                                state.server_list.record_udp_source_reply(&ip_str, tcp_port);
                            }
                            // Now process each file's source list. eMule's
                            // UDP servers can pack multiple file responses
                            // in one OP_GLOBFOUNDSOURCES datagram, so iterate
                            // every entry the parser returned (the previous
                            // single-entry parser silently dropped every
                            // entry past the first, which dramatically
                            // reduced the source pool whenever we batched
                            // multiple file hashes into one OP_GLOBGETSOURCES2
                            // request — i.e. any session with >1 download).
                          for (file_hash, sources) in files {
                            {
                                let hash_hex_udp = hex::encode(file_hash);
                                let matching: Vec<String> = state.pending_downloads.iter()
                                    .filter(|(_, pd)| pd.file_hash == hash_hex_udp)
                                    .map(|(_, pd)| pd.transfer_id.clone())
                                    .collect();
                                for tid in &matching {
                                    let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                                        "transfer_id": tid,
                                        "kind": if sources.is_empty() { "udp_empty" } else { "udp_found" },
                                        "count": sources.len(),
                                    }));
                                }
                                if sources.is_empty() {
                                    debug!("UDP server {} returned 0 sources for file {}", addr, hash_hex_udp);
                                }
                            }
                            if !sources.is_empty() {
                                let hash_hex = hex::encode(file_hash);
                                info!("UDP server {} found {} sources for {}", addr, sources.len(), hash_hex);
                                // Inbound bytes already counted above against
                                // `OverheadCategory::SourceExchange` using the
                                // actual packet length from `try_recv`.
                                let udp_server_port = addr.port().saturating_sub(4);
                                let udp_server_ip = match addr.ip() {
                                    std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
                                    _ => 0,
                                };
                                {
                                    let mut sm = source_manager.write().await;
                                    for (ip, port, client_id) in &sources {
                                        if *client_id > 0 {
                                            // LowID source — no peer
                                            // IP yet (only known once
                                            // the callback connects
                                            // back). No IP-level filter
                                            // we can apply here, so
                                            // register and let the
                                            // upload listener filter
                                            // when the callback
                                            // actually arrives.
                                            sm.register_lowid_source(
                                                file_hash,
                                                *client_id,
                                                *port,
                                                udp_server_ip,
                                                udp_server_port,
                                                [0u8; 16],
                                                0,
                                            );
                                        } else {
                                            // HighID source — apply
                                            // the same IP filter /
                                            // banned / special-use
                                            // gate as
                                            // `inject_source_into_active_transfers`
                                            // BEFORE registering, so
                                            // banned IPs don't end up
                                            // in the source manager
                                            // (where they would
                                            // pollute SX out and
                                            // future retries).
                                            if crate::security::is_special_use_v4(*ip) || ip.is_multicast() {
                                                continue;
                                            }
                                            if state.ip_filter.is_blocked(*ip) {
                                                continue;
                                            }
                                            if state.banned_ips.contains(ip) {
                                                continue;
                                            }
                                            sm.register_source_full_server(
                                                file_hash, *ip, *port, 0,
                                                udp_server_ip, udp_server_port,
                                                [0u8; 16], 0,
                                            );
                                        }
                                    }
                                }
                                if state.server_connected && !state.low_id {
                                    let needing_callback = {
                                        let sm = source_manager.read().await;
                                        sm.get_lowid_sources_needing_callback(
                                            &file_hash,
                                            udp_server_ip,
                                            udp_server_port,
                                            ed2k::dead_sources::FILEREASKTIME_SECS,
                                        )
                                    };
                                    if !needing_callback.is_empty() {
                                        if let Some(conn) = &mut state.server_connection {
                                            let current_server_matches = state.server_addr.map(|server_addr| {
                                                server_addr.ip() == addr.ip() && server_addr.port() == udp_server_port
                                            }).unwrap_or(false);
                                            if current_server_matches {
                                                let mut sm = source_manager.write().await;
                                                for cid in &needing_callback {
                                                    if conn.request_callback(*cid).await.is_ok() {
                                                        sm.mark_callback_sent(&file_hash, *cid);
                                                    }
                                                }
                                                debug!("Sent {} LowID callback requests from UDP sources", needing_callback.len());
                                            }
                                        }
                                    }
                                }
                                // Inject HighID sources into active downloads
                                let matching_transfer_ids = {
                                    let mgr = transfer_manager.read().await;
                                    matching_active_transfer_ids_for_hash(&state, &mgr, &hash_hex)
                                };
                                for (ip, port, client_id) in &sources {
                                    if *client_id == 0 && !ip.is_unspecified() {
                                        if state.dead_sources.is_dead_source_for_file(&file_hash, u32::from(*ip), *port) {
                                            continue;
                                        }
                                        let uh = {
                                            let sm = source_manager.read().await;
                                            sm.get_user_hash(&file_hash, *ip, *port)
                                        };
                                        let co = {
                                            let sm = source_manager.read().await;
                                            sm.get_connect_options(&file_hash, *ip, *port)
                                        };
                                        let download_source = DownloadSource {
                                            peer_ip: ip.to_string(),
                                            peer_port: *port,
                                            available_parts: Vec::new(),
                                            peer_user_hash: uh,
                                            peer_connect_options: co,
                                        };
                                        let stats = inject_source_into_active_transfers(
                                            &mut state,
                                            file_hash,
                                            &matching_transfer_ids,
                                            &download_source,
                                            0,
                                        );
                                        if stats.dropped_full > 0 || stats.dropped_closed > 0 {
                                            warn!(
                                                "UDP sources: source {}:{} for {} matched {} active downloads, injected={}, preserved={}, full={}, overflowed={}, closed={}",
                                                ip,
                                                port,
                                                hash_hex,
                                                stats.matched_transfers,
                                                stats.injected,
                                                stats.persisted,
                                                stats.dropped_full,
                                                stats.overflowed,
                                                stats.dropped_closed,
                                            );
                                        }
                                    }
                                }
                                // Register source details so the frontend shows ed2k origin icons
                                {
                                    let matching_transfer_ids = {
                                        let mgr = transfer_manager.read().await;
                                        matching_active_transfer_ids_for_hash(&state, &mgr, &hash_hex)
                                    };
                                    if !matching_transfer_ids.is_empty() {
                                        let mut mgr = transfer_manager.write().await;
                                        for (ip, port, client_id) in &sources {
                                            if *client_id == 0 && !ip.is_unspecified() {
                                                let cc = crate::geoip::lookup_country(&geoip, std::net::IpAddr::V4(*ip));
                                                for tid in &matching_transfer_ids {
                                                    mgr.update_source_detail(
                                                        tid,
                                                        crate::types::SourceInfo {
                                                            ip: ip.to_string(),
                                                            port: *port,
                                                            status: crate::types::SourceStatus::Connecting,
                                                            queue_rank: None,
                                                            speed: 0,
                                                            transferred: 0,
                                                            client_software: String::new(),
                                                            peer_name: String::new(),
                                                            available_parts: None,
                                                            total_parts: None,
                                                            country_code: cc.clone(),
                                                            source_origin: Some("ed2k".into()),
                                                        },
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                                for pd in state.pending_downloads.values_mut() {
                                    if pd.file_hash == hash_hex {
                                        pd.last_search_at = 0;
                                        debug!("Marked pending download {} for immediate retry (UDP sources)", pd.transfer_id);
                                    }
                                }
                                let matching_tids: Vec<String> = state.pending_downloads
                                    .iter()
                                    .filter(|(_, pd)| pd.file_hash == hash_hex)
                                    .map(|(tid, _)| tid.clone())
                                    .collect();
                                for tid in matching_tids {
                                    let _ = try_start_pending_download_from_known_sources(
                                        &mut state,
                                        &tid,
                                        &transfer_manager,
                                        &source_manager,
                                        &credit_manager,
                                        &bandwidth_limiter,
                                        &dl_event_tx,
                                        &app_handle,
                                        &settings,
                                        &shared_ember_payload,
                                        &ember_payload_generation,
                                        &shared_banned_ips,
                                        &geoip,
                                        &friend_hashes,
                                        ember_hash,
                                        &stats_manager.sx_counters,
                                    ).await;
                                }
                            }
                          } // end `for (file_hash, sources) in files`
                        }
                        ServerUdpResponse::SearchResult { results } => {
                            if !results.is_empty() {
                                debug!("UDP search returned {} results", results.len());
                                let search_results: Vec<SearchResult> = results.iter().map(|sr| {
                                    let hash_hex = hex::encode(sr.file_hash);
                                    let extension = sr.file_name
                                        .rsplit_once('.')
                                        .map(|(_, ext)| ext.to_string())
                                        .unwrap_or_default();
                                    let source_addresses = if sr.client_id >= ed2k::server::LOWID_THRESHOLD {
                                        let ip = Ipv4Addr::from(sr.client_id.to_le_bytes());
                                        if is_search_source_safe(&state, ip) {
                                            vec![format!("{}:{}", ip, sr.client_port)]
                                        } else {
                                            Vec::new()
                                        }
                                    } else {
                                        Vec::new()
                                    };
                                    SearchResult {
                                        file: FileInfo {
                                            id: hash_hex.clone(),
                                            name: sr.file_name.clone(),
                                            path: String::new(),
                                            size: sr.file_size,
                                            hash: hash_hex,
                                            aich_hash: String::new(),
                                            extension: extension.clone(),
                                            modified_at: 0,
                                            priority: "normal".to_string(),
                                            requests: 0,
                                            accepted: 0,
                                            bytes_transferred: 0,
                                            alltime_requests: 0,
                                            alltime_accepted: 0,
                                            alltime_transferred: 0,
                                            complete_sources: 0,
                                            folder: String::new(),
                                            shared: false,
                                            shared_kad: false,
                                            shared_ed2k: false,
                                        },
                                        peer_id: format!("{}:{}", sr.client_id, sr.client_port),
                                        peer_name: String::new(),
                                        availability: 1,
                                        file_type: crate::search::index::infer_file_type(&extension),
                                        source_addresses,
                                        rating: None,
                                        comment: None,
                                        spam_rating: 0,
                                        is_spam: false,
                                        clean_name: String::new(),
                                        result_origin: crate::search::merge::ORIGIN_SERVER_UDP.to_string(),
                                    }
                                }).collect();
                                if let Some(active) = state.active_search_request.as_ref() {
                                    state.server_udp_search_age = 0;
                                    let request_id = active.request_id;
                                    let ft_filter = active.file_type_filter.clone();
                                    let kws = active.keywords.clone();
                                    enrich_and_emit_search_results(
                                        &app_handle,
                                        &spam_filter,
                                        &settings,
                                        request_id,
                                        search_results,
                                        &ft_filter,
                                        &kws,
                                        None,
                                    ).await;
                                }
                            }
                        }
                    }
                }
            }

            // Poll background server connection (non-blocking)
            result = async {
                match state.pending_server_connect.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                state.pending_server_connect = None;
                match result {
                    Ok(ServerConnectResult { addr, ip, port, result: Ok((mut conn, session)) }) => {
                        // Check server IP against IP filter (eMule: FilterServerByIP)
                        if settings.filter_servers_by_ip {
                            let server_ipv4 = match addr.ip() {
                                std::net::IpAddr::V4(v4) => Some(v4),
                                std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                            };
                            if let Some(ipv4) = server_ipv4 {
                                if state.ip_filter.is_blocked(ipv4) {
                                    warn!("Server {ip}:{port} blocked by IP filter, disconnecting");
                                    emit_server_log(&app_handle, &format!("Server {ip}:{port} blocked by IP filter"));
                                    conn.disconnect().await;
                                    state.server_list.record_failure(&ip, port);
                                    let met_path = state.data_dir.join("server.met");
                                    let _ = state.server_list.save_server_met(&met_path);
                                    *shared_server_addr.write().await = None;
                                    state.server_reconnect_failures = state.server_reconnect_failures.saturating_add(1);
                                    state.stats.server_status = "disconnected".to_string();
                                    let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
                                    continue;
                                }
                            }
                        }

                        for motd in &session.motd_messages {
                            emit_server_log(&app_handle, &format!("Server: {motd}"));
                        }

                        let is_low = conn.is_low_id();
                        let our_id = conn.our_client_id().unwrap_or(0);
                        let id_type = if is_low { "LowID" } else { "HighID" };
                        info!("Connected to ed2k server: {} ({} users, {} files, {} id={})",
                            session.server_name, session.user_count, session.file_count,
                            id_type, our_id);
                        emit_server_log(&app_handle, &format!(
                            "Connected to {} ({} users, {} files, {})",
                            if session.server_name.is_empty() { &ip } else { &session.server_name },
                            session.user_count, session.file_count, id_type,
                        ));
                        state.low_id = is_low;
                        state.server_client_id = session.client_id;
                        state.server_list.record_success(&ip, port);
                        state.server_connected = true;
                        state.server_reconnect_failures = 0;
                        last_server_activity_at = chrono::Utc::now().timestamp();
                        state.server_addr = Some(addr);
                        *shared_server_addr.write().await = Some(addr);

                        // HighID from server is the most reliable TCP firewall test:
                        // the server successfully connected back to our TCP port.
                        if !is_low && our_id >= ed2k::server::LOWID_THRESHOLD {
                            if state.firewalled {
                                info!("HighID from server confirms TCP port is open, clearing firewalled status");
                                state.firewalled = false;
                                state.firewalled_shared.store(false, std::sync::atomic::Ordering::Relaxed);
                                state.firewall_checker.handle_tcp_connect_back();
                                update_publish_manager_state(&mut state);
                                if state.buddy_manager.state() == BuddyState::FindingBuddy {
                                    state.buddy_manager.find_failed();
                                    info!("Cancelled buddy search: HighID proves TCP is open");
                                }
                            }
                            state.stats.firewalled = state.firewalled;
                            state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
                            state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
                            let _ = app_handle.emit("firewall-status", serde_json::json!({
                                "firewalled": state.firewalled,
                                "external_ip": state.stats.external_ip,
                                "tcp_status": state.stats.tcp_status,
                                "udp_status": state.stats.udp_status,
                            }));
                            // HighID = our external IP (ed2k stores IPs as LE u32)
                            let ip_bytes = our_id.to_le_bytes();
                            let ext_ip = Ipv4Addr::from(ip_bytes);
                            info!("Server HighID reports our IP as {}", ext_ip);
                            if !ext_ip.is_unspecified() && !ext_ip.is_loopback() {
                                let was_none = state.external_ip.is_none();
                                if was_none {
                                    set_external_ip(&mut state, Some(ext_ip));
                                    state.stats.external_ip = ext_ip.to_string();
                                    info!("External IP set from server HighID: {}", ext_ip);
                                } else if state.external_ip == Some(ext_ip) {
                                    set_external_ip(&mut state, Some(ext_ip));
                                    state.stats.external_ip = ext_ip.to_string();
                                } else {
                                    info!("Server HighID IP {} differs from current external IP {:?} — not overwriting", ext_ip, state.external_ip);
                                }
                                // Server HighID is a single trusted report; route it
                                // through the dedicated 1-arg path rather than the
                                // KAD-peer-vote path (which requires a reporter IP
                                // for distinct-/24 sybil protection).
                                state.firewall_checker.handle_server_highid_response(ext_ip);
                                if was_none && state.nat_info.nat_type == ember::nat::NatType::Unknown {
                                    info!("External IP discovered via server HighID — running initial NAT probe");
                                    state.nat_info = ember::nat::probe_nat(&udp_socket).await;
                                    // STUN can fail (firewall, DNS, blocked egress)
                                    // even when the host is perfectly punchable.
                                    // HighID + a successful TCP connect-back is
                                    // strong evidence we sit behind a cone NAT (or
                                    // none), so promote `Unknown` to
                                    // `PortRestricted` rather than disabling
                                    // hole-punch outright.
                                    if state.nat_info.apply_highid_fallback(
                                        std::net::IpAddr::V4(ext_ip),
                                        state.udp_port,
                                    ) {
                                        info!(
                                            "NAT probe failed but HighID confirmed external IP {} — assuming PortRestricted (mapped {}:{})",
                                            ext_ip, ext_ip, state.udp_port,
                                        );
                                    }
                                }
                            }
                        }

                        // eMule: "Update server list when connecting" —
                        // process OP_SERVERLIST payload received during login handshake.
                        // Some servers push it unsolicited (handled here); most modern
                        // servers wait for an explicit OP_GETSERVERLIST request from
                        // the client (sent below). Either way the response opcode is
                        // the same OP_SERVERLIST and arrives via the regular
                        // `ServerEvent::ServerList` branch in the read loop.
                        if settings.add_servers_from_server {
                            if let Some(ref list_data) = session.server_list_data {
                                let added = state.server_list.add_from_server_list_packet(
                                    list_data,
                                    settings.filter_servers_by_ip,
                                    &mut state.ip_filter,
                                );
                                if added > 0 {
                                    emit_server_log(&app_handle, &format!("Added {added} servers from connected server"));
                                    let met_path = state.data_dir.join("server.met");
                                    if let Err(e) = state.server_list.save_server_met(&met_path) {
                                        warn!("Failed to save server.met after login server list: {e}");
                                    }
                                }
                            }
                            // Explicitly request the server list. eMule's "Update
                            // server list when connecting" sends OP_GETSERVERLIST
                            // shortly after login because most public ed2k servers
                            // don't push the list unsolicited — they wait for the
                            // client to ask. Without this our `add_servers_from_server`
                            // setting was effectively dead for the common case.
                            if let Err(e) = conn.request_server_list().await {
                                warn!("Failed to send OP_GETSERVERLIST: {e}");
                            }
                        }

                        // eMule: send OP_OFFERFILES after login to announce shared files.
                        // Include incomplete .part downloads as partial offers (0xFCFC on newer servers).
                        {
                            let mut seen_offer_hashes = std::collections::HashSet::new();
                            let mut offer_files: Vec<ed2k::server::OfferFile> = {
                                let index = local_index.read().await;
                                index
                                    .all_files()
                                    .iter()
                                    .filter(|f| f.shared)
                                    .filter_map(|f| {
                                        let hash_bytes = hex::decode(&f.hash).ok()?;
                                        if hash_bytes.len() < 16 {
                                            return None;
                                        }
                                        if !seen_offer_hashes.insert(f.hash.clone()) {
                                            return None;
                                        }
                                        let mut h = [0u8; 16];
                                        h.copy_from_slice(&hash_bytes[..16]);
                                        Some(ed2k::server::OfferFile {
                                            hash: h,
                                            name: f.name.clone(),
                                            size: f.size,
                                            is_complete: true,
                                            file_type: String::new(),
                                        })
                                    })
                                    .collect()
                            };

                            let temp_dir = PathBuf::from(&settings.download_folder).join("Temp");
                            {
                                let mgr = transfer_manager.read().await;
                                for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                                    if transfer.direction != TransferDirection::Download {
                                        continue;
                                    }
                                    if matches!(transfer.status, TransferStatus::Completed | TransferStatus::Failed) {
                                        continue;
                                    }
                                    if transfer.file_hash.is_empty() || !seen_offer_hashes.insert(transfer.file_hash.clone()) {
                                        continue;
                                    }
                                    let hash_bytes = match hex::decode(&transfer.file_hash) {
                                        Ok(bytes) if bytes.len() >= 16 => bytes,
                                        _ => continue,
                                    };
                                    let part_path = temp_dir.join(format!("{}.part", transfer.id));
                                    if !part_path.exists() {
                                        continue;
                                    }
                                    let mut h = [0u8; 16];
                                    h.copy_from_slice(&hash_bytes[..16]);
                                    offer_files.push(ed2k::server::OfferFile {
                                        hash: h,
                                        name: transfer.file_name.clone(),
                                        size: transfer.total_size,
                                        is_complete: false,
                                        file_type: String::new(),
                                    });
                                }
                            }

                            let complete_count = offer_files.iter().filter(|f| f.is_complete).count();
                            let partial_count = offer_files.len() - complete_count;
                            if !offer_files.is_empty() {
                                info!("Offering {} files to server ({} complete, {} partial)", offer_files.len(), complete_count, partial_count);
                                if let Err(e) = conn.offer_files(&offer_files, settings.tcp_port).await {
                                    warn!("Failed to send OP_OFFERFILES: {e}");
                                }
                            } else {
                                warn!("No files to offer to server after login — check shared folders");
                            }
                        }

                        // eMule: request sources for incomplete downloads after server login.
                        // Send a small initial batch immediately (up to 5), then let the
                        // periodic TCP source timer drain the rest. Sending all at once
                        // triggers server flood protection.
                        {
                            let mut all_hashes: Vec<([u8; 16], u64)> = Vec::new();
                            for pd in state.pending_downloads.values() {
                                if pd.control.is_cancelled() || pd.control.is_paused() { continue; }
                                if let Ok(hash_bytes) = hex::decode(&pd.file_hash) {
                                    if hash_bytes.len() == 16 {
                                        let mut fh = [0u8; 16];
                                        fh.copy_from_slice(&hash_bytes);
                                        all_hashes.push((fh, pd.file_size));
                                    }
                                }
                            }
                            {
                                let mgr = transfer_manager.read().await;
                                let seen: std::collections::HashSet<[u8; 16]> =
                                    all_hashes.iter().map(|(fh, _)| *fh).collect();
                                for tid in state.active_source_senders.keys() {
                                    if let Some(transfer) = mgr.get_transfer(tid) {
                                        if let Ok(raw) = hex::decode(&transfer.file_hash) {
                                            if raw.len() == 16 {
                                                let mut fh = [0u8; 16];
                                                fh.copy_from_slice(&raw[..16]);
                                                if !seen.contains(&fh) {
                                                    all_hashes.push((fh, transfer.total_size));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            let total = all_hashes.len();
                            const LOGIN_BATCH_LIMIT: usize = 5;
                            let immediate = total.min(LOGIN_BATCH_LIMIT);
                            let mut sent = 0u32;
                            for (fh, file_size) in all_hashes.iter().take(immediate) {
                                if let Ok(bytes) = conn.send_get_sources(fh, *file_size).await {
                                    if bytes > 0 {
                                        sent += 1;
                                        // TCP source request to the connected
                                        // server is source-discovery overhead.
                                        stats_manager.add_overhead(
                                            crate::storage::statistics::OverheadCategory::SourceExchange,
                                            crate::storage::statistics::OverheadDirection::Upload,
                                            bytes,
                                        );
                                    }
                                }
                            }
                            let deferred = total - immediate;
                            if deferred > 0 {
                                state.server_tcp_getsources_cursor = 0;
                                info!("Sent OP_GETSOURCES for {sent}/{total} downloads on login ({deferred} deferred to periodic batch)");
                            } else if total > 0 {
                                info!("Sent OP_GETSOURCES to server for {sent}/{total} downloads");
                            }
                        }

                        state.server_connection = Some(conn);
                        state.stats.server_status = "connected".to_string();
                        let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "connected" }));

                        // L-2: flush LowID callback requests for any
                        // sources we previously learned about via UDP
                        // from this server. Without this, UDP-discovered
                        // LowID sources from a server we *weren't* TCP-
                        // connected to at discovery time would sit in
                        // source manager unreachable forever — eMule
                        // protocol requires the callback to go through
                        // the source's originating server.
                        if !is_low {
                            let server_ip_u32 = match addr.ip() {
                                std::net::IpAddr::V4(v4) => u32::from_le_bytes(v4.octets()),
                                _ => 0,
                            };
                            let server_port_u16 = addr.port();
                            if server_ip_u32 != 0 {
                                let pending: Vec<([u8; 16], u32)> = {
                                    let sm = source_manager.read().await;
                                    sm.get_lowid_sources_for_server(
                                        server_ip_u32,
                                        server_port_u16,
                                        ed2k::dead_sources::FILEREASKTIME_SECS,
                                    )
                                };
                                if !pending.is_empty() {
                                    if let Some(conn) = &mut state.server_connection {
                                        // Send callbacks WITHOUT
                                        // holding the source_manager
                                        // write lock — each
                                        // `request_callback` is an
                                        // async TCP write (potentially
                                        // tens of ms when slow), and
                                        // holding `source_manager`
                                        // exclusively blocks every
                                        // other task that needs to
                                        // register / look up a source
                                        // (KAD source-search results,
                                        // EPX source-receive, server
                                        // OP_FOUNDSOURCES handler,
                                        // upload listener IP-banlist
                                        // queries). Collect successes,
                                        // then re-acquire the lock
                                        // briefly to batch-mark.
                                        let mut succeeded: Vec<([u8; 16], u32)> =
                                            Vec::with_capacity(pending.len());
                                        for (file_hash, client_id) in &pending {
                                            if conn.request_callback(*client_id).await.is_ok() {
                                                succeeded.push((*file_hash, *client_id));
                                            }
                                        }
                                        let sent = succeeded.len();
                                        if sent > 0 {
                                            let mut sm = source_manager.write().await;
                                            for (file_hash, client_id) in &succeeded {
                                                sm.mark_callback_sent(file_hash, *client_id);
                                            }
                                        }
                                        if sent > 0 {
                                            info!(
                                                "L-2 flush: requested {sent}/{} LowID callbacks via newly-connected server {}:{}",
                                                pending.len(), addr.ip(), server_port_u16,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(ServerConnectResult { ip, port, result: Err(e), .. }) => {
                        warn!("Failed to connect to server {ip}:{port}: {e}");
                        emit_server_log(&app_handle, &format!("Connection failed: {e}"));
                        state.server_reconnect_failures = state.server_reconnect_failures.saturating_add(1);
                        *shared_server_addr.write().await = None;
                        state.server_list.record_failure(&ip, port);
                        let met_path = state.data_dir.join("server.met");
                        let _ = state.server_list.save_server_met(&met_path);
                        state.stats.server_status = "disconnected".to_string();
                        let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
                    }
                    Err(e) => {
                        warn!("Server connection task panicked: {e}");
                        emit_server_log(&app_handle, &format!("Connection error: {e}"));
                        state.server_reconnect_failures = state.server_reconnect_failures.saturating_add(1);
                        *shared_server_addr.write().await = None;
                        state.stats.server_status = "disconnected".to_string();
                        let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
                    }
                }
            }

            // Poll buddy events (we are firewalled, buddy relays to us)
            event = async {
                match state.buddy_event_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    Some(BuddyEvent::PingReceived) => {
                        state.buddy_manager.send_pong_to_buddy().await;
                    }
                    Some(BuddyEvent::PongReceived) => {
                        debug!("Buddy pong received");
                    }
                    Some(BuddyEvent::Callback { file_hash, dest_ip, dest_port }) => {
                        info!("Buddy callback: connect to {dest_ip}:{dest_port} for file {}", hex::encode(file_hash));

                        let matching_tid = state.pending_downloads.iter()
                            .find(|(_, pd)| {
                                hex::decode(&pd.file_hash).ok()
                                    .filter(|b| b.len() == 16 && b[..] == file_hash[..])
                                    .is_some()
                            })
                            .map(|(tid, _)| tid.clone());

                        if let Some(tid) = matching_tid {
                            if let Some(pd) = state.pending_downloads.remove(&tid) {
                                let source_addr = SocketAddr::new(dest_ip.into(), dest_port);
                                info!("Starting callback download {} to {source_addr}", pd.transfer_id);

                                {
                                    let mut sm = source_manager.write().await;
                                    sm.register_source(file_hash, dest_ip, dest_port);
                                }
                                {
                                    let pfs = state
                                        .per_file_sources
                                        .entry(pd.transfer_id.clone())
                                        .or_insert_with(|| ed2k::sources::PerFileSourceList::new(file_hash));
                                    if pfs.add_source_full(dest_ip, dest_port, 0) {
                                        state.ember_payload_dirty = true;
                                    }
                                }
                                {
                                    let mut mgr = transfer_manager.write().await;
                                    mgr.update_status(&tid, TransferStatus::Active);
                                    mgr.update_sources(&tid, 1, 0, 0);
                                }
                                let _ = app_handle.emit("transfer-status", serde_json::json!({
                                    "id": tid,
                                    "status": "active",
                                    "sources": 1,
                                    "active_sources": 0,
                                    "queued_sources": 0,
                                }));

                                let uh = {
                                    let sm = source_manager.read().await;
                                    sm.get_user_hash(&file_hash, dest_ip, dest_port)
                                };
                                let co = {
                                    let sm = source_manager.read().await;
                                    sm.get_connect_options(&file_hash, dest_ip, dest_port)
                                };
                                let download_sources = vec![DownloadSource {
                                    peer_ip: dest_ip.to_string(),
                                    peer_port: dest_port,
                                    available_parts: Vec::new(),
                                    peer_user_hash: uh,
                                    peer_connect_options: co,
                                }];

                                let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
                                let (est_inject_tx, est_inject_rx) =
                                    mpsc::channel::<ed2k::multi_source::EstablishedSource>(8);
                                let ms_download = MultiSourceDownload {
                                    transfer_id: pd.transfer_id.clone(),
                                    file_hash,
                                    file_name: pd.file_name,
                                    file_size: pd.file_size,
                                    sources: download_sources,
                                    download_dir: PathBuf::from(&settings.download_folder),
                                    user_hash: state.user_hash,
                                    nickname: settings.nickname.clone(),
                                    tcp_port: settings.tcp_port,
                                    udp_port: settings.udp_port,
                                    bandwidth_limiter: bandwidth_limiter.clone(),
                                    control: pd.control,
                                    source_manager: Some(source_manager.clone()),
                                    comment_manager: Some(state.comment_manager.clone()),
                                    credit_manager: Some(credit_manager.clone()),
                                    shared_buddy_info: Some(state.shared_buddy_info.clone()),
                                    obfuscation_enabled: state.obfuscation_enabled,
                                    server_addr: state.server_addr,
                                    new_source_rx: Some(src_inject_rx),
                                    new_established_rx: Some(est_inject_rx),
                        ed2k_limits: settings.ed2k_download_limits(),
                        ember_hash,
                        friend_hashes: Some(friend_hashes.clone()),
                                    ember_payload: shared_ember_payload.clone(),
                                    ember_payload_generation: ember_payload_generation.clone(),
                                    ip_filter: Some(state.shared_ip_filter.clone()),
                                    banned_ips: Some(shared_banned_ips.clone()),
                                    external_ip: state.external_ip,
                                    aich_pending: Some(state.aich_recovery_pending.clone()),
                                    geoip: geoip.clone(),
                                    tracker_registry: Some(state.tracker_registry.clone()),
                                    sx_overhead: stats_manager.sx_counters.clone(),
                                };
                                let dl_tid = ms_download.transfer_id.clone();
                                state.active_source_senders.insert(dl_tid.clone(), src_inject_tx);
                                state.active_established_senders.insert(dl_tid.clone(), est_inject_tx);
                                let tx = dl_event_tx.clone();
                                let tx2 = tx.clone();
                                if let Some(old_handle) = state.download_handles.remove(&dl_tid) {
                                    warn!("Aborting existing download task for {dl_tid} before starting callback multi-source download");
                                    old_handle.abort();
                                }
                                let dl_tid2 = dl_tid.clone();
                                let handle = tokio::spawn(async move {
                                    if let Err(e) = ms_download.run(tx).await {
                                        warn!("Callback download failed: {e}");
                                        let kind = classify_error(&e.to_string());
                                        let _ = tx2.send(DownloadEvent::Failed { transfer_id: dl_tid, error: e.to_string(), failure_kind: kind }).await;
                                    }
                                });
                                state.download_handles.insert(dl_tid2, handle);
                            }
                        } else {
                            debug!("No pending download for callback file hash {}", hex::encode(file_hash));
                        }
                    }
                    Some(BuddyEvent::ReaskCallback { dest_ip, dest_port, file_hash }) => {
                        let hash_hex = hex::encode(file_hash);
                        let file_size = match state.pending_downloads.values()
                            .find(|pd| pd.file_hash == hash_hex)
                            .map(|pd| pd.file_size)
                        {
                            Some(fs) => fs,
                            None => {
                                let mgr = transfer_manager.read().await;
                                mgr.active.values().chain(mgr.queue.iter())
                                    .find(|t| t.file_hash == hash_hex)
                                    .map(|t| t.total_size)
                                    .unwrap_or(0)
                            }
                        };
                        let complete_sources = state.per_file_sources.values()
                            .find(|pfs| pfs.file_hash == file_hash)
                            .map(|pfs| pfs.complete_source_count())
                            .unwrap_or(0);
                        let addr = SocketAddr::new(dest_ip.into(), dest_port);
                        let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
                        pkt.extend_from_slice(&ed2k::messages::build_reask_file_ping(
                            &file_hash, file_size, complete_sources, None,
                        ));
                        let _ = udp_socket.send_to(&pkt, addr).await;
                        debug!("Sent UDP reask to {}:{} via buddy relay for file {}", dest_ip, dest_port, hash_hex);
                    }
                    Some(BuddyEvent::Disconnected) | None => {
                        if state.buddy_manager.state() == BuddyState::Connected {
                            state.buddy_manager.disconnect_buddy();
                            state.buddy_event_rx = None;
                            *state.shared_buddy_info.write().await = None;
                        }
                    }
                }
            }

            // Poll serving buddy events (we are the non-firewalled buddy)
            event = async {
                match state.serving_event_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match event {
                    Some(BuddyEvent::PingReceived) => {
                        state.buddy_manager.send_pong_to_serving().await;
                    }
                    Some(BuddyEvent::PongReceived) => {
                        debug!("Serving buddy pong received");
                    }
                    Some(BuddyEvent::Callback { .. }) | Some(BuddyEvent::ReaskCallback { .. }) => {
                        debug!("Unexpected callback on serving side");
                    }
                    Some(BuddyEvent::Disconnected) | None => {
                        if state.buddy_manager.is_serving() {
                            state.buddy_manager.disconnect_serving();
                            state.serving_event_rx = None;
                        }
                    }
                }
            }

            // Poll outgoing buddy connect (spawned from FindBuddyRes)
            result = async {
                match state.pending_outgoing_buddy.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                state.pending_outgoing_buddy = None;
                match result {
                    Ok(Some((buddy_id, buddy_ip, buddy_port, rx, writer, reader_handle))) => {
                        state.buddy_event_rx = Some(rx);
                        state.buddy_manager.install_buddy_connection(
                            buddy_id, buddy_ip, buddy_port,
                            writer, reader_handle,
                        );
                        *state.shared_buddy_info.write().await = Some(ed2k::messages::BuddyInfo {
                            buddy_ip: u32::from(buddy_ip),
                            buddy_port,
                        });
                        info!("Buddy connected: {} at {}:{}", buddy_id, buddy_ip, buddy_port);
                        let findbuddy_sids: Vec<_> = state.search_manager.active.iter()
                            .filter(|(_, s)| matches!(s.search_type, SearchType::FindBuddy))
                            .map(|(sid, _)| *sid)
                            .collect();
                        for sid in findbuddy_sids {
                            if let Some(removed) = state.search_manager.remove(&sid) {
                                state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                            }
                        }
                    }
                    Ok(None) => {
                        if state.buddy_manager.state() == BuddyState::FindingBuddy {
                            state.buddy_manager.find_failed();
                        }
                    }
                    Err(e) => {
                        debug!("Buddy connect task panicked: {e}");
                        if state.buddy_manager.state() == BuddyState::FindingBuddy {
                            state.buddy_manager.find_failed();
                        }
                    }
                }
            }

            // Accept incoming buddy connections forwarded from the upload listener
            buddy_conn = buddy_conn_rx.recv() => {
                if let Some((peer_hash, callback_check, reader, writer)) = buddy_conn {
                    let peer_id = KadId(peer_hash);
                    if let Some(rx) = state.buddy_manager.accept_buddy_connection(peer_id, callback_check, reader, writer) {
                        state.serving_event_rx = Some(rx);
                        info!("Accepted incoming buddy connection from {}", peer_id);
                    }
                }
            }

            // Handle callback connections: firewalled source connected back to us
            // (KAD buddy relay or server LowID callback via OP_CALLBACKREQUEST)
            cb_conn = kad_callback_rx.recv() => {
                if let Some(parts) = cb_conn {
                    let hash_hex = hex::encode(parts.file_hash);
                    let matching_tid = state.pending_downloads.iter()
                        .find(|(_, pd)| pd.file_hash == hash_hex)
                        .map(|(tid, _)| tid.clone());

                    if let Some(tid) = matching_tid {
                        if let Some(pd) = state.pending_downloads.remove(&tid) {
                            let source_addr = SocketAddr::new(parts.peer_ip.into(), parts.peer_port);
                            state.callback_buddy_attempts.retain(|&(_, fh), _| fh != parts.file_hash);
                            info!("Starting callback download {tid} from {source_addr}");
                            let download = Ed2kDownload {
                                transfer_id: pd.transfer_id.clone(),
                                file_hash: parts.file_hash,
                                file_name: pd.file_name,
                                file_size: pd.file_size,
                                source_addr,
                                download_dir: PathBuf::from(&settings.download_folder),
                                tcp_port: settings.tcp_port,
                                udp_port: settings.udp_port,
                                bandwidth_limiter: bandwidth_limiter.clone(),
                                control: pd.control,
                                source_manager: Some(source_manager.clone()),
                                comment_manager: Some(state.comment_manager.clone()),
                                credit_manager: Some(credit_manager.clone()),
                                obfuscation_enabled: state.obfuscation_enabled,
                        ed2k_limits: settings.ed2k_download_limits(),
                        ember_hash,
                        our_nickname: settings.nickname.clone(),
                        friend_hashes: Some(friend_hashes.clone()),
                                ember_payload: shared_ember_payload.clone(),
                                ember_payload_generation: ember_payload_generation.clone(),
                                ip_filter: Some(state.shared_ip_filter.clone()),
                                banned_ips: Some(shared_banned_ips.clone()),
                                external_ip: state.external_ip,
                                aich_pending: Some(state.aich_recovery_pending.clone()),
                                geoip: geoip.clone(),
                                sx_overhead: stats_manager.sx_counters.clone(),
                            };
                            {
                                let mut mgr = transfer_manager.write().await;
                                mgr.update_status(&tid, TransferStatus::Active);
                            }
                            let _ = app_handle.emit("transfer-status", serde_json::json!({
                                "id": tid,
                                "status": "active",
                                "peer_id": source_addr.to_string(),
                            }));
                            let tx = dl_event_tx.clone();
                            let tid2 = tid.clone();
                            let tid3 = tid.clone();
                            let tx2 = tx.clone();
                            if let Some(old_handle) = state.download_handles.remove(&tid3) {
                                old_handle.abort();
                            }
                            let handle = tokio::spawn(async move {
                                if let Err(e) = download.run_from_callback(
                                    parts.reader, parts.writer, parts.peer_user_hash,
                                    parts.emule_info_done, tx,
                                ).await {
                                    warn!("Callback download failed: {e}");
                                    let kind = classify_error(&e.to_string());
                                    let _ = tx2.send(DownloadEvent::Failed { transfer_id: tid2, error: e.to_string(), failure_kind: kind }).await;
                                }
                            });
                            state.download_handles.insert(tid3, handle);
                        }
                    } else {
                        // Download already active — the LowID peer
                        // connected *back* to us (server-relay or KAD
                        // callback). Hand the live, post-handshake
                        // stream to the running multi-source worker
                        // so it adopts the connection rather than
                        // dialing the LowID peer's NAT'd address —
                        // which can't accept inbound TCP and would
                        // always fail at `stage:hello_wait: forcibly
                        // closed`. Falls back to the legacy metadata
                        // injection only if the established channel
                        // can't accept the stream (no matching active
                        // download, channel full, channel closed),
                        // mirroring the pre-fix behaviour as a
                        // last resort.

                        // Extract Copy / clonable fields up front so
                        // we can keep them after the stream itself is
                        // moved into the EstablishedSource.
                        let cb_peer_ip = parts.peer_ip;
                        let cb_peer_port = parts.peer_port;
                        let cb_peer_user_hash = parts.peer_user_hash;
                        let cb_file_hash = parts.file_hash;
                        let cb_emule_info_done = parts.emule_info_done;

                        // Apply the same reputation gate that
                        // `inject_source_into_active_transfers` uses
                        // for metadata-only injection. Without this,
                        // a peer banned by user-hash reputation could
                        // bypass the ban via a LowID callback — the
                        // metadata path checked, the
                        // established-stream fast path didn't.
                        // All-zero hash means "unknown identity" and
                        // is exempt from reputation checks (treated
                        // as "no identity to ban yet"); only verified
                        // hashes carry reputation entries.
                        // `continue` here returns to the outer event
                        // loop; the moved-but-not-yet-consumed
                        // `parts.reader` / `parts.writer` go out of
                        // scope and the TCP socket is dropped.
                        if cb_peer_user_hash != [0u8; 16]
                            && state.reputation.is_banned(&cb_peer_user_hash)
                        {
                            debug!(
                                "Dropping LowID callback from {cb_peer_ip}:{cb_peer_port} for {hash_hex}: peer is reputation-banned",
                            );
                            continue;
                        }

                        let server_info = state.server_addr.and_then(|sa| {
                            if let std::net::IpAddr::V4(v4) = sa.ip() {
                                Some((u32::from_le_bytes(v4.octets()), sa.port()))
                            } else {
                                None
                            }
                        });
                        {
                            let mut sm = source_manager.write().await;
                            if let Some((srv_ip, srv_port)) = server_info {
                                sm.promote_lowid_source(
                                    srv_ip, srv_port,
                                    cb_peer_port,
                                    cb_peer_ip,
                                    cb_peer_user_hash,
                                );
                            }
                            sm.register_source_full_opts(
                                cb_file_hash,
                                cb_peer_ip,
                                cb_peer_port,
                                0,
                                cb_peer_user_hash,
                                0,
                            );
                        }
                        let matching_tids = {
                            let mgr = transfer_manager.read().await;
                            matching_active_transfer_ids_for_hash(&state, &mgr, &hash_hex)
                        };
                        let uh = if cb_peer_user_hash != [0u8; 16] { Some(cb_peer_user_hash) } else { None };
                        let download_source = DownloadSource {
                            peer_ip: cb_peer_ip.to_string(),
                            peer_port: cb_peer_port,
                            available_parts: Vec::new(),
                            peer_user_hash: uh,
                            peer_connect_options: None,
                        };

                        // Try to hand off the live stream to the first
                        // matching active download. A single inbound
                        // TCP connection can only be adopted by one
                        // downloader, so we pick the first matching
                        // active transfer; if no established sender
                        // takes it, the stream is dropped and we fall
                        // back to the legacy metadata path so the
                        // peer at least appears as a known source for
                        // retry rounds.
                        let mut stream_dispatched = false;
                        let mut pending_stream = Some(ed2k::multi_source::EstablishedStream {
                            reader: parts.reader,
                            writer: parts.writer,
                            peer_user_hash: cb_peer_user_hash,
                            emule_info_done: cb_emule_info_done,
                        });
                        let mut closed_senders: Vec<String> = Vec::new();
                        for tid in &matching_tids {
                            let stream = match pending_stream.take() {
                                Some(s) => s,
                                None => break,
                            };
                            let est_source = ed2k::multi_source::EstablishedSource {
                                source: download_source.clone(),
                                stream,
                            };
                            match state.active_established_senders.get(tid) {
                                Some(tx) => match tx.try_send(est_source) {
                                    Ok(()) => {
                                        info!(
                                            "Adopted LowID callback stream from {cb_peer_ip}:{cb_peer_port} into active download {tid} for {hash_hex}",
                                        );
                                        stream_dispatched = true;
                                        break;
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Full(_es)) => {
                                        warn!(
                                            "Established-stream channel full for {tid}; dropping callback stream from {cb_peer_ip}:{cb_peer_port}",
                                        );
                                        // Stream value consumed by
                                        // try_send and dropped here.
                                        // Don't try other matching
                                        // downloads — only one of
                                        // them needed the stream and
                                        // we already lost it.
                                        break;
                                    }
                                    Err(tokio::sync::mpsc::error::TrySendError::Closed(es)) => {
                                        debug!(
                                            "Established-stream channel closed for {tid}; trying next match",
                                        );
                                        // Sender is stale; mark for
                                        // cleanup and try the next
                                        // matching download.
                                        closed_senders.push(tid.clone());
                                        pending_stream = Some(es.stream);
                                    }
                                },
                                None => {
                                    debug!(
                                        "No established-stream channel for {tid}; trying next match",
                                    );
                                    pending_stream = Some(est_source.stream);
                                }
                            }
                        }
                        // Reap any closed senders we encountered above
                        // so we don't keep retrying them.
                        // Reap any closed senders we encountered. A
                        // `Closed` on the established channel means the
                        // multi-source worker is gone, so the paired
                        // metadata sender is also dead — keep both maps
                        // in lockstep (see field doc on
                        // `active_established_senders`).
                        for tid in &closed_senders {
                            state.active_established_senders.remove(tid);
                            state.active_source_senders.remove(tid);
                        }
                        // If nothing took the stream it's dropped here
                        // (`pending_stream` goes out of scope).
                        drop(pending_stream);

                        if !stream_dispatched {
                            // Last-resort: legacy metadata injection.
                            // The live stream is gone, so the dial-
                            // back will likely fail for true LowID
                            // peers — but the call mirrors the
                            // pre-fix behaviour and at least registers
                            // the peer for SX / future retry rounds.
                            let stats = inject_source_into_active_transfers(
                                &mut state,
                                cb_file_hash,
                                &matching_tids,
                                &download_source,
                                0,
                            );
                            if stats.injected > 0 {
                                info!(
                                    "Injected LowID callback peer {}:{} (metadata-only fallback) into {} active download(s) for {}",
                                    download_source.peer_ip, download_source.peer_port, stats.injected, hash_hex,
                                );
                            } else {
                                debug!("No active download accepts callback peer for {hash_hex}");
                            }
                        }
                    }
                }
            }

            udp_fw_req = udp_fw_check_rx.recv() => {
                if let Some(req) = udp_fw_req {
                    send_kad_udp_firewall_result(
                        &udp_socket,
                        &state,
                        req.peer_ip,
                        req.internal_udp_port,
                        req.external_udp_port,
                        req.receiver_udp_key,
                    ).await;
                }
            }

            // Periodic nodes.dat save to protect against crashes
            _ = nodes_save_timer.tick() => {
                let contacts = state.routing_table.export_bootstrap_contacts(200);
                let nodes_path = state.data_dir.join("nodes.dat");
                if let Err(e) = bootstrap::save_nodes_dat(&nodes_path, &contacts) {
                    error!("Failed periodic nodes.dat save: {e}");
                }
            }

            // Renew UPnP port mappings before the 1-hour lease expires
            _ = upnp_renew_timer.tick() => {
                if upnp_enabled && upnp_mappings.has_gateway() {
                    upnp_mappings.renew().await;
                }
            }

            // Statistics rate recording (every second)
            _ = stats_timer.tick() => {
                stats_manager.session_down_counter.store(bandwidth_limiter.total_downloaded(), std::sync::atomic::Ordering::Relaxed);
                stats_manager.session_up_counter.store(bandwidth_limiter.total_uploaded(), std::sync::atomic::Ordering::Relaxed);
                // Fold peer-to-peer SX bytes (OP_REQUESTSOURCES /
                // OP_ANSWERSOURCES + Ember EPX) accumulated by the
                // upload / transfer / multi_source tasks into the
                // overhead category. Without this the Source Exchange
                // row on the Statistics page shows only server-based
                // source-asking and reads zero on KAD/Ember-only runs.
                stats_manager.drain_sx_counters();
                stats_manager.record_rate();
                state.ip_filter.collect_shared_hits(&shared_ip_filter);
                for (transfer_id, injected, remaining) in drain_active_source_overflow(&mut state) {
                    debug!(
                        "Drained {} overflow source(s) for active download {}, {} remaining queued",
                        injected,
                        transfer_id,
                        remaining
                    );
                }
                let (health_updates, speed_resets) = {
                    let mut mgr = transfer_manager.write().await;
                    mgr.refresh_health(chrono::Utc::now().timestamp())
                };
                for update in &health_updates {
                    emit_transfer_health(&app_handle, update);
                }
                for sr in &speed_resets {
                    let _ = app_handle.emit(
                        "transfer-speed-decay",
                        serde_json::json!({
                            "id": sr.id,
                            "speed": 0,
                        }),
                    );
                }
            }

            // Periodic statistics save (every 5 minutes)
            _ = stats_save_timer.tick() => {
                stats_manager.save_cumulative(&db);
            }

            // Periodic reputation maintenance (every 60s: lift bans)
            _ = reputation_timer.tick() => {
                state.reputation.lift_expired_bans();
            }

            // Periodic reputation save (every 5 minutes)
            _ = reputation_save_timer.tick() => {
                let rep_path = state.data_dir.join("reputation.json");
                if let Err(e) = state.reputation.save(&rep_path) {
                    error!("Failed to save reputation.json: {e}");
                }
            }

            // Periodic known.met save (every 11 minutes, matching eMule)
            _ = known_met_save_timer.tick() => {
                if known_files.is_dirty() {
                    let known_path = state.data_dir.join("known.met");
                    if let Err(e) = known_files.save(&known_path) {
                        error!("Failed to save known.met: {e}");
                    }
                }
                while let Ok(hs) = aich_set_rx.try_recv() {
                    state.aich_hash_sets.push(hs);
                }
                if !state.aich_hash_sets.is_empty() {
                    let known2_path = state.data_dir.join("known2_64.met");
                    if let Err(e) = ed2k::aich::save_known2_met(&known2_path, &state.aich_hash_sets) {
                        error!("Failed to save known2_64.met: {e}");
                    }
                }
            }

            // Dead source cleanup (every 5 minutes)
            _ = dead_source_timer.tick() => {
                state.dead_sources.cleanup();
                let count = state.dead_sources.len();
                if count > 0 {
                    debug!("Dead source list: {count} blocked sources");
                }
            }

            // Ember Peer Exchange: rebuild shared payload from active downloads + known sources
            _ = ember_refresh_timer.tick() => {
                if !state.ember_payload_dirty {
                    continue;
                }
                // Also look up AICH roots from local shared file index
                {
                    let index = local_index.read().await;
                    let mgr = transfer_manager.read().await;
                    for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                        if let Ok(ed2k_bytes) = hex::decode(&transfer.file_hash) {
                            if ed2k_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&ed2k_bytes);
                                if !state.aich_root_map.contains_key(&fh) {
                                    if let Some(fi) = index.get_by_hash(&transfer.file_hash) {
                                        if !fi.aich_hash.is_empty() {
                                            if let Ok(ab) = hex::decode(&fi.aich_hash) {
                                                if ab.len() == 20 {
                                                    let mut ah = [0u8; 20];
                                                    ah.copy_from_slice(&ab);
                                                    state.aich_root_map.insert(fh, ah);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let entries = {
                    let mgr = transfer_manager.read().await;
                    let sm = source_manager.read().await;
                    let mut file_entries = Vec::new();
                    let mut seen_hashes = HashSet::new();

                    // Include active/queued downloads
                    for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                        if transfer.direction != TransferDirection::Download {
                            continue;
                        }
                        if matches!(transfer.status, TransferStatus::Completed | TransferStatus::Failed) {
                            continue;
                        }
                        let hash_bytes = match hex::decode(&transfer.file_hash) {
                            Ok(b) if b.len() == 16 => {
                                let mut h = [0u8; 16];
                                h.copy_from_slice(&b);
                                h
                            }
                            _ => continue,
                        };
                        seen_hashes.insert(transfer.file_hash.clone());
                        let aich_root = state.aich_root_map.get(&hash_bytes).copied();
                        let sources: Vec<ember::EmberSource> = state
                            .per_file_sources
                            .get(&transfer.id)
                            .map(|pfs| {
                                pfs.sources
                                    .iter()
                                    .filter(|s| s.tcp_port > 0
                                        && !s.ip.is_unspecified()
                                        && !s.ip.is_private()
                                        && !s.ip.is_loopback()
                                        && !s.ip.is_link_local())
                                    .take(ember::MAX_EPX_SOURCES_PER_FILE)
                                    .map(|s| {
                                        let mut flags = 0u8;
                                        if matches!(s.state,
                                            ed2k::sources::DownloadSourceState::WaitCallback
                                            | ed2k::sources::DownloadSourceState::WaitCallbackKad
                                            | ed2k::sources::DownloadSourceState::LowToLowIp
                                        ) {
                                            flags |= ember::SOURCE_FLAG_FIREWALLED;
                                        } else if !s.ip.is_private() {
                                            flags |= ember::SOURCE_FLAG_RELAY_CAPABLE;
                                        }
                                        if sm.get_connect_options(&hash_bytes, s.ip, s.tcp_port).map_or(false, |co| co & 0x07 != 0) {
                                            flags |= ember::SOURCE_FLAG_OBFUSCATION;
                                        }
                                        ember::EmberSource {
                                            ip: s.ip,
                                            tcp_port: s.tcp_port,
                                            udp_port: s.udp_port,
                                            flags,
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        file_entries.push(ember::EmberFileEntry {
                            file_hash: hash_bytes,
                            file_size: transfer.total_size,
                            aich_root,
                            sources,
                        });
                    }

                    // Include completed (seeded) files that have known sources
                    for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                        if transfer.status != TransferStatus::Completed {
                            continue;
                        }
                        if seen_hashes.contains(&transfer.file_hash) {
                            continue;
                        }
                        if file_entries.len() >= ember::MAX_EPX_FILES {
                            break;
                        }
                        let hash_bytes = match hex::decode(&transfer.file_hash) {
                            Ok(b) if b.len() == 16 => {
                                let mut h = [0u8; 16];
                                h.copy_from_slice(&b);
                                h
                            }
                            _ => continue,
                        };
                        let aich_root = state.aich_root_map.get(&hash_bytes).copied();
                        let sources: Vec<ember::EmberSource> = state
                            .per_file_sources
                            .get(&transfer.id)
                            .map(|pfs| {
                                pfs.sources
                                    .iter()
                                    .filter(|s| s.tcp_port > 0
                                        && !s.ip.is_unspecified()
                                        && !s.ip.is_private()
                                        && !s.ip.is_loopback()
                                        && !s.ip.is_link_local())
                                    .take(ember::MAX_EPX_SOURCES_PER_FILE)
                                    .map(|s| {
                                        let mut flags = 0u8;
                                        if matches!(s.state,
                                            ed2k::sources::DownloadSourceState::WaitCallback
                                            | ed2k::sources::DownloadSourceState::WaitCallbackKad
                                            | ed2k::sources::DownloadSourceState::LowToLowIp
                                        ) {
                                            flags |= ember::SOURCE_FLAG_FIREWALLED;
                                        } else if !s.ip.is_private() {
                                            flags |= ember::SOURCE_FLAG_RELAY_CAPABLE;
                                        }
                                        if sm.get_connect_options(&hash_bytes, s.ip, s.tcp_port).map_or(false, |co| co & 0x07 != 0) {
                                            flags |= ember::SOURCE_FLAG_OBFUSCATION;
                                        }
                                        ember::EmberSource {
                                            ip: s.ip,
                                            tcp_port: s.tcp_port,
                                            udp_port: s.udp_port,
                                            flags,
                                        }
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        if sources.is_empty() {
                            continue;
                        }
                        seen_hashes.insert(transfer.file_hash.clone());
                        file_entries.push(ember::EmberFileEntry {
                            file_hash: hash_bytes,
                            file_size: transfer.total_size,
                            aich_root,
                            sources,
                        });
                    }

                    file_entries
                };

                // Drop entries older than `KNOWN_EMBER_PEER_TTL` before
                // building the wire list so we never advertise a peer
                // we haven't heard from in a day. Cheap O(N) sweep — N
                // is hard-capped at MAX_KNOWN_EMBER_PEERS = 500.
                let pruned_before = state.known_ember_peers.len();
                prune_stale_ember_peers(&mut state.known_ember_peers);
                let pruned_after = state.known_ember_peers.len();
                if pruned_after != pruned_before {
                    state.stats.ember_peers = pruned_after as u32;
                    tracing::debug!(
                        "Pruned {} stale Ember peer(s) (now {})",
                        pruned_before - pruned_after,
                        pruned_after
                    );
                }

                // Build peer discovery list from previously-discovered peers
                // (we don't have IP:port for session keys — they're ember
                // hashes — so the EPX peer section is sourced entirely from
                // the timestamped `known_ember_peers` map). Prefer most
                // recently-seen peers so the wire payload reflects current
                // mesh activity rather than whatever the HashMap iteration
                // order happens to surface.
                let ember_peers: Vec<ember::EmberPeer> = {
                    let mut candidates: Vec<((Ipv4Addr, u16), std::time::Instant)> = state
                        .known_ember_peers
                        .iter()
                        .filter(|((ip, _), _)| {
                            !crate::security::is_special_use_v4(*ip) && !ip.is_multicast()
                        })
                        .map(|((ip, port), ts)| ((*ip, *port), *ts))
                        .collect();
                    candidates.sort_by(|a, b| b.1.cmp(&a.1));
                    candidates
                        .into_iter()
                        .take(ember::MAX_EPX_PEERS)
                        .map(|((ip, port), _)| ember::EmberPeer { ip, tcp_port: port })
                        .collect()
                };

                let payload = ember::build_exchange_payload(&entries, &ember_peers);
                *shared_ember_payload.write().await = Arc::new(payload);
                ember_payload_generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                state.ember_payload_dirty = false;
            }

            _ = source_count_sync_timer.tick() => {
                let hashes = {
                    let index = local_index.read().await;
                    index.all_hashes()
                };
                if hashes.is_empty() {
                    continue;
                }
                let sm = source_manager.read().await;
                let mut updates: Vec<(String, u32)> = Vec::new();
                for hash_hex in &hashes {
                    let hash_bytes: [u8; 16] = match hex::decode(hash_hex) {
                        Ok(b) if b.len() == 16 => {
                            let mut h = [0u8; 16];
                            h.copy_from_slice(&b);
                            h
                        }
                        _ => continue,
                    };
                    let mut count = sm.source_count(&hash_bytes) as u32;
                    for pfs in state.per_file_sources.values() {
                        if pfs.file_hash == hash_bytes {
                            let pfs_count = pfs.complete_source_count() as u32;
                            if pfs_count > count {
                                count = pfs_count;
                            }
                            break;
                        }
                    }
                    // Fallback for purely-shared files (never searched/downloaded):
                    // use the number of KAD peers that accepted our most recent
                    // source publish. This represents *other* peers who know
                    // about us as a source; the local copy is not counted so
                    // the UI label ("Peers") stays honest.
                    let kad_hash = md4_bytes_to_kad_id(&hash_bytes);
                    if let Some(&ack_count) = state.source_publish_acks.get(&kad_hash) {
                        if ack_count > count {
                            count = ack_count;
                        }
                    }
                    if count > 0 {
                        updates.push((hash_hex.clone(), count));
                    }
                }
                drop(sm);
                if !updates.is_empty() {
                    let mut index = local_index.write().await;
                    for (hash_hex, count) in &updates {
                        index.update_complete_sources(hash_hex, *count);
                    }
                    drop(index);
                    let li_ref = local_index.clone();
                    let s_files = shared_files.clone();
                    let kad_connected = state.stats.status == NetworkStatus::Connected;
                    let srv_connected = state.server_connected;
                    tokio::spawn(async move {
                        let file_snap = {
                            let index = li_ref.read().await;
                            let mut snap = index.all_files().to_vec();
                            for f in &mut snap {
                                f.shared_kad = f.shared && kad_connected && !f.hash.is_empty();
                                f.shared_ed2k = f.shared && srv_connected && !f.hash.is_empty();
                            }
                            snap
                        };
                        *s_files.write().await = file_snap;
                    });
                }
            }

            _ = watchdog_timer.tick() => {
                let now = chrono::Utc::now().timestamp();

                if state.server_connected
                    && state.server_connection.is_some()
                    && now.saturating_sub(last_server_activity_at) > 120
                {
                    handle_server_disconnect(
                        &mut state,
                        &shared_server_addr,
                        &app_handle,
                        "watchdog: no server activity for 120s",
                    ).await;
                }

                if cache_write_handle.as_ref().is_some_and(|h| !h.is_finished())
                    && last_cache_refresh_started_at > 0
                    && now.saturating_sub(last_cache_refresh_started_at) > 20
                {
                    warn!(
                        "Watchdog: aborting stale cache refresh after {}s",
                        now.saturating_sub(last_cache_refresh_started_at)
                    );
                    if let Some(handle) = cache_write_handle.take() {
                        handle.abort();
                    }
                }

                if !state.pending_downloads.is_empty()
                    && state.stats.status != NetworkStatus::Disconnected
                    && now.saturating_sub(last_kad_activity_at) > 180
                {
                    for pending in state.pending_downloads.values_mut() {
                        pending.last_search_at = 0;
                    }
                    warn!(
                        "Watchdog: no UDP activity for {}s with {} pending downloads; forcing immediate source refresh",
                        now.saturating_sub(last_kad_activity_at),
                        state.pending_downloads.len()
                    );
                    last_kad_activity_at = now;
                }
            }

            // Periodic UDP source requests (eMule UDPSERVERREASKTIME)
            _ = server_udp_source_timer.tick() => {
                let mut all_for_udp: Vec<([u8; 16], u64)> = state.pending_downloads.values()
                    .filter(|pd| !pd.control.is_cancelled() && !pd.control.is_paused())
                    .filter_map(|pd| {
                        let hash_bytes = hex::decode(&pd.file_hash).ok()?;
                        if hash_bytes.len() != 16 {
                            return None;
                        }
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&hash_bytes);
                        Some((fh, pd.file_size))
                    })
                    .collect();

                // Also query servers for active downloads (not just pending)
                {
                    let mgr = transfer_manager.read().await;
                    let mut seen: std::collections::HashSet<[u8; 16]> = all_for_udp.iter().map(|(fh, _)| *fh).collect();
                    for (tid, _sender) in &state.active_source_senders {
                        if let Some(transfer) = mgr.get_transfer(tid) {
                            if let Ok(hash_bytes) = hex::decode(&transfer.file_hash) {
                                if hash_bytes.len() == 16 {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&hash_bytes);
                                    if seen.insert(fh) {
                                        all_for_udp.push((fh, transfer.total_size));
                                    }
                                }
                            }
                        }
                    }
                }

                if all_for_udp.is_empty() { continue; }
                let total_downloads = all_for_udp.len();
                // Filter out files that already have enough sources
                let mut need_sources: Vec<([u8; 16], u64)> = Vec::new();
                {
                    let sm = source_manager.read().await;
                    for (fh, file_size) in all_for_udp {
                        if sm.source_count(&fh) < MAX_SOURCES_FOR_UDP {
                            need_sources.push((fh, file_size));
                        }
                    }
                }
                if !need_sources.is_empty() {
                    // eMule packs multiple file hashes per server packet (up to 35)
                    let packets = build_all_getsources_packets_multi(&state, &need_sources);
                    if !packets.is_empty() {
                        let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                        let queued = packets.len().min(room);
                        debug!("Queuing {}/{} packed UDP source packets for {} files across servers",
                            queued, packets.len(), need_sources.len());
                        state.udp_source_queue.extend(packets.into_iter().take(room));
                    }
                }
                debug!("Periodic UDP source sweep for {} downloads ({} need sources)",
                    total_downloads, need_sources.len());
            }

            // eMule ProcessLocalRequests(): batch TCP OP_GETSOURCES over the
            // active server connection every 4 min, up to 15 per frame.
            _ = server_tcp_source_timer.tick() => {
                if !state.server_connected || state.server_connection.is_none() { continue; }

                const MAX_TCP_GETSOURCES_PER_FRAME: usize = 15;

                let mut all_downloads: Vec<(String, [u8; 16], u64, usize)> = Vec::new();

                {
                    let sm = source_manager.read().await;
                    for (tid, pd) in &state.pending_downloads {
                        if pd.control.is_cancelled() || pd.control.is_paused() { continue; }
                        if let Ok(raw) = hex::decode(&pd.file_hash) {
                            if raw.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&raw[..16]);
                                let src_count = sm.source_count(&fh);
                                all_downloads.push((tid.clone(), fh, pd.file_size, src_count));
                            }
                        }
                    }
                }

                // Also include active downloads
                {
                    let mgr = transfer_manager.read().await;
                    let sm = source_manager.read().await;
                    let seen: std::collections::HashSet<String> = all_downloads.iter().map(|(t, _, _, _)| t.clone()).collect();
                    for (tid, _sender) in &state.active_source_senders {
                        if seen.contains(tid) { continue; }
                        if let Some(transfer) = mgr.get_transfer(tid) {
                            if let Ok(raw) = hex::decode(&transfer.file_hash) {
                                if raw.len() == 16 {
                                    let mut fh = [0u8; 16];
                                    fh.copy_from_slice(&raw[..16]);
                                    let src_count = sm.source_count(&fh);
                                    all_downloads.push((tid.clone(), fh, transfer.total_size, src_count));
                                }
                            }
                        }
                    }
                }

                if all_downloads.is_empty() { continue; }

                // Prioritize files with fewer sources
                all_downloads.sort_by_key(|(_, _, _, sc)| *sc);

                let total = all_downloads.len();
                let cursor = state.server_tcp_getsources_cursor % total;
                let batch_size = MAX_TCP_GETSOURCES_PER_FRAME.min(total);
                let mut sent = 0u32;

                if let Some(conn) = state.server_connection.as_mut() {
                    for i in 0..batch_size {
                        let idx = (cursor + i) % total;
                        let (_, ref fh, file_size, _) = all_downloads[idx];
                        if let Ok(bytes) = conn.send_get_sources(fh, file_size).await {
                            if bytes > 0 { sent += 1; }
                            // Periodic TCP source-asking sweep also counts as
                            // SourceExchange overhead — same wire flow as the
                            // login-time and on-demand requests below.
                            if bytes > 0 {
                                stats_manager.add_overhead(
                                    crate::storage::statistics::OverheadCategory::SourceExchange,
                                    crate::storage::statistics::OverheadDirection::Upload,
                                    bytes,
                                );
                            }
                        }
                    }
                }

                state.server_tcp_getsources_cursor = (cursor + batch_size) % total;
                if sent > 0 {
                    info!("TCP source batch: sent OP_GETSOURCES for {sent}/{batch_size} downloads (cursor at {}/{})", state.server_tcp_getsources_cursor, total);
                }
            }

            // USS: send a KAD Ping to the selected host for RTT measurement
            _ = uss_ping_timer.tick() => {
                if state.stats.status == NetworkStatus::Disconnected { continue; }
                if !state.uss_enabled_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    state.uss_host = None;
                    continue;
                }
                let now_ts = chrono::Utc::now().timestamp();

                // Expire old pending pings (> 10s without response)
                state.pending_uss_pings.retain(|_, sent| sent.elapsed().as_secs() < 10);

                // Rotate host every 5 minutes or after 3 consecutive missed pongs
                let should_rotate = state.uss_host.is_some()
                    && (state.uss_missed_pongs >= 3 || now_ts.saturating_sub(state.uss_host_selected_at) > 300);
                if should_rotate {
                    debug!("USS: rotating ping host (missed={}, age={}s)", state.uss_missed_pongs, now_ts - state.uss_host_selected_at);
                    state.uss_host = None;
                }

                // Select a host if needed
                if state.uss_host.is_none() {
                    let candidate = state.routing_table.all_contacts()
                        .filter(|c| c.verified && !c.is_dead() && !c.is_udp_firewalled())
                        .find(|c| {
                            let addr = SocketAddr::new(c.ip.into(), c.udp_port);
                            state.uss_host.as_ref().map(|(a, _)| *a) != Some(addr)
                        });
                    if let Some(contact) = candidate {
                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                        state.uss_host = Some((addr, contact.id));
                        state.uss_missed_pongs = 0;
                        state.uss_host_selected_at = now_ts;
                        info!("USS: selected ping host {addr}");
                    }
                }

                // Send Ping to the USS host (via obfuscation layer)
                if let Some((addr, ref contact_id)) = state.uss_host {
                    let msg = KadMessage::Ping;
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        let _ = send_kad_packet(&udp_socket, &packet, addr, &state, contact_id).await;
                        state.pending_uss_pings.insert(addr, std::time::Instant::now());
                        state.uss_missed_pongs += 1;
                    }
                }
            }

            // Refresh shared peer/stats caches for frontend reads (non-blocking)
            _ = cache_refresh_timer.tick() => {
                // Skip if previous write task hasn't finished yet — avoids
                // accumulating queued writers on the RwLocks which would starve
                // Tauri IPC read handlers and freeze the UI.
                if cache_write_handle.as_ref().is_some_and(|h| !h.is_finished()) {
                    continue;
                }

                // Collect raw contact data quickly (no hex/distance computation).
                // The expensive conversions happen in the spawned background task.
                let local_id = state.local_id;
                let raw_contacts: Vec<_> = state.routing_table.all_contacts()
                    .take(500)
                    .map(|c| {
                        let nick = state.peer_nicknames.get(&c.id).cloned().unwrap_or_default();
                        (c.clone(), nick)
                    })
                    .collect();

                state.stats.connected_peers = state.routing_table.len() as u32;
                state.stats.kad_users_estimate = state.routing_table.estimate_count();
                state.stats.upload_speed = bandwidth_limiter.smoothed_upload_speed();
                state.stats.download_speed = bandwidth_limiter.smoothed_download_speed();
                state.stats.total_uploaded = bandwidth_limiter.total_uploaded();
                state.stats.total_downloaded = bandwidth_limiter.total_downloaded();
                state.stats.upnp_mapped = state.upnp_mapped;
                state.stats.buddy_status = match state.buddy_manager.state() {
                    BuddyState::NoBuddy => {
                        if let Some(bid) = state.buddy_manager.serving_for() {
                            format!("serving:{}", bid)
                        } else {
                            "none".to_string()
                        }
                    }
                    BuddyState::FindingBuddy => "searching".to_string(),
                    BuddyState::Connected => {
                        if let Some(bid) = state.buddy_manager.buddy_id() {
                            format!("connected:{}", bid)
                        } else {
                            "connected".to_string()
                        }
                    }
                };
                state.stats.external_ip = state
                    .external_ip
                    .map(|ip| ip.to_string())
                    .unwrap_or_default();
                let fw_shared = state.firewalled_shared.load(std::sync::atomic::Ordering::Relaxed);
                if state.firewalled && !fw_shared {
                    state.firewalled = false;
                    state.firewall_checker.handle_tcp_connect_back();
                }
                state.stats.firewalled = state.firewalled;
                update_publish_manager_state(&mut state);

                let cached_s: Vec<KadSearchInfo> = state
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
                            SearchType::FindSource { .. } => {
                                // pending_downloads may have been consumed
                                // already by `try_start_from_known`; fall
                                // back to whatever the transfer manager
                                // knows for a display-name.
                                state.download_source_searches.get(sid)
                                    .and_then(|(tid, _)| state.pending_downloads.get(tid).map(|pd| pd.file_name.clone()))
                                    .unwrap_or_else(|| "Source Search".to_string())
                            }
                            SearchType::FindBuddy => "Find Buddy".to_string(),
                            _ => String::new(),
                        };
                        let is_store = matches!(search.search_type,
                            SearchType::StoreFile | SearchType::StoreKeyword | SearchType::StoreNotes);
                        let responses = if is_store {
                            search.closest.len() as u32
                        } else {
                            search.results.len() as u32
                        };
                        // K11: see `kad_searches_snapshot` for the same
                        // computation — keep them in sync.
                        let queried = search.queried.len() as u32;
                        let responded = search.responded_during_lookup.len() as u32;
                        let pending = search.pending.len() as u32;
                        let load_total = queried.saturating_add(pending);
                        let load_pct = if queried == 0 { 0 } else { (responded * 100) / queried };
                        KadSearchInfo {
                            id: sid.0,
                            target: search.target.to_hex(),
                            search_type: type_name.to_string(),
                            name,
                            status: if search.completed { "stopping".to_string() } else { "active".to_string() },
                            load: load_pct,
                            load_response: responded,
                            load_total,
                            packets_sent: queried,
                            request_answer: pending,
                            responses,
                            started_at: search.started_at,
                        }
                    })
                    .collect();

                let stats_snapshot = state.stats.clone();

                let cached_srv: Vec<ServerInfo> = state.server_list.servers().iter().map(|s| ServerInfo {
                    ip: s.ip.clone(),
                    port: s.port,
                    name: s.name.clone(),
                    description: s.description.clone(),
                    user_count: s.user_count,
                    file_count: s.file_count,
                    max_users: s.max_users,
                    soft_files: s.soft_files,
                    hard_files: s.hard_files,
                    is_static: s.is_static,
                    fail_count: s.fail_count,
                    client_id: 0,
                    is_low_id: false,
                }).collect();

                let cached_conn_srv: Option<ServerInfo> = state.server_connection.as_ref().and_then(|conn| {
                    let session = conn.session.as_ref()?;
                    let addr = state.server_addr?;
                    Some(ServerInfo {
                        ip: addr.ip().to_string(),
                        port: addr.port(),
                        name: session.server_name.clone(),
                        description: String::new(),
                        user_count: session.user_count,
                        file_count: session.file_count,
                        max_users: 0,
                        soft_files: 0,
                        hard_files: 0,
                        is_static: false,
                        fail_count: 0,
                        client_id: state.server_client_id,
                        is_low_id: state.low_id,
                    })
                });

                let cached_tstats = stats_manager.get_stats();

                // Collect known-file stats for the background task (can't move known_files into spawn)
                let known_stats: Vec<([u8; 16], u32, u32, u64)> = known_files
                    .all_records()
                    .map(|r| (r.file_hash, r.all_time_requested, r.all_time_accepted, r.all_time_transferred))
                    .collect();

                // Spawn ALL heavy work (hex conversion, distance computation, writes,
                // and the local_index stats merge) as a background task so the event
                // loop isn't blocked by any RwLock contention.
                let sp = shared_peers.clone();
                let ss = shared_stats.clone();
                let sc = shared_contacts.clone();
                let ssrch = shared_searches.clone();
                let s_srv = shared_servers.clone();
                let s_conn = shared_connected_server.clone();
                let s_tstats = shared_transfer_stats.clone();
                let s_files = shared_files.clone();
                let db_ref = db.clone();
                let li_ref = local_index.clone();
                let kad_connected = state.stats.status == NetworkStatus::Connected;
                let srv_connected = state.server_connected;
                last_cache_refresh_started_at = chrono::Utc::now().timestamp();
                cache_write_handle = Some(tokio::spawn(async move {
                    // Merge all-time stats from known.met into local_index, then
                    // snapshot the file list for frontend IPC reads.
                    // IMPORTANT: release the local_index lock before acquiring
                    // cached_shared_files -- never nest these two locks.
                    let file_snap = {
                        let mut index = li_ref.write().await;
                        for (file_hash, reqs, accepted, transferred) in &known_stats {
                            let hash_hex = hex::encode(file_hash);
                            index.update_alltime_stats(&hash_hex, *reqs, *accepted, *transferred);
                        }
                        let mut snap = index.all_files().to_vec();
                        for f in &mut snap {
                            f.shared_kad = f.shared && kad_connected && !f.hash.is_empty();
                            f.shared_ed2k = f.shared && srv_connected && !f.hash.is_empty();
                        }
                        snap
                    };
                    *s_files.write().await = file_snap;
                    // Do the expensive hex/distance conversions here, off the event loop
                    let mut peers: Vec<PeerInfo> = Vec::new();
                    let mut cached_c: Vec<KadContactInfo> = Vec::new();
                    for (c, nick) in &raw_contacts {
                        let hex_id = c.id.to_hex();
                        if peers.len() < 200 {
                            peers.push(PeerInfo {
                                id: hex_id.clone(),
                                addresses: vec![format!("{}:{}", c.ip, c.udp_port)],
                                nickname: nick.clone(),
                                last_seen: c.last_seen,
                                files_shared: 0,
                                banned: false,
                            });
                        }
                        let distance = c.id.xor_distance(&local_id);
                        cached_c.push(KadContactInfo {
                            id: hex_id,
                            contact_type: c.contact_type,
                            version: c.version,
                            distance: distance.to_hex(),
                            ip_verified: c.verified,
                            bootstrap: c.contact_type == CONTACT_TYPE_NEW && c.version == 0,
                        });
                    }

                    let saved_peers = tokio::task::spawn_blocking(move || {
                        db_ref.get_peers().unwrap_or_default()
                    }).await.unwrap_or_default();
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
                    *sp.write().await = peers;
                    *ss.write().await = stats_snapshot;
                    *sc.write().await = cached_c;
                    *ssrch.write().await = cached_s;
                    *s_srv.write().await = cached_srv;
                    *s_conn.write().await = cached_conn_srv;
                    *s_tstats.write().await = cached_tstats;
                }));
            }
        }

        // Yield to the tokio scheduler so other tasks (Tauri IPC command handlers,
        // background cache writers, etc.) can make progress. Without this, the
        // select loop can monopolize the worker thread in debug builds where
        // synchronous timer handlers consume enough CPU to starve other tasks.
        tokio::task::yield_now().await;
    }
    }).catch_unwind().await;

    if let Err(panic_info) = loop_panic {
        let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
            format!("Network event loop panicked: {s}")
        } else if let Some(s) = panic_info.downcast_ref::<String>() {
            format!("Network event loop panicked: {s}")
        } else {
            "Network event loop panicked (unknown payload)".to_string()
        };
        error!("{msg}");
        let _ = app_handle.emit("network-error", serde_json::json!({
            "message": "Internal error in network task. The application may need to be restarted.",
        }));
    }

    // Abort pending server connection if any
    if let Some(handle) = state.pending_server_connect.take() {
        handle.abort();
    }
    if let Some(handle) = state.pending_outgoing_buddy.take() {
        handle.abort();
    }

    if let Some(handle) = cache_write_handle.take() {
        match tokio::time::timeout(std::time::Duration::from_secs(2), handle).await {
            Ok(Ok(())) => debug!("Cache refresh task finished before shutdown"),
            Ok(Err(_)) => debug!("Cache refresh task cancelled during shutdown"),
            Err(_) => warn!("Cache refresh task did not finish before shutdown"),
        }
    }

    {
        let mgr = transfer_manager.read().await;
        for tid in state.download_handles.keys() {
            if let Some(control) = mgr.get_control(tid) {
                control.cancel();
            }
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Cancel and await all active download tasks
    for (tid, handle) in state.download_handles.drain() {
        handle.abort();
        match tokio::time::timeout(std::time::Duration::from_secs(5), handle).await {
            Ok(Ok(())) => debug!("Download task {tid} shut down cleanly"),
            Ok(Err(_)) => debug!("Download task {tid} cancelled"),
            Err(_) => warn!("Download task {tid} did not finish within timeout"),
        }
    }

    // Persist .part.met for any downloads that were in progress when aborted.
    if let Ok(reg) = state.tracker_registry.lock() {
        let count = reg.len();
        if count > 0 {
            for (tid, tracker) in reg.iter() {
                if let Ok(t) = tracker.try_read() {
                    t.save();
                    debug!("Saved .part.met for aborted download {tid}");
                } else {
                    warn!("Could not lock tracker for {tid} to save .part.met on shutdown");
                }
            }
            info!("Saved {count} download tracker(s) on shutdown");
        }
    }
    state.active_source_senders.clear();
    // Lockstep — every download is dead at shutdown, both sender
    // maps must be cleared together (see field doc).
    state.active_established_senders.clear();
    state.active_source_overflow.clear();
    state.active_kad_search_state.clear();

    // Unregister from the rendezvous server on graceful shutdown
    if state.rendezvous_registered {
        let rv_url = settings.rendezvous_url.clone();
        let rv_hash = ember_hash;
        if let Err(e) = rendezvous::unregister(&rv_url, &rv_hash).await {
            warn!("Failed to unregister from rendezvous server: {e}");
        }
    }

    // Save all state on shutdown
    info!("Shutting down network");
    let contacts = state.routing_table.export_bootstrap_contacts(200);
    let nodes_path = state.data_dir.join("nodes.dat");
    if let Err(e) = bootstrap::save_nodes_dat(&nodes_path, &contacts) {
        error!("Failed to save nodes.dat: {e}");
    }

    stats_manager.save_cumulative(&db);
    info!("Statistics saved on shutdown");

    let known_path = state.data_dir.join("known.met");
    if let Err(e) = known_files.save(&known_path) {
        error!("Failed to save known.met on shutdown: {e}");
    }
    while let Ok(hs) = aich_set_rx.try_recv() {
        state.aich_hash_sets.push(hs);
    }
    if !state.aich_hash_sets.is_empty() {
        let known2_path = state.data_dir.join("known2_64.met");
        if let Err(e) = ed2k::aich::save_known2_met(&known2_path, &state.aich_hash_sets) {
            error!("Failed to save known2_64.met on shutdown: {e}");
        } else {
            info!("Saved {} AICH hash sets to known2_64.met", state.aich_hash_sets.len());
        }
    }
    flush_credit_state(&credit_manager, &db, &state.data_dir, true).await;
    info!("Credit state saved on shutdown");

    let rep_path = state.data_dir.join("reputation.json");
    if let Err(e) = state.reputation.save(&rep_path) {
        error!("Failed to save reputation.json on shutdown: {e}");
    } else {
        info!("Reputation data saved on shutdown ({} peers tracked)", state.reputation.tracked_count());
    }

    let server_met_path = state.data_dir.join("server.met");
    let _ = state.server_list.save_server_met(&server_met_path);

    if upnp_enabled {
        upnp_mappings.teardown().await;
    }

    Ok(())
}

/// Send a KAD packet, optionally using obfuscation if the target supports it
/// and the user has enabled protocol obfuscation in settings.
async fn send_kad_packet(
    socket: &UdpSocket,
    packet: &[u8],
    addr: SocketAddr,
    state: &NetworkState,
    target_id: &KadId,
) -> std::io::Result<usize> {
    let contact = state.routing_table.get_contact(target_id);
    let use_obfuscation = state.obfuscation_enabled
        && contact.map_or(false, |c| c.supports_obfuscation());

    let result = if use_obfuscation {
        let their_ip = match addr.ip() {
            std::net::IpAddr::V4(ip) => u32::from(ip),
            _ => 0,
        };
        let sender_key = KadUDPKey::generate(state.udp_key_seed, their_ip);
        let receiver_key_val = contact
            .and_then(|c| c.udp_key)
            .filter(|k| k.is_valid())
            .map(|k| k.get_key_value(their_ip))
            .unwrap_or(0);
        let encrypted = obfuscation::encrypt_kad_packet(
            packet,
            target_id,
            sender_key.key,
            receiver_key_val,
        );
        socket.send_to(&encrypted, addr).await
    } else {
        socket.send_to(packet, addr).await
    };
    if let Err(e) = &result {
        debug!("UDP send to {addr} failed: {e}");
    }
    result
}

/// Resolve the KAD id to trust for a store-side operation. We prefer the
/// KAD id already in our routing table for the source IP:port, because that
/// entry was either added after a successful Hello (verified path) or from
/// nodes.dat (booted from disk). We only fall back to the wire `claimed`
/// value when we have no contact at that address, which is the common case
/// for unsolicited publish requests. This stops a single IP from writing
/// per-sender entries under arbitrary KAD IDs to poison the store.
/// Identity we use for DHT store accounting when a publish arrives from a
/// peer whose `claimed` `KadId` we can't cross-check against the routing
/// table. K6: the previous behaviour was to trust the wire value, which
/// let one IP rotate claimed IDs on every publish to occupy many logical
/// publisher slots. We now derive a deterministic-but-unspoofable ID by
/// hashing `(ip, port)` into the 128-bit KadId space so the same peer
/// always resolves to the same synthetic identity regardless of what
/// they claim on the wire.
fn resolve_verified_sender_id(
    state: &NetworkState,
    from: SocketAddr,
    claimed: &KadId,
) -> KadId {
    let v4 = match from.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => return *claimed,
    };
    if let Some(c) = state.routing_table.all_contacts()
        .find(|c| c.ip == v4 && c.udp_port == from.port())
    {
        return c.id;
    }
    // Unknown sender — synthesize a stable ID from the socket pair.
    // MD5 is enough here: we're hashing into an opaque 16-byte identity
    // namespace, not making a cryptographic claim. Prefix distinguishes
    // these synthetic IDs in logs / debug tools.
    use digest::Digest;
    let mut h = md5::Md5::new();
    h.update(b"ember-kad-unknown-sender-v1");
    h.update(v4.octets());
    h.update(from.port().to_le_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest);
    KadId(bytes)
}

async fn send_kad_response(
    socket: &UdpSocket,
    packet: &[u8],
    addr: SocketAddr,
    state: &NetworkState,
    target_id: Option<&KadId>,
    peer_udp_key: Option<KadUDPKey>,
) -> std::io::Result<usize> {
    let their_ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => u32::from(ip),
        _ => 0,
    };
    let receiver_key_val = peer_udp_key
        .filter(|k| k.is_valid())
        .map(|k| k.get_key_value(their_ip))
        .unwrap_or_else(|| {
            target_id
                .and_then(|id| state.routing_table.get_contact(id))
                .and_then(|c| c.udp_key)
                .filter(|k| k.is_valid())
                .map(|k| k.get_key_value(their_ip))
                .unwrap_or(0)
        });
    let target_kad_id = target_id.copied();
    let use_obfuscation = state.obfuscation_enabled
        && target_kad_id.is_some()
        && (receiver_key_val != 0
            || target_id
                .and_then(|id| state.routing_table.get_contact(id))
                .map(|c| c.supports_obfuscation())
                .unwrap_or(false));
    let result = if use_obfuscation {
        if let Some(kad_id) = target_kad_id {
            let sender_key = KadUDPKey::generate(state.udp_key_seed, their_ip).key;
            let encrypted = obfuscation::encrypt_kad_packet(
                packet,
                &kad_id,
                sender_key,
                receiver_key_val,
            );
            socket.send_to(&encrypted, addr).await
        } else {
            socket.send_to(packet, addr).await
        }
    } else {
        socket.send_to(packet, addr).await
    };
    if let Err(e) = &result {
        debug!("UDP response to {addr} failed: {e}");
    }
    result
}

fn kad_request_opcode(msg: &KadMessage) -> Option<u8> {
    match msg {
        KadMessage::BootstrapReq => Some(kad::messages::KADEMLIA2_BOOTSTRAP_REQ),
        KadMessage::HelloReq { .. } => Some(kad::messages::KADEMLIA2_HELLO_REQ),
        KadMessage::HelloRes { .. } => Some(kad::messages::KADEMLIA2_HELLO_RES),
        KadMessage::KadReq { .. } => Some(kad::messages::KADEMLIA2_REQ),
        KadMessage::SearchKeyReq { .. } => Some(kad::messages::KADEMLIA2_SEARCH_KEY_REQ),
        KadMessage::SearchSourceReq { .. } => Some(kad::messages::KADEMLIA2_SEARCH_SOURCE_REQ),
        KadMessage::SearchNotesReq { .. } => Some(kad::messages::KADEMLIA2_SEARCH_NOTES_REQ),
        KadMessage::PublishKeyReq { .. } => Some(kad::messages::KADEMLIA2_PUBLISH_KEY_REQ),
        KadMessage::PublishSourceReq { .. } => Some(kad::messages::KADEMLIA2_PUBLISH_SOURCE_REQ),
        KadMessage::PublishNotesReq { .. } => Some(kad::messages::KADEMLIA2_PUBLISH_NOTES_REQ),
        KadMessage::FindBuddyReq { .. } => Some(kad::messages::KADEMLIA_FINDBUDDY_REQ),
        KadMessage::CallbackReq { .. } => Some(kad::messages::KADEMLIA_CALLBACK_REQ),
        KadMessage::Ping => Some(kad::messages::KADEMLIA2_PING),
        _ => None,
    }
}

async fn send_kad_search_results(
    socket: &UdpSocket,
    addr: SocketAddr,
    state: &NetworkState,
    sender_id: KadId,
    target: KadId,
    results: &[kad::messages::SearchResultEntry],
    peer_udp_key: Option<KadUDPKey>,
) {
    if results.is_empty() {
        return;
    }

    const HEADER_OVERHEAD: usize = 50;
    const MAX_BATCH: usize = kad::messages::UDP_KAD_MAXFRAGMENT;
    let mut batch: Vec<kad::messages::SearchResultEntry> = Vec::new();
    let mut batch_est_size: usize = HEADER_OVERHEAD;

    for entry in results {
        let entry_est = 16 + entry.tags.len() * 24 + 8;
        if batch_est_size + entry_est > MAX_BATCH && !batch.is_empty() {
            let msg = KadMessage::SearchRes {
                sender_id,
                target,
                results: std::mem::take(&mut batch),
            };
            if let Ok(packet) = messages::encode_packet(&msg) {
                let _ = send_kad_response(socket, &packet, addr, state, None, peer_udp_key).await;
            }
            batch_est_size = HEADER_OVERHEAD;
        }
        batch_est_size += entry_est;
        batch.push(entry.clone());
    }

    if !batch.is_empty() {
        let msg = KadMessage::SearchRes {
            sender_id,
            target,
            results: batch,
        };
        if let Ok(packet) = messages::encode_packet(&msg) {
            let _ = send_kad_response(socket, &packet, addr, state, None, peer_udp_key).await;
        }
    }
}

fn build_kad_connect_options(state: &NetworkState) -> u8 {
    let supports_crypt = state.obfuscation_enabled as u8;
    let requests_crypt = state.obfuscation_enabled as u8;
    let requires_crypt = 0u8;
    let direct_udp_callback = (state.firewalled && !state.udp_firewalled && state.udp_fw_verified) as u8;
    (direct_udp_callback << 3) | (requires_crypt << 2) | (requests_crypt << 1) | supports_crypt
}

/// Mutate `state.external_ip` AND publish the change to the shared atomic
/// that long-lived subsystems (e.g. the upload listener's HelloAnswer path)
/// read without holding a lock. Always use this instead of assigning to
/// `state.external_ip` directly so the two views never drift. `None` clears
/// the atomic back to `0`, which the Hello builder interprets as "advertise
/// client_id=0 and let the peer's BaseClient auto-heal from the connect IP"
/// — correct fallback behavior when we don't yet have a trusted public IP.
fn set_external_ip(state: &mut NetworkState, ip: Option<Ipv4Addr>) {
    state.external_ip = ip;
    let client_id_le = match ip {
        Some(v4) => u32::from_le_bytes(v4.octets()),
        None => 0,
    };
    state
        .external_ip_shared
        .store(client_id_le, std::sync::atomic::Ordering::Relaxed);
}

fn update_publish_manager_state(state: &mut NetworkState) {
    state.publish_manager.firewalled = state.firewalled;
    state.publish_manager.use_extern_kad_port = matches!(state.external_udp_port, Some(port) if port != 0 && port != state.udp_port);
    state.publish_manager.direct_udp_callback = state.firewalled && !state.udp_firewalled && state.udp_fw_verified;
    state.publish_manager.connect_options = build_kad_connect_options(state);

    if let Some(buddy) = state.buddy_manager.buddy_id().cloned() {
        state.publish_manager.buddy_id = Some(buddy);
        if let Some((ip, tcp_port)) = state.buddy_manager.buddy_addr() {
            state.publish_manager.buddy_ip = u32::from_be_bytes(ip.octets());
            let buddy_udp = state.routing_table.get_contact(&buddy)
                .map(|c| c.udp_port)
                .unwrap_or_else(|| tcp_port.saturating_add(3));
            state.publish_manager.buddy_port = buddy_udp;
        }
    } else {
        state.publish_manager.buddy_id = None;
        state.publish_manager.buddy_ip = 0;
        state.publish_manager.buddy_port = 0;
    }
}

fn dispatch_udp_firewall_probe_requests(state: &mut NetworkState, settings: &AppSettings) {
    if !state.firewall_checker.needs_udp_firewall_probes() {
        return;
    }
    let external_udp_port = state
        .firewall_checker
        .external_udp_port()
        .filter(|&p| p > 0)
        .or(state.external_udp_port)
        .unwrap_or(settings.udp_port);

    // Prefer contacts that report open TCP (kad_options bit 1 clear).
    // Contacts with kad_options == 0 haven't reported status; put them second.
    let mut candidates: Vec<KadContact> = state
        .routing_table
        .all_contacts()
        .filter(|c| {
            c.verified
                && !c.is_dead()
                && c.version > KADEMLIA_VERSION5_48A
                && c.tcp_port > 0
                && !c.is_tcp_firewalled()
                && !state.firewall_checker.is_udp_firewall_check_ip(c.ip)
        })
        .cloned()
        .collect();
    // Sort: contacts with known-open TCP first (kad_options reported & not firewalled),
    // then contacts with unknown status (kad_options == 0).
    candidates.sort_by_key(|c| if c.kad_options != 0 { 0u8 } else { 1u8 });
    let contacts: Vec<KadContact> = candidates.into_iter().take(4).collect();

    if !contacts.is_empty() {
        info!("Dispatching {} UDP firewall probe(s) (ext_udp_port={})", contacts.len(), external_udp_port);
    }
    let external_ip = state.external_ip;
    let obfuscation_enabled = settings.obfuscation_enabled;
    for contact in contacts {
        state.firewall_checker.record_udp_firewall_request_sent(contact.ip);
        spawn_udp_firewall_probe_request(
            contact,
            state.user_hash,
            settings.nickname.clone(),
            state.tcp_port,
            state.udp_port,
            external_udp_port,
            state.udp_key_seed,
            external_ip,
            obfuscation_enabled,
        );
    }
}

fn spawn_udp_firewall_probe_request(
    contact: KadContact,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    external_udp_port: u16,
    udp_key_seed: u32,
    external_ip: Option<Ipv4Addr>,
    obfuscation_enabled: bool,
) {
    let contact_ip = contact.ip;
    let contact_tcp = contact.tcp_port;
    tokio::spawn(async move {
        match send_udp_firewall_probe_request(
            contact,
            user_hash,
            nickname,
            tcp_port,
            udp_port,
            external_udp_port,
            udp_key_seed,
            external_ip,
            obfuscation_enabled,
        )
        .await
        {
            Ok(()) => debug!("UDP firewall probe sent to {}:{} (asking for reply on ports {}/{})",
                contact_ip, contact_tcp, udp_port, external_udp_port),
            // Probe failures are routine — Windows surfaces remote
            // ICMP-unreachable as `os error 10054`, which just means the
            // peer's UDP port is closed (very common for stale routing
            // contacts). Each cycle dispatches several probes and we
            // only need *one* successful peer to confirm not-firewalled,
            // so per-probe failures are debug-only. The aggregate
            // outcome is logged separately as "UDP firewall test
            // passed/failed".
            Err(e) => debug!("UDP firewall probe to {}:{} failed: {e}", contact_ip, contact_tcp),
        }
    });
}

async fn send_udp_firewall_probe_request(
    contact: KadContact,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    external_udp_port: u16,
    udp_key_seed: u32,
    external_ip: Option<Ipv4Addr>,
    obfuscation_enabled: bool,
) -> anyhow::Result<()> {
    let addr = SocketAddr::new(contact.ip.into(), contact.tcp_port);
    let stream = tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timeout to {addr}"))??;
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);

    let our_client_id = external_ip
        .map(|ip| u32::from_le_bytes(ip.octets()))
        .unwrap_or(0);
    let hello = ed2k::messages::build_hello_with_buddy(
        &user_hash,
        our_client_id,
        tcp_port,
        udp_port,
        &nickname,
        None,
    );
    write_ed2k_packet_simple(&mut writer, OP_EDONKEYHEADER, ed2k::messages::OP_HELLO, &hello).await?;

    let (proto, opcode, _) = read_ed2k_packet_simple(&mut reader).await?;
    if proto != OP_EDONKEYHEADER || opcode != ed2k::messages::OP_HELLOANSWER {
        anyhow::bail!("expected HelloAnswer from {addr}, got proto=0x{proto:02X} op=0x{opcode:02X}");
    }

    let emule_info = ed2k::messages::build_emule_info(udp_port, obfuscation_enabled, None, None);
    write_ed2k_packet_simple(&mut writer, OP_EMULEPROT, ed2k::messages::OP_EMULEINFO, &emule_info).await?;

    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), read_ed2k_packet_simple(&mut reader)).await;

    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&udp_port.to_le_bytes());
    payload.extend_from_slice(&external_udp_port.to_le_bytes());
    let receiver_key = KadUDPKey::generate(udp_key_seed, u32::from(contact.ip)).key;
    payload.extend_from_slice(&receiver_key.to_le_bytes());
    write_ed2k_packet_simple(&mut writer, OP_EMULEPROT, ed2k::messages::OP_FWCHECKUDPREQ, &payload).await?;
    // Give the remote peer time to read and process the request before
    // we drop the TCP connection.  Without this, some clients abort
    // processing when they see the connection close immediately.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    Ok(())
}

async fn send_kad_udp_firewall_result(
    socket: &UdpSocket,
    state: &NetworkState,
    peer_ip: Ipv4Addr,
    internal_udp_port: u16,
    external_udp_port: u16,
    receiver_udp_key: u32,
) {
    let mut ports = vec![internal_udp_port];
    if external_udp_port != 0 && external_udp_port != internal_udp_port {
        ports.push(external_udp_port);
    }

    for port in ports {
        if port == 0 {
            continue;
        }
        let msg = KadMessage::FirewallUdp {
            error_code: 0,
            udp_port: port,
        };
        let Ok(packet) = messages::encode_packet(&msg) else {
            continue;
        };
        let addr = SocketAddr::new(peer_ip.into(), port);
        let result = if receiver_udp_key != 0 {
            let sender_key = KadUDPKey::generate(state.udp_key_seed, u32::from(peer_ip)).key;
            let encrypted = obfuscation::encrypt_kad_packet(
                &packet,
                &KadId::zero(),
                sender_key,
                receiver_udp_key,
            );
            socket.send_to(&encrypted, addr).await
        } else {
            socket.send_to(&packet, addr).await
        };
        if let Err(e) = result {
            debug!("Failed to send FirewallUdp result to {addr}: {e}");
        }
    }
}

async fn read_ed2k_packet_simple(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 5_000_000 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid packet length: {length}"),
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length.saturating_sub(1);
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok((protocol, opcode, payload))
}

async fn write_ed2k_packet_simple(
    writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let length = (1 + payload.len()) as u32;
    writer.write_u8(protocol).await?;
    writer.write_u32_le(length).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn handle_udp_packet(
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
) {
    // Reject oversized packets (max 64 KiB for UDP)
    if data.len() > 65535 {
        debug!("Dropping oversized packet from {from}: {} bytes", data.len());
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
    if state.ip_filter.is_blocked_readonly(from_ipv4) {
        debug!("Dropping UDP packet from blocked IP {from}");
        return;
    }
    if state.banned_ips.contains(&from_ipv4) {
        debug!("Dropping UDP packet from banned peer {from}");
        return;
    }

    // Handle eMule peer-to-peer and server UDP packets
    let header = data.first().copied().unwrap_or(0);
    if header == OP_EDONKEYHEADER || header == OP_EMULEPROT {
        if data.len() >= 2 {
            let opcode = data[1];
            let payload = &data[2..];

            if opcode == OP_PORTTEST {
                debug!("Received UDP Port Test from {from}");
                let maybe_tx = {
                    let waiters = active_port_tests.lock().await;
                    waiters.get(&std::net::IpAddr::V4(from_ipv4)).cloned()
                };
                if let Some(tx) = maybe_tx {
                    let _ = tx.send(()).await;
                }
                return;
            }

            // eMule UDP reask: peer asks if we still have a file and what their queue rank is
            if header == OP_EMULEPROT && opcode == ed2k::messages::OP_REASKFILEPING && payload.len() >= 16 {
                let mut file_hash = [0u8; 16];
                file_hash.copy_from_slice(&payload[..16]);
                let hash_hex = hex::encode(file_hash);

                let has_file = {
                    let idx = local_index.read().await;
                    idx.get_by_hash(&hash_hex).is_some()
                };

                if has_file {
                    // Compute the peer's real queue rank from the shared
                    // upload queue. If they're not currently queued (e.g.,
                    // just granted a slot or dropped), fall back to 0 which
                    // eMule-family clients interpret as "alive, not queued".
                    let rank = ed2k::upload::udp_queue_rank_for_peer(
                        upload_queue,
                        credit_manager,
                        local_index,
                        from.ip(),
                        &file_hash,
                    )
                    .await
                    .unwrap_or(0);
                    let mut resp = vec![OP_EMULEPROT, ed2k::messages::OP_REASKACK];
                    resp.extend_from_slice(&rank.to_le_bytes());
                    let _ = socket.send_to(&resp, from).await;
                    debug!(
                        "Answered UDP reask from {from} for {hash_hex}: file available, rank={rank}"
                    );
                } else {
                    let resp = vec![OP_EMULEPROT, ed2k::messages::OP_FILEREQANSNOFIL];
                    let _ = socket.send_to(&resp, from).await;
                    debug!("Answered UDP reask from {from} for {hash_hex}: file not found");
                }
                return;
            }

            // eMule UDP reask response: source confirms it has the file.
            if header == OP_EMULEPROT && opcode == ed2k::messages::OP_REASKACK {
                let rank = if payload.len() >= 2 {
                    Some(u16::from_le_bytes([payload[0], payload[1]]) as u32)
                } else {
                    None
                };
                // Accept both native IPv4 and IPv4-mapped IPv6 (::ffff:x.x.x.x)
                // so hosts that open IPv6 UDP sockets still get their queue
                // rank updated correctly.
                let v4_opt = match from.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                if let Some(v4) = v4_opt {
                    for pfs in state.per_file_sources.values_mut() {
                        for src in &mut pfs.sources {
                            if src.ip == v4 && src.udp_port == from.port() {
                                src.state = ed2k::sources::DownloadSourceState::OnQueue { rank };
                                src.state_changed = std::time::Instant::now();
                            }
                        }
                    }
                }
                debug!("UDP reask ACK from {from} (source alive)");
                return;
            }

            // eMule UDP: queue full or file not found responses
            if header == OP_EMULEPROT && (opcode == ed2k::messages::OP_QUEUEFULL_UDP || opcode == ed2k::messages::OP_FILEREQANSNOFIL || opcode == ed2k::messages::OP_FILENOTFOUND_UDP) {
                let v4_opt = match from.ip() {
                    IpAddr::V4(v4) => Some(v4),
                    IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                };
                if let Some(v4) = v4_opt {
                    let is_banned = state.banned_ips.contains(&v4);
                    for pfs in state.per_file_sources.values_mut() {
                        for src in &mut pfs.sources {
                            if src.ip == v4 && src.udp_port == from.port() {
                                if is_banned {
                                    src.state = ed2k::sources::DownloadSourceState::Banned;
                                    src.state_changed = std::time::Instant::now();
                                } else if opcode == ed2k::messages::OP_QUEUEFULL_UDP {
                                    src.state = ed2k::sources::DownloadSourceState::OnQueue { rank: None };
                                    src.state_changed = std::time::Instant::now();
                                } else {
                                    src.state = ed2k::sources::DownloadSourceState::Failed;
                                    src.state_changed = std::time::Instant::now();
                                    src.fail_count += 1;
                                }
                            }
                        }
                    }
                }
                debug!("UDP reask negative response (opcode 0x{opcode:02X}) from {from}");
                return;
            }

            // eMule UDP callback reask: Low-ID peer asks us to relay a reask
            if header == OP_EMULEPROT && opcode == ed2k::messages::OP_REASKCALLBACKUDP && payload.len() >= 16 {
                let mut file_hash = [0u8; 16];
                file_hash.copy_from_slice(&payload[..16]);
                debug!("Received OP_REASKCALLBACKUDP from {from} for file {}", hex::encode(file_hash));
                return;
            }
        }
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
        if state.ip_filter.is_blocked_readonly(ipv4) {
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
    if state.flood_protection.check_rate_limit_with_opcode(from.ip(), known_peer, opcode_hint) {
        debug!("Rate limit exceeded for {from} (opcode 0x{opcode_hint:02X}), dropping packet");
        return;
    }

    // K21: per-IP zlib-decompression budget. A malicious peer can send
    // compressed KAD packets all day and burn CPU on every one; the
    // per-packet MAX_DECOMPRESSED_SIZE caps one shot but nothing caps
    // aggregate throughput. Reject decompression when the IP is over its
    // 10-packets/sec budget for compressed traffic specifically.
    if data.first() == Some(&kad::messages::OP_KADEMLIAPACKEDPROT)
        && state.flood_protection.over_compressed_budget(from.ip())
    {
        debug!(
            "Dropping compressed KAD packet from {from}: per-IP decompression budget exhausted"
        );
        return;
    }

    let mut packet_sender_udp_key: Option<KadUDPKey> = None;
    let mut packet_valid_receiver_key = false;
    let msg = match messages::decode_packet(data) {
        Ok(m) => m,
        Err(_first_err) => {
            let receiver_vk = match from.ip() {
                std::net::IpAddr::V4(ip) => KadUDPKey::generate(state.udp_key_seed, u32::from(ip)).key,
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
                packet_sender_udp_key = decrypted.sender_udp_key;
                packet_valid_receiver_key = decrypted.valid_receiver_key;
                match messages::decode_packet(&decrypted.payload) {
                    Ok(m) => {
                        // Diagnostic: classify every successful decrypt+decode
                        // so the `Publish cycle:` log can distinguish
                        // "obfuscated path is broken" from "PublishRes
                        // specifically is missing" from "remote never sent".
                        state.obf_decoded_total =
                            state.obf_decoded_total.saturating_add(1);
                        if matches!(&m, KadMessage::PublishRes { .. }) {
                            state.publish_res_obf_decoded =
                                state.publish_res_obf_decoded.saturating_add(1);
                        }
                        debug!("Decrypted obfuscated KAD packet from {from} ({} bytes)", data.len());
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
                    debug!("Failed to decode KAD packet from {from} ({} bytes): {_first_err}", data.len());
                } else {
                    debug!("Unreadable packet from {from} ({} bytes, header 0x{header:02X})", data.len());
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
                warn!("Dropping unsolicited SearchRes from {from} (no matching outgoing SearchKeyReq)");
            } else if opcode == 0x5A {
                warn!("Dropping unsolicited FindBuddyRes from {from} (no matching tracked FindBuddyReq)");
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
            // eMule: GetBootstrapContacts returns 20 contacts from top buckets
            let contacts = state.routing_table.export_bootstrap_contacts(20);
            let res = KadMessage::BootstrapRes {
                sender_id: state.local_id,
                tcp_port: state.tcp_port,
                version: KADEMLIA_VERSION,
                contacts,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
            }
        }

        KadMessage::BootstrapRes {
            sender_id,
            tcp_port,
            version,
            contacts,
        } => {
            debug!(
                "BootstrapRes from {from}: {} contacts",
                contacts.len()
            );
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
            // them unverified and let the normal handshake / UDP-key
            // exchange flow promote them. Up to the first 8 contacts get
            // an immediate Hello via `contact_addrs` below to bootstrap
            // liveness; the rest wait to be verified lazily as they're
            // touched.
            let mut contact_addrs = Vec::new();
            for c in contacts {
                let addr = SocketAddr::new(c.ip.into(), c.udp_port);
                contact_addrs.push(addr);
                state.routing_table.insert(c);
            }

            // eMule Process_KADEMLIA2_BOOTSTRAP_RES: only adds contacts to routing
            // zone. Does NOT chain-bootstrap or send HelloReq to returned contacts.
            // The periodic bootstrap timer and self-lookup handle further discovery.

            // Send HelloReq only to the bootstrap node itself (not all returned contacts)
            let hello = KadMessage::HelloReq {
                sender_id: state.local_id,
                tcp_port: state.tcp_port,
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
                        if state.udp_firewalled { our_options |= 0x01; }
                        if state.firewalled { our_options |= 0x02; }
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
                let _ = send_kad_response(socket, &packet, from, state, Some(&sender_id), packet_sender_udp_key).await;
                debug!("Sent HelloReq to bootstrap node {from}");
            }

            let table_size = state.routing_table.len();
            debug!("Routing table now has {table_size} contacts");
            state.stats.connected_peers = table_size as u32;
            if state.stats.status != NetworkStatus::Connected {
                state.stats.status = NetworkStatus::Connected;
                let _ = app_handle.emit("network-status", NetworkStatus::Connected);
            }

            // eMule: first FindNode(self) only after MIN2S(3) from KAD start (not on first packet).
            const SELF_LOOKUP_FIRST_DELAY_SECS: i64 = 3 * 60;
            let now_ts = chrono::Utc::now().timestamp();
            if !state.self_lookup_done
                && table_size >= 2
                && now_ts >= state.kad_started_at + SELF_LOOKUP_FIRST_DELAY_SECS
            {
                let closest = state.routing_table.find_closest(&state.local_id, SEARCH_INITIAL_CONTACTS);
                if !closest.is_empty() {
                    let sid = state.search_manager.start_search(
                        state.local_id,
                        SearchType::FindNode,
                        closest,
                    );
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
            let kad_options = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_KADMISCOPTIONS)))
                .and_then(|t| t.uint8_value().or_else(|| t.uint16_value().map(|v| v as u8)).or_else(|| t.uint32_value().map(|v| v as u8)))
                .unwrap_or(0);
            let peer_udp_firewalled = kad_options & 0x01 != 0;

            let valid_receiver_key = packet_valid_receiver_key;
            let received_hello_port = tags.iter()
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
                debug!("Not adding UDP-firewalled contact {} from {}", sender_id, from);
            }

            if let Some(nick) = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_FILENAME)))
                .and_then(|t| t.string_value())
            {
                let sanitized = crate::security::sanitize_display_name(nick);
                if !sanitized.is_empty() {
                    state.peer_nicknames.insert(sender_id, sanitized);
                }
            }

            // If valid receiver key, also explicitly verify in routing table
            if valid_receiver_key {
                state.routing_table.mark_verified(&sender_id);
            }

            // Build our firewall options + UDP verify key for the peer
            // Bit 0: UDP firewalled, bit 1: TCP firewalled, bit 2: request ACK
            // eMule: only request ACK if the contact was added and not yet verified
            let needs_ack = !valid_receiver_key && version >= KADEMLIA_VERSION8_49B;
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
                if state.udp_firewalled { our_options |= 0x01; }
                if state.firewalled { our_options |= 0x02; }
                if needs_ack { our_options |= 0x04; }
                res_tags.push(KadTag {
                    name: TagName::Id(TAG_KADMISCOPTIONS),
                    value: TagValue::Uint8(our_options),
                });
            }

            let res = KadMessage::HelloRes {
                sender_id: state.local_id,
                tcp_port: state.tcp_port,
                version: KADEMLIA_VERSION,
                tags: res_tags,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                state.flood_protection.track_request(from, 0x19);
                let _ = send_kad_response(socket, &packet, from, state, Some(&sender_id), packet_sender_udp_key).await;
            }

            if !valid_receiver_key && version <= KADEMLIA_VERSION7_49A {
                let ping = KadMessage::Ping;
                if let Ok(packet) = messages::encode_packet(&ping) {
                    state.flood_protection.track_request(from, 0x60);
                    let _ = send_kad_response(socket, &packet, from, state, Some(&sender_id), packet_sender_udp_key).await;
                }
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

            let kad_options = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_KADMISCOPTIONS)))
                .and_then(|t| t.uint8_value().or_else(|| t.uint16_value().map(|v| v as u8)).or_else(|| t.uint32_value().map(|v| v as u8)))
                .unwrap_or(0);
            let peer_udp_firewalled = kad_options & 0x01 != 0;

            let valid_receiver_key = packet_valid_receiver_key;

            let now = chrono::Utc::now().timestamp();
            let received_hello_port = tags.iter()
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
                debug!("Not adding UDP-firewalled contact {} from HelloRes ({from})", sender_id);
            }

            // If valid receiver key, also verify the contact in the routing table
            if valid_receiver_key {
                state.routing_table.mark_verified(&sender_id);
            }
            state.stats.connected_peers = state.routing_table.len() as u32;

            let nick = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_FILENAME)))
                .and_then(|t| t.string_value())
                .map(|n| crate::security::sanitize_display_name(n))
                .unwrap_or_default();

            if !nick.is_empty() {
                state.peer_nicknames.insert(sender_id, nick.clone());
            }

            // eMule: if the remote requested an ACK (bit 2 of kad_options), send HelloResAck
            let wants_ack = kad_options & 0x04 != 0;
            if wants_ack {
                if packet_sender_udp_key.is_none() {
                    warn!("Ignoring HelloRes ACK request from {from}: packet did not include a sender UDP key");
                }
                let ack = KadMessage::HelloResAck {
                    sender_id: state.local_id,
                    tags: Vec::new(),
                };
                if packet_sender_udp_key.is_some() {
                    if let Ok(packet) = messages::encode_packet(&ack) {
                        let _ = send_kad_response(socket, &packet, from, state, Some(&sender_id), packet_sender_udp_key).await;
                    }
                }
            }

            // Persist peer to database
            let peer_info = PeerInfo {
                id: hex::encode(sender_id.0),
                addresses: vec![format!("{}:{}", ip, tcp_port)],
                nickname: nick,
                last_seen: now,
                files_shared: 0,
                banned: false,
            };
            if let Err(e) = db.save_peer(&peer_info) {
                debug!("Failed to persist peer: {e}");
            }
        }

        KadMessage::HelloResAck { sender_id, tags: _ } => {
            let sender_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            if !packet_valid_receiver_key {
                warn!("Ignoring HelloResAck from {from}: invalid receiver key");
                return;
            }
            let valid_sender = state
                .routing_table
                .get_contact(&sender_id)
                .map(|contact| contact.ip == sender_ip)
                .unwrap_or(false);
            if !valid_sender {
                warn!("Ignoring HelloResAck from {from}: sender {} does not match routing table", sender_id);
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
                let closest = state
                    .routing_table
                    .find_closest_verified_by_type(&target, requested_count, 2);
                let res = KadMessage::KadRes {
                    target,
                    contacts: closest,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
                }
            }
        }

        KadMessage::KadRes { target, contacts } => {
            debug!("KadRes from {from}: {} contacts for target {target}", contacts.len());

            // eMule Process_KADEMLIA2_RES: verify we have an active search for this target.
            let expected = state.search_manager.get_expected_response_count(&target);
            if expected == 0 {
                debug!("  No active search for target {target}, ignoring response");
                return;
            }
            // eMule accepts up to KADEMLIA_FIND_NODE (11) contacts in any response.
            // GetRequestContactCount controls what we *ask for*, not what we accept.
            // Peers commonly return more contacts than requested (e.g. 4 for a
            // FIND_VALUE request asking for 2).
            if contacts.len() > KADEMLIA_FIND_NODE as usize {
                warn!("KadRes from {from}: contact count {} exceeds max {}, ignoring", contacts.len(), KADEMLIA_FIND_NODE);
                return;
            }

            // Route response to the specific search that queried this sender,
            // not all searches sharing the same target (fixes double-counting).
            let sender_ip_port: Option<(Ipv4Addr, u16)> = match from.ip() {
                std::net::IpAddr::V4(v4) => Some((v4, from.port())),
                _ => None,
            };

            let owning_sid: Option<SearchId> = sender_ip_port.and_then(|(ip, port)| {
                state.search_manager.active.iter()
                    .filter(|(_, s)| s.target == target && !s.completed)
                    .find(|(_, s)| s.tried.contains_key(&(ip, port)))
                    .map(|(id, _)| *id)
            });

            let search_ids: Vec<SearchId> = if let Some(sid) = owning_sid {
                vec![sid]
            } else {
                // Fallback: no search claims this sender via tried — pick the most recent one.
                let mut candidates: Vec<SearchId> = state.search_manager.active.iter()
                    .filter(|(_, s)| s.target == target && !s.completed)
                    .map(|(id, _)| *id)
                    .collect();
                candidates.sort_by(|a, b| b.0.cmp(&a.0));
                candidates.truncate(1);
                candidates
            };

            if search_ids.is_empty() {
                debug!("  No active search for this target");
            }

            for sid in search_ids {
                let sender_id = sender_ip_port.and_then(|(ip, port)| {
                    state.search_manager.active.get(&sid)
                        .and_then(|s| s.tried.get(&(ip, port)).copied())
                }).or_else(|| {
                    sender_ip_port.and_then(|(ip, port)| {
                        state.routing_table.all_contacts()
                            .find(|c| c.ip == ip && c.udp_port == port)
                            .map(|c| c.id)
                    })
                });

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

                    let safe_contacts: Vec<KadContact> = contacts.iter()
                        .filter(|c| {
                            // eMule: reject Kad1 contacts (version <= 1)
                            if !c.is_kad2() {
                                return false;
                            }
                            // eMule: reject DNS port 53 for old versions
                            if c.udp_port == 53 && c.version <= KADEMLIA_VERSION5_48A {
                                return false;
                            }
                            if state.ip_filter.is_blocked(c.ip)
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
                                    debug!("KadRes: >2 contacts from subnet {}.{}.{}.0, ignoring {}", o[0], o[1], o[2], c.ip);
                                    return false;
                                }
                            }
                            true
                        })
                        .cloned()
                        .collect();
                    debug!("  Search {}: processing {} contacts from {} ({} filtered)", sid.0, safe_contacts.len(), sender_id, contacts.len() - safe_contacts.len());
                    search.handle_response(&sender_id, safe_contacts.clone());

                    // eMule behavior: for FindBuddy searches, send FindBuddyReq
                    // to EVERY node that responds during the lookup, not just the
                    // final closest at convergence.
                    if matches!(search.search_type, SearchType::FindBuddy)
                        && search.phase == SearchPhase::Lookup
                        && state.buddy_manager.state() == BuddyState::FindingBuddy
                    {
                        let buddy_target = state.buddy_manager.find_buddy_target();
                        let user_id = KadId(cuint128_swap(&state.user_hash));
                        let local_tcp = state.buddy_manager.tcp_port();
                        let msg = KadMessage::FindBuddyReq {
                            buddy_id: buddy_target,
                            user_id,
                            tcp_port: local_tcp,
                        };
                        if let Ok(packet) = messages::encode_packet(&msg) {
                            state.flood_protection.track_request(from, 0x51);
                            let _ = send_kad_packet(
                                socket, &packet, from, state, &sender_id,
                            ).await;
                        }
                    }

                    for c in &safe_contacts {
                        state.routing_table.insert(c.clone());
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
                from, target, results.len()
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
                    i, hex::encode(raw_md4), entry.tags.len(), sources_val, has_name, src_ip
                );
            }

            // Route response to the specific search that queried this sender.
            let sender_ip_port: Option<(Ipv4Addr, u16)> = match from.ip() {
                std::net::IpAddr::V4(v4) => Some((v4, from.port())),
                _ => None,
            };

            let owning_sid: Option<SearchId> = sender_ip_port.and_then(|(ip, port)| {
                state.search_manager.active.iter()
                    .filter(|(_, s)| s.target == target && !s.completed)
                    .find(|(_, s)| s.tried.contains_key(&(ip, port)))
                    .map(|(id, _)| *id)
            });

            let search_ids: Vec<SearchId> = if let Some(sid) = owning_sid {
                vec![sid]
            } else {
                let mut candidates: Vec<SearchId> = state.search_manager.active.iter()
                    .filter(|(_, s)| s.target == target && !s.completed)
                    .map(|(id, _)| *id)
                    .collect();
                candidates.sort_by(|a, b| b.0.cmp(&a.0));
                candidates.truncate(1);
                candidates
            };

            if search_ids.is_empty() {
                debug!("  No active search for this target");
            }

            for sid in search_ids {
                let resolved_sender_id = sender_ip_port.and_then(|(ip, port)| {
                    state.search_manager.active.get(&sid)
                        .and_then(|s| s.tried.get(&(ip, port)).copied())
                }).or_else(|| {
                    sender_ip_port.and_then(|(ip, port)| {
                        state.routing_table.all_contacts()
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
                        sid.0, search.results.len(), unique.len(), search.phase
                    );
                } else {
                    debug!("Ignoring SearchRes from {from}: sender could not be resolved from queried contacts");
                }
            }
        }

        KadMessage::PublishRes { target, load } => {
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
            // different source *port* than the one we sent to because
            // the router rewrites the mapping; the IP stays stable. As a
            // last resort, match on target alone (consume any pending
            // entry for this target) — this accepts that the publish
            // was acknowledged even if we can't identify the exact peer,
            // which is what the counter is really measuring. Without
            // this, many networks silently show `0 confirmed` forever.
            let matched_key: Option<(KadId, SocketAddr)> = if state.publish_pending.contains_key(&(target, from)) {
                Some((target, from))
            } else {
                let from_ip = from.ip();
                state
                    .publish_pending
                    .keys()
                    .find(|(t, a)| *t == target && a.ip() == from_ip)
                    .copied()
                    .or_else(|| {
                        state
                            .publish_pending
                            .keys()
                            .find(|(t, _)| *t == target)
                            .copied()
                    })
            };
            if let Some(key) = matched_key {
                state.publish_pending.remove(&key);
                state.publish_confirmed += 1;
                debug!(
                    "Publish confirmed for {target} from {from} (orig_key={:?}, load={load}, total_confirmed={})",
                    key, state.publish_confirmed
                );
            } else {
                state.publish_res_unmatched = state.publish_res_unmatched.saturating_add(1);
                debug!(
                    "PublishRes from {from} for {target} matched no pending entry (load={load})"
                );
            }
            // Count this ack toward the file's "complete sources" estimate.
            // `target` for a source publish equals the file hash, so presence
            // in `source_publish_acks` both identifies source-publish acks and
            // filters out keyword-publish acks (whose target is a keyword hash).
            if let Some(count) = state.source_publish_acks.get_mut(&target) {
                *count = count.saturating_add(1);
                // K15: use the reported load to adapt source republish
                // frequency for this file hash. High load = back off.
                state.publish_manager.record_source_publish_load(&target, load);
            } else {
                // K15: keyword publish path. The target is a keyword hash,
                // not a file hash, so we route the feedback through the
                // keyword-search → file mapping we keep in
                // store_keyword_searches.
                if let Some((file, _)) = state.store_keyword_searches
                    .values()
                    .find(|(_, entries)| entries.iter().any(|(kw, _)| *kw == target))
                {
                    state
                        .publish_manager
                        .record_keyword_publish_load(&file.file_hash, load);
                }
            }
            // KAD v9+: acknowledge the PublishRes
            let ack = KadMessage::PublishResAck;
            if let Ok(packet) = messages::encode_packet(&ack) {
                let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
            }
            if load >= 100 {
                if let std::net::IpAddr::V4(ipv4) = from.ip() {
                    let now = chrono::Utc::now().timestamp();
                    state.overloaded_nodes.insert(ipv4, now);
                    info!("Node {from} reported full load, will avoid publishing to it for 10 min");
                }
            } else if load > 80 {
                warn!("High DHT load ({load}) from {from} for target {target}");
            }
        }

        KadMessage::Ping => {
            let pong = KadMessage::Pong { udp_port: from.port() };
            if let Ok(packet) = messages::encode_packet(&pong) {
                let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
            }
        }

        KadMessage::Pong { udp_port } => {
            debug!("Pong from {from} (reported udp_port={})", udp_port);
            if udp_port > 0 {
                state.firewall_checker.handle_pong(udp_port);
                if let Some(ext_port) = state.firewall_checker.external_udp_port() {
                    state.external_udp_port = Some(ext_port);
                }
                dispatch_udp_firewall_probe_requests(state, settings);
            }
            // K22: only promote a contact to verified when the Pong
            // carried our correct per-receiver UDP key (proves the sender
            // could decrypt/compose against our current key seed, not
            // just that their source address is reachable). This matches
            // eMule's own check before accepting an identity claim.
            if packet_valid_receiver_key {
                if let std::net::IpAddr::V4(v4) = from.ip() {
                    let contact_id = state.routing_table.all_contacts()
                        .find(|c| c.ip == v4 && c.udp_port == from.port())
                        .map(|c| c.id);
                    if let Some(contact) = contact_id {
                        state.routing_table.mark_verified(&contact);
                    }
                }
            }
            // USS RTT measurement: if this Pong is from our USS ping target, compute RTT
            if let Some(sent_at) = state.pending_uss_pings.remove(&from) {
                let rtt_ms = sent_at.elapsed().as_secs_f64() * 1000.0;
                if let Ok(mut queue) = state.uss_rtt_queue.try_lock() {
                    queue.push_back(rtt_ms);
                }
                state.uss_missed_pongs = 0;
                debug!("USS RTT from {from}: {rtt_ms:.1}ms");
            }
        }

        KadMessage::SearchKeyReq { target, start_position, search_terms } => {
            let search_expr = if search_terms.is_empty() {
                None
            } else {
                match parse_kad_search_expression(&search_terms) {
                    Some(expr) => Some(expr),
                    None => {
                        warn!("Ignoring SearchKeyReq from {from}: invalid restrictive search expression");
                        return;
                    }
                }
            };

            let mut results = state.dht_store.search_keywords(&target);
            if let Some(expr) = &search_expr {
                results.retain(|entry| matches_search_expr_for_entry(expr, entry));
            }

            {
                let index = local_index.read().await;
                for file in index.all_files() {
                    if results.len() >= 200 {
                        break;
                    }
                    let file_keywords = kad::publish::extract_keywords(&file.name);
                    let matches_keyword = file_keywords.iter().any(|kw| {
                        kad::publish::keyword_to_kad_id(kw) == target
                    });
                    if !matches_keyword {
                        continue;
                    }
                    if let Some(expr) = &search_expr {
                        if !matches_search_expr_for_local_file(expr, &file.name, file.size) {
                            continue;
                        }
                    }
                    if let Ok(raw_bytes) = hex::decode(&file.hash) {
                        let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
                        results.push(kad::messages::SearchResultEntry {
                            id: kad_hash,
                            tags: vec![
                                KadTag { name: TagName::Id(TAG_FILENAME), value: TagValue::String(file.name.clone()) },
                                KadTag { name: TagName::Id(TAG_FILESIZE), value: TagValue::Uint64(file.size) },
                                KadTag { name: TagName::Id(TAG_FILETYPE), value: TagValue::String(crate::search::index::infer_file_type(&file.extension)) },
                                KadTag { name: TagName::Id(TAG_SOURCES), value: TagValue::Uint32(1) },
                                KadTag { name: TagName::Id(TAG_COMPLETE_SOURCES), value: TagValue::Uint32(file.complete_sources.max(1)) },
                            ],
                        });
                    }
                }
            }
            let start = (start_position & 0x7FFF) as usize;
            let end = results.len().min(start + 200);
            let page = if start < results.len() { results[start..end].to_vec() } else { Vec::new() };

            if !page.is_empty() {
                send_kad_search_results(
                    socket,
                    from,
                    state,
                    state.local_id,
                    target,
                    &page,
                    packet_sender_udp_key,
                ).await;
            }
        }

        KadMessage::SearchSourceReq { target, start_position, file_size } => {
            let results = state.dht_store.search_sources(&target)
                .into_iter()
                .filter(|entry| matches_requested_file_size(entry, file_size))
                .collect::<Vec<_>>();
            let start = (start_position & 0x7FFF) as usize;
            let end = results.len().min(start + 200);
            let page = if start < results.len() { results[start..end].to_vec() } else { Vec::new() };

            // eMule behavior: do not send SearchRes when there are no results.
            if !page.is_empty() {
                send_kad_search_results(
                    socket,
                    from,
                    state,
                    state.local_id,
                    target,
                    &page,
                    packet_sender_udp_key,
                ).await;
            }
        }

        KadMessage::PublishKeyReq { target, entries } => {
            if state.udp_firewalled {
                // K14: we can't be a reliable DHT storage node while
                // firewalled, but silently dropping publishes makes the
                // publisher retry us forever. Send an explicit reject
                // with load=100 so they mark us "done" and move on.
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
                }
                return;
            }
            if !state.dht_store.is_within_tolerance(&target) {
                debug!("PublishKeyReq for {target} rejected - outside tolerance zone");
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
                }
            } else {
                // Identify the sender by IP:port from the routing table
                let sender_kad_id = {
                    let v4 = match from.ip() {
                        std::net::IpAddr::V4(v4) => v4,
                        _ => Ipv4Addr::UNSPECIFIED,
                    };
                    state.routing_table.all_contacts()
                        .find(|c| c.ip == v4 && c.udp_port == from.port())
                        .map(|c| c.id)
                        .unwrap_or_else(|| {
                            let mut id = KadId::zero();
                            let octets = v4.octets();
                            id.0[0] = octets[0]; id.0[1] = octets[1];
                            id.0[2] = octets[2]; id.0[3] = octets[3];
                            id
                        })
                };
                let load = state.dht_store.store_keyword_entries(&target, entries, &sender_kad_id);
                let res = KadMessage::PublishRes { target, load };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, Some(&sender_kad_id), packet_sender_udp_key).await;
                }
            }
        }

        KadMessage::PublishSourceReq { target, sender_id, tags } => {
            if state.udp_firewalled {
                // K14: see PublishKeyReq for the rationale; also emit a
                // reject PublishRes so the publisher stops retrying us.
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, Some(&sender_id), packet_sender_udp_key).await;
                }
                return;
            }
            // Bind the publishing identity to the UDP-authenticated contact
            // (IP:port). Trusting the wire sender_id lets an attacker poison
            // the storage index with arbitrary per-publisher keys; the routing
            // table match is only honoured when sender_id also matches the
            // entry we have for that address.
            let verified_sender_id = resolve_verified_sender_id(state, from, &sender_id);
            if !state.dht_store.is_within_tolerance(&target) {
                debug!("PublishSourceReq for {target} rejected - outside tolerance zone");
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, Some(&verified_sender_id), packet_sender_udp_key).await;
                }
            } else {
                let sender_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let load = state.dht_store.store_source_entry(
                    &target, verified_sender_id, tags, sender_ip, from.port(),
                );
                let res = KadMessage::PublishRes { target, load };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, Some(&verified_sender_id), packet_sender_udp_key).await;
                }
            }
        }

        KadMessage::PublishNotesReq { target, sender_id, ref tags } => {
            if state.udp_firewalled {
                // K14: emit a reject PublishRes so the publisher stops.
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, Some(&sender_id), packet_sender_udp_key).await;
                }
                return;
            }
            let verified_sender_id = resolve_verified_sender_id(state, from, &sender_id);
            // Tolerance check FIRST: if we're not responsible for this hash we
            // must not absorb the comment into our local view either. Letting
            // peers dump arbitrary per-hash comments into our UI without the
            // tolerance gate makes us a spam/comment-poisoning amplifier.
            if !state.dht_store.is_within_tolerance(&target) {
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, Some(&verified_sender_id), packet_sender_udp_key).await;
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
                        if let TagValue::Uint8(r) = tag.value {
                            note_rating = r;
                        }
                    }
                    _ => {}
                }
            }
            if note_rating > 0 || !note_comment.is_empty() {
                let hash_hex = target.to_hex();
                let peer_name = verified_sender_id.to_hex()[..8].to_string();
                use ed2k::comments::rating_name;
                debug!("Received peer note for {}: rating={} ({})", hash_hex, note_rating, rating_name(note_rating));
                state.comment_manager.write().await.add_peer_comment(&hash_hex, peer_name, note_rating, note_comment, 1);
            }
            let tags_owned = tags.clone();
            let load = state.dht_store.store_notes_entry(&target, verified_sender_id, tags_owned);
            let res = KadMessage::PublishRes { target, load };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = send_kad_response(socket, &packet, from, state, Some(&verified_sender_id), packet_sender_udp_key).await;
            }
        }

        KadMessage::SearchNotesReq { target, file_size } => {
            let results = state.dht_store.search_notes(&target)
                .into_iter()
                .filter(|entry| matches_requested_file_size(entry, file_size))
                .collect::<Vec<_>>();
            // eMule behavior: do not send SearchRes when there are no results.
            if !results.is_empty() {
                send_kad_search_results(
                    socket,
                    from,
                    state,
                    state.local_id,
                    target,
                    &results,
                    packet_sender_udp_key,
                ).await;
            }
        }

        KadMessage::PublishResAck => {
            state.stats.stores_acknowledged += 1;
            debug!(
                "PublishResAck from {from} (total stores acked: {})",
                state.stats.stores_acknowledged
            );
        }

        KadMessage::FirewalledReq { tcp_port: peer_tcp_port } => {
            // Return the requester's external IP as we see it
            let peer_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            let ip_raw = u32::from_be_bytes(peer_ip.octets());
            let res = KadMessage::FirewalledRes { ip: ip_raw };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
            }

            // K18: per-IP cooldown for the (expensive) TCP connect-back.
            // 60s is generous vs. eMule's 1-hour self-recheck cadence.
            // Also reject special-use / port-0 / port-53 destinations
            // so the connect-back path can't be abused as a reflective
            // TCP probe at arbitrary private hosts or DNS resolvers.
            const FIREWALL_REQ_COOLDOWN_SECS: i64 = 60;
            const MAX_FIREWALL_REQ_COOLDOWN_ENTRIES: usize = 4096;
            if peer_tcp_port == 0
                || peer_tcp_port == 53
                || crate::security::is_special_use_v4(peer_ip)
            {
                return;
            }
            let now = chrono::Utc::now().timestamp();
            // Prune stale entries lazily to keep the map bounded.
            if state.firewall_req_cooldown.len() >= MAX_FIREWALL_REQ_COOLDOWN_ENTRIES {
                state
                    .firewall_req_cooldown
                    .retain(|_, ts| now - *ts < FIREWALL_REQ_COOLDOWN_SECS);
            }
            if let Some(prev) = state.firewall_req_cooldown.get(&peer_ip) {
                if now - *prev < FIREWALL_REQ_COOLDOWN_SECS {
                    debug!(
                        "Skipping FirewalledReq connect-back to {peer_ip}: within {FIREWALL_REQ_COOLDOWN_SECS}s cooldown"
                    );
                    return;
                }
            }
            state.firewall_req_cooldown.insert(peer_ip, now);

            if peer_tcp_port > 0 {
                let tcp_addr = SocketAddr::new(peer_ip.into(), peer_tcp_port);
                let fw_sem = state.firewall_connect_semaphore.clone();
                tokio::spawn(async move {
                    let _permit = match fw_sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::net::TcpStream::connect(tcp_addr),
                    )
                    .await;
                    match result {
                        Ok(Ok(stream)) => {
                            debug!("Peer {tcp_addr} is reachable on TCP");
                            let (_r, w) = stream.into_split();
                            let mut writer = tokio::io::BufWriter::new(w);
                            let ack_packet = {
                                let mut pkt = Vec::with_capacity(6);
                                pkt.push(OP_EMULEPROT);
                                pkt.extend_from_slice(&1u32.to_le_bytes());
                                pkt.push(ed2k::messages::OP_KAD_FWTCPCHECK_ACK);
                                pkt
                            };
                            let _ = tokio::io::AsyncWriteExt::write_all(&mut writer, &ack_packet).await;
                            let _ = tokio::io::AsyncWriteExt::flush(&mut writer).await;
                        }
                        _ => debug!("Peer {tcp_addr} is NOT reachable on TCP"),
                    }
                });
            }
        }

        KadMessage::FirewalledRes { ip } => {
            let sender_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            if !state.firewall_checker.is_firewall_check_ip(sender_ip) {
                tracing::warn!("Ignoring unrequested FirewalledRes from {from}");
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
            state.firewall_checker.handle_firewalled_response(external_ip, sender_ip);

            // K8: only write state.external_ip once the firewall checker
            // has confirmed it (≥3 distinct /24 voters). The prior
            // "tentative" path let a single report write the global
            // external_ip, which propagates through credits, friend
            // payloads, logs — a Sybil-trivial vector. Downstream code
            // that needs a best-effort IP can still read
            // `firewall_checker.tentative_ip()` (see below) without
            // mutating shared state.
            let prev_ip = state.external_ip;
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

            if prev_ip.is_none() && state.external_ip.is_some() && state.nat_info.nat_type == ember::nat::NatType::Unknown {
                info!("External IP discovered via KAD — running initial NAT probe");
                state.nat_info = ember::nat::probe_nat(socket).await;
                // STUN can fail wholesale (firewall, DNS, blocked egress).
                // We still know our external IP from KAD votes, so fall
                // back to `PortRestricted` rather than leaving `Unknown`,
                // which would force every subsequent LowID-to-LowID
                // attempt straight into the relay path (see
                // `attempt_low_to_low()` — `is_punchable()` is false for
                // `Unknown`). Mirrors the same fallback already in the
                // server-HighID branch above.
                if let Some(ext_ip) = state.external_ip {
                    if state.nat_info.apply_highid_fallback(
                        std::net::IpAddr::V4(ext_ip),
                        state.udp_port,
                    ) {
                        info!(
                            "NAT probe failed but KAD confirmed external IP {} — assuming PortRestricted (mapped {}:{})",
                            ext_ip, ext_ip, state.udp_port,
                        );
                    }
                }
            }

            if state.external_ip.is_some() {
                let tcp_status = state.firewall_checker.tcp_status();
                let udp_status = state.firewall_checker.udp_status();
                let _ = app_handle.emit("firewall-status", serde_json::json!({
                    "firewalled": state.firewalled,
                    "external_ip": state.stats.external_ip,
                    "tcp_status": format!("{:?}", tcp_status),
                    "udp_status": format!("{:?}", udp_status),
                }));
            }
        }

        KadMessage::Firewalled2Req { tcp_port: peer_tcp_port, user_hash, connect_options } => {
            let ip_raw = match from.ip() {
                std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                _ => return,
            };
            let res = KadMessage::FirewalledRes { ip: ip_raw };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
            }
            if peer_tcp_port > 0 {
                let peer_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let tcp_addr = SocketAddr::new(peer_ip.into(), peer_tcp_port);
                let allow_obf = state.obfuscation_enabled && (connect_options & 0x01) != 0;
                let fw_sem = state.firewall_connect_semaphore.clone();
                tokio::spawn(async move {
                    let _permit = match fw_sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };
                    let connect_result = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::net::TcpStream::connect(tcp_addr),
                    ).await;
                    match connect_result {
                        Ok(Ok(stream)) => {
                            debug!("Peer {tcp_addr} is reachable on TCP (Firewalled2)");
                            let (r, w) = stream.into_split();
                            let mut reader = tokio::io::BufReader::new(r);
                            let mut writer = tokio::io::BufWriter::new(w);
                            let ack_packet = {
                                let mut pkt = Vec::with_capacity(6);
                                pkt.push(OP_EMULEPROT);
                                pkt.extend_from_slice(&1u32.to_le_bytes());
                                pkt.push(ed2k::messages::OP_KAD_FWTCPCHECK_ACK);
                                pkt
                            };
                            let write_res = if allow_obf && user_hash != [0u8; 16] {
                                match ed2k::tcp_obfuscation::negotiate_outgoing(&mut reader, &mut writer, &user_hash).await {
                                    Ok((recv_key, send_key)) => {
                                        let _obf_reader = tokio::io::BufReader::new(ed2k::tcp_obfuscation::Rc4Reader::new(reader, recv_key));
                                        let mut obf_writer = tokio::io::BufWriter::new(ed2k::tcp_obfuscation::Rc4Writer::new(writer, send_key));
                                        match obf_writer.write_all(&ack_packet).await {
                                            Ok(()) => obf_writer.flush().await,
                                            Err(e) => Err(e),
                                        }
                                    }
                                    Err(e) if (connect_options & 0x04) != 0 => Err(e),
                                    Err(_) => {
                                        drop(writer);
                                        drop(reader);
                                        match tokio::time::timeout(
                                            std::time::Duration::from_secs(5),
                                            tokio::net::TcpStream::connect(tcp_addr),
                                        ).await {
                                            Ok(Ok(plain_stream)) => {
                                                let mut pw = tokio::io::BufWriter::new(plain_stream);
                                                match pw.write_all(&ack_packet).await {
                                                    Ok(()) => pw.flush().await,
                                                    Err(e) => Err(e),
                                                }
                                            }
                                            Ok(Err(e)) => Err(e),
                                            Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "plain fallback connect timeout")),
                                        }
                                    },
                                }
                            } else {
                                match writer.write_all(&ack_packet).await {
                                    Ok(()) => writer.flush().await,
                                    Err(e) => Err(e),
                                }
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
            }
        }

        KadMessage::FirewallUdp { error_code, udp_port } => {
            debug!("FirewallUdp from {from}: error={error_code}, port={udp_port}");
            let sender_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            if !state.firewall_checker.is_udp_firewall_check_ip(sender_ip) {
                warn!("Ignoring unsolicited FirewallUdp from {from}");
                return;
            }
            let expected_internal = state.udp_port;
            let expected_external = state
                .firewall_checker
                .external_udp_port()
                .or(state.external_udp_port)
                .unwrap_or(0);
            if udp_port == 0
                || (udp_port != expected_internal && udp_port != expected_external)
            {
                warn!(
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
                state.stats.firewalled = state.firewalled;
                if udp_port > 0 {
                    state.external_udp_port = Some(udp_port);
                }
                state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
                state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
                let _ = app_handle.emit("firewall-status", serde_json::json!({
                    "firewalled": state.firewalled,
                    "external_ip": state.stats.external_ip,
                    "tcp_status": state.stats.tcp_status,
                    "udp_status": state.stats.udp_status,
                }));
                if !was_already_verified {
                    info!("UDP firewall test passed - UDP port {udp_port} is reachable, not UDP-firewalled");
                } else {
                    debug!("UDP firewall test: additional confirmation on port {udp_port} from {from}");
                }
            } else {
                state.firewall_checker.handle_udp_firewall_result(false);
                info!("UDP firewall test returned remote error from {from} on port {udp_port} (error={error_code})");
            }
        }

        KadMessage::FindBuddyReq { buddy_id, user_id, tcp_port: peer_tcp_port } => {
            debug!("FindBuddyReq from {from}: buddy_id={buddy_id}, user_id={user_id}");
            if !state.firewalled && !state.udp_firewalled && state.udp_fw_verified && !state.buddy_manager.is_serving() {
                let res = KadMessage::FindBuddyRes {
                    buddy_id,
                    user_hash: state.user_hash,
                    tcp_port: state.tcp_port,
                    connect_options: build_kad_connect_options(state),
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = send_kad_response(socket, &packet, from, state, None, packet_sender_udp_key).await;
                }
                info!("Offered to be buddy for {user_id} (tcp_port={})", peer_tcp_port);

                // Register this user's hash so the upload listener recognizes the incoming
                // buddy TCP connection (the firewalled client will connect to us).
                state.buddy_manager.register_pending_buddy(cuint128_swap(&user_id.0), buddy_id).await;
            }
        }

        KadMessage::FindBuddyRes { buddy_id, user_hash, tcp_port: peer_tcp_port, connect_options } => {
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
                warn!(
                    "Ignoring FindBuddyRes from {from}: unexpected buddy target {} (expected {:?})",
                    buddy_id, expected_buddy_target
                );
                return;
            }
            if peer_tcp_port == 0 {
                warn!("Ignoring FindBuddyRes from {from}: missing TCP port");
                return;
            }
            if state.buddy_manager.state() == BuddyState::FindingBuddy
                && state.pending_outgoing_buddy.is_none()
            {
                let buddy_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let allow_obfuscation = settings.obfuscation_enabled;
                let mut mgr_clone = BuddyManager::new(
                    state.buddy_manager.local_id().clone(),
                    state.user_hash,
                    settings.nickname.clone(),
                    state.tcp_port,
                    state.udp_port,
                    state.pending_buddy_hashes.clone(),
                );
                state.pending_outgoing_buddy = Some(tokio::spawn(async move {
                    match mgr_clone.handle_findbuddy_response(
                        buddy_id,
                        buddy_ip,
                        peer_tcp_port,
                        user_hash,
                        connect_options,
                        allow_obfuscation,
                    ).await {
                        Some((rx, writer, reader_handle)) => Some((buddy_id, buddy_ip, peer_tcp_port, rx, writer, reader_handle)),
                        None => None,
                    }
                }));
            }
        }

        KadMessage::CallbackReq { buddy_id, file_id, tcp_port: peer_tcp_port } => {
            debug!("CallbackReq from {from}: buddy_id={buddy_id}, file_id={file_id}");
            if let Some(serving_id) = state.buddy_manager.serving_for().cloned() {
                if serving_id != buddy_id {
                    debug!("Rejecting CallbackReq: buddy_id mismatch (expected {serving_id}, got {buddy_id})");
                } else {
                    let client_ip = match from.ip() {
                        std::net::IpAddr::V4(v4) => v4,
                        _ => return,
                    };
                    let relayed = state.buddy_manager.send_callback_relay(
                        &serving_id, client_ip, peer_tcp_port, file_id.0,
                    ).await;
                    if relayed {
                        debug!("Callback relayed via OP_CALLBACK to buddy");
                    } else {
                        warn!("Failed to relay callback to buddy");
                    }
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

async fn handle_command(
    socket: &UdpSocket,
    cmd: NetworkCommand,
    state: &mut NetworkState,
    local_index: &Arc<RwLock<LocalIndex>>,
    settings: &AppSettings,
    dl_event_tx: &mpsc::Sender<DownloadEvent>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    source_manager: &Arc<RwLock<SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    stats_manager: &mut StatsManager,
    known_files: &mut KnownFileList,
    _server_udp: &ServerUdpSocket,
    firewall_probe_ips: &upload_server::FirewallProbeSet,
    shared_banned_ips: &upload_server::SharedBannedIps,
    shared_banned_hashes: &upload_server::SharedBannedHashes,
    shared_server_addr: &Arc<RwLock<Option<SocketAddr>>>,
    shared_ember_payload: &ember::SharedEmberPayload,
    ember_payload_generation: &ember::EmberPayloadGeneration,
    geoip: &crate::geoip::GeoIpReader,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    ul_event_tx: &mpsc::Sender<upload_server::UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
    upload_queue: &ed2k::upload::UploadQueueRef,
) {
    match cmd {
        NetworkCommand::SearchFiles { query, method, request_id, tx, search_filters } => {
            if let Some(active) = state.active_search_request.take() {
                if active.request_id != request_id {
                    cancel_search_request(state, app_handle, active.request_id);
                }
            }

            let mut tx = Some(tx);
            let mut local_results: Option<Vec<SearchResult>> = Some(Vec::new());
            let file_type_filter = search_filters.as_ref().and_then(|f| f.file_type.clone());
            let mut active_request = ActiveSearchRequest {
                request_id,
                server_pending: false,
                kad_pending: false,
                udp_pending: false,
                file_type_filter: file_type_filter.clone(),
                keywords: Vec::new(),
                server_ip: state.server_addr.map(|a| a.ip().to_string()),
            };

            let keywords = kad::publish::extract_keywords(&query);
            if keywords.is_empty() {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(local_results.take().unwrap_or_default());
                }
                let _ = app_handle.emit(
                    "search-complete",
                    SearchCompleteEvent { request_id },
                );
                return;
            }
            active_request.keywords = keywords.clone();

            // Build the search expression once, reuse for TCP + UDP.
            // Single keyword → string leaf; multiple → AND tree; file-type
            // filter is AND-combined when present.
            let kad_file_type = search_filters.as_ref().and_then(|f| f.file_type.clone());
            let search_expr = kad::messages::build_search_expression(&keywords, kad_file_type.as_deref());

            // --- TCP server search ---
            let run_server = matches!(method, SearchMethod::Global | SearchMethod::Server);
            let run_udp    = matches!(method, SearchMethod::Global);
            let run_kad    = matches!(method, SearchMethod::Global | SearchMethod::Kad);

            if run_server && state.server_connected {
                if let Some(mut conn) = state.server_connection.take() {
                    match conn.send_search_expr_bytes(&search_expr).await {
                        Ok(()) => {
                            active_request.server_pending = true;
                            state.pending_server_search = Some(PendingServerSearch {
                                tx: None,
                                results: Vec::new(),
                                request_id,
                            });
                            state.server_search_age = 0;
                            info!("TCP server search started for '{query}'");
                        }
                        Err(e) => {
                            warn!("TCP server search failed to send: {e}");
                        }
                    }
                    state.server_connection = Some(conn);
                }
            }

            // --- UDP global search ---
            if run_udp {
                let servers = state.server_list.servers();
                for server in servers {
                    if let Some(pkt) = ServerUdpSocket::build_global_search_packet(server, &search_expr) {
                        state.udp_search_queue.push_back(pkt);
                    }
                }
                if !state.udp_search_queue.is_empty() {
                    active_request.udp_pending = true;
                    state.server_udp_search_age = 0;
                    info!("UDP global search queued for {} servers", state.udp_search_queue.len());
                }
            }

            // --- KAD search ---
            let kad_started = 'kad: {
                if !run_kad {
                    break 'kad false;
                }
                let Some(primary_keyword) = keywords.iter().max_by_key(|k| k.len()) else {
                    break 'kad false;
                };
                let keyword_hash = kad::publish::keyword_to_kad_id(primary_keyword);
                info!("Searching KAD ({} keywords) -> hash {}", keywords.len(), keyword_hash);

                let closest = state
                    .routing_table
                    .find_closest_prefer_verified(&keyword_hash, SEARCH_INITIAL_CONTACTS);

                if closest.is_empty() {
                    info!("KAD search: no closest contacts in routing table");
                    break 'kad false;
                }

                stats_manager.add_overhead(crate::storage::statistics::OverheadCategory::Kad, crate::storage::statistics::OverheadDirection::Upload, 64);
                let sid = state.search_manager.start_search(
                    keyword_hash,
                    SearchType::FindKeyword,
                    closest,
                );

                if sid == SearchId(0) {
                    info!("KAD search: rejected (too many active searches)");
                    break 'kad false;
                }
                if let Some(search) = state.search_manager.get_mut(&sid) {
                    search.search_terms_data = search_expr;
                }
                active_request.kad_pending = true;
                let Some(search_tx) = tx.take() else {
                    tracing::error!("KAD search: tx already consumed");
                    break 'kad false;
                };
                state.pending_keyword_searches.insert(sid, PendingKeywordSearch {
                    tx: search_tx,
                    local_results: local_results.take().unwrap_or_default(),
                    keywords,
                    request_id,
                    last_streamed_count: 0,
                    file_type_filter,
                });
                true
            };

            if !kad_started {
                if let Some(tx) = tx.take() {
                    let _ = tx.send(local_results.take().unwrap_or_default());
                }
                if !active_request.server_pending && !active_request.udp_pending {
                    let _ = app_handle.emit(
                        "search-complete",
                        SearchCompleteEvent { request_id },
                    );
                    return;
                }
            }

            state.active_search_request = Some(active_request);
        }

        NetworkCommand::CancelSearch { request_id } => {
            cancel_search_request(state, app_handle, request_id);
            info!("Cancelled search request {}", request_id);
        }

        NetworkCommand::CancelDownload { transfer_id, cleanup_ack } => {
            // eMule: CPartFile::DeletePartFile -> StopFile -> PauseFile ->
            //   CSearchManager::StopSearch(GetKadFileSearchID(), true)
            // Remove from pending_downloads so no new searches are started
            let removed_pending = state.pending_downloads.remove(&transfer_id);

            // Find and stop all active KAD source searches for this transfer
            let search_ids: Vec<SearchId> = state.download_source_searches.iter()
                .filter(|(_, (tid, _))| tid == &transfer_id)
                .map(|(sid, _)| *sid)
                .collect();
            for sid in &search_ids {
                state.download_source_searches.remove(sid);
                if let Some(removed) = state.search_manager.remove(sid) {
                    state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                }
            }

            state.active_source_senders.remove(&transfer_id);
            // Lockstep with the metadata sender (see field doc on
            // `active_established_senders`). Without this, a cancelled
            // download leaves a dead `EstablishedSource` channel
            // registered; future LowID callbacks for the same hash
            // would hit `Closed` on dispatch and waste a round.
            state.active_established_senders.remove(&transfer_id);
            state.active_source_overflow.remove(&transfer_id);
            state.active_kad_search_state.remove(&transfer_id);
            state.per_file_sources.remove(&transfer_id);
            if let Some(handle) = state.download_handles.remove(&transfer_id) {
                if cleanup_ack.is_none() {
                    // Stop path: preserve .part.met for resume
                    if let Ok(reg) = state.tracker_registry.lock() {
                        if let Some(tracker) = reg.get(&transfer_id) {
                            if let Ok(t) = tracker.try_read() { t.save(); }
                        }
                    }
                }
                handle.abort();
                let _ = handle.await;
            }
            if cleanup_ack.is_some() {
                if let Ok(mut reg) = state.tracker_registry.lock() {
                    reg.remove(&transfer_id);
                }
            }

            // Remove partial download from KAD source publish
            let cancel_hash = removed_pending.as_ref().map(|p| p.file_hash.clone())
                .or_else(|| {
                    // Not in pending — check transfer_manager for file hash
                    // (use try_read to avoid blocking the event loop)
                    transfer_manager.try_read().ok()
                        .and_then(|mgr| mgr.get_transfer(&transfer_id).map(|t| t.file_hash.clone()))
                });
            if let Some(fh) = cancel_hash {
                if let Ok(hb) = hex::decode(&fh) {
                    if hb.len() >= 16 {
                        let kad_hash = md4_bytes_to_kad_id(&hb[..16]);
                        state.publish_manager.remove_file(&kad_hash);
                        state.source_publish_acks.remove(&kad_hash);
                        let mut fh_arr = [0u8; 16];
                        fh_arr.copy_from_slice(&hb[..16]);
                        state.corruption_blackbox.remove_file(&fh_arr);
                        if let Ok(mut map) = state.aich_recovery_pending.write() {
                            map.retain(|(file_hash, _), _| *file_hash != fh_arr);
                        }
                    }
                }
            }

            if removed_pending.is_some() || !search_ids.is_empty() {
                info!(
                    "CancelDownload {}: removed pending_download={}, stopped {} KAD source search(es)",
                    transfer_id, removed_pending.is_some(), search_ids.len()
                );
            }

            if let Some(tx) = cleanup_ack {
                let _ = tx.send(());
            }
        }

        NetworkCommand::PauseDownload { transfer_id } => {
            // eMule PauseFile: tear down active network state but keep source
            // knowledge so the download can be resumed quickly.
            if let Some(handle) = state.download_handles.remove(&transfer_id) {
                if let Ok(reg) = state.tracker_registry.lock() {
                    if let Some(tracker) = reg.get(&transfer_id) {
                        if let Ok(t) = tracker.try_read() { t.save(); }
                    }
                }
                handle.abort();
            }
            state.active_source_senders.remove(&transfer_id);
            // Pause = worker is gone; keep both sender maps in lockstep
            // so a callback that arrives mid-pause doesn't try to
            // dispatch to a dead established channel.
            state.active_established_senders.remove(&transfer_id);
            state.active_source_overflow.remove(&transfer_id);
            state.active_kad_search_state.remove(&transfer_id);
            if let Some(pfs) = state.per_file_sources.get_mut(&transfer_id) {
                pfs.reset_active_states();
            }

            // Keep download_source_searches mappings alive so in-flight KAD
            // searches can still register discovered sources into
            // SourceManager when they complete. The search completion
            // handler checks `pending_downloads` to decide whether to start
            // the transfer; paused downloads STAY in `pending_downloads`
            // but have their `PendingDownload::control` marked paused, so
            // `try_start_pending_download_from_known_sources` guards against
            // starting them until resumed. (L4: earlier comment wrongly
            // said paused downloads are "removed from pending_downloads".)
            let in_flight = state.download_source_searches.values()
                .filter(|(tid, _)| tid == &transfer_id)
                .count();

            info!(
                "PauseDownload {}: aborted task, removed sender, {} in-flight KAD search(es) will drain naturally",
                transfer_id, in_flight
            );
        }

        NetworkCommand::StartDownload {
            file_hash,
            file_name,
            file_size,
            peer_ip,
            peer_port,
            transfer_id,
            control,
        } => {
            let has_source = !peer_ip.is_empty() && peer_ip != "0.0.0.0" && peer_port > 0;

            let publish_file_name = file_name.clone();
            let publish_ext = std::path::Path::new(&file_name)
                .extension()
                .map(|e| e.to_string_lossy().to_string())
                .unwrap_or_default();

            if has_source {
                let hash_bytes = match hex::decode(&file_hash) {
                    Ok(b) if b.len() == 16 => {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        error!("Invalid file hash: {file_hash}");
                        return;
                    }
                };
                let source_addr: SocketAddr = match format!("{peer_ip}:{peer_port}").parse() {
                    Ok(a) => a,
                    Err(e) => {
                        error!("Invalid peer address: {e}");
                        return;
                    }
                };

                {
                    let mut sm = source_manager.write().await;
                    if let std::net::IpAddr::V4(v4) = source_addr.ip() {
                        sm.register_source(hash_bytes, v4, source_addr.port());
                    }
                }
                let download_sources = {
                    let sm = source_manager.read().await;
                    let uh = if let std::net::IpAddr::V4(v4) = source_addr.ip() {
                        sm.get_user_hash(&hash_bytes, v4, source_addr.port())
                    } else { None };
                    let co = if let std::net::IpAddr::V4(v4) = source_addr.ip() {
                        sm.get_connect_options(&hash_bytes, v4, source_addr.port())
                    } else { None };
                    vec![DownloadSource {
                        peer_ip: peer_ip.clone(),
                        peer_port,
                        available_parts: Vec::new(),
                        peer_user_hash: uh,
                        peer_connect_options: co,
                    }]
                };
                let (src_inject_tx, src_inject_rx) = mpsc::channel::<DownloadSource>(32);
                let (est_inject_tx, est_inject_rx) =
                    mpsc::channel::<ed2k::multi_source::EstablishedSource>(8);
                let ms_download = MultiSourceDownload {
                    transfer_id,
                    file_hash: hash_bytes,
                    file_name,
                    file_size,
                    sources: download_sources,
                    download_dir: PathBuf::from(&settings.download_folder),
                    user_hash: state.user_hash,
                    nickname: settings.nickname.clone(),
                    tcp_port: settings.tcp_port,
                    udp_port: settings.udp_port,
                    bandwidth_limiter: bandwidth_limiter.clone(),
                    control,
                    source_manager: Some(source_manager.clone()),
                    comment_manager: Some(state.comment_manager.clone()),
                    credit_manager: Some(credit_manager.clone()),
                    shared_buddy_info: Some(state.shared_buddy_info.clone()),
                    obfuscation_enabled: state.obfuscation_enabled,
                    server_addr: state.server_addr,
                    new_source_rx: Some(src_inject_rx),
                    new_established_rx: Some(est_inject_rx),
                        ed2k_limits: settings.ed2k_download_limits(),
                        ember_hash,
                        friend_hashes: Some(friend_hashes.clone()),
                    ember_payload: shared_ember_payload.clone(),
                    ember_payload_generation: ember_payload_generation.clone(),
                    ip_filter: Some(state.shared_ip_filter.clone()),
                    banned_ips: Some(shared_banned_ips.clone()),
                    external_ip: state.external_ip,
                    aich_pending: Some(state.aich_recovery_pending.clone()),
                    geoip: geoip.clone(),
                    tracker_registry: Some(state.tracker_registry.clone()),
                    sx_overhead: stats_manager.sx_counters.clone(),
                };

                let tx = dl_event_tx.clone();
                let tid = ms_download.transfer_id.clone();
                let tid2 = tid.clone();
                state.active_source_senders.insert(tid.clone(), src_inject_tx);
                state.active_established_senders.insert(tid.clone(), est_inject_tx);
                state.active_kad_search_state.insert(tid.clone(), (chrono::Utc::now().timestamp(), 0));
                let tx2 = tx.clone();
                if let Some(old_handle) = state.download_handles.remove(&tid2) {
                    warn!("Aborting existing download task for {tid2} before starting new one");
                    old_handle.abort();
                }
                let handle = tokio::spawn(async move {
                    if let Err(e) = ms_download.run(tx).await {
                        error!("Multi-source download failed: {e}");
                        let kind = classify_error(&e.to_string());
                        let _ = tx2.send(DownloadEvent::Failed { transfer_id: tid, error: e.to_string(), failure_kind: kind }).await;
                    }
                });
                state.download_handles.insert(tid2, handle);
            } else {
                info!("No source address for {file_hash}, starting KAD source search");

                let hash_bytes = match hex::decode(&file_hash) {
                    Ok(b) if b.len() == 16 => b,
                    _ => {
                        error!("Invalid file hash: {file_hash}");
                        return;
                    }
                };
                let kad_hash = md4_bytes_to_kad_id(&hash_bytes);

                let mut closest = state.routing_table.find_closest_prefer_verified(&kad_hash, SEARCH_INITIAL_CONTACTS);
                if closest.is_empty() {
                    warn!("No routing table contacts for source search, download will retry later");
                }

                let now = chrono::Utc::now().timestamp();

                // Persist download to database for resume across restarts.
                // Check for an existing DB row first so we don't clobber
                // progress/priority when a queued download is promoted.
                {
                    let db_ref = db.clone();
                    let tid = transfer_id.clone();
                    let fname = file_name.clone();
                    let fhash = file_hash.clone();
                    tokio::task::spawn_blocking(move || {
                        if db_ref.transfer_exists(&tid) {
                            let _ = db_ref.update_transfer_status(&tid, "searching");
                        } else {
                            let db_transfer = Transfer {
                                id: tid,
                                file_name: fname,
                                file_hash: fhash,
                                peer_id: String::new(),
                                peer_name: String::new(),
                                direction: TransferDirection::Download,
                                status: TransferStatus::Searching,
                                progress: 0.0,
                                speed: 0,
                                total_size: file_size,
                                transferred: 0,
                                completed_size: 0,
                                started_at: now,
                                failure_reason: None,
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
                                stalled_since: None,
                                category: String::new(),
                                wait_time: 0,
                                upload_time: 0,
                                a4af_sources: 0,
                                max_sources: 0,
                                preview_priority: false,
                                ember_sources: 0,
                                client_software: String::new(),
                                country_code: None,
                                user_hash: None,
                            };
                            let _ = db_ref.save_transfer(&db_transfer);
                        }
                    });
                }

                let kad_search_started = if !closest.is_empty() {
                    closest.sort_by_key(|c| c.is_tcp_firewalled() as u8);
                    let sid = state.search_manager.start_search(
                        kad_hash,
                        SearchType::FindSource { file_size },
                        closest,
                    );
                    if sid != SearchId(0) {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&hash_bytes[..16]);
                        state.download_source_searches.insert(sid, (transfer_id.clone(), fh));
                        stats_manager.add_overhead(crate::storage::statistics::OverheadCategory::FileRequest, crate::storage::statistics::OverheadDirection::Upload, 48);
                        info!("Started source search {} for download {}", sid.0, transfer_id);
                        let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                            "transfer_id": &transfer_id,
                            "kind": "kad_search",
                        }));
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                // Look up actual priority from the transfer manager if this
                // is a promoted/re-started download, otherwise default to normal.
                let pending_priority = {
                    let mgr = transfer_manager.read().await;
                    mgr.get_transfer(&transfer_id)
                        .map(|t| priority_str_to_u32(&t.priority))
                        .unwrap_or(1)
                };
                state.pending_downloads.insert(transfer_id.clone(), PendingDownload {
                    transfer_id: transfer_id.clone(),
                    file_hash: file_hash.clone(),
                    file_name,
                    file_size,
                    control,
                    search_count: if kad_search_started { 1 } else { 0 },
                    last_search_at: if kad_search_started { now } else { 0 },
                    priority: pending_priority,
                });

                // Request sources from the connected ed2k server (non-blocking)
                if state.server_connected {
                    if let Some(conn) = &mut state.server_connection {
                        let mut file_hash_arr = [0u8; 16];
                        file_hash_arr.copy_from_slice(&hash_bytes);
                        if let Ok(bytes) = conn.send_get_sources(&file_hash_arr, file_size).await {
                            if bytes > 0 {
                                stats_manager.add_overhead(
                                    crate::storage::statistics::OverheadCategory::SourceExchange,
                                    crate::storage::statistics::OverheadDirection::Upload,
                                    bytes,
                                );
                                let _ = app_handle.emit("transfer:source-search", serde_json::json!({
                                    "transfer_id": &transfer_id,
                                    "kind": "server_query",
                                }));
                            }
                        }
                    }
                }

                // Queue UDP source requests to ALL eligible servers (paced via udp_source_queue)
                {
                    let mut file_hash_arr = [0u8; 16];
                    file_hash_arr.copy_from_slice(&hash_bytes);
                    let packets = build_all_getsources_packets(
                        &state,
                        &file_hash_arr,
                        file_size,
                    );
                    if !packets.is_empty() {
                        let room = MAX_UDP_SOURCE_QUEUE.saturating_sub(state.udp_source_queue.len());
                        debug!("Queuing {}/{} UDP source requests for new download", packets.len().min(room), packets.len());
                        state.udp_source_queue.extend(packets.into_iter().take(room));
                    }
                }
            }

            if let Ok(hb) = hex::decode(&file_hash) {
                if hb.len() >= 16 {
                    state.publish_manager.add_file(PublishableFile {
                        file_hash: md4_bytes_to_kad_id(&hb[..16]),
                        file_name: publish_file_name,
                        file_size,
                        file_type: crate::search::index::infer_file_type(&publish_ext),
                        complete_sources: 0,
                    });
                    info!("Published partial download to KAD source publish");
                }
            }
        }

        NetworkCommand::AnnounceFiles { files } => {
            for file in files {
                if !file.shared { continue; }
                if let Ok(raw_bytes) = hex::decode(&file.hash) {
                    if raw_bytes.len() != 16 { continue; }
                    let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
                    let publishable = PublishableFile {
                        file_hash: kad_hash,
                        file_name: file.name.clone(),
                        file_size: file.size,
                        file_type: crate::search::index::infer_file_type(&file.extension),
                        complete_sources: file.complete_sources,
                    };
                    state.publish_manager.add_file(publishable);
                }
            }
            info!(
                "Registered {} files for KAD publishing",
                state.publish_manager.file_count()
            );
        }

        NetworkCommand::RepublishFile { file_hash_hex } => {
            let Ok(raw_bytes) = hex::decode(&file_hash_hex) else {
                warn!("RepublishFile: invalid hex in file hash");
                return;
            };
            if raw_bytes.len() != 16 {
                warn!("RepublishFile: expected 16-byte MD4 hash, got {}", raw_bytes.len());
                return;
            }
            let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
            state.publish_manager.reset_source_publish(&kad_hash);
            state.publish_manager.reset_keyword_publish(&kad_hash);
            info!(
                "Scheduled immediate KAD republish for file hash {}",
                &file_hash_hex[..file_hash_hex.len().min(16)]
            );
        }

        NetworkCommand::PublishNote { file_hash, rating, comment } => {
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&file_hash, SEARCH_INITIAL_CONTACTS);

            if closest.is_empty() {
                warn!("No contacts to publish note to");
                return;
            }

            let sid = state.search_manager.start_search(
                file_hash,
                SearchType::StoreNotes,
                closest,
            );
            if sid == SearchId(0) {
                warn!("Failed to start StoreNotes search: too many active searches");
            } else {
                state.pending_note_publishes.insert(sid, (file_hash, rating, comment.clone()));
                info!(
                    "Started StoreNotes search {} for file {} (rating={}, comment_len={})",
                    sid.0, file_hash, rating, comment.len()
                );
            }
        }

        NetworkCommand::BanPeer { peer_id_hex } => {
            if let Some(kad_id) = KadId::from_hex(&peer_id_hex) {
                // Grab the IP before removing from routing table
                let contact_ip = state.routing_table.get_contact(&kad_id).map(|c| c.ip);
                if state.routing_table.remove(&kad_id) {
                    info!("Removed banned peer {} from routing table", peer_id_hex);
                    state.stats.connected_peers = state.routing_table.len() as u32;
                }
                if let Some(ip) = contact_ip {
                    state.banned_ips.insert(ip);
                }
                // Also check peer database for the IP
                if let Ok(peers) = db.get_peers() {
                    for peer in &peers {
                        if peer.id == peer_id_hex {
                            for addr_str in &peer.addresses {
                                if let Some((ip_str, _)) = addr_str.rsplit_once(':') {
                                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                        state.banned_ips.insert(ip);
                                    }
                                }
                            }
                        }
                    }
                }
                if let Ok(mut shared) = shared_banned_ips.write() {
                    *shared = state.banned_ips.clone();
                }
                // Also add user hash to upload-only banned set
                if let Ok(mut set) = shared_banned_hashes.write() {
                    set.insert(kad_id.0);
                }
            }
        }

        NetworkCommand::UnbanPeer { peer_id_hex } => {
            if let Some(kad_id) = KadId::from_hex(&peer_id_hex) {
                if let Some(contact) = state.routing_table.get_contact(&kad_id) {
                    state.banned_ips.remove(&contact.ip);
                }
            }
            if let Ok(peers) = db.get_peers() {
                for peer in &peers {
                    if peer.id == peer_id_hex {
                        for addr_str in &peer.addresses {
                            if let Some((ip_str, _)) = addr_str.rsplit_once(':') {
                                if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                    state.banned_ips.remove(&ip);
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(mut shared) = shared_banned_ips.write() {
                *shared = state.banned_ips.clone();
            }
            // Also remove from upload-only banned set
            if let Some(kad_id) = KadId::from_hex(&peer_id_hex) {
                if let Ok(mut set) = shared_banned_hashes.write() {
                    set.remove(&kad_id.0);
                }
            }
            info!("Unbanned peer {peer_id_hex}");
        }


        NetworkCommand::GetPeersSnapshot { tx } => {
            let _ = tx.send(peers_snapshot(state, db).await);
        }

        NetworkCommand::GetNetworkStatsSnapshot { tx } => {
            let _ = tx.send(state.stats.clone());
        }

        NetworkCommand::GetUploadQueueSnapshot { tx } => {
            let snap = upload_queue_snapshot(
                upload_queue,
                credit_manager,
                local_index,
                friend_hashes,
                geoip,
            ).await;
            let _ = tx.send(snap);
        }

        NetworkCommand::GetKnownClientsSnapshot { tx } => {
            let snap = known_clients_snapshot(credit_manager, geoip).await;
            let _ = tx.send(snap);
        }

        NetworkCommand::GetAntiLeechSnapshot { tx } => {
            let _ = tx.send(antileech_snapshot(state));
        }

        NetworkCommand::SetAntiLeechPatterns { patterns, tx } => {
            let _ = tx.send(antileech_set_patterns(state, patterns));
        }

        NetworkCommand::SetAntiLeechEnabled { enabled, tx } => {
            let _ = tx.send(antileech_set_enabled(state, enabled));
        }

        NetworkCommand::ResetAntiLeechToDefaults { tx } => {
            let _ = tx.send(antileech_reset_defaults(state));
        }

        NetworkCommand::GetKadContactsSnapshot { tx } => {
            let _ = tx.send(kad_contacts_snapshot(state, state.local_id));
        }

        NetworkCommand::GetKadSearchesSnapshot { tx } => {
            let _ = tx.send(kad_searches_snapshot(state));
        }

        NetworkCommand::CancelKadSearch { id } => {
            // K30: release routing-table in-use refs first (so the
            // contacts can be cleaned up normally) then drop the search.
            let sid = crate::network::kad::search::SearchId(id);
            if let Some(removed) = state.search_manager.remove(&sid) {
                if !removed.in_use_ids.is_empty() {
                    state.routing_table.release_contacts_in_use(&removed.in_use_ids);
                }
                info!("KAD search {id} cancelled by user");
            } else {
                debug!("KAD search {id} not found (already completed?) — ignoring cancel");
            }
        }

        NetworkCommand::IsFriendDiscoverable { tx } => {
            let _ = tx.send(state.rendezvous_registered);
        }

        NetworkCommand::FindNotes { file_hash, file_size, tx } => {
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&file_hash, SEARCH_INITIAL_CONTACTS);

            if closest.is_empty() {
                let _ = tx.send(Vec::new());
                return;
            }

            let sid = state.search_manager.start_search(
                file_hash,
                SearchType::FindNotes { file_size },
                closest,
            );
            if sid == SearchId(0) {
                let _ = tx.send(Vec::new());
                return;
            }
            state.pending_notes_searches.insert(sid, tx);
        }

        NetworkCommand::FindSources { file_hash, file_size, tx } => {
            let closest = state
                .routing_table
                .find_closest_prefer_verified(&file_hash, SEARCH_INITIAL_CONTACTS);

            if closest.is_empty() {
                let _ = tx.send(Vec::new());
                return;
            }

            let sid = state.search_manager.start_search(
                file_hash,
                SearchType::FindSource { file_size },
                closest,
            );

            if sid == SearchId(0) {
                let _ = tx.send(Vec::new());
                return;
            }
            state.pending_source_searches.insert(sid, tx);
        }

        NetworkCommand::BootstrapContacts { contacts } => {
            let count = contacts.len();
            for c in &contacts {
                state.routing_table.insert(c.clone());
            }
            let table_size = state.routing_table.len();
            info!(
                "Injected {} bootstrap contacts, routing table now has {} entries",
                count,
                table_size
            );

            // eMule: GetBootstrapContacts returns at most 20 contacts.
            // Limit bootstrap requests to prevent flooding the event loop.
            let sample_size = count.min(20);
            for contact in contacts.iter().take(sample_size) {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = KadMessage::BootstrapReq;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    state.flood_protection.track_request(addr, 0x01);
                    let _ = socket.send_to(&packet, addr).await;
                }
            }
            info!("Sent bootstrap requests to {sample_size} contacts (table has {table_size})");
        }

        NetworkCommand::ReloadIpFilter { path } => {
            // Persist the imported filter to ipfilter.dat so it loads on next startup
            let default_path = state.data_dir.join("ipfilter.dat");
            if path != default_path {
                if let Err(e) = std::fs::copy(&path, &default_path) {
                    warn!("Failed to persist IP filter to {:?}: {}", default_path, e);
                } else {
                    info!("Persisted imported IP filter to {:?}", default_path);
                }
            }
            // Load from the (now updated) default path
            state.ip_filter.load_from_file(&default_path);
            state.ip_filter.update_shared_snapshot(&state.shared_ip_filter);
            info!(
                "Reloaded IP filter: {} ranges",
                state.ip_filter.range_count(),
            );
            // Purge servers now blocked by the updated filter
            if settings.filter_servers_by_ip {
                let removed = state.server_list.remove_filtered(&mut state.ip_filter);
                if removed > 0 {
                    let met_path = state.data_dir.join("server.met");
                    let _ = state.server_list.save_server_met(&met_path);
                    info!("Removed {removed} servers blocked by updated IP filter");
                }
            }
        }

        NetworkCommand::GetIpFilterStats { tx } => {
            let _ = tx.send(state.ip_filter.get_stats());
        }

        NetworkCommand::AddIpRange { start_ip, end_ip, description } => {
            if let (Ok(start), Ok(end)) = (start_ip.parse::<Ipv4Addr>(), end_ip.parse::<Ipv4Addr>()) {
                state.ip_filter.add_range(start, end, description);
                state.ip_filter.update_shared_snapshot(&state.shared_ip_filter);
                info!("Added IP filter range {start_ip} - {end_ip}, total ranges: {}", state.ip_filter.range_count());
            }
        }

        NetworkCommand::RemoveIpRange { start_ip, end_ip } => {
            if state.ip_filter.remove_range(&start_ip, &end_ip) {
                state.ip_filter.update_shared_snapshot(&state.shared_ip_filter);
                info!("Removed IP filter range {start_ip} - {end_ip}, total ranges: {}", state.ip_filter.range_count());
            }
        }

        NetworkCommand::SetIpFilterEnabled { enabled } => {
            state.ip_filter.set_enabled(enabled);
            state.ip_filter.update_shared_snapshot(&state.shared_ip_filter);
            info!("IP filter enabled: {enabled}");
        }

        NetworkCommand::SetBlockPrivateIps { block_private } => {
            state.ip_filter.set_block_private(block_private);
            state.ip_filter.update_shared_snapshot(&state.shared_ip_filter);
            info!("Block private IPs: {block_private}");
        }

        NetworkCommand::KadConnect => {
            info!("KAD connect requested");
            state.upload_disconnected.store(false, std::sync::atomic::Ordering::Relaxed);
            state.stats.status = NetworkStatus::Connecting;
            state.self_lookup_done = false;
            state.last_self_lookup = 0;
            state.kad_started_at = chrono::Utc::now().timestamp();
            state
                .routing_table
                .reset_big_timer_global(chrono::Utc::now().timestamp());
            let _ = app_handle.emit("network-status", NetworkStatus::Connecting);

            // Reload routing table from saved nodes.dat (eMule recreates RoutingZone on Start).
            // K3: trust the legacy on-disk format for convenience; the
            // modern format carries per-contact verified bits which we
            // respect as-is.
            let nodes_path = state.data_dir.join("nodes.dat");
            if state.routing_table.is_empty() {
                if nodes_path.exists() {
                    match bootstrap::load_nodes_dat_with_format(&nodes_path) {
                        Ok((mut saved, fmt)) => {
                            if fmt == bootstrap::NodesDatFormat::LegacyNoVerified {
                                for c in &mut saved {
                                    c.verified = true;
                                }
                            }
                            for c in &saved {
                                state.routing_table.insert(c.clone());
                            }
                            info!("Loaded {} contacts from nodes.dat on connect", saved.len());
                        }
                        Err(e) => warn!("Failed to load nodes.dat on connect: {e}"),
                    }
                }
            }

            let contacts: Vec<KadContact> = state.routing_table.all_contacts().cloned().collect();
            if contacts.is_empty() {
                let default_contacts = bootstrap::default_bootstrap_contacts();
                for c in &default_contacts {
                    state.routing_table.insert(c.clone());
                }
                for contact in &default_contacts {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    let msg = KadMessage::BootstrapReq;
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        state.flood_protection.track_request(addr, 0x01);
                        let _ = socket.send_to(&packet, addr).await;
                    }
                }
                info!("Bootstrapped from {} default contacts", default_contacts.len());
            } else {
                for contact in contacts.iter().take(20) {
                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                    let msg = KadMessage::BootstrapReq;
                    if let Ok(packet) = messages::encode_packet(&msg) {
                        state.flood_protection.track_request(addr, 0x01);
                        let _ = socket.send_to(&packet, addr).await;
                    }
                }
                info!("Sent bootstrap requests to {} existing contacts", contacts.len().min(20));
            }

            // Firewall check is deferred to the periodic bootstrap_timer recheck,
            // which runs once we have verified contacts (table_size >= 10).
            // Sending checks here against stale nodes.dat contacts produces
            // false Firewalled results because those contacts may be offline.
        }

        NetworkCommand::KadDisconnect => {
            info!("KAD disconnect requested");

            // Save routing table before clearing (eMule saves on Stop)
            let contacts = state.routing_table.export_bootstrap_contacts(200);
            let nodes_path = state.data_dir.join("nodes.dat");
            if let Err(e) = bootstrap::save_nodes_dat(&nodes_path, &contacts) {
                error!("Failed to save nodes.dat on disconnect: {e}");
            } else {
                info!("Saved {} contacts to nodes.dat on disconnect", contacts.len());
            }

            // Stop all searches and cancel pending oneshot channels
            state.search_manager = SearchManager::new();
            for (_, PendingKeywordSearch { tx, local_results, .. }) in state.pending_keyword_searches.drain() {
                let _ = tx.send(local_results);
            }
            for (_, tx) in state.pending_source_searches.drain() {
                let _ = tx.send(Vec::new());
            }
            for (_, tx) in state.pending_notes_searches.drain() {
                let _ = tx.send(Vec::new());
            }
            state.active_search_request = None;
            state.download_source_searches.clear();
            state.store_keyword_searches.clear();
            state.store_source_searches.clear();
            state.pending_note_publishes.clear();
            state.publish_pending.clear();
            state.source_publish_acks.clear();

            // Reset network state (eMule resets firewall, deletes routing zone)
            state.routing_table.clear();
            set_external_ip(state, None);
            state.external_udp_port = None;
            state.firewalled = true;
            state.firewalled_shared.store(true, std::sync::atomic::Ordering::Relaxed);
            state.firewall_checks_sent = 0;
            state.firewall_checker = FirewallChecker::new();
            state.self_lookup_done = false;
            state.last_self_lookup = 0;
            state.last_kad_contact = None;
            state.udp_firewalled = true;
            state.udp_fw_verified = false;
            state.overloaded_nodes.clear();
            state.buddy_manager.reset();
            state.buddy_event_rx = None;
            state.serving_event_rx = None;
            *state.shared_buddy_info.write().await = None;
            state.peer_nicknames.clear();
            state.publish_confirmed = 0;
            state.first_publish_done = false;
            state.kad_initial_source_burst_done = false;
            state.friend_presence_initial_done = false;
            state.friend_search_initial_done = false;
            state.friend_search_started_at = None;
            state.rendezvous_registered = false;
            state.rendezvous_last_register = None;
            // Emit offline for all previously-online friends
            for eh in state.online_friends.keys() {
                let _ = app_handle.emit("ember:friend-offline", serde_json::json!({
                    "user_hash": hex::encode(eh),
                }));
            }
            state.online_friends.clear();
            state.outbound_session_tasks.clear();

            // Abort all active download tasks — they hold open TCP connections
            // to peers and will keep transferring data even though the network
            // is logically disconnected.  Re-queue each as a pending download
            // so they resume automatically when the user reconnects.
            // Save .part.met for in-progress downloads before aborting tasks.
            if let Ok(reg) = state.tracker_registry.lock() {
                for (tid, tracker) in reg.iter() {
                    if let Ok(t) = tracker.try_read() {
                        t.save();
                        debug!("Saved .part.met for {tid} before disconnect abort");
                    }
                }
            }

            for (tid, handle) in state.download_handles.drain() {
                handle.abort();
                let _ = handle.await;
                debug!("Aborted download task {tid} on KAD disconnect");
            }

            // Clear the registry — tasks are gone, trackers are saved.
            if let Ok(mut reg) = state.tracker_registry.lock() {
                reg.clear();
            }
            state.active_source_senders.clear();
            // Lockstep cleanup — KAD disconnect tears down all
            // workers, so the established-source channel map must be
            // cleared too. Without this, on reconnect new downloads
            // would create new entries while stale closed senders
            // remain forever.
            state.active_established_senders.clear();
            state.active_source_overflow.clear();
            state.active_kad_search_state.clear();

            // Move all active downloads back to pending so they can be
            // restarted when the network is reconnected.
            {
                let mut mgr = transfer_manager.write().await;
                let active_tids: Vec<String> = mgr.get_all().iter()
                    .filter(|t| t.status == TransferStatus::Active && t.direction == TransferDirection::Download)
                    .map(|t| t.id.clone())
                    .collect();
                for tid in &active_tids {
                    if state.pending_downloads.contains_key(tid) {
                        continue;
                    }
                    if let Some(t) = mgr.get_transfer(tid).cloned() {
                        let control = TransferControl::new();
                        mgr.register_control(tid, control.clone());
                        mgr.update_sources(tid, t.sources, 0, 0);
                        mgr.update_status(tid, TransferStatus::Searching);
                        state.pending_downloads.insert(tid.clone(), PendingDownload {
                            transfer_id: tid.clone(),
                            file_hash: t.file_hash.clone(),
                            file_name: t.file_name.clone(),
                            file_size: t.total_size,
                            control,
                            search_count: 0,
                            last_search_at: 0,
                            priority: priority_str_to_u32(&t.priority),
                        });
                        if let Some(pfs) = state.per_file_sources.get_mut(tid) {
                            pfs.reset_active_states();
                        }
                        let _ = app_handle.emit("transfer-status", serde_json::json!({
                            "id": tid,
                            "status": "searching",
                            "sources": t.sources,
                        }));
                    }
                }
            }

            // Signal the upload listener to reject new connections and
            // terminate active upload sessions (eMule: all uploads stop on disconnect).
            state.upload_disconnected.store(true, std::sync::atomic::Ordering::Relaxed);

            state.stats.status = NetworkStatus::Disconnected;
            state.stats.connected_peers = 0;
            state.stats.external_ip = String::new();
            state.stats.firewalled = true;
            state.stats.buddy_status = "none".to_string();
            state.stats.stores_acknowledged = 0;
            let _ = app_handle.emit("network-status", NetworkStatus::Disconnected);

            // Tear down eD2K server — it should only be up while KAD is connected
            if let Some(handle) = state.pending_server_connect.take() {
                handle.abort();
            }
            if state.server_connected || state.server_connection.is_some() {
                if let Some(conn) = state.server_connection.take() {
                    conn.disconnect().await;
                }
                handle_server_disconnect(
                    state,
                    &shared_server_addr,
                    &app_handle,
                    "KAD disconnected",
                ).await;
            }

            info!("KAD fully disconnected — all activity stopped");
        }

        NetworkCommand::KadBootstrapIp { ip, port, tx } => {
            info!("KAD bootstrap from IP {ip}:{port}");
            let outcome: Result<String, String> = if !(11..=65535).contains(&port) {
                // eMule's convention is "tcp_port = udp_port - 10".
                // For any UDP port < 11, that produces 0 (or wraps with
                // saturating_sub) — a silently broken contact whose
                // TCP port is unusable. Reject up front with a clear
                // error rather than insert a poison record into the
                // routing table.
                Err(format!(
                    "Invalid UDP port {port} for manual bootstrap (must be ≥ 11 so the implied TCP port = UDP-10 is non-zero)",
                ))
            } else if let Ok(addr_ip) = ip.parse::<Ipv4Addr>() {
                let contact = KadContact {
                    id: KadId::zero(),
                    ip: addr_ip,
                    udp_port: port,
                    tcp_port: port - 10,
                    version: KADEMLIA_VERSION,
                    last_seen: chrono::Utc::now().timestamp(),
                    verified: false,
                    contact_type: CONTACT_TYPE_NEW,
                    udp_key: None,
                    kad_options: 0,
                    created_at: chrono::Utc::now().timestamp(),
                    expires_at: 0,
                    last_type_set: 0,
                    received_hello: false,
                };
                state.routing_table.insert(contact);

                let addr = SocketAddr::new(addr_ip.into(), port);
                let msg = KadMessage::BootstrapReq;
                match messages::encode_packet(&msg) {
                    Ok(packet) => {
                        state.flood_protection.track_request(addr, 0x01);
                        match socket.send_to(&packet, addr).await {
                            Ok(_) => {
                                info!("Sent bootstrap request to {addr}");
                                if state.stats.status == NetworkStatus::Disconnected {
                                    state.stats.status = NetworkStatus::Connecting;
                                }
                                Ok(format!(
                                    "Bootstrap request sent to {addr} — contacts will appear as they respond"
                                ))
                            }
                            Err(e) => Err(format!("Failed to send bootstrap packet: {e}")),
                        }
                    }
                    Err(e) => Err(format!("Failed to encode bootstrap packet: {e}")),
                }
            } else {
                warn!("Invalid bootstrap IP: {ip}");
                Err(format!("Invalid bootstrap IP: {ip}"))
            };
            let _ = tx.send(outcome);
        }

        NetworkCommand::KadBootstrapUrl { url, host, resolved_addrs, tx } => {
            info!("KAD bootstrap from URL: {url}");
            const MAX_NODES_BYTES: usize = 10 * 1024 * 1024;
            let outcome: Result<String, String> =
                match crate::security::build_pinned_client(&host, &resolved_addrs) {
                    Ok(client) => match client.get(&url).send().await {
                        Ok(resp) => {
                            if !resp.status().is_success() {
                                Err(format!(
                                    "HTTP {} from {}",
                                    resp.status().as_u16(),
                                    host
                                ))
                            } else {
                                let download_result: Result<Vec<u8>, String> = {
                                    use futures::StreamExt;
                                    let mut body = Vec::new();
                                    let mut stream = resp.bytes_stream();
                                    let mut err: Option<String> = None;
                                    while let Some(chunk) = stream.next().await {
                                        match chunk {
                                            Ok(data) => {
                                                body.extend_from_slice(&data);
                                                if body.len() > MAX_NODES_BYTES {
                                                    err = Some(format!(
                                                        "Response exceeded {} byte cap",
                                                        MAX_NODES_BYTES
                                                    ));
                                                    break;
                                                }
                                            }
                                            Err(e) => {
                                                err = Some(format!("Download failed: {e}"));
                                                break;
                                            }
                                        }
                                    }
                                    if let Some(e) = err { Err(e) } else { Ok(body) }
                                };
                                match download_result {
                                    Ok(bytes) => {
                                        let tmp_dir = std::env::temp_dir();
                                        let tmp_path = tmp_dir.join(format!(
                                            "ember-nodes-{}.dat",
                                            chrono::Utc::now().timestamp()
                                        ));
                                        match tokio::fs::write(&tmp_path, &bytes).await {
                                            Err(e) => Err(format!(
                                                "Failed to write temp nodes.dat: {e}"
                                            )),
                                            Ok(_) => {
                                                let parse_res =
                                                    bootstrap::load_nodes_dat(&tmp_path);
                                                let _ = tokio::fs::remove_file(&tmp_path).await;
                                                match parse_res {
                                                    Err(e) => Err(format!(
                                                        "Parsed {} bytes but file is not a valid nodes.dat: {e}",
                                                        bytes.len()
                                                    )),
                                                    Ok(contacts) => {
                                                        let count = contacts.len();
                                                        if count == 0 {
                                                            Err("Downloaded nodes.dat contained no contacts".into())
                                                        } else {
                                                            for c in &contacts {
                                                                state.routing_table.insert(c.clone());
                                                            }
                                                            for contact in contacts.iter().take(20) {
                                                                let addr = SocketAddr::new(
                                                                    contact.ip.into(),
                                                                    contact.udp_port,
                                                                );
                                                                let msg = KadMessage::BootstrapReq;
                                                                if let Ok(packet) =
                                                                    messages::encode_packet(&msg)
                                                                {
                                                                    state
                                                                        .flood_protection
                                                                        .track_request(addr, 0x01);
                                                                    let _ = socket
                                                                        .send_to(&packet, addr)
                                                                        .await;
                                                                }
                                                            }
                                                            info!(
                                                                "Loaded {count} contacts from URL, bootstrapping"
                                                            );
                                                            if state.stats.status
                                                                == NetworkStatus::Disconnected
                                                            {
                                                                state.stats.status =
                                                                    NetworkStatus::Connecting;
                                                            }
                                                            Ok(format!(
                                                                "Loaded {count} contacts from nodes.dat"
                                                            ))
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => Err(e),
                                }
                            }
                        }
                        Err(e) => Err(format!("Failed to reach {host}: {e}")),
                    },
                    Err(e) => Err(format!("Failed to build HTTP client for {url}: {e}")),
                };
            if let Err(ref e) = outcome {
                warn!("KAD bootstrap from {url} failed: {e}");
            }
            let _ = tx.send(outcome);
        }

        NetworkCommand::KadBootstrapClients { tx } => {
            info!("KAD bootstrap from connected clients");
            let contacts: Vec<KadContact> = state
                .routing_table
                .all_contacts()
                .filter(|contact| contact.verified && !contact.is_dead())
                .cloned()
                .collect();
            let send_count = contacts.len().min(20);
            let mut actually_sent = 0usize;
            for contact in contacts.iter().take(send_count) {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                // K17: the KadBootstrapIp path tracks outgoing bootstrap
                // requests in flood_protection so we don't double-send.
                // This bulk path didn't, meaning a rapid user-triggered
                // rebootstrap could send duplicate BootstrapReqs to the
                // same contact within the flood window — we'd then reject
                // our own replies. Track every send here too.
                state.flood_protection.track_request(addr, 0x01);
                let msg = KadMessage::BootstrapReq;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    if socket.send_to(&packet, addr).await.is_ok() {
                        actually_sent += 1;
                    }
                }
            }
            info!("Sent bootstrap requests to {actually_sent}/{send_count} connected contacts");
            if state.stats.status == NetworkStatus::Disconnected && actually_sent > 0 {
                state.stats.status = NetworkStatus::Connecting;
            }
            let _ = tx.send(if actually_sent > 0 {
                Ok(actually_sent)
            } else {
                Err("No known contacts are available for bootstrap".to_string())
            });
        }

        NetworkCommand::RecheckFirewall { tx } => {
            info!("Rechecking firewall status");
            state.firewall_checks_sent = 0;

            state.firewall_checker.start_check();
            state.external_udp_port = None;
            if let Ok(mut probes) = firewall_probe_ips.lock() { probes.clear(); }

            let contacts: Vec<KadContact> = state
                .routing_table
                .all_contacts()
                .filter(|contact| contact.verified && !contact.is_dead())
                .take(4)
                .cloned()
                .collect();

            for contact in &contacts {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let (msg, track_opcode) = if contact.version > KADEMLIA_VERSION6_49ABETA {
                    (KadMessage::Firewalled2Req {
                        tcp_port: state.tcp_port,
                        user_hash: state.user_hash,
                        connect_options: build_kad_connect_options(&state),
                    }, 0x53u8)
                } else {
                    (KadMessage::FirewalledReq { tcp_port: state.tcp_port }, 0x50u8)
                };
                if let Ok(packet) = messages::encode_packet(&msg) {
                    state.flood_protection.track_request(addr, track_opcode);
                    if let Ok(mut probes) = firewall_probe_ips.lock() { probes.insert(contact.ip); }
                    let _ = send_kad_packet(socket, &packet, addr, &state, &contact.id).await;
                    state.firewall_checks_sent += 1;
                    state.firewall_checker.record_tcp_request_sent(contact.ip);
                }
            }

            let ping_contacts: Vec<KadContact> = state
                .routing_table
                .all_contacts()
                .filter(|contact| contact.verified && !contact.is_dead())
                .skip(4)
                .take(4)
                .cloned()
                .collect();
            for contact in &ping_contacts {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = KadMessage::Ping;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    state.flood_protection.track_request(addr, 0x60);
                    let _ = send_kad_packet(socket, &packet, addr, &state, &contact.id).await;
                    state.firewall_checker.record_udp_port_probe_sent();
                }
            }

            // Eagerly dispatch UDP firewall probes (uses previous external port
            // or falls back to settings.udp_port). Pong handler will also retry.
            dispatch_udp_firewall_probe_requests(state, &settings);

            info!("Sent {} firewall checks and {} ping probes", state.firewall_checks_sent, ping_contacts.len());
            let _ = tx.send(if state.firewall_checks_sent > 0 || !ping_contacts.is_empty() {
                Ok((state.firewall_checks_sent as usize) + ping_contacts.len())
            } else {
                Err("No verified contacts available for firewall recheck".to_string())
            });
        }

        NetworkCommand::UpdateSettings { .. } => {
            // Handled inline in the command dispatch loop (start_network)
            // to allow updating the owned `settings` variable.
        }

        NetworkCommand::ConnectToServer { ip, port } => {
            state.server_auto_reconnect = true;
            state.server_reconnect_failures = 0;
            if let Some(handle) = state.pending_server_connect.take() {
                handle.abort();
            }
            if let Some(conn) = state.server_connection.take() {
                emit_server_log(app_handle, "Disconnecting from current server...");
                conn.disconnect().await;
                state.server_connected = false;
                state.server_addr = None;
                *shared_server_addr.write().await = None;
                state.stats.server_status = "disconnected".to_string();
                let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
            }
            let user_hash = state.user_hash;
            let nickname = settings.nickname.clone();
            let tcp_port = state.tcp_port;
            let obf_port = state.server_list.servers().iter()
                .find(|s| s.ip == ip && s.port == port)
                .map(|s| s.obfuscation_port_tcp)
                .unwrap_or(0);
            let ip_clone = ip.clone();
            let app_for_connect = app_handle.clone();
            // Pre-set server addr so upload handler can detect HighID port test callbacks
            if let Ok(ip_addr) = ip.parse::<std::net::IpAddr>() {
                *shared_server_addr.write().await = Some(SocketAddr::new(ip_addr, port));
            }
            info!("Connecting to ed2k server {ip}:{port} (background)...");
            emit_server_log(app_handle, &format!("Connecting to {ip}:{port}..."));
            state.stats.server_status = "connecting".to_string();
            let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "connecting" }));
            state.pending_server_connect = Some(tokio::spawn(async move {
                let result = async {
                    const MAX_LOGIN_ATTEMPTS: u32 = 3;
                    let mut last_err = String::new();
                    for attempt in 0..MAX_LOGIN_ATTEMPTS {
                        if attempt > 0 {
                            info!("Retrying server {ip_clone}:{port} (attempt {})", attempt + 1);
                            emit_server_log(&app_for_connect, &format!("Retrying ({})...", attempt + 1));
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                        let (mut conn, resolved_addr) = match try_connect_server(&ip_clone, port, obf_port, &app_for_connect, false).await {
                            Ok(r) => r,
                            Err(e) => { last_err = format!("Connect failed: {e}"); continue; }
                        };
                        if attempt == 0 {
                            emit_server_log(
                                &app_for_connect,
                                &format!("Sending login request (client TCP port {tcp_port})..."),
                            );
                        }
                        match conn.login(&user_hash, &nickname, tcp_port).await {
                            Ok(session) => return Ok((conn, session, resolved_addr)),
                            Err(login_err) if conn.is_encrypted() => {
                                warn!("Encrypted login to {ip_clone}:{port} failed: {login_err}, falling back to plain TCP");
                                emit_server_log(
                                    &app_for_connect,
                                    &format!("Encrypted login failed ({login_err}), trying plain TCP..."),
                                );
                                drop(conn);
                                let plain_addr = tokio::net::lookup_host((ip_clone.as_str(), port))
                                    .await
                                    .map_err(|e| format!("Plain fallback resolve failed: {e}"))?
                                    .find(|addr| addr.is_ipv4())
                                    .ok_or_else(|| format!("No IPv4 address for plain fallback {ip_clone}:{port}"))?;
                                let mut plain_conn = Ed2kServerConnection::connect(plain_addr)
                                    .await
                                    .map_err(|e| format!("Plain fallback connect failed: {e}"))?;
                                emit_server_log(
                                    &app_for_connect,
                                    &format!("Sending login over plain TCP (port {tcp_port})..."),
                                );
                                match plain_conn.login(&user_hash, &nickname, tcp_port).await {
                                    Ok(session) => return Ok((plain_conn, session, plain_addr)),
                                    Err(e) => { last_err = format!("Plain TCP login failed: {e}"); continue; }
                                }
                            }
                            Err(e) => { last_err = format!("Login failed: {e}"); continue; }
                        }
                    }
                    Err(last_err)
                }.await;
                let addr = result
                    .as_ref()
                    .ok()
                    .map(|(_, _, resolved_addr)| *resolved_addr)
                    .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
                ServerConnectResult {
                    addr,
                    ip,
                    port,
                    result: result.map(|(conn, session, _)| (conn, session)),
                }
            }));
        }

        NetworkCommand::DisconnectServer => {
            info!("Disconnecting from ed2k server");
            state.server_auto_reconnect = false;
            if let Some(handle) = state.pending_server_connect.take() {
                handle.abort();
            }
            if let Some(conn) = state.server_connection.take() {
                conn.disconnect().await;
            }
            handle_server_disconnect(state, shared_server_addr, app_handle, "User disconnected").await;
        }

        NetworkCommand::AddServer { ip, port, name: _, tx } => {
            let _ = tx.send(Err(format!("Server list is managed internally; cannot add {ip}:{port}")));
        }

        NetworkCommand::RemoveServer { ip, port, tx } => {
            let _ = tx.send(Err(format!("Server list is managed internally; cannot remove {ip}:{port}")));
        }

        NetworkCommand::GetServerListSnapshot { tx } => {
            let _ = tx.send(state.server_list.servers().iter().map(server_entry_to_info).collect());
        }

        NetworkCommand::GetConnectedServerSnapshot { tx } => {
            let _ = tx.send(connected_server_info(state));
        }

        NetworkCommand::SetUploadPriority { file_hash_hex, priority } => {
            // Push a priority change from the UI directly into the
            // in-memory `KnownFileList` so the upload server's
            // per-request priority lookup sees it without waiting for
            // a reload. Without this hook the new priority sat in the
            // search index but the upload handler — which reads
            // `KnownFileRecord::upload_priority` — kept using the
            // stale value until the next process restart.
            if let Ok(hash_bytes) = hex::decode(&file_hash_hex) {
                if hash_bytes.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&hash_bytes);
                    if let Some(record) = known_files.find_by_hash_mut(&fh) {
                        record.upload_priority = priority;
                        known_files.mark_dirty();
                        debug!(
                            "Updated upload_priority={priority} for {file_hash_hex} in known.met"
                        );
                    }
                }
            }
        }

        NetworkCommand::SharedFilesChanged => {
            let index = local_index.read().await;
            for f in index.all_files() {
                if let Ok(hash_bytes) = hex::decode(&f.hash) {
                    if hash_bytes.len() == 16 {
                        let mut fh = [0u8; 16];
                        fh.copy_from_slice(&hash_bytes);
                        // Refresh-on-drift fix: if a record already
                        // exists for this hash but its `file_path`
                        // or `modified_at` no longer match what we
                        // just discovered on disk, rewrite the
                        // record with the current values. See
                        // `KnownFileList::record_needs_refresh` for
                        // the full rationale — short version, this
                        // breaks the "permanent rehash loop" that
                        // surfaces whenever an external process
                        // touches a shared file's metadata.
                        if known_files.record_needs_refresh(
                            &fh,
                            &f.path,
                            f.size,
                            f.modified_at,
                            &f.name,
                            &f.aich_hash,
                        ) {
                            use crate::storage::known_files::KnownFileRecord;
                            // Preserve cumulative counters from the
                            // existing record (uploaded bytes /
                            // request totals shouldn't reset just
                            // because mtime drifted).
                            let existing = known_files.find_by_hash(&fh).cloned();
                            let (att, atr, ata, prio, lps) = match &existing {
                                Some(r) => (
                                    r.all_time_transferred.max(f.bytes_transferred),
                                    r.all_time_requested.max(f.requests),
                                    r.all_time_accepted.max(f.accepted),
                                    r.upload_priority,
                                    r.last_publish_src,
                                ),
                                None => (
                                    f.bytes_transferred,
                                    f.requests,
                                    f.accepted,
                                    0,
                                    0,
                                ),
                            };
                            let part_hashes = existing
                                .as_ref()
                                .map(|r| r.part_hashes.clone())
                                .unwrap_or_default();
                            known_files.add_or_update(KnownFileRecord {
                                file_hash: fh,
                                part_hashes,
                                file_name: f.name.clone(),
                                file_size: f.size,
                                file_path: f.path.clone(),
                                aich_hash: if !f.aich_hash.is_empty() {
                                    f.aich_hash.clone()
                                } else {
                                    existing
                                        .as_ref()
                                        .map(|r| r.aich_hash.clone())
                                        .unwrap_or_default()
                                },
                                modified_at: f.modified_at,
                                all_time_transferred: att,
                                all_time_requested: atr,
                                all_time_accepted: ata,
                                upload_priority: prio,
                                last_publish_src: lps,
                                last_shared: chrono::Utc::now().timestamp() as u32,
                            });
                        }
                    }
                }
            }
            let mut seen_hashes = std::collections::HashSet::new();
            let files: Vec<PublishableFile> = index.all_files()
                .iter()
                .filter(|f| f.shared)
                .filter_map(|f| {
                    if f.hash.is_empty() || !seen_hashes.insert(f.hash.clone()) {
                        return None;
                    }
                    let hash_bytes = hex::decode(&f.hash).ok()?;
                    if hash_bytes.len() < 16 { return None; }
                    Some(PublishableFile {
                        file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                        file_name: f.name.clone(),
                        file_size: f.size,
                        file_type: crate::search::index::infer_file_type(&f.extension),
                        complete_sources: f.complete_sources,
                    })
                })
                .collect();
            let shared_count = files.len();
            state.publish_manager.clear_all();
            state.publish_manager.add_files_batch(files);
            // Reset the ack map alongside publish state -- the counters
            // correspond to the previous set of published hashes.
            state.source_publish_acks.clear();

            // Re-add active partial downloads to KAD publish after clear
            let mut partial_count = 0u32;
            {
                let mgr = transfer_manager.read().await;
                for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                    if transfer.direction != TransferDirection::Download { continue; }
                    if matches!(transfer.status, TransferStatus::Completed | TransferStatus::Failed) { continue; }
                    if transfer.file_hash.is_empty() || !seen_hashes.insert(transfer.file_hash.clone()) { continue; }
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
                    });
                    partial_count += 1;
                }
            }
            info!("Re-populated publish manager with {shared_count} shared + {partial_count} partial downloads after change");

            // eMule: re-send OP_OFFERFILES to the server when shared files change
            if state.server_connected {
                if let Some(conn) = state.server_connection.as_mut() {
                    let mut seen_offer_hashes = std::collections::HashSet::new();
                    let mut offer_files: Vec<ed2k::server::OfferFile> = index.all_files()
                        .iter()
                        .filter(|f| f.shared)
                        .filter_map(|f| {
                            if f.hash.is_empty() || !seen_offer_hashes.insert(f.hash.clone()) {
                                return None;
                            }
                            let hash_bytes = hex::decode(&f.hash).ok()?;
                            if hash_bytes.len() < 16 {
                                return None;
                            }
                            let mut h = [0u8; 16];
                            h.copy_from_slice(&hash_bytes[..16]);
                            Some(ed2k::server::OfferFile {
                                hash: h,
                                name: f.name.clone(),
                                size: f.size,
                                is_complete: true,
                                file_type: String::new(),
                            })
                        })
                        .collect();
                    let temp_dir = PathBuf::from(&settings.download_folder).join("Temp");
                    {
                        let mgr = transfer_manager.read().await;
                        for transfer in mgr.active.values().chain(mgr.queue.iter()) {
                            if transfer.direction != TransferDirection::Download {
                                continue;
                            }
                            if matches!(transfer.status, TransferStatus::Completed | TransferStatus::Failed) {
                                continue;
                            }
                            if transfer.file_hash.is_empty() || !seen_offer_hashes.insert(transfer.file_hash.clone()) {
                                continue;
                            }
                            let hash_bytes = match hex::decode(&transfer.file_hash) {
                                Ok(bytes) if bytes.len() >= 16 => bytes,
                                _ => continue,
                            };
                            let part_path = temp_dir.join(format!("{}.part", transfer.id));
                            if !part_path.exists() {
                                continue;
                            }
                            let mut h = [0u8; 16];
                            h.copy_from_slice(&hash_bytes[..16]);
                            offer_files.push(ed2k::server::OfferFile {
                                hash: h,
                                name: transfer.file_name.clone(),
                                size: transfer.total_size,
                                is_complete: false,
                                file_type: String::new(),
                            });
                        }
                    }
                    if let Err(e) = conn.offer_files(&offer_files, settings.tcp_port).await {
                        warn!("Failed to re-send OP_OFFERFILES: {e}");
                    }
                }
            }
        }

        NetworkCommand::SetFileComment { file_hash, rating, comment } => {
            state.comment_manager.write().await.set_our_comment(&file_hash, rating, comment.clone());
            if let Err(e) = db.save_file_comment(&file_hash, rating, &comment) {
                warn!("Failed to save comment: {e}");
            }
        }

        NetworkCommand::GetFileComments { file_hash, tx } => {
            let cm = state.comment_manager.read().await;
            let avg = cm.average_rating(&file_hash);
            let fake = cm.has_fake_rating(&file_hash);
            let (_our_rating, _our_comment) = cm.get_our_comment(&file_hash);
            if fake {
                debug!("File {} has fake rating reports", file_hash);
            }
            if avg > 0.0 {
                debug!("File {} average rating: {:.1}", file_hash, avg);
            }
            let _all = cm.all_comments();
            let info = cm.get_comments(&file_hash).cloned();
            let _ = tx.send(info);
        }

        NetworkCommand::MergeServerMet { data, tx } => {
            let result = state.server_list.merge_from_bytes_filtered(
                &data,
                settings.filter_servers_by_ip,
                Some(&mut state.ip_filter),
            );
            if result.is_ok() {
                let met_path = state.data_dir.join("server.met");
                let _ = state.server_list.save_server_met(&met_path);
            }
            let _ = tx.send(result);
        }

        NetworkCommand::PreviewFile { transfer_id, tx } => {
            let result = async {
                let mgr_guard = transfer_manager.read().await;
                let transfer = mgr_guard.get_transfer(&transfer_id)
                    .ok_or_else(|| "Transfer not found".to_string())?;

                let file_name = transfer.file_name.clone();
                let file_size = transfer.total_size;
                let tid = transfer.id.clone();
                drop(mgr_guard);

                let part_path = PathBuf::from(&settings.download_folder)
                    .join("Temp")
                    .join(format!("{tid}.part"));

                if !part_path.exists() {
                    return Err("Part file not found — download may not have started".to_string());
                }

                // `PartTracker::new` reads and parses the `.part.met` file
                // from disk; run it on the blocking pool so the main network
                // loop isn't stalled on sync file IO while the user opens a
                // preview.
                let pp_owned = part_path.clone();
                let tracker_bundle = tokio::task::spawn_blocking(move || {
                    let tracker = ed2k::part_tracker::PartTracker::new(file_size, &pp_owned);
                    let filled_ranges: Vec<ed2k::preview::FilledRange> = tracker
                        .filled_ranges()
                        .into_iter()
                        .map(|(start, end)| ed2k::preview::FilledRange { start, end })
                        .collect();
                    let completed_bytes = tracker.completed_bytes();
                    let has_part_hashes = !tracker.part_hashes().is_empty();
                    let verified_complete_parts = tracker.completed_parts();
                    (filled_ranges, completed_bytes, has_part_hashes, verified_complete_parts)
                })
                .await
                .map_err(|e| format!("Preview task panicked: {e}"))?;
                let (filled_ranges, completed_bytes, has_part_hashes, verified_complete_parts) = tracker_bundle;
                let part_size = ed2k::hash::PARTSIZE;

                if !ed2k::preview::can_preview(
                    &file_name,
                    file_size,
                    completed_bytes,
                    has_part_hashes,
                    &verified_complete_parts,
                    part_size,
                ) {
                    return Err("File is not ready for preview (need the first 256KB downloaded and MD4-verified, and a previewable file type)".to_string());
                }

                let preview_path = ed2k::preview::create_preview_file(&part_path, &filled_ranges, &file_name)
                    .map_err(|e| format!("Failed to create preview file: {e}"))?;

                ed2k::preview::launch_preview(&preview_path)
                    .map_err(|e| format!("Failed to launch preview: {e}"))?;

                Ok::<String, String>(format!("Preview launched: {}", preview_path.display()))
            }.await;
            let _ = tx.send(result);
        }

        // UpdateIpFilterFromUrl removed — download now happens directly in the command handler with DNS-pinned client

        NetworkCommand::SendChatMessage { ember_hash: friend_eh, message, tx } => {
            if settings.friend_chat_disabled {
                let _ = tx.send(Err("Chat is disabled in Friends settings".into()));
            } else {
            let sessions = state.ember_sessions.read().await;
            if let Some(sender) = sessions.get(&friend_eh) {
                let msg_bytes = message.as_bytes();
                let mut packet = Vec::with_capacity(6 + msg_bytes.len());
                packet.push(OP_EMULEPROT);
                let size = (1 + msg_bytes.len()) as u32;
                packet.extend_from_slice(&size.to_le_bytes());
                packet.push(ed2k::messages::OP_EMBER_CHAT_MSG);
                packet.extend_from_slice(msg_bytes);
                match sender.try_send(packet) {
                    Ok(()) => {
                        let hash_hex = hex::encode(friend_eh);
                        let db2 = db.clone();
                        let msg2 = message.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = db2.insert_chat_message(&hash_hex, "sent", &msg2) {
                                tracing::warn!("Failed to persist sent chat message: {e}");
                            }
                        });
                        let _ = app_handle.emit("ember:chat-message", serde_json::json!({
                            "user_hash": hex::encode(friend_eh),
                            "message": message,
                            "direction": "sent",
                            "timestamp": chrono::Utc::now().timestamp(),
                        }));
                        let _ = tx.send(Ok(()));
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => { let _ = tx.send(Err("Connection channel full".into())); }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => { let _ = tx.send(Err("Connection to friend closed".into())); }
                }
            } else {
                drop(sessions);
                if state.outbound_session_tasks.contains_key(&friend_eh) {
                    let _ = tx.send(Err("Connecting to friend, please retry in a moment".into()));
                } else {
                    let db2 = db.clone();
                    let hash_hex = hex::encode(friend_eh);
                    let addr_opt = tokio::task::spawn_blocking(move || db2.get_friend_address(&hash_hex))
                        .await.ok().and_then(|r| r.ok()).flatten();
                    if let Some((ip_str, port)) = addr_opt {
                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                            let addr = SocketAddr::new(ip.into(), port);
                            state.outbound_session_tasks.insert(friend_eh, std::time::Instant::now());
                            let our_user_hash = state.user_hash;
                            let our_ember_hash = ember_hash;
                            let nickname = settings.nickname.clone();
                            let client_id = state.external_ip
                                .map(|eip| u32::from_le_bytes(eip.octets()))
                                .unwrap_or(0);
                            let tcp = settings.tcp_port;
                            let udp = settings.udp_port;
                            let obfs = settings.friend_session_encryption;
                            let sessions_clone = state.ember_sessions.clone();
                            let ul_tx = ul_event_tx.clone();
                            let fh = friend_hashes.clone();
                            let app2 = app_handle.clone();
                            let db3 = db.clone();
                            let msg = message.clone();
                            let ul_tx2 = ul_event_tx.clone();
                            // debug! (not info!) because the Ember hash + address pair
                            // is identity-correlatable PII; we keep it for troubleshooting
                            // but don't surface it in the default log stream.
                            debug!("Auto-connecting to friend {} for chat at {}", hex::encode(friend_eh), addr);
                            tokio::spawn(async move {
                                match ed2k::friend_connect::open_and_run_friend_session(
                                    addr, our_user_hash, our_ember_hash, nickname,
                                    client_id, tcp, udp, obfs, sessions_clone.clone(), ul_tx, fh,
                                    Some(ed25519_pubkey), Some(ed25519_secret_key),
                                ).await {
                                    Ok(handle) => {
                                        let msg_bytes = msg.as_bytes();
                                        let mut packet = Vec::with_capacity(6 + msg_bytes.len());
                                        packet.push(OP_EMULEPROT);
                                        let size = (1 + msg_bytes.len()) as u32;
                                        packet.extend_from_slice(&size.to_le_bytes());
                                        packet.push(ed2k::messages::OP_EMBER_CHAT_MSG);
                                        packet.extend_from_slice(msg_bytes);
                                        if handle.outbound_tx.try_send(packet).is_ok() {
                                            let hash_hex = hex::encode(friend_eh);
                                            let msg_for_db = msg.clone();
                                            tokio::task::spawn_blocking(move || {
                                                if let Err(e) = db3.insert_chat_message(&hash_hex, "sent", &msg_for_db) {
                                                    tracing::warn!("Failed to persist sent chat message: {e}");
                                                }
                                            });
                                            let _ = app2.emit("ember:chat-message", serde_json::json!({
                                                "user_hash": hex::encode(friend_eh),
                                                "message": msg,
                                                "direction": "sent",
                                                "timestamp": chrono::Utc::now().timestamp(),
                                            }));
                                            let _ = tx.send(Ok(()));
                                        } else {
                                            let _ = tx.send(Err("Failed to send on new connection".into()));
                                        }
                                    }
                                    Err(e) => {
                                        debug!("Auto-connect for chat to {} failed: {e}", hex::encode(friend_eh));
                                        let _ = tx.send(Err(format!("Auto-connect failed: {e}")));
                                        let _ = ul_tx2.send(upload_server::UploadEvent {
                                            transfer_id: String::new(),
                                            kind: upload_server::UploadEventKind::EmberFriendDisconnected { ember_hash: friend_eh },
                                        }).await;
                                    }
                                }
                            });
                        } else {
                            let _ = tx.send(Err("Invalid friend IP address".into()));
                        }
                    } else {
                        let rv_url = settings.rendezvous_url.clone();
                        let our_uh = state.user_hash;
                        let our_eh = ember_hash;
                        let nick = settings.nickname.clone();
                        let cid = state.external_ip.map(|eip| u32::from_le_bytes(eip.octets())).unwrap_or(0);
                        let tcp = settings.tcp_port;
                        let udp = settings.udp_port;
                        let obfs = settings.friend_session_encryption;
                        let sess = state.ember_sessions.clone();
                        let ultx = ul_event_tx.clone();
                        let fh = friend_hashes.clone();
                        let app2 = app_handle.clone();
                        let db3 = db.clone();
                        let msg = message.clone();
                        let ultx2 = ul_event_tx.clone();
                        state.outbound_session_tasks.insert(friend_eh, std::time::Instant::now());
                        debug!("No stored address for {}, trying rendezvous for chat", hex::encode(friend_eh));
                        tokio::spawn(async move {
                            match crate::network::rendezvous::lookup(&rv_url, &friend_eh).await {
                                Ok(Some((ip, port))) => {
                                    let addr = std::net::SocketAddr::new(ip.into(), port);
                                    match ed2k::friend_connect::open_and_run_friend_session(
                                        addr, our_uh, our_eh, nick, cid, tcp, udp, obfs, sess, ultx, fh,
                                        Some(ed25519_pubkey), Some(ed25519_secret_key),
                                    ).await {
                                        Ok(handle) => {
                                            let msg_bytes = msg.as_bytes();
                                            let mut packet = Vec::with_capacity(6 + msg_bytes.len());
                                            packet.push(OP_EMULEPROT);
                                            let size = (1 + msg_bytes.len()) as u32;
                                            packet.extend_from_slice(&size.to_le_bytes());
                                            packet.push(ed2k::messages::OP_EMBER_CHAT_MSG);
                                            packet.extend_from_slice(msg_bytes);
                                            if handle.outbound_tx.try_send(packet).is_ok() {
                                                let hash_hex = hex::encode(friend_eh);
                                                let msg_for_db = msg.clone();
                                                tokio::task::spawn_blocking(move || {
                                                    if let Err(e) = db3.insert_chat_message(&hash_hex, "sent", &msg_for_db) {
                                                        tracing::warn!("Failed to persist sent chat message: {e}");
                                                    }
                                                });
                                                let _ = app2.emit("ember:chat-message", serde_json::json!({
                                                    "user_hash": hex::encode(friend_eh),
                                                    "message": msg,
                                                    "direction": "sent",
                                                    "timestamp": chrono::Utc::now().timestamp(),
                                                }));
                                                let _ = app2.emit("ember:friend-online", serde_json::json!({
                                                    "user_hash": hex::encode(friend_eh),
                                                }));
                                                let _ = tx.send(Ok(()));
                                            } else {
                                                let _ = tx.send(Err("Failed to send on new connection".into()));
                                            }
                                        }
                                        Err(e) => {
                                            let _ = tx.send(Err(format!("Could not connect: {e}")));
                                            let _ = ultx2.send(upload_server::UploadEvent {
                                                transfer_id: String::new(),
                                                kind: upload_server::UploadEventKind::EmberFriendDisconnected { ember_hash: friend_eh },
                                            }).await;
                                        }
                                    }
                                }
                                _ => {
                                    let _ = tx.send(Err("Friend is offline".into()));
                                }
                            }
                        });
                    }
                }
            }
            }
        }

        NetworkCommand::BrowseFriend { ember_hash: friend_eh, tx } => {
            if settings.friend_browse_disabled {
                let _ = tx.send(Err("Browse is disabled in Friends settings".into()));
            } else {
                let sessions = state.ember_sessions.read().await;
                if let Some(sender) = sessions.get(&friend_eh) {
                    let mut packet = Vec::with_capacity(6);
                    packet.push(OP_EMULEPROT);
                    let size: u32 = 1;
                    packet.extend_from_slice(&size.to_le_bytes());
                    packet.push(ed2k::messages::OP_EMBER_BROWSE_REQ);
                    match sender.try_send(packet) {
                        Ok(()) => { let _ = tx.send(Ok(())); }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => { let _ = tx.send(Err("Connection channel full".into())); }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => { let _ = tx.send(Err("Connection to friend closed".into())); }
                    }
                } else {
                    drop(sessions);
                    if state.outbound_session_tasks.contains_key(&friend_eh) {
                        let _ = tx.send(Err("Connecting to friend, please retry in a moment".into()));
                    } else {
                        let db2 = db.clone();
                        let hash_hex = hex::encode(friend_eh);
                        let addr_opt = tokio::task::spawn_blocking(move || db2.get_friend_address(&hash_hex))
                            .await.ok().and_then(|r| r.ok()).flatten();
                        if let Some((ip_str, port)) = addr_opt {
                            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                let addr = SocketAddr::new(ip.into(), port);
                                state.outbound_session_tasks.insert(friend_eh, std::time::Instant::now());
                                let our_user_hash = state.user_hash;
                                let our_ember_hash = ember_hash;
                                let nickname = settings.nickname.clone();
                                let client_id = state.external_ip
                                    .map(|eip| u32::from_le_bytes(eip.octets()))
                                    .unwrap_or(0);
                                let tcp = settings.tcp_port;
                                let udp = settings.udp_port;
                                let obfs = settings.friend_session_encryption;
                                let sessions_clone = state.ember_sessions.clone();
                                let ul_tx = ul_event_tx.clone();
                                let fh = friend_hashes.clone();
                                let ul_tx2 = ul_event_tx.clone();
                                info!("Auto-connecting to friend {} for browse at {}", hex::encode(friend_eh), addr);
                                tokio::spawn(async move {
                                    match ed2k::friend_connect::open_and_run_friend_session(
                                        addr, our_user_hash, our_ember_hash, nickname,
                                        client_id, tcp, udp, obfs, sessions_clone.clone(), ul_tx, fh,
                                        Some(ed25519_pubkey), Some(ed25519_secret_key),
                                    ).await {
                                        Ok(handle) => {
                                            let mut packet = Vec::with_capacity(6);
                                            packet.push(OP_EMULEPROT);
                                            let size: u32 = 1;
                                            packet.extend_from_slice(&size.to_le_bytes());
                                            packet.push(ed2k::messages::OP_EMBER_BROWSE_REQ);
                                            // Surface a real error to the caller if the
                                            // browse packet couldn't even be queued
                                            // (channel full or session closed mid-spawn).
                                            // The previous `let _ = ...; tx.send(Ok(()))`
                                            // pattern reported success unconditionally,
                                            // and the UI had no way to know the request
                                            // never went out.
                                            match handle.outbound_tx.try_send(packet) {
                                                Ok(()) => {
                                                    let _ = tx.send(Ok(()));
                                                }
                                                Err(e) => {
                                                    let _ = tx.send(Err(format!(
                                                        "Friend session opened but browse request could not be queued: {e}"
                                                    )));
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            info!("Auto-connect for browse to {} failed: {e}", hex::encode(friend_eh));
                                            let _ = tx.send(Err(format!("Could not connect: {e}")));
                                            let _ = ul_tx2.send(upload_server::UploadEvent {
                                                transfer_id: String::new(),
                                                kind: upload_server::UploadEventKind::EmberFriendDisconnected { ember_hash: friend_eh },
                                            }).await;
                                        }
                                    }
                                });
                            } else {
                                let _ = tx.send(Err("Invalid friend IP address".into()));
                            }
                        } else {
                            let rv_url = settings.rendezvous_url.clone();
                            let our_uh = state.user_hash;
                            let our_eh = ember_hash;
                            let nick = settings.nickname.clone();
                            let cid = state.external_ip.map(|eip| u32::from_le_bytes(eip.octets())).unwrap_or(0);
                            let tcp = settings.tcp_port;
                            let udp = settings.udp_port;
                            let obfs = settings.friend_session_encryption;
                            let sess = state.ember_sessions.clone();
                            let ultx = ul_event_tx.clone();
                            let fh = friend_hashes.clone();
                            let app2 = app_handle.clone();
                            let ultx2 = ul_event_tx.clone();
                            state.outbound_session_tasks.insert(friend_eh, std::time::Instant::now());
                            info!("No stored address for {}, trying rendezvous for browse", hex::encode(friend_eh));
                            tokio::spawn(async move {
                                match crate::network::rendezvous::lookup(&rv_url, &friend_eh).await {
                                    Ok(Some((ip, port))) => {
                                        let addr = std::net::SocketAddr::new(ip.into(), port);
                                        match ed2k::friend_connect::open_and_run_friend_session(
                                            addr, our_uh, our_eh, nick, cid, tcp, udp, obfs, sess, ultx, fh,
                                            Some(ed25519_pubkey), Some(ed25519_secret_key),
                                        ).await {
                                            Ok(handle) => {
                                                let mut packet = Vec::with_capacity(6);
                                                packet.push(OP_EMULEPROT);
                                                let size: u32 = 1;
                                                packet.extend_from_slice(&size.to_le_bytes());
                                                packet.push(ed2k::messages::OP_EMBER_BROWSE_REQ);
                                                // See sibling tx.send() above — surface a
                                                // real error rather than reporting success
                                                // when the outbound channel rejected the
                                                // browse packet.
                                                match handle.outbound_tx.try_send(packet) {
                                                    Ok(()) => {
                                                        let _ = app2.emit("ember:friend-online", serde_json::json!({
                                                            "user_hash": hex::encode(friend_eh),
                                                        }));
                                                        let _ = tx.send(Ok(()));
                                                    }
                                                    Err(e) => {
                                                        let _ = tx.send(Err(format!(
                                                            "Friend session opened but browse request could not be queued: {e}"
                                                        )));
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                let _ = tx.send(Err(format!("Could not connect: {e}")));
                                                let _ = ultx2.send(upload_server::UploadEvent {
                                                    transfer_id: String::new(),
                                                    kind: upload_server::UploadEventKind::EmberFriendDisconnected { ember_hash: friend_eh },
                                                }).await;
                                            }
                                        }
                                    }
                                    _ => {
                                        let _ = tx.send(Err("Friend is offline".into()));
                                    }
                                }
                            });
                        }
                    }
                }
            }
        }

        NetworkCommand::FriendRemoved { ember_hash: removed_hash } => {
            state.online_friends.remove(&removed_hash);
            state.ember_sessions.write().await.remove(&removed_hash);
        }

        NetworkCommand::ConnectForFriendRequest { ember_hash: target_hash, ip, port } => {
            let addr = SocketAddr::new(ip.into(), port);
            let our_user_hash = state.user_hash;
            let our_ember_hash = ember_hash;
            let nickname = settings.nickname.clone();
            let client_id = state.external_ip
                .map(|eip| u32::from_le_bytes(eip.octets()))
                .unwrap_or(0);
            let tcp = settings.tcp_port;
            let udp = settings.udp_port;
            let obfs = settings.friend_session_encryption;
            let db3 = db.clone();
            let app2 = app_handle.clone();
            let fh = friend_hashes.clone();
            let sess = state.ember_sessions.clone();
            let ultx = ul_event_tx.clone();
            let target_hex = hex::encode(target_hash);
            info!("Initiating proactive friend connect to {} at {}", target_hex, addr);
            tokio::spawn(async move {
                match ed2k::friend_connect::connect_and_send_friend_request(
                    addr,
                    &our_user_hash,
                    &our_ember_hash,
                    &nickname,
                    client_id,
                    tcp,
                    udp,
                    obfs,
                    Some(ed25519_pubkey),
                    Some(ed25519_secret_key),
                ).await {
                    Ok(Some(remote_eh)) => {
                        info!("Friend connect to {} succeeded, remote ember_hash={}", addr, hex::encode(remote_eh));
                        if fh.read().await.contains(&remote_eh) {
                            // Do NOT auto-flip mutual: ember_hash in the remote handshake is
                            // self-reported and unverified (FUTURE_WORK.md F2). We still emit
                            // "confirmed" to clear the searching spinner and mark online, but
                            // mutual promotion must come from an explicit user accept on an
                            // inbound friend request.
                            let _ = app2.emit("ember:friend-confirmed", serde_json::json!({
                                "user_hash": hex::encode(remote_eh),
                            }));
                            let _ = app2.emit("ember:friend-online", serde_json::json!({
                                "user_hash": hex::encode(remote_eh),
                            }));
                            if !sess.read().await.contains_key(&remote_eh) {
                                info!("Opening persistent session to {} after proactive friend connect", addr);
                                if let Err(e) = ed2k::friend_connect::open_and_run_friend_session(
                                    addr, our_user_hash, our_ember_hash, nickname,
                                    client_id, tcp, udp, obfs, sess, ultx.clone(), fh,
                                    Some(ed25519_pubkey), Some(ed25519_secret_key),
                                ).await {
                                    info!("Persistent session to {} failed: {e}", addr);
                                    let _ = ultx.send(upload_server::UploadEvent {
                                        transfer_id: String::new(),
                                        kind: upload_server::UploadEventKind::EmberFriendDisconnected { ember_hash: remote_eh },
                                    }).await;
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        info!("Friend connect to {} succeeded (no reciprocal request yet)", addr);
                    }
                    Err(e) => {
                        let emsg = format!("{e}");
                        let reason = if emsg.contains("timeout") { "timeout" }
                            else if emsg.contains("refused") { "refused" }
                            else { "error" };
                        info!("Friend connect to {} failed (clearing stale address): {e}", addr);
                        let _ = tokio::task::spawn_blocking(move || db3.clear_friend_address(&target_hex));
                        let _ = app2.emit("ember:friend-search-failed", serde_json::json!({
                            "user_hash": hex::encode(target_hash),
                            "reason": reason,
                        }));
                    }
                }
            });
        }

        NetworkCommand::FindFriendAndConnect { ember_hash: target_hash } => {
            if !state.outbound_session_tasks.contains_key(&target_hash) {
                state.outbound_session_tasks.insert(target_hash, std::time::Instant::now());
                let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                    "user_hash": hex::encode(target_hash),
                }));
                spawn_rendezvous_friend_lookup(
                    &settings, &state, ember_hash, target_hash,
                    &db, &app_handle, &friend_hashes, &ul_event_tx,
                    ed25519_pubkey, ed25519_secret_key,
                );
            }
        }

        NetworkCommand::RetryFriendSearch { ember_hash: target_hash, tx } => {
            let hash_hex = hex::encode(target_hash);

            if state.online_friends.contains_key(&target_hash) || state.ember_sessions.read().await.contains_key(&target_hash) {
                info!("RetryFriendSearch: {} already online/connected", hash_hex);
                let _ = tx.send(Ok(()));
                return;
            }

            state.outbound_session_tasks.insert(target_hash, std::time::Instant::now());
            let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                "user_hash": hash_hex,
            }));

            spawn_rendezvous_friend_lookup(
                &settings, &state, ember_hash, target_hash,
                &db, &app_handle, &friend_hashes, &ul_event_tx,
                ed25519_pubkey, ed25519_secret_key,
            );

            let _ = tx.send(Ok(()));
        }

        NetworkCommand::EnsureFriendSession { ember_hash: target_hash, tx } => {
            // Already have a session?
            if state.ember_sessions.read().await.contains_key(&target_hash) {
                let _ = tx.send(Ok(()));
                return;
            }
            // Already connecting?
            if state.outbound_session_tasks.contains_key(&target_hash) {
                let _ = tx.send(Ok(()));
                return;
            }
            // Look up friend address from DB
            let db2 = db.clone();
            let hash_hex = hex::encode(target_hash);
            let addr_opt = tokio::task::spawn_blocking(move || db2.get_friend_address(&hash_hex))
                .await
                .ok()
                .and_then(|r| r.ok())
                .flatten();

            if let Some((ip_str, port)) = addr_opt {
                if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                    let addr = SocketAddr::new(ip.into(), port);
                    state.outbound_session_tasks.insert(target_hash, std::time::Instant::now());
                    let our_user_hash = state.user_hash;
                    let nickname = settings.nickname.clone();
                    let client_id = state.external_ip
                        .map(|eip| u32::from_le_bytes(eip.octets()))
                        .unwrap_or(0);
                    let tcp = settings.tcp_port;
                    let udp = settings.udp_port;
                    let obfs = settings.friend_session_encryption;
                    let sessions = state.ember_sessions.clone();
                    let ul_tx = ul_event_tx.clone();
                    let fh = friend_hashes.clone();
                    info!("Opening outbound friend session to {} at {}", hex::encode(target_hash), addr);
                    tokio::spawn(async move {
                        match ed2k::friend_connect::open_and_run_friend_session(
                            addr, our_user_hash, ember_hash, nickname,
                            client_id, tcp, udp, obfs,
                            sessions, ul_tx, fh,
                            Some(ed25519_pubkey), Some(ed25519_secret_key),
                        ).await {
                            Ok(_handle) => {
                                info!("Outbound friend session to {} established", hex::encode(target_hash));
                            }
                            Err(e) => {
                                info!("Failed to open friend session to {}: {e}", hex::encode(target_hash));
                            }
                        }
                    });
                    let _ = tx.send(Ok(()));
                } else {
                    let _ = tx.send(Err("Invalid friend IP address".into()));
                }
            } else {
                info!("No stored address for {}, trying rendezvous for session", hex::encode(target_hash));
                let _ = app_handle.emit("ember:friend-searching", serde_json::json!({
                    "user_hash": hex::encode(target_hash),
                }));
                spawn_rendezvous_friend_lookup(
                    &settings, &state, ember_hash, target_hash,
                    &db, &app_handle, &friend_hashes, &ul_event_tx,
                    ed25519_pubkey, ed25519_secret_key,
                );
                let _ = tx.send(Ok(()));
            }
        }

        NetworkCommand::GetPeerReputation { user_hash, tx } => {
            let info = state.reputation.get_peer(&user_hash).map(|p| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                PeerReputationInfo {
                    score: p.score,
                    successful_transfers: p.successful_transfers,
                    failed_transfers: p.failed_transfers,
                    is_banned: p.is_banned(now),
                    first_seen: p.first_seen,
                    last_interaction: p.last_interaction,
                }
            });
            let _ = tx.send(info);
        }

        NetworkCommand::GetReputationStats { tx } => {
            let _ = tx.send(ReputationStatsInfo {
                tracked_peers: state.reputation.tracked_count(),
                banned_peers: state.reputation.banned_count(),
            });
        }

        NetworkCommand::Shutdown => {}
    }
}

/// Re-verify a .part file that was fully downloaded but the app crashed before
/// completion.  On success, moves the file to `Downloads/` and cleans up.
async fn reverify_complete_part_file(
    transfer_id: &str,
    file_hash: &str,
    file_name: &str,
    file_size: u64,
    download_dir: &std::path::Path,
) -> anyhow::Result<()> {
    let part_path = download_dir
        .join("Temp")
        .join(format!("{transfer_id}.part"));
    let expected = file_hash.to_string();
    let verify_path = part_path.clone();
    let computed_hash = tokio::task::spawn_blocking(move || {
        ed2k::hash::ed2k_hash_file(&verify_path)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;

    if computed_hash != expected {
        anyhow::bail!("Re-verification hash mismatch — .part preserved for retry");
    }

    let safe_name = crate::security::sanitize_filename(file_name);
    let completed_dir = download_dir.join("Downloads");
    tokio::fs::create_dir_all(&completed_dir).await
        .map_err(|e| anyhow::anyhow!("Failed to create Downloads dir: {e}"))?;
    let final_target = completed_dir.join(&safe_name);
    let pp = part_path.clone();
    tokio::task::spawn_blocking(move || {
        ed2k::transfer::move_part_to_final(&pp, &final_target)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking: {e}"))??;

    // Clean up .part.met
    let met_path = part_path.with_extension("part.met");
    let _ = tokio::fs::remove_file(&met_path).await;

    info!(
        "Re-verified and completed restored download {transfer_id} ({file_name}, {file_size} bytes)"
    );
    Ok(())
}

async fn handle_download_event(
    event: DownloadEvent,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    db: &Arc<Database>,
    promoted_out: &mut Vec<Transfer>,
    stats_manager: &mut StatsManager,
    remove_finished: bool,
    a4af: &Arc<RwLock<ed2k::a4af::A4AFManager>>,
    download_folder: &str,
    db_progress_last_persist: &mut HashMap<String, std::time::Instant>,
    db_progress_persist_interval: std::time::Duration,
) {
    match event {
        DownloadEvent::Progress {
            transfer_id,
            downloaded,
            total,
        } => {
            let capped_downloaded = if total > 0 { downloaded.min(total) } else { downloaded };
            let speed = {
                let mut mgr = transfer_manager.write().await;
                mgr.update_progress(&transfer_id, capped_downloaded, 0);
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
                if let Err(e) = db.update_transfer_progress(&transfer_id, capped_downloaded, progress, speed) {
                    warn!("DB update_transfer_progress failed for {transfer_id}: {e}");
                }
                db_progress_last_persist.insert(transfer_id.clone(), std::time::Instant::now());
            }
            let _ = app_handle.emit(
                "transfer-progress",
                &crate::types::TransferProgressPayload {
                    id: &transfer_id,
                    downloaded: capped_downloaded,
                    total,
                    progress,
                    speed,
                    uploaded: None,
                    direction: None,
                    upload_time: None,
                },
            );
        }
        DownloadEvent::Verifying { transfer_id } => {
            {
                let mut mgr = transfer_manager.write().await;
                mgr.update_status(&transfer_id, crate::types::TransferStatus::Verifying);
            }
            if let Err(e) = db.update_transfer_status(&transfer_id, "verifying") {
                warn!("DB update_transfer_status('verifying') failed for {transfer_id}: {e}");
            }
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
            {
                let mut mgr = transfer_manager.write().await;
                mgr.update_sources(&transfer_id, total, active, queued);
            }
            let _ = app_handle.emit(
                "transfer-sources",
                &crate::types::TransferSourcesPayload {
                    id: &transfer_id,
                    sources: total,
                    active_sources: active,
                    queued_sources: queued,
                },
            );
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
                "queued" => crate::types::SourceStatus::Queued,
                "queue_full" => crate::types::SourceStatus::QueueFull,
                "no_needed_parts" => crate::types::SourceStatus::NoNeededParts,
                "transferring" => crate::types::SourceStatus::Transferring,
                "completed" => crate::types::SourceStatus::Completed,
                _ => crate::types::SourceStatus::Failed,
            };
            {
                let mut mgr = transfer_manager.write().await;
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
                        source_origin: None,
                    },
                );
            }
            if status == "queued" || status == "transferring" {
                if let Ok(addr) = format!("{ip}:{port}").parse::<std::net::SocketAddr>() {
                    let mut a4af_lock = a4af.write().await;
                    a4af_lock.update_source_state(
                        addr,
                        queue_rank.unwrap_or(0).min(u16::MAX as u32) as u16,
                        status != "queued" || queue_rank.unwrap_or(u32::MAX) < 500,
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
                    "status": status,
                    "queue_rank": queue_rank,
                    "speed": speed,
                    "transferred": transferred,
                    "client_software": client_software,
                    "peer_name": peer_name,
                    "available_parts": available_parts,
                    "total_parts": total_parts,
                    "country_code": country_code,
                }),
            );
        }
        DownloadEvent::Completed { transfer_id } => {
            stats_manager.record_completed_download();
            // Flush the final in-memory progress snapshot to the DB before
            // changing status. Progress persistence is rate-limited during
            // the download, so the last persisted row could be up to a few
            // seconds stale; make sure the terminal state reflects reality.
            let final_progress = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&transfer_id)
                    .map(|t| (t.transferred, t.progress, t.speed))
            };
            if let Some((transferred, progress, speed)) = final_progress {
                if let Err(e) = db.update_transfer_progress(&transfer_id, transferred, progress, speed) {
                    warn!("DB update_transfer_progress (final) failed for {transfer_id}: {e}");
                }
            }
            db_progress_last_persist.remove(&transfer_id);
            if let Some(promoted) = {
                let mut mgr = transfer_manager.write().await;
                mgr.complete(&transfer_id)
            } {
                for t in &promoted {
                    info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
                }
                promoted_out.extend(promoted);
            } else {
                warn!("Completed event for transfer {transfer_id} not found in active set");
            }
            if let Err(e) = db.update_transfer_status(&transfer_id, "completed") {
                warn!("DB update_transfer_status('completed') failed for {transfer_id}: {e}");
            }

            {
                let mgr = transfer_manager.read().await;
                if let Some(t) = mgr.get_transfer(&transfer_id) {
                    if let Err(e) = db.record_download_history(&t.file_hash, &t.file_name, t.total_size, "completed") {
                        tracing::warn!("Failed to record download history: {e}");
                    }
                }
            }

            let _ = app_handle.emit(
                "transfer-complete",
                serde_json::json!({ "id": transfer_id }),
            );

            // Defensive cleanup: remove any leftover .part / .part.met files
            // that should have been moved/deleted during the completion flow.
            let temp_dir = PathBuf::from(download_folder).join("Temp");
            let part_path = temp_dir.join(format!("{transfer_id}.part"));
            let met_path = temp_dir.join(format!("{transfer_id}.part.met"));
            if part_path.exists() {
                if let Err(e) = tokio::fs::remove_file(&part_path).await {
                    warn!("Failed to clean up leftover .part after completion: {} — {e}", part_path.display());
                } else {
                    info!("Cleaned up leftover .part file for completed download {transfer_id}");
                }
            }
            if met_path.exists() {
                let _ = tokio::fs::remove_file(&met_path).await;
            }

            if remove_finished {
                let mut mgr = transfer_manager.write().await;
                mgr.remove(&transfer_id);
                let _ = db.remove_transfer(&transfer_id);
            }
        }
        DownloadEvent::Failed { transfer_id, error, failure_kind } => {
            let failure_stage = ed2k::transfer::infer_stage_from_error(&error).to_string();
            let failure_kind_name = ed2k::transfer::failure_kind_name(&failure_kind);
            let failure_summary = ed2k::transfer::summarize_error(&error, &failure_kind);
            let current_status = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&transfer_id).map(|t| t.status.clone())
            };
            if matches!(current_status, Some(TransferStatus::Paused | TransferStatus::Stopped)) {
                return;
            }
            // Flush final progress snapshot (see Completed above) and drop
            // the rate-limit cache entry so a re-queue of the same id starts
            // with a fresh budget.
            let final_progress = {
                let mgr = transfer_manager.read().await;
                mgr.get_transfer(&transfer_id)
                    .map(|t| (t.transferred, t.progress, t.speed))
            };
            if let Some((transferred, progress, speed)) = final_progress {
                if let Err(e) = db.update_transfer_progress(&transfer_id, transferred, progress, speed) {
                    warn!("DB update_transfer_progress (final) failed for {transfer_id}: {e}");
                }
            }
            db_progress_last_persist.remove(&transfer_id);
            if let Some(promoted) = {
                let mut mgr = transfer_manager.write().await;
                mgr.fail(
                    &transfer_id,
                    &failure_summary,
                    Some(failure_kind_name.clone()),
                    Some(failure_stage.clone()),
                )
            } {
                for t in &promoted {
                    info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
                }
                promoted_out.extend(promoted);
            } else {
                warn!("Failed event for transfer {transfer_id} not found in active set");
            }
            if let Err(e) = db.update_transfer_status(&transfer_id, "failed") {
                warn!("DB update_transfer_status('failed') failed for {transfer_id}: {e}");
            }
            let _ = app_handle.emit(
                "transfer-failed",
                serde_json::json!({
                    "id": transfer_id,
                    "error": failure_summary,
                    "failure_kind": failure_kind_name,
                    "failure_stage": failure_stage,
                }),
            );
        }
        DownloadEvent::SourceExchange { .. } => {
            // Handled directly in the network event loop (source injection).
        }
        DownloadEvent::EmberSources { .. } | DownloadEvent::EmberPeerDiscovered { .. } | DownloadEvent::EmberFriendRequest { .. } => {
            // Handled directly in the network event loop (EPX source injection / peer tracking / friend requests).
        }
        DownloadEvent::DataReceived { .. }
        | DownloadEvent::PartVerified { .. }
        | DownloadEvent::PartCorrupted { .. }
        | DownloadEvent::AichRecoveryFailed { .. }
        | DownloadEvent::PartFileReady { .. }
        | DownloadEvent::FriendSeen { .. }
        | DownloadEvent::EmberChatMessage { .. }
        | DownloadEvent::EmberBrowseResponse { .. } => {
            // Handled directly in the network event loop.
        }
    }
}

async fn handle_upload_event(
    event: UploadEvent,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    promoted_out: &mut Vec<Transfer>,
    stats_manager: &mut StatsManager,
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
                stalled_since: None,
                category: String::new(),
                wait_time: 0,
                upload_time: 0,
                a4af_sources: 0,
                max_sources: 0,
                preview_priority: false,
                ember_sources: 0,
                client_software,
                country_code,
                user_hash,
            };
            {
                let mut mgr = transfer_manager.write().await;
                mgr.enqueue(transfer.clone());
            }
            let _ = app_handle.emit(
                "transfer-started",
                &transfer,
            );
        }
        UploadEventKind::Progress { uploaded, total } => {
            let capped_uploaded = if total > 0 { uploaded.min(total) } else { uploaded };
            let (speed, upload_time_ms) = {
                let mut mgr = transfer_manager.write().await;
                mgr.update_progress(&event.transfer_id, capped_uploaded, 0);
                let t = mgr.active.get_mut(&event.transfer_id);
                let speed = t.as_ref().map(|t| t.speed).unwrap_or(0);
                let ut = t.map(|t| {
                    let elapsed = (chrono::Utc::now().timestamp() - t.started_at).max(0) as u64 * 1000;
                    t.upload_time = elapsed;
                    elapsed
                }).unwrap_or(0);
                (speed, ut)
            };
            let progress = if total > 0 {
                ((capped_uploaded as f64 / total as f64) * 100.0).min(100.0)
            } else {
                0.0
            };
            let _ = app_handle.emit(
                "transfer-progress",
                &crate::types::TransferProgressPayload {
                    id: &event.transfer_id,
                    downloaded: 0,
                    total,
                    progress,
                    speed,
                    uploaded: Some(capped_uploaded),
                    direction: Some("upload"),
                    upload_time: Some(upload_time_ms),
                },
            );
        }
        UploadEventKind::ShareInterest { .. } => {}
        UploadEventKind::Completed => {
            stats_manager.record_completed_upload();
            // Match eMule's "session ends → row vanishes" UX. We still
            // call `mgr.complete()` so the queued-promotion logic fires
            // and stats are accurate, but we then immediately drop the
            // transfer from `mgr.completed` so a subsequent `get_all()`
            // poll doesn't resurrect the row in the upload pane after
            // the frontend has already removed it on `transfer-complete`.
            // Cumulative byte totals live in `StatsManager`, not in the
            // per-session `Transfer`, so dropping the row loses no
            // historical data.
            let promoted = match {
                let mut mgr = transfer_manager.write().await;
                let promoted = mgr.complete(&event.transfer_id);
                mgr.completed.retain(|t| t.id != event.transfer_id);
                promoted
            } {
                Some(promoted) => promoted,
                None => return,
            };
            for t in &promoted {
                info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
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
            let promoted = match {
                let mut mgr = transfer_manager.write().await;
                let promoted = mgr.fail(&event.transfer_id, &error, None, None);
                mgr.completed.retain(|t| t.id != event.transfer_id);
                promoted
            } {
                Some(promoted) => promoted,
                None => return,
            };
            for t in &promoted {
                info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
            }
            promoted_out.extend(promoted);
            let _ = app_handle.emit(
                "transfer-failed",
                serde_json::json!({ "id": event.transfer_id, "error": error, "direction": "upload" }),
            );
        }
        UploadEventKind::EmberSources { .. }
        | UploadEventKind::EmberPeerDiscovered { .. }
        | UploadEventKind::FriendSeen { .. }
        | UploadEventKind::EmberChatMessage { .. }
        | UploadEventKind::EmberBrowseRequest { .. }
        | UploadEventKind::EmberBrowseResponse { .. }
        | UploadEventKind::EmberFriendDisconnected { .. }
        | UploadEventKind::EmberFriendRequest { .. } => {
            // Handled directly in the network event loop.
        }
    }
}

fn name_spam_penalty(name: &str) -> usize {
    let lower = name.to_lowercase();
    let mut score = 0;
    for pat in ["http://", "https://", "www.", ".com/", ".org/", ".net/", "download at", "powered by"] {
        if lower.contains(pat) { score += 10; }
    }
    score += name.matches('[').count().saturating_sub(1) * 3;
    score
}

fn convert_search_results(
    entries: &[kad::messages::SearchResultEntry],
) -> Vec<SearchResult> {
    use crate::search::index::infer_file_type;

    struct ParsedEntry {
        hash: String,
        name: String,
        size: u64,
        file_type: String,
        extension: String,
        source_addr: String,
        sources_tag: u32,
        complete_sources_tag: u32,
        rating: Option<u8>,
        comment: Option<String>,
    }

    let parsed: Vec<ParsedEntry> = entries
        .iter()
        .filter_map(|entry| {
            let mut name = String::new();
            let mut size = 0u64;
            let mut file_type = String::new();
            let mut source_ip = 0u32;
            let mut source_port = 0u16;
            let mut sources_tag = 0u32;
            let mut complete_sources_tag = 0u32;
            let mut rating: Option<u8> = None;
            let mut comment: Option<String> = None;

            for tag in &entry.tags {
                match &tag.name {
                    TagName::Id(TAG_FILENAME) => {
                        if let Some(s) = tag.string_value() {
                            name = s.to_string();
                        }
                    }
                    TagName::Id(TAG_FILESIZE) => {
                        if let Some(v) = tag.uint64_value() {
                            size = v;
                        } else if let Some(v) = tag.uint32_value() {
                            size = v as u64;
                        }
                    }
                    TagName::Id(TAG_FILETYPE) => {
                        if let Some(s) = tag.string_value() {
                            file_type = s.to_string();
                        }
                    }
                    TagName::Id(TAG_SOURCES) => {
                        if let Some(v) = tag.uint32_value() {
                            sources_tag = v;
                        } else if let TagValue::Uint16(v) = &tag.value {
                            sources_tag = *v as u32;
                        }
                    }
                    TagName::Id(TAG_COMPLETE_SOURCES) => {
                        if let Some(v) = tag.uint32_value() {
                            complete_sources_tag = v;
                        } else if let Some(v) = tag.uint16_value() {
                            complete_sources_tag = v as u32;
                        }
                    }
                    TagName::Id(TAG_SOURCEIP) => {
                        if let Some(v) = tag.uint32_value() {
                            source_ip = v;
                        }
                    }
                    TagName::Id(TAG_SOURCEPORT) => {
                        if let Some(v) = tag.uint16_value() {
                            source_port = v;
                        }
                    }
                    TagName::Id(TAG_FILERATING) => {
                        if let Some(v) = tag.uint32_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint16_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint8_value() {
                            rating = Some(v);
                        }
                    }
                    TagName::Str(s) if s == "filerating" => {
                        if let Some(v) = tag.uint32_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint16_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint8_value() {
                            rating = Some(v);
                        }
                    }
                    TagName::Id(TAG_DESCRIPTION) => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    TagName::Str(s) if s == "description" => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    _ => {}
                }
            }

            if name.is_empty() {
                return None;
            }

            let extension = name
                .rsplit_once('.')
                .map(|(_, ext)| ext.to_string())
                .unwrap_or_default();

            let inferred = infer_file_type(&extension);
            if !inferred.is_empty() {
                file_type = inferred;
            }

            let source_addr = if source_ip != 0 {
                let ip = Ipv4Addr::from(source_ip.to_be_bytes());
                format!("{}:{}", ip, source_port)
            } else {
                String::new()
            };

            // entry.id is the KAD ID (byte-swapped MD4). Reverse the swap
            // to get the raw MD4 hash needed for ED2K file transfers.
            let raw_md4 = kad_id_to_md4_bytes(&entry.id);
            Some(ParsedEntry {
                hash: hex::encode(raw_md4),
                name,
                size,
                file_type,
                extension,
                source_addr,
                sources_tag,
                complete_sources_tag,
                rating,
                comment,
            })
        })
        .collect();

    // Deduplicate by file hash, accumulating source counts across KAD nodes.
    // In eMule (CSearch::ProcessResult), each search result entry with the
    // same file hash adds to the source count. If TAG_SOURCES is 0 or absent,
    // the entry still counts as 1 source (the publishing node itself).
    let mut dedup: HashMap<String, SearchResult> = HashMap::new();
    let mut sources_accum: HashMap<String, u32> = HashMap::new();
    let mut complete_accum: HashMap<String, u32> = HashMap::new();

    for p in parsed {
        let effective_sources = if p.sources_tag > 0 { p.sources_tag } else { 1 };

        if let Some(existing) = dedup.get_mut(&p.hash) {
            existing.result_origin = crate::search::merge::combine_origin(
                &existing.result_origin,
                crate::search::merge::ORIGIN_KAD,
            );
            if !p.source_addr.is_empty() && !existing.source_addresses.contains(&p.source_addr) {
                existing.source_addresses.push(p.source_addr);
            }
            let acc = sources_accum.entry(p.hash.clone()).or_insert(0);
            *acc += effective_sources;
            existing.availability = (*acc).max(existing.source_addresses.len() as u32);

            let cs = complete_accum.entry(p.hash.clone()).or_insert(0);
            *cs += p.complete_sources_tag;
            existing.file.complete_sources = *cs;

            if name_spam_penalty(&p.name) < name_spam_penalty(&existing.file.name) {
                existing.file.name = p.name;
            }
            if existing.file_type.is_empty() && !p.file_type.is_empty() {
                existing.file_type = p.file_type;
            }
            if existing.rating.is_none() && p.rating.is_some() {
                existing.rating = p.rating;
            }
            if existing.comment.is_none() && p.comment.is_some() {
                existing.comment = p.comment;
            }
        } else {
            let mut source_addresses = Vec::new();
            if !p.source_addr.is_empty() {
                source_addresses.push(p.source_addr.clone());
            }
            let availability = effective_sources.max(source_addresses.len() as u32);
            sources_accum.insert(p.hash.clone(), effective_sources);
            complete_accum.insert(p.hash.clone(), p.complete_sources_tag);
            dedup.insert(
                p.hash.clone(),
                SearchResult {
                    file: FileInfo {
                        id: p.hash.clone(),
                        name: p.name,
                        path: String::new(),
                        size: p.size,
                        hash: p.hash,
                        aich_hash: String::new(),
                        extension: p.extension,
                        modified_at: 0,
                        priority: "normal".to_string(),
                        requests: 0,
                        accepted: 0,
                        bytes_transferred: 0,
                        alltime_requests: 0,
                        alltime_accepted: 0,
                        alltime_transferred: 0,
                        complete_sources: p.complete_sources_tag,
                        folder: String::new(),
                        shared: false,
                        shared_kad: false,
                        shared_ed2k: false,
                    },
                    peer_id: p.source_addr,
                    peer_name: String::new(),
                    availability,
                    file_type: p.file_type,
                    source_addresses,
                    rating: p.rating,
                    comment: p.comment,
                    spam_rating: 0,
                    is_spam: false,
                    clean_name: String::new(),
                    result_origin: crate::search::merge::ORIGIN_KAD.to_string(),
                },
            );
        }
    }

    let mut results: Vec<SearchResult> = dedup.into_values().collect();
    crate::search::merge::sort_search_results(&mut results);

    // Log availability distribution for debugging
    let with_multi_sources = results.iter().filter(|r| r.availability > 1).count();
    if !results.is_empty() {
        let max_avail = results.iter().map(|r| r.availability).max().unwrap_or(0);
        info!(
            "convert_search_results: {} unique files from {} raw entries, {} with >1 source, max availability={}",
            results.len(), entries.len(), with_multi_sources, max_avail
        );
    }

    results
}

fn convert_note_search_results(
    entries: &[kad::messages::SearchResultEntry],
    file_hash: &KadId,
) -> Vec<SearchResult> {
    let forced_hash = hex::encode(kad_id_to_md4_bytes(file_hash));

    entries
        .iter()
        .filter_map(|entry| {
            let mut name = String::new();
            let mut size = 0u64;
            let mut rating: Option<u8> = None;
            let mut comment: Option<String> = None;

            for tag in &entry.tags {
                match &tag.name {
                    TagName::Id(TAG_FILENAME) => {
                        if let Some(s) = tag.string_value() {
                            name = s.to_string();
                        }
                    }
                    TagName::Id(TAG_FILESIZE) => {
                        if let Some(v) = tag.uint64_value() {
                            size = v;
                        } else if let Some(v) = tag.uint32_value() {
                            size = v as u64;
                        }
                    }
                    TagName::Id(TAG_FILERATING) => {
                        if let Some(v) = tag.uint32_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint16_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint8_value() {
                            rating = Some(v);
                        }
                    }
                    TagName::Id(TAG_DESCRIPTION) => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    TagName::Str(s) if s == "filerating" => {
                        if let Some(v) = tag.uint32_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint16_value() {
                            rating = Some(v as u8);
                        } else if let Some(v) = tag.uint8_value() {
                            rating = Some(v);
                        }
                    }
                    TagName::Str(s) if s == "description" => {
                        if let Some(s) = tag.string_value() {
                            comment = Some(s.to_string());
                        }
                    }
                    _ => {}
                }
            }

            if rating.is_none() && comment.as_ref().is_none_or(|c| c.is_empty()) {
                return None;
            }

            let publisher_hex = entry.id.to_hex();
            let peer_name = publisher_hex.chars().take(8).collect::<String>();

            Some(SearchResult {
                file: FileInfo {
                    id: forced_hash.clone(),
                    name: if name.is_empty() { "File note".to_string() } else { name },
                    path: String::new(),
                    size,
                    hash: forced_hash.clone(),
                    aich_hash: String::new(),
                    extension: String::new(),
                    modified_at: 0,
                    priority: "normal".to_string(),
                    requests: 0,
                    accepted: 0,
                    bytes_transferred: 0,
                    alltime_requests: 0,
                    alltime_accepted: 0,
                    alltime_transferred: 0,
                    complete_sources: 0,
                    folder: String::new(),
                    shared: false,
                    shared_kad: false,
                    shared_ed2k: false,
                },
                peer_id: publisher_hex,
                peer_name,
                availability: 0,
                file_type: String::new(),
                source_addresses: Vec::new(),
                rating,
                comment,
                spam_rating: 0,
                is_spam: false,
                clean_name: String::new(),
                result_origin: crate::search::merge::ORIGIN_NOTES.to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
struct KadSource {
    ip: Ipv4Addr,
    tcp_port: u16,
    udp_port: u16,
    source_type: u8,
    connect_options: u8,
    buddy_ip: Option<Ipv4Addr>,
    buddy_port: Option<u16>,
    buddy_hash: Option<KadId>,
    /// For source-search results this is the publisher's ED2K user hash.
    source_user_hash: Option<[u8; 16]>,
    /// Type-2: eD2K LowID value (0 = not a LowID source).
    lowid: u32,
    /// Type-2: eD2K server IP (network u32).
    ed2k_server_ip: u32,
    /// Type-2: eD2K server TCP port.
    ed2k_server_port: u16,
    /// `true` if this peer advertised `EMBER_CAP_RELAY_PUNCH_V1` in the
    /// KAD source publish (string tag `"ember"`). Other Ember peers gate
    /// LowID-to-LowID broker attempts on this — see the broker call
    /// sites in this file. Defaults to `false` for any source we
    /// haven't seen the tag from (vanilla eMule peers, type-2 LowID
    /// sources from the ed2k server, or older Ember peers from before
    /// this tag existed).
    is_ember_capable: bool,
}

/// Returns true if this `KadSource` actually describes us — either by
/// matching our externally-visible `(IP, TCP port)` pair or by carrying
/// our ed2k `user_hash`.
///
/// Self-sources arise naturally after a publish cycle: we publish
/// `(SourceIP=our_ext_ip, SourcePort=our_tcp_port, SourceUID=our_user_hash)`
/// to the DHT nodes closest to each file hash, and a subsequent source
/// search for the same hash converges on those same nodes, which
/// dutifully hand our own entry back to us. Injecting it as a download
/// source wastes an idx slot and produces a noisy
/// "Injected source N failed: stage:hello_wait" line when we attempt to
/// connect to ourselves. The user-hash check also catches the dynamic
/// IP case where our publishes were made under a different IP than the
/// one we report now.
fn is_self_source(src: &KadSource, state: &NetworkState) -> bool {
    if let Some(ext) = state.external_ip {
        if src.ip == ext && src.tcp_port == state.tcp_port {
            return true;
        }
    }
    if let Some(uh) = src.source_user_hash {
        if uh == state.user_hash {
            return true;
        }
    }
    false
}

fn extract_kad_sources(
    entries: &[kad::messages::SearchResultEntry],
) -> Vec<KadSource> {
    let mut sources = Vec::new();
    for entry in entries {
        let mut ip = 0u32;
        let mut port = 0u16;
        let mut udp_port = 0u16;
        let mut source_type = 0u8;
        let mut connect_options = 0u8;
        let mut server_ip = 0u32;
        let mut server_port = 0u16;
        let mut buddy_hash: Option<[u8; 16]> = None;
        let mut is_ember_capable = false;
        for tag in &entry.tags {
            match &tag.name {
                TagName::Id(TAG_SOURCEIP) => {
                    if let Some(v) = tag.uint32_value() { ip = v; }
                }
                TagName::Id(TAG_SOURCEPORT) => {
                    if let Some(v) = tag.uint16_value() { port = v; }
                }
                TagName::Id(TAG_SOURCEUPORT) => {
                    if let Some(v) = tag.uint16_value() { udp_port = v; }
                }
                TagName::Id(TAG_SOURCETYPE) => {
                    if let Some(v) = tag.uint8_value() { source_type = v; }
                }
                TagName::Id(TAG_ENCRYPTION) => {
                    if let Some(v) = tag.uint8_value() { connect_options = v; }
                }
                TagName::Id(TAG_SERVERIP) => {
                    if let Some(v) = tag.uint32_value() { server_ip = v; }
                }
                TagName::Id(TAG_SERVERPORT) => {
                    if let Some(v) = tag.uint16_value() { server_port = v; }
                }
                TagName::Id(TAG_BUDDYHASH) => {
                    if let Some(h) = tag.hash_value() {
                        buddy_hash = Some(h);
                    } else if let Some(s) = tag.string_value() {
                        if let Ok(bytes) = hex::decode(s) {
                            if bytes.len() == 16 {
                                let mut h = [0u8; 16];
                                h.copy_from_slice(&bytes);
                                buddy_hash = Some(h);
                            }
                        }
                    }
                }
                // Ember capability advertisement — see the corresponding
                // emit site in `kad/publish.rs::build_source_publish` and
                // `EMBER_CAP_RELAY_PUNCH_V1`. Bit 0 means "speaks Ember
                // v1 LowID-to-LowID protocol". Higher bits are reserved.
                // Vanilla eMule peers won't carry this tag so the field
                // stays `false`, which is exactly what gates the broker.
                TagName::Str(s) if s == "ember" => {
                    if let Some(v) = tag.uint8_value() {
                        is_ember_capable =
                            (v & kad::publish::EMBER_CAP_RELAY_PUNCH_V1) != 0;
                    }
                }
                _ => {}
            }
        }

        let source_user_hash = if entry.id.0 != [0u8; 16] {
            Some(cuint128_swap(&entry.id.0))
        } else {
            None
        };

        match source_type {
            1 | 4 => {
                if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    if !sources.iter().any(|s: &KadSource| s.ip == addr && s.tcp_port == port) {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                        });
                    }
                }
            }
            2 => {
                if ip > 0 && ip < ed2k::server::LOWID_THRESHOLD && server_ip != 0 && server_port != 0 {
                    if !sources.iter().any(|s: &KadSource| s.lowid == ip && s.ed2k_server_ip == server_ip) {
                        sources.push(KadSource {
                            ip: Ipv4Addr::UNSPECIFIED,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: ip,
                            ed2k_server_ip: server_ip,
                            ed2k_server_port: server_port,
                            is_ember_capable,
                        });
                    }
                } else if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    if !sources.iter().any(|s: &KadSource| s.ip == addr && s.tcp_port == port) {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                        });
                    }
                }
            }
            3 | 5 => {
                // Prefer callback path when buddy data is present, otherwise fall back
                // to direct candidate handling for interoperability with mixed clients.
                if server_ip != 0 && server_port != 0 {
                    let source_addr = Ipv4Addr::from(ip.to_be_bytes());
                    let b_ip = Ipv4Addr::from(server_ip.to_be_bytes());
                    let b_hash = buddy_hash.map(KadId);
                    if !sources.iter().any(|s: &KadSource| s.buddy_ip == Some(b_ip) && s.buddy_port == Some(server_port)) {
                        sources.push(KadSource {
                            ip: source_addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: Some(b_ip),
                            buddy_port: Some(server_port),
                            buddy_hash: b_hash,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                        });
                    }
                } else if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    debug!("Source type {} without buddy tags, treating {addr}:{port} as direct fallback", source_type);
                    if !sources.iter().any(|s: &KadSource| s.ip == addr && s.tcp_port == port) {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                        });
                    }
                }
            }
            6 => {
                if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    debug!("Type-6 source {addr}:{port} treated as direct fallback");
                    if !sources.iter().any(|s: &KadSource| s.ip == addr && s.tcp_port == port) {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                        });
                    }
                }
            }
            _ => {
                if ip != 0 && port != 0 {
                    let addr = Ipv4Addr::from(ip.to_be_bytes());
                    if !sources.iter().any(|s: &KadSource| s.ip == addr && s.tcp_port == port) {
                        sources.push(KadSource {
                            ip: addr,
                            tcp_port: port,
                            udp_port,
                            source_type: 3,
                            connect_options,
                            buddy_ip: None,
                            buddy_port: None,
                            buddy_hash: None,
                            source_user_hash,
                            lowid: 0,
                            ed2k_server_ip: 0,
                            ed2k_server_port: 0,
                            is_ember_capable,
                        });
                    }
                }
            }
        }
    }
    sources
}

#[derive(Debug, Clone)]
enum KadSearchExpr {
    And(Box<KadSearchExpr>, Box<KadSearchExpr>),
    Or(Box<KadSearchExpr>, Box<KadSearchExpr>),
    Not(Box<KadSearchExpr>, Box<KadSearchExpr>),
    String(String),
    MetaString { tag: SearchTagRef, value: String },
    Numeric { tag: SearchTagRef, op: KadNumericOp, value: u64 },
}

#[derive(Debug, Clone)]
enum SearchTagRef {
    Id(u8),
    Str(String),
}

#[derive(Debug, Clone, Copy)]
enum KadNumericOp {
    Eq,
    Gt,
    Lt,
    Ge,
    Le,
    Ne,
}

fn parse_kad_search_expression(data: &[u8]) -> Option<KadSearchExpr> {
    if data.is_empty() {
        return None;
    }
    let mut cursor = Cursor::new(data);
    // K5: hostile peers can craft a deep left-leaning boolean expression
    // in a ~64 KiB UDP packet; recursive descent would blow the stack.
    // Cap both depth and total node count. eMule's own SearchKeyReq
    // expressions are trivially small in practice (a few leaves).
    let mut node_budget: u32 = 256;
    let expr = parse_kad_search_expression_node(&mut cursor, 0, &mut node_budget).ok()?;
    if cursor.position() as usize != data.len() {
        return None;
    }
    Some(expr)
}

/// Maximum nesting depth for a KAD search expression. Chosen so a legit
/// `(a AND b AND c AND d AND ...)` of 32 conjuncts still parses but
/// nothing remotely close to stack exhaustion is possible.
const MAX_KAD_SEARCH_EXPR_DEPTH: u32 = 32;

fn parse_kad_search_expression_node(
    cursor: &mut Cursor<&[u8]>,
    depth: u32,
    node_budget: &mut u32,
) -> std::io::Result<KadSearchExpr> {
    if depth >= MAX_KAD_SEARCH_EXPR_DEPTH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "search expression nested too deeply",
        ));
    }
    if *node_budget == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "search expression exceeded node-count budget",
        ));
    }
    *node_budget -= 1;
    match ReadBytesExt::read_u8(cursor)? {
        0x00 => {
            let op = ReadBytesExt::read_u8(cursor)?;
            let left = Box::new(parse_kad_search_expression_node(cursor, depth + 1, node_budget)?);
            let right = Box::new(parse_kad_search_expression_node(cursor, depth + 1, node_budget)?);
            match op {
                0x00 => Ok(KadSearchExpr::And(left, right)),
                0x01 => Ok(KadSearchExpr::Or(left, right)),
                0x02 => Ok(KadSearchExpr::Not(left, right)),
                _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown boolean search operator")),
            }
        }
        0x01 => Ok(KadSearchExpr::String(read_kad_search_string(cursor)?)),
        0x02 => {
            let value = read_kad_search_string(cursor)?;
            let tag = read_kad_search_tag_ref(cursor)?;
            Ok(KadSearchExpr::MetaString { tag, value })
        }
        0x03 => {
            let value = ReadBytesExt::read_u32::<LittleEndian>(cursor)? as u64;
            let op = read_kad_numeric_op(ReadBytesExt::read_u8(cursor)?)?;
            let tag = read_kad_search_tag_ref(cursor)?;
            Ok(KadSearchExpr::Numeric { tag, op, value })
        }
        0x08 => {
            let value = ReadBytesExt::read_u64::<LittleEndian>(cursor)?;
            let op = read_kad_numeric_op(ReadBytesExt::read_u8(cursor)?)?;
            let tag = read_kad_search_tag_ref(cursor)?;
            Ok(KadSearchExpr::Numeric { tag, op, value })
        }
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown search expression node")),
    }
}

fn read_kad_numeric_op(op: u8) -> std::io::Result<KadNumericOp> {
    match op {
        0x00 => Ok(KadNumericOp::Eq),
        0x01 => Ok(KadNumericOp::Gt),
        0x02 => Ok(KadNumericOp::Lt),
        0x03 => Ok(KadNumericOp::Ge),
        0x04 => Ok(KadNumericOp::Le),
        0x05 => Ok(KadNumericOp::Ne),
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown numeric search operator")),
    }
}

fn read_kad_search_string(cursor: &mut Cursor<&[u8]>) -> std::io::Result<String> {
    let len = ReadBytesExt::read_u16::<LittleEndian>(cursor)? as usize;
    let start = cursor.position() as usize;
    let end = start.saturating_add(len);
    if end > cursor.get_ref().len() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "search string exceeds payload"));
    }
    let bytes = &cursor.get_ref()[start..end];
    cursor.set_position(end as u64);
    Ok(String::from_utf8_lossy(bytes).to_string())
}

fn read_kad_search_tag_ref(cursor: &mut Cursor<&[u8]>) -> std::io::Result<SearchTagRef> {
    let len = ReadBytesExt::read_u16::<LittleEndian>(cursor)? as usize;
    let start = cursor.position() as usize;
    let end = start.saturating_add(len);
    if end > cursor.get_ref().len() {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "search tag name exceeds payload"));
    }
    let bytes = &cursor.get_ref()[start..end];
    cursor.set_position(end as u64);
    if len == 1 {
        Ok(SearchTagRef::Id(bytes[0]))
    } else {
        Ok(SearchTagRef::Str(String::from_utf8_lossy(bytes).to_string().to_lowercase()))
    }
}

fn matches_search_expr_for_local_file(expr: &KadSearchExpr, file_name: &str, file_size: u64) -> bool {
    let lower_name = file_name.to_lowercase();
    let extension = file_name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_string())
        .unwrap_or_default();
    let file_type = crate::search::index::infer_file_type(&extension);
    let tags = vec![
        KadTag { name: TagName::Id(TAG_FILETYPE), value: TagValue::String(file_type) },
    ];
    matches_search_expr_impl(expr, &lower_name, file_size, Some(&tags))
}

fn matches_search_expr_for_entry(expr: &KadSearchExpr, entry: &kad::messages::SearchResultEntry) -> bool {
    let file_name = entry.tags.iter()
        .find(|tag| matches!(&tag.name, TagName::Id(TAG_FILENAME)))
        .and_then(|tag| tag.string_value())
        .unwrap_or_default()
        .to_lowercase();
    let file_size = entry.tags.iter()
        .find_map(search_entry_tag_u64)
        .unwrap_or(0);
    matches_search_expr_impl(expr, &file_name, file_size, Some(&entry.tags))
}

fn search_entry_tag_u64(tag: &KadTag) -> Option<u64> {
    if !matches!(&tag.name, TagName::Id(TAG_FILESIZE)) {
        return None;
    }
    tag.uint64_value()
        .or_else(|| tag.uint32_value().map(|v| v as u64))
        .or_else(|| tag.uint16_value().map(|v| v as u64))
        .or_else(|| tag.uint8_value().map(|v| v as u64))
}

fn matches_search_expr_impl(
    expr: &KadSearchExpr,
    lower_name: &str,
    file_size: u64,
    tags: Option<&[KadTag]>,
) -> bool {
    match expr {
        KadSearchExpr::And(left, right) => {
            matches_search_expr_impl(left, lower_name, file_size, tags)
                && matches_search_expr_impl(right, lower_name, file_size, tags)
        }
        KadSearchExpr::Or(left, right) => {
            matches_search_expr_impl(left, lower_name, file_size, tags)
                || matches_search_expr_impl(right, lower_name, file_size, tags)
        }
        KadSearchExpr::Not(left, right) => {
            matches_search_expr_impl(left, lower_name, file_size, tags)
                && !matches_search_expr_impl(right, lower_name, file_size, tags)
        }
        KadSearchExpr::String(value) => lower_name.contains(&value.to_lowercase()),
        KadSearchExpr::MetaString { tag, value } => {
            let value = value.to_lowercase();
            if tag_matches_filename(tag) {
                lower_name.contains(&value)
            } else if let Some(tags) = tags {
                tags.iter()
                    .find(|entry_tag| tag_name_matches(tag, &entry_tag.name))
                    .and_then(|entry_tag| entry_tag.string_value())
                    .map(|entry_value| entry_value.to_lowercase().contains(&value))
                    .unwrap_or(false)
            } else {
                false
            }
        }
        KadSearchExpr::Numeric { tag, op, value } => {
            let numeric = if tag_matches_filesize(tag) {
                Some(file_size)
            } else if let Some(tags) = tags {
                tags.iter()
                    .find(|entry_tag| tag_name_matches(tag, &entry_tag.name))
                    .and_then(|entry_tag| {
                        entry_tag.uint64_value()
                            .or_else(|| entry_tag.uint32_value().map(|v| v as u64))
                            .or_else(|| entry_tag.uint16_value().map(|v| v as u64))
                            .or_else(|| entry_tag.uint8_value().map(|v| v as u64))
                    })
            } else {
                None
            };
            numeric.map(|actual| match op {
                KadNumericOp::Eq => actual == *value,
                KadNumericOp::Gt => actual > *value,
                KadNumericOp::Lt => actual < *value,
                KadNumericOp::Ge => actual >= *value,
                KadNumericOp::Le => actual <= *value,
                KadNumericOp::Ne => actual != *value,
            }).unwrap_or(false)
        }
    }
}

fn tag_name_matches(search_tag: &SearchTagRef, tag_name: &TagName) -> bool {
    match (search_tag, tag_name) {
        (SearchTagRef::Id(a), TagName::Id(b)) => a == b,
        (SearchTagRef::Str(a), TagName::Str(b)) => a == &b.to_lowercase(),
        (SearchTagRef::Str(a), TagName::Id(b)) if a.len() == 1 => a.as_bytes()[0] == *b,
        _ => false,
    }
}

fn tag_matches_filename(tag: &SearchTagRef) -> bool {
    match tag {
        SearchTagRef::Id(id) => *id == TAG_FILENAME,
        SearchTagRef::Str(name) => name == "filename" || name == "name",
    }
}

fn tag_matches_filesize(tag: &SearchTagRef) -> bool {
    match tag {
        SearchTagRef::Id(id) => *id == TAG_FILESIZE,
        SearchTagRef::Str(name) => name == "filesize" || name == "size",
    }
}

fn matches_requested_file_size(entry: &kad::messages::SearchResultEntry, requested_size: u64) -> bool {
    if requested_size == 0 {
        return true;
    }
    entry.tags.iter().find_map(search_entry_tag_u64).map(|size| size == requested_size).unwrap_or(true)
}
