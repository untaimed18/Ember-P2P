mod api;
mod bans;
mod browse;
mod channel_gossip;
mod channel_membership;
mod channel_relay;
mod channel_xfer;
mod chat;
pub(crate) mod chat_attach;
mod command;
mod downloads;
pub mod ed2k;
pub mod ember;
mod ember_dht;
mod ember_peers;
mod ember_publish;
mod ember_publishing;
mod ember_search;
mod ember_udp;
mod event_loop;
mod friend_transfer;
mod friends;
mod health;
pub mod kad;
mod kad_io;
mod kad_search;
mod nat_mapping;
mod persistence;
mod publishing;
pub mod rendezvous;
mod search;
mod server;
mod settings;
mod snapshots;
mod sources;
mod state;
mod transfer_events;
mod udp;
pub mod upnp;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};
use futures::FutureExt;
use tauri::{Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::search::index::LocalIndex;
use crate::sharing::manager::{
    TransferControl, TransferHealthCode, TransferHealthUpdate, TransferManager,
};
use crate::storage::database::{ChannelMemberWrite, Database};
use crate::types::*;

use self::ed2k::a4af::A4AFManager;
use self::ed2k::comments::CommentManager;
use self::ed2k::corruption_blackbox::CorruptionBlackBox;
use self::ed2k::credits::CreditManager;
use self::ed2k::dead_sources::DeadSourceList;
use self::ed2k::messages::{OP_EDONKEYHEADER, OP_EMULEPROT, OP_PORTTEST};
use self::ed2k::multi_source::{DownloadSource, MultiSourceDownload, SharedTrackerRegistry};
use self::ed2k::server::Ed2kServerConnection;
use self::ed2k::server_list::{ServerEntry, ServerList};
use self::ed2k::server_udp::{ServerUdpResponse, ServerUdpSocket};
use self::ed2k::sources::SourceManager;
use self::ed2k::transfer::{classify_error, DownloadEvent, Ed2kDownload, SourceFailureKind};
use self::ed2k::upload::{self as upload_server, UploadEvent, UploadEventKind};
use self::kad::bootstrap;
use self::kad::buddy::{BuddyEvent, BuddyManager, BuddyState, PendingBuddySet};
use self::kad::firewall::FirewallChecker;
use self::kad::ip_filter::{IpFilter, IpFilterStats};
use self::kad::legacy_challenge::LegacyChallengeTracker;
use self::kad::messages::{self, KadMessage};
use self::kad::obfuscation;
use self::kad::protection::FloodProtection;
use self::kad::publish::{
    kad_id_to_md4_bytes, md4_bytes_to_kad_id, round_robin_next, KeywordPublishBatch,
    PublishManager, PublishableFile,
};
use self::kad::routing::RoutingTable;
use self::kad::search::{
    SearchId, SearchManager, SearchPhase, SearchType, SEARCH_INITIAL_CONTACTS, STOP_GRACE_SECS,
    STORE_PUBLISH_TARGET_TOTAL,
};
use self::kad::store::DhtStore;
use self::kad::types::*;

use crate::storage::known_files::KnownFileList;
use crate::storage::statistics::{StatsManager, TransferStats};

use self::browse::{
    bind_browse_request_to_session, browse_request_is_pending, cancel_browse_request,
    complete_browse_request, dispatch_browse_head, enqueue_browse_request, remove_browse_request,
    remove_browse_requests_for_session, send_browse_response_to_origin, PendingBrowseRequests,
};
use self::command::handle_command;
use self::ember_publish::{
    ember_batch_ack_deadline, EmberBatchInFlight, EmberBatchPublisher, EmberFlushStats,
    EmberPublishAttempts, EmberPublishKind, EmberPublishPassStats, EmberRecordRef,
    EMBER_BATCH_ACK_TIMEOUT, EMBER_BATCH_QUEUE_MAX, EMBER_FLUSH_INTERVAL,
    EMBER_MAX_BATCH_FRAMES_PER_PEER, EMBER_PUBLISH_MAX_ATTEMPTS,
    EMBER_STORE_RECORDS_PER_PEER_PER_MIN, K_EMBER_REPLICAS,
};
use self::health::{
    ActiveSourceInjectionStats, FriendRelayTicketPollResult, KnownMetSaveResult, NatProbeResult,
    PeriodicSaveJob, PeriodicSaveResult, PublishHealthSnapshot, RendezvousRegisterResult,
    ServerConnectResult, SourceInjectionResult, SpamSaveResult, TcpMappingKeepaliveResult,
    TcpPortConfirmation, UdpDiscoveryHealthSnapshot, UdpMappingKeepaliveResult, UpnpMaintainResult,
    XferFinishResult,
};

use self::api::*;
use self::bans::*;
use self::channel_gossip::*;
use self::channel_membership::*;
use self::channel_relay::*;
use self::channel_xfer::*;
use self::chat::*;
use self::downloads::*;
use self::ember_dht::*;
use self::ember_peers::*;
use self::ember_publishing::*;
use self::ember_search::*;
use self::ember_udp::*;
use self::event_loop::*;
use self::friend_transfer::*;
use self::friends::*;
use self::kad_io::*;
use self::kad_search::*;
use self::nat_mapping::*;
use self::persistence::*;
use self::publishing::*;
use self::search::*;
use self::server::*;
use self::settings::*;
use self::snapshots::*;
use self::sources::*;
use self::state::*;
use self::transfer_events::*;
use self::udp::*;

pub use self::api::{
    ChannelTransferSnapshot, EmberDhtContactInfo, EmberDhtSearchInfo, EmberDhtStoreInfo,
    NetworkCommand, PeerReputationInfo, ReputationStatsInfo, SearchFilters, SearchMethod,
};
pub(crate) use self::downloads::{
    apply_transfer_completion_write, apply_transfer_status_write, transfer_status_write_clock,
    TransferStatusWriteClock,
};
pub(crate) use self::friends::{deliver_friend_request_verdict, FriendRequestVerdict};
pub use self::server::{clear_server_log_history, server_log_history, ServerLogLine};
pub use self::state::{
    EmberMaintenanceResult, EmberPublishPending, EmberPublishResult, EmberValueLookupPending,
};
#[cfg(debug_assertions)]
pub use self::state::{EmberDhtFindPending, EmberDhtLookupPending, EmberPingPending};

fn relay_ticket_next_round_delay(
    round_started_at: tokio::time::Instant,
    completed_at: tokio::time::Instant,
) -> std::time::Duration {
    (round_started_at + rendezvous::FRIEND_RELAY_TICKET_RESPONDER_POLL_INTERVAL)
        .saturating_duration_since(completed_at)
}

/// This mirrors the rendezvous server's accepted-ticket cap. Keeping the
/// responder's active join/session work bounded prevents a hostile or slow
/// relay endpoint from accumulating background tasks across poll cycles.
const MAX_FRIEND_RELAY_TICKET_SESSIONS: usize = 8;

const PERIODIC_SAVE_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(300);
const SHORT_IO_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(60);
const NAT_PROBE_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(20);
/// Realistic worst-case STUN/TCP-hold cycle is 79s: 3×(5+8) + 4×(5+5)
/// (DNS+connect timeouts on three TCP-hold targets then four TCP STUN
/// servers). The QUIC keep-alive is a parallel DNS lookup (≤5s) plus an
/// immediate datagram and does not add. Pathological (every STUN write/read
/// stage also times out) is ~139s: 3×(5+8) + 4×(5+5+5+5+5). 90s is not
/// sized to wait that out — a cycle still running then has already missed
/// four `MAPPING_KEEPALIVE_INTERVAL`s (20s) and cannot hold a NAT mapping
/// open. Abandoning it is intentional (~1s cost); the generation guard
/// discards the late result.
const MAPPING_KA_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(90);
const RENDEZVOUS_REGISTER_WATCHDOG: std::time::Duration = std::time::Duration::from_secs(60);

/// Everything [`start_network`] needs from the rest of the application.
///
/// The network task owns the single `NetworkState` and drives ed2k, KAD and
/// Ember from one place, so it is wired to nearly every other subsystem. This
/// struct exists only to carry that wiring as one value instead of 25
/// positional parameters; the fields are destructured back into locals at the
/// top of `start_network` and used exactly as the parameters were. Field
/// order matches the original parameter order so binding and drop order are
/// unchanged.
pub struct NetworkDeps {
    // --- Runtime handles ---
    /// Tauri handle used for event emission and resource/data path lookups.
    pub app_handle: tauri::AppHandle,
    /// Inbound commands from the Tauri command layer. Not clonable: the
    /// network task is the sole consumer, so `start_network` takes
    /// `NetworkDeps` by value.
    pub cmd_rx: mpsc::Receiver<NetworkCommand>,

    // --- Configuration and identity ---
    /// Settings snapshot at boot; mutated in place by `SettingsUpdated`.
    pub settings: AppSettings,
    /// Long-lived node identity (KAD ID, user hash, Ember keys).
    pub identity: Arc<crate::storage::identity::NodeIdentity>,
    /// Gate that must report loaded before any socket is bound.
    pub security_policy: Arc<crate::security::policy::SecurityPolicyGate>,

    // --- Storage and local index ---
    /// Index of locally shared files, shared with the sharing/scan tasks.
    pub local_index: Arc<RwLock<LocalIndex>>,
    /// Side-channel cache of freshly computed part hashes, keyed by file hash.
    pub fresh_part_hashes: Arc<RwLock<HashMap<[u8; 16], Vec<[u8; 16]>>>>,
    /// Application database (transfers, friends, chat, known files).
    pub db: Arc<Database>,

    // --- Transfers and bandwidth ---
    /// Download/upload bookkeeping shared with the sharing manager.
    pub transfer_manager: Arc<RwLock<TransferManager>>,
    /// Global up/down rate limiter.
    pub bandwidth_limiter: Arc<BandwidthLimiter>,

    // --- Snapshot caches read by the IPC/command layer ---
    // The network task publishes into these so Tauri commands can answer
    // without blocking on the network task itself.
    pub shared_peers: Arc<RwLock<Vec<PeerInfo>>>,
    pub shared_stats: Arc<RwLock<NetworkStats>>,
    pub shared_contacts: Arc<RwLock<Vec<KadContactInfo>>>,
    pub shared_searches: Arc<RwLock<Vec<KadSearchInfo>>>,
    pub shared_servers: Arc<RwLock<Vec<ServerInfo>>>,
    pub shared_connected_server: Arc<RwLock<Option<ServerInfo>>>,
    pub shared_transfer_stats: Arc<RwLock<TransferStats>>,
    pub shared_files: Arc<RwLock<Vec<FileInfo>>>,

    // --- Sharing and friends ---
    /// Shared folder list consulted by the upload listener.
    pub upload_shared_folders: crate::app_state::SharedFolderList,
    /// User hashes of accepted friends.
    pub friend_hashes: crate::app_state::SharedFriendHashes,
    /// Subset of `friend_hashes` where friendship is confirmed both ways.
    pub mutual_friend_hashes: crate::app_state::SharedFriendHashes,

    // --- Upload slot scheduling (USS) ---
    pub uss_rtt_queue: crate::bandwidth::UssRttQueue,
    pub uss_enabled_flag: crate::bandwidth::UssEnabledFlag,

    // --- Search support services ---
    /// Keyword/result spam classifier.
    pub spam_filter: Arc<RwLock<crate::search::spam::SpamFilter>>,
    /// eD2K file comment/rating store.
    pub comment_manager: Arc<RwLock<CommentManager>>,
}

pub async fn start_network(deps: NetworkDeps) -> anyhow::Result<()> {
    let NetworkDeps {
        app_handle,
        mut cmd_rx,
        mut settings,
        identity,
        security_policy,
        local_index,
        fresh_part_hashes,
        db,
        transfer_manager,
        bandwidth_limiter,
        shared_peers,
        shared_stats,
        shared_contacts,
        shared_searches,
        shared_servers,
        shared_connected_server,
        shared_transfer_stats,
        shared_files,
        upload_shared_folders,
        friend_hashes,
        mutual_friend_hashes,
        uss_rtt_queue,
        uss_enabled_flag,
        spam_filter,
        comment_manager,
    } = deps;
    // Do not bind KAD/eD2K/Ember sockets or start the upload listener while a
    // recovered/reset policy database is awaiting explicit acknowledgement.
    while !security_policy.is_loaded() {
        tokio::select! {
            command = cmd_rx.recv() => {
                match command {
                    Some(NetworkCommand::Shutdown { .. }) | None => return Ok(()),
                    Some(_) => {
                        warn!("Dropping network command while security policy reset is unacknowledged");
                    }
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
        }
    }
    // Taken after the policy wait, which drops commands: a line sent during it
    // never reaches the retry queue and belongs to the startup sweep.
    let channel_sweep_cutoff = chrono::Utc::now().timestamp();
    let data_dir = crate::storage::paths::ensure_data_dir().unwrap_or_else(|_| PathBuf::from("."));

    let geoip = crate::geoip::empty();
    let geoip_resource_dir = app_handle
        .path()
        .resource_dir()
        .unwrap_or_else(|_| PathBuf::from("."));

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
                let _ = app_handle.emit(
                    "network-error",
                    serde_json::json!({
                        "message": format!("Failed to create UDP socket: {e}"),
                    }),
                );
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
    let udp_socket = Arc::new(udp_socket);
    let udp_port = bound_udp_port;
    if udp_port != settings.udp_port {
        warn!(
            "Configured UDP port {} was unavailable, bound to port {} instead",
            settings.udp_port, udp_port
        );
        let _ = app_handle.emit("network-warning", serde_json::json!({
            "message": format!("UDP port {} was in use. Using port {} instead.", settings.udp_port, udp_port),
        }));
    }
    info!("UDP socket bound on port {udp_port}");

    // The connection broker binds a *second* UDP socket for QUIC on the
    // configured `tcp_port`, so `tcp_port == udp_port` means QUIC loses that
    // port to the Kad UDP socket bound above and
    // `build_server_client_endpoint` takes the next free neighbour.
    //
    // Noted rather than warned about, and no advice offered. Setting both
    // fields to one number is what a VPN forwarding a single port requires,
    // and `wizard_ports_desc` tells users to do exactly that — telling them
    // afterwards to pick distinct values asks for something their tunnel
    // cannot give. Reachability does not depend on the fallback port being
    // forwarded either: the endpoint STUN-probes its own public port and
    // rendezvous advertises that, which is what a hole-punch dials whichever
    // local port QUIC ended up on. The one thing worth having in a log is
    // that port, because the Windows Firewall rule is added for the port QUIC
    // actually bound rather than the one configured here.
    if settings.tcp_port == settings.udp_port {
        info!(
            "tcp_port and udp_port are both {} — a single-port setup. Kad UDP \
             holds that port, so QUIC will bind a neighbour and advertise its \
             STUN-discovered public port; see the QUIC endpoint line below for \
             which local port it took.",
            settings.tcp_port,
        );
    }

    let mut routing_table = RoutingTable::new(local_id, settings.block_private_ips);
    let search_manager = SearchManager::new();
    let mut publish_manager = PublishManager::new(local_id, user_hash, tcp_port, udp_port);
    publish_manager.noise_pub = identity.noise_public_key;

    // Load bootstrap contacts from the app's own nodes.dat.
    // Legacy files carry no verification bit, so contacts must re-earn
    // verification through the normal Hello/ACK flow.
    let nodes_dat_path = data_dir.join("nodes.dat");
    let mut boot_contacts = if nodes_dat_path.exists() {
        match bootstrap::load_nodes_dat_with_format(&nodes_dat_path) {
            Ok((cs, bootstrap::NodesDatFormat::LegacyNoVerified)) => {
                if !cs.is_empty() {
                    info!(
                        "Loaded {} unverified contacts from legacy nodes.dat",
                        cs.len()
                    );
                }
                cs
            }
            // Bootstrap-edition hints are unverified seeds (often fetched from
            // a bootstrap URL). Load them as-is so they can be *proven* via the
            // normal Hello/verify handshake, but never promote them to verified
            // on load — eMule treats them as unproven and trusting them would
            // make unconfirmed nodes immediately eligible as lookup/publish
            // targets (routing-poisoning surface).
            Ok((cs, bootstrap::NodesDatFormat::BootstrapHints)) => cs,
            Ok((cs, bootstrap::NodesDatFormat::WithVerifiedBit)) => cs,
            Err(e) => {
                warn!("Failed to load nodes.dat: {e}");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Load saved peers from the database for nickname / ban-state lookup and
    // banned-IP extraction. We intentionally do NOT reconstruct KAD
    // routing-table contacts from this table: its single stored `ip:port` is
    // ambiguous (different save paths persist the KAD *UDP* port from the
    // routing snapshot vs. the ed2k *TCP* port from the Hello handler), and a
    // usable KAD contact also needs the protocol version, UDP key and verified
    // bit that the table doesn't carry. The previous heuristic guessed
    // `udp_port = tcp_port + 10`, which is wrong for any non-default port
    // layout and fired Hellos at the wrong endpoint. `nodes.dat` is the
    // authoritative KAD-contact store (complete, with the real UDP port) and
    // `default_bootstrap_contacts()` covers a cold start, so KAD bootstrap no
    // longer depends on this lossy table.
    let saved_db_peers = db
        .get_peers()
        .map_err(|error| anyhow::anyhow!("failed to load peer/ban policy: {error}"))?;
    if !saved_db_peers.is_empty() {
        info!("Loaded {} peers from database", saved_db_peers.len());
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

    // Mutable: a failed startup mapping auto-disables UPnP for the rest of
    // this session (see the emission below), which gates off the maintenance
    // retries, the QUIC port mapping, and the shutdown teardown.
    let upnp_enabled = settings.upnp_enabled;

    // Defer UPnP gateway discovery/mapping and heavy disk loads until after
    // the event loop is running so splash IPC / GetNetworkStats are not
    // stalled behind SSDP (~5s) or large known.met / ipfilter parses.
    // Start firewalled until the background setup reports a mapping.
    // Do **not** emit `upnp-status` here with `mapped: false` — the UI treats
    // the first event as the session baseline and would sticky-toast a
    // false "UPnP failed" before deferred `setup()` finishes.
    let mut upnp_mappings = upnp::UpnpMappings::new(tcp_port, udp_port);
    let upnp_success = false;
    let ipf_enabled = settings.ip_filter_enabled;
    let ipf_block_private = settings.block_private_ips;
    let ip_filter = IpFilter::new(ipf_enabled, ipf_block_private);

    let shared_ip_filter = ip_filter.create_shared_snapshot();
    routing_table.set_ip_filter(shared_ip_filter.clone());
    // Kad already has `nodes.dat` in the table (inserted above). Ember's
    // `nodes_ember.dat` is loaded after `NetworkState` is built, so the
    // fail-closed snapshot is attached there — not here. Both stacks then
    // share the same policy: a blocked address is refused whichever table
    // learned it, and `evict_filtered_contacts` runs once ranges are ready.
    let ember_dht =
        ember::dht::engine::EmberDht::new(
            identity.ed25519_secret_key,
            identity.noise_public_key,
            settings.block_private_ips,
        );
    // Shared with StatsManager below so send_kad_packet / Ember UDP
    // send-recv can record wire bytes without holding the manager.
    let kad_upload_overhead = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let epx_overhead =
        std::sync::Arc::new(crate::storage::statistics::SxOverheadCounters::default());
    let ember_dht_overhead =
        std::sync::Arc::new(crate::storage::statistics::SxOverheadCounters::default());

    let mut dht_store = DhtStore::new();
    dht_store.set_local_id(local_id);

    let udp_key_seed = identity.udp_key_seed;
    let pending_buddy_hashes: PendingBuddySet =
        std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let buddy_manager = BuddyManager::new(
        local_id,
        user_hash,
        settings.nickname.clone(),
        tcp_port,
        udp_port,
        pending_buddy_hashes.clone(),
    );
    let shared_buddy_info: upload_server::SharedBuddyInfo =
        std::sync::Arc::new(tokio::sync::RwLock::new(None));
    info!(
        "IP filter: enabled={}, block_private={} (ranges load deferred)",
        ip_filter.is_enabled(),
        ip_filter.blocks_private(),
    );

    // Extract banned peer IPs from the already-loaded peer list, then
    // union in the persisted automatic IP bans (corruption / request
    // flooding) from the dedicated `banned_ips` table. Both feed the
    // same in-memory set so every enforcement path sees one combined
    // ban list, and so the periodic cap-reset (which rebuilds from these
    // same two sources) doesn't silently drop auto-bans.
    // Union ALL addresses of each banned peer row — not just the first.
    // `BanPeer` and the periodic over-cap rebuild both enforce every
    // address of a banned peer, so loading only `addresses.first()` here
    // silently un-banned the 2nd+ IPs of a multi-homed banned peer across
    // a restart. Mirror the other two paths (flat_map over all addresses).
    let mut banned_ips: HashSet<Ipv4Addr> = saved_db_peers
        .iter()
        .filter(|p| p.banned)
        .flat_map(|p| p.addresses.iter())
        .filter_map(|addr| addr.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok()))
        .collect();
    banned_ips.extend(
        db.get_banned_ips()
            .map_err(|error| anyhow::anyhow!("failed to load automatic bans: {error}"))?,
    );

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
    let shared_friends_only_hashes: ed2k::upload::SharedFriendsOnlyHashes =
        Arc::new(std::sync::RwLock::new(Default::default()));

    // AntiLeech client-software filter — eMule's `AntiLeech.dat`
    // equivalent. Loads from `<data_dir>/antileech.dat` (seeded with the
    // built-in defaults the first time the file doesn't exist; an
    // unmodified pre-haystack factory file is migrated in place).
    // Wrapped in a `parking_lot::RwLock` so the upload server can
    // hot-read on every handshake while the settings UI hot-swaps the
    // pattern list. The filter is disabled by default — users have to
    // opt in via Settings — to avoid surprising regressions for anyone
    // who didn't ask for it. The defaults are conservative regardless.
    let shared_antileech: crate::security::antileech::SharedAntiLeechFilter = {
        let initial = crate::security::antileech::load_or_seed_defaults(
            &data_dir,
            settings.antileech_enabled,
        );
        Arc::new(parking_lot::RwLock::new(initial))
    };

    // Load the persisted server list from `<data_dir>/server.met` so
    // servers discovered via OP_SERVERLIST, manually added, or merged
    // from a downloaded server.met survive across restarts. An empty /
    // missing list is bootstrapped *after* the event loop starts so the
    // UI is not blocked on the HTTPS download during splash/init.
    let server_list = {
        let met_path = data_dir.join("server.met");
        match ServerList::load_server_met(&met_path) {
            Ok(loaded) => loaded,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    info!(
                        "No persisted server.met at {:?} — will download community list after event loop starts",
                        met_path
                    );
                } else {
                    warn!(
                        "Failed to load persisted server.met from {:?}: {} — will download community list after event loop starts if empty",
                        met_path, e
                    );
                }
                ServerList::new()
            }
        }
    };
    let mut pending_server_met_bootstrap = server_list.is_empty();
    let mut server_met_bootstrap_task: Option<tokio::task::JoinHandle<Result<Vec<u8>, String>>> =
        None;

    // Off the async task: `load_checked` reads and parses the file with
    // synchronous `std::fs`, and this runs on the same runtime that is already
    // serving the UI during splash.
    let reputation = {
        let reputation_path = data_dir.join("reputation.json");
        tokio::task::spawn_blocking(move || {
            ember::reputation::ReputationManager::load_checked(&reputation_path)
        })
        .await
        .map_err(|e| anyhow::anyhow!("reputation load task failed: {e}"))?
        .map_err(|error| anyhow::anyhow!(error))?
    };

    // Verified channel transfers, hashed off the event loop. Created here
    // rather than with the other result channels below because the sender
    // lives in `NetworkState`, which is built next.
    let (xfer_finish_tx, mut xfer_finish_rx) = mpsc::unbounded_channel::<XferFinishResult>();

    let mut state = NetworkState {
        local_id,
        user_hash,
        routing_table,
        search_manager,
        publish_manager,
        dht_store,
        stats: NetworkStats {
            // KAD always bootstraps on startup, so the node opens in
            // `Connecting` rather than waiting to be asked. `Disconnected` is
            // still reachable — an explicit `KadDisconnect` from the KAD
            // Network page puts us there for the rest of the session — so
            // every gate that checks for it below still earns its place.
            status: NetworkStatus::Connecting,
            ..Default::default()
        },
        pending_keyword_searches: HashMap::new(),
        pending_server_search: None,
        active_search_request: None,
        server_search_more_needed: false,
        server_search_more_requests: 0,
        server_followup_search: None,
        server_poll_count: 0,
        server_search_age: 0,
        server_udp_search_age: 0,
        udp_search_queue: VecDeque::new(),
        download_source_searches: HashMap::new(),
        source_search_stream_cursor: HashMap::new(),
        pending_downloads: HashMap::new(),
        data_dir: data_dir.clone(),
        known_met_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        server_met_save_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        server_met_save_lock: Arc::new(std::sync::Mutex::new(())),
        nodes_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        ember_nodes_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        ember_bootstrap_cache: ember::dht::peer_cache::BootstrapCache::new(),
        ember_nodes_file: ember::dht::bootstrap::NodesFileState::Unread,
        external_ip: None,
        external_udp_port: None,
        external_tcp_port: None,
        upnp_tcp_port: None,
        advertise_tcp_port: Arc::new(std::sync::atomic::AtomicU16::new(tcp_port)),
        advertise_udp_port: Arc::new(std::sync::atomic::AtomicU16::new(udp_port)),
        stun_keepalive_enabled: settings.stun_keepalive_enabled,
        stun_ka_auto_suspended: false,
        stun_ka_suspended_at: None,
        stun_ka_candidate_port: None,
        stun_ka_stable_hits: 0,
        stun_ka_tcp_candidate_port: None,
        stun_ka_tcp_stable_hits: 0,
        stun_sourced_udp_port: None,
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
        published_notes: HashMap::new(),
        notes_publish_cursor: None,
        overloaded_nodes: HashMap::new(),
        flood_protection: FloodProtection::new(),
        legacy_challenges: LegacyChallengeTracker::new(),
        buddy_manager,
        udp_key_seed,
        tcp_port,
        udp_port,
        quic_port: None,
        quic_public_port: None,
        upnp_mapped: upnp_success,
        ip_filter,
        banned_ips,
        obfuscation_enabled: settings.obfuscation_enabled,
        firewalled_shared: Arc::new(std::sync::atomic::AtomicBool::new(!upnp_success)),
        tcp_connect_back_shared: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
        server_udp_source_reask_at: HashMap::new(),
        pending_udp_reasks: HashMap::new(),
        last_offer_files_signature: None,
        request_offer_files: false,
        offered_ed2k_hashes: HashSet::new(),
        server_tcp_getsources_cursor: 0,
        server_tcp_srcreq_next_at: 0,
        server_connected_at: 0,
        starved_server_reask_at: std::collections::HashMap::new(),
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
        transfer_friend_hint: HashMap::new(),
        friend_xfer_attempts: HashMap::new(),
        friend_xfer_inbound_last: HashMap::new(),
        friend_xfer_stats: FriendXferStats::default(),
        friend_xfer_punch_serve: HashMap::new(),
        download_handles: HashMap::new(),
        comment_manager: comment_manager.clone(),
        firewall_checker: FirewallChecker::new(),
        udp_fw_candidate_pool: VecDeque::new(),
        udp_fw_node_search: None,
        low_id: false,
        server_client_id: 0,
        server_login_tcp_port: None,
        last_tcp_remap_reconnect_at: None,
        pending_server_connect: None,
        pending_buddy_hashes: pending_buddy_hashes.clone(),
        shared_buddy_info: shared_buddy_info.clone(),
        shared_ip_filter: shared_ip_filter.clone(),
        kad_upload_overhead: kad_upload_overhead.clone(),
        epx_overhead: epx_overhead.clone(),
        ember_dht_overhead: ember_dht_overhead.clone(),
        buddy_event_rx: None,
        serving_event_rx: None,
        pending_outgoing_buddy: None,
        // Off until the user (or auto_connect_server) calls
        // `initiate_server_connect`, which flips this on for drop recovery.
        server_auto_reconnect: false,
        server_reconnect_failures: 0,
        preferred_ed2k_server: None,
        server_last_connect_attempt: None,
        pending_uss_pings: HashMap::new(),
        uss_host: None,
        uss_prev_host: None,
        uss_missed_pongs: 0,
        uss_host_selected_at: 0,
        uss_rtt_queue,
        uss_enabled_flag,
        aich_hash_sets: Vec::new(),
        upload_max_slots: Arc::new(std::sync::atomic::AtomicUsize::new(
            settings.max_concurrent_uploads as usize,
        )),
        upload_max_conn_per_five: Arc::new(std::sync::atomic::AtomicUsize::new(
            settings.max_connections_per_five_secs as usize,
        )),
        obfuscation_enabled_shared: Arc::new(std::sync::atomic::AtomicBool::new(
            settings.obfuscation_enabled,
        )),
        skip_compress_video_shared: Arc::new(std::sync::atomic::AtomicBool::new(
            settings.skip_compress_video,
        )),
        filter_incoming_shared: Arc::new(std::sync::atomic::AtomicBool::new(
            settings.filter_incoming_connections,
        )),
        share_browsing_shared: {
            // Seed the Hello builder's mirror from the same value.
            ed2k::messages::set_share_browsing_allowed(settings.allow_shared_files_browse);
            Arc::new(std::sync::atomic::AtomicBool::new(
                settings.allow_shared_files_browse,
            ))
        },
        ember_payload_dirty: true,
        ember_udp_payload: Arc::new(Vec::new()),
        known_ember_peers: HashMap::new(),
        ember_noise_keys: HashMap::new(),
        ember_keyless_peers: HashMap::new(),
        ember_session_dht_contacts: HashMap::new(),
        ember_rendezvous_published_at: 0,
        ember_rendezvous_search: None,
        ember_rendezvous_looked_up_at: 0,
        ember_rendezvous_empty_streak: 0,
        ember_announced_at: HashMap::new(),
        ember_publish_unplaced: HashMap::new(),
        ember_publish_attempts: HashMap::new(),
        ember_publish_pass: EmberPublishPassStats::default(),
        ember_batch_publish: EmberBatchPublisher::default(),
        ember_started_at: chrono::Utc::now().timestamp(),
        ember_self_lookup_done: false,
        ember_last_self_lookup: 0,
        ember_last_inbound: None,
        ember_rearmed_at: None,
        ember_last_overlay_contacts: 0,
        ember_empty_rearmed_at: 0,
        ember_publish_targets: HashMap::new(),
        ember_publish_target_queue: std::collections::VecDeque::new(),
        ember_publish_target_lookups: HashMap::new(),
        ember_store_loaded: false,
        ember_reach_witness: None,
        ember_udp_reachable_at: None,
            ember_kad_bridge_attempted: HashMap::new(),
        ember_gossip_reputation: ember::dht::gossip::GossipReputation::new(),
        ember_friend_contacts_asked: HashMap::new(),
        ember_friend_contacts_served: HashMap::new(),
            ember_bridge_fast_at: None,
            ember_gossip_probe_window: (std::time::Instant::now(), 0),
            ember_publish_beat_acked: 0,
            ember_publish_beat_failed: 0,
        ember_udp_epx_rate: HashMap::new(),
        ember_udp_epx_req_rate: HashMap::new(),
        ember_diagnostics: EmberDiagnostics::default(),
        ember_verified_highwater: EmberVerifiedHighwater::default(),
        ember_verified_highwater_dirty: false,
        antileech: shared_antileech.clone(),
        aich_root_map: HashMap::new(),
        callback_row_pending_since: HashMap::new(),
        firewall_connect_semaphore: Arc::new(tokio::sync::Semaphore::new(16)),
        firewall_req_response_bucket: TokenBucket::new(128, 4.0),
        firewall_req_connect_bucket: TokenBucket::new(32, 1.0),
        firewall_req_cooldown: HashMap::new(),
        online_friends: HashMap::new(),
        pending_browse_requests: HashMap::new(),
        recent_ember_chat: HashMap::new(),
        ember_sessions: Arc::new(RwLock::new(HashMap::new())),
        // Mirror the `stats.status` initialization above. The upload listener
        // binds and starts accepting TCP connections immediately (see
        // `start_upload_server`), well before this task has actually reached
        // KAD or an eD2K server, so this flag used to start `true` whenever
        // no auto-connect was configured — otherwise a fresh launch was
        // silently servable by any peer that remembered our IP:port from a
        // prior session while the UI still read "Disconnected". Now that KAD
        // always bootstraps there is no such session: startup is always a
        // connect. `KadDisconnect` sets the flag, and `KadConnect` /
        // `initiate_server_connect` clear it again.
        uploads_halted_for_shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        // Starts false on purpose — see the field comment. "Has not connected
        // yet" is not "was asked to go offline".
        user_offline: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        rendezvous_registered: false,
        last_presence_blocked: false,
        rendezvous_register_generation: 0,
        rendezvous_room_beat: 0,
        rendezvous_published_beat: 0,
        rendezvous_last_register: None,
        rendezvous_last_attempt: None,
        rendezvous_register_fail_streak: 0,
        outbound_session_tasks: HashMap::new(),
        friend_search_initial_done: false,
        friend_search_initial_queue: Vec::new(),
        friend_search_started_at: None,
        friend_reconnect_last: HashMap::new(),
        tracker_registry: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        nat_info: ember::nat::NatInfo::unknown(),
        nat_probe_generation: 0,
        mapping_ka_generation: 0,
        friend_nat_context: ember::nat::new_shared_friend_nat_context(),
        connection_broker: None,
        broker_event_rx: None,
        relay_manager: Arc::new(tokio::sync::Mutex::new({
            let mut mgr = ember::relay::RelayManager::new();
            mgr.set_policy(settings.relay_for_peers, settings.max_relay_sessions);
            mgr
        })),
        reputation,
        local_ed25519_pubkey: ed25519_pubkey,
        friend_relay_offer_sent: HashMap::new(),
        friend_relay_offer_seen: HashMap::new(),
        friend_file_offer_seen: HashMap::new(),
        ember_transport: ember::transport::EmberTransport::new(
            identity.noise_private_key,
            identity.noise_public_key,
        ),
        ember_pending_pings: HashMap::new(),
        ember_dht,
        ember_dht_protection: ember::dht::protection::DhtProtection::new(),
        ember_observed_votes: ember::dht::observed::EmberObservedIpVotes::new(),
        ember_content_hashes: HashMap::new(),
        ember_dht_pending_pings: HashMap::new(),
        ember_dht_pending_finds: HashMap::new(),
        ember_search: ember::dht::search::SearchManager::new(),
        ember_dht_search_requests: HashMap::new(),
        ember_dht_pending_lookups: HashMap::new(),
        ember_dht_pending_value_lookups: HashMap::new(),
        ember_publish: ember::dht::publish::PublishManager::new(),
        ember_dht_publish_requests: HashMap::new(),
        ember_dht_pending_publishes: HashMap::new(),
        ember_dht_maint_pings: HashMap::new(),
        ember_source_publish_at: HashMap::new(),
        ember_source_publish_unix: HashMap::new(),
        ember_keyword_publish_at: HashMap::new(),
        ember_keyword_publish_unix: HashMap::new(),
        ember_published_sources: HashSet::new(),
        ember_keyword_searches: HashMap::new(),
        ember_pending_keyword_results: Vec::new(),
        ember_download_source_searches: HashMap::new(),
        ember_source_search_state: HashMap::new(),
        ember_pending_source_injections: Vec::new(),
        ember_pending_callback_connects: Vec::new(),
        ember_pending_proxy_overlay: HashMap::new(),
        channel_gossip_seen: HashMap::new(),
        channel_gossip_seen_order: VecDeque::new(),
        channel_history_sync_times: HashMap::new(),
        channel_gossip_sent_times: VecDeque::new(),
        channel_gossip_local_times: VecDeque::new(),
        channel_origin_retry: VecDeque::new(),
        channel_delivery_notes: VecDeque::new(),
        channel_delivery_sink: (db.clone(), app_handle.clone()),
        channel_gossip_from_times: HashMap::new(),
        channel_view_cache: HashMap::new(),
        channel_gossip_author_times: HashMap::new(),
        channel_history_sync_at: HashMap::new(),
        channel_history_sync_mark: HashMap::new(),
        channel_history_sync_ingested: HashMap::new(),
        ember_channel_presence_searches: HashMap::new(),
        ember_channel_presence_buffer: HashMap::new(),
        ember_pending_channel_presence: Vec::new(),
        channel_presence_fetch_at: HashMap::new(),
        channel_focused: None,
        channel_beacon_beat_at: HashMap::new(),
        channel_beacons: HashMap::new(),
        channel_beacon_flood_at: HashMap::new(),
        channel_beacon_inserts: HashMap::new(),
        channel_presence_dirty: HashMap::new(),
        ember_channel_moderation_searches: HashMap::new(),
        ember_pending_channel_moderation: Vec::new(),
        channel_moderation_fetch_at: HashMap::new(),
        channel_moderation_publish_at: HashMap::new(),
        channel_username_refresh_at: 0,
        rendezvous_url: settings.rendezvous_url.clone(),
        ember_channel_noise_keys: HashMap::new(),
        channel_member_touch_flushed_at: None,
        channel_roster_cache: None,
        channel_neighbor_lookup_at: HashMap::new(),
        channel_neighbor_lookup_inflight: HashSet::new(),
        channel_neighbor_scan_after: None,
        channel_relay_outboxes: HashMap::new(),
        channel_relay_pending: HashSet::new(),
        channel_relay_offer_at: HashMap::new(),
        ember_channel_handoff_searches: HashMap::new(),
        ember_pending_channel_handoff: Vec::new(),
        channel_handoff_fetch_at: HashMap::new(),
        local_ed25519_seed: ed25519_secret_key,
        xfer_send: HashMap::new(),
        xfer_recv: HashMap::new(),
        xfer_finish_tx,
        xfer_finish_in_flight: 0,
        channel_member_touches: HashMap::new(),
        xfer_pending: HashMap::new(),
        xfer_block_times: VecDeque::new(),
        xfer_upload_credit: 0,
        xfer_offer_policy: settings.channel_file_offers.clone(),
        xfer_friend_hashes: friend_hashes.clone(),
        attach_inbound: HashMap::new(),
        attach_fetches: HashMap::new(),
        attach_auto_log: HashMap::new(),
        ember_channel_epoch_searches: HashMap::new(),
        ember_pending_channel_epoch: Vec::new(),
        channel_epoch_fetch_at: HashMap::new(),
        ember_channel_claim_searches: HashMap::new(),
        ember_pending_channel_claim: Vec::new(),
    };

    kad::firewall::publish_local_firewall(state.firewalled, state.udp_firewalled);

    // Chat attachments a restart stranded: offers whose details lived only in
    // memory and receives cut off mid-file. Settled before anything can emit,
    // so the transcript never shows a transfer that will not move again.
    {
        let db = db.clone();
        let folder = settings.download_folder.clone();
        let _ = tokio::task::spawn_blocking(move || chat_attach::sweep_interrupted(&db, &folder)).await;
    }

    // Seed the Ember DHT routing table from the last session's persisted
    // contacts (slice 7). This is the native equivalent of KAD's
    // `nodes.dat` and is what lets Ember rejoin the DHT after a restart
    // without depending on KAD source publishes for discovery. Loaded
    // *before* the fail-closed IP filter is attached: Ember contacts are
    // never Kad bootstrap seeds, so `admits_addr` would otherwise refuse
    // the entire file. `load_contacts` also detaches the range filter for
    // the same reason if one is already present.
    let nodes_ember_path = data_dir.join("nodes_ember.dat");
    crate::security::recover_interrupted_replace(&nodes_ember_path);
    if nodes_ember_path.exists() {
        // Read + parse on the blocking pool: this is a synchronous whole-file
        // `std::fs` read inside an async fn that shares its runtime with the UI.
        let load_path = nodes_ember_path.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            ember::dht::bootstrap::load_nodes_with_state(&load_path)
        })
        .await;
        match loaded {
            Ok(Ok((entries, file_state))) => {
                let n = entries.len();
                state.ember_nodes_file = file_state;
                state.ember_bootstrap_cache.load(entries);
                // Through `seed_batch`, never straight from the file: the table
                // has to receive every remembered peer as unproven, while the
                // cache keeps the timestamps that say when we last reached one.
                // Only the first batch goes in now — `run_ember_maintenance`
                // tops the table up as leads fail, so the peers most likely to
                // answer are dialled in the first tick instead of queuing behind
                // an address book the ping budget would take many minutes to
                // work through.
                let local_id = state.ember_dht.local_id();
                let seed = state.ember_bootstrap_cache.seed_batch(
                    &local_id,
                    &HashSet::new(),
                    EMBER_SEED_BATCH,
                );
                // Only what took a bucket slot counts as tried, exactly as the
                // maintenance top-up requires. This used to ask
                // `contact_for` afterwards, which searches the replacement
                // caches too — so a seed the IP policy or a diversity cap
                // parked read back as admitted, and `charge_silent_session`
                // charged a miss at shutdown to an address no packet was ever
                // sent to. A miss also sinks an address in `seed_batch`
                // ranking, so the error compounded: an untried peer became
                // less likely to be tried on the next launch.
                let admitted = state.ember_dht.load_contacts(seed);
                state
                    .ember_bootstrap_cache
                    .note_offered(admitted.into_iter());
                info!(
                    "Loaded {n} remembered Ember peers from nodes_ember.dat ({} seeded into routing table)",
                    state.ember_dht.contact_count()
                );
            }
            Ok(Err(e)) => {
                // A file we cannot parse would otherwise wedge saving forever:
                // `ember_nodes_loaded` stays false on every launch, so the
                // shrink guard refuses every write and the node can never
                // persist a contact again. Quarantine it once — a version
                // downgrade, a corrupt header or an over-large file are all
                // permanent for this build — and carry on as if the file had
                // been absent. The truncation path already keeps a dated copy
                // this way.
                warn!("Failed to load nodes_ember.dat: {e}");
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let quarantine = nodes_ember_path.with_extension(format!("dat.unreadable.{ts}"));
                match std::fs::rename(&nodes_ember_path, &quarantine) {
                    Ok(()) => {
                        state.ember_nodes_file = ember::dht::bootstrap::NodesFileState::Loaded;
                        warn!(
                            "Moved the unreadable nodes_ember.dat aside to {} so this node can \
                             remember peers again",
                            quarantine.display()
                        );
                    }
                    Err(e) => warn!(
                        "Could not move the unreadable nodes_ember.dat aside ({e}); peer \
                         persistence stays disabled until it is removed"
                    ),
                }
            }
            // A panicked or cancelled task says nothing about the file, so the
            // guard stays armed and the next launch tries again.
            Err(e) => warn!("nodes_ember.dat load task failed: {e}"),
        }
    } else {
        // Absent is not unreadable: there is nothing to preserve, so the save
        // path is free to write whatever this session learns.
        state.ember_nodes_file = ember::dht::bootstrap::NodesFileState::Loaded;
        debug!("No nodes_ember.dat found; Ember DHT routing table starts empty");
    }
    state
        .ember_dht
        .set_ip_filter(state.shared_ip_filter.clone());

    state.ember_verified_highwater =
        load_ember_verified_highwater(&ember_highwater_path(&data_dir));

    // Carry the record store across the restart too. Every record is re-verified
    // and re-dated on the way in, so anything that expired while we were closed
    // is refused rather than revived. Without this a restart dropped everything
    // this node was holding for other publishers, and on a young network with
    // few replicas per record — or when an update restarts many nodes at once —
    // that content is missing until replication and the original publishers
    // refill it.
    let store_ember_path = data_dir.join("store_ember.dat");
    crate::security::recover_interrupted_replace(&store_ember_path);
    if store_ember_path.exists() {
        // Same reasoning as `nodes_ember.dat` above: synchronous file read and
        // record validation, so it belongs on the blocking pool.
        let loaded = tokio::task::spawn_blocking(move || {
            ember::dht::bootstrap::load_store(&store_ember_path)
        })
        .await;
        match loaded {
            Ok(Ok(records)) => {
                let offered = records.len();
                let accepted = state.ember_dht.restore_records(records);
                // Recorded so the shutdown save can tell "this store is genuinely
                // empty" from "we never got to read the file" — see `save_store`.
                state.ember_store_loaded = true;
                info!(
                    "Restored {accepted} of {offered} Ember DHT records from store_ember.dat \
                     (the rest expired while closed or failed validation)"
                );
            }
            Ok(Err(e)) => warn!("Failed to load store_ember.dat: {e}"),
            Err(e) => warn!("store_ember.dat load task failed: {e}"),
        }
    } else {
        state.ember_store_loaded = true;
    }

    // A table that comes up empty — brand-new install, or a lost/corrupt
    // `nodes_ember.dat` — is refilled by the decentralized paths instead of a
    // central pool: the KAD bridge harvests Ember peers from ordinary KAD
    // source responses, and peer exchange plus DHT gossip take over from
    // there. Nothing to kick off here; the maintenance tick drives it.

    // Seed active IP-reputation bans into the enforced set so a restart
    // does not leave a still-banned IP connectable until the first
    // reputation-timer sync (user-hash gates alone miss IP-correlation bans).
    for ip in state.reputation.currently_banned_ips() {
        state.banned_ips.insert(ip);
    }
    if let Ok(mut shared) = shared_banned_ips.write() {
        *shared = state.banned_ips.clone();
    }

    // Load known files / AICH / ipfilter on a blocking thread after the event
    // loop starts (see `deferred_disk_loads`). Start empty so splash IPC is not
    // stalled behind large known.met / ipfilter.dat parses.
    let mut known_files = KnownFileList::new();
    info!("Known files / AICH / ipfilter load deferred until event loop");
    let transfer_status_writes = Arc::clone(transfer_status_write_clock());

    // Initialize statistics manager
    let mut stats_manager = StatsManager::new();
    stats_manager.load_cumulative(&db);
    stats_manager.kad_upload_bytes = kad_upload_overhead;
    stats_manager.epx_counters = epx_overhead;
    stats_manager.ember_dht_counters = ember_dht_overhead;

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
    const DB_PROGRESS_PERSIST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
    let mut db_progress_last_persist: HashMap<String, std::time::Instant> = HashMap::new();
    // Upload `transferred` is intentionally capped to the file size for UI
    // progress. Keep a separate raw counter for durable Library accounting so
    // retransmitted payload bytes are not silently discarded.
    let mut upload_raw_progress: HashMap<String, u64> = HashMap::new();

    // Load comments from database
    if let Ok(rows) = db.load_file_comments() {
        state.comment_manager.write().await.load_from_db_rows(rows);
    }

    // Load previously-published KAD notes so the periodic republish loop can
    // keep them alive on the network across restarts (DHT note entries expire
    // after ~24h).
    if let Ok(rows) = db.load_published_notes() {
        for (hash_hex, rating, comment, last_publish, file_name, file_size) in rows {
            if let Some(kad_id) = KadId::from_hex(&hash_hex) {
                state.published_notes.insert(
                    kad_id,
                    PublishedNote {
                        rating,
                        comment,
                        file_name,
                        file_size,
                        last_publish,
                    },
                );
            }
        }
        if !state.published_notes.is_empty() {
            info!(
                "Loaded {} published KAD notes for periodic republish",
                state.published_notes.len()
            );
        }
    }

    let firewall_probe_ips: upload_server::FirewallProbeSet =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));

    // Send bootstrap requests to initial contacts. Unconditional: KAD is the
    // peer index everything else reads from, and making it opt-in mostly
    // produced installs that looked broken. `boot_contacts` has already
    // fallen back to the hardcoded list if nodes.dat was missing or empty,
    // so there is always something to ask. The firewall check is deferred to
    // the periodic bootstrap_timer recheck, which fires once we have verified
    // contacts (table_size >= 10).
    for contact in &boot_contacts {
        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
        let msg = KadMessage::BootstrapReq;
        if let Ok(packet) = messages::encode_packet(&msg) {
            state.flood_protection.track_request(addr, 0x01);
            let _ = send_kad_packet(&udp_socket, &packet, addr, &state, &contact.id).await;
            debug!("Sent bootstrap req to {addr}");
        }
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
    let (buddy_conn_tx, mut buddy_conn_rx) =
        mpsc::channel::<upload_server::BuddyConnectionParts>(4);

    // Callback connection channel: upload listener sends firewalled sources that
    // connected back (both KAD buddy callbacks and server LowID callbacks).
    //
    // Capacity 256 (was 32): the broker's `BrokerEvent::ConnectionReady` arm
    // forwards established LowID-to-LowID connections here via `try_send`,
    // and the upload accept paths also push direct callbacks. Under bursty
    // discovery the old 32-slot buffer regularly hit its cap and the
    // network task self-deadlocked when awaiting on it — `try_send` plus a
    // larger cushion prevents both.
    let (kad_callback_tx, mut kad_callback_rx) =
        mpsc::channel::<upload_server::KadCallbackParts>(256);

    // Punch-responder adopted streams: pre-established, transport-encrypted
    // connections handed to the upload listener to serve directly (we're the
    // upload/source side; there's no matching active download for these, so
    // they can't go through `kad_callback_tx`). See
    // `upload_server::InboundStreamRequest`.
    let (inbound_stream_tx, inbound_stream_rx) =
        mpsc::channel::<upload_server::InboundStreamRequest>(256);
    let (udp_fw_check_tx, mut udp_fw_check_rx) =
        mpsc::channel::<upload_server::UdpFirewallCheckRequest>(16);
    let pending_kad_callbacks: upload_server::PendingKadCallbacks =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    // Install the machine-wide download-connection cap (eMule `maxconnections`)
    // before any download tasks can spawn, so the raised per-file source
    // budget stays globally bounded.
    ed2k::multi_source::set_global_conn_limit(settings.max_connections as usize);

    // Install the global "preview priority for all downloads" preference so the
    // chunk selector front-loads first/last parts from the very first task.
    crate::sharing::manager::set_global_preview_priority(settings.preview_priority_all);

    let source_manager: Arc<RwLock<SourceManager>> = {
        let mut sm = SourceManager::new();
        sm.set_max_per_file(settings.max_sources_per_file);
        // Reload the eMule-style persistent source cache so we hold peer user
        // hashes from previous sessions and can obfuscate connections to
        // crypt-required sources immediately, instead of getting reset (10054)
        // until we re-learn each hash via KAD/source-exchange.
        let sources_met = data_dir.join("sources.met");
        match sm.load_from_disk(&sources_met) {
            Ok(0) => {}
            Ok(n) => info!("Loaded {n} cached sources (with user hashes) from sources.met"),
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                warn!("Failed to load sources.met: {e}");
            }
            Err(_) => {}
        }
        // Map still-banned reputation identities onto cached source IPs so
        // enforcement matches a live session after restart.
        for uh in state.reputation.currently_banned_node_ids() {
            for ip in sm.find_ips_by_user_hash(&uh) {
                state.banned_ips.insert(ip);
            }
        }
        if let Ok(mut shared) = shared_banned_ips.write() {
            *shared = state.banned_ips.clone();
        }
        Arc::new(RwLock::new(sm))
    };

    let credit_save_ownership = Arc::new(tokio::sync::Mutex::new(()));

    // Load credits from DB (primary) and clients.met (fallback), persist RSA keypair
    let (credit_manager, secident_status, crypto_unreadable): (
        Arc<RwLock<CreditManager>>,
        &'static str,
        bool,
    ) = {
        let mut cm = CreditManager::new();
        cm.load_or_create_keypair(&data_dir);
        if let Ok(records) = db.load_credits() {
            for (
                hash,
                uploaded,
                downloaded,
                last_seen,
                public_key,
                ident_ip,
                ident_state,
                ember_hash,
                crypto_verified_once,
                peer_name,
                client_software,
            ) in records
            {
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
                // Restore SecureIdent state so the Known Clients tab keeps the
                // peer's last-known IP and country flag (both derived from
                // ident_ip) across restarts instead of blanking until the peer
                // reconnects.
                record.ident_ip = ident_ip;
                record.ident_state = ed2k::credits::IdentState::from_u8(ident_state);
                record.ember_hash = ember_hash;
                // Assigning `ident_state` directly bypasses `set_ident_state`,
                // which is what makes the anchor sticky in memory — so it has
                // to be restored explicitly. Without this every record loads
                // unanchored and the anti-theft reset wipes each peer's totals
                // on their first verification after a restart.
                record.crypto_verified_once = crypto_verified_once;
                record.peer_name = peer_name;
                record.client_software = client_software;
            }
            info!(
                "Loaded {} credit records from database",
                cm.all_records().len()
            );
        }
        // Ember credit records live in a separate v15 table. Same
        // "bump-last-seen in helper, overwrite after load" dance as
        // the eMule table above: the `get_or_create_ember` accessor
        // sets `last_seen = now`, which we then overwrite with the
        // persisted value so the 90-day prune honours real ages.
        if let Ok(records) = db.load_ember_credits() {
            let loaded_count = records.len();
            for (
                pk,
                up,
                down,
                last_up,
                last_down,
                completed,
                total,
                avg_speed,
                last_seen,
                verified,
            ) in records
            {
                let record = cm.get_or_create_ember(pk);
                record.uploaded = up;
                record.downloaded = down;
                record.last_upload_time = last_up;
                record.last_download_time = last_down;
                record.completed_sessions = completed;
                record.total_sessions = total;
                record.avg_upload_speed = avg_speed;
                record.last_seen = last_seen;
                record.ident_verified = verified;
            }
            if loaded_count > 0 {
                info!("Loaded {loaded_count} Ember credit records from database");
            }
        }
        let clients_met = data_dir.join("clients.met");
        crate::security::recover_interrupted_replace(&clients_met);
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
        let any_pruned = pruned_before != pruned_after;
        if any_pruned {
            info!(
                "Pruned {} stale credit record(s) on startup (now {})",
                pruned_before - pruned_after,
                pruned_after
            );
        }
        let secident_status = cm.secident_status();
        let crypto_unreadable = cm.crypto_unreadable();
        let arc = Arc::new(RwLock::new(cm));
        // L6: pair the startup prune with an immediate disk flush so
        // a crash inside the first 60-s save tick can't reload the
        // pre-prune rows from the DB on next start. Skip the flush
        // when nothing was pruned to avoid paying for a full-table
        // rewrite on every cold boot. Fire-and-forget on the credit
        // flush path so we don't stall event-loop entry on SQLite I/O.
        if any_pruned {
            spawn_credit_flush(
                arc.clone(),
                db.clone(),
                data_dir.clone(),
                false,
                credit_save_ownership.clone(),
            );
        }
        (arc, secident_status, crypto_unreadable)
    };

    state.stats.secident_status = secident_status.to_string();
    // What the handshake may promise. eMule states the level as
    // `CryptoAvailable() ? 3 : 0` in both the Hello and EmuleInfo, because a
    // peer reading level 3 will ask for a key. `"broken"` is a real state here
    // — `cryptkey.dat` present but unreadable — and claiming SecIdent through
    // it earns nothing and looks like a spoof.
    ed2k::messages::set_secident_available(secident_status == "available");
    if crypto_unreadable {
        let _ = app_handle.emit("secident-key-unreadable", ());
    }

    let a4af_shared: Arc<RwLock<A4AFManager>> = Arc::new(RwLock::new(A4AFManager::new()));
    let pending_dl_hashes: Arc<RwLock<Vec<[u8; 16]>>> = Arc::new(RwLock::new(Vec::new()));
    let active_port_tests: Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, mpsc::Sender<()>>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let shared_server_addr: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));

    // Bind a separate UDP socket for ed2k server status pings.
    // Servers respond on their TCP port + 4; we can use any local port.
    //
    // Bound here, ahead of the upload listener, because this is the last
    // fallible step in startup and it used to sit *after* that listener was
    // spawned. The listener is detached with no `JoinHandle`, so a bind failure
    // returned `Err` from `start_network` and surfaced a fatal network error
    // while the TCP listener stayed bound and accepting, with no event loop
    // left to coordinate it.
    let mut server_udp =
        ServerUdpSocket::from_socket(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);

    // Defer auto-connect until the event loop is running (and, when needed,
    // until server.met bootstrap finishes). Starting the TCP login before the
    // upload listener / command loop are up made splash IPC wait and raced
    // the server's HighID port-test against a not-yet-listening socket.
    let mut pending_auto_connect_server = settings.auto_connect_server;
    // After a successful login, OP_OFFERFILES is queued into pending_offer_files
    // (declared with other deferred startup state) and drained one chunk/turn.

    let shared_ember_payload: ember::SharedEmberPayload =
        Arc::new(RwLock::new(Arc::new(Vec::new())));
    let ember_payload_generation: ember::EmberPayloadGeneration =
        Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Upload queue shared between the upload listener (owner/writer) and
    // the UDP reask-ack handler (reader that needs to answer the real queue
    // rank for a peer pinging us over UDP). Holding the shared handle here
    // avoids a placeholder 0 rank reply.
    let upload_queue_handle: ed2k::upload::UploadQueueRef =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));

    // Channel to ask the upload listener to dial a peer and serve it — the LowID
    // callback-upload path (eMule `OP_CALLBACKREQUESTED` / KAD buddy `OP_CALLBACK`
    // → `TryToConnect` → serve). `connect_serve_tx` stays in this function scope
    // for the server/KAD callback handlers in the main loop below; the receiver
    // is moved into the listener task, which drains it in its accept `select!`.
    let (connect_serve_tx, connect_serve_rx) =
        mpsc::channel::<upload_server::ConnectServeRequest>(64);

    // Shared so Settings nickname changes hot-reload into Hello / EmuleInfo
    // without restarting the upload listener.
    let shared_nickname: Arc<tokio::sync::RwLock<String>> =
        Arc::new(tokio::sync::RwLock::new(settings.nickname.clone()));

    // Start the peer-to-peer upload listener (accepts incoming file requests from other KAD peers)
    {
        let ul_tx = ul_event_tx.clone();
        let ul_index = local_index.clone();
        let ul_transfers = transfer_manager.clone();
        let ul_bw = bandwidth_limiter.clone();
        let ul_folders = upload_shared_folders.clone();
        let ul_nickname = shared_nickname.clone();
        let ul_app = app_handle.clone();
        let ul_max = state.upload_max_slots.clone();
        let ul_max_conn_per_five = state.upload_max_conn_per_five.clone();
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
        let ul_friends_only = shared_friends_only_hashes.clone();
        let ul_antileech = shared_antileech.clone();
        let ul_skip_compress = state.skip_compress_video_shared.clone();
        let ul_filter_incoming = state.filter_incoming_shared.clone();
        let ul_share_browsing = state.share_browsing_shared.clone();
        let ul_obfuscation = state.obfuscation_enabled_shared.clone();
        let ul_download_folder = settings.download_folder.clone();
        let ul_fw_probes = firewall_probe_ips.clone();
        let ul_fw_shared = state.firewalled_shared.clone();
        let ul_tcp_connect_back = state.tcp_connect_back_shared.clone();
        let ul_ext_ip_shared = state.external_ip_shared.clone();
        let ul_kad_cbs = pending_kad_callbacks.clone();
        let ul_kad_cb_tx = kad_callback_tx.clone();
        let ul_udp_fw_tx = udp_fw_check_tx.clone();
        let ul_server_addr = shared_server_addr.clone();
        let ul_friends = friend_hashes.clone();
        let ul_mutual_friends = mutual_friend_hashes.clone();
        let ul_ember = shared_ember_payload.clone();
        let ul_ember_gen = ember_payload_generation.clone();
        let ul_geoip = geoip.clone();
        let ul_ember_sessions = state.ember_sessions.clone();
        let ul_disconnected = state.uploads_halted_for_shutdown.clone();
        let ul_queue = upload_queue_handle.clone();
        let ul_sx_overhead = stats_manager.sx_counters.clone();
        let ul_epx_overhead = stats_manager.epx_counters.clone();
        let ul_inbound_stream_rx = inbound_stream_rx;
        let ul_adv_tcp = state.advertise_tcp_port.clone();
        let ul_adv_udp = state.advertise_udp_port.clone();
        tokio::spawn(async move {
            if let Err(e) = upload_server::start_upload_server(
                tcp_port,
                ul_adv_tcp,
                user_hash,
                ul_nickname,
                udp_port,
                ul_adv_udp,
                ul_folders,
                PathBuf::from(&ul_download_folder),
                ul_index,
                ul_transfers,
                ul_bw,
                ul_tx,
                ul_max,
                ul_max_conn_per_five,
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
                ul_friends_only,
                ul_antileech,
                ul_skip_compress,
                ul_filter_incoming,
                ul_share_browsing,
                ul_fw_probes,
                ul_fw_shared,
                ul_tcp_connect_back,
                ul_ext_ip_shared,
                ul_kad_cbs,
                ul_kad_cb_tx,
                ul_udp_fw_tx,
                ul_obfuscation,
                ul_server_addr,
                ul_friends,
                ul_mutual_friends,
                ul_ember,
                ul_ember_gen,
                ul_geoip,
                ul_ember_sessions,
                ember_hash,
                ed25519_pubkey,
                ed25519_secret_key,
                ul_disconnected,
                ul_queue,
                ul_sx_overhead,
                ul_epx_overhead,
                connect_serve_rx,
                ul_inbound_stream_rx,
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
    let mut server_udp_ping_idx: usize = 0;

    // Use MissedTickBehavior::Skip on ALL timers so that slow loop iterations
    // (common in debug builds) never cause burst catch-up that starves other
    // tokio tasks (including Tauri IPC handlers → UI navigation freezes).
    use tokio::time::MissedTickBehavior;

    let mut bootstrap_timer = tokio::time::interval(std::time::Duration::from_secs(10));
    bootstrap_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut bootstrap_attempts: u32 = 0;
    // Backoff state for the hardcoded-seed-node blast below. eMule's own
    // CKademlia::Process() pops one bootstrap contact at a time no more than
    // every 15s (2s only while the routing table is truly empty) and stops
    // entirely once its bootstrap list is exhausted — it never re-hits the
    // same handful of well-known IPs forever. We don't have that "give up"
    // behavior (this is our only fallback for a client with no nodes.dat and
    // no live contacts), but without *some* backoff a client that's
    // permanently offline or firewalled from UDP would otherwise hammer the
    // same 5 public seed IPs every 10s indefinitely for as long as the app
    // runs. Track the last send time and a shift that grows the interval
    // (10s, 20s, 40s, ... capped at 10 minutes) each time we actually send,
    // reset once we successfully reach `NetworkStatus::Connected`.
    let mut last_hardcoded_bootstrap_ts: i64 = 0;
    let mut hardcoded_bootstrap_backoff_shift: u32 = 0;
    let mut last_sampled_bootstrap_ts: i64 = 0;
    let mut sampled_bootstrap_backoff_shift: u32 = 0;
    let mut publish_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    // Punch mailbox polling ticks fast but only *works* when there is something
    // to answer — see the arm's gate. The rendezvous server keeps a punch
    // registration for only 30 s (`PUNCH_TTL`), so this used to ride the 60 s
    // `publish_timer`: a friend's registration routinely expired before we ever
    // looked, which is why friend hole-punching was documented as purely
    // best-effort. A coordinated transfer punch cannot tolerate that at all.
    let mut punch_poll_timer = tokio::time::interval(std::time::Duration::from_secs(3));
    punch_poll_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut last_punch_poll: Option<tokio::time::Instant> = None;
    publish_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // eMule's Kad publish driver wakes every KADEMLIAPUBLISHTIME (2s)
    // and starts at most one due source/keyword/note store per tick while
    // respecting per-type active-search caps.
    let mut kad_publish_timer = tokio::time::interval(std::time::Duration::from_secs(2));
    kad_publish_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
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
    let mut last_udp_discovery_health: UdpDiscoveryHealthSnapshot =
        UdpDiscoveryHealthSnapshot::default();
    let mut search_poll_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    search_poll_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // eMule UDPSEARCHSPEED = SEC2MS(3)/4 = 750ms: send one UDP search per tick
    let mut udp_search_timer = tokio::time::interval(std::time::Duration::from_millis(750));
    udp_search_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // UDP source-query drain cadence. The previous 1000ms-per-single-packet
    // pace was far stricter than eMule's: eMule's `CDownloadQueue::Process()`
    // ticks every ~1s and sends a BURST of OP_GLOBGETSOURCES(2) packets
    // within each tick — one per eligible server — so a freshly-added
    // download sees UDP replies from all servers within the first second.
    // Our old implementation pop'd one packet per 1s tick, meaning a 7-server
    // queue took 7 seconds to fully dispatch even though the server-side
    // responses arrive in <500ms. That made new-download source discovery
    // feel sluggish next to eMule for no protocol reason.
    //
    // 200ms tick + up to 3 packets per tick = peak 15 pkts/sec, well below
    // any per-client anti-flood heuristics (typical thresholds are in the
    // hundreds of pkts/sec), and drains a 7-server burst in ~0.4s —
    // matching the eMule UX the user pointed out.
    let mut udp_source_timer = tokio::time::interval(std::time::Duration::from_millis(200));
    udp_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut cleanup_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    cleanup_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // `None` so the first cleanup tick sweeps, clearing anything left queued by
    // a previous run before the user has a chance to look at it.
    let mut last_chat_expiry_sweep: Option<std::time::Instant> = None;
    // Once per run: rows left queued by a previous process, settled before the
    // user can look at them. Later queued rows belong to this run's retry.
    let mut channel_queue_settled = false;
    let mut small_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    small_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // eMule main loop calls Kademlia::Process very frequently; ~100ms matches typical tick cadence.
    let mut kad_process_timer = tokio::time::interval(std::time::Duration::from_millis(100));
    kad_process_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // eMule Kademlia::Process schedules Consolidate() every MIN2S(45) —
    // and MIN2S(min) == min*60, so that is 45 *minutes* (2700s), not 45
    // seconds. The previous 45s value ran the whole zone tree ~60x too
    // often, wasting CPU and thrashing split/merge near bucket boundaries.
    let mut consolidate_timer = tokio::time::interval(std::time::Duration::from_secs(2700));
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
    // Path B telemetry summary: connection-cap usage + detach/diversion/rotation
    // counts, logged once a minute (only when non-idle) to validate and tune the
    // queued-source model in the field.
    let mut pathb_stats_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    pathb_stats_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
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
    let mut server_udp_ping_timer =
        tokio::time::interval(std::time::Duration::from_millis(initial_ping_interval_ms));
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
    // UPnP maintenance cadence. `UpnpMappings::maintain` decides what work is
    // actually due on each tick (lease renewal at 45 min, discovery retry with
    // backoff, stale-gateway re-discovery), so the tick itself can be short.
    let mut upnp_renew_timer = tokio::time::interval(std::time::Duration::from_secs(10 * 60));
    upnp_renew_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut dead_source_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    dead_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reputation_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    reputation_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut reputation_save_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    reputation_save_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut watchdog_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    watchdog_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Broker tick + event drain. Runs at 200 ms so relay events are
    // dispatched within a single tick rather than waiting for the
    // 5-minute cleanup timer.
    //   * `broker.tick()` reaps expired in-flight attempts close to
    //     their nominal 30 s timeout.
    // Idle cost per tick is one `try_recv()` (returns `Empty` instantly)
    // plus a hashmap walk over at most `MAX_ACTIVE_ATTEMPTS` entries.
    let mut broker_timer = tokio::time::interval(std::time::Duration::from_millis(200));
    broker_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // UDP source sweep for active downloads (eMule UDPSERVERREASKTIME = 30 min)
    let mut server_udp_source_timer =
        tokio::time::interval(std::time::Duration::from_secs(30 * 60));
    server_udp_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut uss_ping_timer = tokio::time::interval(std::time::Duration::from_secs(2));
    uss_ping_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Batch TCP OP_GETSOURCES to connected server (eMule ~4 min ProcessLocalRequests cycle)
    let mut server_tcp_source_timer = tokio::time::interval(std::time::Duration::from_secs(4 * 60));
    server_tcp_source_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut ember_refresh_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    ember_refresh_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Expire stalled iterative-lookup queries and push searches forward.
    // 1 s granularity bounds how long a dead hop can hold up a lookup
    // (combined with EMBER_SEARCH_QUERY_TIMEOUT) without busy-spinning.
    let mut ember_search_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    ember_search_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Drain queued STORE records. Separate from the 60-second publish tick
    // that fills the queue: a tick's worth routinely exceeds one peer's frame
    // budget, and holding the overflow until the next tick wasted most of a
    // minute per batch.
    let mut ember_flush_timer = tokio::time::interval(EMBER_FLUSH_INTERVAL);
    ember_flush_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Periodic DHT maintenance: bucket refresh, contact liveness pings,
    // and record republish. Each task is internally gated on a much longer
    // interval, so the 60-second cadence is cheap when nothing is due.
    let mut ember_maintenance_timer = tokio::time::interval(EMBER_MAINT_INTERVAL);
    ember_maintenance_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut friend_relay_ticket_poll_timer =
        tokio::time::interval(rendezvous::FRIEND_RELAY_TICKET_RESPONDER_POLL_INTERVAL);
    friend_relay_ticket_poll_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut source_count_sync_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    source_count_sync_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut cache_write_handle: Option<tokio::task::JoinHandle<()>> = None;
    let (known_met_save_result_tx, mut known_met_save_result_rx) =
        mpsc::unbounded_channel::<KnownMetSaveResult>();
    let (periodic_save_result_tx, mut periodic_save_result_rx) =
        mpsc::unbounded_channel::<PeriodicSaveResult>();
    let (spam_save_result_tx, mut spam_save_result_rx) =
        mpsc::unbounded_channel::<SpamSaveResult>();
    let (upnp_maintain_result_tx, mut upnp_maintain_result_rx) =
        mpsc::unbounded_channel::<UpnpMaintainResult>();
    let (rendezvous_register_result_tx, mut rendezvous_register_result_rx) =
        mpsc::unbounded_channel::<RendezvousRegisterResult>();
    let (channel_neighbor_lookup_tx, mut channel_neighbor_lookup_rx) =
        mpsc::unbounded_channel::<ChannelNeighborLookupResult>();
    let (channel_relay_event_tx, mut channel_relay_event_rx) =
        mpsc::unbounded_channel::<ChannelRelayEvent>();
    let (friend_relay_ticket_poll_result_tx, mut friend_relay_ticket_poll_result_rx) =
        mpsc::unbounded_channel::<FriendRelayTicketPollResult>();
    let (friend_relay_ticket_session_done_tx, mut friend_relay_ticket_session_done_rx) =
        mpsc::unbounded_channel::<String>();
    let (nat_probe_result_tx, mut nat_probe_result_rx) =
        mpsc::unbounded_channel::<NatProbeResult>();
    // Completed-download BLAKE3 digests, computed off the event loop.
    // `(ed2k hash, digest)`.
    let (ember_digest_result_tx, mut ember_digest_result_rx) =
        mpsc::unbounded_channel::<([u8; 16], [u8; 32])>();
    // Completed-download ed2k part hashsets, recomputed off the event loop for
    // the same reason as the digests above. `(ed2k hash, part hashes)`.
    let (part_hashset_result_tx, mut part_hashset_result_rx) =
        mpsc::unbounded_channel::<([u8; 16], Vec<[u8; 16]>)>();
    // Durable inputs for the enforced-ban rebuild, read off the event loop.
    // `None` means the read failed and the current set must be kept.
    let (banned_ips_sync_tx, mut banned_ips_sync_rx) =
        mpsc::unbounded_channel::<Option<BannedIpsSyncInputs>>();
    let mut banned_ips_sync_in_flight = false;
    let mut nat_probe_packet_tx: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>> = None;
    let (udp_map_ka_result_tx, mut udp_map_ka_result_rx) =
        mpsc::unbounded_channel::<UdpMappingKeepaliveResult>();
    let mut udp_map_ka_packet_tx: Option<mpsc::Sender<(Vec<u8>, SocketAddr)>> = None;
    let (tcp_map_ka_result_tx, mut tcp_map_ka_result_rx) =
        mpsc::unbounded_channel::<TcpMappingKeepaliveResult>();
    let mut mapping_ka_server_index: usize = 0;
    let mut udp_map_ka_in_flight = false;
    let mut tcp_map_ka_in_flight = false;
    let mut udp_map_ka_started_at: Option<tokio::time::Instant> = None;
    let mut tcp_map_ka_started_at: Option<tokio::time::Instant> = None;
    let mut udp_map_ka_gen: Option<u64> = None;
    let mut tcp_map_ka_gen: Option<u64> = None;
    // Whether *any* keep-alive contribution (confirmed UDP mapping, applied
    // TCP mapping, or a successful TCP hold) succeeded for the current
    // generation. Reset when a new round starts; checked once every in-flight
    // half of that round has been processed so a fully failed cycle can
    // clear the "Active" indicator instead of leaving it sticky.
    let mut mapping_ka_cycle_success = false;
    let mut next_mapping_ka_at = tokio::time::Instant::now()
        + if settings.stun_keepalive_enabled {
            std::time::Duration::from_secs(3)
        } else {
            ember::mapping_keepalive::MAPPING_KEEPALIVE_INTERVAL
        };
    let mut known_met_save_in_flight = false;
    let mut known_met_save_started_at: Option<tokio::time::Instant> = None;
    let mut stats_save_in_flight = false;
    let mut stats_save_started_at: Option<tokio::time::Instant> = None;
    let mut reputation_save_in_flight = false;
    let mut reputation_save_started_at: Option<tokio::time::Instant> = None;
    // Same dirty-check shape as `known2_saved_len` below: the generation the
    // last *durable* reputation write covered, and the one the in-flight write
    // is carrying. On a long-lived node the peer/IP maps sit near their 20k cap
    // and rarely change between 5-minute ticks, so without this the timer
    // cloned 20k entries and fsync'd ~2 MB of identical JSON 288 times a day.
    let mut reputation_saved_generation: Option<u64> = None;
    let mut reputation_in_flight_generation: u64 = 0;
    let mut known2_save_in_flight = false;
    let mut known2_save_started_at: Option<tokio::time::Instant> = None;
    // Length of `aich_hash_sets` as of the last durable `known2_64.met` write,
    // or `None` if this session has not written one yet. `aich_hash_sets` is
    // append-only — nothing removes an entry and the cap refuses new sets
    // rather than evicting — so its length identifies its contents, which
    // makes this a sufficient dirty check.
    let mut known2_saved_len: Option<usize> = None;
    let mut known2_in_flight_len: usize = 0;
    let mut nodes_save_in_flight = false;
    let mut nodes_save_started_at: Option<tokio::time::Instant> = None;
    let mut spam_save_in_flight = false;
    let mut spam_save_started_at: Option<tokio::time::Instant> = None;
    let mut upnp_maintain_in_flight = false;
    let mut upnp_maintain_started_at: Option<tokio::time::Instant> = None;
    // Handle on the detached UPnP pass, kept only so the watchdog can abort a
    // stuck one. Clearing `upnp_maintain_in_flight` alone lets the next tick
    // start a second pass while the first is still parked inside a SOAP call
    // that may never return, and every ten minutes adds another — each holding
    // a cloned `UpnpMappings` and its gateway socket for the life of the
    // process. The calls themselves are bounded now (`upnp::SOAP_TIMEOUT`), so
    // this is the backstop for anything that outlives its own timeout.
    let mut upnp_maintain_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut rendezvous_register_in_flight = false;
    let mut rendezvous_register_started_at: Option<tokio::time::Instant> = None;
    let mut friend_relay_ticket_polls_in_flight = 0usize;
    let mut friend_relay_ticket_sessions_in_flight = HashSet::<String>::new();
    let mut friend_relay_ticket_poll_retry_delay = std::time::Duration::from_secs(1);
    let mut friend_relay_ticket_poll_not_before = tokio::time::Instant::now();
    let mut friend_relay_ticket_poll_round_started_at: Option<tokio::time::Instant> = None;
    let mut nat_probe_in_flight = false;
    let mut nat_probe_started_at: Option<tokio::time::Instant> = None;
    let mut nat_probe_backoff_until: Option<tokio::time::Instant> = None;
    let mut credit_flush_handle: Option<tokio::task::JoinHandle<()>> = None;
    let mut last_server_activity_at = chrono::Utc::now().timestamp();
    let mut last_kad_activity_at = chrono::Utc::now().timestamp();
    let mut last_cache_refresh_started_at = 0i64;
    // `(known.met dirty generation, publish-badge fingerprint)` the cached
    // shared-file list was last built from. `None` until the first refresh, so
    // the first tick after startup always builds one.
    let mut last_file_snapshot_inputs: Option<(u64, u64)> = None;

    // Defer transfer resume, orphan sweep, firewall rules, and heavy disk
    // loads until the event loop can service splash IPC. UPnP setup is also
    // kicked here (non-blocking) via the maintain-result channel.
    // Hold the same admission mutex used by direct and collection IPC until
    // every retained startup row has entered the manager/network maps. This
    // prevents a renderer request racing the restore at N+1.
    let mut startup_download_admission =
        if let Some(app_state) = app_handle.try_state::<crate::app_state::AppState>() {
            Some(app_state.download_admission.clone().lock_owned().await)
        } else {
            None
        };
    let overflow_count = db
        .quarantine_excess_pending_downloads(
            crate::commands::transfers::MAX_PENDING_DOWNLOADS,
            crate::commands::transfers::MAX_PENDING_REMAINING_BYTES,
        )
        .unwrap_or_else(|error| {
            warn!("Failed to migrate oversized pending-download queue: {error}");
            0
        });
    if overflow_count > 0 {
        warn!(
            "Quarantined {overflow_count} legacy pending download(s) beyond the safety budget; a durable UI notice will be shown"
        );
    }
    let mut restored_rows = Vec::new();
    const RESTORE_PAGE_SIZE: usize = 256;
    let mut restore_offset = 0usize;
    loop {
        match db.get_incomplete_downloads_page(RESTORE_PAGE_SIZE, restore_offset) {
            Ok(page) if page.is_empty() => break,
            Ok(page) => {
                restore_offset = restore_offset.saturating_add(page.len());
                restored_rows.extend(page);
                if restored_rows.len() >= crate::commands::transfers::MAX_PENDING_DOWNLOADS {
                    break;
                }
            }
            Err(error) => {
                warn!("Failed to load incomplete download restore page: {error}");
                break;
            }
        }
    }
    let mut pending_incomplete_downloads = if restored_rows.is_empty() {
        None
    } else {
        info!(
            "Will resume {} incomplete downloads after event loop starts",
            restored_rows.len()
        );
        Some(restored_rows)
    };
    if pending_incomplete_downloads.is_none() {
        startup_download_admission.take();
    }
    let mut part_progress_task: Option<
        tokio::task::JoinHandle<std::collections::HashMap<String, (u64, bool, bool)>>,
    > = None;
    let mut part_progress_map: Option<std::collections::HashMap<String, (u64, bool, bool)>> = None;
    let mut pending_startup_cleanup = true;
    let mut known_met_ready = false;
    let mut pending_upnp_setup = upnp_enabled;
    let mut deferred_disk_loads: Option<tokio::task::JoinHandle<DeferredDiskLoads>> = {
        let ipfilter_path = data_dir.join("ipfilter.dat");
        let known_met_path = data_dir.join("known.met");
        let known2_met_path = data_dir.join("known2_64.met");
        let aich_cache_path = data_dir.join("aich_cache.dat");
        let geoip_for_load = geoip.clone();
        let geoip_dir = geoip_resource_dir.clone();
        Some(tokio::task::spawn_blocking(move || {
            let mut filter = IpFilter::new(ipf_enabled, ipf_block_private);
            // Only clear the fail-closed gate when the load succeeded or the
            // file is absent (intentional empty). Mid-file I/O failure returns
            // None and must leave ranges_ready=false so we do not silently
            // run with enabled+empty blacklist (R3).
            let ranges_ready = if ipf_enabled && ipfilter_path.exists() {
                match filter.load_from_file(&ipfilter_path) {
                    Some(n @ 1..) => {
                        info!(
                            "Loaded IP filter: enabled={}, block_private={}, ranges={}",
                            filter.is_enabled(),
                            filter.blocks_private(),
                            n,
                        );
                        true
                    }
                    Some(0) => {
                        filter.mark_ranges_not_ready();
                        warn!(
                            "IP filter at {} contained no valid ranges; leaving the enabled filter fail-closed until a successful reload",
                            ipfilter_path.display()
                        );
                        false
                    }
                    None => {
                        warn!(
                            "IP filter load failed for {}; leaving fail-closed until a successful reload",
                            ipfilter_path.display()
                        );
                        false
                    }
                }
            } else {
                info!(
                    "Loaded IP filter: enabled={}, block_private={}, ranges={}",
                    filter.is_enabled(),
                    filter.blocks_private(),
                    filter.range_count(),
                );
                true
            };
            if ranges_ready {
                filter.mark_ranges_ready();
            }
            let known_files = KnownFileList::load(&known_met_path);
            info!("Loaded {} known files", known_files.file_count());

            let mut aich_hash_sets = Vec::new();
            match ed2k::aich::load_known2_met(&known2_met_path) {
                Ok(sets) => {
                    let total = sets.len();
                    aich_hash_sets = sets
                        .into_iter()
                        .take(MAX_AICH_HASH_SETS)
                        .map(|(root, leaves)| {
                            let file_size =
                                leaves.len() as u64 * ed2k::aich::AICH_BLOCK_SIZE as u64;
                            ed2k::aich::AICHRecoveryHashSet {
                                root_hash: root,
                                leaf_hashes: leaves,
                                file_size,
                            }
                        })
                        .collect();
                    if total > MAX_AICH_HASH_SETS {
                        warn!(
                            "known2_64.met has {} sets (cap {}); dropping {} oldest on load",
                            total,
                            MAX_AICH_HASH_SETS,
                            total - MAX_AICH_HASH_SETS,
                        );
                    }
                    info!(
                        "Loaded {} AICH hash sets from known2_64.met",
                        aich_hash_sets.len()
                    );
                }
                Err(e) => {
                    if known2_met_path.exists() {
                        warn!("Failed to load known2_64.met: {e}");
                    }
                }
            }

            let mut aich_root_map = HashMap::new();
            if let Ok(contents) = std::fs::read_to_string(&aich_cache_path) {
                let mut skipped_at_cap = 0usize;
                for line in contents.lines() {
                    if let Some((ed2k_hex, aich_hex)) = line.split_once('=') {
                        if let (Ok(ed2k_bytes), Ok(aich_bytes)) =
                            (hex::decode(ed2k_hex.trim()), hex::decode(aich_hex.trim()))
                        {
                            if ed2k_bytes.len() == 16 && aich_bytes.len() == 20 {
                                if aich_root_map.len() >= MAX_AICH_ROOT_MAP_SOFT_CAP {
                                    skipped_at_cap = skipped_at_cap.saturating_add(1);
                                    continue;
                                }
                                let mut fh = [0u8; 16];
                                let mut ah = [0u8; 20];
                                fh.copy_from_slice(&ed2k_bytes);
                                ah.copy_from_slice(&aich_bytes);
                                aich_root_map.insert(fh, ah);
                            }
                        }
                    }
                }
                if skipped_at_cap > 0 {
                    warn!(
                        "aich_cache.dat had {} entries past soft cap {}; ignored on load",
                        skipped_at_cap, MAX_AICH_ROOT_MAP_SOFT_CAP,
                    );
                }
                info!(
                    "Loaded {} AICH root mappings from cache",
                    aich_root_map.len()
                );
            }

            crate::geoip::fill(&geoip_for_load, &geoip_dir);

            DeferredDiskLoads {
                ip_filter: filter,
                known_files,
                aich_hash_sets,
                aich_root_map,
            }
        }))
    };

    // Rate-limited LowID callback flush after login (avoid monopolizing the loop).
    let mut pending_lowid_callback_queue: std::collections::VecDeque<([u8; 16], u32)> =
        std::collections::VecDeque::new();
    // Chunked OP_OFFERFILES across loop turns (post-login + shared-files changes).
    let mut pending_offer_files: Option<Vec<ed2k::server::OfferFile>> = None;
    let mut pending_offer_signature: Option<(usize, u64)> = None;
    let mut next_offer_packet_at: Option<tokio::time::Instant> = None;

    let (aich_set_tx, mut aich_set_rx) =
        tokio::sync::mpsc::channel::<ed2k::aich::AICHRecoveryHashSet>(128);

    info!("Network event loop starting");
    let mut shutdown_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
    /// Budget handed to the save sequence when the loop ends without a
    /// `Shutdown` command, i.e. when nobody supplied a deadline.
    const UNREQUESTED_SHUTDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);
    // Whether `shutdown_deadline` came from a caller that is waiting on us.
    // Only a `Shutdown` command sets it; the other two ways out of the loop (a
    // panic caught below, and the command channel closing) leave the initial
    // start-up value, which is in the past for any session older than the
    // budget above — and every phase deadline is `min(global, now + phase)`, so
    // a past global expires all of them instantly and silently skips
    // nodes.dat, known.met, credits, reputation, sources.met and server.met.
    let mut shutdown_requested = false;

    let loop_panic = std::panic::AssertUnwindSafe(async {
    loop {
        // Give frontend commands priority, but cap each batch so a full IPC
        // channel cannot starve UDP, timers, and transfer events indefinitely.
        const MAX_COMMANDS_PER_ITERATION: usize = 128;
        let mut shutting_down = false;
        for _ in 0..MAX_COMMANDS_PER_ITERATION {
            let Ok(cmd) = cmd_rx.try_recv() else {
                break;
            };
            match cmd {
                NetworkCommand::Shutdown { deadline } => {
                    shutdown_deadline = deadline;
                    shutdown_requested = true;
                    shutting_down = true;
                    break;
                }
                NetworkCommand::UpdateSettings { settings: new_settings } => {
                    let old_channel_username = settings.channel_username.clone();
                    if apply_network_settings(
                        &mut state,
                        &mut settings,
                        new_settings,
                        &app_handle,
                    ) {
                        load_ipfilter_on_enable(&mut state).await;
                    }
                    publish_presence_under_new_username(
                        &udp_socket,
                        &mut state,
                        &db,
                        &settings,
                        &identity,
                        &old_channel_username,
                    )
                    .await;
                    state
                        .relay_manager
                        .lock()
                        .await
                        .set_policy(settings.relay_for_peers, settings.max_relay_sessions);
                    {
                        let mut nick = shared_nickname.write().await;
                        *nick = settings.nickname.clone();
                    }
                    source_manager
                        .write()
                        .await
                        .set_max_per_file(settings.max_sources_per_file);
                    if settings.filter_servers_by_ip {
                        apply_server_ip_filter(
                            &mut state,
                            &shared_server_addr,
                            &app_handle,
                            true,
                        )
                        .await;
                    }
                }
                cmd => {
                    handle_command(
                        &udp_socket,
                        cmd,
                        &mut state,
                        &local_index,
                        &fresh_part_hashes,
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
                        &shared_friends_only_hashes,
                        &shared_server_addr,
                        &shared_ember_payload,
                        &ember_payload_generation,
                        &geoip,
                        &friend_hashes,
                        &mutual_friend_hashes,
                        ember_hash,
                        &ul_event_tx,
                        ed25519_pubkey,
                        ed25519_secret_key,
                        &upload_queue_handle,
                        &transfer_status_writes,
                    ).await;
                }
            }
        }
        if shutting_down {
            info!("Network shutting down");
            // Stop the upload listener from accepting new connections (and let it
            // terminate active sessions) during the multi-second shutdown save
            // sequence, so it can't spawn work against state being torn down.
            state.uploads_halted_for_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            break;
        }

        // --- Deferred startup: disk loads, UPnP, transfer resume, offers ------
        if pending_upnp_setup {
            pending_upnp_setup = false;
            if upnp_enabled {
                let revision = upnp_mappings.revision();
                let mut mappings = upnp_mappings.clone();
                let tx = upnp_maintain_result_tx.clone();
                upnp_maintain_in_flight = true;
                upnp_maintain_started_at = Some(tokio::time::Instant::now());
                upnp_maintain_handle = Some(tokio::spawn(async move {
                    mappings.setup().await;
                    let mapped = mappings.is_mapped();
                    if mapped {
                        info!("UPnP port mapping succeeded -- not firewalled");
                    } else {
                        debug!(
                            "UPnP initial port mapping failed; keeping UPnP enabled and retrying in the background"
                        );
                    }
                    let _ = tx.send(UpnpMaintainResult {
                        revision,
                        mappings,
                        mapped,
                    });
                }));
            } else {
                info!("UPnP disabled by user -- skipping port mapping");
            }
        }

        if let Some(handle) = deferred_disk_loads.as_mut() {
            if handle.is_finished() {
                match deferred_disk_loads.take().unwrap().await {
                    Ok(loads) => {
                        // Preserve enable/private flags and any ranges the
                        // user added while the deferred load was in flight.
                        // If ReloadIpFilter (or a manual add that loaded the
                        // file) already replaced the live list, do not write
                        // the stale startup snapshot back over it.
                        if state.ip_filter.has_loaded_ranges() {
                            info!(
                                "Deferred IP filter load skipped: live filter already loaded"
                            );
                        } else {
                            let live_enabled = state.ip_filter.is_enabled();
                            let live_block_private = state.ip_filter.blocks_private();
                            let mut loaded = loads.ip_filter;
                            // Capture before set_enabled(true), which clears ranges_ready.
                            let deferred_load_ready = loaded.ranges_ready();
                            loaded.merge_ranges_from(&state.ip_filter);
                            loaded.set_enabled(live_enabled);
                            loaded.set_block_private(live_block_private);
                            if live_enabled {
                                if deferred_load_ready {
                                    loaded.mark_ranges_ready();
                                } else {
                                    warn!(
                                        "Deferred IP filter load failed; leaving fail-closed until a successful reload"
                                    );
                                }
                            }
                            state.ip_filter = loaded;
                            state
                                .ip_filter
                                .update_shared_snapshot(&state.shared_ip_filter);
                            state.routing_table.evict_filtered_contacts();
                            state.ember_dht.evict_filtered_contacts();
                        }
                        known_files.absorb_missing_from(loads.known_files);
                        sync_shared_friends_only_hashes(&shared_friends_only_hashes, &known_files);
                        or_index_friends_only_from_known(&local_index, &known_files).await;
                        known_met_ready = true;
                        // Startup scan often finishes (and no-ops AnnounceFiles)
                        // against the placeholder catalog a few hundred ms
                        // before this absorb. KAD auto-connect is off, so
                        // `first_publish_done` is still false here — gating
                        // the backfill on it left the publish manager empty
                        // for the rest of the session. Always register now;
                        // friends-only hashes stay out inside the helpers.
                        let shared_n = publish_kad_completes_from_index(
                            &mut state,
                            &local_index,
                            &known_files,
                        )
                        .await;
                        let partial_n = publish_kad_partials_from_transfers(
                            &mut state,
                            &transfer_manager,
                            &local_index,
                            &known_files,
                        )
                        .await;
                        if shared_n + partial_n as usize > 0 {
                            info!(
                                "Backfilled {shared_n} public shares + {partial_n} partial downloads into KAD publish after known.met load"
                            );
                            // The library is registered, so the KAD-connect
                            // promotion does not need to sweep it again — that
                            // second pass re-derives every keyword, and on the
                            // UDP promotion path it runs inside packet
                            // handling. Left false when nothing registered
                            // (index still scanning) so that path retries.
                            state.first_publish_done = true;
                        }
                        state.request_offer_files = true;
                        hydrate_ember_publish_schedule(
                            &known_files,
                            &mut state.ember_source_publish_at,
                            &mut state.ember_source_publish_unix,
                            &mut state.ember_keyword_publish_at,
                            &mut state.ember_keyword_publish_unix,
                            &mut state.ember_published_sources,
                        );
                        state.aich_hash_sets = loads.aich_hash_sets;
                        // The deferred load replaces the in-memory set wholesale,
                        // so any length this session already wrote no longer
                        // describes what is in memory.
                        known2_saved_len = None;
                        for (k, v) in loads.aich_root_map {
                            if state.aich_root_map.len() >= MAX_AICH_ROOT_MAP_SOFT_CAP {
                                break;
                            }
                            state.aich_root_map.entry(k).or_insert(v);
                        }
                        if settings.filter_servers_by_ip {
                            apply_server_ip_filter(
                                &mut state,
                                &shared_server_addr,
                                &app_handle,
                                true,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        warn!("Deferred disk load task panicked: {e}");
                        known_met_ready = true;
                        // Absorbing the catalog is the *only* thing that makes
                        // it authoritative, and authoritative is what un-gates
                        // every advertise and serve path: `kad_may_advertise_*`
                        // and `mark_friends_only_snapshot_ready`. Leaving it
                        // unset because an unrelated part of that task (the IP
                        // filter, the AICH sets) panicked would silently turn
                        // off KAD and Ember publishing, `OP_OFFERFILES`, and
                        // every upload to a non-friend for the whole session,
                        // with this one log line as the only signal. The
                        // deferred handle is already taken and never retried,
                        // so recover the catalog on its own here.
                        let known_path = state.data_dir.join("known.met");
                        match tokio::task::spawn_blocking(move || {
                            KnownFileList::load_checked(&known_path)
                        })
                        .await
                        {
                            Ok(Ok(loaded)) => {
                                known_files.absorb_missing_from(loaded);
                                sync_shared_friends_only_hashes(
                                    &shared_friends_only_hashes,
                                    &known_files,
                                );
                                or_index_friends_only_from_known(&local_index, &known_files).await;
                                let shared_n = publish_kad_completes_from_index(
                                    &mut state,
                                    &local_index,
                                    &known_files,
                                )
                                .await;
                                let partial_n = publish_kad_partials_from_transfers(
                                    &mut state,
                                    &transfer_manager,
                                    &local_index,
                                    &known_files,
                                )
                                .await;
                                if shared_n + partial_n as usize > 0 {
                                    state.first_publish_done = true;
                                }
                                state.request_offer_files = true;
                                info!(
                                    "Recovered known.met after the deferred load panicked: \
                                     {shared_n} public shares + {partial_n} partial downloads \
                                     registered; sharing stays enabled"
                                );
                            }
                            Ok(Err(load_err)) => {
                                error!(
                                    "known.met could not be read after the deferred load panicked \
                                     ({load_err}); sharing and publishing stay disabled for this \
                                     session to avoid advertising a friends-only file"
                                );
                            }
                            Err(join_err) => {
                                error!(
                                    "known.met recovery task panicked as well ({join_err}); \
                                     sharing and publishing stay disabled for this session"
                                );
                            }
                        }
                        // A failed deferred read must not turn an enabled
                        // filter into an intentional empty one. Keep the
                        // peer paths fail-closed until a successful reload.
                        if state.ip_filter.is_enabled() {
                            state.ip_filter.mark_ranges_not_ready();
                            state
                                .ip_filter
                                .update_shared_snapshot(&state.shared_ip_filter);
                        }
                    }
                }
            }
        }

        if let Some(pending) = pending_incomplete_downloads
            .as_ref()
            .filter(|_| part_progress_task.is_none() && part_progress_map.is_none())
        {
            let dl_folder = settings.download_folder.clone();
            let jobs: Vec<(String, u64, String)> = pending
                .iter()
                .map(|t| (t.id.clone(), t.total_size, t.file_name.clone()))
                .collect();
            part_progress_task = Some(tokio::task::spawn_blocking(move || {
                let mut map = std::collections::HashMap::new();
                for (id, total, name) in jobs {
                    let part_path = PathBuf::from(&dl_folder)
                        .join("Temp")
                        .join(format!("{id}.part"));
                    if part_path.exists() && total > 0 {
                        let tracker =
                            crate::network::ed2k::part_tracker::PartTracker::new(total, &part_path);
                        map.insert(
                            id,
                            (
                                tracker.completed_bytes(),
                                tracker.is_preview_ready(&name, total),
                                tracker.all_complete(),
                            ),
                        );
                    }
                }
                map
            }));
        }
        if let Some(handle) = part_progress_task.as_mut() {
            if handle.is_finished() {
                match part_progress_task.take().unwrap().await {
                    Ok(map) => part_progress_map = Some(map),
                    Err(e) => {
                        warn!("Part progress restore task panicked: {e}");
                        part_progress_map = Some(std::collections::HashMap::new());
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
                collect_friends_only_hashes(&index, &known_files)
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

                // Check .part file for actual progress (part files live in Temp subdir)
                let part_path = PathBuf::from(&dl_folder)
                    .join("Temp")
                    .join(format!("{}.part", transfer.id));
                if part_path.exists() && transfer.total_size > 0 {
                    if let Some((completed_bytes, preview_ready, _)) =
                        progress_map.get(&transfer.id).copied()
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
                            ((completed_bytes as f64 / transfer.total_size as f64) * 100.0)
                                .min(100.0);
                        control.set_preview_ready(preview_ready);
                    }
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
                        let all_complete = progress_map
                            .get(&transfer.id)
                            .map(|(_, _, ac)| *ac)
                            .unwrap_or(false);
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
                            last_search_at: 0,
                            priority: priority_str_to_u32(&transfer.priority),
                        },
                    );
                }

                // Register partial download for KAD source publishing
                if let Ok(hash_bytes) = hex::decode(&transfer.file_hash) {
                    if hash_bytes.len() >= 16
                        && kad_may_advertise_partial(
                            &known_files,
                            &resume_restricted,
                            &transfer.file_hash,
                        )
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
        }

        if pending_startup_cleanup
            && pending_incomplete_downloads.is_none()
            && part_progress_task.is_none()
            && part_progress_map.is_none()
        {
            pending_startup_cleanup = false;
            {
                let known_ids: std::collections::HashSet<String> = {
                    let mgr = transfer_manager.read().await;
                    mgr.get_all().into_iter().map(|t| t.id).collect()
                };
                crate::commands::transfers::sweep_orphan_part_files(
                    &settings.download_folder,
                    &known_ids,
                    &db,
                )
                .await;
            }

            #[cfg(target_os = "windows")]
            {
                let fw_tcp = tcp_port;
                let fw_udp = udp_port;
                tokio::task::spawn_blocking(move || {
                    crate::security::firewall::ensure_firewall_rules(fw_tcp, fw_udp);
                });
            }

            ed2k::preview::cleanup_previews();
        }

        // Drain at most one OP_OFFERFILES chunk per `ED2K_OFFER_PACKET_INTERVAL`,
        // as eMule's `CSharedFileList::Process` does; the first packet after
        // login goes out at once.
        if state.request_offer_files && pending_offer_files.is_none() {
            state.request_offer_files = false;
            if state.server_connected {
                let mut seen_offer_hashes = std::collections::HashSet::new();
                let (mut offer_files, restricted) = {
                    let index = local_index.read().await;
                    let restricted = collect_friends_only_hashes(&index, &known_files);
                    let offer_files: Vec<ed2k::server::OfferFile> = index
                        .all_files()
                        .iter()
                        .filter(|f| kad_may_advertise_complete(f, &known_files, &restricted))
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
                        .collect();
                    (offer_files, restricted)
                };
                let temp_dir = PathBuf::from(&settings.download_folder).join("Temp");
                {
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
                        if !kad_may_advertise_partial(
                            &known_files,
                            &restricted,
                            &transfer.file_hash,
                        ) {
                            continue;
                        }
                        if transfer.file_hash.is_empty()
                            || !seen_offer_hashes.insert(transfer.file_hash.clone())
                        {
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
                let signature = offer_files_signature(&offer_files);
                if offer_files.is_empty() {
                    pending_offer_signature = Some(signature);
                    if state.offered_ed2k_hashes.is_empty() {
                        state.last_offer_files_signature = Some(signature);
                        pending_offer_files = None;
                    } else {
                        // Tell the server we no longer share anything. Do not
                        // republish the old list on the way out.
                        pending_offer_files = Some(Vec::new());
                    }
                } else {
                    let incremental =
                        incremental_ed2k_offers(offer_files, &state.offered_ed2k_hashes);
                    pending_offer_signature = Some(signature);
                    if incremental.is_empty() {
                        state.last_offer_files_signature = Some(signature);
                        pending_offer_files = None;
                    } else {
                        pending_offer_files = Some(incremental);
                    }
                }
            }
        }
        let offer_packet_due =
            next_offer_packet_at.is_none_or(|at| tokio::time::Instant::now() >= at);
        if let Some(files) = pending_offer_files.as_mut().filter(|_| offer_packet_due) {
            if state.server_connection.is_some() {
                let limit = state
                    .server_connection
                    .as_ref()
                    .map(|c| c.offer_files_chunk_limit())
                    .unwrap_or(200);
                let end = limit.min(files.len());
                let chunk: Vec<_> = files.drain(..end).collect();
                let offer_tcp_port = advertised_tcp_port(&state);
                if let Some(conn) = state.server_connection.as_mut() {
                    if !chunk.is_empty() {
                        match conn.offer_files_chunk(&chunk, offer_tcp_port).await {
                            Ok(()) => {
                                next_offer_packet_at =
                                    Some(tokio::time::Instant::now() + ED2K_OFFER_PACKET_INTERVAL);
                                record_offered_ed2k_hashes(&mut state, &chunk);
                                if files.is_empty() {
                                    pending_offer_files = None;
                                    if let Some(sig) = pending_offer_signature.take() {
                                        state.last_offer_files_signature = Some(sig);
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Failed to send OP_OFFERFILES chunk: {e}");
                                // Put the failed chunk back at the front so it is
                                // retried on a later turn instead of being dropped.
                                let mut rest = std::mem::take(files);
                                let mut retry = chunk;
                                retry.append(&mut rest);
                                *files = retry;
                            }
                        }
                    } else if files.is_empty() {
                        // An empty offer is a real message — it tells the
                        // server we no longer share anything, and
                        // `offer_files_chunk` deliberately supports the
                        // count=0 form. Dropping it here meant a user who
                        // unshared their library (or removed their last
                        // shared folder, or marked everything friends-only)
                        // stayed listed as a source for all of it until they
                        // disconnected, with peers still being handed their
                        // address. It also left `last_offer_files_signature`
                        // stale, so every later reconcile re-armed this same
                        // no-op.
                        match conn.offer_files_chunk(&chunk, offer_tcp_port).await {
                            Ok(()) => {
                                next_offer_packet_at =
                                    Some(tokio::time::Instant::now() + ED2K_OFFER_PACKET_INTERVAL);
                                pending_offer_files = None;
                                state.offered_ed2k_hashes.clear();
                                if let Some(sig) = pending_offer_signature.take() {
                                    state.last_offer_files_signature = Some(sig);
                                }
                            }
                            Err(e) => {
                                debug!("Failed to send the clearing OP_OFFERFILES: {e}");
                            }
                        }
                    }
                }
            } else {
                pending_offer_files = None;
                pending_offer_signature = None;
            }
        }

        // Rate-limit LowID callback requests after login / poll bursts. Every
        // producer feeds this queue through `queue_lowid_callbacks` (capped at
        // MAX_PENDING_LOWID_CALLBACKS) rather than writing to the server itself.
        if !pending_lowid_callback_queue.is_empty()
            && state.server_connected
            && !state.low_id
        {
            if let Some(conn) = state.server_connection.as_mut() {
                let mut succeeded = Vec::new();
                for _ in 0..MAX_LOWID_CALLBACKS_PER_TURN {
                    let Some((file_hash, client_id)) = pending_lowid_callback_queue.pop_front()
                    else {
                        break;
                    };
                    if conn.request_callback(client_id).await.is_ok() {
                        succeeded.push((file_hash, client_id));
                    } else {
                        // Keep the entry and stop this turn — further attempts
                        // against a failing TCP session would just burn the quota.
                        pending_lowid_callback_queue.push_front((file_hash, client_id));
                        break;
                    }
                }
                if !succeeded.is_empty() {
                    let mut sm = source_manager.write().await;
                    for (file_hash, client_id) in &succeeded {
                        sm.mark_callback_sent(file_hash, *client_id);
                    }
                    debug!(
                        "Sent {} LowID callbacks ({} still queued)",
                        succeeded.len(),
                        pending_lowid_callback_queue.len()
                    );
                }
            }
        }


        // --- Deferred startup: server.met bootstrap + auto-connect ------------
        // Kept out of pre-loop init so splash/GetNetworkStats can complete while
        // the upload listener is already accepting the server's HighID port-test.
        if pending_server_met_bootstrap && server_met_bootstrap_task.is_none() {
            pending_server_met_bootstrap = false;
            let url = crate::commands::server::DEFAULT_SERVER_MET_URL;
            info!("Empty server list — downloading server.met from {url} (background)");
            server_met_bootstrap_task = Some(tokio::spawn(async move {
                crate::commands::server::fetch_server_met_bytes(url).await
            }));
        } else if server_met_bootstrap_task.is_none()
            && pending_auto_connect_server
            && deferred_disk_loads.is_none()
            && state.ip_filter.ranges_ready()
            && state.pending_server_connect.is_none()
            && !state.server_connected
            && state.server_connection.is_none()
        {
            pending_auto_connect_server = false;
            match ed2k::server_list::ServerList::resolve_auto_connect_target(
                &state.data_dir,
                &state.server_list,
            ) {
                Some((server_ip, server_port)) => {
                    initiate_server_connect(
                        &mut state,
                        &settings,
                        &app_handle,
                        &shared_server_addr,
                        server_ip,
                        server_port,
                    )
                    .await;
                }
                None => {
                    emit_server_auto_connect_failed(
                        &app_handle,
                        "no last server and eMule Sunrise not in list",
                    );
                }
            }
        }

        if state.stats.status == NetworkStatus::Disconnected {
            // Ember-only nodes remain KAD-Disconnected permanently. Do not
            // cancel an in-flight STUN probe that discovers `external_ip` for
            // slice-9 source publish — clearing here every loop iteration
            // would respawn forever and ignore every STUN reply as stale.
            //
            // Also don't stomp a probe that just started: this runs on EVERY
            // loop iteration while disconnected (not just once on the
            // disconnect transition), and STUN keepalive's own external-IP
            // discovery can satisfy the NAT-probe trigger conditions before
            // `KadConnect` ever flips status away from `Disconnected` (often
            // within the same second at startup). Without this guard, each
            // iteration here would reset `nat_probe_in_flight = false`,
            // letting the catch-all trigger below immediately spawn a NEW
            // probe and orphan the previous one's reply-routing channel —
            // observed in practice as 3 probes spawned within ~40ms and a
            // "STUN reply channel closed" error on the abandoned ones.
            let probe_is_fresh = nat_probe_in_flight
                && nat_probe_started_at
                    .map(|t| t.elapsed() < NAT_PROBE_WATCHDOG)
                    .unwrap_or(false);
            if !settings.ember_native_enabled && !probe_is_fresh {
                nat_probe_in_flight = false;
                nat_probe_started_at = None;
                nat_probe_packet_tx = None;
            }
            // Same trap as the NAT probe above, and for the same reason: once
            // the user disconnects KAD the node is `Disconnected` for the rest
            // of the session, so clearing unconditionally left the in-flight guard
            // permanently false. The bootstrap timer then respawned
            // registration every tick, each spawn bumped
            // `rendezvous_register_generation`, and the result handler dropped
            // every reply as stale — `rendezvous_registered` and
            // `friend_presence_initial_done` could never latch and friends
            // never saw us. Only give up on an attempt the watchdog would have
            // abandoned anyway.
            let register_is_fresh = rendezvous_register_in_flight
                && rendezvous_register_started_at
                    .map(|t| t.elapsed() < RENDEZVOUS_REGISTER_WATCHDOG)
                    .unwrap_or(false);
            if !register_is_fresh {
                rendezvous_register_in_flight = false;
                rendezvous_register_started_at = None;
            }
        }

        // Probe NAT when we already know an external IP (refine type), or when
        // Ember is on and we still lack one (STUN discovers the mapped address
        // so KAD-less HighID source publish can advertise a real IP).
        let want_nat_probe = (state.external_ip.is_some()
            || (settings.ember_native_enabled && state.external_ip.is_none()))
            && state.nat_info.nat_type == ember::nat::NatType::Unknown
            && !nat_probe_in_flight
            && mapping_probe_has_active_reason(&state)
            && nat_probe_backoff_until.is_none_or(|deadline| {
                tokio::time::Instant::now() >= deadline
            });
        if want_nat_probe {
            // This catch-all trigger (unlike the two dedicated "External IP
            // discovered via X — scheduling initial NAT probe" sites) had no
            // log line at all, making it indistinguishable from "never
            // fires" in normal logs. Needed to diagnose why nat_info stayed
            // Unknown all session despite external_ip being known early
            // (STUN keepalive's own 1:1 confirmation can set external_ip
            // before either of the other two trigger sites sees a
            // None->Some transition, silently skipping them).
            info!("NAT probe: external IP available — scheduling probe (catch-all trigger)");
            nat_probe_in_flight = true;
            nat_probe_started_at = Some(tokio::time::Instant::now());
            state.nat_probe_generation = state.nat_probe_generation.saturating_add(1);
            let reason = if state.external_ip.is_some() {
                "external IP available"
            } else {
                "ember needs STUN external IP"
            };
            nat_probe_packet_tx = Some(spawn_nat_probe(
                udp_socket.clone(),
                nat_probe_result_tx.clone(),
                state.nat_probe_generation,
                reason,
            ));
        }

        tokio::select! {
            // Background first-launch server.met download (must not block splash).
            result = async {
                match server_met_bootstrap_task.as_mut() {
                    Some(handle) => handle.await,
                    None => std::future::pending().await,
                }
            } => {
                server_met_bootstrap_task = None;
                match result {
                    Ok(Ok(data)) => {
                        match state.server_list.merge_from_bytes_filtered(
                            &data,
                            settings.filter_servers_by_ip,
                            Some(&mut state.ip_filter),
                        ) {
                            Ok(stats) => {
                                info!(
                                    "First-launch server.met: {} added, {} updated, {} filtered, {} dropped at capacity",
                                    stats.added, stats.updated, stats.filtered, stats.at_capacity
                                );
                                let met_path = state.data_dir.join("server.met");
                                spawn_save_server_met(&state.server_list, met_path.clone(), &state.server_met_save_generation, &state.server_met_save_lock);
                            }
                            Err(e) => {
                                warn!("Failed to parse downloaded server.met: {e}");
                                if pending_auto_connect_server {
                                    pending_auto_connect_server = false;
                                    emit_server_auto_connect_failed(
                                        &app_handle,
                                        "downloaded server.met could not be parsed",
                                    );
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        warn!(
                            "Failed to download server.met: {e} — server list remains empty \
                             (use Servers page to add servers or retry download)"
                        );
                        if pending_auto_connect_server {
                            pending_auto_connect_server = false;
                            emit_server_auto_connect_failed(
                                &app_handle,
                                "server.met download failed",
                            );
                        }
                    }
                    Err(e) => {
                        warn!("server.met bootstrap task failed: {e}");
                        if pending_auto_connect_server {
                            pending_auto_connect_server = false;
                            emit_server_auto_connect_failed(
                                &app_handle,
                                "server.met download task failed",
                            );
                        }
                    }
                }
            }

            // Incoming UDP packets: batch up to 20 per iteration so we re-check
            // commands and timers between batches
            result = udp_socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((len, from)) => {
                        if route_stun_binding_packet(
                            &mut nat_probe_packet_tx,
                            &mut udp_map_ka_packet_tx,
                            &udp_buf[..len],
                            from,
                        ) {
                            // STUN replies are consumed by the background NAT
                            // probe; keep the main loop as the only UDP
                            // receiver so normal KAD/Ember packets cannot be
                            // stolen by a concurrent recv task.
                        } else if settings.ember_native_enabled
                            && ember::transport::EmberTransport::is_ember_packet(&udp_buf[..len])
                        {
                            // Ember rides the KAD socket but skips
                            // `handle_udp_packet`, so the shared
                            // IP-filter/ban/rate-limit gate must run here.
                            if ember_udp_recv_allowed(&mut state, from) {
                                handle_ember_native_udp(
                                    &udp_socket,
                                    &udp_buf[..len],
                                    from,
                                    &mut state,
                                    &transfer_manager,
                                    &source_manager,
                                    &local_index,
                                    &db,
                                    &app_handle,
                                    &bandwidth_limiter,
                                ).await;
                            }
                        } else {
                            // Always dispatch: this handler owns eD2K peer UDP as
                            // well as KAD, and it gates the KAD half on connection
                            // state itself. Only the KAD accounting is conditional.
                            if state.stats.status != NetworkStatus::Disconnected {
                                last_kad_activity_at = chrono::Utc::now().timestamp();
                                stats_manager.add_overhead(
                                    crate::storage::statistics::OverheadCategory::Kad,
                                    crate::storage::statistics::OverheadDirection::Download,
                                    len as u64,
                                );
                            }
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
                                &transfer_manager,
                                &source_manager,
                                &known_files,
                                &bandwidth_limiter,
                            ).await;
                        }
                    }
                    Err(e) => {
                        debug!("UDP recv error: {e}");
                    }
                }
                // Process up to 19 more queued packets without re-entering select
                for _ in 0..19 {
                    match udp_socket.try_recv_from(&mut udp_buf) {
                        Ok((len, from)) => {
                            if route_stun_binding_packet(
                                &mut nat_probe_packet_tx,
                                &mut udp_map_ka_packet_tx,
                                &udp_buf[..len],
                                from,
                            ) {
                                // Routed to the active NAT probe.
                            } else if settings.ember_native_enabled
                                && ember::transport::EmberTransport::is_ember_packet(&udp_buf[..len])
                            {
                                // See the gate rationale on the first
                                // recv branch above — same fast-path
                                // bypass of `handle_udp_packet`.
                                if ember_udp_recv_allowed(&mut state, from) {
                                    handle_ember_native_udp(
                                        &udp_socket,
                                        &udp_buf[..len],
                                        from,
                                        &mut state,
                                        &transfer_manager,
                                        &source_manager,
                                        &local_index,
                                        &db,
                                        &app_handle,
                                        &bandwidth_limiter,
                                    ).await;
                                }
                            } else {
                                // See the first recv branch: dispatch regardless so
                                // eD2K peer UDP is served with KAD down, and gate
                                // only the KAD accounting.
                                if state.stats.status != NetworkStatus::Disconnected {
                                    last_kad_activity_at = chrono::Utc::now().timestamp();
                                    stats_manager.add_overhead(
                                        crate::storage::statistics::OverheadCategory::Kad,
                                        crate::storage::statistics::OverheadDirection::Download,
                                        len as u64,
                                    );
                                }
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
                                    &transfer_manager,
                                    &source_manager,
                                    &known_files,
                                    &bandwidth_limiter,
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
                    Some(NetworkCommand::Shutdown { deadline }) => {
                        shutdown_deadline = deadline;
                        shutdown_requested = true;
                        info!("Network shutting down");
                        // See the try_recv drain above: stop the upload listener
                        // before the shutdown save sequence runs.
                        state.uploads_halted_for_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
                        break;
                    }
                    None => {
                        info!("Network shutting down");
                        // See the try_recv drain above: stop the upload listener
                        // before the shutdown save sequence runs.
                        state.uploads_halted_for_shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
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
                        let old_channel_username = settings.channel_username.clone();
                        if apply_network_settings(
                            &mut state,
                            &mut settings,
                            new_settings,
                            &app_handle,
                        ) {
                            load_ipfilter_on_enable(&mut state).await;
                        }
                        publish_presence_under_new_username(
                            &udp_socket,
                            &mut state,
                            &db,
                            &settings,
                            &identity,
                            &old_channel_username,
                        )
                        .await;
                        state
                            .relay_manager
                            .lock()
                            .await
                            .set_policy(settings.relay_for_peers, settings.max_relay_sessions);
                        {
                            let mut nick = shared_nickname.write().await;
                            *nick = settings.nickname.clone();
                        }
                        source_manager
                            .write()
                            .await
                            .set_max_per_file(settings.max_sources_per_file);
                        if settings.filter_servers_by_ip {
                            apply_server_ip_filter(
                                &mut state,
                                &shared_server_addr,
                                &app_handle,
                                true,
                            )
                            .await;
                        }
                    }
                    Some(cmd) => {
                        handle_command(
                            &udp_socket,
                            cmd,
                            &mut state,
                            &local_index,
                            &fresh_part_hashes,
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
                            &shared_friends_only_hashes,
                            &shared_server_addr,
                            &shared_ember_payload,
                            &ember_payload_generation,
                            &geoip,
                            &friend_hashes,
                            &mutual_friend_hashes,
                            ember_hash,
                            &ul_event_tx,
                            ed25519_pubkey,
                            ed25519_secret_key,
                            &upload_queue_handle,
                            &transfer_status_writes,
                        ).await;
                    }
                }
            }

            // Download progress events
            Some(event) = dl_event_rx.recv() => {
                if let DownloadEvent::PartFileReady { ref transfer_id, ref file_hash, file_size, ref file_name } = event {
                    info!("Part file ready for {} ({}) — offering to server and publishing to KAD",
                        transfer_id, hex::encode(file_hash));
                    let restricted = {
                        let index = local_index.read().await;
                        !known_files.is_authoritative()
                            || hash16_is_friends_only(file_hash, &index, &known_files)
                    };
                    if !restricted {
                    // Skip if this hash already went out in the login dump or
                    // an earlier incremental offer. Re-sending it is a
                    // one-file republish; Lugdunum's penalty is for republish,
                    // not for a later new file (eMule SendFileToServer).
                    if state.server_connected && !state.offered_ed2k_hashes.contains(file_hash) {
                        let offer = vec![ed2k::server::OfferFile {
                            hash: *file_hash,
                            name: file_name.clone(),
                            size: file_size,
                            is_complete: false,
                            file_type: String::new(),
                        }];
                        let offer_tcp_port = advertised_tcp_port(&state);
                        let offered_ok = if let Some(conn) = state.server_connection.as_mut() {
                            match conn.offer_files(&offer, offer_tcp_port).await {
                                Ok(()) => true,
                                Err(e) => {
                                    debug!("Failed to offer new partial to server: {e}");
                                    false
                                }
                            }
                        } else {
                            false
                        };
                        if offered_ok {
                            record_offered_ed2k_hashes(&mut state, &offer);
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
                        keyword_publishable: false,
                        last_source_publish: known_files
                            .find_by_hash(file_hash)
                            .map(|r| r.last_publish_src as i64)
                            .unwrap_or(0),
                    });
                    }
                }
                if let DownloadEvent::Completed {
                    ref transfer_id,
                    ref final_path,
                    part_hashes: ref event_part_hashes,
                    ..
                } = event
                {
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
                                        map.retain(|(h, _), _| *h != fh);
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
                    // Snapshot only the fields we need, then release the
                    // `transfer_manager` read lock immediately. The rest of
                    // this handler runs several `.await`s (source_manager
                    // read, local_index write/read, shared_files write, and a
                    // server `offer_files` network round-trip). Holding the
                    // read lock across them previously stalled the whole
                    // network `select!` loop and blocked download workers that
                    // need `transfer_manager.write()`.
                    let completed_snapshot = {
                        let mgr = transfer_manager.read().await;
                        mgr.get_transfer(transfer_id).map(|t| (
                            t.peer_id.clone(),
                            t.file_hash.clone(),
                            t.file_name.clone(),
                            t.total_size,
                            t.transferred,
                        ))
                    };
                    if let Some((peer_id, file_hash, file_name, file_size, _transferred)) = completed_snapshot {
                        if let Some((ip_str, port_str)) = peer_id.split_once(':') {
                            if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                                state.dead_sources.remove(0, u32::from(ip), port);
                            }
                        }
                        // Clear all per-file dead source entries for this completed file
                        if let Ok(fh_bytes) = hex::decode(&file_hash) {
                            if fh_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&fh_bytes);
                                let sm = source_manager.read().await;
                                for (ip, port) in sm.get_sources(&fh) {
                                    state.dead_sources.remove_for_file(&fh, u32::from(ip), port);
                                }
                            }
                        }
                        let sanitized_name = crate::security::sanitize_filename(&file_name);
                        let default_completed_path = PathBuf::from(&settings.download_folder)
                            .join("Downloads")
                            .join(&sanitized_name);
                        // The transfer owns final-name claiming and may choose a
                        // deduplicated path. Using a reconstructed default path
                        // here creates a second transient LocalIndex row when the
                        // file watcher observes the actual path.
                        let completed_path = final_path
                            .as_deref()
                            .filter(|path| !path.is_empty())
                            .map(PathBuf::from)
                            .unwrap_or_else(|| default_completed_path.clone());
                        let completed_name = completed_path
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .filter(|name| !name.is_empty())
                            .unwrap_or(sanitized_name);
                        let now = chrono::Utc::now().timestamp();

                        if let Ok(hash_bytes) = hex::decode(&file_hash) {
                            if hash_bytes.len() == 16 {
                                let mut fh = [0u8; 16];
                                fh.copy_from_slice(&hash_bytes);
                                use crate::storage::known_files::KnownFileRecord;
                                let existing = known_files.find_by_hash(&fh).cloned();
                                // Prefer the hashset already verified during
                                // the transfer, then a valid cached set, before
                                // re-reading the completed file.
                                let part_hashes = if !event_part_hashes.is_empty() {
                                    event_part_hashes.clone()
                                } else if existing.as_ref().is_some_and(|record| {
                                    record.part_hashes.len()
                                        == ed2k::hash::ed2k_known_met_part_hash_count(file_size)
                                }) {
                                    existing
                                        .as_ref()
                                        .map(|record| record.part_hashes.clone())
                                        .unwrap_or_default()
                                } else {
                                    // Recompute off the loop and fold it in
                                    // when it lands, exactly as the BLAKE3
                                    // digest below does. Awaiting a sequential
                                    // end-to-end read of a multi-GB file here
                                    // suspended the whole `select!` — no UDP
                                    // receive, no timers, no command handling —
                                    // on every completion that arrives without
                                    // a hashset (callback and single-source
                                    // downloads, and restore re-verification).
                                    let hash_path = completed_path.clone();
                                    let hashset_tx = part_hashset_result_tx.clone();
                                    tokio::task::spawn_blocking(move || {
                                        // Another whole-file read the library
                                        // scheduler would otherwise not see. It
                                        // rations reads per physical drive, and
                                        // this one lands on the same spindle a
                                        // scan may be working through.
                                        let _drive_busy =
                                            crate::sharing::disk::note_external_read(&hash_path);
                                        if let Ok(hashes) =
                                            ed2k::hash::ed2k_part_hashes_file(&hash_path)
                                        {
                                            if !hashes.is_empty() {
                                                let _ = hashset_tx.send((fh, hashes));
                                            }
                                        }
                                    });
                                    Vec::new()
                                };
                                let record = KnownFileRecord {
                                    file_hash: fh,
                                    part_hashes,
                                    file_name: completed_name.clone(),
                                    file_size,
                                    file_path: completed_path.to_string_lossy().to_string(),
                                    aich_hash: existing
                                        .as_ref()
                                        .map(|record| record.aich_hash.clone())
                                        .unwrap_or_default(),
                                    ember_file_hash: {
                                        // Prefer a digest verified/learned this
                                        // session, then any prior known.met value,
                                        // then compute BLAKE3 of the completed
                                        // file so deep-link / paste downloads
                                        // still get content integrity for share.
                                        let ember_hex = state
                                            .ember_content_hashes
                                            .get(&fh)
                                            .map(|pin| pin.digest)
                                            .filter(|d| *d != [0u8; 32])
                                            .map(hex::encode)
                                            .or_else(|| {
                                                existing.as_ref().and_then(|record| {
                                                    if record.ember_file_hash.is_empty() {
                                                        None
                                                    } else {
                                                        Some(record.ember_file_hash.clone())
                                                    }
                                                })
                                            })
                                            .unwrap_or_default();
                                        if ember_hex.is_empty() {
                                            // Compute it off the loop and fold
                                            // it in when it lands. Awaiting the
                                            // hash here suspended the whole
                                            // `select!` for as long as it took
                                            // to read the file end to end — no
                                            // UDP receive, no timers, no
                                            // command handling, on every plain
                                            // eD2K completion (the fallback is
                                            // the common case: only an Ember
                                            // DHT hit or a prior known.met
                                            // record fills the field above).
                                            let hash_path = completed_path.clone();
                                            let digest_tx = ember_digest_result_tx.clone();
                                            tokio::task::spawn_blocking(move || {
                                                if let Ok(digest) =
                                                    crate::network::ember::crypto::blake3_hash_file_path(
                                                        &hash_path,
                                                    )
                                                {
                                                    let _ = digest_tx.send((fh, digest));
                                                }
                                            });
                                        }
                                        ember_hex
                                    },
                                    modified_at: now,
                                    // The dropped `_transferred` field on the
                                    // completed-download snapshot is this
                                    // transfer's *downloaded* byte count, not
                                    // anything uploaded. Seeding
                                    // all_time_transferred with it (as this code
                                    // used to) credited every freshly-downloaded,
                                    // auto-shared file with a full-file-size
                                    // "upload" the moment it finished
                                    // downloading, even with zero real uploads —
                                    // inflating the Library's Top Uploads panel
                                    // for every completed download. Only ever
                                    // preserve a pre-existing record's real
                                    // upload total (e.g. re-downloading
                                    // previously-shared content); a genuinely new
                                    // hash starts at 0 and accumulates only
                                    // through real upload events (see
                                    // `add_all_time_transferred`).
                                    all_time_transferred: existing
                                        .as_ref()
                                        .map(|record| record.all_time_transferred)
                                        .unwrap_or(0),
                                    all_time_requested: existing
                                        .as_ref()
                                        .map(|record| record.all_time_requested)
                                        .unwrap_or(0),
                                    all_time_accepted: existing
                                        .as_ref()
                                        .map(|record| record.all_time_accepted)
                                        .unwrap_or(0),
                                    upload_priority: existing
                                        .as_ref()
                                        .map(|record| record.upload_priority)
                                        .unwrap_or_else(|| {
                                            crate::storage::known_files::priority_str_to_u8(
                                                "normal",
                                            )
                                        }),
                                    last_publish_src: existing
                                        .as_ref()
                                        .map(|record| record.last_publish_src)
                                        .unwrap_or(0),
                                    last_shared: existing
                                        .as_ref()
                                        .map(|record| record.last_shared)
                                        .unwrap_or(0),
                                    is_shared: crate::storage::share_intent::effective_shared(
                                        &fh,
                                        existing
                                            .as_ref()
                                            .map(|record| record.is_shared)
                                            .unwrap_or(true),
                                    ),
                                    // Re-downloading content the user had
                                    // restricted to friends must not quietly
                                    // republish it to the open network.
                                    friends_only: existing
                                        .as_ref()
                                        .map(|record| record.friends_only)
                                        .unwrap_or(false),
                                    complete_sources: existing
                                        .as_ref()
                                        .map(|record| record.complete_sources)
                                        .unwrap_or(0),
                                    last_ember_source_publish: existing
                                        .as_ref()
                                        .map(|record| record.last_ember_source_publish)
                                        .unwrap_or(0),
                                    last_ember_keyword_publish: existing
                                        .as_ref()
                                        .map(|record| record.last_ember_keyword_publish)
                                        .unwrap_or(0),
                                    media: existing.as_ref().and_then(|r| r.media.clone()),
                                    media_scanned: existing
                                        .as_ref()
                                        .is_some_and(|r| r.media_scanned),
                                };
                                let completed_friends_only = record.friends_only;
                                known_files.add_or_update(record.clone());

                                // Auto-share completed download (eMule: CPartFile::PerformFileCompleteEnd)
                                let ext = completed_path.extension()
                                    .map(|e| e.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                let folder = completed_path.parent()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                let shared_file = FileInfo {
                                    id: file_hash.clone(),
                                    name: completed_name,
                                    path: completed_path.to_string_lossy().to_string(),
                                    size: file_size,
                                    hash: file_hash,
                                    aich_hash: record.aich_hash.clone(),
                                    ember_file_hash: record.ember_file_hash.clone(),
                                    extension: ext,
                                    modified_at: now,
                                    priority: existing
                                        .as_ref()
                                        .map(|record| {
                                            crate::storage::known_files::priority_u8_to_str(
                                                record.upload_priority,
                                            )
                                            .to_string()
                                        })
                                        .unwrap_or_else(|| "normal".to_string()),
                                    requests: 0,
                                    accepted: 0,
                                    bytes_transferred: 0,
                                    alltime_requests: existing
                                        .as_ref()
                                        .map(|record| record.all_time_requested)
                                        .unwrap_or(0),
                                    alltime_accepted: existing
                                        .as_ref()
                                        .map(|record| record.all_time_accepted)
                                        .unwrap_or(0),
                                    alltime_transferred: existing
                                        .as_ref()
                                        .map(|record| record.all_time_transferred)
                                        .unwrap_or(0),
                                    complete_sources: existing
                                        .as_ref()
                                        .map(|record| record.complete_sources)
                                        .unwrap_or(0),
                                    folder,
                                    shared: crate::storage::share_intent::effective_shared(
                                        &fh,
                                        existing
                                            .as_ref()
                                            .map(|record| record.is_shared)
                                            .unwrap_or(true),
                                    ),
                                    friends_only: completed_friends_only,
                                    shared_kad: false,
                                    shared_ed2k: false,
                                    shared_ember: false,
                                };
                                let shared_file = {
                                    let mut index = local_index.write().await;
                                    // Clean up the old reconstructed-default row
                                    // only when it is an on-disk orphan carrying
                                    // this exact completed hash/size. A pending
                                    // or merely same-named row is not proof that
                                    // it represents this physical completion.
                                    if default_completed_path != completed_path
                                        && !default_completed_path.exists()
                                    {
                                        let default_path =
                                            default_completed_path.to_string_lossy().to_string();
                                        let is_proven_orphan = index
                                            .get_by_path(&default_path)
                                            .is_some_and(|file| {
                                                file.hash.eq_ignore_ascii_case(&shared_file.hash)
                                                    && file.size == shared_file.size
                                            });
                                        if is_proven_orphan {
                                            index.remove_file_by_path(&default_path);
                                        }
                                    }
                                    // Always upsert. LocalIndex preserves
                                    // runtime/shared flags from an existing
                                    // same-path (including pending) row.
                                    index.add_file(shared_file.clone());
                                    index
                                        .get_by_path(&shared_file.path)
                                        .cloned()
                                        .unwrap_or(shared_file)
                                };
                                {
                                    let mut snap = local_index.read().await.all_files().to_vec();
                                    let kad_connected =
                                        state.stats.status == NetworkStatus::Connected;
                                    let kad_published =
                                        state.publish_manager.source_published_md4_hashes();
                                    apply_publish_badges(
                                        &mut snap,
                                        kad_connected,
                                        state.server_connected,
                                        settings.ember_native_enabled
                                            && state.ember_dht.routing().verified_len() > 0,
                                        &kad_published,
                                        &state.offered_ed2k_hashes,
                                        &state.ember_published_sources,
                                    );
                                    *shared_files.write().await = snap;
                                }

                                if kad_may_advertise_complete(
                                    &shared_file,
                                    &known_files,
                                    &{
                                        let index = local_index.read().await;
                                        collect_friends_only_hashes(&index, &known_files)
                                    },
                                ) {
                                    // Publish to KAD
                                    state.publish_manager.add_file(PublishableFile {
                                        file_hash: md4_bytes_to_kad_id(&hash_bytes[..16]),
                                        file_name: shared_file.name.clone(),
                                        file_size: shared_file.size,
                                        file_type: crate::search::index::infer_file_type(&shared_file.extension),
                                        complete_sources: shared_file.complete_sources,
                                        keyword_publishable: true,
                                        last_source_publish: {
                                            let mut raw = [0u8; 16];
                                            raw.copy_from_slice(&hash_bytes[..16]);
                                            known_files
                                                .find_by_hash(&raw)
                                                .map(|r| r.last_publish_src as i64)
                                                .unwrap_or(0)
                                        },
                                    });

                                    // Offer to eD2K server
                                    if state.server_connected {
                                        let offer = vec![ed2k::server::OfferFile {
                                            hash: fh,
                                            name: shared_file.name.clone(),
                                            size: shared_file.size,
                                            is_complete: true,
                                            file_type: String::new(),
                                        }];
                                        let offer_tcp_port = advertised_tcp_port(&state);
                                        let offered_ok =
                                            if let Some(conn) = state.server_connection.as_mut() {
                                                match conn.offer_files(&offer, offer_tcp_port).await
                                                {
                                                    Ok(()) => true,
                                                    Err(e) => {
                                                        debug!("Failed to offer completed download to server: {e}");
                                                        false
                                                    }
                                                }
                                            } else {
                                                false
                                            };
                                        if offered_ok {
                                            record_offered_ed2k_hashes(&mut state, &offer);
                                        }
                                    }
                                }

                                let _ = app_handle.emit("shared-files-changed", serde_json::json!({
                                    "phase": "download-complete",
                                    "count": 1,
                                }));
                                info!(
                                    "Indexed completed download: {} (shared={})",
                                    file_name, shared_file.shared
                                );

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
                                            if let Err(error) =
                                                persist_aich_cache_entry(&cache_path, fh, hs.root_hash)
                                            {
                                                tracing::warn!(
                                                    "Failed to persist AICH cache entry: {error}"
                                                );
                                            }
                                            tracing::info!("Computed AICH root for completed download: {aich_hex}");
                                            if let Err(e) = aich_tx.try_send(hs) {
                                                tracing::warn!("AICH hash-set queue full/closed, hash set not stored: {e}");
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
                    let failure_code = ed2k::transfer::classify_failure(error, failure_kind);
                    let failure_summary = failure_code.message();

                    // Prefer is_user_cancel_error for source-failure classification;
                    // also honour an already-cancelled control (cancel race).
                    // `settled_by_user` covers the rest of the same story: Pause
                    // and Stop cancel the control, which tears the part writer
                    // down under any in-flight write and surfaces here as a
                    // source failure. The row is already Paused/Stopped by the
                    // IPC command, so labelling its source as failed is noise
                    // about a teardown the user asked for. The status guards
                    // further down already keep the *transfer* out of Failed;
                    // this keeps the label off the row too.
                    let (is_user_cancel, peer_id_str, settled_by_user) = {
                        let mgr = transfer_manager.read().await;
                        let t = mgr.get_transfer(transfer_id);
                        (
                            ed2k::transfer::is_user_cancel_error(error)
                                || mgr.is_control_cancelled(transfer_id),
                            t.map(|t| t.peer_id.clone()).unwrap_or_default(),
                            t.is_some_and(|t| matches!(
                                t.status,
                                TransferStatus::Paused
                                    | TransferStatus::Stopped
                                    | TransferStatus::Insufficient
                                    | TransferStatus::Completed
                            )),
                        )
                    };

                    if !is_user_cancel && !settled_by_user {
                        let _ = app_handle.emit("transfer:source-failed", serde_json::json!({
                            "transfer_id": transfer_id,
                            "source": peer_id_str,
                            "stage": &failure_stage,
                            "kind": &failure_kind_name,
                            "reason": failure_summary,
                            "reason_code": failure_code.as_code(),
                        }));
                    }

                    // Dead source marking for individual sources is handled by
                    // SourceDetail "failed" events (which carry the actual IP/port).
                    // For single-source downloads that set peer_id, apply a
                    // belt-and-suspenders mark here as well.
                    {
                        // Sources retired below are also dropped from the
                        // registry, which is what makes the count honest — see
                        // `retire_dead_source_from_registry`. Collected while the
                        // manager lock is held and applied after it is released.
                        let mut retire: Option<([u8; 16], Ipv4Addr, u16)> = None;
                        let mgr = transfer_manager.read().await;
                        if let Some(t) = mgr.get_transfer(transfer_id) {
                            if let Some((ip_str, port_str)) = t.peer_id.split_once(':') {
                                if let (Ok(ip), Ok(port)) = (ip_str.parse::<Ipv4Addr>(), port_str.parse::<u16>()) {
                                    if *failure_kind == SourceFailureKind::Permanent {
                                        // The block time follows the *source's*
                                        // reachability, not ours — see
                                        // `add_dead_source`.
                                        let src_fw = state
                                            .per_file_sources
                                            .get(transfer_id)
                                            .is_some_and(|pfs| pfs.source_is_firewalled(ip, port, None));
                                        state.dead_sources.add_dead_source(0, u32::from(ip), port, src_fw);
                                        if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                            if fh_bytes.len() == 16 {
                                                let mut fh = [0u8; 16];
                                                fh.copy_from_slice(&fh_bytes);
                                                state.dead_sources.add_dead_source_for_file(fh, u32::from(ip), port);
                                                retire = Some((fh, ip, port));
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
                        if let Some((fh, ip, port)) = retire {
                            retire_dead_source_from_registry(&source_manager, &fh, ip, port).await;
                        }
                    }

                    // eMule-style: downloads never auto-fail. Re-queue for source
                    // retry unless the user explicitly cancelled — or the local
                    // disk is full (Insufficient), which is transfer-level —
                    // or the Ember BLAKE3 pin missed. That last one is also
                    // transfer-level: the ed2k parts already matched, so
                    // searching more sources cannot change the digest.
                    // `is_user_cancel` was resolved above, before the
                    // `transfer:source-failed` emit it also gates.
                    let is_disk_full = *failure_kind == SourceFailureKind::InsufficientDisk
                        || ed2k::transfer::is_disk_full_error(error);
                    let is_ember_pin_fail = ed2k::transfer::is_ember_blake3_mismatch(error)
                        || failure_code
                            == ed2k::transfer::TransferFailureCode::EmberContentHashMismatch;
                    let is_aich_pin_fail = ed2k::transfer::is_expected_aich_mismatch(error)
                        || failure_code == ed2k::transfer::TransferFailureCode::AichHashMismatch;
                    if (is_ember_pin_fail || is_aich_pin_fail) && !is_user_cancel {
                        state.pending_downloads.remove(transfer_id);
                        // A remote-derived digest that fails the content check is
                        // worse than no digest at all: every later start for this
                        // hash re-reads it from the map, so the file can never
                        // complete however many honest sources turn up, and the
                        // ed2k/AICH hashes that *did* match count for nothing.
                        // Drop it so a better-corroborated walk — or an explicit
                        // click — can pin again. A digest computed from local
                        // bytes stays: that one is evidence the downloaded bytes
                        // are wrong, not evidence the pin is.
                        if is_ember_pin_fail {
                            let file_hash = {
                                let mgr = transfer_manager.read().await;
                                mgr.get_transfer(transfer_id)
                                    .and_then(|t| hex::decode(&t.file_hash).ok())
                                    .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
                            };
                            if let Some(fh) = file_hash {
                                let remote_pin = state
                                    .ember_content_hashes
                                    .get(&fh)
                                    .is_some_and(|pin| {
                                        pin.provenance != EmberDigestProvenance::Local
                                    });
                                if remote_pin {
                                    state.ember_content_hashes.remove(&fh);
                                    warn!(
                                        "Cleared unverifiable Ember digest pin for {} after a content mismatch",
                                        hex::encode(fh)
                                    );
                                }
                            }
                        }
                        info!(
                            "{} pin failed for {transfer_id} — not re-queuing",
                            if is_ember_pin_fail { "Ember BLAKE3" } else { "AICH" }
                        );
                    } else if is_disk_full && !is_user_cancel {
                        let file_name = {
                            let mgr = transfer_manager.read().await;
                            mgr.get_transfer(transfer_id)
                                .map(|t| t.file_name.clone())
                                .unwrap_or_default()
                        };
                        state.pending_downloads.remove(transfer_id);
                        let freed_slots = mark_download_insufficient(
                            &transfer_manager,
                            &db,
                            &app_handle,
                            transfer_id,
                            &file_name,
                            &transfer_status_writes,
                        )
                        .await;
                        // Start any downloads promoted into the freed concurrent
                        // slots before continuing (T2).
                        for t in freed_slots {
                            crate::commands::transfers::emit_transfer_status(
                                &app_handle,
                                &t.id,
                                &t.status,
                            );
                            let control =
                                reregister_transfer_control(&transfer_manager, &t.id).await;
                            handle_command(
                                &udp_socket,
                                NetworkCommand::StartDownload {
                                    file_hash: t.file_hash.clone(),
                                    file_name: t.file_name.clone(),
                                    file_size: t.total_size,
                                    peer_ip: t
                                        .peer_id
                                        .split(':')
                                        .next()
                                        .unwrap_or("")
                                        .to_string(),
                                    peer_port: t
                                        .peer_id
                                        .split(':')
                                        .nth(1)
                                        .and_then(|p| p.parse().ok())
                                        .unwrap_or(0),
                                    extra_sources: Vec::new(),
                                    ember_file_hash: t.ember_file_hash.clone().unwrap_or_default(),
                                    expected_aich: t.expected_aich.clone(),
                                    transfer_id: t.id.clone(),
                                    control,
                                    discovery_only: false,
                                    friend_ember_hash: None,
                                },
                                &mut state,
                                &local_index,
                                &fresh_part_hashes,
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
                                &shared_friends_only_hashes,
                                &shared_server_addr,
                                &shared_ember_payload,
                                &ember_payload_generation,
                                &geoip,
                                &friend_hashes,
                                &mutual_friend_hashes,
                                ember_hash,
                                &ul_event_tx,
                                ed25519_pubkey,
                                ed25519_secret_key,
                                &upload_queue_handle,
                                &transfer_status_writes,
                            )
                            .await;
                        }
                        // Must not fall through to handle_download_event →
                        // fail()/transfer-failed, which would overwrite the
                        // resumable Insufficient state as Failed.
                        continue;
                    } else {
                    // Re-queue all non-cancel failures (including final-hash
                    // mismatch after part reopen) so recovery can continue.
                    if !is_user_cancel {
                        let transfer_info = {
                            let mgr = transfer_manager.read().await;
                            mgr.get_transfer(transfer_id).cloned()
                        };
                        if let Some(t) = transfer_info {
                            // Pause/Stop/Insufficient must not be undone by a
                            // late Failed requeue (T1/T3).
                            //
                            // `Completed`/`Failed` belong here for the reason the
                            // `Failed` arm of `handle_download_event` documents: a
                            // worker that raced completion must not persist a
                            // failure for a download whose bytes verified. That
                            // guard cannot help us — this block ends in `continue`,
                            // so it is never reached. Without these two states a
                            // late duplicate `Failed` wrote `failure_reason` and a
                            // "Retrying after …" health onto the terminal row
                            // (`get_transfer_mut` searches `completed` too),
                            // re-registered a control `complete()` had removed,
                            // re-inserted a pending entry that can never start, and
                            // queued a `"searching"` status write whose sequence is
                            // NEWER than the completion write — so the DB row
                            // regressed from `completed` and the finished file was
                            // re-downloaded on the next launch.
                            if matches!(
                                t.status,
                                TransferStatus::Paused
                                    | TransferStatus::Stopped
                                    | TransferStatus::Insufficient
                                    | TransferStatus::Completed
                                    | TransferStatus::Failed
                            ) {
                                continue;
                            }
                            let control = TransferControl::new();
                            let health_update = {
                                let mut mgr = transfer_manager.write().await;
                                // Re-check under write lock — status can flip
                                // between the read above and here.
                                let blocked = mgr.get_transfer(transfer_id).is_some_and(|row| {
                                    matches!(
                                        row.status,
                                        TransferStatus::Paused
                                            | TransferStatus::Stopped
                                            | TransferStatus::Insufficient
                                            | TransferStatus::Completed
                                            | TransferStatus::Failed
                                    )
                                });
                                if blocked {
                                    None
                                } else {
                                    if let Some(active_t) = mgr.active.get_mut(transfer_id) {
                                        active_t.status = TransferStatus::Searching;
                                        active_t.speed = 0;
                                    }
                                    mgr.set_failure_context(
                                        transfer_id,
                                        Some(failure_code),
                                        Some(failure_kind_name.clone()),
                                        Some(failure_stage.clone()),
                                    );
                                    let update = mgr.set_retrying_after(transfer_id, failure_code);
                                    mgr.register_control(transfer_id, control.clone());
                                    Some(update)
                                }
                            };
                            let Some(health_update) = health_update else {
                                continue;
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
                            insert_pending_download_bounded(&mut state.pending_downloads, transfer_id.clone(), PendingDownload {
                                transfer_id: transfer_id.clone(),
                                file_hash: t.file_hash.clone(),
                                file_name: t.file_name.clone(),
                                file_size: t.total_size,
                                expected_aich: t.expected_aich.clone(),
                                control,
                                search_count: prev_search_count.saturating_add(1),
                                last_search_at: 0,
                                priority: priority_str_to_u32(&t.priority),
                            });
                            info!("Re-queued failed download {} for source retry: {}", transfer_id, error);
                            spawn_transfer_status_write(
                                &transfer_status_writes,
                                db.clone(),
                                transfer_id.clone(),
                                "searching",
                            );

                            let _ = app_handle.emit("transfer-status", serde_json::json!({
                                "id": transfer_id,
                                "status": "searching",
                                "failure_reason": failure_summary,
                                "failure_code": failure_code.as_code(),
                                "failure_kind": failure_kind_name,
                                "failure_stage": failure_stage,
                                "health": "degraded",
                                "health_reason": TransferHealthCode::retrying_after(failure_code),
                                "health_code": TransferHealthCode::RetryingAfter.as_code(),
                            }));
                            continue;
                        }
                    }
                    if is_user_cancel {
                        // cancel_transfer / CancelDownload already removed the
                        // row and recorded history as "cancelled". Falling
                        // through would emit transfer-failed and paint the
                        // download bar red for a moment before the UI drops it.
                        continue;
                    }
                    } // end else (!is_disk_full)
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
                if let DownloadEvent::EmberSources { ref transfer_id, ref entries, ref aich_roots, ref ember_peers, ref relay_attestations, from_ember_hash } = event {
                    let we_are_unreachable = state.firewalled || state.low_id;
                    handle_epx_sources(&mut state, &transfer_manager, &source_manager, &local_index, entries, aich_roots, ember_peers, relay_attestations, from_ember_hash, &format!("download {transfer_id}"), false, we_are_unreachable).await;
                }

                if let DownloadEvent::EmberPeerDiscovered { ip, tcp_port, udp_port } = event {
                    // A live eD2K session is an introduction. Do not apply
                    // `block_private_ips` here — that would hide a LAN 1.5.x
                    // neighbour from Ember DHT even though TCP already accepted it.
                    note_connected_ember_peer(
                        &udp_socket,
                        &mut state,
                        settings.ember_native_enabled,
                        ip,
                        tcp_port,
                        udp_port,
                    )
                    .await;
                }

                if let DownloadEvent::FriendSeen { ember_hash: friend_eh, ip, port } = event {
                    // FriendSeen is only emitted post-PoP for a peer that was a
                    // friend at emit time, but a concurrent removal can race the
                    // event. Don't resurrect a just-removed friend as "online"
                    // or proactively re-dial them.
                    if !friend_hashes.read().await.contains(&friend_eh) {
                        continue;
                    }
                    // The inbound counterpart to the ask on `EmberFriendConnected`:
                    // a friend that dialled us never raises that event, and a
                    // starved node should not wait out a 60s tick for the one
                    // bootstrap path that does not need their UDP port.
                    if settings.ember_native_enabled {
                        ask_friends_for_ember_contacts(&mut state).await;
                    }
                    let hash_hex = hex::encode(friend_eh);
                    let now = chrono::Utc::now().timestamp();
                    state.online_friends.insert(friend_eh, now);
                    state.friend_reconnect_last.remove(&friend_eh);
                    let ip_str = match ip { std::net::IpAddr::V4(v4) => v4.to_string(), std::net::IpAddr::V6(v6) => v6.to_string() };
                    let db2 = db.clone();
                    let h2 = hash_hex.clone();
                    let ip2 = ip_str.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                            warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
                        }
                    });
                    // `FriendSeen` now carries the peer's Hello listen port
                    // (not the connection's ephemeral socket port — see the
                    // emission sites in multi_source.rs/transfer.rs), so it's
                    // safe to reseed download sources from it too.
                    if let std::net::IpAddr::V4(v4) = ip {
                        reseed_friend_endpoint(
                            &mut state,
                            &source_manager,
                            &credit_manager,
                            &transfer_manager,
                            friend_eh,
                            None,
                            v4,
                            port,
                        )
                        .await;
                    }
                    let _ = app_handle.emit("ember:friend-online", serde_json::json!({
                        "user_hash": hash_hex,
                        "ip": ip_str,
                        "port": port,
                    }));
                    if !state.ember_sessions.read().await.get(&friend_eh).is_some_and(|h| h.is_fresh())
                        && !state.outbound_session_tasks.contains_key(&friend_eh)
                    {
                        if let std::net::IpAddr::V4(v4) = ip {
                            state.outbound_session_tasks.insert(friend_eh, std::time::Instant::now());
                            let our_uh = state.user_hash;
                            let our_eh = ember_hash;
                            let nick = settings.nickname.clone();
                            let cid = state.external_ip.map(|eip| u32::from_le_bytes(eip.octets())).unwrap_or(0);
                            let tcp = advertised_tcp_port(&state);
                            let udp = advertised_udp_port(&state);
                            let obfs = settings.friend_session_encryption;
                            let sess = state.ember_sessions.clone();
                            let offline = state.user_offline.clone();
                            let ultx = ul_event_tx.clone();
                            let fh = friend_hashes.clone();
                            let friend_addr = SocketAddr::new(v4.into(), port);
                            info!("Proactively opening friend session to {} at {}", hex::encode(friend_eh), friend_addr);
                            let ultx2 = ul_event_tx.clone();
                            // NAT-fallback context — see `spawn_rendezvous_friend_lookup`'s
                            // identical capture for why a plain TCP-only dial isn't enough.
                            let rv_url = settings.rendezvous_url.clone();
                            let nat_ctx = state.friend_nat_context.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ed2k::friend_connect::connect_friend_with_fallback(
                                    friend_addr, friend_eh, our_uh, our_eh, nick,
                                    cid, tcp, udp, obfs, sess, offline, ultx, fh,
                                    Some(ed25519_pubkey), Some(ed25519_secret_key),
                                    rv_url, nat_ctx,
                                ).await {
                                    info!("Proactive friend session to {} failed: {e}", hex::encode(friend_eh));
                                    let _ = ultx2.send(upload_server::UploadEvent {
                                        transfer_id: String::new(),
                                        kind: upload_server::UploadEventKind::EmberFriendSearchFailed { ember_hash: friend_eh },
                                    }).await;
                                }
                            });
                        }
                    }
                    continue;
                }

                if let DownloadEvent::EmberFriendRequest {
                    ember_hash,
                    pubkey,
                    nickname,
                    peer_ip,
                    peer_port,
                    verified,
                } = event
                {
                    // File-transfer sockets (the downloader's side of an
                    // upload) are how Add Friend on the uploads pane
                    // delivers `OP_EMBER_FRIEND_REQ` when the peer is
                    // firewalled and FindFriendAndConnect cannot dial
                    // back. `verified` is PoP/Noise; unverified *strangers*
                    // still queue with the unverified badge. Reciprocal
                    // accepts from someone we already added auto-confirm
                    // when verified and are ignored when not.
                    process_inbound_friend_request(
                        &db,
                        &app_handle,
                        &mut state.online_friends,
                        &mutual_friend_hashes,
                        ember_hash,
                        pubkey,
                        &nickname,
                        &peer_ip,
                        peer_port,
                        verified,
                    )
                    .await;
                    continue;
                }

                if let DownloadEvent::EmberChatMessage { ember_hash, .. } = event {
                    debug!(
                        "Dropping unbound chat event from generic download connection for {}",
                        hex::encode(ember_hash)
                    );
                    continue;
                }

                if let DownloadEvent::EmberBrowseResponse {
                    ember_hash,
                    ref entries,
                } = event
                {
                    // Browse requests are dispatched only over a canonical
                    // friend session. A generic download connection has no
                    // session generation, so accepting its response could
                    // reintroduce cross-reconnect mis-correlation.
                    debug!(
                        "Ignoring unbound browse response from download connection for {} ({} entries)",
                        hex::encode(ember_hash),
                        entries.len()
                    );
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
                                // `v4` at this call site always comes from an active
                                // per-source connection worker (see `DownloadEvent::
                                // SourceDetail`'s emitters), which by construction
                                // requires a real, dialable IP — never the identity-only
                                // `UNSPECIFIED` placeholder rows KAD/server LowID
                                // publishes create — so `None` here can't collide with
                                // an unrelated peer's row (see `PerFileSourceList::
                                // resolve_idx`).
                                "connecting" => pfs.set_connecting(v4, port, None),
                                "queued" => pfs.set_on_queue(v4, port, *queue_rank, None),
                                "queue_full" => pfs.set_on_queue(v4, port, None, None),
                                // Slot granted, waiting on the first block —
                                // eMule is already DS_DOWNLOADING here.
                                "stalled" | "transferring" => pfs.set_downloading(v4, port, None),
                                "completed" => {}
                                "failed" => {
                                    if state.banned_ips.contains(&v4) {
                                        pfs.set_banned(v4, port, None);
                                    } else {
                                        let penalty = match failure_kind {
                                            Some(SourceFailureKind::Transient) => 1,
                                            Some(SourceFailureKind::DownloadTimeout) => 2,
                                            Some(SourceFailureKind::Permanent) => 4,
                                            // Disk-full is transfer-level, not a peer fault —
                                            // don't punish the source.
                                            Some(SourceFailureKind::InsufficientDisk) => 0,
                                            None => 1,
                                        };
                                        pfs.set_failed_with_penalty(v4, port, penalty, None);
                                    }
                                }
                                "no_needed_parts" => pfs.set_none_needed_parts(v4, port, None),
                                "parts_busy" => pfs.set_parts_busy(v4, port, None),
                                "duplicate" => pfs.clear_duplicate_route(v4, port, None),
                                "too_many_conns" => pfs.set_too_many_conns(v4, port, None),
                                _ => {}
                            }
                        }
                    }

                    // Soft defer only — do not push a Failed row into the UI.
                    if status == "parts_busy" {
                        continue;
                    }

                    if status == "failed" {
                        let failure_kind_name = match failure_kind {
                            Some(SourceFailureKind::Permanent) => "permanent",
                            Some(SourceFailureKind::DownloadTimeout) => "timeout",
                            Some(SourceFailureKind::InsufficientDisk) => "insufficient_disk",
                            Some(SourceFailureKind::Transient) | None => "transient",
                        };
                        let _ = app_handle.emit("transfer:source-failed", serde_json::json!({
                            "transfer_id": transfer_id,
                            "source": format!("{}:{}", ip, port),
                            "kind": failure_kind_name,
                        }));
                        // Before writing this source off, check whether it is
                        // the friend this download came from. A friend behind
                        // NAT can't be dialed but can dial us, and asking them
                        // over their friend session needs no eD2K server, no
                        // KAD buddy, and no HighID on either side — so a friend
                        // transfer no longer depends on ID status the way the
                        // callback paths below do.
                        let friend_escalated = if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                            maybe_escalate_to_friend_transfer(
                                &mut state,
                                &transfer_manager,
                                &credit_manager,
                                &friend_hashes,
                                &pending_kad_callbacks,
                                &app_handle,
                                transfer_id,
                                v4,
                                port,
                            )
                            .await
                        } else {
                            false
                        };
                        if let (false, Ok(v4)) = (friend_escalated, ip.parse::<Ipv4Addr>()) {
                            let is_permanent = matches!(failure_kind, Some(SourceFailureKind::Permanent));
                            if is_permanent {
                                let src_fw = state
                                    .per_file_sources
                                    .get(transfer_id)
                                    .is_some_and(|pfs| pfs.source_is_firewalled(v4, port, None));
                                state.dead_sources.add_dead_source(0, u32::from(v4), port, src_fw);
                                let mut retire: Option<[u8; 16]> = None;
                                let mgr = transfer_manager.read().await;
                                if let Some(t) = mgr.get_transfer(transfer_id) {
                                    if let Ok(fh_bytes) = hex::decode(&t.file_hash) {
                                        if fh_bytes.len() == 16 {
                                            let mut fh = [0u8; 16];
                                            fh.copy_from_slice(&fh_bytes);
                                            state.dead_sources.add_dead_source_for_file(fh, u32::from(v4), port);
                                            retire = Some(fh);
                                        }
                                    }
                                }
                                drop(mgr);
                                if let Some(fh) = retire {
                                    retire_dead_source_from_registry(&source_manager, &fh, v4, port)
                                        .await;
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
                        // Escalated to a friend connect-back: the source is
                        // parked, not failed. Stop the event here — same soft
                        // defer as `parts_busy` above — so `handle_download_event`
                        // can't overwrite the `FriendConnect` row with `Failed`
                        // and emit a trailing `"failed"` that makes the drawer
                        // drop the row. Skipping the reputation block below is
                        // deliberate: we are not treating this as the friend's
                        // fault.
                        if friend_escalated {
                            continue;
                        }
                    }
                    // Reputation: record handshake success; only score real
                    // download timeouts as Timeout (not our disk-full, permanent
                    // "no file", or other non-timeout failures).
                    if status == "transferring" {
                        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                            let sm = source_manager.read().await;
                            let maybe_uh = sm.find_user_hash_by_addr(v4, port);
                            drop(sm);
                            if let Some(uh) = maybe_uh {
                                let (node_banned, ip_banned) =
                                    state.reputation.record_event_with_ip(
                                        &uh,
                                        v4,
                                        ember::reputation::ReputationEvent::SuccessfulHandshake,
                                    );
                                if node_banned || ip_banned {
                                    apply_reputation_ban_ips(
                                        &mut state,
                                        &shared_banned_ips,
                                        std::iter::once(v4),
                                        &uh,
                                    );
                                }
                            }
                        }
                    } else if status == "failed"
                        && matches!(failure_kind, Some(SourceFailureKind::DownloadTimeout))
                    {
                        if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                            let sm = source_manager.read().await;
                            let maybe_uh = sm.find_user_hash_by_addr(v4, port);
                            drop(sm);
                            if let Some(uh) = maybe_uh {
                                let (node_banned, ip_banned) =
                                    state.reputation.record_event_with_ip(
                                        &uh,
                                        v4,
                                        ember::reputation::ReputationEvent::Timeout,
                                    );
                                if node_banned || ip_banned {
                                    apply_reputation_ban_ips(
                                        &mut state,
                                        &shared_banned_ips,
                                        std::iter::once(v4),
                                        &uh,
                                    );
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
                    // Snapshot who contributed still-unverified bytes to this
                    // exact part range BEFORE `corrupted_part` marks them
                    // corrupt (marking doesn't change which IP owns a block,
                    // so ordering isn't strictly required, but doing it first
                    // keeps the "who could plausibly be blamed" question
                    // independent of the mutation below).
                    let contributors = state
                        .corruption_blackbox
                        .corrupted_part_contributors(file_hash, part_start, part_end);
                    let ban_list = state.corruption_blackbox.corrupted_part(file_hash, part_start, part_end);
                    for ip in ban_list {
                        // Sustained corruption is a deterministic, serious
                        // signal — persist it so the ban survives a restart and
                        // the periodic banned_ips cap reset.
                        let reason = format!("corruption blackbox (high corruption ratio for file {})", hex::encode(file_hash));
                        apply_persistent_ip_ban(
                            &mut state.banned_ips,
                            &shared_banned_ips,
                            &db,
                            ip,
                            &reason,
                            AUTO_BAN_TTL_CONTENT_SECS,
                        );
                    }
                    // `sender_user_hash` is whichever peer's connection
                    // happened to deliver the bytes that completed this part
                    // and triggered verification — in a multi-source
                    // download that is NOT necessarily the peer whose bytes
                    // were actually bad. Only apply the per-connection
                    // reputation strike when that peer was the sole
                    // contributor of unverified data in this part; the
                    // byte-ratio ban above (which is genuinely per-IP
                    // attributed) already covers the ambiguous multi-source
                    // case without punishing an innocent connection.
                    if contributors.len() <= 1 {
                        if let Some(ref uh) = sender_user_hash {
                            let contributor_ip = contributors.iter().next().copied();
                            let (node_banned, ip_banned) = if let Some(ip) = contributor_ip {
                                state.reputation.record_event_with_ip(
                                    uh,
                                    ip,
                                    ember::reputation::ReputationEvent::CorruptData,
                                )
                            } else {
                                (
                                    state.reputation.record_event(
                                        uh,
                                        ember::reputation::ReputationEvent::CorruptData,
                                    ),
                                    false,
                                )
                            };
                            if node_banned || ip_banned {
                                let sm = source_manager.read().await;
                                let mut ips = sm.find_ips_by_user_hash(uh);
                                drop(sm);
                                if let Some(ip) = contributor_ip {
                                    if !ips.contains(&ip) {
                                        ips.push(ip);
                                    }
                                }
                                apply_reputation_ban_ips(
                                    &mut state,
                                    &shared_banned_ips,
                                    ips,
                                    uh,
                                );
                            }
                        }
                    }
                }
                if let DownloadEvent::ProtocolViolation { sender_ip, ref sender_user_hash } = event {
                    // Reputation-scored, not a deterministic abuse ban: a
                    // single violation just nudges the score down, and only a
                    // repeat offender crosses the ban threshold. We therefore
                    // don't DB-persist here — reputation lifetime (and its
                    // per-user-hash enforcement) is governed by reputation.json,
                    // mirroring the other reputation-driven IP bans.
                    if let Some(ref uh) = sender_user_hash {
                        let (node_banned, ip_banned) =
                            state.reputation.record_event_with_ip(
                                uh,
                                sender_ip,
                                ember::reputation::ReputationEvent::ProtocolViolation,
                            );
                        if node_banned || ip_banned {
                            let sm = source_manager.read().await;
                            let mut ips = sm.find_ips_by_user_hash(uh);
                            drop(sm);
                            if !ips.contains(&sender_ip) {
                                ips.push(sender_ip);
                            }
                            apply_reputation_ban_ips(
                                &mut state,
                                &shared_banned_ips,
                                ips,
                                uh,
                            );
                        }
                    } else {
                        // No user hash to score against — fall back to a
                        // durable IP ban so the offender cannot reconnect
                        // for the auto-ban TTL (and so over-cap rebuilds
                        // do not silently drop the entry).
                        apply_persistent_ip_ban(
                            &mut state.banned_ips,
                            &shared_banned_ips,
                            &db,
                            sender_ip,
                            "protocol violation (no user hash)",
                            AUTO_BAN_TTL_CONTENT_SECS,
                        );
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
                if let DownloadEvent::Completed { ref transfer_id, .. } | DownloadEvent::Failed { ref transfer_id, .. } = event {
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
                let completed_file_hash = if let DownloadEvent::Completed { ref transfer_id, .. } = event {
                    let mgr = transfer_manager.read().await;
                    mgr.get_transfer(transfer_id).map(|t| t.file_hash.clone())
                } else {
                    None
                };
                let mut promoted = Vec::new();
                // Isolate per-event panics so one malformed/unexpected download
                // event can't unwind the whole network loop (→ outer catch →
                // shutdown). Mirrors the handle_command_inner/handle_udp_packet_inner
                // catch_unwind pattern.
                if let Err(p) = std::panic::AssertUnwindSafe(handle_download_event(event, &app_handle, &transfer_manager, &source_manager, &db, &mut promoted, &mut stats_manager, settings.remove_finished_downloads, &a4af_shared, &settings.download_folder, &mut db_progress_last_persist, DB_PROGRESS_PERSIST_INTERVAL, &mut state.callback_row_pending_since, &transfer_status_writes)).catch_unwind().await {
                    error!("handle_download_event panicked, dropping event: {}", describe_panic(&*p));
                }

                if let Some(ref file_hash) = completed_file_hash {
                    let mut sf = spam_filter.write().await;
                    sf.auto_mark_not_spam(file_hash);
                }
                for t in promoted {
                    // The transfer just moved from the queue into the active set
                    // with a fresh waiting status (Searching/Queued). Announce it
                    // now so the row leaves "Queued" in real time instead of
                    // waiting for the next reconciling poll.
                    crate::commands::transfers::emit_transfer_status(
                        &app_handle,
                        &t.id,
                        &t.status,
                    );
                    let control = reregister_transfer_control(&transfer_manager, &t.id).await;
                    let (resume_peer_ip, resume_peer_port) = split_peer_id(&t.peer_id);
                    handle_command(
                        &udp_socket,
                        NetworkCommand::StartDownload {
                            file_hash: t.file_hash.clone(),
                            file_name: t.file_name.clone(),
                            file_size: t.total_size,
                            peer_ip: resume_peer_ip,
                            peer_port: resume_peer_port,
                            extra_sources: Vec::new(),
                            ember_file_hash: t.ember_file_hash.clone().unwrap_or_default(),
                            expected_aich: t.expected_aich.clone(),
                            transfer_id: t.id.clone(),
                            control,
                            discovery_only: false,
                            friend_ember_hash: None,
                        },
                        &mut state,
                        &local_index,
                        &fresh_part_hashes,
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
                        &shared_friends_only_hashes,
                        &shared_server_addr,
                        &shared_ember_payload,
                        &ember_payload_generation,
                        &geoip,
                        &friend_hashes,
                        &mutual_friend_hashes,
                        ember_hash,
                        &ul_event_tx,
                        ed25519_pubkey,
                        ed25519_secret_key,
                        &upload_queue_handle,
                        &transfer_status_writes,
                    ).await;
                }

                // Do not auto-resume user-paused downloads when a transfer
                // completes — Pausing is an explicit user action. Concurrent
                // slot refill for queued (not paused) work is handled elsewhere.
            }

            // Upload events from the peer-to-peer upload listener
            Some(event) = ul_event_rx.recv() => {
                // Attribute payload bytes to the Library as Progress events
                // arrive. The old completion-only path depended on finding a
                // still-live transfer row at session teardown; in real uploads
                // that lookup frequently missed, leaving known.met counters at
                // zero despite gigabytes in aggregate Statistics. Events from
                // one upload connection are ordered, and the manager still
                // contains the previous progress snapshot here (the generic
                // handler below applies this event afterward), so the delta is
                // exact and cannot double-count repeated/coalesced updates.
                let library_upload_delta = if let UploadEventKind::Progress {
                    uploaded,
                    ..
                } = &event.kind
                {
                    let manager = transfer_manager.read().await;
                    manager.get_transfer(&event.transfer_id).and_then(|transfer| {
                        let previous = upload_raw_progress
                            .get(&event.transfer_id)
                            .copied()
                            .unwrap_or_default();
                        let next = (*uploaded).max(previous);
                        upload_raw_progress.insert(event.transfer_id.clone(), next);
                        let delta = next.saturating_sub(previous);
                        (delta > 0 && !transfer.file_hash.is_empty())
                            .then(|| (transfer.file_hash.clone(), delta))
                    })
                } else {
                    None
                };
                if let Some((hash_hex, uploaded_bytes)) = library_upload_delta {
                    if let Ok(bytes) = hex::decode(&hash_hex) {
                        if bytes.len() == 16 {
                            let mut file_hash = [0u8; 16];
                            file_hash.copy_from_slice(&bytes);
                            let persisted_alltime = known_files
                                .add_all_time_transferred(&file_hash, uploaded_bytes);
                            if !persisted_alltime {
                                warn!(
                                    "Upload progress for {hash_hex} has no known.met record; keeping session stats only"
                                );
                            }
                            {
                                let mut index = local_index.write().await;
                                index.apply_upload_completed_bytes(
                                    &hash_hex,
                                    uploaded_bytes,
                                    persisted_alltime,
                                );
                            }
                            {
                                let mut cached = shared_files.write().await;
                                for file in cached.iter_mut() {
                                    if file.hash.eq_ignore_ascii_case(&hash_hex) {
                                        file.bytes_transferred = file
                                            .bytes_transferred
                                            .saturating_add(uploaded_bytes);
                                        if persisted_alltime {
                                            file.alltime_transferred = file
                                                .alltime_transferred
                                                .saturating_add(uploaded_bytes);
                                        }
                                    }
                                }
                            }
                            let _ = app_handle.emit(
                                "shared-files-changed",
                                serde_json::json!({
                                    "phase": "upload-progress",
                                    "count": 1,
                                }),
                            );
                        }
                    }
                }
                if matches!(
                    &event.kind,
                    UploadEventKind::Completed { .. } | UploadEventKind::Failed { .. }
                ) {
                    upload_raw_progress.remove(&event.transfer_id);
                }

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
                                let persisted_alltime = known_files.bump_share_interest(
                                    &fh,
                                    inc_requests,
                                    inc_accepted,
                                );
                                if !persisted_alltime {
                                    warn!(
                                        "Upload interest for {file_hash} has no known.met record"
                                    );
                                }
                                {
                                    let mut idx = local_index.write().await;
                                    idx.apply_upload_share_deltas(
                                        file_hash,
                                        inc_requests,
                                        inc_accepted,
                                        persisted_alltime,
                                    );
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
                                            if persisted_alltime {
                                                f.alltime_requests = f
                                                    .alltime_requests
                                                    .saturating_add(inc_requests);
                                                f.alltime_accepted = f
                                                    .alltime_accepted
                                                    .saturating_add(inc_accepted);
                                            }
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

                // A friend forwarded the relay attestations it knows. Each is
                // verified against its own signature before admission, so the
                // friend is trusted only to deliver bytes, not to vouch for
                // them — the same standard the EPX trailer is held to.
                if let UploadEventKind::EmberRelayOffer {
                    ember_hash: relay_eh,
                    ref attestations,
                } = event.kind
                {
                    let now = std::time::Instant::now();
                    let too_soon = state
                        .friend_relay_offer_seen
                        .get(&relay_eh)
                        .is_some_and(|last| {
                            now.saturating_duration_since(*last)
                                < FRIEND_RELAY_OFFER_MIN_INTERVAL
                        });
                    if too_soon {
                        debug!(
                            "Ignoring relay offer from friend {} — arrived inside the {}s throttle",
                            hex::encode(relay_eh),
                            FRIEND_RELAY_OFFER_MIN_INTERVAL.as_secs()
                        );
                    } else if friend_hashes.read().await.contains(&relay_eh) {
                        state.friend_relay_offer_seen.insert(relay_eh, now);
                        // Bounded alongside the live-session sweep the sender
                        // side runs, but capped here too: the throttle map is
                        // written from an inbound path, so a peer that
                        // connects, offers once and leaves must not leave a
                        // permanent entry behind.
                        if state.friend_relay_offer_seen.len() > MAX_FRIEND_RELAY_OFFER_TRACKED {
                            state
                                .friend_relay_offer_seen
                                .retain(|_, last| {
                                    now.saturating_duration_since(*last)
                                        < FRIEND_RELAY_OFFER_MIN_INTERVAL
                                });
                        }
                        let now_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let admitted = admit_relay_attestations(
                            &mut state,
                            attestations,
                            now_unix,
                            Some(relay_eh),
                            &format!("friend relay offer from {}", hex::encode(relay_eh)),
                        );
                        debug!(
                            "Friend {} offered {} relay attestation(s), admitted {admitted}",
                            hex::encode(relay_eh),
                            attestations.len()
                        );
                    }
                }

                // A friend offered us a file. Surface it for an explicit
                // accept and immediately ack receipt — the ack says "your
                // offer arrived", not "I want it", so the sender can drop its
                // pending state without waiting on a human.
                if let UploadEventKind::EmberFileOffer { ember_hash: offer_eh, ref offer, ref reply_tx } = event.kind {
                    // Throttled like inbound transfer requests and relay
                    // offers. Each accepted offer raises a prompt in the UI, so
                    // without a floor between them a friend — or something that
                    // has taken over their client — can bury the user under
                    // dialogs, and every one of them is a decision they have to
                    // make. Declining outright rather than dropping keeps the
                    // sender's request from hanging until its own timeout.
                    let offer_now = std::time::Instant::now();
                    let offer_too_soon = state
                        .friend_file_offer_seen
                        .get(&offer_eh)
                        .is_some_and(|last| {
                            offer_now.saturating_duration_since(*last)
                                < FRIEND_FILE_OFFER_MIN_INTERVAL
                        });
                    if offer_too_soon {
                        debug!(
                            "Declining file offer from friend {} — inside the {}s throttle",
                            hex::encode(offer_eh),
                            FRIEND_FILE_OFFER_MIN_INTERVAL.as_secs()
                        );
                        let ack = ed2k::messages::build_ember_file_offer_ack(
                            ed2k::messages::OFFER_STATUS_THROTTLED,
                            &offer.file_hash,
                        );
                        let mut framed = Vec::with_capacity(6 + ack.len());
                        framed.push(OP_EMULEPROT);
                        framed.extend_from_slice(&((1 + ack.len()) as u32).to_le_bytes());
                        framed.push(ed2k::messages::OP_EMBER_FILE_OFFER_ACK);
                        framed.extend_from_slice(&ack);
                        let _ = reply_tx.try_send(framed);
                    } else if friend_hashes.read().await.contains(&offer_eh) {
                        let status = if settings.friend_chat_disabled {
                            // Reuse the chat switch as the "no unsolicited
                            // contact from friends" control rather than adding
                            // a second one that could disagree with it.
                            ed2k::messages::OFFER_STATUS_DECLINED
                        } else {
                            ed2k::messages::OFFER_STATUS_ACCEPTED
                        };
                        if status == ed2k::messages::OFFER_STATUS_ACCEPTED {
                            // Charged only when a prompt is actually raised.
                            // What the throttle protects is the user's
                            // attention, so an offer that never reaches them —
                            // because unsolicited contact is switched off —
                            // costs nothing and must not consume the budget.
                            // Stamping it regardless made the next offer inside
                            // the window answer "too many at once" when the
                            // truthful answer was the same steady refusal.
                            state.friend_file_offer_seen.insert(offer_eh, offer_now);
                            // Bounded here as well as by the periodic sweep:
                            // this map is written from an inbound path, so a
                            // peer that connects, offers once and leaves must
                            // not leave an entry behind for the life of the
                            // process.
                            if state.friend_file_offer_seen.len() > MAX_FRIEND_RELAY_OFFER_TRACKED {
                                state.friend_file_offer_seen.retain(|_, last| {
                                    offer_now.saturating_duration_since(*last)
                                        < FRIEND_FILE_OFFER_MIN_INTERVAL
                                });
                            }
                            // The name is peer-supplied, so strip the same
                            // bidi/control primitives chat text goes through
                            // before it reaches the UI.
                            let safe_name = crate::security::sanitize_chat_text(&offer.file_name);
                            let _ = app_handle.emit(
                                "ember:file-offer",
                                serde_json::json!({
                                    "user_hash": hex::encode(offer_eh),
                                    "file_hash": hex::encode(offer.file_hash),
                                    "file_name": safe_name,
                                    "file_size": offer.file_size,
                                    "ember_file_hash": offer.ember_file_hash.map(hex::encode),
                                }),
                            );
                        }
                        let ack = ed2k::messages::build_ember_file_offer_ack(status, &offer.file_hash);
                        let mut framed = Vec::with_capacity(6 + ack.len());
                        framed.push(OP_EMULEPROT);
                        framed.extend_from_slice(&((1 + ack.len()) as u32).to_le_bytes());
                        framed.push(ed2k::messages::OP_EMBER_FILE_OFFER_ACK);
                        framed.extend_from_slice(&ack);
                        let _ = reply_tx.try_send(framed);
                    }
                }

                // Chat attachments. The readers only surface these from a
                // session that already holds friend privileges; the friend set
                // is checked again here because it is the one this loop acts on.
                if let UploadEventKind::EmberAttachOffer { ember_hash: attach_eh, ref offer, peer_addr } = event.kind {
                    if friend_hashes.read().await.contains(&attach_eh) {
                        chat_attach::on_offer(
                            &mut state,
                            &db,
                            &app_handle,
                            &settings,
                            attach_eh,
                            offer.clone(),
                            peer_addr,
                        )
                        .await;
                    }
                }
                if let UploadEventKind::EmberAttachReply { ember_hash: attach_eh, xfer_id, reply, quic_port, peer_addr } = event.kind {
                    chat_attach::on_reply(
                        &mut state,
                        &db,
                        &app_handle,
                        attach_eh,
                        xfer_id,
                        reply,
                        quic_port,
                        peer_addr,
                    )
                    .await;
                }
                if let UploadEventKind::EmberAttachCancel { ember_hash: attach_eh, xfer_id, reason } = event.kind {
                    chat_attach::on_cancel(
                        &mut state,
                        &db,
                        &app_handle,
                        &settings,
                        attach_eh,
                        xfer_id,
                        reason,
                    );
                }

                if let UploadEventKind::EmberFileOfferAck { ember_hash: ack_eh, status, file_hash } = event.kind {
                    let _ = app_handle.emit(
                        "ember:file-offer-ack",
                        serde_json::json!({
                            "user_hash": hex::encode(ack_eh),
                            "file_hash": hex::encode(file_hash),
                            "accepted": status == ed2k::messages::OFFER_STATUS_ACCEPTED,
                            // Kept apart from `accepted` so the sender does not
                            // report a rate-limited offer as a refusal — nobody
                            // on the other end has seen it, let alone decided.
                            "throttled": status == ed2k::messages::OFFER_STATUS_THROTTLED,
                        }),
                    );
                }

                // Inject Ember Peer Exchange sources from upload-side peers
                if let UploadEventKind::EmberSources { ref entries, ref aich_roots, ref ember_peers, ref relay_attestations, from_ember_hash } = event.kind {
                    let we_are_unreachable = state.firewalled || state.low_id;
                    handle_epx_sources(&mut state, &transfer_manager, &source_manager, &local_index, entries, aich_roots, ember_peers, relay_attestations, from_ember_hash, "upload", false, we_are_unreachable).await;
                }

                if let UploadEventKind::EmberPeerDiscovered { ip, tcp_port, udp_port } = event.kind {
                    note_connected_ember_peer(
                        &udp_socket,
                        &mut state,
                        settings.ember_native_enabled,
                        ip,
                        tcp_port,
                        udp_port,
                    )
                    .await;
                }

                // The friend contact exchange. Gated on the overlay being on,
                // because with it off there is neither a table to share nor one
                // to fill.
                if let UploadEventKind::EmberDhtContactRequest { ember_hash, target, ref reply_tx } = event.kind {
                    if settings.ember_native_enabled {
                        answer_friend_ember_contact_request(
                            &mut state,
                            ember_hash,
                            target,
                            reply_tx,
                        )
                        .await;
                    }
                }

                if let UploadEventKind::EmberDhtContacts { ember_hash, ref contacts } = event.kind {
                    if settings.ember_native_enabled {
                        ingest_friend_ember_contacts(
                            &udp_socket,
                            &mut state,
                            ember_hash,
                            contacts,
                        )
                        .await;
                    }
                }

                // Any inbound friend activity implies they're online — update
                // status if we haven't already so the UI card flips immediately.
                {
                    let activity_eh = match &event.kind {
                        UploadEventKind::EmberChatMessage { ember_hash, .. }
                        | UploadEventKind::EmberChatTyping { ember_hash, .. }
                        | UploadEventKind::EmberChatRead { ember_hash, .. }
                        | UploadEventKind::EmberBrowseRequest { ember_hash, .. }
                        | UploadEventKind::EmberBrowseResponse { ember_hash, .. }
                        | UploadEventKind::EmberFriendRequest { ember_hash, .. } => Some(*ember_hash),
                        _ => None,
                    };
                    if let Some(eh) = activity_eh {
                        if friend_hashes.read().await.contains(&eh) {
                            let was_new = !state.online_friends.contains_key(&eh);
                            state.online_friends.insert(eh, chrono::Utc::now().timestamp());
                            if was_new {
                                let _ = app_handle.emit("ember:friend-online", serde_json::json!({
                                    "user_hash": hex::encode(eh),
                                }));
                            }
                        }
                    }
                }

                match &event.kind {
                    UploadEventKind::EmberFriendConnected {
                        ember_hash,
                        peer_user_hash,
                        ip,
                        port,
                    } => {
                        // Outbound session just came up. Mirror the inbound-activity
                        // block above: mark online (if not already) and notify the
                        // UI. `friend_hashes` re-check guards the same removal race
                        // documented on the `FriendSeen` handlers.
                        let still_friend = friend_hashes.read().await.contains(ember_hash);
                        if still_friend {
                            let was_new = !state.online_friends.contains_key(ember_hash);
                            state
                                .online_friends
                                .insert(*ember_hash, chrono::Utc::now().timestamp());
                            if was_new {
                                let _ = app_handle.emit(
                                    "ember:friend-online",
                                    serde_json::json!({
                                        "user_hash": hex::encode(ember_hash),
                                    }),
                                );
                            }
                        }
                        // The session is live, so anything the user typed
                        // while this friend was unreachable can go out now.
                        if still_friend {
                            flush_pending_chat(
                                &db,
                                &app_handle,
                                &state.ember_sessions,
                                &ed25519_secret_key,
                                *ember_hash,
                            )
                            .await;
                            if !settings.friend_chat_disabled && settings.friend_chat_read_receipts
                            {
                                flush_pending_read_receipt(
                                    &db,
                                    &state.ember_sessions,
                                    &ed25519_secret_key,
                                    *ember_hash,
                                )
                                .await;
                            }
                        }
                        if still_friend && !ip.is_unspecified() && *port > 0 {
                            let hash_hex = hex::encode(ember_hash);
                            let ip_str = ip.to_string();
                            let db2 = db.clone();
                            let h2 = hash_hex;
                            let ip2 = ip_str;
                            let port = *port;
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                                    warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
                                }
                            });
                            reseed_friend_endpoint(
                                &mut state,
                                &source_manager,
                                &credit_manager,
                                &transfer_manager,
                                *ember_hash,
                                Some(*peer_user_hash),
                                *ip,
                                port,
                            )
                            .await;
                        }
                        // A friend session coming up is the moment a starved
                        // table has something to ask, and waiting for the 60s
                        // maintenance tick is most of a short visit. The ask
                        // rate-limits per friend, so a session that flaps
                        // cannot turn this into a burst.
                        if still_friend && settings.ember_native_enabled {
                            ask_friends_for_ember_contacts(&mut state).await;
                        }
                    }
                    UploadEventKind::FriendEndpointDiscovered {
                        ember_hash,
                        ip,
                        port,
                    } => {
                        if friend_hashes.read().await.contains(ember_hash) {
                            let hash_hex = hex::encode(ember_hash);
                            let ip_str = ip.to_string();
                            let db2 = db.clone();
                            let h2 = hash_hex;
                            let ip2 = ip_str;
                            let port = *port;
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                                    warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
                                }
                            });
                            reseed_friend_endpoint(
                                &mut state,
                                &source_manager,
                                &credit_manager,
                                &transfer_manager,
                                *ember_hash,
                                None,
                                *ip,
                                port,
                            )
                            .await;
                        }
                    }
                    UploadEventKind::FriendSeen {
                        ember_hash,
                        ip,
                        port,
                    }
                        // Gate on current membership: FriendSeen fires post-PoP for a
                        // peer that was a friend at emit time, but a concurrent
                        // removal can still race it. Without this a just-removed
                        // friend could be resurrected as "online" in the UI until the
                        // 5-minute sweep.
                        if friend_hashes.read().await.contains(ember_hash) => {
                            let hash_hex = hex::encode(ember_hash);
                            let now = chrono::Utc::now().timestamp();
                            state.online_friends.insert(*ember_hash, now);
                            // Mirror the download-side FriendSeen handler: clear any
                            // reconnect backoff so a later disconnect can re-dial
                            // promptly instead of waiting out the cooldown.
                            state.friend_reconnect_last.remove(ember_hash);
                            let ip_str = match ip {
                                std::net::IpAddr::V4(v4) => v4.to_string(),
                                std::net::IpAddr::V6(v6) => v6.to_string(),
                            };
                            let db2 = db.clone();
                            let h2 = hash_hex.clone();
                            let ip2 = ip_str.clone();
                            let port = *port;
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = db2.update_friend_address(&h2, &ip2, port) {
                                    warn!("Failed to persist friend {h2} address {ip2}:{port}: {e}");
                                }
                            });
                            // `FriendSeen` now carries the peer's Hello listen
                            // port (see the emission sites in upload.rs), so
                            // it's safe to reseed download sources from it too.
                            if let std::net::IpAddr::V4(v4) = ip {
                                reseed_friend_endpoint(
                                    &mut state,
                                    &source_manager,
                                    &credit_manager,
                                    &transfer_manager,
                                    *ember_hash,
                                    None,
                                    *v4,
                                    port,
                                )
                                .await;
                            }
                            let _ = app_handle.emit(
                                "ember:friend-online",
                                serde_json::json!({
                                    "user_hash": hash_hex,
                                    "ip": ip_str,
                                    "port": port,
                                }),
                            );
                            // A friend who dials *us* never produces
                            // `EmberFriendConnected` (that is emitted only by
                            // the outbound dial path), so without flushing
                            // here queued chat would sit unsent while the UI
                            // showed the friend online and new sends worked.
                            flush_pending_chat(
                                &db,
                                &app_handle,
                                &state.ember_sessions,
                                &ed25519_secret_key,
                                *ember_hash,
                            )
                            .await;
                            if !settings.friend_chat_disabled && settings.friend_chat_read_receipts
                            {
                                flush_pending_read_receipt(
                                    &db,
                                    &state.ember_sessions,
                                    &ed25519_secret_key,
                                    *ember_hash,
                                )
                                .await;
                            }
                        }
                    _ => {}
                }

                if let UploadEventKind::EmberFriendRequest { ember_hash: req_hash, pubkey, ref nickname, ref peer_ip, peer_port, verified } = event.kind {
                    process_inbound_friend_request(
                        &db,
                        &app_handle,
                        &mut state.online_friends,
                        &mutual_friend_hashes,
                        req_hash,
                        pubkey,
                        nickname,
                        peer_ip,
                        peer_port,
                        verified,
                    )
                    .await;
                }

                if let UploadEventKind::EmberFriendRetract { ember_hash: retract_hash } = event.kind {
                    let hash_hex = hex::encode(retract_hash);
                    // Only the queued request goes. Reaching into `friends`
                    // here would turn a withdrawal into a way to remove
                    // yourself from someone else's friend list, and if they
                    // accepted a moment ago there is simply no row left to
                    // delete.
                    let db_retract = db.clone();
                    let h_retract = hash_hex.clone();
                    match tokio::task::spawn_blocking(move || {
                        db_retract.remove_friend_request(&h_retract)
                    })
                    .await
                    {
                        Ok(Ok(())) => {
                            info!("Cleared withdrawn friend request from {hash_hex}");
                            let _ = app_handle.emit(
                                "ember:friend-request-withdrawn",
                                serde_json::json!({
                                    "sender_hash": hash_hex,
                                }),
                            );
                        }
                        Ok(Err(e)) => warn!("Failed to clear withdrawn request from {hash_hex}: {e}"),
                        Err(e) => warn!("Withdrawn-request task failed for {hash_hex}: {e}"),
                    }
                }

                if let UploadEventKind::EmberFriendDecline { ember_hash: decline_hash } = event.kind {
                    let hash_hex = hex::encode(decline_hash);
                    // Only a row they have never accepted. `decline_friend_request`
                    // is written to refuse a mutual friendship outright, so this
                    // cannot become a way to remove yourself from somebody
                    // else's friend list — and if they accepted a moment ago,
                    // there is nothing one-sided left to delete.
                    let db_decline = db.clone();
                    let h_decline = hash_hex.clone();
                    match tokio::task::spawn_blocking(move || {
                        db_decline.decline_friend_request(&h_decline)
                    })
                    .await
                    {
                        Ok(Ok(true)) => {
                            info!("Friend request to {hash_hex} was declined");
                            // We added them, which granted them friend access
                            // to this node; their refusal ends that. Dropping
                            // the hash alone leaves any stream they already
                            // hold authenticated, so the grant has to be
                            // revoked the same way removal revokes it.
                            friend_hashes.write().await.remove(&decline_hash);
                            ed2k::upload::revoke_all_secure_sessions(decline_hash);
                            let _ = app_handle.emit(
                                "ember:friend-request-declined",
                                serde_json::json!({
                                    "user_hash": hash_hex,
                                }),
                            );
                        }
                        // Nothing one-sided on file: they accepted first, or we
                        // had already removed them. Either way the decline has
                        // nothing to act on and is not worth telling anyone.
                        Ok(Ok(false)) => {
                            debug!("Ignoring a decline from {hash_hex} with no pending request")
                        }
                        Ok(Err(e)) => warn!("Failed to clear declined request to {hash_hex}: {e}"),
                        Err(e) => warn!("Declined-request task failed for {hash_hex}: {e}"),
                    }
                }

                if let UploadEventKind::EmberChatMessage { ember_hash: chat_eh, ref message } = event.kind {
                    if !friend_hashes.read().await.contains(&chat_eh) {
                        debug!("Dropping secure chat event after friend removal");
                        continue;
                    }
                    // Nothing can be stored while chat is locked, and surfacing
                    // a message we cannot keep is worse than not surfacing it:
                    // it would appear, contradict the banner explaining that
                    // chat is unusable, and disappear on the next reload.
                    if db.chat_locked() {
                        debug!(
                            "Dropping inbound chat from {} — history is locked",
                            hex::encode(chat_eh)
                        );
                        continue;
                    }
                    if !settings.friend_chat_disabled {
                        let hash_hex = hex::encode(chat_eh);
                        // L20: same ingress sanitisation as the
                        // download-event path above. Inbound chat
                        // arrives via two upload-listener routes
                        // (`upload.rs` direct, plus the
                        // friend-session reader in
                        // `friend_connect.rs`) and both ultimately
                        // land here, so this single call covers
                        // every inbound chat persistence point.
                        let cleaned = crate::security::sanitize_chat_text(message);
                        // Dedup against the `DownloadEvent::EmberChatMessage`
                        // path above — see `recent_ember_chat`'s doc comment.
                        // The two upload-listener routes feeding *this* arm
                        // already can't double-deliver on their own (both
                        // honour `ember_sessions` slot ownership), but an
                        // ordinary download connection to the same friend
                        // deliberately doesn't participate in that ownership
                        // check, so this shared map is what catches it.
                        let now = chrono::Utc::now().timestamp();
                        let is_dup = state
                            .recent_ember_chat
                            .get(&chat_eh)
                            .is_some_and(|(last_msg, last_at)| {
                                *last_msg == cleaned
                                    && now.saturating_sub(*last_at) <= EMBER_CHAT_DEDUP_WINDOW_SECS
                            });
                        if !is_dup {
                            match persist_chat_history_message(
                                db.clone(),
                                hash_hex.clone(),
                                "received",
                                cleaned.clone(),
                            )
                            .await
                            {
                                Ok(id) => {
                                    state
                                        .recent_ember_chat
                                        .insert(chat_eh, (cleaned.clone(), now));
                                    let _ = app_handle.emit("ember:chat-message", serde_json::json!({
                                        "user_hash": hash_hex,
                                        "id": id,
                                        "message": cleaned,
                                        "direction": "received",
                                        "timestamp": now,
                                    }));
                                }
                                Err(error) => {
                                    warn!(
                                        "Received chat message was not emitted because history persistence failed: {error}"
                                    );
                                }
                            }
                        }
                    }
                }

                if let UploadEventKind::EmberChatTyping { ember_hash: typing_eh, typing } = event.kind {
                    if !settings.friend_chat_disabled
                        && friend_hashes.read().await.contains(&typing_eh)
                    {
                        let _ = app_handle.emit(
                            "ember:chat-typing",
                            serde_json::json!({
                                "user_hash": hex::encode(typing_eh),
                                "typing": typing,
                            }),
                        );
                    }
                }

                if let UploadEventKind::EmberChatRead { ember_hash: read_eh, body_hash } = event.kind
                {
                    // Same gate as outbound send/flush: off means we neither
                    // tell friends we have read nor record that they have read
                    // us. Persisting while the setting is off would still paint
                    // "Seen" the moment it is turned back on.
                    if settings.friend_chat_disabled
                        || !settings.friend_chat_read_receipts
                        || !friend_hashes.read().await.contains(&read_eh)
                    {
                        continue;
                    }
                    let hash_hex = hex::encode(read_eh);
                    let body_hex = hex::encode(body_hash);
                    let db_seen = db.clone();
                    let hash_for_db = hash_hex.clone();
                    match tokio::task::spawn_blocking(move || {
                        db_seen.mark_sent_seen_by_hash(&hash_for_db, &body_hex)
                    })
                    .await
                    {
                        Ok(Ok(Some(until_id))) => {
                            let _ = app_handle.emit(
                                "ember:chat-read",
                                serde_json::json!({
                                    "user_hash": hash_hex,
                                    "until_id": until_id,
                                }),
                            );
                        }
                        Ok(Ok(None)) => {}
                        Ok(Err(e)) => warn!("Failed to apply chat read receipt from {hash_hex}: {e}"),
                        Err(e) => warn!("Chat read-receipt task failed for {hash_hex}: {e}"),
                    }
                }

                if let UploadEventKind::EmberBrowseRequest {
                    ember_hash: browse_eh,
                    session_id,
                    ref reply_tx,
                    supports_ebr1,
                } = event.kind
                {
                    // Mutual, not merely listed. The UI already hides Browse
                    // until a friendship is mutual, but that is cosmetic: the
                    // wire has to enforce it, or anyone who learns our Ember
                    // hash could add us one-sidedly and read our library.
                    if !settings.friend_browse_disabled
                        && mutual_friend_hashes.read().await.contains(&browse_eh)
                    {
                        let hash_hex = hex::encode(browse_eh);
                        let files = {
                            let idx = local_index.read().await;
                            idx.all_files().to_vec()
                        };
                        // Cap both entry count and total payload bytes. The
                        // receiving side's inbound frame reader
                        // (`read_packet_with_first_byte` in upload.rs) rejects
                        // any packet over 512 KiB outright with no partial
                        // delivery, so an oversized answer silently loses the
                        // *entire* browse response rather than a truncated
                        // one — cap well under that so a large library still
                        // gets a usable (if truncated) reply. The entry count
                        // also matches `MAX_BROWSE_ENTRIES` in
                        // `multi_source::parse_browse_response`, which is what
                        // the peer receiving our answer actually keeps.
                        const MAX_BROWSE_ANSWER_FILES: usize = 1_000;
                        const MAX_BROWSE_ANSWER_BYTES: usize = 400 * 1024;
                        let mut encoded_entries: Vec<(
                            [u8; 16],
                            u64,
                            Vec<u8>,
                            Option<[u8; 20]>,
                            Option<[u8; 32]>,
                        )> = Vec::new();
                        // Mutual friends see friends-only files alongside
                        // public ones — that is the whole point of the scope.
                        for f in files
                            .iter()
                            .filter(|f| f.is_friend_visible())
                            .take(MAX_BROWSE_ANSWER_FILES)
                        {
                            let Ok(hash_bytes) = hex::decode(&f.hash) else {
                                continue;
                            };
                            if hash_bytes.len() != 16 {
                                continue;
                            }
                            let mut hash = [0u8; 16];
                            hash.copy_from_slice(&hash_bytes);
                            let name_bytes = f.name.as_bytes().to_vec();
                            let aich = if f.aich_hash.len() == 40 {
                                let mut root = [0u8; 20];
                                if hex::decode_to_slice(&f.aich_hash, &mut root).is_ok() {
                                    Some(root)
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            let ember = if f.ember_file_hash.len() == 64 {
                                let mut digest = [0u8; 32];
                                if hex::decode_to_slice(&f.ember_file_hash, &mut digest).is_ok() {
                                    Some(digest)
                                } else {
                                    None
                                }
                            } else {
                                None
                            };
                            encoded_entries.push((hash, f.size, name_bytes, aich, ember));
                            // Rough pre-cap so encode stays under the frame budget.
                            let approx = encoded_entries.iter().fold(8usize, |acc, e| {
                                acc + 16
                                    + 8
                                    + 2
                                    + e.2.len()
                                    + 1
                                    + if e.3.is_some() { 20 } else { 0 }
                                    + 32
                            });
                            if approx >= MAX_BROWSE_ANSWER_BYTES {
                                break;
                            }
                        }
                        let res_payload = if supports_ebr1 {
                            ed2k::multi_source::encode_browse_response_v1(
                                encoded_entries.iter().map(|(h, s, n, a, e)| {
                                    (h, *s, n.as_slice(), a.as_ref(), e.as_ref())
                                }),
                            )
                        } else {
                            ed2k::multi_source::encode_browse_response_legacy(
                                encoded_entries
                                    .iter()
                                    .map(|(h, s, n, _, _)| (h, *s, n.as_slice())),
                            )
                        };
                        let mut packet = Vec::with_capacity(6 + res_payload.len());
                        packet.push(OP_EMULEPROT);
                        let size = (1 + res_payload.len()) as u32;
                        packet.extend_from_slice(&size.to_le_bytes());
                        packet.push(ed2k::messages::OP_EMBER_BROWSE_RES);
                        packet.extend_from_slice(&res_payload);
                        if let Err(e) = send_browse_response_to_origin(reply_tx, packet) {
                            tracing::warn!(
                                "Browse response to {} on session {} dropped: {e}",
                                hex::encode(browse_eh),
                                session_id,
                            );
                        }
                        let _ = app_handle.emit("ember:browse-request", serde_json::json!({
                            "user_hash": hash_hex,
                        }));
                    } else {
                        // Complete the requester's wait. Dropping the packet
                        // left their UI spinning until the 30s browse timeout
                        // — the same "no files" answer they would get from an
                        // empty library, without leaking whether we refused
                        // for policy or had nothing to show.
                        let res_payload = if supports_ebr1 {
                            ed2k::multi_source::encode_browse_response_v1(std::iter::empty())
                        } else {
                            ed2k::multi_source::encode_browse_response_legacy(std::iter::empty())
                        };
                        let mut packet = Vec::with_capacity(6 + res_payload.len());
                        packet.push(OP_EMULEPROT);
                        let size = (1 + res_payload.len()) as u32;
                        packet.extend_from_slice(&size.to_le_bytes());
                        packet.push(ed2k::messages::OP_EMBER_BROWSE_RES);
                        packet.extend_from_slice(&res_payload);
                        if let Err(e) = send_browse_response_to_origin(reply_tx, packet) {
                            tracing::debug!(
                                "Browse refusal to {} on session {} dropped: {e}",
                                hex::encode(browse_eh),
                                session_id,
                            );
                        }
                    }
                }

                if let UploadEventKind::EmberBrowseSessionReady {
                    ember_hash: browse_eh,
                    request_id,
                    session_id,
                    tx,
                } = event.kind
                {
                    let Some(()) = bind_browse_request_to_session(
                        &mut state.pending_browse_requests,
                        browse_eh,
                        &request_id,
                        session_id,
                    ) else {
                        let _ = tx.send(Err(
                            "Browse request was cancelled before the friend session opened".into(),
                        ));
                        continue;
                    };
                    dispatch_browse_head(&mut state, &app_handle, browse_eh).await;
                    if browse_request_is_pending(
                        &state.pending_browse_requests,
                        browse_eh,
                        &request_id,
                    ) {
                        let _ = tx.send(Ok(()));
                    } else {
                        let _ = tx.send(Err(
                            "Browse session was replaced before the request was sent".into(),
                        ));
                    }
                    continue;
                }

                if let UploadEventKind::EmberBrowseSessionFailed {
                    ember_hash: browse_eh,
                    request_id,
                    error,
                    tx,
                } = event.kind
                {
                    let _ = remove_browse_request(
                        &mut state.pending_browse_requests,
                        browse_eh,
                        &request_id,
                    );
                    dispatch_browse_head(&mut state, &app_handle, browse_eh).await;
                    let _ = tx.send(Err(error));
                    continue;
                }

                if let UploadEventKind::EmberBrowseResponse {
                    ember_hash: browse_eh,
                    session_id,
                    ref entries,
                } = event.kind
                {
                    if !friend_hashes.read().await.contains(&browse_eh) {
                        debug!("Dropping secure browse response after friend removal");
                        continue;
                    }
                    let hash_hex = hex::encode(browse_eh);
                    let files: Vec<serde_json::Value> = entries
                        .iter()
                        .map(|(hash, size, name, aich, ember)| {
                            let clean_name = crate::security::sanitize_display_name(name);
                            let mut obj = serde_json::json!({
                                "hash": hash,
                                "size": size,
                                "name": clean_name,
                            });
                            if let Some(aich_hash) = aich.as_ref().filter(|h| h.len() == 40) {
                                obj.as_object_mut().unwrap().insert(
                                    "aich_hash".into(),
                                    serde_json::Value::String(aich_hash.clone()),
                                );
                            }
                            if let Some(ember_file_hash) = ember.as_ref().filter(|h| h.len() == 64)
                            {
                                obj.as_object_mut().unwrap().insert(
                                    "ember_file_hash".into(),
                                    serde_json::Value::String(ember_file_hash.clone()),
                                );
                            }
                            obj
                        })
                        .collect();
                    if let Some(request_id) = complete_browse_request(
                        &mut state.pending_browse_requests,
                        browse_eh,
                        session_id,
                    ) {
                        let _ = app_handle.emit("ember:browse-result", serde_json::json!({
                            "user_hash": hash_hex,
                            "request_id": request_id,
                            "files": files,
                        }));
                        dispatch_browse_head(&mut state, &app_handle, browse_eh).await;
                    } else {
                        debug!(
                            "Ignoring stale or unbound browse response from {} session {}",
                            hash_hex, session_id
                        );
                    }
                }

                if let UploadEventKind::EmberFriendDisconnected {
                    ember_hash: dc_eh,
                    session_id,
                } = event.kind
                {
                    let hash_hex = hex::encode(dc_eh);
                    for request_id in remove_browse_requests_for_session(
                        &mut state.pending_browse_requests,
                        dc_eh,
                        session_id,
                    ) {
                        let _ = app_handle.emit("ember:browse-error", serde_json::json!({
                            "user_hash": hash_hex,
                            "request_id": request_id,
                            "reason": "Friend disconnected",
                        }));
                    }
                    // The queue may still contain requests already bound to a
                    // newer replacement session. Re-enter the sole dispatcher
                    // so the new head is sent instead of being stranded.
                    dispatch_browse_head(&mut state, &app_handle, dc_eh).await;
                    let newer_session_active = state
                        .ember_sessions
                        .read()
                        .await
                        .get(&dc_eh)
                        .is_some_and(|handle| {
                            handle.session_id() != session_id && handle.is_fresh()
                        });
                    if newer_session_active {
                        debug!(
                            "Ignoring disconnect from retired friend session {} for {}",
                            session_id, hash_hex
                        );
                    } else {
                        state.online_friends.remove(&dc_eh);
                        state.outbound_session_tasks.remove(&dc_eh);
                        let _ = app_handle.emit("ember:friend-offline", serde_json::json!({
                            "user_hash": hash_hex,
                        }));
                    }

                    if !newer_session_active
                        && friend_hashes.read().await.contains(&dc_eh)
                        && !state.ember_sessions.read().await.get(&dc_eh).is_some_and(|h| h.is_fresh())
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
                                &app_handle, &friend_hashes, &ul_event_tx,
                                ed25519_pubkey, ed25519_secret_key,
                            );
                        } else {
                            debug!("Friend {} reconnect skipped (backoff cooldown)", hash_hex);
                        }
                    }
                }

                // A friend cannot dial us and is asking us to dial them
                // instead so they can download a file we share. This is the
                // friend-layer counterpart of an inbound eD2K
                // `OP_CALLBACKREQUESTED`, and needs neither a server login
                // nor a HighID on either side — the ask arrived over the
                // friend session, and the dial goes out from us.
                if let UploadEventKind::EmberTransferRequest {
                    ember_hash: xfer_eh,
                    request,
                    ref reply_tx,
                    peer_addr: xfer_peer_addr,
                } = event.kind
                {
                    let mut status = friend_transfer_request_status(
                        &mut state,
                        &local_index,
                        xfer_eh,
                        &request,
                        xfer_peer_addr,
                        &friend_hashes,
                        &mutual_friend_hashes,
                    )
                    .await;

                    // Enqueue the dial *before* acking, so an accept is never
                    // sent for a connect-back that never happens: the friend
                    // would then park its source waiting on us for the full
                    // attempt timeout instead of retrying promptly.
                    //
                    // Only a connect-back dials. A punch carries `tcp_port` 0
                    // and is answered by the punch responder taking the serve
                    // role, so dialing here would target `peer_ip:0`.
                    if status == ed2k::messages::XFER_STATUS_ACCEPTED
                        && request.method == ed2k::messages::EmberXferMethod::ConnectBack
                    {
                        // Dial the address the friend session is actually
                        // connected to, never one from the payload, with the
                        // listening port they advertised. `secure_friend_ember_hash`
                        // makes this a Noise IK dial so they can route our
                        // connection into the right download by proven identity.
                        let dial_addr = SocketAddr::new(xfer_peer_addr.ip(), request.tcp_port);
                        match connect_serve_tx.try_send(
                            upload_server::ConnectServeRequest {
                                peer_addr: dial_addr,
                                crypt_options: 0,
                                user_hash: None,
                                push_grant_file_hash: None,
                                push_grant_accepted: None,
                                secure_friend_ember_hash: Some(xfer_eh),
                            },
                        ) {
                            Ok(()) => info!(
                                "Friend {} asked us to connect back to {dial_addr} for {}; dialing",
                                hex::encode(xfer_eh),
                                hex::encode(request.file_hash)
                            ),
                            Err(e) => {
                                debug!(
                                    "Could not enqueue friend transfer dial to {dial_addr}: {e}"
                                );
                                // Our dialer is saturated, not the friend's
                                // fault and not permanent — "try later" is
                                // exactly what rate-limited means to them.
                                status = ed2k::messages::XFER_STATUS_DECLINED_RATE_LIMITED;
                                // Don't let a request we couldn't act on start
                                // the inbound cooldown.
                                state.friend_xfer_inbound_last.remove(&xfer_eh);
                            }
                        }
                    }

                    let ack = ed2k::messages::build_ember_xfer_ack(status, &request.nonce);
                    let mut packet = Vec::with_capacity(6 + ack.len());
                    packet.push(OP_EMULEPROT);
                    packet.extend_from_slice(&((1 + ack.len()) as u32).to_le_bytes());
                    packet.push(ed2k::messages::OP_EMBER_XFER_ACK);
                    packet.extend_from_slice(&ack);
                    let _ = reply_tx.try_send(packet);
                }

                // A friend answered our own `OP_EMBER_XFER_REQ`. An accept
                // needs no action here — the pending expectation was already
                // registered when we sent the request, precisely so their dial
                // can't arrive before we're ready for it. A decline releases
                // the source immediately instead of letting it idle out the
                // full attempt timeout.
                if let UploadEventKind::EmberTransferAck {
                    ember_hash: ack_eh,
                    status,
                    nonce,
                } = event.kind
                {
                    handle_friend_transfer_ack(
                        &mut state,
                        &transfer_manager,
                        &pending_kad_callbacks,
                        &app_handle,
                        &settings,
                        ed25519_secret_key,
                        ember_hash,
                        ack_eh,
                        status,
                        nonce,
                    )
                    .await;
                }

                if let UploadEventKind::EmberFriendSearchFailed { ember_hash: failed_eh } = event.kind {
                    // Pure cleanup signal from the rendezvous /
                    // chat-auto-connect / browse-auto-connect spawns.
                    // Distinct from `EmberFriendDisconnected` so we
                    // don't fire `ember:friend-offline` /
                    // `ember:browse-error` for a peer who was never
                    // online in this session, and don't kick off a
                    // reconnect attempt (the spawn just gave up — an
                    // immediate retry would dogpile rendezvous and
                    // hammer the same dead address). The user-facing
                    // `ember:friend-search-failed` event with a
                    // structured reason is emitted from inside the
                    // spawn itself; here we only mutate state.
                    state.outbound_session_tasks.remove(&failed_eh);
                }

                // Reputation: record upload-side events
                match &event.kind {
                    UploadEventKind::Started {
                        user_hash: Some(ref uh_hex),
                        ref peer_addr,
                        ..
                    } => {
                        if let Ok(bytes) = hex::decode(uh_hex) {
                            if bytes.len() == 16 {
                                let mut uh = [0u8; 16];
                                uh.copy_from_slice(&bytes);
                                if let Some(ip) = peer_addr
                                    .parse::<SocketAddr>()
                                    .ok()
                                    .and_then(|addr| match addr.ip() {
                                        std::net::IpAddr::V4(ip) => Some(ip),
                                        _ => None,
                                    })
                                {
                                    state.reputation.record_event_with_ip(
                                        &uh,
                                        ip,
                                        ember::reputation::ReputationEvent::SuccessfulHandshake,
                                    );
                                } else {
                                    state.reputation.record_event(
                                        &uh,
                                        ember::reputation::ReputationEvent::SuccessfulHandshake,
                                    );
                                }
                            }
                        }
                    }
                    UploadEventKind::Completed { .. } => {
                        let mgr = transfer_manager.read().await;
                        if let Some(t) = mgr.get_transfer(&event.transfer_id) {
                            if let Some(ref uh_hex) = t.user_hash {
                                if let Ok(bytes) = hex::decode(uh_hex) {
                                    if bytes.len() == 16 {
                                        let mut uh = [0u8; 16];
                                        uh.copy_from_slice(&bytes);
                                        if let Some(ip) = t
                                            .peer_id
                                            .split(':')
                                            .next()
                                            .and_then(|value| value.parse::<Ipv4Addr>().ok())
                                        {
                                            state.reputation.record_event_with_ip(
                                                &uh,
                                                ip,
                                                ember::reputation::ReputationEvent::SuccessfulChunk,
                                            );
                                        } else {
                                            state.reputation.record_event(
                                                &uh,
                                                ember::reputation::ReputationEvent::SuccessfulChunk,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        drop(mgr);
                    }
                    UploadEventKind::Failed { ref error } => {
                        // Pull the peer identity out first, then drop the
                        // transfer-manager lock before touching the source
                        // manager / reputation state. Skip queue/session
                        // mechanics that are not evidence of bad peer data.
                        if is_neutral_upload_failure(error) {
                            // no reputation strike
                        } else {
                        let peer_info: Option<([u8; 16], Option<Ipv4Addr>)> = {
                            let mgr = transfer_manager.read().await;
                            mgr.get_transfer(&event.transfer_id).and_then(|t| {
                                t.user_hash.as_ref().and_then(|uh_hex| hex::decode(uh_hex).ok()).and_then(|bytes| {
                                    if bytes.len() == 16 {
                                        let mut uh = [0u8; 16];
                                        uh.copy_from_slice(&bytes);
                                        let peer_ip =
                                            split_peer_id(&t.peer_id).0.parse::<Ipv4Addr>().ok();
                                        Some((uh, peer_ip))
                                    } else {
                                        None
                                    }
                                })
                            })
                        };
                        if let Some((uh, peer_ip)) = peer_info {
                            let (node_banned, ip_banned) = if let Some(ip) = peer_ip {
                                state.reputation.record_event_with_ip(
                                    &uh,
                                    ip,
                                    ember::reputation::ReputationEvent::FailedChunk,
                                )
                            } else {
                                (
                                    state.reputation.record_event(
                                        &uh,
                                        ember::reputation::ReputationEvent::FailedChunk,
                                    ),
                                    false,
                                )
                            };
                            if node_banned || ip_banned {
                                // Ban every known IP for this user hash (not just
                                // the one address on the transfer row) so a
                                // multi-homed peer can't keep going from another
                                // address — matching the PartCorrupted path.
                                let sm = source_manager.read().await;
                                let mut ips = sm.find_ips_by_user_hash(&uh);
                                drop(sm);
                                if let Some(ip) = peer_ip {
                                    if !ips.contains(&ip) {
                                        ips.push(ip);
                                    }
                                }
                                apply_reputation_ban_ips(
                                    &mut state,
                                    &shared_banned_ips,
                                    ips,
                                    &uh,
                                );
                            }
                        }
                        }
                    }
                    UploadEventKind::PeerAutoBanned { ip, reason, user_hash } => {
                        // Manual live-session capture (hash-banned peer caught
                        // mid-upload): persist against the peer row only — not
                        // the 7-day auto-ban table — so unban_peer remains the
                        // sole lifetime authority.
                        let is_manual_capture = user_hash.is_some()
                            && reason.starts_with("manual peer ban");
                        if is_manual_capture {
                            if state.banned_ips.insert(*ip) {
                                warn!("Manual ban capture: banning IP {ip} ({reason})");
                            }
                            if let Ok(mut shared) = shared_banned_ips.write() {
                                *shared = state.banned_ips.clone();
                            }
                            if let Some(uh) = user_hash {
                                let peer_id_hex = hex::encode(uh);
                                if let Err(e) = db.add_banned_peer_address(&peer_id_hex, *ip) {
                                    warn!("Failed to record captured ban IP {ip} for peer {peer_id_hex}: {e}");
                                }
                            }
                        } else {
                            // Abuse / AddRequestCount: a timing heuristic, so it
                            // gets eMule's `CLIENTBANTIME` rather than the long
                            // ban reserved for content evidence.
                            apply_persistent_ip_ban(
                                &mut state.banned_ips,
                                &shared_banned_ips,
                                &db,
                                *ip,
                                reason,
                                AUTO_BAN_TTL_BEHAVIOUR_SECS,
                            );
                        }
                    }
                    _ => {}
                }

                let mut promoted = Vec::new();
                if let Err(p) = std::panic::AssertUnwindSafe(handle_upload_event(event, &app_handle, &transfer_manager, &mut promoted, &mut stats_manager, bandwidth_limiter.effective_upload_rate())).catch_unwind().await {
                    error!("handle_upload_event panicked, dropping event: {}", describe_panic(&*p));
                }
                for t in promoted {
                    // The transfer just moved from the queue into the active set
                    // with a fresh waiting status (Searching/Queued). Announce it
                    // now so the row leaves "Queued" in real time instead of
                    // waiting for the next reconciling poll.
                    crate::commands::transfers::emit_transfer_status(
                        &app_handle,
                        &t.id,
                        &t.status,
                    );
                    let control = reregister_transfer_control(&transfer_manager, &t.id).await;
                    let (resume_peer_ip, resume_peer_port) = split_peer_id(&t.peer_id);
                    handle_command(
                        &udp_socket,
                        NetworkCommand::StartDownload {
                            file_hash: t.file_hash.clone(),
                            file_name: t.file_name.clone(),
                            file_size: t.total_size,
                            peer_ip: resume_peer_ip,
                            peer_port: resume_peer_port,
                            extra_sources: Vec::new(),
                            ember_file_hash: t.ember_file_hash.clone().unwrap_or_default(),
                            expected_aich: t.expected_aich.clone(),
                            transfer_id: t.id.clone(),
                            control,
                            discovery_only: false,
                            friend_ember_hash: None,
                        },
                        &mut state,
                        &local_index,
                        &fresh_part_hashes,
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
                        &shared_friends_only_hashes,
                        &shared_server_addr,
                        &shared_ember_payload,
                        &ember_payload_generation,
                        &geoip,
                        &friend_hashes,
                        &mutual_friend_hashes,
                        ember_hash,
                        &ul_event_tx,
                        ed25519_pubkey,
                        ed25519_secret_key,
                        &upload_queue_handle,
                        &transfer_status_writes,
                    ).await;
                }
            }

            // Periodic search polling
            _ = search_poll_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_search_poll_tick(
                    &udp_socket,
                    &mut state,
                    &settings,
                    &dl_event_tx,
                    &bandwidth_limiter,
                    &db,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &credit_manager,
                    &stats_manager,
                    &mut known_files,
                    &shared_banned_ips,
                    &shared_ember_payload,
                    &ember_payload_generation,
                    &geoip,
                    &friend_hashes,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &comment_manager,
                    &pending_kad_callbacks,
                    &mut pending_lowid_callback_queue,
                    &spam_filter,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'search_poll_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic bootstrap (eMule BigTimer style)
            _ = bootstrap_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_bootstrap_tick(
                    &udp_socket,
                    &mut state,
                    &local_index,
                    &settings,
                    &bandwidth_limiter,
                    &db,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &known_files,
                    &firewall_probe_ips,
                    &shared_banned_ips,
                    &friend_hashes,
                    ember_hash,
                    &ul_event_tx,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &mut bootstrap_attempts,
                    &mut hardcoded_bootstrap_backoff_shift,
                    &inbound_stream_tx,
                    &mut last_hardcoded_bootstrap_ts,
                    &mut last_sampled_bootstrap_ts,
                    &mut nat_probe_in_flight,
                    &mut nat_probe_packet_tx,
                    &nat_probe_result_tx,
                    &mut nat_probe_started_at,
                    &mut rendezvous_register_in_flight,
                    &rendezvous_register_result_tx,
                    &mut rendezvous_register_started_at,
                    &mut sampled_bootstrap_backoff_shift,
                    upnp_enabled,
                    &mut upnp_maintain_handle,
                    &mut upnp_maintain_in_flight,
                    &upnp_maintain_result_tx,
                    &mut upnp_maintain_started_at,
                    &upnp_mappings,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'bootstrap_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Poll authenticated friend relay offers independently from the
            // 60-second publishing heartbeat. The bounded timeout and
            // in-flight flag guarantee a slow rendezvous cannot create one
            // task per cadence tick.
            _ = friend_relay_ticket_poll_timer.tick() => {
                if state.rendezvous_registered
                    && friend_relay_ticket_polls_in_flight == 0
                    && tokio::time::Instant::now() >= friend_relay_ticket_poll_not_before
                {
                    // One authenticated self-mailbox poll. No friend IDs,
                    // candidate pages, nicknames, or graph-sized payloads
                    // leave the client while idle.
                    friend_relay_ticket_poll_round_started_at =
                        Some(tokio::time::Instant::now());
                    let rv_url = settings.rendezvous_url.clone();
                    let poll_tx = friend_relay_ticket_poll_result_tx.clone();
                    friend_relay_ticket_polls_in_flight = 1;
                    tokio::spawn(async move {
                        let result = match tokio::time::timeout(
                            rendezvous::FRIEND_RELAY_TICKET_POLL_TIMEOUT,
                            rendezvous::poll_friend_relay_tickets(
                                &rv_url,
                                &ember_hash,
                                &ed25519_secret_key,
                            ),
                        )
                        .await
                        {
                            Ok(result) => result,
                            Err(_) => Err("friend relay mailbox poll timed out".to_string()),
                        };
                        let _ = poll_tx.send(FriendRelayTicketPollResult { result });
                    });
                }
            }

            Some(result) = friend_relay_ticket_poll_result_rx.recv() => {
                friend_relay_ticket_polls_in_flight =
                    friend_relay_ticket_polls_in_flight.saturating_sub(1);
                let page = match result.result {
                    Ok(page) => page,
                    Err(e) => {
                        tracing::trace!("Friend relay ticket poll: {e}");
                        if rendezvous::is_transient_relay_ticket_read_error(&e)
                            || e.contains("timed out")
                        {
                            friend_relay_ticket_poll_not_before =
                                tokio::time::Instant::now()
                                    + friend_relay_ticket_poll_retry_delay;
                            friend_relay_ticket_poll_retry_delay =
                                (friend_relay_ticket_poll_retry_delay * 2)
                                    .min(std::time::Duration::from_secs(5));
                        }
                        continue;
                    }
                };
                friend_relay_ticket_poll_retry_delay = std::time::Duration::from_secs(1);
                if friend_relay_ticket_polls_in_flight == 0 {
                    let now = tokio::time::Instant::now();
                    let delay = friend_relay_ticket_poll_round_started_at
                        .take()
                        .map(|started_at| relay_ticket_next_round_delay(started_at, now))
                        .unwrap_or(rendezvous::FRIEND_RELAY_TICKET_RESPONDER_POLL_INTERVAL);
                    // Reset to the scheduled cadence boundary, not
                    // immediately: fast responses must never create a
                    // tight poll loop, while a completion just after a
                    // missed tick can still begin the next round now.
                    friend_relay_ticket_poll_not_before = now + delay;
                    friend_relay_ticket_poll_timer.reset_after(delay);
                }
                let offers = page.tickets;

                // The server only sees identities, not local friend
                // relationships. Filter offers locally, then keep at most the
                // accepted-ticket capacity worth of join/session tasks alive.
                //
                // Rosters are read at most once per room per response. A peer
                // that can enqueue many tickets for one room used to turn a
                // single poll into one `list_channel_members` query per
                // ticket, each taking the global connection lock on the
                // network loop.
                let mut rosters: HashMap<[u8; 16], Vec<[u8; 32]>> = HashMap::new();
                for offer in offers {
                    if let Some(channel_id) = offer.channel_id {
                        if state.channel_relay_outboxes.len()
                            + state.channel_relay_pending.len()
                            >= MAX_CHANNEL_RELAY_SESSIONS
                        {
                            continue;
                        }
                        let members = rosters.entry(channel_id).or_insert_with(|| {
                            channel_member_pubkeys(&db, &hex::encode(channel_id))
                        });
                        let Some(peer_pubkey) = members.iter().copied().find(|pk| {
                            let hash = ember::channel::channel_id_from_pubkey(pk);
                            rendezvous::hashed_id(&hash)
                                .eq_ignore_ascii_case(&offer.initiator_id)
                        }) else {
                            tracing::debug!(
                                "Ignoring channel relay ticket from an unknown member"
                            );
                            continue;
                        };
                        // Keyed by peer, not only by `ticket_id`. The in-flight
                        // set below is per ticket, so it never stopped a second
                        // session to the *same peer* from a different ticket —
                        // which is exactly what a mutual simultaneous offer
                        // produces, since this side's own outbound offer is in
                        // negotiation at the same time.
                        if state.channel_relay_outboxes.contains_key(&peer_pubkey)
                            || state.channel_relay_pending.contains(&peer_pubkey)
                        {
                            continue;
                        }
                        let ticket_id = offer.ticket_id;
                        if !friend_relay_ticket_sessions_in_flight.insert(ticket_id.clone()) {
                            continue;
                        }
                        state.channel_relay_pending.insert(peer_pubkey);
                        let rv_url = settings.rendezvous_url.clone();
                        let done_tx = friend_relay_ticket_session_done_tx.clone();
                        let event_tx = channel_relay_event_tx.clone();
                        let fc_our_ember_hash = ember_hash;
                        let session_id = next_channel_relay_session_id();
                        tokio::spawn(async move {
                            // Clears `channel_relay_pending` however this task
                            // ends, including the accept failures below.
                            let _session = ChannelRelaySessionGuard {
                                event_tx: event_tx.clone(),
                                peer_pubkey,
                                session_id,
                            };
                            let responder_token = match tokio::time::timeout(
                                rendezvous::FRIEND_RELAY_TICKET_ACTION_TIMEOUT,
                                rendezvous::accept_friend_relay_ticket(
                                    &rv_url,
                                    &fc_our_ember_hash,
                                    &ticket_id,
                                    &ed25519_secret_key,
                                ),
                            )
                            .await
                            {
                                Ok(Ok(token)) => token,
                                Ok(Err(e)) => {
                                    tracing::debug!("Channel relay ticket accept failed: {e}");
                                    let _ = done_tx.send(ticket_id);
                                    return;
                                }
                                Err(_) => {
                                    tracing::debug!("Channel relay ticket accept timed out");
                                    let _ = done_tx.send(ticket_id);
                                    return;
                                }
                            };
                            match ember::relay::connect_server_relay(
                                &rv_url,
                                &ticket_id,
                                &responder_token,
                            )
                            .await
                            {
                                Ok(ws) => {
                                    run_channel_relay_session(
                                        ws, peer_pubkey, session_id, event_tx,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    tracing::debug!("Channel relay ticket join failed: {e}");
                                }
                            }
                            let _ = done_tx.send(ticket_id);
                        });
                        continue;
                    }

                    if friend_relay_ticket_sessions_in_flight.len()
                        >= MAX_FRIEND_RELAY_TICKET_SESSIONS
                    {
                        break;
                    }
                    let peer_ember_hash = {
                        let friends = friend_hashes.read().await;
                        friends.iter().copied().find(|hash| {
                            rendezvous::hashed_id(hash)
                                .eq_ignore_ascii_case(&offer.initiator_id)
                        })
                    };
                    let Some(peer_ember_hash) = peer_ember_hash else {
                        tracing::debug!("Ignoring relay ticket from a non-friend identity");
                        continue;
                    };

                    let ticket_id = offer.ticket_id;
                    if !friend_relay_ticket_sessions_in_flight.insert(ticket_id.clone()) {
                        continue;
                    }

                    let rv_url = settings.rendezvous_url.clone();
                    let done_tx = friend_relay_ticket_session_done_tx.clone();
                    let fc_our_ember_hash = ember_hash;
                    let relay_inbound_tx = inbound_stream_tx.clone();

                    tokio::spawn(async move {
                        let responder_token = match tokio::time::timeout(
                            rendezvous::FRIEND_RELAY_TICKET_ACTION_TIMEOUT,
                            rendezvous::accept_friend_relay_ticket(
                                &rv_url,
                                &fc_our_ember_hash,
                                &ticket_id,
                                &ed25519_secret_key,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(token)) => token,
                            Ok(Err(e)) => {
                                tracing::debug!("Friend relay ticket accept failed: {e}");
                                let _ = done_tx.send(ticket_id);
                                return;
                            }
                            Err(_) => {
                                tracing::debug!("Friend relay ticket accept timed out");
                                let _ = done_tx.send(ticket_id);
                                return;
                            }
                        };

                        match ember::relay::connect_server_relay(
                            &rv_url,
                            &ticket_id,
                            &responder_token,
                        )
                        .await
                        {
                            Ok(ws) => {
                                let (reader, writer) = tokio::io::split(ws);
                                let addr = SocketAddr::new(
                                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                                    0,
                                );
                                if let Err(e) = relay_inbound_tx
                                    .send(upload_server::InboundStreamRequest {
                                        peer_addr: addr,
                                        reader: Box::new(reader),
                                        writer: Box::new(writer),
                                        // Social relay session: the friend that
                                        // opened it sends Hello first.
                                        serve_friend_ember_hash: None,
                                        relayed: true,
                                    })
                                    .await
                                {
                                    tracing::debug!(
                                        "Friend relay responder handoff failed for {}: {e}",
                                        hex::encode(peer_ember_hash),
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::debug!("Friend relay ticket join failed: {e}");
                            }
                        }
                        let _ = done_tx.send(ticket_id);
                    });
                }
            }

            Some(ticket_id) = friend_relay_ticket_session_done_rx.recv() => {
                friend_relay_ticket_sessions_in_flight.remove(&ticket_id);
            }

            // Periodic publishing
            _ = publish_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_publish_tick(
                    &udp_socket,
                    &mut state,
                    &local_index,
                    &settings,
                    &mut known_files,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'publish_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Punch mailbox responder. Split out of `publish_timer` so it can
            // run on a cadence shorter than the rendezvous server's 30 s punch
            // TTL, and so it no longer depends on the KAD routing table.
            _ = punch_poll_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_punch_poll_tick(
                    &state,
                    &settings,
                    &friend_hashes,
                    ember_hash,
                    ed25519_secret_key,
                    &inbound_stream_tx,
                    &mut last_punch_poll,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'punch_poll_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // eMule-compatible Kad publish scheduler. The 60s publish_timer
            // above is now only for coarse diagnostics and Ember rendezvous
            // work; this 2s arm mirrors KADEMLIAPUBLISHTIME and starts at
            // most one source, one keyword, and one note store per tick while
            // respecting the local eMule per-type active-search caps.
            _ = kad_publish_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_kad_publish_tick(
                    &mut state,
                    &local_index,
                    &settings,
                    &app_handle,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'kad_publish_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Publish-pipeline health heartbeat (10s). Only logs when at
            // least one diagnostic counter has moved since the last beat,
            // so it stays quiet at idle. Crucially this fires *between*
            // the 60s `Publish cycle:` lines, so the user can see whether
            // PublishRes packets are flowing seconds after publishes are
            // sent — not 60s later.
            _ = publish_health_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if state.stats.status == NetworkStatus::Disconnected { return; }
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
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'publish_health_timer' panicked: {}", describe_panic(&*__p));
                }
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
                let __panic_result = std::panic::AssertUnwindSafe(on_udp_discovery_health_tick(
                    &mut state,
                    &settings,
                    &friend_hashes,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &mut last_udp_discovery_health,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'udp_discovery_health_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Cleanup stale searches, expired DHT entries, and unconfirmed publishes
            _ = cleanup_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_cleanup_tick(
                    &udp_socket,
                    &mut state,
                    &settings,
                    &db,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &credit_manager,
                    &friend_hashes,
                    ember_hash,
                    &ul_event_tx,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &mut channel_queue_settled,
                    channel_sweep_cutoff,
                    &mut credit_flush_handle,
                    &credit_save_ownership,
                    &mut db_progress_last_persist,
                    &mut last_chat_expiry_sweep,
                    &mut nat_probe_in_flight,
                    &mut nat_probe_packet_tx,
                    &nat_probe_result_tx,
                    &mut nat_probe_started_at,
                    &pending_kad_callbacks,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'cleanup_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Broker tick + event drain. Used to live inside the
            // `cleanup_timer` arm (5-minute cadence), which made relay
            // events sit in the channel past their 30-second timeout.
            // 200 ms cadence is
            // small enough that punch/relay scheduling is effectively
            // event-driven and large enough that an idle tick costs
            // one `try_recv()` (returns `Empty` instantly) plus a
            // hashmap walk over at most `MAX_ACTIVE_ATTEMPTS` entries.
            _ = broker_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_broker_tick(
                    &mut state,
                    &settings,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &kad_callback_tx,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'broker_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // eMule Consolidate: merge sparse sibling leaf zones every 45 minutes
            _ = consolidate_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if state.stats.status == NetworkStatus::Disconnected { return; }
                let merged = state.routing_table.consolidate();
                if merged > 0 {
                    debug!("Consolidated {merged} zone pairs");
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'consolidate_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // eMule CKademlia::Process big timer: RandomLookup at most once per tick (~100ms cadence).
            _ = kad_process_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_kad_process_tick(
                    &udp_socket,
                    &mut state,
                    &settings,
                    &bandwidth_limiter,
                    &db,
                    &app_handle,
                    &mut xfer_finish_rx,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'kad_process_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Throttled UDP global search: send one packet per 750ms tick
            _ = udp_search_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if let Some((queued_request_id, packet, addr)) = state.udp_search_queue.pop_front() {
                    let sock = server_udp.socket_handle();
                    if let Err(e) = sock.send_to(&packet, addr).await {
                        // Most common failures are transient ICMP-unreachable
                        // (Windows: WSAECONNRESET = "An existing connection
                        // was forcibly closed") from a previous packet to a
                        // dead server. Log at debug to avoid spam; aggregate
                        // visibility is in the periodic discovery health log.
                        debug!("UDP global search send_to {addr} failed: {e}");
                    } else {
                        // eMule SentUDPRequestNotification: only accept replies
                        // from IPs we successfully queried this search.
                        if let (Some(active), IpAddr::V4(ip)) =
                            (state.active_search_request.as_mut(), addr.ip())
                        {
                            // Only if this packet was queued for the search that
                            // is running now; otherwise its reply would be
                            // admitted into a tab that never asked the question.
                            if active.udp_pending && active.request_id == queued_request_id {
                                active.udp_search_sent_ips.insert(ip);
                            }
                        }
                        if state.udp_search_queue.is_empty() {
                            debug!("UDP global search: all servers queried");
                        }
                    }
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'udp_search_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Paced UDP source-request drain: up to UDP_SOURCE_BURST_PER_TICK
            // packets per ~200ms tick. Bursting a small batch per tick
            // (rather than 1 packet per tick) matches eMule's
            // `CDownloadQueue::Process` behaviour — when a download is
            // added eMule sends a flurry of OP_GLOBGETSOURCES(2) to all
            // eligible servers in quick succession, so their replies land
            // within the first second. See the timer-definition comment
            // for the rate rationale.
            _ = udp_source_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_udp_source_tick(
                    &mut state,
                    &mut stats_manager,
                    &server_udp,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'udp_source_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // SmallTimer (eMule): probe expired contacts with HELLO_REQ, remove dead
            _ = small_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_small_tick(
                    &udp_socket,
                    &mut state,
                    &settings,
                    &app_handle,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'small_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Buddy system: find a relay buddy if firewalled (always-on, like eMule)
            _ = buddy_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_buddy_tick(
                    &udp_socket,
                    &mut state,
                    &app_handle,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'buddy_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Cleanup flood protection tracking and cap peer nicknames
            _ = flood_cleanup_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_flood_cleanup_tick(
                    &mut state,
                    &db,
                    &app_handle,
                    &mut banned_ips_sync_in_flight,
                    &banned_ips_sync_tx,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'flood_cleanup_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Retry source search for pending downloads (eMule: never auto-fail, search forever)
            _ = pathb_stats_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if let Some((in_use, max, acquires, contended)) =
                    ed2k::multi_source::global_conn_stats()
                {
                    let (detaches, diversions, rotations) =
                        ed2k::multi_source::pathb_event_counts();
                    // Only log when something has actually happened, so an idle
                    // client doesn't emit a heartbeat of zeros every minute.
                    if in_use > 0
                        || acquires > 0
                        || detaches > 0
                        || diversions > 0
                        || rotations > 0
                    {
                        info!(
                            "Path B stats: dl-conns {in_use}/{max} in use, {acquires} acquires \
                             ({contended} contended), {detaches} detaches, {diversions} push-grant \
                             diversions, {rotations} slow-source rotations",
                        );
                    }
                }
                // Friend transfer negotiation, on the same when-something-happened
                // rule. Logged as well as exposed via `get_ember_diagnostics`
                // because neither the connect-back nor the punch can be unit
                // tested, so a log trail is how a field problem gets diagnosed.
                {
                    let fs = state.friend_xfer_stats;
                    let asked = fs.connect_back_requested + fs.punch_requested;
                    if asked > 0 || fs.inbound_accepted > 0 || fs.inbound_declined > 0 {
                        info!(
                            "Friend transfer stats: asked {asked} ({} connect-back, {} punch), \
                             {} accepted, {} declined, {} connected, {} timed out; \
                             inbound {} accepted, {} declined",
                            fs.connect_back_requested,
                            fs.punch_requested,
                            fs.accepted,
                            fs.declined,
                            fs.connected,
                            fs.timed_out,
                            fs.inbound_accepted,
                            fs.inbound_declined,
                        );
                    }
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'pathb_stats_timer' panicked: {}", describe_panic(&*__p));
                }
            }
            _ = source_retry_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_source_retry_tick(
                    &udp_socket,
                    &mut state,
                    &settings,
                    &dl_event_tx,
                    &bandwidth_limiter,
                    &db,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &credit_manager,
                    &mut stats_manager,
                    &shared_banned_ips,
                    &shared_ember_payload,
                    &ember_payload_generation,
                    &geoip,
                    &friend_hashes,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &a4af_shared,
                    &pending_kad_callbacks,
                    &mut pending_lowid_callback_queue,
                    &transfer_status_writes,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'source_retry_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic credit save to database (with stale record cleanup)
            _ = credit_save_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if credit_flush_handle.as_ref().is_some_and(|handle| handle.is_finished()) {
                    if let Some(handle) = credit_flush_handle.take() {
                        if let Err(e) = handle.await {
                            warn!("Periodic credit flush task failed: {e}");
                        }
                    }
                }
                if credit_flush_handle.is_none() {
                    credit_flush_handle = Some(spawn_credit_flush(
                        credit_manager.clone(),
                        db.clone(),
                        state.data_dir.clone(),
                        true,
                        credit_save_ownership.clone(),
                    ));
                } else {
                    debug!("Skipping credit flush: previous flush is still in flight");
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'credit_save_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // A4AF swap evaluation every 8 minutes
            _ = a4af_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_a4af_tick(
                    &udp_socket,
                    &mut state,
                    &transfer_manager,
                    &source_manager,
                    &a4af_shared,
                    &pending_dl_hashes,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'a4af_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // ed2k server keep-alive, message polling, and auto-reconnect (non-blocking)
            _ = server_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_server_tick(
                    &mut state,
                    &local_index,
                    &settings,
                    &dl_event_tx,
                    &bandwidth_limiter,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &credit_manager,
                    &mut stats_manager,
                    &shared_banned_ips,
                    &shared_server_addr,
                    &shared_ember_payload,
                    &ember_payload_generation,
                    &geoip,
                    &friend_hashes,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &comment_manager,
                    &connect_serve_tx,
                    &mut last_server_activity_at,
                    &spam_filter,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'server_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Ping the next server in the list via UDP to get user/file counts
            _ = server_udp_ping_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_server_udp_ping_tick(
                    &mut state,
                    &local_index,
                    &settings,
                    &dl_event_tx,
                    &bandwidth_limiter,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &credit_manager,
                    &mut stats_manager,
                    &mut server_udp,
                    &shared_banned_ips,
                    &shared_ember_payload,
                    &ember_payload_generation,
                    &geoip,
                    &friend_hashes,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &comment_manager,
                    &mut pending_lowid_callback_queue,
                    &mut server_udp_ping_idx,
                    &spam_filter,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'server_udp_ping_timer' panicked: {}", describe_panic(&*__p));
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
                    Ok(ServerConnectResult { addr, ip, port, login_tcp_port, result: Ok((mut conn, session)) }) => {
                        // Check server IP against IP filter (eMule: FilterServerByIP)
                        if settings.filter_servers_by_ip {
                            let server_ipv4 = match addr.ip() {
                                std::net::IpAddr::V4(v4) => Some(v4),
                                std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
                            };
                            if let Some(ipv4) = server_ipv4 {
                                let skip_fail_closed = state.ip_filter.is_enabled()
                                    && !state.ip_filter.ranges_ready();
                                if !skip_fail_closed && state.ip_filter.is_blocked(ipv4) {
                                    warn!("Server {ip}:{port} blocked by IP filter, disconnecting");
                                    emit_server_log(&app_handle, &format!("Server {ip}:{port} blocked by IP filter"));
                                    conn.disconnect().await;
                                    state.server_list.record_failure(&ip, port);
                                    let met_path = state.data_dir.join("server.met");
                                    spawn_save_server_met(&state.server_list, met_path, &state.server_met_save_generation, &state.server_met_save_lock);
                                    *shared_server_addr.write().await = None;
                                    state.server_reconnect_failures =
                                        state.server_reconnect_failures.saturating_add(1);
                                    state.stats.server_status = "disconnected".to_string();
                                    let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
                                    if state.server_auto_reconnect
                                        && state.server_reconnect_failures >= AUTO_CONNECT_MAX_FAILURES
                                    {
                                        abandon_server_auto_reconnect(
                                            &mut state,
                                            &app_handle,
                                            &format!("preferred server {ip}:{port} blocked by IP filter"),
                                        );
                                    }
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
                        state.server_login_tcp_port = Some(login_tcp_port);
                        state.server_list.record_success(&ip, port);
                        state.server_connected = true;
                        ed2k::server::set_server_flags_mirror(session.server_flags);
                        state.server_reconnect_failures = 0;
                        state.preferred_ed2k_server = Some((ip.clone(), port));
                        {
                            let last = ed2k::server_list::LastEd2kServer {
                                ip: ip.clone(),
                                port,
                                name: session.server_name.clone(),
                            };
                            let last_path = state.data_dir.join("last_ed2k_server.json");
                            if let Err(e) = last.save(&last_path) {
                                warn!("Failed to persist last eD2K server: {e}");
                            }
                        }
                        last_server_activity_at = chrono::Utc::now().timestamp();
                        state.server_connected_at = last_server_activity_at;
                        state.server_addr = Some(addr);
                        *shared_server_addr.write().await = Some(addr);

                        // Cap OP_OFFERFILES at this server's soft per-client file
                        // limit, the way eMule's SendListToServer does. Looked up
                        // from the server-list metadata (ST_SOFTFILES); 0 => the
                        // 200-file default. Set before the post-login offer below.
                        let server_soft_files = state.server_list.servers().iter()
                            .find(|s| s.ip == ip && s.port == port)
                            .map(|s| s.soft_files)
                            .unwrap_or(0);
                        conn.set_soft_files(server_soft_files);

                        // HighID from server is the most reliable TCP firewall test:
                        // the server successfully connected back to our TCP port.
                        // Always update tcp_status — even when UPnP already cleared
                        // `state.firewalled` — otherwise the UI stays on Unknown
                        // until a later KAD probe cycle.
                        if !is_low && our_id >= ed2k::server::LOWID_THRESHOLD {
                            if state.firewalled {
                                info!("HighID from server confirms TCP port is open, clearing firewalled status");
                                state.firewalled = false;
                                state.firewalled_shared.store(false, std::sync::atomic::Ordering::Relaxed);
                                if state.buddy_manager.state() == BuddyState::FindingBuddy {
                                    state.buddy_manager.find_failed();
                                    info!("Cancelled buddy search: HighID proves TCP is open");
                                }
                            } else if state.firewall_checker.tcp_status()
                                != crate::network::kad::firewall::FirewallStatus::Open
                            {
                                info!("HighID from server confirms TCP port is open (updating tcp_status)");
                            }
                            // TCP Open must be recorded *before* we refresh the
                            // publish manager. `kad_source_publish_treat_as_firewalled`
                            // treats Unknown as firewalled, so an update here used
                            // to leave source publishes skipped (no buddy, no type-6)
                            // until a later unrelated refresh.
                            state.firewall_checker.handle_tcp_connect_back();
                            kad::firewall::publish_local_firewall(
                                state.firewalled,
                                state.udp_firewalled,
                            );
                            update_publish_manager_state(&mut state);
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
                            if !crate::security::is_bogus_v4(ext_ip) {
                                let was_none = state.external_ip.is_none();
                                if state.external_ip != Some(ext_ip) {
                                    info!(
                                        "External IP set from server HighID: {} (was {:?})",
                                        ext_ip, state.external_ip
                                    );
                                }
                                set_external_ip(&mut state, Some(ext_ip));
                                state.stats.external_ip = ext_ip.to_string();
                                // Server HighID is a single trusted report; route it
                                // through the dedicated 1-arg path rather than the
                                // KAD-peer-vote path (which requires a reporter IP
                                // for distinct-/24 sybil protection).
                                state.firewall_checker.handle_server_highid_response(ext_ip);
                                if was_none && state.nat_info.nat_type == ember::nat::NatType::Unknown {
                                    if !nat_probe_in_flight {
                                        info!("External IP discovered via server HighID — scheduling initial NAT probe");
                                        nat_probe_in_flight = true;
                                        nat_probe_started_at = Some(tokio::time::Instant::now());
                                        state.nat_probe_generation =
                                            state.nat_probe_generation.saturating_add(1);
                                        nat_probe_packet_tx = Some(spawn_nat_probe(
                                            udp_socket.clone(),
                                            nat_probe_result_tx.clone(),
                                            state.nat_probe_generation,
                                            "server HighID",
                                        ));
                                    }
                                }
                            }
                        } else if is_low {
                            // LowID: server could not connect back — TCP is firewalled.
                            state.firewalled = true;
                            state.firewalled_shared.store(true, std::sync::atomic::Ordering::Relaxed);
                            state.firewall_checker.note_tcp_firewalled();
                            // Hello's `supports_direct_udp_callback` reads a
                            // process atomic, not `state`. Without this a
                            // session that was HighID earlier keeps advertising
                            // "no UDP callback" while LowID, so peers that
                            // cannot dial our TCP port drop us instead of
                            // calling back over UDP.
                            kad::firewall::note_local_tcp_firewalled(true);
                            update_publish_manager_state(&mut state);
                            state.stats.firewalled = true;
                            state.stats.tcp_status = format!("{:?}", state.firewall_checker.tcp_status());
                            state.stats.udp_status = format!("{:?}", state.firewall_checker.udp_status());
                            let _ = app_handle.emit("firewall-status", serde_json::json!({
                                "firewalled": state.firewalled,
                                "external_ip": state.stats.external_ip,
                                "tcp_status": state.stats.tcp_status,
                                "udp_status": state.stats.udp_status,
                            }));
                            if session.server_reported_ip != 0 {
                                // eMule ServerSocket OP_IDCHANGE: for a LowID client the
                                // server reports our real public IP at offset 12 —
                                // `if (IsLowID(clientid) && dwServerReportedIP != 0)
                                // SetPublicIP(dwServerReportedIP)`. LowID keeps us
                                // firewalled, so unlike the HighID branch we do NOT touch
                                // firewalled status here beyond note_tcp_firewalled above;
                                // this only teaches us our external IP.
                                let ext_ip = Ipv4Addr::from(session.server_reported_ip.to_le_bytes());
                                if !crate::security::is_special_use_v4(ext_ip)
                                    && state.external_ip.is_none()
                                {
                                    set_external_ip(&mut state, Some(ext_ip));
                                    state.stats.external_ip = ext_ip.to_string();
                                    info!("External IP set from server LowID report");
                                    // Trusted single-reporter path, same as the HighID
                                    // case above (records the confirmed external IP
                                    // without the KAD distinct-/24 vote requirement).
                                    state.firewall_checker.handle_server_highid_response(ext_ip);
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
                                    spawn_save_server_met(&state.server_list, met_path, &state.server_met_save_generation, &state.server_met_save_lock);
                                }
                            }
                            // Explicitly request the server list. eMule's "Update
                            // server list when connecting" sends OP_GETSERVERLIST
                            // shortly after login because most public ed2k servers
                            // don't push the list unsolicited — they wait for the
                            // client to ask. Without this our `add_servers_from_server`
                            // setting was effectively dead for the common case.
                            if let Err(e) = conn.request_server_list().await {
                                debug!("Failed to send OP_GETSERVERLIST: {e}");
                            }
                        }

                        // Queue OP_OFFERFILES for chunked drain on later turns so
                        // firewall/server status events and GetNetworkStats can
                        // flush to the UI before a potentially large offer.
                        {
                            let mut seen_offer_hashes = std::collections::HashSet::new();
                            let (mut offer_files, restricted) = {
                                let index = local_index.read().await;
                                let restricted = collect_friends_only_hashes(&index, &known_files);
                                let offer_files: Vec<ed2k::server::OfferFile> = index
                                    .all_files()
                                    .iter()
                                    .filter(|f| {
                                        kad_may_advertise_complete(f, &known_files, &restricted)
                                    })
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
                                    .collect();
                                (offer_files, restricted)
                            };
                            let temp_dir = PathBuf::from(&settings.download_folder).join("Temp");
                            {
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
                                    if !kad_may_advertise_partial(
                                        &known_files,
                                        &restricted,
                                        &transfer.file_hash,
                                    ) {
                                        continue;
                                    }
                                    if transfer.file_hash.is_empty()
                                        || !seen_offer_hashes.insert(transfer.file_hash.clone())
                                    {
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
                            if offer_files.is_empty() {
                                warn!("No files to offer to server after login — check shared folders");
                                pending_offer_files = None;
                                pending_offer_signature = None;
                            } else {
                                // This TCP session has never published to this
                                // server. Leftover hashes from a disconnect that
                                // skipped `reset_ed2k_server_session` would make
                                // incremental skip the opening dump entirely.
                                state.offered_ed2k_hashes.clear();
                                next_offer_packet_at = None;
                                let limit = conn.offer_files_chunk_limit();
                                let signature = offer_files_signature(&offer_files);
                                let incremental =
                                    incremental_ed2k_offers(offer_files, &state.offered_ed2k_hashes);
                                info!(
                                    "Queuing {} files to offer to server ({limit} per packet)",
                                    incremental.len()
                                );
                                pending_offer_signature = Some(signature);
                                pending_offer_files = if incremental.is_empty() {
                                    state.last_offer_files_signature = Some(signature);
                                    None
                                } else {
                                    Some(incremental)
                                };
                            }
                        }

                        // eMule: request sources for incomplete downloads after
                        // server login — but NOT in the same instant we receive
                        // OP_IDCHANGE. The server is still streaming its welcome
                        // (OP_SERVERSTATUS / message / list / ident) for the next
                        // ~1-2s, and bursting OP_GETSOURCES into that window
                        // (login batch + warm-start + starved re-ask all at once)
                        // is both premature and trips Lugdunum flood protection,
                        // which then silently drops source requests. Instead, let
                        // the connection settle: fast-forward the periodic TCP
                        // source timer to fire just after `SERVER_SOURCE_SETTLE_SECS`
                        // so the first OP_GETSOURCES batch goes out once the server
                        // is ready (it already covers every pending + active
                        // download). The on-demand warm-start / starved-re-ask
                        // paths below are likewise gated on `server_connected_at`.
                        state.server_tcp_getsources_cursor = 0;
                        // A new connection carries no spent credit, so the first
                        // frame may go out as soon as the welcome has settled.
                        state.server_tcp_srcreq_next_at = 0;
                        server_tcp_source_timer.reset_after(std::time::Duration::from_secs(
                            SERVER_SOURCE_SETTLE_SECS as u64,
                        ));

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
                                    // Queue for rate-limited drain (MAX_LOWID_CALLBACKS_PER_TURN)
                                    // so login cannot monopolize the loop with N sequential awaits.
                                    let n = queue_lowid_callbacks(
                                        &mut pending_lowid_callback_queue,
                                        pending,
                                    );
                                    if n > 0 {
                                        info!(
                                            "L-2 flush: queued {n} LowID callbacks via newly-connected server {}:{}",
                                            addr.ip(), server_port_u16,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Ok(ServerConnectResult { ip, port, result: Err(e), .. }) => {
                        info!("Failed to connect to server {ip}:{port}: {e}");
                        let attempt = state.server_reconnect_failures.saturating_add(1);
                        let will_retry = state.server_auto_reconnect
                            && state.preferred_ed2k_server.as_ref().is_some_and(|(pip, pport)| {
                                pip == &ip && *pport == port
                            })
                            && attempt < AUTO_CONNECT_MAX_FAILURES;
                        if will_retry {
                            emit_server_log(
                                &app_handle,
                                &format!(
                                    "Connection failed ({e}); retrying preferred server ({attempt}/{AUTO_CONNECT_MAX_FAILURES})..."
                                ),
                            );
                        } else {
                            emit_server_log(
                                &app_handle,
                                &format!("Connection failed ({e})."),
                            );
                        }
                        state.server_reconnect_failures = attempt;
                        *shared_server_addr.write().await = None;
                        state.server_list.record_failure(&ip, port);
                        let met_path = state.data_dir.join("server.met");
                        spawn_save_server_met(&state.server_list, met_path, &state.server_met_save_generation, &state.server_met_save_lock);
                        state.stats.server_status = "disconnected".to_string();
                        let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
                        if state.server_auto_reconnect && attempt >= AUTO_CONNECT_MAX_FAILURES {
                            abandon_server_auto_reconnect(
                                &mut state,
                                &app_handle,
                                &format!("could not reach preferred server {ip}:{port}"),
                            );
                        }
                        // Keep `server_last_connect_attempt` so reconnect backoff
                        // still applies when retrying the same preferred host.
                    }
                    Err(e) => {
                        warn!("Server connection task panicked: {e}");
                        emit_server_log(&app_handle, &format!("Connection error: {e}"));
                        state.server_reconnect_failures =
                            state.server_reconnect_failures.saturating_add(1);
                        *shared_server_addr.write().await = None;
                        state.stats.server_status = "disconnected".to_string();
                        let _ = app_handle.emit("server-status-changed", serde_json::json!({ "status": "disconnected" }));
                        if state.server_auto_reconnect
                            && state.server_reconnect_failures >= AUTO_CONNECT_MAX_FAILURES
                        {
                            let detail = state
                                .preferred_ed2k_server
                                .as_ref()
                                .map(|(ip, port)| format!("could not reach preferred server {ip}:{port}"))
                                .unwrap_or_else(|| "server connection task failed".to_string());
                            abandon_server_auto_reconnect(&mut state, &app_handle, &detail);
                        }
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
                        // `OP_CALLBACK` carries the file id in CUInt128 order,
                        // the way the requester wrote it into
                        // `KADEMLIA_CALLBACK_REQ` and the way a relaying buddy
                        // forwards it. eMule's `ListenSocket` does
                        // `ToByteArray` before looking the file up; without the
                        // matching swap here the bytes never equal a pending
                        // download's ed2k hash and the source registers under a
                        // hash nothing else uses.
                        let file_hash = kad::publish::kad_id_to_md4_bytes(&KadId(file_hash));
                        info!("Buddy callback: connect to {dest_ip}:{dest_port} for file {}", hex::encode(file_hash));

                        // eMule parity (KAD buddy OP_CALLBACK -> TryToConnect -> serve): a peer
                        // reached us (LowID) through our buddy relay because it wants to interact
                        // over a connection *we* open. Dial back and serve it via the upload
                        // listener's outbound path, so a firewalled node can upload. buddy.rs
                        // already validated the callback (crypto check token, non-zero port, not
                        // special-use); we add the runtime ip-filter / ban gate here before dialing.
                        // The KAD callback carries no crypt options or user hash, so we dial plain
                        // (crypt_options=0, user_hash=None) and let the peer's Hello drive the rest.
                        // We still keep the download-direction handling below (the peer may also be
                        // a source of a file we want). Non-blocking hand-off; a full queue drops it.
                        let buddy_target_safe = !state.ip_filter.is_blocked(dest_ip)
                            && !state.banned_ips.contains(&dest_ip)
                            && connect_serve_target_ok(
                                dest_ip,
                                dest_port,
                                state.external_ip,
                                state.tcp_port,
                                advertised_tcp_port(&state),
                                None,
                                &state.user_hash,
                            );
                        if buddy_target_safe {
                            let cb_addr = SocketAddr::new(dest_ip.into(), dest_port);
                            if let Err(e) = connect_serve_tx.try_send(
                                upload_server::ConnectServeRequest {
                                    peer_addr: cb_addr,
                                    crypt_options: 0,
                                    user_hash: None,
                                    push_grant_file_hash: None,
                                    push_grant_accepted: None,
                                    secure_friend_ember_hash: None,
                                },
                            ) {
                                debug!("Could not enqueue buddy callback-serve for {cb_addr}: {e}");
                            }
                        }

                        let matching_tid = state.pending_downloads.iter()
                            .find(|(_, pd)| {
                                hex::decode(&pd.file_hash).ok()
                                    .filter(|b| b.len() == 16 && b[..] == file_hash[..])
                                    .is_some()
                            })
                            .map(|(tid, _)| tid.clone());

                        if let Some(tid) = matching_tid {
                            // Respect pause/cancel and the concurrency cap exactly as the
                            // KAD-callback arm below does. A paused download deliberately
                            // stays in `pending_downloads` with a cancelled control, so
                            // without this guard a buddy connect-back resurrected it: the
                            // worker bails at once on the cancelled control, its `Failed` is
                            // classified as a user cancel and suppressed, and the row is left
                            // `Active` with no worker and no pending entry — a slot consumed
                            // for the rest of the session that `resume()` cannot reach,
                            // because `resume` is a no-op for a row already reading `Active`.
                            // The `active` membership test additionally keeps a row still
                            // waiting in the queue from starting a worker outside its slot
                            // (`try_start_pending_download_from_known_sources` checks the
                            // same thing, since a queued download legitimately keeps a
                            // pending entry for source discovery).
                            let blocked = state
                                .pending_downloads
                                .get(&tid)
                                .map(|pd| pd.control.is_paused() || pd.control.is_cancelled())
                                .unwrap_or(true)
                                || !transfer_manager.read().await.active.contains_key(&tid);
                            if blocked {
                                debug!(
                                    "Ignoring buddy callback for {tid}: paused, cancelled, or not holding an active slot"
                                );
                            } else if let Some(pd) = state.pending_downloads.remove(&tid) {
                                let source_addr = SocketAddr::new(dest_ip.into(), dest_port);
                                info!("Starting callback download {} to {source_addr}", pd.transfer_id);

                                {
                                    let mut sm = source_manager.write().await;
                                    // A buddy callback answers a request we
                                    // made for a peer some network already
                                    // told us about, so it names no origin of
                                    // its own.
                                    sm.register_source(file_hash, dest_ip, dest_port, None);
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
                                    mpsc::channel::<ed2k::multi_source::EstablishedSource>(ESTABLISHED_SOURCE_CHANNEL_CAP);
                                let expected_aich_master =
                                    expected_aich_bytes(pd.expected_aich.as_deref());
                                let ms_download = MultiSourceDownload {
                                    transfer_id: pd.transfer_id.clone(),
                                    file_hash,
                                    file_name: pd.file_name,
                                    file_size: pd.file_size,
                                    sources: download_sources,
                                    download_dir: PathBuf::from(&settings.download_folder),
                                    user_hash: state.user_hash,
                                    nickname: settings.nickname.clone(),
                                    tcp_port: advertised_tcp_port(&state),
                                    udp_port: advertised_udp_port(&state),
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
                        ed25519_public_key: ed25519_pubkey,
                        ed25519_secret_key,
                        friend_hashes: Some(friend_hashes.clone()),
                                    ember_payload: shared_ember_payload.clone(),
                                    ember_payload_generation: ember_payload_generation.clone(),
                                    ip_filter: Some(state.shared_ip_filter.clone()),
                                    banned_ips: Some(shared_banned_ips.clone()),
                                    external_ip: state.external_ip,
                                    aich_pending: Some(state.aich_recovery_pending.clone()),
                                    trusted_aich_master: expected_aich_master
                                        .or_else(|| state.aich_root_map.get(&file_hash).copied()),
                                    expected_aich_master,
                                    ember_file_hash: state
                                        .ember_content_hashes
                                        .get(&file_hash)
                                        .map(|pin| pin.digest)
                                        .unwrap_or([0u8; 32]),
                                    geoip: geoip.clone(),
                                    tracker_registry: Some(state.tracker_registry.clone()),
                                    sx_overhead: stats_manager.sx_counters.clone(),
                                    file_req_overhead: stats_manager.file_req_counters.clone(),
                                    epx_overhead: stats_manager.epx_counters.clone(),
                                };
                                let dl_tid = ms_download.transfer_id.clone();
                                state.active_source_senders.insert(dl_tid.clone(), src_inject_tx);
                                state.active_established_senders.insert(dl_tid.clone(), est_inject_tx);
                                let tx = dl_event_tx.clone();
                                let tx2 = tx.clone();
                                if let Some(old_handle) = state.download_handles.remove(&dl_tid) {
                                    debug!("Aborting existing download task for {dl_tid} before starting callback multi-source download");
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
                            // The buddy can callback after a transfer has
                            // already left `pending_downloads` and is running
                            // as a multi-source download. Treat that as a
                            // normal newly discovered source instead of
                            // dropping it; this mirrors the KAD/server callback
                            // receiver path and keeps firewalled sources useful
                            // throughout the download, not only before the
                            // first worker starts.
                            let hash_hex = hex::encode(file_hash);
                            let matching_ids = {
                                let mgr = transfer_manager.read().await;
                                matching_active_transfer_ids_for_hash(&state, &mgr, &hash_hex)
                            };
                            if matching_ids.is_empty() {
                                debug!(
                                    "No pending or active download for buddy callback file hash {}",
                                    hash_hex
                                );
                            } else if state.dead_sources.is_dead_source_for_file(
                                &file_hash,
                                u32::from(dest_ip),
                                dest_port,
                            ) {
                                debug!(
                                    "Ignoring buddy callback from dead source {}:{} for {}",
                                    dest_ip, dest_port, hash_hex
                                );
                            } else {
                                {
                                    let mut sm = source_manager.write().await;
                                    // A buddy callback answers a request we
                                    // made for a peer some network already
                                    // told us about, so it names no origin of
                                    // its own.
                                    sm.register_source(file_hash, dest_ip, dest_port, None);
                                }
                                let source = DownloadSource {
                                    peer_ip: dest_ip.to_string(),
                                    peer_port: dest_port,
                                    available_parts: Vec::new(),
                                    peer_user_hash: None,
                                    peer_connect_options: None,
                                };
                                let stats = inject_source_into_active_transfers(
                                    &mut state,
                                    file_hash,
                                    &matching_ids,
                                    &source,
                                    0,
                                );
                                if stats.injected > 0 {
                                    info!(
                                        "Buddy callback injected {} active source(s) for {}",
                                        stats.injected, hash_hex
                                    );
                                }
                            }
                        }
                    }
                    Some(BuddyEvent::ReaskCallback { dest_ip, dest_port, file_hash }) => {
                        let hash_hex = hex::encode(file_hash);
                        let pending_match = state
                            .pending_downloads
                            .iter()
                            .find(|(_, pd)| pd.file_hash == hash_hex)
                            .map(|(tid, pd)| (tid.clone(), pd.file_size));
                        let (pending_tid, file_size) = match pending_match {
                            Some((tid, fs)) => (Some(tid), fs),
                            None => {
                                let mgr = transfer_manager.read().await;
                                (
                                    None,
                                    mgr.active.values().chain(mgr.queue.iter())
                                        .find(|t| t.file_hash == hash_hex)
                                        .map(|t| t.total_size)
                                        .unwrap_or(0),
                                )
                            }
                        };
                        let serveable_parts = match pending_tid.as_deref() {
                            Some(tid) => udp_reask_serveable_parts(&state, tid).await,
                            None => None,
                        };
                        let complete_sources = state.per_file_sources.values()
                            .find(|pfs| pfs.file_hash == file_hash)
                            .map(|pfs| pfs.complete_source_count())
                            .unwrap_or(0);
                        let addr = SocketAddr::new(dest_ip.into(), dest_port);
                        let Some(reask_payload) = ed2k::messages::build_reask_file_ping(
                            &file_hash,
                            file_size,
                            complete_sources,
                            serveable_parts.as_deref(),
                        ) else {
                            warn!("Skipping buddy UDP reask: file exceeds standard ED2K wire part-count limit");
                            continue;
                        };
                        let mut pkt = vec![OP_EMULEPROT, ed2k::messages::OP_REASKFILEPING];
                        pkt.extend_from_slice(&reask_payload);
                        // Register like the source-timer senders do: an answer to
                        // a reask that is not in this map is dropped as
                        // unsolicited by both reply branches.
                        state.pending_udp_reasks.insert(
                            (dest_ip, dest_port),
                            (file_hash, chrono::Utc::now().timestamp()),
                        );
                        let _ = udp_socket.send_to(&pkt, addr).await;
                        debug!("Sent UDP reask to {}:{} via buddy relay for file {}", dest_ip, dest_port, hash_hex);
                    }
                    Some(BuddyEvent::Disconnected) | None => {
                        // Retire the receiver unconditionally, and only ask the
                        // manager to disconnect if it still thinks it is
                        // connected. The two are not the same condition: a send
                        // helper that finds its writer dead disconnects the
                        // session itself, so by the time the channel's close
                        // reaches us the manager is already `NoBuddy`. A closed
                        // channel yields `None` from `recv()` immediately and
                        // forever, so leaving the receiver installed made this
                        // `select!` arm ready on every iteration and pinned a
                        // core at 100% for the rest of the session — something
                        // the peer could induce by accepting our connection and
                        // then stopping reading.
                        if state.buddy_manager.state() == BuddyState::Connected {
                            state.buddy_manager.disconnect_buddy().await;
                        }
                        state.buddy_event_rx = None;
                        *state.shared_buddy_info.write().await = None;
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
                        state.buddy_manager.send_pong_to_serving();
                    }
                    Some(BuddyEvent::PongReceived) => {
                        debug!("Serving buddy pong received");
                    }
                    Some(BuddyEvent::Callback { .. }) | Some(BuddyEvent::ReaskCallback { .. }) => {
                        debug!("Unexpected callback on serving side");
                    }
                    Some(BuddyEvent::Disconnected) | None => {
                        // See the outgoing-buddy arm above: the receiver has to
                        // be retired even when the manager has already stopped
                        // serving, or the closed channel spins this arm at
                        // 100% CPU. `send_pong_to_serving` and
                        // `send_callback_relay` both disconnect on a dead
                        // writer, so that ordering is the common case rather
                        // than a corner.
                        if state.buddy_manager.is_serving() {
                            state.buddy_manager.disconnect_serving();
                        }
                        state.serving_event_rx = None;
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
                    Ok(Some(conn)) => {
                        let buddy_id = conn.buddy_id;
                        let buddy_ip = conn.buddy_ip;
                        let buddy_port = conn.buddy_tcp_port;
                        let rx = state.buddy_manager.install_buddy_connection(conn);
                        state.buddy_event_rx = Some(rx);
                        // `CT_EMULE_BUDDYIP` (Hello tag 0xFC) follows the same
                        // wire convention as KAD `TAG_SERVERIP`: eMule sends
                        // `GetBuddy()->GetIP()` (raw `m_dwUserIP` = Winsock
                        // `sin_addr.s_addr` on LE = "LSB-first host integer"),
                        // and the receiver stores `m_nBuddyIP = temptag.GetInt()`
                        // with no `htonl`. For dotted-quad `a.b.c.d` we need
                        // the wire bytes to be `[a,b,c,d]`, which — because
                        // Uint32 tags LE-encode — means the integer must be
                        // `0xddccbbaa` = `u32::from_le_bytes([a,b,c,d])`.
                        // `u32::from(Ipv4Addr)` returns big-endian (`0xaabbccdd`)
                        // and would publish every buddy IP byte-reversed (the
                        // same class of bug we fixed for KAD `TAG_SERVERIP`).
                        // See `network/mod.rs::update_publish_manager` for the
                        // KAD-side counterpart and `BaseClient.cpp:955-961` /
                        // `BaseClient.cpp:441-458` in `emulesource` for the
                        // eMule send/receive code we're matching.
                        *state.shared_buddy_info.write().await = Some(ed2k::messages::BuddyInfo {
                            buddy_ip: u32::from_le_bytes(buddy_ip.octets()),
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
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if let Some((peer_hash, callback_check, reader, writer)) = buddy_conn {
                    let peer_id = KadId(peer_hash);
                    if let Some(rx) = state.buddy_manager.accept_buddy_connection(peer_id, callback_check, reader, writer) {
                        state.serving_event_rx = Some(rx);
                        info!("Accepted incoming buddy connection from {}", peer_id);
                    }
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'buddy_conn_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            // Handle callback connections: firewalled source connected back to us
            // (KAD buddy relay or server LowID callback via OP_CALLBACKREQUEST)
            cb_conn = kad_callback_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_kad_callback_conn(
                    cb_conn,
                    &mut state,
                    &settings,
                    &dl_event_tx,
                    &bandwidth_limiter,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &credit_manager,
                    &stats_manager,
                    &shared_banned_ips,
                    &shared_ember_payload,
                    &ember_payload_generation,
                    &geoip,
                    &friend_hashes,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'kad_callback_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            udp_fw_req = udp_fw_check_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
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
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'udp_fw_check_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic nodes.dat save to protect against crashes
            _ = nodes_save_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_nodes_save_tick(
                    &mut state,
                    &mut nodes_save_in_flight,
                    &mut nodes_save_started_at,
                    &periodic_save_result_tx,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'nodes_save_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // UPnP maintenance: renew leases before expiry, retry gateway
            // discovery (with backoff) if it failed at startup, re-discover
            // after a router reboot — and keep the mapped status in sync so
            // the dashboard doesn't show a stale value for the rest of the
            // session.
            _ = upnp_renew_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if upnp_enabled && !upnp_maintain_in_flight {
                    let revision = upnp_mappings.revision();
                    let mut mappings = upnp_mappings.clone();
                    let tx = upnp_maintain_result_tx.clone();
                    upnp_maintain_in_flight = true;
                    upnp_maintain_started_at = Some(tokio::time::Instant::now());
                    upnp_maintain_handle = Some(tokio::spawn(async move {
                        let mapped = mappings.maintain().await;
                        let _ = tx.send(UpnpMaintainResult {
                            revision,
                            mappings,
                            mapped,
                        });
                    }));
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'upnp_renew_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = upnp_maintain_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_upnp_maintain_result(
                    result,
                    &mut state,
                    &app_handle,
                    &mut upnp_maintain_handle,
                    &mut upnp_maintain_in_flight,
                    &mut upnp_maintain_started_at,
                    &mut upnp_mappings,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'upnp_maintain_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = nat_probe_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_nat_probe_result(
                    result,
                    &mut state,
                    &mut nat_probe_backoff_until,
                    &mut nat_probe_in_flight,
                    &mut nat_probe_packet_tx,
                    &mut nat_probe_started_at,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'nat_probe_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = udp_map_ka_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_udp_mapping_keepalive_result(
                    result,
                    &mut state,
                    &app_handle,
                    &mut mapping_ka_cycle_success,
                    tcp_map_ka_in_flight,
                    &mut udp_map_ka_gen,
                    &mut udp_map_ka_in_flight,
                    &mut udp_map_ka_packet_tx,
                    &mut udp_map_ka_started_at,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'udp_map_ka_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = tcp_map_ka_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_tcp_mapping_keepalive_result(
                    result,
                    &mut state,
                    &settings,
                    &app_handle,
                    &shared_server_addr,
                    &mut mapping_ka_cycle_success,
                    &mut tcp_map_ka_gen,
                    &mut tcp_map_ka_in_flight,
                    &mut tcp_map_ka_started_at,
                    udp_map_ka_in_flight,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'tcp_map_ka_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            _ = tokio::time::sleep_until(next_mapping_ka_at) => {
                let __panic_result = std::panic::AssertUnwindSafe(on_mapping_keepalive_tick(
                    &udp_socket,
                    &mut state,
                    &mut mapping_ka_cycle_success,
                    &mut mapping_ka_server_index,
                    &mut next_mapping_ka_at,
                    &mut tcp_map_ka_gen,
                    &mut tcp_map_ka_in_flight,
                    &tcp_map_ka_result_tx,
                    &mut tcp_map_ka_started_at,
                    &mut udp_map_ka_gen,
                    &mut udp_map_ka_in_flight,
                    &mut udp_map_ka_packet_tx,
                    &udp_map_ka_result_tx,
                    &mut udp_map_ka_started_at,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'mapping_keepalive_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = rendezvous_register_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_rendezvous_register_result(
                    result,
                    &mut state,
                    &app_handle,
                    &mut rendezvous_register_in_flight,
                    &mut rendezvous_register_started_at,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'rendezvous_register_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            // Statistics rate recording (every second)
            _ = stats_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_stats_tick(
                    &udp_socket,
                    &mut state,
                    &local_index,
                    &settings,
                    &bandwidth_limiter,
                    &db,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &mut stats_manager,
                    &mut known_files,
                    &shared_banned_ips,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &mut banned_ips_sync_in_flight,
                    &mut banned_ips_sync_rx,
                    &mut channel_neighbor_lookup_rx,
                    &channel_neighbor_lookup_tx,
                    &mut channel_relay_event_rx,
                    &channel_relay_event_tx,
                    &mut ember_digest_result_rx,
                    &mut part_hashset_result_rx,
                    &shared_ip_filter,
                    &shared_transfer_stats,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'stats_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = known_met_save_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                known_met_save_in_flight = false;
                known_met_save_started_at = None;
                match result.result {
                    Ok(true) => known_files.mark_saved_if_generation(result.generation),
                    Ok(false) => {
                        known_files.mark_save_failed();
                        warn!("known.met save completed but companion known_paths.dat was not durable; will retry");
                    }
                    Err(e) => {
                        known_files.mark_save_failed();
                        error!("Failed to save known.met: {e}");
                    }
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'known_met_save_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = periodic_save_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                let job_name = match result.job {
                    PeriodicSaveJob::Stats => {
                        stats_save_in_flight = false;
                        stats_save_started_at = None;
                        "statistics"
                    }
                    PeriodicSaveJob::Reputation => {
                        reputation_save_in_flight = false;
                        reputation_save_started_at = None;
                        if result.result.is_ok() {
                            // Only a durable write lets the next tick skip; a
                            // failed one leaves the file behind the maps.
                            reputation_saved_generation = Some(reputation_in_flight_generation);
                        }
                        "reputation.json"
                    }
                    PeriodicSaveJob::Known2 => {
                        known2_save_in_flight = false;
                        known2_save_started_at = None;
                        if result.result.is_ok() {
                            // Only a durable write lets the next tick skip; a
                            // failed one leaves the file behind the set.
                            known2_saved_len = Some(known2_in_flight_len);
                        }
                        "known2_64.met"
                    }
                    PeriodicSaveJob::Nodes => {
                        nodes_save_in_flight = false;
                        nodes_save_started_at = None;
                        "nodes.dat"
                    }
                };
                if let Err(e) = result.result {
                    error!("Failed to save {job_name}: {e}");
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'periodic_save_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            Some(result) = spam_save_result_rx.recv() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                spam_save_in_flight = false;
                spam_save_started_at = None;
                // `drain_saves` already called `mark_saved` under the gate.
                if let Err(e) = result.result {
                    warn!("Failed to save spam filter: {e}");
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'spam_save_result_rx' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic statistics save (every 60s — see stats_save_timer)
            _ = stats_save_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                if !stats_save_in_flight {
                    let pairs = stats_manager.cumulative_save_pairs();
                    let db_for_save = db.clone();
                    let tx = periodic_save_result_tx.clone();
                    stats_save_in_flight = true;
                    stats_save_started_at = Some(tokio::time::Instant::now());
                    tokio::spawn(async move {
                        let result = tokio::task::spawn_blocking(move || {
                            db_for_save.save_statistics(&pairs).map_err(|e| e.to_string())
                        })
                        .await
                        .map_err(|e| format!("statistics save task failed: {e}"))
                        .and_then(|r| r);
                        let _ = tx.send(PeriodicSaveResult {
                            job: PeriodicSaveJob::Stats,
                            result,
                        });
                    });
                }

                // Flush the spam filter's learned signals on the same cadence.
                // `auto_mark_not_spam` (completed downloads) and
                // `record_server_clean_batch` (server-reputation decay) set the
                // dirty flag but have no save path of their own; without this
                // periodic flush they'd persist only on the next user-driven
                // mark or at shutdown, and be lost on a crash. Shares
                // `SpamFilter::save_gate` with IPC mark_spam saves so the two
                // paths cannot overwrite each other out of order.
                let needs_spam_save = if !spam_save_in_flight {
                    spam_filter.read().await.is_dirty()
                } else {
                    false
                };
                if needs_spam_save {
                    spam_save_in_flight = true;
                    spam_save_started_at = Some(tokio::time::Instant::now());
                    let sf = spam_filter.clone();
                    let tx = spam_save_result_tx.clone();
                    tokio::spawn(async move {
                        let result = crate::search::spam::SpamFilter::drain_saves(&sf).await;
                        let _ = tx.send(SpamSaveResult { result });
                    });
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'stats_save_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic reputation maintenance (every 60s: lift expired
            // bans and apply the hourly score decay). `maybe_decay`
            // self-gates on DECAY_INTERVAL (1h), so calling it each minute
            // is cheap and is what actually drives decay in production —
            // this timer is the only decay trigger, so without it scores
            // would never decay. After lift, rebuild `banned_ips` from
            // durable sources + still-active reputation bans so 24h
            // reputation IPs and expired 7d auto-bans leave the enforced set.
            _ = reputation_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                state.reputation.lift_expired_bans();
                state.reputation.maybe_decay();
                // The durable half of the rebuild is read off the loop and
                // applied when it lands (see `BannedIpsSyncInputs`).
                request_banned_ips_sync(
                    &mut banned_ips_sync_in_flight,
                    &db,
                    &banned_ips_sync_tx,
                );
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'reputation_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic reputation save (every 5 minutes)
            _ = reputation_save_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                let reputation_generation = state.reputation.generation();
                if !reputation_save_in_flight
                    && reputation_saved_generation != Some(reputation_generation)
                {
                    let rep_path = state.data_dir.join("reputation.json");
                    let reputation_snapshot = state.reputation.clone();
                    let tx = periodic_save_result_tx.clone();
                    reputation_save_in_flight = true;
                    reputation_in_flight_generation = reputation_generation;
                    reputation_save_started_at = Some(tokio::time::Instant::now());
                    tokio::spawn(async move {
                        let result = tokio::task::spawn_blocking(move || {
                            reputation_snapshot.save(&rep_path)
                        })
                        .await
                        .map_err(|e| format!("reputation save task failed: {e}"))
                        .and_then(|r| r);
                        let _ = tx.send(PeriodicSaveResult {
                            job: PeriodicSaveJob::Reputation,
                            result,
                        });
                    });
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'reputation_save_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic known.met save (every 120s)
            _ = known_met_save_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_known_met_save_tick(
                    &mut state,
                    &mut known_files,
                    &mut aich_set_rx,
                    &mut known2_in_flight_len,
                    &mut known2_save_in_flight,
                    &mut known2_save_started_at,
                    known2_saved_len,
                    &mut known_met_save_in_flight,
                    &known_met_save_result_tx,
                    &mut known_met_save_started_at,
                    &periodic_save_result_tx,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'known_met_save_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Dead source cleanup (every 5 minutes)
            _ = dead_source_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                state.dead_sources.cleanup();
                let count = state.dead_sources.len();
                if count > 0 {
                    debug!("Dead source list: {count} blocked sources");
                }
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'dead_source_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Ember Peer Exchange: rebuild shared payload from active downloads + known sources
            _ = ember_refresh_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_ember_refresh_tick(
                    &mut state,
                    &local_index,
                    &settings,
                    &transfer_manager,
                    &source_manager,
                    &known_files,
                    &shared_ember_payload,
                    &ember_payload_generation,
                    ed25519_pubkey,
                    ed25519_secret_key,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'ember_refresh_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            _ = ember_flush_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(async {
                // Ahead of the empty-queue return: `prune_sent_window` otherwise
                // only ever runs from inside the flush, which writes the window
                // entries at its end — so the last flush before a node stops
                // publishing leaves its tail resident for the rest of the
                // session. Bounded either way by one window's destinations, but
                // it should be bounded by the prune, not by the table size.
                state
                    .ember_batch_publish
                    .prune_sent_window(std::time::Instant::now());
                if state.ember_batch_publish.queued.is_empty() {
                    return;
                }
                flush_ember_batch_publish(&udp_socket, &mut state).await;
                }).catch_unwind().await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'ember_flush_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            _ = ember_search_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_ember_search_tick(
                    &udp_socket,
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
                    &stats_manager,
                    &shared_banned_ips,
                    &shared_ember_payload,
                    &ember_payload_generation,
                    &geoip,
                    &friend_hashes,
                    ember_hash,
                    ed25519_pubkey,
                    ed25519_secret_key,
                    &comment_manager,
                    &connect_serve_tx,
                    &identity,
                    &pending_kad_callbacks,
                    &spam_filter,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'ember_search_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            _ = ember_maintenance_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_ember_maintenance_tick(
                    &udp_socket,
                    &mut state,
                    &settings,
                    &db,
                    &app_handle,
                    &identity,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'ember_maintenance_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            _ = source_count_sync_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_source_count_sync_tick(
                    &state,
                    &local_index,
                    &settings,
                    &app_handle,
                    &mut known_files,
                    &shared_files,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'source_count_sync_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            _ = watchdog_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_watchdog_tick(
                    &mut state,
                    &app_handle,
                    &shared_server_addr,
                    &cache_write_handle,
                    known2_save_in_flight,
                    known2_save_started_at,
                    &mut last_cache_refresh_started_at,
                    &mut last_kad_activity_at,
                    last_server_activity_at,
                    &mut nat_probe_backoff_until,
                    &mut nat_probe_in_flight,
                    &mut nat_probe_packet_tx,
                    &mut nat_probe_started_at,
                    nodes_save_in_flight,
                    nodes_save_started_at,
                    reputation_save_in_flight,
                    reputation_save_started_at,
                    &mut spam_save_in_flight,
                    &mut spam_save_started_at,
                    &mut stats_save_in_flight,
                    &mut stats_save_started_at,
                    &mut tcp_map_ka_gen,
                    &mut tcp_map_ka_in_flight,
                    &mut tcp_map_ka_started_at,
                    &mut udp_map_ka_gen,
                    &mut udp_map_ka_in_flight,
                    &mut udp_map_ka_packet_tx,
                    &mut udp_map_ka_started_at,
                    &mut upnp_maintain_handle,
                    &mut upnp_maintain_in_flight,
                    &mut upnp_maintain_started_at,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'watchdog_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Periodic UDP source requests (eMule UDPSERVERREASKTIME)
            _ = server_udp_source_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_server_udp_source_tick(
                    &mut state,
                    &transfer_manager,
                    &source_manager,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'server_udp_source_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // eMule ProcessLocalRequests(): batch TCP OP_GETSOURCES over the
            // active server connection every 4 min, up to 15 per frame.
            _ = server_tcp_source_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_server_tcp_source_tick(
                    &mut state,
                    &transfer_manager,
                    &source_manager,
                    &mut stats_manager,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'server_tcp_source_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // USS: send a KAD Ping to the selected host for RTT measurement
            _ = uss_ping_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_uss_ping_tick(
                    &udp_socket,
                    &mut state,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'uss_ping_timer' panicked: {}", describe_panic(&*__p));
                }
            }

            // Refresh shared peer/stats caches for frontend reads (non-blocking)
            _ = cache_refresh_timer.tick() => {
                let __panic_result = std::panic::AssertUnwindSafe(on_cache_refresh_tick(
                    &mut state,
                    &local_index,
                    &settings,
                    &bandwidth_limiter,
                    &db,
                    &app_handle,
                    &stats_manager,
                    &known_files,
                    &mut cache_write_handle,
                    &mut last_cache_refresh_started_at,
                    &mut last_file_snapshot_inputs,
                    &shared_connected_server,
                    &shared_contacts,
                    &shared_files,
                    &shared_peers,
                    &shared_searches,
                    &shared_servers,
                    &shared_stats,
                    &shared_transfer_stats,
                ))
                .catch_unwind()
                .await;
                if let Err(__p) = __panic_result {
                    error!("Network loop arm 'cache_refresh_timer' panicked: {}", describe_panic(&*__p));
                }
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
        error!(
            "Network event loop panicked: {}",
            describe_panic(&*panic_info)
        );
        let _ = app_handle.emit("network-error", serde_json::json!({
            "message": "Internal error in network task. The application may need to be restarted.",
        }));
    }

    // Nobody asked for this shutdown, so nobody is waiting on a deadline and the
    // one we still hold is the start-up value from `UNREQUESTED_SHUTDOWN_BUDGET`
    // ago. Start the budget now instead: the saves below are the whole reason
    // this sequence exists, and an expired global would skip every one of them
    // while logging it as a slow-disk timeout. A caller-supplied deadline is
    // left exactly as given, even if it has already elapsed — `run_graceful_
    // shutdown` bounds its own wait, and overrunning it would race the process
    // teardown it is about to perform.
    if !shutdown_requested {
        shutdown_deadline = tokio::time::Instant::now() + UNREQUESTED_SHUTDOWN_BUDGET;
        warn!(
            "Network loop exited without a shutdown command; running the save sequence on a fresh {}s budget",
            UNREQUESTED_SHUTDOWN_BUDGET.as_secs()
        );
    }

    // Apply any transfer verification the blocking pool is still working on,
    // before anything below tears down the paths its completion frame needs.
    // `finish_xfer_recv` renames the file into place on that pool, so the
    // download itself survives a quit either way — what is lost by exiting
    // early is the `XFER_DONE` frame, and the sender has no other way to learn
    // the transfer succeeded: it answers block requests and then waits, so its
    // own stall timer reports a file we actually received as failed.
    //
    // Runs before the QUIC endpoint closes because `send_xfer_frame` falls
    // back to the relay for a peer we have no direct path to. Bounded, and
    // deliberately tighter than the save phases below: this is a courtesy to
    // the sender, and a 100 MB hash on a spinning disk is not worth delaying
    // the writes that protect our own state.
    let xfer_drain_deadline =
        shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(3));
    while state.xfer_finish_in_flight > 0 {
        match tokio::time::timeout_at(xfer_drain_deadline, xfer_finish_rx.recv()).await {
            Ok(Some(finished)) => {
                apply_xfer_finish(&udp_socket, &mut state, &db, &app_handle, finished).await;
            }
            // Only `state` holds a sender, so this cannot happen while the
            // loop owns it — treat it as "nothing more is coming" regardless.
            Ok(None) => break,
            Err(_) => {
                warn!(
                    "{} Ember transfer verification(s) still hashing 3s into shutdown; \
                     the file is already saved but the sender will time it out",
                    state.xfer_finish_in_flight
                );
                break;
            }
        }
    }

    // Abort pending server connection if any
    if let Some(handle) = state.pending_server_connect.take() {
        handle.abort();
    }
    if let Some(handle) = state.pending_outgoing_buddy.take() {
        handle.abort();
    }

    // Close the QUIC endpoint so `run_quic_accept_loop` sees `accept() == None`
    // and exits, instead of lingering as a detached task (and refusing inbound
    // relay handshakes) until the process dies. This also tears down in-flight
    // relay connections gracefully.
    if let Some(endpoint) = state
        .connection_broker
        .as_ref()
        .and_then(|broker| broker.quic_endpoint())
    {
        endpoint.close(0u32.into(), b"shutting down");
    }

    if let Some(handle) = cache_write_handle.take() {
        match tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(2)),
            handle,
        )
        .await
        {
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
    tokio::time::sleep_until(shutdown_phase_deadline(
        shutdown_deadline,
        std::time::Duration::from_millis(300),
    ))
    .await;

    // Cancel and await all active download tasks. Abort every task first, then
    // await them *concurrently* under one global deadline. Awaiting each task's
    // 5s timeout sequentially made total shutdown time scale with the number of
    // active downloads, which could overrun the bounded window the UI thread
    // waits on (SHUTDOWN_WAIT in lib.rs) and let the process exit mid-save.
    let download_handles: Vec<_> = state.download_handles.drain().collect();
    for (_, handle) in &download_handles {
        handle.abort();
    }
    if !download_handles.is_empty() {
        let await_all = futures::future::join_all(download_handles.into_iter().map(
            |(tid, handle)| async move {
                match handle.await {
                    Ok(()) => debug!("Download task {tid} shut down cleanly"),
                    Err(_) => debug!("Download task {tid} cancelled/aborted"),
                }
            },
        ));
        if tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            await_all,
        )
        .await
        .is_err()
        {
            warn!("Some download tasks did not finish within the shutdown abort window");
        }
    }

    // Persist .part.met for any downloads that were in progress when aborted.
    //
    // Snapshot the registry's Arc handles, then release the registry lock
    // BEFORE awaiting each tracker's read lock. The previous non-blocking
    // `try_read()` silently skipped (and lost the resume metadata for) any
    // tracker whose worker hadn't fully released its write lock yet — the
    // download tasks are aborted just above, but an abort that landed mid
    // write-guard could still be releasing it. A short bounded `read().await`
    // waits for that hand-off instead of dropping the save, while the timeout
    // still guarantees shutdown can't hang on a genuinely stuck tracker.
    let trackers: Vec<_> = state
        .tracker_registry
        .lock()
        .iter()
        .map(|(tid, t)| (tid.clone(), t.clone()))
        .collect();
    if !trackers.is_empty() {
        let count = trackers.len();
        // Save every .part.met *concurrently* under one global deadline. Done
        // sequentially, each tracker's internal 2s+5s timeouts summed across
        // many active downloads could exceed the UI's shutdown wait and cut a
        // save off mid-write, losing resume metadata. `save_part_tracker_snapshot`
        // is self-bounded; the outer timeout is a backstop against a stall.
        let saves =
            futures::future::join_all(trackers.into_iter().map(|(tid, tracker)| async move {
                save_part_tracker_snapshot(tracker, &tid, "shutdown").await;
            }));
        if tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(8)),
            saves,
        )
        .await
        .is_err()
        {
            warn!("Timed out saving some .part.met file(s) within the shutdown window");
        }
        info!("Saved {count} download tracker(s) on shutdown");
    }
    state.active_source_senders.clear();
    // Lockstep — every download is dead at shutdown, both sender
    // maps must be cleared together (see field doc).
    state.active_established_senders.clear();
    state.active_source_overflow.clear();
    state.active_kad_search_state.clear();

    // Save all state on shutdown
    info!("Shutting down network");
    // Final Path B tally so even a short test run (under the 60 s periodic
    // cadence) always captures the queued-source-model counters.
    if let Some((in_use, max, acquires, contended)) = ed2k::multi_source::global_conn_stats() {
        let (detaches, diversions, rotations) = ed2k::multi_source::pathb_event_counts();
        info!(
            "Path B final stats: dl-conns {in_use}/{max} in use at shutdown, {acquires} acquires \
             ({contended} contended), {detaches} detaches, {diversions} push-grant diversions, \
             {rotations} slow-source rotations",
        );
    }
    let contacts = state.routing_table.export_bootstrap_contacts(200);
    let nodes_path = state.data_dir.join("nodes.dat");
    match tokio::time::timeout_at(
        shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
        state.nodes_save_lock.lock(),
    )
    .await
    {
        Ok(_ownership) => {
            if let Err(e) = bootstrap::save_nodes_dat(&nodes_path, &contacts) {
                error!("Failed to save nodes.dat: {e}");
            }
        }
        Err(_) => {
            warn!("Final nodes.dat save skipped: serialized periodic writer still owns the file")
        }
    }

    // Persist the remembered peer set (slice 7) so the next session can rejoin
    // the DHT immediately.
    //
    // The only place an address is ever forgotten, and only ever for want of
    // room. A session long enough to have pinged the peers it offered the table
    // sinks each silent one in the ranking; the trim then keeps the best
    // `EMBER_PERSIST_MAX_CONTACTS` of them, proven addresses ahead of gossip. A peer that is merely offline
    // tonight is still here tomorrow — which matters most on a small overlay,
    // where the addresses of a handful of peers who happen to be asleep are the
    // only way back in. Charging misses per save instead would turn a session
    // into five minutes and put the old ratchet back.
    let live = ember_persistable_contacts(&state);
    state.ember_bootstrap_cache.observe(live.iter());
    let now_secs = chrono::Utc::now().timestamp();
    let sunk = state.ember_bootstrap_cache.charge_silent_session(now_secs);
    let local_id = state.ember_dht.local_id();
    let dropped = state
        .ember_bootstrap_cache
        .trim_to(&local_id, EMBER_PERSIST_MAX_CONTACTS);
    let ember_contacts = state
        .ember_bootstrap_cache
        .snapshot(&local_id, EMBER_PERSIST_MAX_CONTACTS);
    info!(
        "Ember bootstrap cache: remembering {} peer(s) ({sunk} silent this session, \
         {dropped} dropped for room)",
        ember_contacts.len(),
    );
    if !ember_contacts.is_empty() {
        let ember_nodes_path = state.data_dir.join("nodes_ember.dat");
        // Wait out a periodic save that is still in flight, bounded by the shared
        // shutdown budget, and skip the write if it will not let go — exactly as
        // the nodes.dat path above does. Writing anyway would race that task on
        // the same file: whichever rename landed last would win, so the older
        // periodic snapshot could bury this newer one.
        match tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(2)),
            state.ember_nodes_save_lock.lock(),
        )
        .await
        {
            Ok(_ownership) => {
                if let Err(e) = ember::dht::bootstrap::save_nodes(
                    &ember_nodes_path,
                    &ember_contacts,
                    state.ember_nodes_file,
                ) {
                    error!("Failed to save nodes_ember.dat on shutdown: {e}");
                }
            }
            Err(_) => {
                warn!(
                    "Skipping the nodes_ember.dat shutdown save: a periodic save still holds the \
                     lock, and its snapshot is the one on disk"
                );
            }
        }
    }

    if state.ember_verified_highwater_dirty
        || state.ember_verified_highwater.alltime > 0
        || state.ember_verified_highwater.daily > 0
    {
        save_ember_verified_highwater(
            &ember_highwater_path(&state.data_dir),
            &state.ember_verified_highwater,
        );
    }

    // Persist the record store so the next session starts holding what this one
    // held. Shutdown only, deliberately: the store can be several megabytes and
    // writing that every few minutes is the disk hitch the peer-list save was
    // changed to avoid. An abnormal exit falls back to replication refilling the
    // store, which is what happened on every exit before this.
    let ember_records = state
        .ember_dht
        .persistable_records(EMBER_PERSIST_MAX_RECORDS);
    let store_ember_path = state.data_dir.join("store_ember.dat");
    let ember_store_loaded = state.ember_store_loaded;
    if tokio::time::Instant::now() >= shutdown_deadline {
        error!(
            "Shutdown deadline exhausted before store_ember.dat save; shutdown result is explicitly truncated"
        );
    } else {
        let writer = tokio::task::spawn_blocking(move || {
            ember::dht::bootstrap::save_store(
                &store_ember_path,
                &ember_records,
                ember_store_loaded,
            )
        });
        match tokio::time::timeout_at(shutdown_deadline, writer).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => error!("Failed to save store_ember.dat on shutdown: {e}"),
            Ok(Err(e)) => error!("store_ember.dat shutdown writer failed: {e}"),
            Err(_) => error!(
                "Shutdown deadline exhausted joining store_ember.dat writer; shutdown result is explicitly truncated"
            ),
        }
    }

    // Drain any in-flight periodic statistics save before the final write.
    // The 60s timer spawns a detached `spawn_blocking` with a snapshot of
    // `cumulative_save_pairs()` — the same stale-overwrite race we already
    // document for known.met. If that task lands after this final save, it
    // silently rolls back session bytes (and completed counts) accrued
    // after the snapshot was taken.
    if stats_save_in_flight {
        let deadline =
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5));
        while stats_save_in_flight {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                warn!(
                    "Periodic statistics save still in flight 5s into shutdown; \
                     proceeding with the final save anyway"
                );
                break;
            }
            match tokio::time::timeout(remaining, periodic_save_result_rx.recv()).await {
                Ok(Some(result)) => match result.job {
                    PeriodicSaveJob::Stats => {
                        stats_save_in_flight = false;
                        if let Err(e) = result.result {
                            error!("Periodic statistics save (drained at shutdown) failed: {e}");
                        }
                    }
                    // Sibling periodic jobs may finish while we wait for Stats;
                    // update their flags too so the authoritative shutdown
                    // writers below know those stale snapshots are joined.
                    other => {
                        match other {
                            PeriodicSaveJob::Reputation => reputation_save_in_flight = false,
                            // Known2 belongs here too: consuming its completion
                            // while leaving the flag set left the join below
                            // waiting on a message already taken, which burns its
                            // wait and can push the later sources.met/server.met
                            // saves past the global deadline.
                            PeriodicSaveJob::Known2 => known2_save_in_flight = false,
                            PeriodicSaveJob::Nodes => {}
                            PeriodicSaveJob::Stats => unreachable!(),
                        }
                        if let Err(e) = result.result {
                            let name = match other {
                                PeriodicSaveJob::Reputation => "reputation.json",
                                PeriodicSaveJob::Known2 => "known2_64.met",
                                PeriodicSaveJob::Nodes => "nodes.dat",
                                PeriodicSaveJob::Stats => unreachable!(),
                            };
                            error!("Periodic {name} save (drained at shutdown) failed: {e}");
                        }
                    }
                },
                Ok(None) => break,
                Err(_) => {
                    warn!(
                        "Periodic statistics save still in flight 5s into shutdown; \
                         proceeding with the final save anyway"
                    );
                    break;
                }
            }
        }
    }

    stats_manager.save_cumulative(&db);
    info!("Statistics saved on shutdown");

    // Drain any in-flight periodic known.met background save before doing
    // this shutdown's own authoritative save below. `known_met_save_timer`
    // (every 120s) spawns each save via a detached `tokio::spawn` holding
    // its own up-to-120s-old clone of `known_files` — breaking out of the
    // event loop on `Shutdown` does not wait for it. Left alone, that
    // background task's `atomic_write`/rename can land *after* the
    // checkpoint+save below and silently revert it to the stale snapshot,
    // reintroducing the exact "AICH rehash restarts from scratch" bug this
    // checkpoint exists to fix — intermittently, only when a save happened
    // to be in flight at quit time. Bounded so a genuinely stuck save can't
    // hang shutdown.
    if known_met_save_in_flight {
        match tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            known_met_save_result_rx.recv(),
        )
        .await
        {
            Ok(Some(result)) => match result.result {
                Ok(true) => known_files.mark_saved_if_generation(result.generation),
                Ok(false) => known_files.mark_save_failed(),
                Err(e) => {
                    known_files.mark_save_failed();
                    error!("Periodic known.met save (drained at shutdown) failed: {e}");
                }
            },
            Ok(None) => {}
            Err(_) => {
                warn!(
                    "Periodic known.met save still in flight 5s into shutdown; \
                     proceeding with the final save anyway"
                );
            }
        }
    }

    // Final digest checkpoint before the shutdown save: fold any freshly
    // recomputed AICH roots and Ember BLAKE3 digests from the live index into
    // known.met so a hash pass interrupted by this shutdown (either one-time
    // migration re-hash) resumes next launch instead of restarting. This
    // mirrors the digest arms of the SharedFilesChanged reconcile, minus the
    // publish-set rebuild that's pointless during shutdown, and preserves
    // every other field.
    {
        let idx = local_index.read().await;
        let mut any_updated = false;
        for f in idx.all_files() {
            if f.hash.is_empty() || (f.aich_hash.is_empty() && f.ember_file_hash.is_empty()) {
                continue;
            }
            if let Ok(hb) = hex::decode(&f.hash) {
                if hb.len() == 16 {
                    let mut fh = [0u8; 16];
                    fh.copy_from_slice(&hb);
                    if let Some(record) = known_files.find_by_hash_mut(&fh) {
                        if !f.aich_hash.is_empty() && record.aich_hash != f.aich_hash {
                            record.aich_hash = f.aich_hash.clone();
                            any_updated = true;
                        }
                        if !f.ember_file_hash.is_empty()
                            && record.ember_file_hash != f.ember_file_hash
                        {
                            record.ember_file_hash = f.ember_file_hash.clone();
                            any_updated = true;
                        }
                    }
                }
            }
        }
        if any_updated {
            known_files.mark_dirty();
        }
    }

    let known_path = state.data_dir.join("known.met");
    sync_ember_publish_to_known(
        &state.ember_source_publish_unix,
        &state.ember_keyword_publish_unix,
        &mut known_files,
    );
    match tokio::time::timeout_at(
        shutdown_phase_deadline(
            shutdown_deadline,
            std::time::Duration::from_secs(5),
        ),
        state.known_met_save_lock.lock(),
    )
    .await
    {
        Ok(_ownership) => {
            if let Err(e) = known_files.save(&known_path) {
                error!("Failed to save known.met on shutdown: {e}");
            }
        }
        Err(_) => warn!(
            "Final known.met save skipped: serialized periodic writer still owns the file; refusing a racing overwrite"
        ),
    }
    // Drain remaining AICH sets, but honour the same cap as the
    // periodic timer — we don't want shutdown to be the one place
    // that silently writes a known2_64.met file larger than every
    // subsequent startup is willing to load.
    let mut shutdown_dropped = 0usize;
    while let Ok(hs) = aich_set_rx.try_recv() {
        if state.aich_hash_sets.len() >= MAX_AICH_HASH_SETS {
            shutdown_dropped = shutdown_dropped.saturating_add(1);
            continue;
        }
        state.aich_hash_sets.push(hs);
    }
    if shutdown_dropped > 0 {
        warn!(
            "Shutdown drain hit AICH cap {}; dropped {} new set(s)",
            MAX_AICH_HASH_SETS, shutdown_dropped,
        );
    }
    if !state.aich_hash_sets.is_empty() {
        // Wait out a periodic writer still in flight. Every sibling shutdown
        // save drains its in-flight flag or takes its lock; this one did
        // neither, so a 120-second periodic save that happened to be running
        // could rename its older snapshot over the one written here. The
        // writes are atomic, so the file could not be corrupted — but the
        // shutdown snapshot is strictly newer (it drains `aich_set_rx` just
        // above), and losing it discards the AICH recovery sets computed
        // since that save began.
        if known2_save_in_flight {
            // Charged to the shared shutdown budget like every sibling phase. A
            // bare 5s of wall clock was not deducted from any phase but still
            // advanced the clock, so it could silently consume the headroom the
            // reputation / sources.met / server.met saves below depend on.
            let known2_join_deadline =
                shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5));
            while known2_save_in_flight && tokio::time::Instant::now() < known2_join_deadline {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    periodic_save_result_rx.recv(),
                )
                .await
                {
                    Ok(Some(result)) => {
                        // One shared channel carries every periodic save, so clear
                        // whichever flag this result belongs to. Dropping a
                        // sibling's completion left its own join below waiting on a
                        // message already consumed here, burning that phase's slice
                        // of the *shared* shutdown budget and reporting it as a
                        // deadline exhaustion — which can then push the later
                        // sources.met / server.met saves past the global deadline.
                        match result.job {
                            PeriodicSaveJob::Known2 => known2_save_in_flight = false,
                            PeriodicSaveJob::Reputation => reputation_save_in_flight = false,
                            PeriodicSaveJob::Nodes | PeriodicSaveJob::Stats => {}
                        }
                        if let Err(error) = result.result {
                            error!("Periodic shutdown writer failed before final save: {error}");
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {}
                }
            }
            if known2_save_in_flight {
                warn!(
                    "Periodic known2_64.met save still in flight 5s into shutdown; \
                     writing the final snapshot anyway"
                );
            }
        }
        let known2_path = state.data_dir.join("known2_64.met");
        let hash_sets = state.aich_hash_sets.clone();
        let hash_set_count = hash_sets.len();
        if tokio::time::Instant::now() >= shutdown_deadline {
            error!(
                "Shutdown deadline exhausted before known2_64.met save; shutdown result is explicitly truncated"
            );
        } else {
            let writer = tokio::task::spawn_blocking(move || {
                ed2k::aich::save_known2_met(&known2_path, &hash_sets)
            });
            match tokio::time::timeout_at(shutdown_deadline, writer).await {
                Ok(Ok(Ok(()))) => info!(
                    "Saved {hash_set_count} AICH hash sets to known2_64.met"
                ),
                Ok(Ok(Err(e))) => error!("Failed to save known2_64.met on shutdown: {e}"),
                Ok(Err(e)) => error!("known2_64.met shutdown writer failed: {e}"),
                Err(_) => error!(
                    "Shutdown deadline exhausted joining known2_64.met writer; shutdown result is explicitly truncated"
                ),
            }
        }
    }
    if let Some(mut handle) = credit_flush_handle.take() {
        if tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            &mut handle,
        )
        .await
        .is_err()
        {
            warn!(
                "Periodic credit flush still running at shutdown; aborting its async owner and retrying the final flush through serialized save ownership"
            );
            handle.abort();
            let _ = handle.await;
        }
    }
    match tokio::time::timeout_at(
        shutdown_phase_deadline(
            shutdown_deadline,
            std::time::Duration::from_secs(8),
        ),
        flush_credit_state(
            &credit_manager,
            &db,
            &state.data_dir,
            true,
            &credit_save_ownership,
        ),
    )
    .await
    {
        Ok(()) => info!("Credit state saved on shutdown"),
        Err(_) => warn!(
            "Final credit flush could not acquire/finish serialized save ownership within shutdown timeout"
        ),
    }

    // Reputation carries active automatic bans. Join any stale periodic
    // writer before the final authoritative snapshot so it cannot rename an
    // older ban set over the shutdown save.
    let reputation_join_deadline =
        shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5));
    while reputation_save_in_flight {
        match tokio::time::timeout_at(reputation_join_deadline, periodic_save_result_rx.recv())
            .await
        {
            Ok(Some(result)) => {
                match result.job {
                    PeriodicSaveJob::Reputation => reputation_save_in_flight = false,
                    PeriodicSaveJob::Known2 | PeriodicSaveJob::Nodes | PeriodicSaveJob::Stats => {}
                }
                if let Err(error) = result.result {
                    error!("Periodic shutdown writer failed before final save: {error}");
                }
            }
            Ok(None) => break,
            Err(_) => {
                error!(
                    "Shutdown deadline exhausted joining the periodic reputation/ban writer; shutdown result is explicitly truncated"
                );
                break;
            }
        }
    }

    let rep_path = state.data_dir.join("reputation.json");
    if tokio::time::Instant::now() >= shutdown_deadline {
        error!(
            "Shutdown deadline exhausted before reputation/ban save; shutdown result is explicitly truncated"
        );
    } else {
        let reputation_snapshot = state.reputation.clone();
        let tracked = reputation_snapshot.tracked_count();
        let writer = tokio::task::spawn_blocking(move || reputation_snapshot.save(&rep_path));
        match tokio::time::timeout_at(shutdown_deadline, writer).await {
            Ok(Ok(Ok(()))) => {
                info!("Reputation data saved on shutdown ({tracked} peers tracked)")
            }
            Ok(Ok(Err(error))) => {
                error!("Failed to save reputation.json on shutdown: {error}")
            }
            Ok(Err(error)) => error!("Reputation shutdown writer failed: {error}"),
            Err(_) => error!(
                "Shutdown deadline exhausted joining reputation/ban writer; shutdown result is explicitly truncated"
            ),
        }
    }

    // Persist the source cache (peer user hashes + crypt options) so the next
    // session can obfuscate connections to the same crypt-required peers
    // immediately, mirroring eMule's persisted source identities.
    if tokio::time::Instant::now() < shutdown_deadline {
        let sources_met = state.data_dir.join("sources.met");
        let source_snapshot = source_manager.read().await.clone();
        let writer =
            tokio::task::spawn_blocking(move || source_snapshot.save_to_disk(&sources_met));
        match tokio::time::timeout_at(shutdown_deadline, writer).await {
            Ok(Ok(Ok(count))) => {
                info!("Saved {count} cached sources (with user hashes) to sources.met")
            }
            Ok(Ok(Err(error))) => error!("Failed to save sources.met on shutdown: {error}"),
            Ok(Err(error)) => error!("sources.met shutdown writer failed: {error}"),
            Err(_) => error!(
                "Shutdown deadline exhausted joining sources.met writer; shutdown result is explicitly truncated"
            ),
        }
    } else {
        error!(
            "Shutdown deadline exhausted before sources.met; shutdown result is explicitly truncated"
        );
    }

    let server_met_path = state.data_dir.join("server.met");
    if tokio::time::Instant::now() < shutdown_deadline {
        match state.server_list.to_server_met_bytes() {
            Ok(bytes) => {
                let generation = state.server_met_save_generation.clone();
                let save_lock = state.server_met_save_lock.clone();
                let gen = generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let writer = tokio::task::spawn_blocking(move || {
                    let _guard = match save_lock.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if generation.load(std::sync::atomic::Ordering::Relaxed) != gen {
                        return Ok(());
                    }
                    ed2k::server_list::ServerList::write_server_met_bytes(&server_met_path, &bytes)
                });
                match tokio::time::timeout_at(shutdown_deadline, writer).await {
                    Ok(Ok(Ok(()))) => info!("server.met writer joined on shutdown"),
                    Ok(Ok(Err(error))) => {
                        error!("Failed to save server.met on shutdown: {error}")
                    }
                    Ok(Err(error)) => error!("server.met shutdown writer failed: {error}"),
                    Err(_) => error!(
                        "Shutdown deadline exhausted while joining server.met writer; shutdown result is explicitly truncated"
                    ),
                }
            }
            Err(error) => error!("Failed to serialize server.met on shutdown: {error}"),
        }
    } else {
        error!(
            "Shutdown deadline exhausted before server.met; shutdown result is explicitly truncated"
        );
    }

    // Unregister from the rendezvous server LAST and with a short bound.
    // This is a best-effort courtesy call to a remote host that may be slow
    // or unreachable; running it before the local saves above (with the
    // client's full 10s request timeout) could exhaust the app's ~12s
    // shutdown budget and cut off nodes.dat / known.met / credit / reputation
    // persistence. All local state is already on disk by this point, so a slow
    // unregister can no longer cost us durability.
    if state.rendezvous_registered {
        let rv_url = settings.rendezvous_url.clone();
        let rv_hash = ember_hash;
        match tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(3)),
            rendezvous::unregister(&rv_url, &rv_hash, &ed25519_secret_key),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => debug!("Failed to unregister from rendezvous server: {e}"),
            Err(_) => debug!("Rendezvous unregister timed out on shutdown; skipping"),
        }
    }

    if upnp_enabled {
        // Best-effort removal; don't let an unresponsive gateway stall app
        // shutdown on TCP connect timeouts. Timed leases expire on their own
        // within the hour, and permanent-lease mappings (the error-725
        // fallback) are reclaimed by the next session's conflict handling.
        let _ = tokio::time::timeout_at(
            shutdown_phase_deadline(shutdown_deadline, std::time::Duration::from_secs(5)),
            upnp_mappings.teardown(),
        )
        .await;
    }

    Ok(())
}
