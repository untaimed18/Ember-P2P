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
pub(crate) mod friend_intro;
mod friend_transfer;
mod friends;
mod health;
mod host_port_map;
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
mod shares_browsed;
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
use self::ed2k::server::{Ed2kServerConnection, ServerLink};
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
use self::host_port_map::HostPortMap;
use self::ember_publish::{
    ember_batch_ack_deadline, EmberBatchInFlight, EmberBatchPublisher, EmberFlushStats,
    EmberProxyBuddyPacer, EmberPublishAttempts, EmberPublishKind, EmberPublishPassStats, EmberRecordRef,
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
pub(crate) use self::persistence::write_ipfilter_dat_superseding;
use self::publishing::*;
use self::search::*;
use self::server::*;
use self::settings::*;
use self::shares_browsed::*;
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
    let (xfer_stream_tx, xfer_stream_rx) = mpsc::unbounded_channel::<StreamFetchOutcome>();

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
        server_search_more_due_at: None,
        server_search_more_requests: 0,
        server_followup_search: None,
        server_followup_due_at: None,
        server_poll_count: 0,
        server_search_age: 0,
        server_udp_search_age: 0,
        udp_search_queue: VecDeque::new(),
        download_source_searches: HashMap::new(),
        source_search_stream_cursor: HashMap::new(),
        evicted_kad_sources: Vec::new(),
        pending_downloads: HashMap::new(),
        data_dir: data_dir.clone(),
        known_met_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        server_met_save_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        server_met_save_lock: Arc::new(std::sync::Mutex::new(())),
        nodes_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        ember_nodes_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        ember_highwater_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        ember_source_address_save_lock: Arc::new(tokio::sync::Mutex::new(())),
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
        kad_outbound: parking_lot::Mutex::new(kad::outbound::KadOutboundGovernor::new()),
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
        server_tcp_srcreq_file_at: HashMap::new(),
        server_tcp_srcreq_asks: VecDeque::new(),
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
        restored_upload_queue: ed2k::upload_queue_store::restore(&data_dir),
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
        pending_known2_sets: Vec::new(),
        upload_max_slots: Arc::new(std::sync::atomic::AtomicUsize::new(
            settings.max_concurrent_uploads as usize,
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
        known_ember_peers: HostPortMap::new(),
        ember_noise_keys: HashMap::new(),
        ember_keyless_peers: HostPortMap::new(),
        ember_session_dht_contacts: HostPortMap::new(),
        ember_rendezvous_published_at: 0,
        ember_rendezvous_search: None,
        ember_rendezvous_looked_up_at: 0,
        ember_rendezvous_empty_streak: 0,
        ember_announced_at: HashMap::new(),
        ember_publish_unplaced: HashMap::new(),
        ember_publish_placed: HashSet::new(),
        ember_publish_partial: HashSet::new(),
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
        ember_maint_last_run: None,
        ember_stale_purge_held_until: 0,
        ember_session_hold_pinged: HashSet::new(),
        ember_publish_targets: HashMap::new(),
        ember_publish_target_queue: std::collections::VecDeque::new(),
        ember_publish_target_lookups: HashMap::new(),
        ember_store_loaded: false,
        ember_reach_witness: None,
        ember_udp_reachable_at: None,
        ember_reach_external_ip: None,
        ember_source_address: EmberSourceAddress::default(),
        ember_source_address_dirty: false,
        shares_browsed_seen: HashMap::new(),
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
        rendezvous_force_register_at: None,
        outbound_session_tasks: HashMap::new(),
        friend_search_initial_done: false,
        friend_search_initial_queue: Vec::new(),
        friend_search_started_at: None,
        friend_search_waiting_since: None,
        friend_search_followup_at: None,
        friend_search_followup_done: false,
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
        ember_named_source_buddy: None,
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
        pending_direct_callbacks: Vec::new(),
        direct_callback_requests: HashMap::new(),
        ember_pending_proxy_overlay: HashMap::new(),
        ember_proxy_buddies: EmberProxyBuddyPacer::default(),
        channel_gossip_seen: HashMap::new(),
        channel_gossip_seen_order: VecDeque::new(),
        channel_history_sync_times: HashMap::new(),
        channel_typing_recv_times: HashMap::new(),
        channel_typing_sent_times: HashMap::new(),
        channel_gossip_sent_times: VecDeque::new(),
        channel_gossip_local_times: VecDeque::new(),
        channel_origin_retry: VecDeque::new(),
        channel_delivery_notes: VecDeque::new(),
        channel_delivery_sink: (db.clone(), app_handle.clone()),
        channel_gossip_from_times: HashMap::new(),
        channel_view_cache: HashMap::new(),
        channel_gossip_author_times: HashMap::new(),
        channel_history_sync_at: HashMap::new(),
        channel_history_sync_failures: HashMap::new(),
        channel_handoff_publishes: HashMap::new(),
        channel_handoff_completing: Arc::new(std::sync::Mutex::new(HashSet::new())),
        channel_handoff_failure_noted: HashSet::new(),
        channel_history_sync_mark: HashMap::new(),
        channel_history_sync_ingested: HashMap::new(),
        ember_channel_presence_searches: HashMap::new(),
        ember_channel_presence_buffer: HashMap::new(),
        ember_pending_channel_presence: Vec::new(),
        ember_channel_ingest: None,
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
        xfer_finishing: HashMap::new(),
        channel_member_touches: HashMap::new(),
        xfer_pending: HashMap::new(),
        xfer_grants: Default::default(),
        xfer_stream_ports: HashMap::new(),
        xfer_streams: HashMap::new(),
        xfer_stream_tx,
        xfer_stream_rx,
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
                // A corrupt file would otherwise wedge saving forever:
                // `ember_nodes_file` stays `Unread` on every launch, so the
                // save guard refuses every write and the node can never
                // persist a contact again. A newer build's file or a failed
                // read is left alone and stays guarded instead.
                state.ember_nodes_file =
                    ember::dht::bootstrap::settle_unloadable_nodes(&nodes_ember_path, &e);
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
    state.ember_source_address = load_ember_source_address(&ember_source_address_path(&data_dir));

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
    ed2k::multi_source::set_new_connections_per_five(
        settings.max_connections_per_five_secs as usize,
    );

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
        // Still-banned identities are refused by user hash, and the addresses
        // they were caught on are in IP reputation (see
        // `apply_enforced_banned_ips` for why cached source rows are not).
        for ip in state.reputation.currently_banned_ips() {
            state.banned_ips.insert(ip);
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
                seen_ip,
            ) in records
            {
                // Built here and adopted by `insert_loaded_credit` rather
                // than via `get_or_create`, which would bump `last_seen` to
                // "now" and index it there, so cap eviction and the 90-day
                // prune would both misjudge the record's real age.
                let mut record = ed2k::credits::CreditRecord::new(hash);
                record.uploaded = uploaded;
                record.downloaded = downloaded;
                record.last_seen = last_seen;
                record.public_key = public_key;
                // Restore SecureIdent state so the Known Clients tab keeps the
                // peer's last-known IP and country flag (both derived from
                // ident_ip) across restarts instead of blanking until the peer
                // reconnects.
                record.ident_ip = ident_ip;
                // Identification is per session, as in eMule, which loads a
                // keyed record as IS_IDNEEDED (`ClientCredits.cpp:293-302`).
                // Restoring `Verified` with its old IP made a peer that later
                // regenerated its key and moved address a permanent BadGuy
                // (queue score 0): its new signatures never verify, so the
                // stale pin was never replaced.
                record.ident_state = match ed2k::credits::IdentState::from_u8(ident_state) {
                    ed2k::credits::IdentState::Verified | ed2k::credits::IdentState::Failed => {
                        ed2k::credits::IdentState::Needed
                    }
                    other => other,
                };
                record.ember_hash = ember_hash;
                // Assigning `ident_state` directly bypasses `set_ident_state`,
                // which is what makes the anchor sticky in memory — so it has
                // to be restored explicitly. Without this every record loads
                // unanchored and the anti-theft reset wipes each peer's totals
                // on their first verification after a restart.
                record.crypto_verified_once = crypto_verified_once;
                record.peer_name = peer_name;
                record.client_software = client_software;
                record.seen_ip = seen_ip;
                cm.insert_loaded_credit(record);
            }
            info!(
                "Loaded {} credit records from database",
                cm.all_records().len()
            );
        }
        // Ember credit records live in a separate v15 table, loaded the
        // same way as the eMule table above.
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
                let mut record = ed2k::credits::EmberCreditRecord::new(pk);
                record.uploaded = up;
                record.downloaded = down;
                record.last_upload_time = last_up;
                record.last_download_time = last_down;
                record.completed_sessions = completed;
                record.total_sessions = total;
                record.avg_upload_speed = avg_speed;
                record.last_seen = last_seen;
                record.ident_verified = verified;
                cm.insert_loaded_ember_credit(record);
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
        // L6: the startup prune reaches disk through the first
        // `credit_save_timer` tick, which completes immediately on loop entry
        // (the prune marked the manager dirty). No flush is spawned here:
        // one outside `credit_flush_handle` could overlap the periodic and
        // shutdown flushes instead of being serialized with them.
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
    // A restart for an update goes back to the server the user was on, whether
    // or not auto-connect is set: they were connected a minute ago.
    let mut resume_server = crate::auto_update::resume::take_resume_server();
    let mut pending_auto_connect_server = settings.auto_connect_server || resume_server.is_some();
    // After a successful login, OP_OFFERFILES is queued into pending_offer_files
    // (declared with other deferred startup state) and drained one chunk/turn.

    let shared_ember_payload: ember::SharedEmberPayload =
        Arc::new(RwLock::new(Arc::new(Vec::new())));
    let ember_payload_generation: ember::EmberPayloadGeneration =
        Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Upload queue shared between the upload listener (owner/writer) and
    // the UDP reask-ack handler (reader that needs to answer the real queue
    // rank for a peer pinging us over UDP). Holding the shared handle here
    // avoids a placeholder 0 rank reply. Whoever was still waiting when the
    // last session shut down rejoins it once the library has loaded
    // (`state.restored_upload_queue`).
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
        let ul_file_streams = Some(ember::relay::FileStreamServe {
            chat: ember::relay::AttachServeContext {
                db: db.clone(),
                our_ed25519_seed: ed25519_secret_key,
                app_handle: app_handle.clone(),
            },
            room: ember::relay::RoomXferServeContext {
                grants: state.xfer_grants.clone(),
            },
        });
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
                ul_file_streams,
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
    // Minutes since the upload queue line last went out when only its size had
    // anything to say.
    let mut queue_report_quiet_minutes: u32 = 0;
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
    // Dirty check for the periodic reputation save: the generation the
    // last *durable* reputation write covered, and the one the in-flight write
    // is carrying. On a long-lived node the peer/IP maps sit near their 20k cap
    // and rarely change between 5-minute ticks, so without this the timer
    // cloned 20k entries and fsync'd ~2 MB of identical JSON 288 times a day.
    let mut reputation_saved_generation: Option<u64> = None;
    let mut reputation_in_flight_generation: u64 = 0;
    let mut known2_save_in_flight = false;
    let mut known2_save_started_at: Option<tokio::time::Instant> = None;
    // How many of the front of `pending_known2_sets` the in-flight append
    // carries; a successful append drains exactly that many.
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

            let known2 = match ed2k::aich::Known2Store::open(&known2_met_path) {
                Ok(store) => {
                    info!("Indexed {} AICH hash sets in known2_64.met", store.len());
                    Some(store)
                }
                Err(e) => {
                    // Not installed, so appends queue and are retried rather
                    // than written over a file this build could not read.
                    warn!("Failed to index known2_64.met: {e}");
                    None
                }
            };

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
                known2,
                aich_root_map,
            }
        }))
    };

    // Rate-limited LowID callback flush after login (avoid monopolizing the loop).
    let mut pending_lowid_callback_queue: std::collections::VecDeque<([u8; 16], u32)> =
        std::collections::VecDeque::new();
    let mut next_lowid_callback_at = tokio::time::Instant::now();
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
                    apply_settings_update(
                        &udp_socket,
                        &mut state,
                        &mut settings,
                        new_settings,
                        &db,
                        &identity,
                        &app_handle,
                        &shared_nickname,
                        &source_manager,
                        &shared_server_addr,
                    )
                    .await;
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

        apply_deferred_disk_loads(
            &mut state,
            &local_index,
            &settings,
            &app_handle,
            &transfer_manager,
            &mut known_files,
            &shared_friends_only_hashes,
            &shared_server_addr,
            &mut deferred_disk_loads,
            &mut known_met_ready,
        )
        .await;

        resume_incomplete_downloads(
            &mut state,
            &local_index,
            &settings,
            &dl_event_tx,
            &db,
            &transfer_manager,
            &known_files,
            known_met_ready,
            &mut part_progress_map,
            &mut part_progress_task,
            &mut pending_incomplete_downloads,
            &mut startup_download_admission,
        )
        .await;

        if pending_startup_cleanup
            && pending_incomplete_downloads.is_none()
            && part_progress_task.is_none()
            && part_progress_map.is_none()
        {
            pending_startup_cleanup = false;
            {
                let mut known_ids: std::collections::HashSet<String> = {
                    let mgr = transfer_manager.read().await;
                    mgr.get_all().into_iter().map(|t| t.id).collect()
                };
                // Room receives accepted since startup own their part files.
                known_ids.extend(
                    state
                        .xfer_recv
                        .keys()
                        .chain(state.xfer_finishing.keys())
                        .map(|id| format!("ember-xfer-{}", hex::encode(id))),
                );
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

        drain_offer_files(
            &mut state,
            &local_index,
            &settings,
            &transfer_manager,
            &known_files,
            &mut next_offer_packet_at,
            &mut pending_offer_files,
            &mut pending_offer_signature,
        )
        .await;

        // Rate-limit LowID callback requests after login / poll bursts. Every
        // producer feeds this queue through `queue_lowid_callbacks` (capped at
        // MAX_PENDING_LOWID_CALLBACKS) rather than writing to the server itself.
        if !pending_lowid_callback_queue.is_empty()
            && state.server_connected
            && !state.low_id
            && tokio::time::Instant::now() >= next_lowid_callback_at
        {
            next_lowid_callback_at = tokio::time::Instant::now() + LOWID_CALLBACK_INTERVAL;
            if let Some(conn) = state.server_connection.as_mut() {
                let mut succeeded = Vec::new();
                for _ in 0..MAX_LOWID_CALLBACKS_PER_TURN {
                    let Some((file_hash, client_id)) = pending_lowid_callback_queue.pop_front()
                    else {
                        break;
                    };
                    if conn.request_callback(client_id).is_ok() {
                        succeeded.push((file_hash, client_id));
                    } else {
                        // Keep the entry and stop this turn: the writer queue
                        // is full or the session is broken, and either way
                        // the rest would be refused too.
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

        // A new download or Find Sources waits for the next source frame,
        // not the sweep's next 4-minute tick: when the frame budget is open,
        // run it now. The tick either spends the frame or drops every ask it
        // could not use, so this cannot fire twice for the same line.
        if !state.server_tcp_srcreq_asks.is_empty()
            && server_tcp_srcreq_frame_open(&state, chrono::Utc::now().timestamp())
        {
            server_tcp_source_timer.reset_immediately();
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
            // Only a server still in the user's own list: the resume file is
            // untrusted, and this is the one value in it that makes Ember dial.
            let resuming = resume_server.is_some();
            let resumed = resume_server.take().filter(|(ip, port)| {
                state
                    .server_list
                    .servers()
                    .iter()
                    .any(|s| &s.ip == ip && s.port == *port)
            });
            // Without it, fall back to the ordinary auto-connect target only
            // for a user who has auto-connect on: a resume goes back to the
            // server the user chose, not to one they never asked for.
            let target = resumed.or_else(|| {
                settings.auto_connect_server.then(|| {
                    ed2k::server_list::ServerList::resolve_auto_connect_target(
                        &state.data_dir,
                        &state.server_list,
                    )
                })?
            });
            if target.is_none() && resuming && !settings.auto_connect_server {
                info!("Not reconnecting after the update: that server is no longer in the list");
            } else {
                match target {
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
                    // does not have access to. The try_recv drain above handles
                    // it through the same `apply_settings_update`; the dispatched `handle_command`
                    // arm for `UpdateSettings` is empty. Without this branch a
                    // settings update that arrives between `try_recv` returning
                    // empty and `select!` re-arming would be silently dropped
                    // (obfuscation toggle, USS toggle, max-uploads slider all
                    // had no effect until the next message woke the loop).
                    Some(NetworkCommand::UpdateSettings { settings: new_settings }) => {
                        apply_settings_update(
                            &udp_socket,
                            &mut state,
                            &mut settings,
                            new_settings,
                            &db,
                            &identity,
                            &app_handle,
                            &shared_nickname,
                            &source_manager,
                            &shared_server_addr,
                        )
                        .await;
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
                on_download_event(
                    event,
                    &udp_socket,
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
                    &a4af_shared,
                    &aich_set_tx,
                    &mut db_progress_last_persist,
                    &ember_digest_result_tx,
                    &part_hashset_result_tx,
                    &pending_kad_callbacks,
                    &shared_files,
                    &spam_filter,
                    &transfer_status_writes,
                    &upload_queue_handle,
                )
                .await;
            }

            // Upload events from the peer-to-peer upload listener
            Some(event) = ul_event_rx.recv() => {
                on_upload_event(
                    event,
                    &udp_socket,
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
                    &connect_serve_tx,
                    &pending_kad_callbacks,
                    &shared_files,
                    &transfer_status_writes,
                    &upload_queue_handle,
                    &mut upload_raw_progress,
                )
                .await;
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
                on_friend_relay_ticket_poll_result(
                    result,
                    &mut state,
                    &settings,
                    &db,
                    &friend_hashes,
                    ember_hash,
                    ed25519_secret_key,
                    &channel_relay_event_tx,
                    &mut friend_relay_ticket_poll_not_before,
                    &mut friend_relay_ticket_poll_retry_delay,
                    &mut friend_relay_ticket_poll_round_started_at,
                    &mut friend_relay_ticket_poll_timer,
                    &mut friend_relay_ticket_polls_in_flight,
                    &friend_relay_ticket_session_done_tx,
                    &mut friend_relay_ticket_sessions_in_flight,
                    &inbound_stream_tx,
                )
                .await;
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
                // A node with no shared folders never runs the startup
                // reconcile that merges last session's upload waiters.
                if state
                    .restored_upload_queue
                    .as_ref()
                    .is_some_and(|pending| pending.overdue())
                {
                    if let Some(pending) = state.restored_upload_queue.take() {
                        ed2k::upload_queue_store::merge_pending(
                            pending,
                            &upload_queue_handle,
                            &local_index,
                            &transfer_manager,
                        )
                        .await;
                    }
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
                // Why an upload queue stays short, readable from an ordinary
                // log: the per-peer lines behind these counts are debug-only.
                let queue = ed2k::upload::take_queue_health();
                let turned_away =
                    queue.refused_at_limit + queue.dropped_unshared + queue.reask_not_found > 0;
                queue_report_quiet_minutes = queue_report_quiet_minutes.saturating_add(1);
                if turned_away || (queue.waiting > 0 && queue_report_quiet_minutes >= 10) {
                    queue_report_quiet_minutes = 0;
                    info!(
                        "Upload queue: {} waiting; since the last report {} incoming connection(s) \
                         refused at the connection limit, {} waiter(s) dropped because their file \
                         is not shared, {} UDP re-ask(s) answered \"file not found\"",
                        queue.waiting,
                        queue.refused_at_limit,
                        queue.dropped_unshared,
                        queue.reask_not_found,
                    );
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
                    &mut pending_lowid_callback_queue,
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
                on_server_connect_result(
                    result,
                    &udp_socket,
                    &mut state,
                    &local_index,
                    &settings,
                    &app_handle,
                    &transfer_manager,
                    &source_manager,
                    &known_files,
                    &shared_server_addr,
                    &mut last_server_activity_at,
                    &mut nat_probe_in_flight,
                    &mut nat_probe_packet_tx,
                    &nat_probe_result_tx,
                    &mut nat_probe_started_at,
                    &mut next_offer_packet_at,
                    &mut pending_lowid_callback_queue,
                    &mut pending_offer_files,
                    &mut pending_offer_signature,
                    &mut server_tcp_source_timer,
                )
                .await;
            }

            // Poll buddy events (we are firewalled, buddy relays to us)
            event = async {
                match state.buddy_event_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                on_buddy_event(
                    event,
                    &udp_socket,
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
                    &connect_serve_tx,
                )
                .await;
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
                            // A failed append keeps its sets queued for the next tick.
                            let done = known2_in_flight_len.min(state.pending_known2_sets.len());
                            state.pending_known2_sets.drain(..done);
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
                    &app_handle,
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

    save_on_shutdown(
        &udp_socket,
        &mut state,
        &local_index,
        &settings,
        &db,
        &app_handle,
        &transfer_manager,
        &source_manager,
        &credit_manager,
        &stats_manager,
        &mut known_files,
        ember_hash,
        ed25519_secret_key,
        &mut aich_set_rx,
        &mut cache_write_handle,
        &mut credit_flush_handle,
        &credit_save_ownership,
        &mut known2_save_in_flight,
        known_met_save_in_flight,
        &mut known_met_save_result_rx,
        &mut periodic_save_result_rx,
        &mut reputation_save_in_flight,
        shutdown_deadline,
        &mut stats_save_in_flight,
        upnp_enabled,
        &mut upnp_mappings,
        &mut xfer_finish_rx,
        &upload_queue_handle,
    )
    .await;

    Ok(())
}
