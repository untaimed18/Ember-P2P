pub mod ed2k;
pub mod kad;
pub mod upnp;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use tauri::Emitter;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, RwLock};
use tracing::{debug, error, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::search::index::LocalIndex;
use crate::sharing::manager::{TransferControl, TransferManager};
use crate::storage::database::Database;
use crate::types::*;

use self::ed2k::upload::{self as upload_server, UploadEvent, UploadEventKind};
use self::ed2k::multi_source::{DownloadSource, MultiSourceDownload};
use self::ed2k::transfer::{DownloadEvent, Ed2kDownload};
use self::kad::bootstrap;
use self::kad::buddy::{BuddyManager, BuddyState};
use self::kad::ip_filter::{IpFilter, IpFilterStats};
use self::kad::messages::{self, KadMessage};
use self::kad::obfuscation;
use self::kad::protection::FloodProtection;
use self::kad::publish::{PublishManager, PublishableFile, md4_bytes_to_kad_id, kad_id_to_md4_bytes};
use self::kad::routing::RoutingTable;
use self::kad::search::{SearchId, SearchManager, SearchType, SEARCH_INITIAL_CONTACTS};
use self::kad::store::DhtStore;
use self::kad::types::*;

#[derive(Debug)]
pub enum NetworkCommand {
    SearchFiles {
        query: String,
        tx: oneshot::Sender<Vec<SearchResult>>,
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
    GetPeers {
        tx: oneshot::Sender<Vec<PeerInfo>>,
    },
    GetStats {
        tx: oneshot::Sender<NetworkStats>,
    },
    AnnounceFiles {
        files: Vec<FileInfo>,
    },
    UnannounceFiles {
        file_hashes: Vec<String>,
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
    Shutdown,
}

struct PendingDownload {
    transfer_id: String,
    file_hash: String,
    file_name: String,
    file_size: u64,
    control: Arc<TransferControl>,
    search_count: u32,
    last_search_at: i64,
}

struct NetworkState {
    local_id: KadId,
    user_hash: [u8; 16],
    routing_table: RoutingTable,
    search_manager: SearchManager,
    publish_manager: PublishManager,
    dht_store: DhtStore,
    stats: NetworkStats,
    pending_keyword_searches: HashMap<SearchId, (oneshot::Sender<Vec<SearchResult>>, Vec<SearchResult>)>,
    pending_source_searches: HashMap<SearchId, oneshot::Sender<Vec<(String, u16)>>>,
    /// Source searches tied to pending downloads (search_id -> transfer_id)
    download_source_searches: HashMap<SearchId, String>,
    /// Downloads waiting for sources (transfer_id -> PendingDownload)
    pending_downloads: HashMap<String, PendingDownload>,
    data_dir: PathBuf,
    external_ip: Option<Ipv4Addr>,
    external_udp_port: Option<u16>,
    firewalled: bool,
    firewall_checks_sent: u32,
    firewall_responses: Vec<Ipv4Addr>,
    udp_port_responses: Vec<u16>,
    peer_nicknames: HashMap<KadId, String>,
    /// target -> (file_hash, sent_at, is_source_publish)
    publish_pending: HashMap<KadId, (KadId, i64, bool)>,
    publish_confirmed: u32,
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
    nat_traversal_enabled: bool,
    upnp_mapped: bool,
    /// IP filter for blocking known-bad ranges (eMule ipfilter.dat compatible)
    ip_filter: IpFilter,
    /// Cached set of banned peer IPs for fast lookup at network level
    banned_ips: HashSet<Ipv4Addr>,
    /// Whether to use protocol obfuscation (RC4 encryption) for outgoing KAD packets
    obfuscation_enabled: bool,
    /// Shared firewall status that can be updated from spawned tasks
    firewalled_shared: Arc<std::sync::atomic::AtomicBool>,
    /// Whether we've done the initial self-lookup (FindNode for own ID)
    self_lookup_done: bool,
}

pub async fn start_network(
    app_handle: tauri::AppHandle,
    mut cmd_rx: mpsc::Receiver<NetworkCommand>,
    settings: AppSettings,
    local_index: Arc<RwLock<LocalIndex>>,
    db: Arc<Database>,
    transfer_manager: Arc<RwLock<TransferManager>>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
) -> anyhow::Result<()> {
    let data_dir = directories::ProjectDirs::from("com", "nexus", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&data_dir)?;

    let identity = crate::storage::identity::NodeIdentity::load_or_create(&data_dir)?;
    let local_id = identity.kad_id();
    let user_hash = identity.user_hash;
    info!("Local KAD ID: {}…", &local_id.to_hex()[..8]);

    let tcp_port = settings.tcp_port;
    let udp_port = settings.udp_port;

    let udp_addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), udp_port);
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
    sock2.set_recv_buffer_size(1024 * 1024)?;
    sock2.set_nonblocking(true)?;
    if let Err(e) = sock2.bind(&socket2::SockAddr::from(udp_addr)) {
        let msg = format!("UDP port {udp_port} is already in use. Is another instance running? Change the port in Settings or close the other application.");
        error!("{msg}: {e}");
        let _ = app_handle.emit("network-error", serde_json::json!({
            "message": msg,
        }));
        anyhow::bail!("{msg}");
    }
    let udp_socket = UdpSocket::from_std(std::net::UdpSocket::from(sock2))?;
    info!("KAD UDP socket bound on port {udp_port}");

    let mut routing_table = RoutingTable::new(local_id, settings.block_private_ips);
    let search_manager = SearchManager::new();
    let publish_manager = PublishManager::new(local_id, tcp_port, udp_port);

    // Load bootstrap contacts
    let nodes_dat_path = data_dir.join("nodes.dat");
    let mut boot_contacts = if nodes_dat_path.exists() {
        bootstrap::load_nodes_dat(&nodes_dat_path).unwrap_or_default()
    } else {
        Vec::new()
    };

    // Load saved peers from database to supplement contacts
    if let Ok(saved_peers) = db.get_peers() {
        let peer_count = saved_peers.len();
        for peer in saved_peers {
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
                                udp_port: port.saturating_add(3),
                                tcp_port: port,
                                version: 0,
                                last_seen: peer.last_seen,
                                verified: false,
                                contact_type: CONTACT_TYPE_NEW,
                                udp_key: None,
                                kad_options: 0,
                                created_at: peer.last_seen,
                                expires_at: 0,
                                last_type_set: 0,
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

    for c in &boot_contacts {
        routing_table.insert(c.clone());
    }
    info!(
        "Routing table initialized with {} contacts",
        routing_table.len()
    );

    let _ = app_handle.emit("network-status", NetworkStatus::Connecting);

    let nat_traversal_enabled = settings.nat_traversal_enabled;
    let upnp_enabled = settings.upnp_enabled;

    // Attempt UPnP port mapping (only if UPnP is enabled)
    let mut upnp_mappings = upnp::UpnpMappings::new(tcp_port, udp_port);
    let upnp_success = if upnp_enabled {
        upnp_mappings.setup().await;
        let mapped = upnp_mappings.is_mapped();
        if mapped {
            info!("UPnP port mapping succeeded -- not firewalled");
        }
        mapped
    } else {
        info!("UPnP disabled by user -- skipping port mapping");
        false
    };

    let mut dht_store = DhtStore::new();
    dht_store.set_local_id(local_id);

    let udp_key_seed = identity.udp_key_seed;
    let buddy_manager = BuddyManager::new(local_id, tcp_port);

    // Initialize IP filter (controlled by user settings)
    let mut ip_filter = IpFilter::new(settings.ip_filter_enabled, settings.block_private_ips);
    let ipfilter_path = data_dir.join("ipfilter.dat");
    if settings.ip_filter_enabled && ipfilter_path.exists() {
        ip_filter.load_from_file(&ipfilter_path);
    }
    info!(
        "IP filter: enabled={}, block_private={}, ranges={}",
        ip_filter.is_enabled(),
        ip_filter.blocks_private(),
        ip_filter.range_count(),
    );

    // Load banned peer IPs for fast network-level rejection
    let banned_ips: HashSet<Ipv4Addr> = db.get_peers()
        .unwrap_or_default()
        .iter()
        .filter(|p| p.banned)
        .filter_map(|p| {
            p.addresses.first().and_then(|addr| {
                addr.rsplit_once(':')
                    .and_then(|(ip, _)| ip.parse().ok())
            })
        })
        .collect();
    if !banned_ips.is_empty() {
        info!("Loaded {} banned peer IPs", banned_ips.len());
    }

    let mut state = NetworkState {
        local_id,
        user_hash,
        routing_table,
        search_manager,
        publish_manager,
        dht_store,
        stats: NetworkStats {
            status: NetworkStatus::Connecting,
            ..Default::default()
        },
        pending_keyword_searches: HashMap::new(),
        pending_source_searches: HashMap::new(),
        download_source_searches: HashMap::new(),
        pending_downloads: HashMap::new(),
        data_dir: data_dir.clone(),
        external_ip: None,
        external_udp_port: None,
        firewalled: !upnp_success,
        firewall_checks_sent: 0,
        firewall_responses: Vec::new(),
        udp_port_responses: Vec::new(),
        peer_nicknames: HashMap::new(),
        publish_pending: HashMap::new(),
        publish_confirmed: 0,
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
        nat_traversal_enabled,
        upnp_mapped: upnp_success,
        ip_filter,
        banned_ips,
        obfuscation_enabled: settings.obfuscation_enabled,
        firewalled_shared: Arc::new(std::sync::atomic::AtomicBool::new(!upnp_success)),
        self_lookup_done: false,
    };

    // Send bootstrap requests to initial contacts
    for contact in &boot_contacts {
        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
        let msg = KadMessage::BootstrapReq;
        if let Ok(packet) = messages::encode_packet(&msg) {
            let _ = udp_socket.send_to(&packet, addr).await;
            debug!("Sent bootstrap req to {addr}");
        }
    }

    if nat_traversal_enabled {
        // Send FirewalledReq to a few contacts to detect our external IP
        for contact in boot_contacts.iter().take(3) {
            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
            let msg = KadMessage::FirewalledReq { tcp_port };
            if let Ok(packet) = messages::encode_packet(&msg) {
                let _ = udp_socket.send_to(&packet, addr).await;
                state.firewall_checks_sent += 1;
            }
        }
        debug!("Sent {} firewall check requests", state.firewall_checks_sent);

        // Send Ping to detect our external UDP port
        for contact in boot_contacts.iter().skip(3).take(3) {
            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
            let msg = KadMessage::Ping;
            if let Ok(packet) = messages::encode_packet(&msg) {
                let _ = udp_socket.send_to(&packet, addr).await;
            }
        }
    } else {
        info!("NAT traversal disabled -- skipping firewall/port detection probes");
    }

    // Download event channel
    let (dl_event_tx, mut dl_event_rx) = mpsc::channel::<DownloadEvent>(128);

    // Upload event channel
    let (ul_event_tx, mut ul_event_rx) = mpsc::channel::<UploadEvent>(128);

    // Start the peer-to-peer upload listener (accepts incoming file requests from other KAD peers)
    {
        let ul_tx = ul_event_tx.clone();
        let ul_index = local_index.clone();
        let ul_transfers = transfer_manager.clone();
        let ul_bw = bandwidth_limiter.clone();
        let ul_folders = settings.shared_folders.clone();
        let ul_nickname = settings.nickname.clone();
        let ul_app = app_handle.clone();
        let ul_max = settings.max_concurrent_uploads;
        tokio::spawn(async move {
            if let Err(e) = upload_server::start_upload_server(
                tcp_port,
                user_hash,
                ul_nickname,
                udp_port,
                ul_folders,
                ul_index,
                ul_transfers,
                ul_bw,
                ul_tx,
                ul_max,
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
    let mut bootstrap_timer = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut bootstrap_attempts: u32 = 0;
    let mut publish_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut search_poll_timer = tokio::time::interval(std::time::Duration::from_millis(500));
    let mut cleanup_timer = tokio::time::interval(std::time::Duration::from_secs(300));
    let mut bucket_refresh_timer = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut small_timer = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut eviction_ping_timer = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut buddy_timer = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut flood_cleanup_timer = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut source_retry_timer = tokio::time::interval(std::time::Duration::from_secs(60));

    // Resume incomplete downloads from previous session
    if let Ok(incomplete) = db.get_incomplete_downloads() {
        let count = incomplete.len();
        if count > 0 {
            info!("Resuming {count} incomplete downloads from previous session");
            let now = chrono::Utc::now().timestamp();
            let dl_folder = settings.download_folder.clone();
            for mut transfer in incomplete {
                let control = TransferControl::new();

                // Check .part file for actual progress
                let part_path = PathBuf::from(&dl_folder)
                    .join(format!("{}.part", transfer.id));
                if part_path.exists() && transfer.total_size > 0 {
                    let tracker = crate::network::ed2k::part_tracker::PartTracker::new(
                        transfer.total_size, &part_path,
                    );
                    let completed_bytes: u64 = (0..tracker.part_count)
                        .filter(|&i| tracker.is_part_complete(i))
                        .map(|i| {
                            let (s, e) = tracker.part_range(i);
                            e - s
                        })
                        .sum();
                    transfer.transferred = completed_bytes;
                    transfer.progress = (completed_bytes as f64 / transfer.total_size as f64) * 100.0;
                }

                transfer.status = TransferStatus::Searching;
                {
                    let mut mgr = transfer_manager.write().await;
                    mgr.enqueue(transfer.clone());
                    mgr.register_control(&transfer.id, control.clone());
                }
                state.pending_downloads.insert(transfer.id.clone(), PendingDownload {
                    transfer_id: transfer.id.clone(),
                    file_hash: transfer.file_hash.clone(),
                    file_name: transfer.file_name.clone(),
                    file_size: transfer.total_size,
                    control,
                    search_count: 0,
                    last_search_at: now - 60,
                });
            }
        }
    }

    info!("Network event loop starting");

    loop {
        tokio::select! {
            // Incoming UDP packets
            result = udp_socket.recv_from(&mut udp_buf) => {
                match result {
                    Ok((len, from)) => {
                        handle_udp_packet(
                            &udp_socket,
                            &udp_buf[..len],
                            from,
                            &mut state,
                            &app_handle,
                            &local_index,
                            &settings,
                            &db,
                        ).await;
                    }
                    Err(e) => {
                        warn!("UDP recv error: {e}");
                    }
                }
            }

            // Commands from the frontend
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(NetworkCommand::Shutdown) | None => {
                        info!("Network shutting down");
                        break;
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
                        ).await;
                    }
                }
            }

            // Download progress events
            Some(event) = dl_event_rx.recv() => {
                handle_download_event(event, &app_handle, &transfer_manager, &db, &bandwidth_limiter).await;
            }

            // Upload events from the peer-to-peer upload listener
            Some(event) = ul_event_rx.recv() => {
                handle_upload_event(event, &app_handle, &transfer_manager, &bandwidth_limiter).await;
            }

            // Periodic search polling
            _ = search_poll_timer.tick() => {
                let queries = state.search_manager.poll_queries();
                if !queries.is_empty() {
                    info!("Search poll: sending {} queries", queries.len());
                }
                for (sid, addr, msg) in &queries {
                    if state.flood_protection.check_outgoing_rate(addr.ip()) {
                        info!("Throttling outgoing search {} packet to {addr}", sid.0);
                        continue;
                    }
                    if let Ok(packet) = messages::encode_packet(msg) {
                        let opcode = packet.get(1).copied().unwrap_or(0);
                        // Log SearchKeyReq/SearchSourceReq sends at INFO level for diagnostics
                        if opcode == 0x33 || opcode == 0x34 {
                            info!("  Search {}: sending 0x{opcode:02X} to {addr}", sid.0);
                        }
                        state.flood_protection.track_request(*addr, opcode);
                        let _ = udp_socket.send_to(&packet, addr).await;
                    }
                }

                // Check for completed searches
                let completed_ids: Vec<SearchId> = state.search_manager.active
                    .iter()
                    .filter(|(_, s)| s.completed)
                    .map(|(id, _)| *id)
                    .collect();

                // Emit search progress for active keyword searches
                for (sid, search) in state.search_manager.active.iter() {
                    if !search.completed {
                        if state.pending_keyword_searches.contains_key(sid) {
                            // Report unique file count, not raw entries (which include duplicates)
                            let unique_count = {
                                let unique: std::collections::HashSet<&kad::types::KadId> =
                                    search.results.iter().map(|r| &r.id).collect();
                                unique.len()
                            };
                            let _ = app_handle.emit("search-progress", serde_json::json!({
                                "nodes_contacted": search.queried.len(),
                                "results_so_far": unique_count,
                                "phase": format!("{:?}", search.phase),
                            }));
                        }
                    }
                }

                for sid in completed_ids {
                    if let Some((tx, mut local_results)) = state.pending_keyword_searches.remove(&sid) {
                        let network_results = if let Some(search) = state.search_manager.get(&sid) {
                            let unique: std::collections::HashSet<&kad::types::KadId> =
                                search.results.iter().map(|r| &r.id).collect();
                            info!(
                                "Keyword search {} completed: {} unique files ({} raw entries from KAD), {} local results",
                                sid.0, unique.len(), search.results.len(), local_results.len()
                            );
                            convert_search_results(&search.results)
                        } else {
                            Vec::new()
                        };
                        local_results.extend(network_results);
                        local_results.sort_by(|a, b| b.availability.cmp(&a.availability));
                        local_results.truncate(500);
                        let _ = tx.send(local_results);
                        app_handle.emit("search-complete", ()).ok();
                    } else if let Some(tx) = state.pending_source_searches.remove(&sid) {
                        let sources = if let Some(search) = state.search_manager.get(&sid) {
                            extract_sources_from_results(&search.results)
                        } else {
                            Vec::new()
                        };
                        info!("Source search {} completed: {} sources found", sid.0, sources.len());
                        let _ = tx.send(sources);
                    } else if let Some(transfer_id) = state.download_source_searches.remove(&sid) {
                        let sources = if let Some(search) = state.search_manager.get(&sid) {
                            extract_sources_from_results(&search.results)
                        } else {
                            Vec::new()
                        };
                        info!(
                            "Download source search {} completed for {}: {} sources found",
                            sid.0, transfer_id, sources.len()
                        );

                        if let Some(pending) = state.pending_downloads.remove(&transfer_id) {
                            if sources.is_empty() {
                                info!("No sources found yet for {transfer_id}, will retry later");
                                state.pending_downloads.insert(transfer_id, pending);
                            } else {
                                let hash_bytes = match hex::decode(&pending.file_hash) {
                                    Ok(b) if b.len() == 16 => {
                                        let mut arr = [0u8; 16];
                                        arr.copy_from_slice(&b);
                                        arr
                                    }
                                    _ => {
                                        error!("Bad hash in pending download");
                                        continue;
                                    }
                                };

                                {
                                    let mut mgr = transfer_manager.write().await;
                                    mgr.update_status(&transfer_id, TransferStatus::Active);
                                }
                                let peer_desc = sources.iter()
                                    .map(|(ip, port)| format!("{ip}:{port}"))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                let _ = app_handle.emit("transfer-status", serde_json::json!({
                                    "id": transfer_id,
                                    "status": "active",
                                    "peer_id": peer_desc,
                                }));

                                if sources.len() == 1 {
                                    let (src_ip, src_port) = sources[0].clone();
                                    let source_addr: SocketAddr = match format!("{src_ip}:{src_port}").parse() {
                                        Ok(a) => a,
                                        Err(e) => {
                                            error!("Invalid source address: {e}");
                                            continue;
                                        }
                                    };
                                    info!("Starting single-source download {transfer_id} from {source_addr}");
                                    let download = Ed2kDownload {
                                        transfer_id: pending.transfer_id,
                                        file_hash: hash_bytes,
                                        file_name: pending.file_name,
                                        file_size: pending.file_size,
                                        source_addr,
                                        download_dir: PathBuf::from(&settings.download_folder),
                                        user_hash: state.user_hash,
                                        nickname: settings.nickname.clone(),
                                        tcp_port: settings.tcp_port,
                                        udp_port: settings.udp_port,
                                        bandwidth_limiter: bandwidth_limiter.clone(),
                                        control: pending.control,
                                    };
                                    let tx = dl_event_tx.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = download.run(tx).await {
                                            error!("Download failed: {e}");
                                        }
                                    });
                                } else {
                                    info!(
                                        "Starting multi-source download {transfer_id} from {} sources",
                                        sources.len()
                                    );
                                    let download_sources: Vec<DownloadSource> = sources
                                        .iter()
                                        .map(|(ip, port)| DownloadSource {
                                            peer_ip: ip.clone(),
                                            peer_port: *port,
                                            available_parts: Vec::new(),
                                        })
                                        .collect();
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
                                    };
                                    let tx = dl_event_tx.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = ms_download.run(tx).await {
                                            error!("Multi-source download failed: {e}");
                                        }
                                    });
                                }
                            }
                        }
                    } else if let Some(tx) = state.pending_notes_searches.remove(&sid) {
                        let results = if let Some(search) = state.search_manager.get(&sid) {
                            info!(
                                "Notes search {} completed: {} results",
                                sid.0, search.results.len()
                            );
                            convert_search_results(&search.results)
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
                                    .take(3)
                                {
                                    let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                    if let Ok(packet) = messages::encode_packet(msg) {
                                        let _ = udp_socket.send_to(&packet, addr).await;
                                        sent_any = true;
                                    }
                                }
                                state.publish_pending.insert(*kw_hash, (file.file_hash, now, false));
                            }
                            if sent_any {
                                info!(
                                    "StoreKeyword search {} completed: published {} keywords to {} closest nodes",
                                    sid.0, kw_publishes.len(), search.closest.len().min(3)
                                );
                            }
                        }
                    } else if let Some((file_hash, msg)) = state.store_source_searches.remove(&sid) {
                        // StoreSource search completed - send source publish to closest nodes
                        if let Some(search) = state.search_manager.get(&sid) {
                            let now = chrono::Utc::now().timestamp();
                            let mut sent = 0;
                            for contact in search.closest.iter()
                                .filter(|c| !state.overloaded_nodes.contains_key(&c.ip))
                                .take(3)
                            {
                                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                if let Ok(packet) = messages::encode_packet(&msg) {
                                    let _ = udp_socket.send_to(&packet, addr).await;
                                    sent += 1;
                                }
                            }
                            if sent > 0 {
                                state.publish_pending.insert(file_hash, (file_hash, now, true));
                                info!("StoreSource search {} completed: published source to {} closest nodes", sid.0, sent);
                            }
                        }
                    } else if let Some((file_hash, rating, comment)) = state.pending_note_publishes.remove(&sid) {
                        // StoreNotes search completed - send PublishNotesReq to closest nodes
                        if let Some(search) = state.search_manager.get(&sid) {
                            let mut note_tags = vec![
                                KadTag {
                                    name: TagName::Id(TAG_FILENAME),
                                    value: TagValue::String(comment),
                                },
                            ];
                            if rating > 0 {
                                note_tags.push(KadTag {
                                    name: TagName::Id(TAG_FILESIZE),
                                    value: TagValue::Uint8(rating),
                                });
                            }
                            let msg = KadMessage::PublishNotesReq {
                                target: file_hash,
                                sender_id: state.local_id,
                                tags: note_tags,
                            };
                            let mut sent = 0;
                            for contact in search.closest.iter().take(3) {
                                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                                if let Ok(packet) = messages::encode_packet(&msg) {
                                    let _ = udp_socket.send_to(&packet, addr).await;
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
                    state.search_manager.remove(&sid);
                }
            }

            // Periodic bootstrap (eMule BigTimer style)
            _ = bootstrap_timer.tick() => {
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

                // Self-lookup: once we have some contacts, do a FindNode for our own ID
                // This is the primary mechanism eMule uses to populate the routing table
                if !state.self_lookup_done && table_size >= 2 {
                    let closest = state.routing_table.find_closest(&state.local_id, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        let sid = state.search_manager.start_search(
                            state.local_id,
                            SearchType::FindNode,
                            closest,
                        );
                        info!("Started self-lookup (FindNode for own ID), search {}, table has {table_size} contacts", sid.0);
                        state.self_lookup_done = true;
                    }
                }

                // Keep bootstrapping until we have a healthy routing table (~200 contacts)
                if table_size < 200 {
                    // Send bootstrap to hardcoded nodes
                    for contact in &bootstrap::default_bootstrap_contacts() {
                        let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                        let msg = KadMessage::BootstrapReq;
                        if let Ok(packet) = messages::encode_packet(&msg) {
                            let _ = udp_socket.send_to(&packet, addr).await;
                        }
                    }

                    // Query a larger sample of known contacts with BootstrapReq
                    let sample: Vec<KadContact> = {
                        let target = KadId::random();
                        state.routing_table.find_closest(&target, 10)
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

                    // Also start FindNode lookups for random targets to discover
                    // contacts in different parts of the ID space
                    if table_size >= 10 {
                        let random_target = KadId::random();
                        let closest = state.routing_table.find_closest(&random_target, SEARCH_INITIAL_CONTACTS);
                        if !closest.is_empty() {
                            let _sid = state.search_manager.start_search(
                                random_target,
                                SearchType::FindNode,
                                closest,
                            );
                        }
                    }
                }

                let count = state.routing_table.len() as u32;
                if count > 0 && state.stats.status != NetworkStatus::Connected {
                    state.stats.status = NetworkStatus::Connected;
                    let _ = app_handle.emit("network-status", NetworkStatus::Connected);
                }
                state.stats.connected_peers = count;
            }

            // Periodic publishing
            _ = publish_timer.tick() => {
                if state.routing_table.is_empty() {
                    debug!("Skipping publish cycle: routing table is empty");
                } else {
                // Limit publishes per cycle to avoid flooding peers
                const MAX_SOURCE_PUBLISHES_PER_CYCLE: usize = 3;
                const MAX_KEYWORD_PUBLISHES_PER_CYCLE: usize = 2;

                let source_files = state.publish_manager.files_needing_source_publish()
                    .into_iter().take(MAX_SOURCE_PUBLISHES_PER_CYCLE).cloned().collect::<Vec<_>>();
                for file in &source_files {
                    let msg = state.publish_manager.build_source_publish(file);
                    let closest = state.routing_table.find_closest_prefer_verified(&file.file_hash, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        // Use iterative search to find truly closest nodes before publishing
                        let sid = state.search_manager.start_search(
                            file.file_hash,
                            SearchType::StoreKeyword, // reuse STORE type for source publish lookup
                            closest,
                        );
                        state.store_source_searches.insert(sid, (file.file_hash, msg));
                        state.publish_manager.mark_source_published(&file.file_hash);
                    }
                }

                let keyword_files = state.publish_manager.files_needing_keyword_publish()
                    .into_iter().take(MAX_KEYWORD_PUBLISHES_PER_CYCLE).cloned().collect::<Vec<_>>();
                for file in &keyword_files {
                    let publishes = state.publish_manager.build_keyword_publishes(&file);
                    // Use StoreKeyword search to find truly closest nodes, then publish
                    if !publishes.is_empty() {
                        let first_kw_hash = publishes[0].0;
                        let closest = state.routing_table.find_closest_prefer_verified(&first_kw_hash, SEARCH_INITIAL_CONTACTS);
                        if !closest.is_empty() {
                            let sid = state.search_manager.start_search(
                                first_kw_hash,
                                SearchType::StoreKeyword,
                                closest,
                            );
                            state.store_keyword_searches.insert(sid, (file.clone(), publishes));
                            state.publish_manager.mark_keyword_published(&file.file_hash);
                        }
                    }
                }
                } // end is_empty guard
            }

            // Cleanup stale searches, expired DHT entries, and unconfirmed publishes
            _ = cleanup_timer.tick() => {
                state.search_manager.cleanup(120);
                state.dht_store.cleanup_expired();

                // Remove contacts not seen in 2 hours
                let stale_removed = state.routing_table.remove_stale(7200);
                if stale_removed > 0 {
                    debug!("Removed {stale_removed} stale contacts from routing table");
                    state.stats.connected_peers = state.routing_table.len() as u32;
                }

                let now = chrono::Utc::now().timestamp();
                let stale_publishes: Vec<(KadId, KadId, bool)> = state.publish_pending
                    .iter()
                    .filter(|(_, (_, sent_at, _))| now - sent_at > 120)
                    .map(|(target, (file_hash, _, is_source))| (*target, *file_hash, *is_source))
                    .collect();
                for (target, file_hash, is_source) in &stale_publishes {
                    state.publish_pending.remove(target);
                    if *is_source {
                        state.publish_manager.reset_source_publish(file_hash);
                    } else {
                        state.publish_manager.reset_keyword_publish(file_hash);
                    }
                    debug!("Retrying unconfirmed publish for target {target}");
                }
            }

            // Bucket refresh: discover new contacts for stale/sparse buckets
            _ = bucket_refresh_timer.tick() => {
                let now = chrono::Utc::now().timestamp();
                let stale = state.routing_table.stale_buckets(now);
                for bucket_idx in &stale {
                    let bucket_idx = *bucket_idx;
                    let target = state.routing_table.random_id_in_bucket(bucket_idx);
                    let closest = state.routing_table.find_closest(&target, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        state.search_manager.start_search(
                            target,
                            SearchType::FindNode,
                            closest,
                        );
                        state.routing_table.mark_refreshed(bucket_idx);
                        debug!("Refreshing stale bucket {bucket_idx}");
                    }
                }

                // Also fill sparse buckets
                let sparse = state.routing_table.buckets_needing_fill();
                for bucket_idx in sparse {
                    if stale.contains(&bucket_idx) {
                        continue;
                    }
                    let target = state.routing_table.random_id_in_bucket(bucket_idx);
                    let closest = state.routing_table.find_closest(&target, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        state.search_manager.start_search(
                            target,
                            SearchType::FindNode,
                            closest,
                        );
                        debug!("Filling sparse bucket {bucket_idx} ({} contacts)", 
                            state.routing_table.get_bucket_contacts(bucket_idx).len());
                    }
                }
            }

            // Send pings for pending evictions and process timeouts
            _ = eviction_ping_timer.tick() => {
                send_eviction_pings(&udp_socket, &mut state).await;
                let evicted = state.routing_table.process_eviction_timeouts(10);
                if !evicted.is_empty() {
                    debug!("Evicted {} unresponsive contacts", evicted.len());
                    state.stats.connected_peers = state.routing_table.len() as u32;
                }
            }

            // SmallTimer (eMule): probe expired contacts with HELLO_REQ, remove dead
            _ = small_timer.tick() => {
                let dead_removed = state.routing_table.remove_dead_contacts();
                if dead_removed > 0 {
                    debug!("SmallTimer: removed {dead_removed} dead contacts");
                    state.stats.connected_peers = state.routing_table.len() as u32;
                }

                let to_probe = state.routing_table.get_contacts_to_probe();
                for (_bucket_idx, contact) in &to_probe {
                    debug!("Probing contact {} at {}", contact.id, contact.addr_string());
                }
                for (_bucket_idx, contact) in to_probe {
                    let our_options: u8 = if state.firewalled { 0x05 } else { 0x04 };
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
                    state.flood_protection.track_request(dest, 0x19);
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

            // Buddy system: find a relay buddy if firewalled (only when NAT traversal is enabled)
            _ = buddy_timer.tick() => {
                if !state.nat_traversal_enabled { continue; }
                state.buddy_manager.check_buddy_alive().await;
                if state.buddy_manager.should_find_buddy(state.firewalled) {
                    state.buddy_manager.start_finding();
                    let target = state.buddy_manager.find_buddy_target();
                    let local = *state.buddy_manager.local_id();
                    let local_tcp = state.buddy_manager.tcp_port();
                    let closest = state.routing_table.find_closest(&target, SEARCH_INITIAL_CONTACTS);
                    if !closest.is_empty() {
                        let _sid = state.search_manager.start_search(
                            target,
                            SearchType::FindBuddy,
                            closest,
                        );
                        // Send FindBuddyReq to closest contacts
                        for contact in state.routing_table.find_closest(&target, 3) {
                            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                            let msg = KadMessage::FindBuddyReq {
                                buddy_id: target,
                                user_id: local,
                                tcp_port: local_tcp,
                            };
                            if let Ok(packet) = messages::encode_packet(&msg) {
                                let _ = udp_socket.send_to(&packet, addr).await;
                            }
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
            }

            // Retry source search for pending downloads
            _ = source_retry_timer.tick() => {
                let now = chrono::Utc::now().timestamp();
                let max_retries = 10u32;
                let retry_interval = 60i64;

                let mut to_retry = Vec::new();
                let mut to_fail = Vec::new();

                for (tid, pd) in &state.pending_downloads {
                    if pd.control.is_cancelled() {
                        to_fail.push(tid.clone());
                        continue;
                    }
                    if pd.search_count >= max_retries {
                        to_fail.push(tid.clone());
                        continue;
                    }
                    if now - pd.last_search_at >= retry_interval {
                        to_retry.push(tid.clone());
                    }
                }

                for tid in &to_fail {
                    if let Some(pending) = state.pending_downloads.remove(tid) {
                        warn!("Giving up source search for {tid} after {} attempts", pending.search_count);
                        let mut mgr = transfer_manager.write().await;
                        mgr.update_status(tid, TransferStatus::Failed);
                        let _ = app_handle.emit("transfer-status", serde_json::json!({
                            "id": tid,
                            "status": "failed",
                            "error": "No sources found after multiple search attempts",
                        }));
                    }
                }

                for tid in to_retry {
                    if let Some(pd) = state.pending_downloads.get_mut(&tid) {
                        let hash_bytes = match hex::decode(&pd.file_hash) {
                            Ok(b) if b.len() == 16 => b,
                            _ => continue,
                        };
                        let kad_hash = md4_bytes_to_kad_id(&hash_bytes);
                        let closest = state.routing_table.find_closest(&kad_hash, SEARCH_INITIAL_CONTACTS);
                        if closest.is_empty() {
                            continue;
                        }

                        pd.search_count += 1;
                        pd.last_search_at = now;
                        info!(
                            "Retrying source search for {} (attempt {})",
                            tid, pd.search_count
                        );

                        let sid = state.search_manager.start_search(
                            kad_hash,
                            SearchType::FindSource { file_size: pd.file_size },
                            closest,
                        );
                        state.download_source_searches.insert(sid, tid);
                    }
                }
            }
        }
    }

    // Save routing table on shutdown
    info!("Shutting down network");
    let contacts = state.routing_table.export_contacts();
    let nodes_path = state.data_dir.join("nodes.dat");
    if let Err(e) = bootstrap::save_nodes_dat(&nodes_path, &contacts) {
        error!("Failed to save nodes.dat: {e}");
    }

    if upnp_enabled {
        upnp_mappings.teardown().await;
    }

    Ok(())
}

/// Send pings for all pending evictions that haven't been pinged yet.
async fn send_eviction_pings(socket: &UdpSocket, state: &mut NetworkState) {
    let evictions = state.routing_table.pending_evictions.clone();
    for eviction in &evictions {
        let bucket_idx = eviction.bucket_idx;
        // Use least_recently_seen to verify which contact to probe
        let contact_to_ping = state.routing_table.least_recently_seen(bucket_idx)
            .filter(|c| c.id == eviction.old_contact_id)
            .cloned()
            .or_else(|| state.routing_table.get_contact(&eviction.old_contact_id).cloned());

        if let Some(contact) = contact_to_ping {
            let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
            let ping = KadMessage::Ping;
            if let Ok(packet) = messages::encode_packet(&ping) {
                let _ = socket.send_to(&packet, addr).await;
            }
        }
    }
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

    if use_obfuscation {
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
    }
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
) {
    // Reject oversized packets (max 64 KiB for UDP)
    if data.len() > 65535 {
        debug!("Dropping oversized packet from {from}: {} bytes", data.len());
        return;
    }

    // Security: IP filter and ban check
    if let std::net::IpAddr::V4(ipv4) = from.ip() {
        if state.ip_filter.is_blocked(ipv4) {
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
    if state.flood_protection.check_rate_limit(from.ip()) {
        info!("Rate limit exceeded for {from}, dropping packet");
        return;
    }

    let msg = match messages::decode_packet(data) {
        Ok(m) => m,
        Err(_first_err) => {
            let receiver_vk = match from.ip() {
                std::net::IpAddr::V4(ip) => KadUDPKey::generate(state.udp_key_seed, u32::from(ip)).key,
                _ => 0,
            };
            if let Some(decrypted) = kad::obfuscation::try_decrypt_kad_packet(data, &state.local_id, &state.user_hash, receiver_vk) {
                match messages::decode_packet(&decrypted) {
                    Ok(m) => {
                        debug!("Decrypted obfuscated KAD packet from {from} ({} bytes)", data.len());
                        m
                    }
                    Err(e) => {
                        debug!("Decrypted obfuscated packet from {from} but failed to parse: {e}");
                        return;
                    }
                }
            } else {
                let header = data.first().copied().unwrap_or(0);
                if header == 0xE4 || header == 0xE5 {
                    warn!("Failed to decode KAD packet from {from} ({} bytes): {_first_err}", data.len());
                } else {
                    debug!("Unreadable packet from {from} ({} bytes, header 0x{header:02X})", data.len());
                }
                return;
            }
        }
    };

    // Phase 4: validate responses against tracked outgoing requests
    let response_opcode = match &msg {
        KadMessage::BootstrapRes { .. } => Some(0x09u8),
        KadMessage::HelloRes { .. } => Some(0x19),
        KadMessage::KadRes { .. } => Some(0x29),
        KadMessage::SearchRes { .. } => Some(0x3B),
        KadMessage::PublishRes { .. } => Some(0x4B),
        KadMessage::Pong { .. } => Some(0x61),
        KadMessage::FirewalledRes { .. } => Some(0x58),
        _ => None,
    };
    if let Some(opcode) = response_opcode {
        if !state.flood_protection.validate_response(from, opcode) {
            if opcode == 0x3B {
                warn!("Dropping unsolicited SearchRes from {from} (no matching outgoing SearchKeyReq)");
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
            let contacts = state.routing_table.find_closest(&state.local_id, 20);
            let res = KadMessage::BootstrapRes {
                sender_id: state.local_id,
                tcp_port: state.tcp_port,
                version: KADEMLIA_VERSION,
                contacts,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = socket.send_to(&packet, from).await;
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
                verified: false,
                contact_type: CONTACT_TYPE_NEW,
                udp_key: Some(KadUDPKey::generate(state.udp_key_seed, u32::from(ip))),
                kad_options: 0,
                created_at: now,
                expires_at: 0,
                last_type_set: 0,
            });

            let mut contact_addrs = Vec::new();
            for c in contacts {
                let addr = SocketAddr::new(c.ip.into(), c.udp_port);
                contact_addrs.push(addr);
                state.routing_table.insert(c);
            }

            // Build HelloReq to send to bootstrap node and all returned contacts
            let our_options: u8 = if state.firewalled { 0x05 } else { 0x04 };
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
            let hello = KadMessage::HelloReq {
                sender_id: state.local_id,
                tcp_port: state.tcp_port,
                version: KADEMLIA_VERSION,
                tags: hello_tags,
            };
            if let Ok(packet) = messages::encode_packet(&hello) {
                let _ = socket.send_to(&packet, from).await;
                for addr in &contact_addrs {
                    let _ = socket.send_to(&packet, addr).await;
                }
                debug!("Sent HelloReq to bootstrap node + {} returned contacts", contact_addrs.len());
            }

            // Chain-bootstrap: send BootstrapReq to a subset of returned contacts
            // so they return even more contacts (progressive discovery)
            let bootstrap_msg = KadMessage::BootstrapReq;
            if let Ok(bootstrap_pkt) = messages::encode_packet(&bootstrap_msg) {
                for addr in contact_addrs.iter().take(5) {
                    state.flood_protection.track_request(*addr, 0x01);
                    let _ = socket.send_to(&bootstrap_pkt, addr).await;
                }
            }

            let table_size = state.routing_table.len();
            debug!("Routing table now has {table_size} contacts");
            state.stats.connected_peers = table_size as u32;
            if state.stats.status != NetworkStatus::Connected {
                state.stats.status = NetworkStatus::Connected;
                let _ = app_handle.emit("network-status", NetworkStatus::Connected);
            }

            // Trigger self-lookup as soon as we have contacts from first bootstrap
            if !state.self_lookup_done && table_size >= 2 {
                let closest = state.routing_table.find_closest(&state.local_id, SEARCH_INITIAL_CONTACTS);
                if !closest.is_empty() {
                    let sid = state.search_manager.start_search(
                        state.local_id,
                        SearchType::FindNode,
                        closest,
                    );
                    info!("Started self-lookup from BootstrapRes, search {}, {table_size} contacts", sid.0);
                    state.self_lookup_done = true;
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

            // Parse TAG_KADMISCOPTIONS
            let kad_options = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_KADMISCOPTIONS)))
                .and_then(|t| t.uint8_value().or_else(|| t.uint16_value().map(|v| v as u8)).or_else(|| t.uint32_value().map(|v| v as u8)))
                .unwrap_or(0);

            let wants_ack = kad_options & 0x04 != 0;

            let now = chrono::Utc::now().timestamp();
            let contact_ip_u32 = u32::from(ip);
            state.routing_table.insert(KadContact {
                id: sender_id,
                ip,
                udp_port: from.port(),
                tcp_port,
                version,
                last_seen: now,
                verified: false,
                contact_type: CONTACT_TYPE_OPEN,
                udp_key: Some(KadUDPKey::generate(state.udp_key_seed, contact_ip_u32)),
                kad_options,
                created_at: now,
                expires_at: 0,
                last_type_set: 0,
            });

            if let Some(nick) = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_FILENAME)))
                .and_then(|t| t.string_value())
            {
                let sanitized = crate::security::sanitize_display_name(nick);
                if !sanitized.is_empty() {
                    state.peer_nicknames.insert(sender_id, sanitized);
                }
            }

            // Extract peer's UDP verify key from tags
            if let Some(peer_udp_key) = extract_udp_key_from_tags(&tags) {
                if let Some(contact) = state.routing_table.get_contact_mut(&sender_id) {
                    contact.udp_key = Some(peer_udp_key);
                }
            }

            // Build our firewall options + UDP verify key for the peer
            // Bit 0: UDP firewalled, bit 1: TCP firewalled, bit 2: request ACK
            let our_options: u8 = if state.firewalled { 0x05 } else { 0x04 };
            let contact_ip_u32_for_key = u32::from(ip);
            let our_key_for_peer = KadUDPKey::generate(state.udp_key_seed, contact_ip_u32_for_key);
            let mut res_tags = vec![
                KadTag {
                    name: TagName::Id(TAG_KADMISCOPTIONS),
                    value: TagValue::Uint8(our_options),
                },
                KadTag {
                    name: TagName::Id(TAG_KADUDPKEY),
                    value: TagValue::Uint32(our_key_for_peer.key),
                },
            ];
            if !settings.nickname.is_empty() {
                res_tags.push(KadTag {
                    name: TagName::Id(TAG_FILENAME),
                    value: TagValue::String(settings.nickname.clone()),
                });
            }

            let res = KadMessage::HelloRes {
                sender_id: state.local_id,
                tcp_port: state.tcp_port,
                version: KADEMLIA_VERSION,
                tags: res_tags,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = send_kad_packet(socket, &packet, from, state, &sender_id).await;
            }

            // Send HelloResAck if requested
            if wants_ack {
                let ack_tags = vec![
                    KadTag {
                        name: TagName::Id(TAG_KADUDPKEY),
                        value: TagValue::Uint32(our_key_for_peer.key),
                    },
                ];
                let ack = KadMessage::HelloResAck {
                    sender_id: state.local_id,
                    tags: ack_tags,
                };
                if let Ok(packet) = messages::encode_packet(&ack) {
                    let _ = send_kad_packet(socket, &packet, from, state, &sender_id).await;
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

            let kad_options = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_KADMISCOPTIONS)))
                .and_then(|t| t.uint8_value().or_else(|| t.uint16_value().map(|v| v as u8)).or_else(|| t.uint32_value().map(|v| v as u8)))
                .unwrap_or(0);

            // Extract peer's UDP verify key
            let peer_udp_key = extract_udp_key_from_tags(&tags);

            let now = chrono::Utc::now().timestamp();
            let contact_ip_u32 = u32::from(ip);
            let udp_key = peer_udp_key.unwrap_or_else(|| KadUDPKey::generate(state.udp_key_seed, contact_ip_u32));
            state.routing_table.insert(KadContact {
                id: sender_id,
                ip,
                udp_port: from.port(),
                tcp_port,
                version,
                last_seen: now,
                verified: false,
                contact_type: CONTACT_TYPE_OPEN,
                udp_key: Some(udp_key),
                kad_options,
                created_at: now,
                expires_at: 0,
                last_type_set: 0,
            });
            state.stats.connected_peers = state.routing_table.len() as u32;

            let nick = tags.iter()
                .find(|t| matches!(&t.name, TagName::Id(TAG_FILENAME)))
                .and_then(|t| t.string_value())
                .map(|n| crate::security::sanitize_display_name(n))
                .unwrap_or_default();

            if !nick.is_empty() {
                state.peer_nicknames.insert(sender_id, nick.clone());
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

        KadMessage::HelloResAck { sender_id, tags } => {
            debug!("HelloResAck from {from} - contact {} verified", sender_id);
            state.routing_table.mark_verified(&sender_id);
            if let Some(peer_udp_key) = extract_udp_key_from_tags(&tags) {
                if let Some(contact) = state.routing_table.get_contact_mut(&sender_id) {
                    contact.udp_key = Some(peer_udp_key);
                }
            }
        }

        KadMessage::KadReq {
            search_type,
            target,
            receiver: _,
        } => {
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
                    let _ = socket.send_to(&packet, from).await;
                }
            }
        }

        KadMessage::KadRes { target, contacts } => {
            info!("KadRes from {from}: {} contacts for target {target}", contacts.len());
            let search_ids: Vec<SearchId> = state
                .search_manager
                .active
                .iter()
                .filter(|(_, s)| s.target == target && !s.completed)
                .map(|(id, _)| *id)
                .collect();

            if search_ids.is_empty() {
                info!("  No active search for this target");
            }

            let sender_id_lookup = match from.ip() {
                std::net::IpAddr::V4(v4) => {
                    let from_routing = state
                        .routing_table
                        .all_contacts()
                        .find(|c| c.ip == v4 && c.udp_port == from.port())
                        .map(|c| c.id);
                    if from_routing.is_some() {
                        from_routing
                    } else {
                        let mut found = None;
                        for (_, search) in state.search_manager.active.iter() {
                            if let Some(c) = search.closest.iter().find(|c| c.ip == v4 && c.udp_port == from.port()) {
                                found = Some(c.id);
                                break;
                            }
                        }
                        found
                    }
                }
                _ => None,
            };

            if sender_id_lookup.is_none() && !search_ids.is_empty() {
                info!("  Could not resolve sender KadId for {from}");
            }

            for sid in search_ids {
                let sender_id = sender_id_lookup.or_else(|| {
                    state.search_manager.get(&sid)
                        .and_then(|s| s.pending.iter().next().copied())
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
                            if state.ip_filter.is_blocked_readonly(c.ip)
                                || state.banned_ips.contains(&c.ip)
                            {
                                return false;
                            }
                            if !seen_ips.insert(c.ip) {
                                debug!("KadRes: duplicate IP {} in response, ignoring", c.ip);
                                return false;
                            }
                            let o = c.ip.octets();
                            let subnet = u32::from_be_bytes([o[0], o[1], o[2], 0]);
                            let count = subnet_counts.entry(subnet).or_insert(0);
                            *count += 1;
                            if *count > 2 {
                                debug!("KadRes: >2 contacts from subnet {}.{}.{}.0, ignoring {}", o[0], o[1], o[2], c.ip);
                                return false;
                            }
                            true
                        })
                        .cloned()
                        .collect();
                    info!("  Search {}: processing {} contacts from {} ({} filtered)", sid.0, safe_contacts.len(), sender_id, contacts.len() - safe_contacts.len());
                    search.handle_response(&sender_id, safe_contacts.clone());

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
            info!(
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

            let search_ids: Vec<SearchId> = state
                .search_manager
                .active
                .iter()
                .filter(|(_, s)| s.target == target && !s.completed)
                .map(|(id, _)| *id)
                .collect();

            if search_ids.is_empty() {
                info!("  No active search for this target");
            }

            for sid in search_ids {
                if let Some(search) = state.search_manager.get_mut(&sid) {
                    search.handle_search_results(&sender_id, results.clone());
                    let unique: std::collections::HashSet<&kad::types::KadId> =
                        search.results.iter().map(|r| &r.id).collect();
                    info!(
                        "  Search {} now has {} raw / {} unique results (phase={:?})",
                        sid.0, search.results.len(), unique.len(), search.phase
                    );
                }
            }
        }

        KadMessage::PublishRes { target, load } => {
            if state.publish_pending.remove(&target).is_some() {
                state.publish_confirmed += 1;
                debug!("Publish confirmed for {target} (load={load}, total_confirmed={})", state.publish_confirmed);
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
                let _ = socket.send_to(&packet, from).await;
            }
        }

        KadMessage::Pong { udp_port } => {
            debug!("Pong from {from} (reported udp_port={})", udp_port);
            let sender_id = match from.ip() {
                std::net::IpAddr::V4(v4) => state
                    .routing_table
                    .all_contacts()
                    .find(|c| c.ip == v4 && c.udp_port == from.port())
                    .map(|c| c.id),
                _ => None,
            };
            if let Some(id) = sender_id {
                state.routing_table.handle_pong(&id);
            }
            // External UDP port detection (only when NAT traversal is enabled)
            if udp_port > 0 && state.nat_traversal_enabled {
                state.udp_port_responses.push(udp_port);
                if state.udp_port_responses.len() >= 2 {
                    let mut counts: HashMap<u16, usize> = HashMap::new();
                    for &p in &state.udp_port_responses {
                        *counts.entry(p).or_insert(0) += 1;
                    }
                    if let Some((&best_port, _)) = counts.iter().max_by_key(|(_, &c)| c) {
                        if Some(best_port) != state.external_udp_port {
                            state.external_udp_port = Some(best_port);
                            if best_port != state.udp_port {
                                info!("External UDP port detected: {} (configured: {})", best_port, state.udp_port);
                            }
                        }
                    }
                }
            }
        }

        KadMessage::SearchKeyReq { target, start_position } => {
            let mut results = state.dht_store.search_keywords(&target);

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
                    if let Ok(raw_bytes) = hex::decode(&file.hash) {
                        let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
                        let local_ip = state.external_ip
                            .map(|ip| u32::from_be_bytes(ip.octets()))
                            .unwrap_or(0);
                        results.push(kad::messages::SearchResultEntry {
                            id: kad_hash,
                            tags: vec![
                                KadTag { name: TagName::Id(TAG_FILENAME), value: TagValue::String(file.name.clone()) },
                                KadTag { name: TagName::Id(TAG_FILESIZE), value: TagValue::Uint64(file.size) },
                                KadTag { name: TagName::Id(TAG_SOURCEIP), value: TagValue::Uint32(local_ip) },
                                KadTag { name: TagName::Id(TAG_SOURCEPORT), value: TagValue::Uint16(settings.tcp_port) },
                            ],
                        });
                    }
                }
            }

            let start = start_position as usize;
            let end = results.len().min(start + 200);
            let page = if start < results.len() { results[start..end].to_vec() } else { Vec::new() };

            let res = KadMessage::SearchRes {
                sender_id: state.local_id,
                target,
                results: page,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = socket.send_to(&packet, from).await;
            }
        }

        KadMessage::SearchSourceReq { target, start_position, .. } => {
            let results = state.dht_store.search_sources(&target);
            let start = start_position as usize;
            let end = results.len().min(start + 200);
            let page = if start < results.len() { results[start..end].to_vec() } else { Vec::new() };

            let res = KadMessage::SearchRes {
                sender_id: state.local_id,
                target,
                results: page,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = socket.send_to(&packet, from).await;
            }
        }

        KadMessage::PublishKeyReq { target, entries } => {
            if !state.dht_store.is_within_tolerance(&target) {
                debug!("PublishKeyReq for {target} rejected - outside tolerance zone");
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = socket.send_to(&packet, from).await;
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
                    let _ = socket.send_to(&packet, from).await;
                }
            }
        }

        KadMessage::PublishSourceReq { target, sender_id, tags } => {
            if !state.dht_store.is_within_tolerance(&target) {
                debug!("PublishSourceReq for {target} rejected - outside tolerance zone");
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = socket.send_to(&packet, from).await;
                }
            } else {
                let sender_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let load = state.dht_store.store_source_entry(
                    &target, sender_id, tags, sender_ip, from.port(),
                );
                let res = KadMessage::PublishRes { target, load };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = socket.send_to(&packet, from).await;
                }
            }
        }

        KadMessage::PublishNotesReq { target, sender_id, tags } => {
            if !state.dht_store.is_within_tolerance(&target) {
                let res = KadMessage::PublishRes { target, load: 100 };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = socket.send_to(&packet, from).await;
                }
            } else {
                let load = state.dht_store.store_notes_entry(&target, sender_id, tags);
                let res = KadMessage::PublishRes { target, load };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = socket.send_to(&packet, from).await;
                }
            }
        }

        KadMessage::SearchNotesReq { target, .. } => {
            let results = state.dht_store.search_notes(&target);
            let res = KadMessage::SearchRes {
                sender_id: state.local_id,
                target,
                results,
            };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = socket.send_to(&packet, from).await;
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
            let ip_raw = match from.ip() {
                std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                _ => return,
            };
            let res = KadMessage::FirewalledRes { ip: ip_raw };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = socket.send_to(&packet, from).await;
            }

            // Optionally try to connect back to their TCP port to verify they're reachable
            let peer_ip = match from.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => return,
            };
            if peer_tcp_port > 0 {
                let tcp_addr = SocketAddr::new(peer_ip.into(), peer_tcp_port);
                tokio::spawn(async move {
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::net::TcpStream::connect(tcp_addr),
                    )
                    .await;
                    match result {
                        Ok(Ok(_)) => debug!("Peer {tcp_addr} is reachable on TCP"),
                        _ => debug!("Peer {tcp_addr} is NOT reachable on TCP"),
                    }
                });
            }
        }

        KadMessage::FirewalledRes { ip } => {
            if !state.nat_traversal_enabled { return; }
            let external_ip = Ipv4Addr::from(ip.to_be_bytes());
            info!("FirewalledRes: our external IP is {external_ip}");
            state.firewall_responses.push(external_ip);

            // Use majority vote from multiple responses
            if state.firewall_responses.len() >= 2 {
                let mut counts: HashMap<Ipv4Addr, usize> = HashMap::new();
                for ip in &state.firewall_responses {
                    *counts.entry(*ip).or_insert(0) += 1;
                }
                if let Some((&best_ip, _)) = counts.iter().max_by_key(|(_, &c)| c) {
                    state.external_ip = Some(best_ip);
                    info!("External IP determined: {best_ip}");

                    let test_addr = SocketAddr::new(best_ip.into(), state.tcp_port);
                    let app = app_handle.clone();
                    let fw_flag = state.firewalled_shared.clone();
                    tokio::spawn(async move {
                        let result = tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            tokio::net::TcpStream::connect(test_addr),
                        )
                        .await;
                        match result {
                            Ok(Ok(_)) => {
                                info!("TCP port is reachable - NOT firewalled");
                                fw_flag.store(false, std::sync::atomic::Ordering::Relaxed);
                                let _ = app.emit("firewall-status", serde_json::json!({
                                    "firewalled": false,
                                    "external_ip": best_ip.to_string(),
                                }));
                            }
                            _ => {
                                info!("TCP port is NOT reachable - firewalled");
                                fw_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                                let _ = app.emit("firewall-status", serde_json::json!({
                                    "firewalled": true,
                                    "external_ip": best_ip.to_string(),
                                }));
                            }
                        }
                    });
                }
            } else {
                state.external_ip = Some(external_ip);
            }
        }

        KadMessage::Firewalled2Req { tcp_port: peer_tcp_port, user_hash: _, connect_options: _ } => {
            if !state.nat_traversal_enabled { return; }
            let ip_raw = match from.ip() {
                std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                _ => return,
            };
            let res = KadMessage::FirewalledRes { ip: ip_raw };
            if let Ok(packet) = messages::encode_packet(&res) {
                let _ = socket.send_to(&packet, from).await;
            }
            if peer_tcp_port > 0 {
                let peer_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let tcp_addr = SocketAddr::new(peer_ip.into(), peer_tcp_port);
                tokio::spawn(async move {
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        tokio::net::TcpStream::connect(tcp_addr),
                    ).await;
                    match result {
                        Ok(Ok(_)) => debug!("Peer {tcp_addr} is reachable on TCP (Firewalled2)"),
                        _ => debug!("Peer {tcp_addr} is NOT reachable on TCP (Firewalled2)"),
                    }
                });
            }
        }

        KadMessage::FirewallUdp { error_code, udp_port } => {
            if !state.nat_traversal_enabled { return; }
            debug!("FirewallUdp from {from}: error={error_code}, port={udp_port}");
            if error_code == 0 {
                info!("UDP firewall test passed - UDP port {udp_port} is reachable");
            }
        }

        KadMessage::FindBuddyReq { buddy_id, user_id, tcp_port: peer_tcp_port } => {
            if !state.nat_traversal_enabled { return; }
            debug!("FindBuddyReq from {from}: buddy_id={buddy_id}, user_id={user_id}");
            if !state.firewalled && !state.buddy_manager.is_serving() {
                let res = KadMessage::FindBuddyRes {
                    buddy_id,
                    user_hash: state.user_hash,
                    tcp_port: state.tcp_port,
                    connect_options: 0,
                };
                if let Ok(packet) = messages::encode_packet(&res) {
                    let _ = socket.send_to(&packet, from).await;
                }
                info!("Offered to be buddy for {user_id} (tcp_port={})", peer_tcp_port);

                // The firewalled client will connect to us via TCP. 
                // Accept the buddy relationship proactively via a TCP connection attempt.
                let buddy_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let buddy_addr = SocketAddr::new(buddy_ip.into(), peer_tcp_port);
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    tokio::net::TcpStream::connect(buddy_addr),
                ).await {
                    Ok(Ok(stream)) => {
                        if state.buddy_manager.accept_buddy_request(user_id, stream) {
                            info!("Accepted buddy request from {} at {}", user_id, buddy_addr);
                        }
                    }
                    Ok(Err(e)) => {
                        debug!("Could not establish buddy TCP with {}: {}", user_id, e);
                    }
                    Err(_) => {
                        debug!("Buddy TCP connect to {} timed out", user_id);
                    }
                }
            }
        }

        KadMessage::FindBuddyRes { buddy_id, user_hash: _, tcp_port: peer_tcp_port, .. } => {
            if !state.nat_traversal_enabled { return; }
            debug!("FindBuddyRes from {from}: buddy_id={buddy_id}, tcp_port={peer_tcp_port}");
            if state.buddy_manager.state() == BuddyState::FindingBuddy {
                let buddy_ip = match from.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return,
                };
                let connected = state.buddy_manager.handle_findbuddy_response(
                    buddy_id,
                    buddy_ip,
                    peer_tcp_port,
                ).await;
                if connected {
                    info!("Successfully connected to buddy {} at {}:{}", buddy_id, buddy_ip, peer_tcp_port);
                }
            }
        }

        KadMessage::CallbackReq { buddy_id, file_id, tcp_port: peer_tcp_port } => {
            debug!("CallbackReq from {from}: buddy_id={buddy_id}, file_id={file_id}");
            if state.buddy_manager.is_serving() {
                if let Some(serving_for) = state.buddy_manager.serving_for().cloned() {
                    debug!("Relaying callback to our buddy {}", serving_for);
                    let relay_data = messages::encode_packet(&KadMessage::CallbackReq {
                        buddy_id,
                        file_id,
                        tcp_port: peer_tcp_port,
                    });
                    if let Ok(data) = relay_data {
                        let relayed = state.buddy_manager.relay_callback(&data).await;
                        if relayed {
                            debug!("Callback relayed successfully");
                        } else {
                            warn!("Failed to relay callback to buddy");
                        }
                    }
                }
            }
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
) {
    match cmd {
        NetworkCommand::SearchFiles { query, tx } => {
            let index = local_index.read().await;
            let local_results = index.search(&query);

            let keywords = kad::publish::extract_keywords(&query);
            if keywords.is_empty() {
                let _ = tx.send(local_results);
                return;
            }

            // Use the longest keyword as the primary search term (most selective)
            let primary_keyword = keywords.iter().max_by_key(|k| k.len()).unwrap();
            let keyword_hash = kad::publish::keyword_to_kad_id(primary_keyword);
            info!("Searching KAD for keyword '{}' -> hash {}", primary_keyword, keyword_hash);

            let closest = state
                .routing_table
                .find_closest_prefer_verified(&keyword_hash, SEARCH_INITIAL_CONTACTS);

            if closest.is_empty() {
                let _ = tx.send(local_results);
                return;
            }

            let sid = state.search_manager.start_search(
                keyword_hash,
                SearchType::FindKeyword,
                closest,
            );

            state.pending_keyword_searches.insert(sid, (tx, local_results));
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

                let download = Ed2kDownload {
                    transfer_id,
                    file_hash: hash_bytes,
                    file_name,
                    file_size,
                    source_addr,
                    download_dir: PathBuf::from(&settings.download_folder),
                    user_hash: state.user_hash,
                    nickname: settings.nickname.clone(),
                    tcp_port: settings.tcp_port,
                    udp_port: settings.udp_port,
                    bandwidth_limiter: bandwidth_limiter.clone(),
                    control,
                };

                let tx = dl_event_tx.clone();
                tokio::spawn(async move {
                    if let Err(e) = download.run(tx).await {
                        error!("Download failed: {e}");
                    }
                });
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

                // Persist download to database for resume across restarts
                let db_transfer = Transfer {
                    id: transfer_id.clone(),
                    file_name: file_name.clone(),
                    file_hash: file_hash.clone(),
                    peer_id: String::new(),
                    peer_name: String::new(),
                    direction: TransferDirection::Download,
                    status: TransferStatus::Searching,
                    progress: 0.0,
                    speed: 0,
                    total_size: file_size,
                    transferred: 0,
                    started_at: now,
                    failure_reason: None,
                };
                let _ = db.save_transfer(&db_transfer);

                state.pending_downloads.insert(transfer_id.clone(), PendingDownload {
                    transfer_id: transfer_id.clone(),
                    file_hash: file_hash.clone(),
                    file_name,
                    file_size,
                    control,
                    search_count: 1,
                    last_search_at: now,
                });

                if !closest.is_empty() {
                    // Prefer non-firewalled contacts for source searching
                    closest.sort_by_key(|c| c.is_tcp_firewalled() as u8);
                    let sid = state.search_manager.start_search(
                        kad_hash,
                        SearchType::FindSource { file_size },
                        closest,
                    );
                    state.download_source_searches.insert(sid, transfer_id.clone());
                    info!("Started source search {} for download {}", sid.0, transfer_id);
                }
            }
        }

        NetworkCommand::GetPeers { tx } => {
            let banned_ids = db.banned_peer_ids().unwrap_or_default();
            let peers: Vec<PeerInfo> = state
                .routing_table
                .all_contacts()
                .take(200)
                .filter(|c| !banned_ids.contains(&c.id.to_hex()))
                .map(|c| PeerInfo {
                    id: c.id.to_hex(),
                    addresses: vec![format!("{}:{}", c.ip, c.udp_port)],
                    nickname: state.peer_nicknames.get(&c.id).cloned().unwrap_or_default(),
                    last_seen: c.last_seen,
                    files_shared: 0,
                    banned: false,
                })
                .collect();
            let _ = tx.send(peers);
        }

        NetworkCommand::GetStats { tx } => {
            state.stats.connected_peers = state.routing_table.len() as u32;
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
            // Sync firewall status from shared atomic (updated by spawned detection tasks)
            state.firewalled = state.firewalled_shared.load(std::sync::atomic::Ordering::Relaxed);
            state.stats.firewalled = state.firewalled;
            let _ = tx.send(state.stats.clone());
        }

        NetworkCommand::AnnounceFiles { files } => {
            for file in files {
                if let Ok(raw_bytes) = hex::decode(&file.hash) {
                    let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
                    let publishable = PublishableFile {
                        file_hash: kad_hash,
                        file_name: file.name.clone(),
                        file_size: file.size,
                        file_type: file.extension.clone(),
                    };
                    state.publish_manager.add_file(publishable);
                }
            }
            info!(
                "Registered {} files for KAD publishing",
                state.publish_manager.file_count()
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
            state.pending_note_publishes.insert(sid, (file_hash, rating, comment.clone()));
            info!(
                "Started StoreNotes search {} for file {} (rating={}, comment_len={})",
                sid.0, file_hash, rating, comment.len()
            );
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
            info!("Unbanned peer {peer_id_hex}");
        }

        NetworkCommand::UnannounceFiles { file_hashes } => {
            for hash_hex in &file_hashes {
                if let Ok(raw_bytes) = hex::decode(hash_hex) {
                    let kad_hash = md4_bytes_to_kad_id(&raw_bytes);
                    state.publish_manager.remove_file(&kad_hash);
                }
            }
            info!(
                "Unannounced {} files, {} files remain published",
                file_hashes.len(),
                state.publish_manager.file_count()
            );
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

            state.pending_source_searches.insert(sid, tx);
        }

        NetworkCommand::BootstrapContacts { contacts } => {
            let count = contacts.len();
            for c in &contacts {
                state.routing_table.insert(c.clone());
            }
            info!(
                "Injected {} bootstrap contacts, routing table now has {} entries",
                count,
                state.routing_table.len()
            );

            // Send bootstrap requests to a sample of the new contacts
            let sample_size = count.min(20);
            for contact in contacts.iter().take(sample_size) {
                let addr = SocketAddr::new(contact.ip.into(), contact.udp_port);
                let msg = KadMessage::BootstrapReq;
                if let Ok(packet) = messages::encode_packet(&msg) {
                    let _ = socket.send_to(&packet, addr).await;
                }
            }
            info!("Sent bootstrap requests to {sample_size} new contacts");
        }

        NetworkCommand::ReloadIpFilter { path } => {
            state.ip_filter.load_from_file(&path);
            info!(
                "Reloaded IP filter from {}: {} ranges",
                path.display(),
                state.ip_filter.range_count(),
            );
        }

        NetworkCommand::GetIpFilterStats { tx } => {
            let _ = tx.send(state.ip_filter.get_stats());
        }

        NetworkCommand::AddIpRange { start_ip, end_ip, description } => {
            if let (Ok(start), Ok(end)) = (start_ip.parse::<Ipv4Addr>(), end_ip.parse::<Ipv4Addr>()) {
                state.ip_filter.add_range(start, end, description);
                info!("Added IP filter range {start_ip} - {end_ip}, total ranges: {}", state.ip_filter.range_count());
            }
        }

        NetworkCommand::RemoveIpRange { start_ip, end_ip } => {
            if state.ip_filter.remove_range(&start_ip, &end_ip) {
                info!("Removed IP filter range {start_ip} - {end_ip}, total ranges: {}", state.ip_filter.range_count());
            }
        }

        NetworkCommand::SetIpFilterEnabled { enabled } => {
            state.ip_filter.set_enabled(enabled);
            info!("IP filter enabled: {enabled}");
        }

        NetworkCommand::SetBlockPrivateIps { block_private } => {
            state.ip_filter.set_block_private(block_private);
            info!("Block private IPs: {block_private}");
        }

        NetworkCommand::Shutdown => {}
    }
}

async fn handle_download_event(
    event: DownloadEvent,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    db: &Arc<Database>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    match event {
        DownloadEvent::Progress {
            transfer_id,
            downloaded,
            total,
        } => {
            let speed = {
                let mut mgr = transfer_manager.write().await;
                mgr.update_progress(&transfer_id, downloaded, 0);
                if let Some(t) = mgr.active.get(&transfer_id) {
                    t.speed
                } else {
                    0
                }
            };
            let progress = if total > 0 {
                (downloaded as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let _ = app_handle.emit(
                "transfer-progress",
                serde_json::json!({
                    "id": transfer_id,
                    "downloaded": downloaded,
                    "total": total,
                    "progress": progress,
                    "speed": speed,
                    "global_download_speed": bandwidth_limiter.download_speed(),
                }),
            );
        }
        DownloadEvent::Completed { transfer_id } => {
            let promoted = {
                let mut mgr = transfer_manager.write().await;
                mgr.complete(&transfer_id)
            };
            for t in &promoted {
                info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
            }
            let _ = db.update_transfer_status(&transfer_id, "\"completed\"");
            let _ = app_handle.emit(
                "transfer-complete",
                serde_json::json!({ "id": transfer_id }),
            );
        }
        DownloadEvent::Failed { transfer_id, error } => {
            let promoted = {
                let mut mgr = transfer_manager.write().await;
                mgr.fail(&transfer_id, &error)
            };
            for t in &promoted {
                info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
            }
            let _ = db.update_transfer_status(&transfer_id, "\"failed\"");
            let _ = app_handle.emit(
                "transfer-failed",
                serde_json::json!({ "id": transfer_id, "error": error }),
            );
        }
    }
}

async fn handle_upload_event(
    event: UploadEvent,
    app_handle: &tauri::AppHandle,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
) {
    match event.kind {
        UploadEventKind::Started {
            file_name,
            file_hash,
            total_size,
            peer_addr,
        } => {
            let transfer = Transfer {
                id: event.transfer_id.clone(),
                file_name,
                file_hash,
                peer_id: peer_addr.clone(),
                peer_name: peer_addr,
                direction: TransferDirection::Upload,
                status: TransferStatus::Active,
                progress: 0.0,
                speed: 0,
                total_size,
                transferred: 0,
                started_at: chrono::Utc::now().timestamp(),
                failure_reason: None,
            };
            {
                let mut mgr = transfer_manager.write().await;
                mgr.enqueue(transfer);
            }
            let _ = app_handle.emit(
                "transfer-started",
                serde_json::json!({ "id": event.transfer_id, "direction": "upload" }),
            );
        }
        UploadEventKind::Progress { uploaded, total } => {
            let speed = {
                let mut mgr = transfer_manager.write().await;
                mgr.update_progress(&event.transfer_id, uploaded, 0);
                mgr.active
                    .get(&event.transfer_id)
                    .map(|t| t.speed)
                    .unwrap_or(0)
            };
            let progress = if total > 0 {
                (uploaded as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let _ = app_handle.emit(
                "transfer-progress",
                serde_json::json!({
                    "id": event.transfer_id,
                    "uploaded": uploaded,
                    "total": total,
                    "progress": progress,
                    "speed": speed,
                    "direction": "upload",
                    "global_upload_speed": bandwidth_limiter.upload_speed(),
                }),
            );
        }
        UploadEventKind::Completed => {
            let promoted = {
                let mut mgr = transfer_manager.write().await;
                mgr.complete(&event.transfer_id)
            };
            for t in &promoted {
                info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
            }
            let _ = app_handle.emit(
                "transfer-complete",
                serde_json::json!({ "id": event.transfer_id, "direction": "upload" }),
            );
        }
        UploadEventKind::Failed { error } => {
            let promoted = {
                let mut mgr = transfer_manager.write().await;
                mgr.fail(&event.transfer_id, &error)
            };
            for t in &promoted {
                info!("Promoted queued transfer {} ({}) to active", t.id, t.file_name);
            }
            let _ = app_handle.emit(
                "transfer-failed",
                serde_json::json!({ "id": event.transfer_id, "error": error, "direction": "upload" }),
            );
        }
    }
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
                    TagName::Id(TAG_COMPLETE_SOURCES) => {}
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

            if file_type.is_empty() {
                file_type = infer_file_type(&extension);
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
            })
        })
        .collect();

    // Deduplicate by file hash, accumulating source counts across KAD nodes.
    // In eMule (CSearch::ProcessResult), each search result entry with the
    // same file hash adds to the source count. If TAG_SOURCES is 0 or absent,
    // the entry still counts as 1 source (the publishing node itself).
    let mut dedup: HashMap<String, SearchResult> = HashMap::new();
    let mut sources_accum: HashMap<String, u32> = HashMap::new();

    for p in parsed {
        // eMule treats each entry as at least 1 source even if TAG_SOURCES=0
        let effective_sources = if p.sources_tag > 0 { p.sources_tag } else { 1 };

        if let Some(existing) = dedup.get_mut(&p.hash) {
            if !p.source_addr.is_empty() && !existing.source_addresses.contains(&p.source_addr) {
                existing.source_addresses.push(p.source_addr);
            }
            let acc = sources_accum.entry(p.hash.clone()).or_insert(0);
            *acc += effective_sources;
            existing.availability = (*acc).max(existing.source_addresses.len() as u32);

            if existing.file.name.len() < p.name.len() {
                existing.file.name = p.name;
            }
            if existing.file_type.is_empty() && !p.file_type.is_empty() {
                existing.file_type = p.file_type;
            }
        } else {
            let mut source_addresses = Vec::new();
            if !p.source_addr.is_empty() {
                source_addresses.push(p.source_addr.clone());
            }
            let availability = effective_sources.max(source_addresses.len() as u32);
            sources_accum.insert(p.hash.clone(), effective_sources);
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
                    },
                    peer_id: p.source_addr,
                    peer_name: String::new(),
                    availability,
                    file_type: p.file_type,
                    source_addresses,
                },
            );
        }
    }

    let results: Vec<SearchResult> = dedup.into_values().collect();

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

fn extract_sources_from_results(
    entries: &[kad::messages::SearchResultEntry],
) -> Vec<(String, u16)> {
    let mut sources = Vec::new();
    for entry in entries {
        let mut ip = 0u32;
        let mut port = 0u16;
        for tag in &entry.tags {
            match &tag.name {
                TagName::Id(TAG_SOURCEIP) => {
                    if let Some(v) = tag.uint32_value() {
                        ip = v;
                    }
                }
                TagName::Id(TAG_SOURCEPORT) => {
                    if let Some(v) = tag.uint16_value() {
                        port = v;
                    }
                }
                _ => {}
            }
        }
        if ip != 0 && port != 0 {
            let addr = Ipv4Addr::from(ip.to_be_bytes());
            let key = (addr.to_string(), port);
            if !sources.contains(&key) {
                sources.push(key);
            }
        }
    }
    sources
}

/// Extract a UDP verify key from KAD hello tags.
fn extract_udp_key_from_tags(tags: &[KadTag]) -> Option<KadUDPKey> {
    let key_val = tags.iter()
        .find(|t| matches!(&t.name, TagName::Id(TAG_KADUDPKEY)))
        .and_then(|t| t.uint32_value())?;
    if key_val == 0 {
        return None;
    }
    Some(KadUDPKey { key: key_val, ip: 0 })
}
