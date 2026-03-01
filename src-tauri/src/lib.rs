mod app_state;
mod bandwidth;
mod commands;
mod network;
mod search;
pub mod security;
mod sharing;
mod storage;
mod types;

use tauri::Emitter;

use std::sync::Arc;
use tauri::Manager;
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use app_state::AppState;
use bandwidth::limiter::BandwidthLimiter;
use search::index::LocalIndex;
use sharing::indexer::FileIndexer;
use sharing::manager::TransferManager;
use storage::config::AppConfig;
use storage::database::Database;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let log_dir = directories::ProjectDirs::from("com", "nexus", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);
    let file_appender = tracing_appender::rolling::daily(&log_dir, "nexus.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(tracing_subscriber::fmt::layer().with_ansi(false).with_writer(non_blocking))
        .init();

    // Keep the guard alive for the entire app lifetime
    let _log_guard = _guard;

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            let db = Arc::new(
                Database::new(&app_handle).expect("Failed to initialize database"),
            );

            let config = AppConfig::load(&app_handle).expect("Failed to load config");
            let settings = config.settings.clone();

            let (network_tx, network_rx) = mpsc::channel(256);

            let local_index = Arc::new(RwLock::new(LocalIndex::new()));

            let bandwidth_limiter = Arc::new(BandwidthLimiter::new(
                settings.max_upload_speed,
                settings.max_download_speed,
            ));

            let transfer_manager = Arc::new(RwLock::new(TransferManager::new(settings.max_concurrent_downloads)));

            let shutdown_complete = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shutdown_complete_net = shutdown_complete.clone();

            let bw_shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let scanning_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let cached_peers: Arc<RwLock<Vec<crate::types::PeerInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_stats: Arc<RwLock<crate::types::NetworkStats>> = Arc::new(RwLock::new(crate::types::NetworkStats::default()));
            let cached_contacts: Arc<RwLock<Vec<crate::types::KadContactInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_searches: Arc<RwLock<Vec<crate::types::KadSearchInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_servers: Arc<RwLock<Vec<crate::types::ServerInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_connected_server: Arc<RwLock<Option<crate::types::ServerInfo>>> = Arc::new(RwLock::new(None));
            let cached_transfer_stats: Arc<RwLock<crate::storage::statistics::TransferStats>> = Arc::new(RwLock::new(Default::default()));
            let cached_shared_files: Arc<RwLock<Vec<crate::types::FileInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_peers_net = cached_peers.clone();
            let cached_stats_net = cached_stats.clone();
            let cached_contacts_net = cached_contacts.clone();
            let cached_searches_net = cached_searches.clone();
            let cached_servers_net = cached_servers.clone();
            let cached_connected_server_net = cached_connected_server.clone();
            let cached_transfer_stats_net = cached_transfer_stats.clone();
            let cached_shared_files_net = cached_shared_files.clone();
            let startup_network_tx = network_tx.clone();

            app.manage(AppState {
                network_tx,
                db: db.clone(),
                config: Arc::new(RwLock::new(config)),
                local_index: local_index.clone(),
                bandwidth_limiter: bandwidth_limiter.clone(),
                transfer_manager: transfer_manager.clone(),
                shutdown_complete,
                bw_shutdown: bw_shutdown.clone(),
                scanning_count: scanning_count.clone(),
                cached_peers,
                cached_stats,
                cached_contacts,
                cached_searches,
                cached_servers,
                cached_connected_server,
                cached_transfer_stats,
                cached_shared_files: cached_shared_files.clone(),
            });

            let index_clone = local_index.clone();
            let db_clone = db.clone();
            let shared_folders = settings.shared_folders.clone();
            let startup_scanning = scanning_count.clone();
            let csf = cached_shared_files.clone();
            let startup_app = app_handle.clone();
            let net_tx = startup_network_tx;
            tauri::async_runtime::spawn(async move {
                // Pre-populate index from database for fast startup
                match db_clone.get_shared_files() {
                    Ok(cached_files) if !cached_files.is_empty() => {
                        let count = cached_files.len();
                        let mut index = index_clone.write().await;
                        index.add_files(cached_files);
                        info!("Pre-loaded {count} files from database cache");
                    }
                    _ => {}
                }
                { let snap = index_clone.read().await.all_files().to_vec(); *csf.write().await = snap; }

                if shared_folders.is_empty() {
                    info!("Indexed 0 files from 0 shared folders");
                    return;
                }

                startup_scanning.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                // Phase 1: fast discovery (metadata only, no hashing) for all folders
                let mut all_discovered: Vec<crate::types::FileInfo> = Vec::new();
                for folder in &shared_folders {
                    let f = folder.clone();
                    let discovered = tokio::task::spawn_blocking(move || {
                        FileIndexer::discover_directory(&f)
                    }).await.unwrap_or_default();
                    all_discovered.extend(discovered);
                }
                {
                    let mut index = index_clone.write().await;
                    index.add_files(all_discovered.clone());
                }
                { let snap = index_clone.read().await.all_files().to_vec(); *csf.write().await = snap; }

                let _ = startup_app.emit("shared-files-changed", serde_json::json!({
                    "phase": "discovered",
                    "count": all_discovered.len(),
                }));

                // Phase 2: hash one file at a time (same pattern as addSharedFolder)
                let total = all_discovered.len();
                let mut hashed = 0usize;
                for file in &all_discovered {
                    let file_path = file.path.clone();
                    let file_temp_id = file.id.clone();

                    {
                        let idx = index_clone.read().await;
                        if idx.all_files().iter().any(|f| f.path == file.path && !f.hash.is_empty()) {
                            hashed += 1;
                            continue;
                        }
                    }

                    let _ = startup_app.emit("file-hash-progress", serde_json::json!({
                        "current": hashed + 1,
                        "total": total,
                        "file_name": file.name,
                    }));

                    let hash_result = tokio::task::spawn_blocking(move || {
                        FileIndexer::hash_file(std::path::Path::new(&file_path))
                    }).await;

                    match hash_result {
                        Ok(Ok((ed2k_hash, aich_hash))) => {
                            let mut updated = file.clone();
                            updated.id = ed2k_hash.clone();
                            updated.hash = ed2k_hash;
                            updated.aich_hash = aich_hash;
                            {
                                let mut idx = index_clone.write().await;
                                idx.remove_file_by_id(&file_temp_id);
                                idx.add_file(updated.clone());
                            }
                            { let snap = index_clone.read().await.all_files().to_vec(); *csf.write().await = snap; }
                            let db_ref = db_clone.clone();
                            let announce = updated.clone();
                            tokio::task::spawn_blocking(move || {
                                let _ = db_ref.save_shared_file(&announce);
                            }).await.ok();
                            let _ = net_tx.try_send(network::NetworkCommand::AnnounceFiles {
                                files: vec![updated],
                            });
                            hashed += 1;
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("Startup hash failed for {}: {e}", file.name);
                            let mut idx = index_clone.write().await;
                            idx.remove_file_by_id(&file_temp_id);
                        }
                        Err(e) => {
                            tracing::error!("Startup hash task panicked for {}: {e}", file.name);
                            let mut idx = index_clone.write().await;
                            idx.remove_file_by_id(&file_temp_id);
                        }
                    }
                }

                startup_scanning.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                let _ = net_tx.try_send(network::NetworkCommand::SharedFilesChanged);
                let _ = startup_app.emit("file-hash-progress", serde_json::json!({
                    "current": total,
                    "total": total,
                    "file_name": "",
                    "done": true,
                }));
                info!(
                    "Indexed {} files from {} shared folders",
                    index_clone.read().await.file_count(),
                    shared_folders.len()
                );
            });

            let net_handle = app_handle.clone();
            let net_index = local_index.clone();
            let net_db = db.clone();
            let net_transfers = transfer_manager.clone();
            let net_bw = bandwidth_limiter.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = network::start_network(
                    net_handle,
                    network_rx,
                    settings,
                    net_index,
                    net_db,
                    net_transfers,
                    net_bw,
                    cached_peers_net,
                    cached_stats_net,
                    cached_contacts_net,
                    cached_searches_net,
                    cached_servers_net,
                    cached_connected_server_net,
                    cached_transfer_stats_net,
                    cached_shared_files_net,
                )
                .await
                {
                    tracing::error!("Network error: {e}");
                }
                shutdown_complete_net.store(true, std::sync::atomic::Ordering::Release);
            });

            let bw_limiter = bandwidth_limiter.clone();
            let bw_shutdown_spawn = bw_shutdown.clone();
            tauri::async_runtime::spawn(async move {
                bandwidth::limiter::start_token_refill(bw_limiter, bw_shutdown_spawn).await;
            });

            info!("Nexus P2P application started");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::search::search_files,
            commands::search::cancel_search,
            commands::search::find_notes,
            commands::search::find_sources,
            commands::search::compute_ed2k_hash,
            commands::search::publish_note,
            commands::search::format_ed2k_link,
            commands::search::parse_ed2k_link,
            commands::transfers::start_download,
            commands::transfers::pause_transfer,
            commands::transfers::resume_transfer,
            commands::transfers::cancel_transfer,
            commands::transfers::remove_transfer,
            commands::transfers::get_transfers,
            commands::transfers::clear_completed,
            commands::transfers::get_transfer_sources,
            commands::transfers::set_transfer_priority,
            commands::transfers::pause_all_transfers,
            commands::transfers::resume_all_transfers,
            commands::transfers::stop_transfer,
            commands::transfers::open_file,
            commands::transfers::recover_archive,
            commands::sharing::add_shared_folder,
            commands::sharing::remove_shared_folder,
            commands::sharing::get_shared_files,
            commands::sharing::get_shared_folders,
            commands::sharing::set_file_priority,
            commands::sharing::reload_shared_files,
            commands::sharing::unshare_file,
            commands::sharing::get_scan_status,
            commands::sharing::open_shared_file,
            commands::sharing::open_shared_folder,
            commands::peers::get_peers,
            commands::peers::get_network_stats,
            commands::peers::ban_peer,
            commands::peers::unban_peer,
            commands::peers::kad_connect,
            commands::peers::kad_disconnect,
            commands::peers::kad_bootstrap_ip,
            commands::peers::kad_bootstrap_url,
            commands::peers::kad_bootstrap_clients,
            commands::peers::kad_recheck_firewall,
            commands::peers::get_kad_contacts,
            commands::peers::get_kad_searches,
            commands::settings::get_settings,
            commands::settings::update_settings,
            commands::settings::download_nodes_dat,
            commands::settings::download_ipfilter,
            commands::security::get_ip_filter_stats,
            commands::security::add_ip_filter_range,
            commands::security::remove_ip_filter_range,
            commands::security::set_ip_filter_enabled,
            commands::security::set_block_private_ips,
            commands::security::download_and_load_ipfilter,
            commands::security::update_ipfilter_from_url,
            commands::security::import_ipfilter_file,
            commands::server::connect_to_server,
            commands::server::disconnect_server,
            commands::server::add_server,
            commands::server::remove_server,
            commands::server::get_server_list,
            commands::server::get_connected_server,
            commands::server::download_server_met,
            commands::comments::set_file_comment,
            commands::comments::get_file_comments,
            commands::statistics::get_statistics,
            commands::collections::load_collection,
            commands::collections::create_collection,
            commands::collections::download_collection_files,
            commands::preview::preview_file,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    state.bw_shutdown.store(true, std::sync::atomic::Ordering::Release);
                    let tx = state.network_tx.clone();
                    let _ = tx.try_send(network::NetworkCommand::Shutdown);
                    info!("Sent shutdown command to network, waiting for save...");

                    let flag = state.shutdown_complete.clone();
                    let start = std::time::Instant::now();
                    while !flag.load(std::sync::atomic::Ordering::Acquire) {
                        if start.elapsed() > std::time::Duration::from_secs(5) {
                            tracing::warn!("Network shutdown timed out after 5s");
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    info!("Network shutdown complete");
                }
            }
        });
}
