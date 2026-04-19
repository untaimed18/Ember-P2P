mod app_state;
mod bandwidth;
mod commands;
mod geoip;
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
    let log_dir = directories::ProjectDirs::from("com", "ember", "p2p")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _ = std::fs::create_dir_all(&log_dir);
    security::cleanup_old_logs(&log_dir, 7);
    let file_appender = tracing_appender::rolling::daily(&log_dir, "ember.log");
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
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            let app_handle = app.handle().clone();

            let db = Arc::new(
                Database::new(&app_handle).map_err(|e| {
                    tracing::error!("Failed to initialize database: {e}");
                    e
                })?,
            );

            let config = AppConfig::load(&app_handle).map_err(|e| {
                tracing::error!("Failed to load config: {e}");
                e
            })?;
            let settings = config.settings.clone();

            let spam_data_dir = app_handle
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            let spam_filter = Arc::new(RwLock::new(
                search::spam::SpamFilter::load(&spam_data_dir),
            ));

            let (network_tx, network_rx) = mpsc::channel(256);

            let local_index = Arc::new(RwLock::new(LocalIndex::new()));

            let bandwidth_limiter = Arc::new(BandwidthLimiter::new(
                settings.max_upload_speed,
                settings.max_download_speed,
            ));
            let uss_rtt_queue = bandwidth::new_uss_rtt_queue();
            let uss_enabled_flag = bandwidth::new_uss_enabled_flag(settings.uss_enabled);

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
            let hash_cancel_flags: Arc<RwLock<std::collections::HashMap<String, Arc<std::sync::atomic::AtomicBool>>>> = Arc::new(RwLock::new(std::collections::HashMap::new()));
            let cached_peers_net = cached_peers.clone();
            let cached_stats_net = cached_stats.clone();
            let cached_contacts_net = cached_contacts.clone();
            let cached_searches_net = cached_searches.clone();
            let cached_servers_net = cached_servers.clone();
            let cached_connected_server_net = cached_connected_server.clone();
            let cached_transfer_stats_net = cached_transfer_stats.clone();
            let cached_shared_files_net = cached_shared_files.clone();
            let startup_network_tx = network_tx.clone();

            let upload_shared_folders: app_state::SharedFolderList = Arc::new(RwLock::new(settings.shared_folders.clone()));
            let friend_hashes: app_state::SharedFriendHashes = {
                let mut set = std::collections::HashSet::new();
                if let Ok(rows) = db.get_friends() {
                    for (hash_hex, _, _) in &rows {
                        if let Ok(bytes) = hex::decode(hash_hex) {
                            if bytes.len() == 16 {
                                let mut h = [0u8; 16];
                                h.copy_from_slice(&bytes);
                                set.insert(h);
                            }
                        }
                    }
                    if !set.is_empty() {
                        info!("Loaded {} friends from database", set.len());
                    }
                }
                Arc::new(RwLock::new(set))
            };

            let shared_folder_watcher = sharing::watcher::SharedFoldersWatcher::start(
                app_handle.clone(),
                settings.shared_folders.clone(),
            );

            // known.met in-memory list. ember-V2's network module currently
            // doesn't consume this (see `start_network` signature), but
            // sharing/indexer and some cherry-picked commands still read it
            // via `AppState::known_files`, so we materialise it here rather
            // than leaking `Option<...>` all over the struct.
            let known_files = {
                let data_dir = directories::ProjectDirs::from("com", "ember", "p2p")
                    .map(|d| d.data_dir().to_path_buf())
                    .unwrap_or_else(|| std::path::PathBuf::from("."));
                Arc::new(RwLock::new(storage::known_files::KnownFileList::load(
                    &data_dir.join("known.met"),
                )))
            };

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
                cached_contacts,
                cached_transfer_stats,
                cached_shared_files: cached_shared_files.clone(),
                hash_cancel_flags: hash_cancel_flags.clone(),
                spam_filter: spam_filter.clone(),
                upload_shared_folders: upload_shared_folders.clone(),
                friend_hashes: friend_hashes.clone(),
                known_files,
                shared_folder_watcher,
                background_scans: Arc::new(RwLock::new(std::collections::HashMap::new())),
                background_scan_seq: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            });

            let index_clone = local_index.clone();
            let shared_folders = settings.shared_folders.clone();
            let startup_scanning = scanning_count.clone();
            let csf = cached_shared_files.clone();
            let startup_app = app_handle.clone();
            let net_tx = startup_network_tx;
            let startup_cancel_flags = hash_cancel_flags.clone();
            tauri::async_runtime::spawn(async move {
                if shared_folders.is_empty() {
                    info!("Indexed 0 files from 0 shared folders");
                    return;
                }

                struct StartupScanGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
                impl Drop for StartupScanGuard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                startup_scanning.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _scan_guard = StartupScanGuard(startup_scanning.clone());
                let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                startup_cancel_flags.write().await.insert("__startup__".to_string(), cancel_flag.clone());

                let discovery_handles: Vec<_> = shared_folders
                    .iter()
                    .map(|folder| {
                        let f = folder.clone();
                        tokio::task::spawn_blocking(move || FileIndexer::discover_directory(&f))
                    })
                    .collect();
                let mut all_discovered: Vec<crate::types::FileInfo> = Vec::new();
                for handle in discovery_handles {
                    match handle.await {
                        Ok(files) => all_discovered.extend(files),
                        Err(e) => tracing::error!("discover_directory panicked for folder: {e}"),
                    }
                }

                if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    info!("Startup hashing cancelled during discovery");
                    startup_cancel_flags.write().await.remove("__startup__");
                    let _ = startup_app.emit("file-hash-progress", serde_json::json!({ "done": true, "current": 0, "total": 0, "file_name": "" }));
                    return;
                }

                let known_list = {
                    let data_dir = directories::ProjectDirs::from("com", "ember", "p2p")
                        .map(|d| d.data_dir().to_path_buf())
                        .unwrap_or_else(|| std::path::PathBuf::from("."));
                    storage::known_files::KnownFileList::load(&data_dir.join("known.met"))
                };

                let mut files_to_hash: Vec<crate::types::FileInfo> = Vec::new();
                for file in &mut all_discovered {
                    if let Some(record) = known_list.find_by_path_and_meta(&file.path, file.size, file.modified_at) {
                        let hash = hex::encode(record.file_hash);
                        file.id = hash.clone();
                        file.hash = hash;
                        file.aich_hash = record.aich_hash.clone();
                    } else {
                        files_to_hash.push(file.clone());
                    }
                }

                let current_shared_folders = {
                    let state = startup_app.state::<AppState>();
                    let cfg = state.config.read().await;
                    cfg.settings.shared_folders.clone()
                };
                all_discovered.retain(|file| {
                    commands::sharing::file_in_shared_folders(&file.path, &current_shared_folders)
                });

                {
                    let mut index = index_clone.write().await;
                    index.add_files(all_discovered.clone());
                }
                commands::sharing::refresh_file_cache(&index_clone, &csf).await;

                let _ = startup_app.emit("shared-files-changed", serde_json::json!({
                    "phase": "discovered",
                    "count": all_discovered.len(),
                }));

                let total_to_hash = files_to_hash.len();
                let mut hashed = 0usize;
                let mut last_cache_refresh = std::time::Instant::now();
                let mut was_cancelled = false;

                for file in &files_to_hash {
                    if cancel_flag.load(std::sync::atomic::Ordering::Relaxed) {
                        info!("Startup hashing cancelled at {hashed}/{total_to_hash}");
                        was_cancelled = true;
                        break;
                    }

                    let file_path = file.path.clone();
                    let file_temp_id = file.id.clone();
                    let cf = cancel_flag.clone();

                    tracing::debug!("Startup hashing {}/{}: {}", hashed + 1, total_to_hash, file.name);

                    let _ = startup_app.emit("file-hash-progress", serde_json::json!({
                        "current": hashed + 1,
                        "total": total_to_hash,
                        "file_name": file.name,
                    }));

                    let hash_result = tokio::time::timeout(
                        std::time::Duration::from_secs(300),
                        tokio::task::spawn_blocking(move || {
                            FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
                        }),
                    ).await;

                    match hash_result {
                        Ok(Ok(Ok((ed2k_hash, aich_hash)))) => {
                            tracing::debug!("Startup hash complete: {} -> {}", file.name, &ed2k_hash[..ed2k_hash.len().min(8)]);
                            let mut updated = file.clone();
                            updated.id = ed2k_hash.clone();
                            updated.hash = ed2k_hash;
                            updated.aich_hash = aich_hash;
                            let still_shared = {
                                let state = startup_app.state::<AppState>();
                                let cfg = state.config.read().await;
                                commands::sharing::file_in_shared_folders(&updated.path, &cfg.settings.shared_folders)
                            };
                            {
                                let mut idx = index_clone.write().await;
                                idx.remove_file_by_id(&file_temp_id);
                                if !cancel_flag.load(std::sync::atomic::Ordering::Relaxed) && still_shared {
                                    idx.add_file_no_rebuild(updated.clone());
                                }
                            }
                            if !cancel_flag.load(std::sync::atomic::Ordering::Relaxed) && still_shared {
                                hashed += 1;
                            }
                            if !cancel_flag.load(std::sync::atomic::Ordering::Relaxed)
                                && still_shared
                                && last_cache_refresh.elapsed() >= std::time::Duration::from_secs(5)
                            {
                                commands::sharing::refresh_file_cache(&index_clone, &csf).await;
                                last_cache_refresh = std::time::Instant::now();
                            }
                        }
                        Ok(Ok(Err(e))) => {
                            if e.to_string().contains("cancelled") {
                                info!("Startup hashing cancelled mid-file");
                                was_cancelled = true;
                                let mut idx = index_clone.write().await;
                                idx.remove_file_by_id(&file_temp_id);
                                break;
                            }
                            tracing::warn!("Startup hash failed for {}: {e}", file.name);
                            let mut idx = index_clone.write().await;
                            idx.remove_file_by_id(&file_temp_id);
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Startup hash task panicked for {}: {e}", file.name);
                            let mut idx = index_clone.write().await;
                            idx.remove_file_by_id(&file_temp_id);
                        }
                        Err(_) => {
                            tracing::warn!("Startup hash timed out for {} (file may be on cloud storage or locked), skipping", file.name);
                            let mut idx = index_clone.write().await;
                            idx.remove_file_by_id(&file_temp_id);
                        }
                    }
                }

                {
                    let mut idx = index_clone.write().await;
                    if was_cancelled {
                        idx.remove_pending_files();
                    }
                    idx.rebuild();
                }

                commands::sharing::refresh_file_cache(&index_clone, &csf).await;

                if !was_cancelled {
                    let all_hashed: Vec<_> = index_clone.read().await.all_files().iter()
                        .filter(|f| !f.hash.is_empty())
                        .cloned()
                        .collect();
                    if !all_hashed.is_empty() {
                        if let Err(e) = net_tx.send(network::NetworkCommand::AnnounceFiles { files: all_hashed }).await {
                            tracing::warn!("Failed to send initial file announcement: {e}");
                        }
                    }
                }

                drop(_scan_guard);
                startup_cancel_flags.write().await.remove("__startup__");
                let _ = net_tx.try_send(network::NetworkCommand::SharedFilesChanged);
                let _ = startup_app.emit("file-hash-progress", serde_json::json!({
                    "current": total_to_hash,
                    "total": total_to_hash,
                    "file_name": "",
                    "done": true,
                }));
                let from_known = all_discovered.len().saturating_sub(total_to_hash);
                info!(
                    "Indexed {} files from {} shared folders ({} from known.met, {} hashed)",
                    index_clone.read().await.file_count(),
                    shared_folders.len(),
                    from_known,
                    hashed,
                );
            });

            let net_handle = app_handle.clone();
            let net_index = local_index.clone();
            let net_db = db.clone();
            let net_transfers = transfer_manager.clone();
            let net_bw = bandwidth_limiter.clone();
            let bw_limiter = bandwidth_limiter.clone();
            let bw_shutdown_spawn = bw_shutdown.clone();
            let bw_rtt = uss_rtt_queue.clone();
            let bw_uss_flag = uss_enabled_flag.clone();
            let net_spam = spam_filter.clone();
            let net_handle_err = app_handle.clone();
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
                    upload_shared_folders,
                    friend_hashes,
                    uss_rtt_queue,
                    uss_enabled_flag,
                    net_spam,
                )
                .await
                {
                    tracing::error!("Network error: {e}");
                    // The full error chain can contain IPs, peer IDs, paths,
                    // and low-level socket diagnostics we don't want to leak
                    // to the UI (it's shown verbatim). Log the rich version
                    // for diagnostics and send a redacted, user-facing summary.
                    let redacted = crate::security::redact_fatal_error(&e);
                    let _ = net_handle_err.emit("network-fatal-error", redacted);
                }
                shutdown_complete_net.store(true, std::sync::atomic::Ordering::Release);
            });
            tauri::async_runtime::spawn(async move {
                bandwidth::limiter::start_token_refill(bw_limiter, bw_shutdown_spawn, bw_rtt, bw_uss_flag).await;
            });

            info!("Ember P2P application started");
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
            commands::search::mark_spam,
            commands::search::mark_not_spam,
            commands::search::get_spam_stats,
            commands::search::explain_spam_result,
            commands::search::reset_spam_filter,
            commands::search::get_download_history,
            commands::search::clear_download_history,
            commands::search::remove_download_history_entry,
            commands::transfers::start_download,
            commands::transfers::pause_transfers_batch,
            commands::transfers::resume_transfers_batch,
            commands::transfers::stop_transfers_batch,
            commands::transfers::cancel_transfers_batch,
            commands::transfers::pause_transfer,
            commands::transfers::resume_transfer,
            commands::transfers::cancel_transfer,
            commands::transfers::remove_transfer,
            commands::transfers::get_transfers,
            commands::transfers::get_upload_queue,
            commands::transfers::get_known_clients,
            commands::transfers::clear_completed,
            commands::transfers::get_transfer_sources,
            commands::transfers::set_transfer_priority,
            commands::transfers::set_transfer_category,
            commands::transfers::set_preview_priority,
            commands::transfers::pause_all_transfers,
            commands::transfers::resume_all_transfers,
            commands::transfers::stop_transfer,
            commands::transfers::open_file,
            commands::transfers::open_transfer_file_location,
            commands::transfers::recover_archive,
            commands::sharing::add_shared_folder,
            commands::sharing::remove_shared_folder,
            commands::sharing::get_shared_files,
            commands::sharing::get_shared_folders,
            commands::sharing::set_file_priority,
            commands::sharing::batch_set_priority,
            commands::sharing::batch_share,
            commands::sharing::batch_unshare,
            commands::sharing::reload_shared_files,
            commands::sharing::unshare_file,
            commands::sharing::share_file,
            commands::sharing::unshare_folder,
            commands::sharing::get_scan_status,
            commands::sharing::stop_hashing,
            commands::sharing::resume_hashing,
            commands::sharing::open_shared_file,
            commands::sharing::open_shared_folder,
            commands::sharing::delete_shared_file,
            commands::sharing::republish_file,
            commands::sharing::scan_missing_files,
            commands::sharing::remove_missing_files,
            commands::peers::get_peers,
            commands::peers::get_network_stats,
            commands::peers::ban_peer,
            commands::peers::unban_peer,
            commands::peers::add_friend,
            commands::peers::remove_friend,
            commands::peers::get_friends,
            commands::peers::update_friend_nickname,
            commands::peers::get_my_ember_hash,
            commands::peers::send_chat_message,
            commands::peers::get_chat_messages,
            commands::peers::mark_messages_read,
            commands::peers::get_unread_message_counts,
            commands::peers::get_friend_requests,
            commands::peers::accept_friend_request,
            commands::peers::reject_friend_request,
            commands::peers::browse_friend,
            commands::peers::ensure_friend_session,
            commands::peers::retry_friend_search,
            commands::peers::is_friend_discoverable,
            commands::peers::kad_connect,
            commands::peers::kad_disconnect,
            commands::peers::kad_bootstrap_ip,
            commands::peers::kad_bootstrap_url,
            commands::peers::kad_bootstrap_clients,
            commands::peers::kad_recheck_firewall,
            commands::peers::get_kad_contacts,
            commands::peers::get_kad_searches,
            commands::peers::kad_cancel_search,
            commands::peers::get_peer_reputation,
            commands::peers::get_reputation_stats,
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
            commands::security::get_antileech_patterns,
            commands::security::set_antileech_patterns,
            commands::security::set_antileech_enabled,
            commands::security::reset_antileech_to_defaults,
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
            commands::speed_test::run_speed_test,
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            tracing::error!("Fatal: failed to build Tauri application: {e}");
            std::process::exit(1);
        })
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                network::ed2k::preview::cleanup_previews();
                if let Some(state) = app_handle.try_state::<AppState>() {
                    state.bw_shutdown.store(true, std::sync::atomic::Ordering::Release);
                    let tx = state.network_tx.clone();
                    match tx.blocking_send(network::NetworkCommand::Shutdown) {
                        Ok(()) => info!("Sent shutdown command to network, waiting for save..."),
                        Err(e) => tracing::warn!("Failed to send shutdown command: {e}"),
                    }

                    let flag = state.shutdown_complete.clone();
                    let start = std::time::Instant::now();
                    while !flag.load(std::sync::atomic::Ordering::Acquire) {
                        if start.elapsed() > std::time::Duration::from_secs(12) {
                            tracing::warn!("Network shutdown timed out after 12s");
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                    info!("Network shutdown complete");

                    // Wait for in-flight discovery/hash workers to finish or
                    // abort after a short grace window. Prevents scans from
                    // mutating state (known.met, local_index) while we're
                    // flushing it to disk below.
                    {
                        let scanning = state.scanning_count.clone();
                        let bg = state.background_scans.clone();
                        let rt = tauri::async_runtime::handle();
                        rt.block_on(async move {
                            let deadline = std::time::Instant::now()
                                + std::time::Duration::from_secs(5);
                            while scanning.load(std::sync::atomic::Ordering::Relaxed) > 0
                                && std::time::Instant::now() < deadline
                            {
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            }
                            let handles: Vec<_> = {
                                let mut map = bg.write().await;
                                map.drain().map(|(_, h)| h).collect()
                            };
                            for h in handles {
                                h.abort();
                            }
                        });
                    }

                    if let Ok(mut filter) = state.spam_filter.try_write() {
                        filter.save();
                    }
                }
            }
        });
}
