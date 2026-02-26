mod app_state;
mod bandwidth;
mod commands;
mod network;
mod search;
pub mod security;
mod sharing;
mod storage;
mod types;

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

            app.manage(AppState {
                network_tx,
                db: db.clone(),
                config: Arc::new(RwLock::new(config)),
                local_index: local_index.clone(),
                bandwidth_limiter: bandwidth_limiter.clone(),
                transfer_manager: transfer_manager.clone(),
            });

            let index_clone = local_index.clone();
            let db_clone = db.clone();
            let shared_folders = settings.shared_folders.clone();
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

                for folder in &shared_folders {
                    let folder = folder.clone();
                    let files = tokio::task::spawn_blocking(move || {
                        FileIndexer::scan_directory(&folder)
                    })
                    .await
                    .unwrap_or_default();

                    let mut index = index_clone.write().await;
                    index.add_files(files.clone());

                    for file in &files {
                        let _ = db_clone.save_shared_file(file);
                    }
                }
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
                )
                .await
                {
                    tracing::error!("Network error: {e}");
                }
            });

            let bw_limiter = bandwidth_limiter.clone();
            let bw_shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            tauri::async_runtime::spawn(async move {
                bandwidth::limiter::start_token_refill(bw_limiter, bw_shutdown).await;
            });

            info!("Nexus P2P application started");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::search::search_files,
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
            commands::transfers::get_transfers,
            commands::transfers::clear_completed,
            commands::sharing::add_shared_folder,
            commands::sharing::remove_shared_folder,
            commands::sharing::get_shared_files,
            commands::sharing::get_shared_folders,
            commands::peers::get_peers,
            commands::peers::get_network_stats,
            commands::peers::ban_peer,
            commands::peers::unban_peer,
            commands::settings::get_settings,
            commands::settings::update_settings,
            commands::settings::download_nodes_dat,
            commands::settings::download_ipfilter,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    let tx = state.network_tx.clone();
                    let _ = tx.try_send(network::NetworkCommand::Shutdown);
                    info!("Sent shutdown command to network");
                }
            }
        });
}
