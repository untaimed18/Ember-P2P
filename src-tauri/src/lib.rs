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
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;
use tokio::sync::{mpsc, RwLock};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use app_state::AppState;
use bandwidth::limiter::BandwidthLimiter;
use search::index::LocalIndex;
use sharing::indexer::FileIndexer;
use sharing::manager::TransferManager;
use storage::config::AppConfig;
use storage::database::Database;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Give async tasks a larger worker-thread stack than tokio's 2 MiB default.
    //
    // Ember drives several very large async state machines — the multi-source
    // download loop, the per-peer message loops, and the central network
    // `select!` loop. In debug builds these compile to deep, unboxed poll
    // chains whose combined stack frames sit close to the 2 MiB limit, and
    // small additions have overflowed it (STATUS_STACK_OVERFLOW) right as a
    // download starts. Build our own multi-thread runtime with a roomier stack
    // and hand its handle to Tauri *before* anything spawns (the first spawn
    // happens in `.setup`, and `async_runtime::set` panics if the runtime was
    // already initialized). The runtime is intentionally leaked: Tauri requires
    // the underlying Tokio runtime to outlive the app, and it lives for the
    // whole process regardless.
    let rt = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_stack_size(8 * 1024 * 1024)
            .build()
            .expect("failed to build Tokio runtime"),
    ));
    tauri::async_runtime::set(rt.handle().clone());

    // Install the process-wide rustls CryptoProvider before *anything*
    // can do TLS. Multiple crates in this app speak rustls 0.23
    // (`quinn`, `tokio-tungstenite`, `reqwest`) and 0.23 deliberately
    // refuses to pick a default automatically — any code path that
    // doesn't pass an explicit provider will panic with:
    //   "Could not automatically determine the process-level
    //    CryptoProvider from Rustls crate features."
    // QUIC is fine because `quic.rs::build_{server,client}_config`
    // pass `builder_with_provider(...)` explicitly, but the WS client
    // used by `connect_server_relay` (every LowID-to-LowID relay
    // fallback) goes through `tokio_tungstenite::connect_async`,
    // which uses the global default — no install, every relay
    // attempt panicked the spawned task.
    //
    // Idempotent: returns Err if a provider is already installed
    // (e.g. a future `cargo test` linking us in alongside another
    // initializer). We don't care about that case, hence `let _ =`.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let log_dir = storage::paths::resolve_data_dir();
    let _ = std::fs::create_dir_all(&log_dir);
    security::cleanup_old_logs(&log_dir, 7);
    let file_appender = tracing_appender::rolling::daily(&log_dir, "ember.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(non_blocking),
        )
        .init();

    // Keep the guard alive for the entire app lifetime
    let _log_guard = _guard;

    // Multi-instance harness path: when `EMBER_DATA_DIR` is set, every
    // launched process is meant to be an *isolated* node (own config,
    // identity, database, downloads). The `tauri-plugin-single-instance`
    // plugin enforces uniqueness at the OS level via the Tauri identifier,
    // so without this guard a second harness node would silently focus
    // the first instead of starting up. Production launches (no env var)
    // keep the original "click again to focus the existing window"
    // behavior intact.
    let mut builder = tauri::Builder::default();
    if std::env::var(storage::paths::EMBER_DATA_DIR_ENV)
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // A second launch is how the OS delivers an `ed2k://` link or a
            // `.emulecollection` file while Ember is already running: it spawns
            // a new process with the payload in argv, which this plugin routes
            // here before closing the duplicate. Forward any payload to the
            // existing instance; otherwise just focus the window (the user
            // re-launched the app to bring it to the front).
            let payloads = commands::deeplink::extract_deep_link_payloads(&args);
            if payloads.is_empty() {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.unminimize();
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            } else {
                commands::deeplink::dispatch_deep_links(app, payloads);
            }
        }));
    } else {
        info!(
            "Skipping single-instance plugin: {} is set for harness mode",
            storage::paths::EMBER_DATA_DIR_ENV
        );
    }
    builder
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let app_handle = app.handle().clone();

            // Associate the `ed2k://` scheme with this executable.
            //
            // URI schemes have no Windows "UserChoice" protection: the last
            // writer wins, and a per-user (HKCU) entry overrides a machine-wide
            // one. So calling `register_all()` on every production launch would
            // silently re-claim `ed2k://` from whatever client the user
            // actually prefers (eMule, another ed2k app) — even if they set it
            // back by hand. That's hostile, so we DON'T do it in release.
            //
            // Instead, installed builds get the scheme registered once by the
            // NSIS/MSI installer (driven by `plugins.deep-link.desktop.schemes`
            // in tauri.conf.json), which is an explicit, user-initiated install
            // action and is undone on uninstall. Runtime `register_all()` is
            // only needed for dev builds, which aren't installed and so have no
            // installer to register the scheme — hence the `debug_assertions`
            // gate on Windows. Linux has no standard installer-side mechanism,
            // so it registers at runtime there. macOS reads the association
            // from the bundle's Info.plist and needs neither path.
            #[cfg(any(target_os = "linux", all(debug_assertions, windows)))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                if let Err(e) = app.deep_link().register_all() {
                    tracing::warn!("Failed to register ed2k:// deep link scheme: {e}");
                }
            }

            // Show the running version in the main window title so users
            // can confirm which build they're on at a glance (matches the
            // wix product version we ship and the value reported by the
            // About / Update dialog). `package_info().version` reads the
            // `version` field of `tauri.conf.json` at build time.
            //
            // In harness mode (`EMBER_DATA_DIR` set), we also tag the
            // title with the basename of the data dir so two side-by-side
            // harness instances are visually distinguishable from the
            // taskbar without opening devtools. Production launches
            // (no env var) keep the original title.
            if let Some(window) = app.get_webview_window("main") {
                let version = &app.package_info().version;
                let title = match std::env::var(storage::paths::EMBER_DATA_DIR_ENV) {
                    Ok(dir) if !dir.trim().is_empty() => {
                        let label = std::path::Path::new(dir.trim())
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("harness");
                        format!("Ember v{version} [{label}]")
                    }
                    _ => format!("Ember v{version}"),
                };
                let _ = window.set_title(&title);
            }

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
            // If config.json was corrupt and reset to defaults, surface it to the
            // user once the webview has mounted (the file is preserved as a .bak).
            let corrupt_backup = config.corrupt_backup.clone();

            let spam_data_dir = storage::paths::resolve_data_dir_with_app(&app_handle);
            let spam_filter = Arc::new(RwLock::new(
                search::spam::SpamFilter::load(&spam_data_dir),
            ));

            // Capacity 1024 (was 256): every Tauri command that mutates
            // persistent state (`UpdateSettings`, `BanPeer`, `BootstrapContacts`,
            // `ReloadIpFilter`, `FriendRemoved`, etc.) dispatches a live
            // `NetworkCommand` here via `try_send` after the DB/config write
            // succeeds. The on-disk write is the source of truth, so a
            // dropped live update only delays application until the next
            // restart, but security-relevant changes (ipfilter reload, peer
            // ban) shouldn't degrade silently under burst. 1024 covers the
            // realistic worst case (a user clicking through many rows in
            // rapid succession) with a comfortable margin while the network
            // task drains continuously.
            let (network_tx, network_rx) = mpsc::channel(1024);

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
                let data_dir = storage::paths::resolve_data_dir_with_app(&app_handle);
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
                quit_confirmed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                close_behavior: Arc::new(parking_lot::RwLock::new(
                    settings.close_to_tray_behavior.clone(),
                )),
                pending_deep_links: Arc::new(parking_lot::Mutex::new(Vec::new())),
            });

            // Non-silent recovery notice: if config.json was corrupt at load,
            // tell the user (their settings were reset to defaults; the original
            // is preserved). Delay the emit so the webview has registered its
            // listeners — the file is already safely backed up regardless.
            if let Some(bak) = corrupt_backup {
                let emit_handle = app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let _ = emit_handle.emit(
                        "config-corrupt-recovered",
                        serde_json::json!({ "backup_path": bak.to_string_lossy().to_string() }),
                    );
                });
            }

            // Cold-start deep link: an `ed2k://` link or `.emulecollection`
            // file that launched Ember arrives in our own process args. Buffer
            // it now (AppState is managed above) — the frontend drains the
            // buffer once it mounts the deep-link handler. Done after
            // `app.manage` so `dispatch_deep_links` can reach the buffer.
            {
                let args: Vec<String> = std::env::args().collect();
                let payloads = commands::deeplink::extract_deep_link_payloads(&args);
                if !payloads.is_empty() {
                    commands::deeplink::dispatch_deep_links(&app_handle, payloads);
                }
            }

            // System tray icon. Rendered unconditionally so users who pick
            // "Minimize to Tray" (or the saved `tray` behavior) always have
            // a way back into the running app — without this, hiding the
            // window would orphan the process. The menu also exposes an
            // explicit Quit entry that routes through `app.exit(0)` so the
            // existing `RunEvent::Exit` shutdown sequence still runs.
            let show_item = MenuItem::with_id(
                app,
                "tray_show",
                "Show Ember",
                true,
                None::<&str>,
            )?;
            let quit_item = MenuItem::with_id(
                app,
                "tray_quit",
                "Quit Ember",
                true,
                None::<&str>,
            )?;
            let tray_menu = Menu::with_items(app, &[&show_item, &quit_item])?;

            let tray_icon = app
                .default_window_icon()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing default window icon for tray"))?;

            let _tray = TrayIconBuilder::with_id("main")
                .icon(tray_icon)
                .tooltip("Ember")
                .menu(&tray_menu)
                // Default to "the menu shows on left-click" so users who
                // can't right-click (touchscreens, accessibility tools)
                // can still get to Show/Quit. Linux ignores this flag.
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "tray_show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.unminimize();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "tray_quit" => {
                        if let Some(state) = app.try_state::<AppState>() {
                            state
                                .quit_confirmed
                                .store(true, std::sync::atomic::Ordering::Release);
                        }
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // Single left-click reveals the window. The double-click
                    // event is platform-conditional (macOS doesn't fire it),
                    // so we settle for the click-up flavor of the single
                    // click which is universal.
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.unminimize();
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

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
                    let data_dir = storage::paths::resolve_data_dir_with_app(&startup_app);
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

                let folder_priorities = {
                    let state = startup_app.state::<AppState>();
                    let cfg = state.config.read().await;
                    cfg.settings.folder_priorities.clone()
                };
                {
                    let mut index = index_clone.write().await;
                    index.add_files(all_discovered.clone());
                    // Apply each shared folder's default upload priority so
                    // newly discovered files (and files added while the app
                    // was closed) inherit eMule-style per-directory priority.
                    for (folder, priority) in &folder_priorities {
                        index.set_priority_under_folder(folder, priority);
                    }
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
            commands::search::build_ed2k_link,
            commands::search::parse_ed2k_link,
            commands::search::mark_spam,
            commands::search::mark_not_spam,
            commands::search::get_spam_stats,
            commands::search::explain_spam_result,
            commands::search::reset_spam_filter,
            commands::search::get_download_history,
            commands::search::get_download_history_stats,
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
            commands::sharing::get_shared_file_count,
            commands::sharing::get_shared_folders,
            commands::sharing::get_file_media_metadata,
            commands::sharing::get_folder_priorities,
            commands::sharing::set_folder_priority,
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
            commands::peers::retry_friend_search,
            commands::peers::is_friend_discoverable,
            commands::peers::get_online_friends,
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
            commands::peers::get_ember_diagnostics,
            commands::peers::ember_ping_peer,
            commands::peers::get_ember_dht_contacts,
            commands::peers::add_ember_dht_contact,
            commands::peers::ember_dht_ping_peer,
            commands::peers::ember_dht_find_node,
            commands::peers::ember_dht_iterative_find_node,
            commands::peers::ember_dht_publish_keyword,
            commands::peers::ember_dht_find_value,
            commands::peers::ember_dht_run_maintenance,
            commands::settings::get_settings,
            commands::settings::update_settings,
            commands::settings::download_nodes_dat,
            commands::settings::download_ipfilter,
            commands::settings::hide_to_tray,
            commands::settings::show_main_window,
            commands::settings::quit_app,
            commands::settings::set_close_behavior,
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
            commands::deeplink::take_pending_deep_links,
            commands::deeplink::open_collection_file,
        ])
        .on_window_event(|window, event| {
            // Title-bar X handler. Decides whether to fully exit, hide to
            // the system tray, or hand off to the frontend dialog based on
            // the user's saved `close_to_tray_behavior`. Only the main
            // window participates — auxiliary windows (none today, but
            // future about/preview popups) keep their normal close path.
            if window.label() != "main" {
                return;
            }
            let tauri::WindowEvent::CloseRequested { api, .. } = event else { return };

            let app_handle = window.app_handle();
            let Some(state) = app_handle.try_state::<AppState>() else {
                return;
            };

            // User already explicitly chose Quit (dialog button or tray
            // menu) — `quit_app` set the flag and called `app.exit(0)`.
            // Let the destroy proceed; `RunEvent::Exit` runs the shutdown.
            if state
                .quit_confirmed
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }

            // Read the saved close behavior. We mirror the canonical value
            // into `state.close_behavior` (a synchronous `parking_lot`
            // RwLock) precisely so this UI-thread handler doesn't have to
            // block on the async tokio lock that wraps `AppConfig`.
            let behavior = {
                let guard = state.close_behavior.read();
                match guard.as_str() {
                    "exit" => "exit",
                    "tray" => "tray",
                    _ => "ask",
                }
            };

            match behavior {
                "exit" => {
                    // Default close path. Don't call `prevent_close`; let
                    // Tauri tear the window down and fire `RunEvent::Exit`.
                }
                "tray" => {
                    api.prevent_close();
                    if let Err(e) = window.hide() {
                        tracing::warn!("Failed to hide window for close-to-tray: {e}");
                    }
                }
                _ => {
                    // "ask" — bounce to the frontend so it can render the
                    // themed three-button confirmation dialog (Cancel /
                    // Minimize to Tray / Exit Ember). The frontend then
                    // re-issues either `hide_to_tray` or `quit_app` to
                    // continue down one of the other branches above.
                    api.prevent_close();
                    if let Err(e) = app_handle.emit("close-requested", ()) {
                        tracing::warn!(
                            "Failed to emit close-requested event; falling back to exit: {e}"
                        );
                        // The webview never got the message, so the user
                        // would be stuck with an unresponsive close button.
                        // Mark the close as confirmed and exit so they
                        // aren't trapped.
                        state
                            .quit_confirmed
                            .store(true, std::sync::atomic::Ordering::Release);
                        app_handle.exit(0);
                    }
                }
            }
        })
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

                    // Signal every in-flight hash worker to stop ASAP. The
                    // startup indexer (and `reload_shared_files`) check
                    // these flags between files and mid-file via
                    // `FileIndexer::hash_file_cancellable`, so flipping
                    // them cuts the worst-case shutdown wait from the
                    // full 5-second `scanning_count` grace window down
                    // to ~100ms (one MD4 chunk). Without this the
                    // window disappears immediately after the user
                    // clicks Exit but the process keeps running until
                    // the deadline elapses, which surfaces visually
                    // as "stuck on the Chromium UnregisterClass error".
                    {
                        let cancel_flags = state.hash_cancel_flags.clone();
                        let rt = tauri::async_runtime::handle();
                        rt.block_on(async move {
                            let flags = cancel_flags.read().await;
                            for flag in flags.values() {
                                flag.store(true, std::sync::atomic::Ordering::Relaxed);
                            }
                        });
                    }

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

                    // Flush any learned spam signals not yet persisted by the
                    // periodic flush (e.g. an auto-not-spam that landed since
                    // the last tick). Wait briefly for the lock rather than the
                    // old non-blocking `try_write`, which silently skipped the
                    // save under contention. The network task has already shut
                    // down here, so the lock is normally free; the timeout is a
                    // safety net so shutdown can't hang.
                    {
                        let rt = tauri::async_runtime::handle();
                        let spam = state.spam_filter.clone();
                        rt.block_on(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(2),
                                spam.write(),
                            )
                            .await
                            {
                                Ok(mut filter) => filter.save(),
                                Err(_) => tracing::warn!(
                                    "Spam filter save skipped on shutdown: lock busy"
                                ),
                            }
                        });
                    }
                }
            }
        });
}
