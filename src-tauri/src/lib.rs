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

#[cfg(target_os = "windows")]
fn repair_legacy_data_acls(data_dir: &std::path::Path) {
    const REPAIR_MARKER: &str = ".acl-repair-v2";
    let marker = data_dir.join(REPAIR_MARKER);
    if marker.exists() {
        return;
    }

    let mut complete = true;
    if let Err(error) = security::restrict_file_permissions_checked(data_dir) {
        eprintln!(
            "Failed to repair Ember data directory ACL at {}: {error}",
            data_dir.display()
        );
        complete = false;
    }

    match std::fs::read_dir(data_dir) {
        Ok(entries) => {
            let mut count = 0usize;
            for entry in entries.flatten() {
                if entry.file_name() == REPAIR_MARKER {
                    continue;
                }
                count += 1;
                if count > 4096 {
                    eprintln!("Ember data ACL repair stopped at its safety limit");
                    complete = false;
                    break;
                }
                if let Err(error) = security::restrict_file_permissions_checked(&entry.path()) {
                    eprintln!(
                        "Failed to repair ACL for {}: {error}",
                        entry.path().display()
                    );
                    complete = false;
                }
            }
        }
        Err(error) => {
            eprintln!(
                "Failed to enumerate Ember data for ACL repair at {}: {error}",
                data_dir.display()
            );
            complete = false;
        }
    }

    if complete {
        if let Err(error) = security::atomic_write(&marker, b"2\n", true) {
            eprintln!("Failed to persist Ember ACL repair marker: {error}");
        }
    }
}

async fn reconcile_shared_files(network_tx: &mpsc::Sender<network::NetworkCommand>) -> bool {
    let (tx, rx) = tokio::sync::oneshot::channel();
    if tokio::time::timeout(
        std::time::Duration::from_secs(2),
        network_tx.send(network::NetworkCommand::SharedFilesChangedAck { tx }),
    )
    .await
    .is_err()
    {
        return false;
    }
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(15), rx).await,
        Ok(Ok(Ok(())))
    )
}

/// Ceiling on the whole graceful teardown. Must exceed the network task's
/// bounded teardown budget so we don't return (and let the process exit) while
/// .part.met saves are still in flight: the teardown caps its variable phases
/// at ~5s (await aborted downloads) + ~8s (concurrent tracker saves) plus a few
/// seconds of fixed saves (nodes.dat/known.met/stats). The common case
/// completes in well under a second, so this ceiling only bites if the network
/// is genuinely stuck.
pub(crate) const SHUTDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(45);

/// The one authoritative teardown sequence: stop background work, ask the
/// network task to flush the state it owns (.part.met gap maps, nodes.dat, the
/// known.met checkpoint, sources.met, server.met, reputation, transfer stats)
/// and deregister from ed2k servers / the rendezvous, then flush what it
/// doesn't own.
///
/// `RunEvent::Exit` is not the only way this process dies. Installing an update
/// ends in `std::process::exit(0)` inside `tauri-plugin-updater`, whose
/// `on_before_exit` hook only clears tray icons/resources and hides windows —
/// `RunEvent::Exit` never fires. Both paths call this so an update install can
/// never silently skip the flush and cost the user a full AICH rehash plus the
/// gap maps of every in-progress download.
///
/// Safe to run more than once: once the network task has exited, the shutdown
/// send fails closed instead of waiting, and every remaining step is an
/// idempotent re-save.
pub(crate) async fn run_graceful_shutdown(
    app: &tauri::AppHandle,
    shutdown_wait: std::time::Duration,
) {
    network::ed2k::preview::cleanup_previews();
    let Some(state) = app.try_state::<AppState>() else {
        return;
    };
    state
        .bw_shutdown
        .store(true, std::sync::atomic::Ordering::Release);

    // Signal every in-flight hash worker to stop ASAP. The startup indexer
    // (and `reload_shared_files`) check these flags between files and mid-file
    // via `FileIndexer::hash_file_cancellable`, so flipping them cuts the
    // worst-case shutdown wait from the full 5-second `scanning_count` grace
    // window down to ~100ms (one MD4 chunk). Without this the window
    // disappears immediately after the user clicks Exit but the process keeps
    // running until the deadline elapses, which surfaces visually as "stuck on
    // the Chromium UnregisterClass error".
    {
        let flags = state.hash_cancel_flags.read().await;
        for flag in flags.values() {
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    // Cancelling a hasher only asks it to stop; the task still has to unwind,
    // and dropping its `JoinHandle` detaches it rather than aborting it. Join
    // the registered scans here so none of them can still hold
    // `local_index.write()` (or be part-way through a `known_files` update)
    // while the network task performs the authoritative shutdown flush below —
    // that race is what leaves a half-written `known.met`. Bounded, and
    // `await_background_scans` warns and aborts whatever is left when the
    // window elapses, so a wedged scan cannot hold the process open: with the
    // cancel flags already set a cooperative scan stops within ~100ms.
    const SCAN_JOIN_GRACE: std::time::Duration = std::time::Duration::from_secs(3);
    state.await_background_scans(SCAN_JOIN_GRACE).await;

    let tx = state.network_tx.clone();
    const SHUTDOWN_SEND_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();
    let shutdown_deadline = start + shutdown_wait;
    let mut command = network::NetworkCommand::Shutdown {
        deadline: tokio::time::Instant::from_std(shutdown_deadline),
    };
    let shutdown_sent = loop {
        match tx.try_send(command) {
            Ok(()) => {
                info!("Sent shutdown command to network, waiting for save...");
                break true;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(returned))
                if start.elapsed() < SHUTDOWN_SEND_WAIT =>
            {
                command = returned;
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(e) => {
                tracing::warn!("Failed to send shutdown command within bounded window: {e}");
                break false;
            }
        }
    };

    let flag = state.shutdown_complete.clone();
    while shutdown_sent && !flag.load(std::sync::atomic::Ordering::Acquire) {
        if start.elapsed() > shutdown_wait {
            tracing::warn!(
                "Network shutdown timed out after {}s",
                shutdown_wait.as_secs()
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    if flag.load(std::sync::atomic::Ordering::Acquire) {
        info!("Network shutdown complete");
    } else if shutdown_sent {
        tracing::error!(
            "Shutdown deadline reached before authoritative network writers completed; result is truncated"
        );
    } else {
        // Distinct from the deadline case: no deadline was ever awaited because
        // the command never reached the network task, so it ran no save
        // sequence at all. Reporting this as a timeout sent anyone reading the
        // log looking for a slow writer instead of a full command channel.
        tracing::error!(
            "Network shutdown was never enqueued (command channel stayed full for {}s); \
             no authoritative network writes ran this teardown",
            SHUTDOWN_SEND_WAIT.as_secs()
        );
    }

    // Wait for in-flight discovery/hash workers to finish or abort after a
    // short grace window. Prevents scans from mutating state (known.met,
    // local_index) while we're flushing it to disk below.
    let scanning = state.scanning_count.clone();
    while scanning.load(std::sync::atomic::Ordering::Relaxed) > 0
        && std::time::Instant::now() < shutdown_deadline
    {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let handles: Vec<_> = {
        let mut map = state.background_scans.write().await;
        map.drain().map(|(_, h)| h).collect()
    };
    for h in handles {
        h.abort();
    }

    // Flush any learned spam signals not yet persisted by the periodic flush
    // (e.g. an auto-not-spam that landed since the last tick). Wait briefly for
    // the lock rather than the old non-blocking `try_write`, which silently
    // skipped the save under contention. The network task has already shut down
    // here, so the lock is normally free; the timeout is a safety net so
    // shutdown can't hang.
    match tokio::time::timeout_at(
        tokio::time::Instant::from_std(shutdown_deadline),
        state.spam_filter.write(),
    )
    .await
    {
        Ok(mut filter) => filter.save(),
        Err(_) => tracing::warn!("Spam filter save skipped on shutdown: lock busy"),
    };
}

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

    let data_dir = storage::paths::resolve_data_dir();
    let _ = std::fs::create_dir_all(&data_dir);
    #[cfg(target_os = "windows")]
    repair_legacy_data_acls(&data_dir);

    let log_dir = data_dir.join("logs");
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let verbose_diagnostics = std::env::var("EMBER_VERBOSE_DIAGNOSTICS")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    // Logs now live in their own directory so a stale/locked file can never
    // block access to the rest of the application data directory.
    security::cleanup_old_logs(&data_dir, 7);

    let file_logging = match std::fs::create_dir_all(&log_dir) {
        Ok(()) => {
            #[cfg(target_os = "windows")]
            if let Err(error) = security::restrict_file_permissions_checked(&log_dir) {
                eprintln!("Failed to restrict Ember log directory ACL: {error}");
            }

            security::cleanup_old_logs(&log_dir, 7);
            if let Ok(entries) = std::fs::read_dir(&log_dir) {
                for entry in entries.flatten() {
                    if entry.file_name().to_string_lossy().starts_with("ember.log") {
                        let _ = security::restrict_file_permissions_checked(&entry.path());
                    }
                }
            }

            tracing_appender::rolling::RollingFileAppender::builder()
                .rotation(tracing_appender::rolling::Rotation::DAILY)
                .filename_prefix("ember.log")
                .build(&log_dir)
                .map(|appender| tracing_appender::non_blocking(appender))
                .map_err(|error| error.to_string())
        }
        Err(error) => Err(error.to_string()),
    };
    let (file_writer, log_guard) = match file_logging {
        Ok((writer, guard)) => (Some(writer), Some(guard)),
        Err(error) => {
            eprintln!(
                "File logging is unavailable at {}: {error}; continuing with console logging",
                log_dir.display()
            );
            (None, None)
        }
    };
    let file_layer = file_writer.map(|writer| {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(security::logging::PrivacyMakeWriter::new(
                writer,
                verbose_diagnostics,
            ))
    });

    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(
            security::logging::PrivacyMakeWriter::new(std::io::stdout, verbose_diagnostics),
        ))
        .with(file_layer)
        .init();

    // Keep the guard alive for the entire app lifetime
    let _log_guard = log_guard;

    // Route panics into the log file. Release builds are linked with
    // `windows_subsystem = "windows"` (no console), so the default hook's
    // stderr message goes nowhere and a startup panic is indistinguishable
    // from "the window opened and instantly closed". Without this, the log
    // simply stops mid-startup with no cause recorded.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown location>".to_string());
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        tracing::error!(
            "PANIC at {location} on thread '{}': {payload}",
            std::thread::current().name().unwrap_or("unnamed"),
        );
        default_panic_hook(info);
    }));

    tracing::info!(
        "Ember starting: version={} os={} arch={}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );

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
    builder = builder.register_asynchronous_uri_scheme_protocol(
        "ember-media",
        |ctx, request, responder| {
            let app = ctx.app_handle().clone();
            let encoded_path = request.uri().path().trim_start_matches('/').to_string();
            let range = request
                .headers()
                .get(tauri::http::header::RANGE)
                .and_then(|header| header.to_str().ok())
                .map(str::to_string);
            tauri::async_runtime::spawn(async move {
                responder.respond(
                    commands::sharing::serve_media_request(app, encoded_path, range).await,
                );
            });
        },
    );
    builder
        .manage(commands::updater::UpdaterService::default())
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

            // Swap in a restore staged by `import_backup` before anything
            // opens the files it replaces. Once the database is open and the
            // identity is cached in memory, replacing them underneath is not
            // something that can be done safely.
            match storage::paths::ensure_data_dir_with_app(&app_handle) {
                Ok(dir) => {
                    if let Err(e) = commands::backup::apply_pending_restore(&dir) {
                        tracing::error!("Failed to apply the staged restore: {e}");
                    }
                }
                Err(e) => tracing::error!("Failed to prepare the data dir: {e}"),
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
            let data_dir = storage::paths::resolve_data_dir_with_app(&app_handle);
            std::fs::create_dir_all(&data_dir)?;
            if !settings.download_folder.is_empty() {
                std::fs::create_dir_all(
                    std::path::PathBuf::from(&settings.download_folder).join("Downloads"),
                )?;
                std::fs::create_dir_all(
                    std::path::PathBuf::from(&settings.download_folder).join("Temp"),
                )?;
            }
            let mut configured_roots = settings.shared_folders.clone();
            if !settings.download_folder.is_empty() {
                configured_roots.push(settings.download_folder.clone());
            }
            let approved_roots = security::filesystem::initialize_approved_roots(
                &data_dir,
                &configured_roots,
            )
            .map_err(|error| anyhow::anyhow!("Failed to load approved filesystem roots: {error}"))?;
            storage::share_intent::initialize(&data_dir)
                .map_err(|error| anyhow::anyhow!("Failed to load durable share intent: {error}"))?;
            // Load the persistent identity once before commands or the network
            // task can run. Re-reading/creating it independently at several
            // call sites allowed concurrent first-run callers to generate
            // different identities and race their atomic writes.
            let identity = Arc::new(
                storage::identity::NodeIdentity::load_or_create(
                    &storage::paths::resolve_data_dir_with_app(&app_handle),
                )
                .map_err(|e| {
                    tracing::error!("Failed to load node identity: {e}");
                    e
                })?,
            );
            // If config.json was corrupt and reset to defaults, surface it to the
            // user once the webview has mounted (the file is preserved as a .bak).
            let corrupt_backup = config.corrupt_backup.clone();
            let ember_default_on_applied = config.ember_default_on_applied;
            let db_corrupt_backup = db.corrupt_backup.clone();
            let mut policy_failures = Vec::new();
            let mut policy_scope = security::policy::PolicyResetScope::default();
            if db_corrupt_backup.is_some() {
                policy_scope.reset_bans = true;
                policy_failures.push(
                    "The policy database was corrupt and was replaced; prior bans cannot be trusted"
                        .to_string(),
                );
            }
            if let Err(error) = db.validate_security_policy() {
                policy_scope.reset_bans = true;
                policy_failures.push(format!("Persisted ban policy could not be validated: {error}"));
            }
            if let Err(error) =
                network::ember::reputation::ReputationManager::load_checked(
                    &data_dir.join("reputation.json"),
                )
            {
                policy_scope.reset_reputation = true;
                policy_failures.push(error);
            }
            let security_policy = Arc::new(if policy_failures.is_empty() {
                security::policy::SecurityPolicyGate::ready(data_dir.clone())
            } else {
                security::policy::SecurityPolicyGate::blocked(
                    data_dir.clone(),
                    policy_failures.join("; "),
                    policy_scope,
                )
            });

            // Honour the "launch maximized" preference. The window is
            // created at its configured size (per `tauri.conf.json`); we
            // maximize it here, once at startup, when the user has opted in.
            // It's intentionally a launch-time preference — toggling it in
            // Settings only changes how the *next* launch opens.
            if settings.launch_maximized {
                if let Some(window) = app.get_webview_window("main") {
                    if let Err(e) = window.maximize() {
                        tracing::warn!("Failed to apply launch-maximized preference: {e}");
                    }
                }
            }

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
            let scan_coordination = Arc::new(tokio::sync::Mutex::new(()));

            let cached_peers: Arc<RwLock<Vec<crate::types::PeerInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_stats: Arc<RwLock<crate::types::NetworkStats>> = Arc::new(RwLock::new(crate::types::NetworkStats::default()));
            let cached_contacts: Arc<RwLock<Vec<crate::types::KadContactInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_searches: Arc<RwLock<Vec<crate::types::KadSearchInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_servers: Arc<RwLock<Vec<crate::types::ServerInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let cached_connected_server: Arc<RwLock<Option<crate::types::ServerInfo>>> = Arc::new(RwLock::new(None));
            let cached_transfer_stats: Arc<RwLock<crate::storage::statistics::TransferStats>> = Arc::new(RwLock::new(Default::default()));
            let cached_shared_files: Arc<RwLock<Vec<crate::types::FileInfo>>> = Arc::new(RwLock::new(Vec::new()));
            let hash_cancel_flags: Arc<RwLock<std::collections::HashMap<String, Arc<std::sync::atomic::AtomicBool>>>> = Arc::new(RwLock::new(std::collections::HashMap::new()));
            let fresh_part_hashes: Arc<RwLock<std::collections::HashMap<[u8; 16], Vec<[u8; 16]>>>> = Arc::new(RwLock::new(std::collections::HashMap::new()));
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
            // Mutual friends are the subset that also added us back. Friend-only
            // shares and browse answers key off this rather than `friend_hashes`,
            // so a one-sided add cannot reach private content.
            let mutual_friend_hashes: app_state::SharedFriendHashes = {
                let mut set = std::collections::HashSet::new();
                if let Ok(rows) = db.get_friends_full() {
                    for row in &rows {
                        if !row.6 {
                            continue;
                        }
                        if let Ok(bytes) = hex::decode(&row.0) {
                            if bytes.len() == 16 {
                                let mut h = [0u8; 16];
                                h.copy_from_slice(&bytes);
                                set.insert(h);
                            }
                        }
                    }
                    if !set.is_empty() {
                        info!("Loaded {} mutual friends from database", set.len());
                    }
                }
                Arc::new(RwLock::new(set))
            };

            let shared_folder_watcher = sharing::watcher::SharedFoldersWatcher::start(
                app_handle.clone(),
                settings.shared_folders.clone(),
            );

            // One-time AICH migration: invalidate multi-part AICH root hashes
            // computed before the SHAHashSet part-boundary fix so they get
            // recomputed on this startup's hashing pass. Must run before ANY
            // known.met consumer loads the file so the indexer/hashing task and
            // network task both see the cleared roots. Guarded by a marker file.
            {
                let data_dir = storage::paths::resolve_data_dir_with_app(&app_handle);
                storage::known_files::migrate_aich_v2(&data_dir);
            }

            // Allow WebView media playback for files under shared/download dirs.
            commands::sharing::sync_asset_protocol_scope(&app_handle, &config);

            let pending_deep_links =
                commands::deeplink::load_pending_queue(&app_handle);
            app.manage(AppState {
                network_tx,
                db: db.clone(),
                approved_roots: approved_roots.clone(),
                pending_folder_drop: Arc::new(tokio::sync::Mutex::new(None)),
                security_policy: security_policy.clone(),
                identity: identity.clone(),
                config: Arc::new(RwLock::new(config)),
                settings_save_lock: Arc::new(tokio::sync::Mutex::new(())),
                restore_import_lock: Arc::new(tokio::sync::Mutex::new(())),
                local_index: local_index.clone(),
                bandwidth_limiter: bandwidth_limiter.clone(),
                transfer_manager: transfer_manager.clone(),
                download_admission: Arc::new(tokio::sync::Mutex::new(())),
                shutdown_complete,
                bw_shutdown: bw_shutdown.clone(),
                scanning_count: scanning_count.clone(),
                library_scan_truncated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                scan_coordination: scan_coordination.clone(),
                hashing_paused: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                hashing_fs_dirty: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                cached_transfer_stats,
                cached_shared_files: cached_shared_files.clone(),
                hash_cancel_flags: hash_cancel_flags.clone(),
                fresh_part_hashes: fresh_part_hashes.clone(),
                spam_filter: spam_filter.clone(),
                upload_shared_folders: upload_shared_folders.clone(),
                friend_hashes: friend_hashes.clone(),
                mutual_friend_hashes: mutual_friend_hashes.clone(),
                shared_folder_watcher,
                background_scans: Arc::new(RwLock::new(std::collections::HashMap::new())),
                background_scan_seq: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                quit_confirmed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                pending_close_request: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                pending_ember_default_on_notice: Arc::new(std::sync::atomic::AtomicBool::new(
                    ember_default_on_applied,
                )),
                close_behavior: Arc::new(parking_lot::RwLock::new(
                    settings.close_to_tray_behavior.clone(),
                )),
                pending_deep_links: Arc::new(parking_lot::Mutex::new(pending_deep_links)),
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
            if let Some(bak) = db_corrupt_backup {
                let emit_handle = app_handle.clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let _ = emit_handle.emit(
                        "db-corrupt-recovered",
                        serde_json::json!({ "backup_path": bak.to_string_lossy().to_string() }),
                    );
                });
            }
            // No delayed emit for this one: it is latched in `AppState` above
            // and the layout drains it once its listeners are up. The recovery
            // notices beside it still race a slow cold start — an event fired
            // three seconds in is simply dropped if the webview has not
            // resolved `listen()` yet — but they can be re-derived from the
            // `.bak` files on disk, whereas this migration is one-shot and
            // already persisted, so a lost notice is lost for good.
            if !security_policy.is_loaded() {
                let emit_handle = app_handle.clone();
                let status = security_policy.status();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    let _ = emit_handle.emit("security-policy-reset-required", status);
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
            let startup_scan_coordination = scan_coordination.clone();
            let csf = cached_shared_files.clone();
            let startup_app = app_handle.clone();
            let net_tx = startup_network_tx;
            let startup_cancel_flags = hash_cancel_flags.clone();
            let startup_fresh_part_hashes = fresh_part_hashes.clone();
            let startup_scan_handle = tauri::async_runtime::handle().inner().spawn(async move {
                if shared_folders.is_empty() {
                    info!("Indexed 0 files from 0 shared folders");
                    return;
                }
                // Held for the whole scan and released when this task ends. It is
                // deliberately not handed to the hash-timeout drain: that drain
                // can block indefinitely on a stuck read, and passing the lease
                // to it would wedge every later reload.
                let _coordination_guard = startup_scan_coordination.clone().lock_owned().await;

                struct StartupScanGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
                impl Drop for StartupScanGuard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                startup_scanning.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let scan_guard = StartupScanGuard(startup_scanning.clone());
                let cancel_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                startup_cancel_flags.write().await.insert("__startup__".to_string(), cancel_flag.clone());

                let discovery_handles: Vec<_> = shared_folders
                    .iter()
                    .map(|folder| {
                        let f = folder.clone();
                        // A persisted cursor describes a partial live scan.
                        // Startup begins with an empty index, so resuming at a
                        // later page would make every earlier page disappear
                        // until another full cycle completes. Start each cold
                        // scan at the first page; successful startup persists
                        // a fresh cursor for the next live reload.
                        let cursor: Option<String> = None;
                        (
                            folder.clone(),
                            tokio::task::spawn_blocking(move || {
                                FileIndexer::discover_directory_page(&f, cursor.as_deref())
                            }),
                        )
                    })
                    .collect();
                let mut all_discovered: Vec<crate::types::FileInfo> = Vec::new();
                let mut startup_cursor_updates = std::collections::HashMap::new();
                for (folder, handle) in discovery_handles {
                    match handle.await {
                        Ok(result) => {
                            if result.truncated {
                                tracing::warn!(
                                    "Startup discovery reached the per-folder file cap; some files will wait for a later scan"
                                );
                                startup_app
                                    .state::<AppState>()
                                    .library_scan_truncated
                                    .store(true, std::sync::atomic::Ordering::Relaxed);
                                let _ = startup_app.emit(
                                    "shared-files-scan-truncated",
                                    serde_json::json!({ "folder": "startup", "limit": 100_000 }),
                                );
                            }
                            startup_cursor_updates.insert(folder, result.next_cursor);
                            all_discovered.extend(result.files);
                        }
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
                // Paths with no known.met record at all — genuinely new to
                // this library, as opposed to a previously-shared file that's
                // merely being rediscovered. Only these should inherit a
                // shared folder's *current* default priority below; a file
                // that already has a persisted priority keeps it even if the
                // folder default has since changed, matching `set_file_priority`'s
                // per-file-override contract.
                let mut new_paths: std::collections::HashSet<String> = std::collections::HashSet::new();
                for file in &mut all_discovered {
                    if let Some(record) = known_list.find_by_path_and_meta(&file.path, file.size, file.modified_at) {
                        let hash = hex::encode(record.file_hash);
                        file.id = hash.clone();
                        file.hash = hash;
                        file.aich_hash = record.aich_hash.clone();
                        file.ember_file_hash = record.ember_file_hash.clone();
                        // Restore the per-file priority and shared/unshared
                        // choice from known.met. Without this, every cold
                        // start silently reset custom priorities to "normal"
                        // and re-shared files the user had explicitly
                        // unshared.
                        file.priority = storage::known_files::priority_u8_to_str(record.upload_priority).to_string();
                        file.shared = storage::share_intent::effective_shared(
                            &record.file_hash,
                            record.is_shared,
                        );
                        // Same reasoning for the friends-only scope: losing it
                        // on a cold start would republish a file the user had
                        // deliberately kept off the open network.
                        file.friends_only = record.friends_only;
                        file.alltime_requests = record.all_time_requested;
                        file.alltime_accepted = record.all_time_accepted;
                        file.alltime_transferred = record.all_time_transferred;
                        // Restore the last-known Peers count so the Library
                        // doesn't show 0 until the next 60s source-count sync.
                        file.complete_sources = record.complete_sources;
                        // A matched record short-circuits hashing unless we
                        // still need a one-time repair pass:
                        // - empty AICH on multi-part (v2 migration / missing root)
                        // - empty ember_file_hash (slice 18 migration: pre-upgrade
                        //   shares must get streaming BLAKE3 for DHT publish +
                        //   download verify)
                        // ed2k comes out identical; only the missing digests
                        // are filled. Single-part empty AICH is left as-is
                        // (roots never straddled a part boundary).
                        let needs_aich = file.aich_hash.is_empty()
                            && file.size > crate::network::ed2k::hash::PARTSIZE;
                        let needs_ember = file.ember_file_hash.is_empty();
                        if needs_aich || needs_ember {
                            // Path-unique id while this copy is queued for
                            // re-hashing. `file.id` is the content hash,
                            // which every duplicate of the same content
                            // shares, and `finalize_pending_hash` /
                            // `remove_file_by_id` both take the first match —
                            // so a hash failure on one copy dropped a
                            // different, healthy copy from the Library.
                            //
                            // `rehash:`, not `pending:`: the row is already
                            // hashed and servable and only wants an optional
                            // digest, so a cancelled pass must not discard it.
                            // See [`crate::search::index::REHASH_ID_PREFIX`].
                            file.id = crate::search::index::rehash_id(&file.path);
                            files_to_hash.push(file.clone());
                        }
                    } else {
                        new_paths.insert(crate::search::index::normalize_path_key(&file.path));
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
                // A cursor page is intentionally partial. On a cold start the
                // index is empty, so retain previously completed pages from
                // known.met while the first page is rediscovered; otherwise a
                // large share (>100k files) loses every non-first-page row
                // until the user manually triggers enough reloads to cycle it
                // back in.
                if startup_cursor_updates.values().any(Option::is_some) {
                    let mut known_paths = all_discovered
                        .iter()
                        .map(|file| crate::search::index::normalize_path_key(&file.path))
                        .collect::<std::collections::HashSet<_>>();
                    let hydration_records = known_list.all_records().cloned().collect::<Vec<_>>();
                    let hydration_folders = current_shared_folders.clone();
                    let hydration_paths = known_paths.clone();
                    let hydrated_records = tokio::task::spawn_blocking(move || {
                        hydration_records
                            .into_iter()
                            .filter(|record| {
                                if record.file_path.is_empty()
                                    || hydration_paths.contains(
                                        &crate::search::index::normalize_path_key(
                                            &record.file_path,
                                        ),
                                    )
                                    || !commands::sharing::file_in_shared_folders(
                                        &record.file_path,
                                        &hydration_folders,
                                    )
                                {
                                    return false;
                                }
                                // Re-apply discovery's exclusions. Hydration
                                // re-admits records without walking the tree, so
                                // a record written before one of these rules
                                // existed (the data-directory guard, `.bak`,
                                // `.migration-tmp`) would otherwise come straight
                                // back into the shared and announced index.
                                let record_path = std::path::Path::new(&record.file_path);
                                if crate::sharing::indexer::is_excluded_share_file_name(record_path)
                                    || crate::sharing::indexer::is_excluded_share_location(
                                        record_path,
                                    )
                                {
                                    return false;
                                }
                                let metadata = match std::fs::symlink_metadata(&record.file_path)
                                {
                                    Ok(metadata)
                                        if metadata.file_type().is_file()
                                            && !metadata.file_type().is_symlink() =>
                                    {
                                        metadata
                                    }
                                    _ => return false,
                                };
                                let modified_at = metadata
                                    .modified()
                                    .ok()
                                    .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                                    .map(|duration| duration.as_secs() as i64)
                                    .unwrap_or(0);
                                metadata.len() == record.file_size
                                    && modified_at == record.modified_at
                            })
                            .collect::<Vec<_>>()
                    })
                    .await
                    .unwrap_or_default();
                    for record in hydrated_records {
                        let record_path_key =
                            crate::search::index::normalize_path_key(&record.file_path);
                        if record.file_path.is_empty()
                            || !commands::sharing::file_in_shared_folders(
                                &record.file_path,
                                &current_shared_folders,
                            )
                            || known_paths.contains(&record_path_key)
                        {
                            continue;
                        }
                        known_paths.insert(record_path_key);
                        let hash = hex::encode(record.file_hash);
                        let extension = std::path::Path::new(&record.file_path)
                            .extension()
                            .map(|extension| extension.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let folder = std::path::Path::new(&record.file_path)
                            .parent()
                            .map(|parent| parent.to_string_lossy().to_string())
                            .unwrap_or_default();
                        all_discovered.push(crate::types::FileInfo {
                            id: hash.clone(),
                            name: record.file_name.clone(),
                            path: record.file_path.clone(),
                            size: record.file_size,
                            hash,
                            aich_hash: record.aich_hash.clone(),
                            ember_file_hash: record.ember_file_hash.clone(),
                            extension,
                            modified_at: record.modified_at,
                            priority: storage::known_files::priority_u8_to_str(
                                record.upload_priority,
                            )
                            .to_string(),
                            requests: 0,
                            accepted: 0,
                            bytes_transferred: 0,
                            alltime_requests: record.all_time_requested,
                            alltime_accepted: record.all_time_accepted,
                            alltime_transferred: record.all_time_transferred,
                            complete_sources: record.complete_sources,
                            folder,
                            shared: storage::share_intent::effective_shared(
                                &record.file_hash,
                                record.is_shared,
                            ),
                            friends_only: record.friends_only,
                            shared_kad: false,
                            shared_ed2k: false,
                            shared_ember: false,
                        });
                    }
                }

                let (folder_priorities, pending_share_states, pending_file_priorities) = {
                    let state = startup_app.state::<AppState>();
                    let cfg = state.config.read().await;
                    (
                        cfg.settings.folder_priorities.clone(),
                        cfg.settings.pending_share_states.clone(),
                        cfg.settings.pending_file_priorities.clone(),
                    )
                };
                commands::sharing::apply_pending_intents(
                    &mut all_discovered,
                    &mut files_to_hash,
                    &pending_share_states,
                    &pending_file_priorities,
                );
                {
                    let mut index = index_clone.write().await;
                    index.add_files(all_discovered.clone());
                    // Apply each shared folder's default upload priority so
                    // newly discovered files (files with no known.met record —
                    // never seen before, or added while the app was closed)
                    // inherit eMule-style per-directory priority. Restricted to
                    // `new_paths` so this doesn't clobber a per-file priority
                    // that was just restored from known.met above for a file
                    // that was already known.
                    for (folder, priority) in &folder_priorities {
                        index.set_priority_under_folder_for_paths(folder, priority, &new_paths);
                    }
                    // An explicit priority selected while this path was
                    // pending wins over its folder default — but only for
                    // paths that are actually pending in THIS pass. Applying
                    // the map index-wide would override the priority just
                    // restored from known.met for already-hashed files (a
                    // stale intent would make the user's later choice
                    // permanently un-stickable across restarts).
                    let pending_priority_paths: std::collections::HashSet<String> = files_to_hash
                        .iter()
                        .map(|f| crate::search::index::normalize_path_key(&f.path))
                        .collect();
                    for (path, priority) in &pending_file_priorities {
                        if pending_priority_paths
                            .contains(&crate::search::index::normalize_path_key(path))
                        {
                            index.set_file_priority_by_path(path, priority);
                        }
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
                // Checkpoint recomputed hashes into known.met periodically so a
                // long hash pass (notably the one-time AICH migration re-hash)
                // resumes after a restart instead of starting from zero. Bounded
                // by both elapsed time and file count so the loss window stays
                // small whether files hash slowly (large) or quickly (many).
                let mut last_known_met_persist = std::time::Instant::now();
                let mut hashed_since_persist = 0usize;
                let mut was_cancelled = false;
                let mut page_complete = true;

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

                    let mut hash_task = tokio::task::spawn_blocking(move || {
                        FileIndexer::hash_file_cancellable(std::path::Path::new(&file_path), &cf)
                    });
                    let hash_result = tokio::time::timeout(
                        std::time::Duration::from_secs(300),
                        &mut hash_task,
                    )
                    .await;

                    match hash_result {
                        Ok(Ok(Ok((
                            ed2k_hash,
                            aich_hash,
                            part_hashes,
                            ember_file_hash,
                            hashed_size,
                            hashed_modified_at,
                        )))) => {
                            tracing::debug!("Startup hash complete: {} -> {}", file.name, &ed2k_hash[..ed2k_hash.len().min(8)]);
                            let mut updated = file.clone();
                            updated.id = ed2k_hash.clone();
                            updated.hash = ed2k_hash;
                            updated.aich_hash = aich_hash;
                            updated.ember_file_hash = ember_file_hash;
                            updated.size = hashed_size;
                            updated.modified_at = hashed_modified_at;
                            if let Ok(bytes) = hex::decode(&updated.hash) {
                                if bytes.len() == 16 {
                                    let mut hash = [0u8; 16];
                                    hash.copy_from_slice(&bytes);
                                    updated.shared =
                                        storage::share_intent::effective_shared(
                                            &hash,
                                            updated.shared,
                                        );
                                }
                            }
                            let still_shared = {
                                let state = startup_app.state::<AppState>();
                                let cfg = state.config.read().await;
                                commands::sharing::file_in_shared_folders(&updated.path, &cfg.settings.shared_folders)
                            };
                            // Keep the combined-pass handoff only after the
                            // completed row is committed. A cancellation can
                            // remove the pending row after hashing, leaving no
                            // reconciliation path to drain an early insert.
                            let fresh_handoff = still_shared
                                .then(|| {
                                    commands::sharing::fresh_part_hash_handoff(
                                        &updated.hash,
                                        part_hashes,
                                    )
                                })
                                .flatten();
                            let finalized = {
                                let mut idx = index_clone.write().await;
                                if !cancel_flag.load(std::sync::atomic::Ordering::Relaxed) && still_shared {
                                    // Keep any explicit share/priority choice
                                    // made while this row was pending. A
                                    // removed pending row must not return just
                                    // because its hash computation finished.
                                    idx.finalize_pending_hash(&file_temp_id, updated.clone()).is_some()
                                } else if still_shared {
                                    // Cancelled. A re-hash row is already
                                    // servable and keeps its place; only an
                                    // unhashed row is discarded.
                                    idx.abandon_hash_placeholder(&file_temp_id);
                                    false
                                } else {
                                    // No longer under a shared folder, so the
                                    // row goes whatever kind it is.
                                    idx.remove_file_by_id(&file_temp_id);
                                    false
                                }
                            };
                            commands::sharing::cache_fresh_part_hash_handoff(
                                &startup_fresh_part_hashes,
                                finalized,
                                fresh_handoff,
                            )
                            .await;
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
                            // Fold freshly hashed AICH roots into known.met so an
                            // interrupted pass resumes where it left off. A
                            // SharedFilesChanged reconcile copies the index's new
                            // roots into the network task's known.met (preserving
                            // cumulative counters); its periodic + shutdown save
                            // then flush them to disk.
                            if !cancel_flag.load(std::sync::atomic::Ordering::Relaxed)
                                && still_shared
                            {
                                hashed_since_persist += 1;
                                if hashed_since_persist >= 500
                                    || last_known_met_persist.elapsed()
                                        >= std::time::Duration::from_secs(30)
                                {
                                    if reconcile_shared_files(&net_tx).await {
                                        last_known_met_persist = std::time::Instant::now();
                                        hashed_since_persist = 0;
                                    }
                                }
                            }
                        }
                        Ok(Ok(Err(e))) => {
                            if e.to_string().contains("cancelled") {
                                info!("Startup hashing cancelled mid-file");
                                was_cancelled = true;
                                let mut idx = index_clone.write().await;
                                idx.abandon_hash_placeholder(&file_temp_id);
                                break;
                            }
                            tracing::warn!("Startup hash failed for {}: {e}", file.name);
                            page_complete = false;
                            let mut idx = index_clone.write().await;
                            idx.abandon_hash_placeholder(&file_temp_id);
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Startup hash task panicked for {}: {e}", file.name);
                            page_complete = false;
                            let mut idx = index_clone.write().await;
                            idx.abandon_hash_placeholder(&file_temp_id);
                        }
                        Err(_) => {
                            // One slow file must not end the scan. Cancelling the
                            // whole pass here and dropping the pending rows made
                            // every file after this one silently un-indexed, and
                            // it recurred on every launch because the queue is
                            // walked in a stable order — the same failure the
                            // "leaving pending for retry" behaviour was written to
                            // prevent. Leave the row pending, mark the page
                            // incomplete so nothing is reconciled away, and move on.
                            tracing::warn!(
                                "Startup hash timed out for {} (file may be on cloud storage or locked); leaving pending for retry",
                                file.name
                            );
                            page_complete = false;
                            // Drain the abandoned blocking hash for its log line
                            // only. It must hold no scan lease: the read may be
                            // stuck in the kernel where the cancel flag cannot
                            // reach it, and holding the coordination/scan guards
                            // across that wait would block every later reload and
                            // stall shutdown for the rest of the session.
                            let timed_out_name = file.name.clone();
                            tokio::spawn(async move {
                                if let Err(error) = hash_task.await {
                                    tracing::warn!(
                                        "Timed-out startup hash task for {timed_out_name} failed while draining: {error}"
                                    );
                                }
                            });
                            continue;
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

                if !was_cancelled && page_complete {
                    let app_state = startup_app.state::<AppState>();
                    // Startup always rescans page 1, so its cursor must never
                    // move a reload's further-advanced cursor backward.
                    if let Err(error) = commands::sharing::persist_scan_cursors(
                        &app_state,
                        &startup_cursor_updates,
                        true,
                    )
                    .await
                    {
                        tracing::warn!(
                            "Startup shared-folder pages were indexed but scan cursors were not saved: {error}"
                        );
                    }
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

                drop(scan_guard);
                startup_cancel_flags.write().await.remove("__startup__");
                if !reconcile_shared_files(&net_tx).await {
                    tracing::warn!("Startup shared-file reconciliation failed");
                } else if !was_cancelled {
                    // known.met now owns everything hashed this pass — sweep
                    // handed-off (or stale pre-fix) pending intents so they
                    // can't re-apply share/priority flips on a later rehash.
                    let app_state = startup_app.state::<AppState>();
                    commands::sharing::prune_pending_intents_for_hashed(&app_state).await;
                }
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
            {
                let state = app_handle.state::<AppState>();
                tauri::async_runtime::handle()
                    .block_on(state.register_background_scan(startup_scan_handle));
            }

            let net_handle = app_handle.clone();
            let net_index = local_index.clone();
            let net_fresh_part_hashes = fresh_part_hashes.clone();
            let net_db = db.clone();
            let net_transfers = transfer_manager.clone();
            let net_bw = bandwidth_limiter.clone();
            let bw_limiter = bandwidth_limiter.clone();
            let bw_shutdown_spawn = bw_shutdown.clone();
            let bw_rtt = uss_rtt_queue.clone();
            let bw_uss_flag = uss_enabled_flag.clone();
            let net_spam = spam_filter.clone();
            let net_identity = identity.clone();
            let net_security_policy = security_policy.clone();
            let net_handle_err = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = network::start_network(
                    net_handle,
                    network_rx,
                    settings,
                    net_identity,
                    net_security_policy,
                    net_index,
                    net_fresh_part_hashes,
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
                    mutual_friend_hashes,
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
            commands::backup::export_backup,
            commands::backup::preview_backup,
            commands::backup::import_backup,
            commands::backup::pending_restore_status,
            commands::backup::discard_pending_restore,
            commands::search::search_files,
            commands::search::cancel_search,
            commands::search::find_notes,
            commands::search::find_sources,
            commands::search::compute_ed2k_hash,
            commands::search::publish_note,
            commands::search::format_ed2k_link,
            commands::search::format_ed2k_links,
            commands::search::build_ed2k_link,
            commands::search::parse_ed2k_link,
            commands::search::parse_ed2k_links,
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
            commands::transfers::take_pending_download_overflow_notice,
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
            commands::transfers::open_downloads_folder,
            commands::transfers::recover_archive,
            commands::sharing::pick_shared_folder,
            commands::sharing::confirm_dropped_folders,
            commands::sharing::dismiss_dropped_folders,
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
            commands::sharing::set_files_friends_only,
            commands::sharing::reload_shared_files,
            commands::sharing::unshare_file,
            commands::sharing::share_file,
            commands::sharing::unshare_folder,
            commands::sharing::get_scan_status,
            commands::sharing::get_library_scan_truncated,
            commands::sharing::stop_hashing,
            commands::sharing::resume_hashing,
            commands::sharing::open_shared_file,
            commands::sharing::resolve_media_asset_path,
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
            commands::peers::block_friend,
            commands::peers::unblock_friend,
            commands::peers::get_blocked_friends,
            commands::peers::get_friends,
            commands::peers::update_friend_nickname,
            commands::peers::get_my_ember_hash,
            commands::peers::send_chat_message,
            commands::peers::get_chat_messages,
            commands::peers::is_chat_locked,
            commands::peers::mark_messages_read,
            commands::peers::get_unread_message_counts,
            commands::peers::get_pending_chat_counts,
            commands::peers::offer_file_to_friend,
            commands::peers::get_friend_requests,
            commands::peers::accept_friend_request,
            commands::peers::reject_friend_request,
            commands::peers::browse_friend,
            commands::peers::cancel_browse_friend,
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
            commands::peers::get_ember_dht_searches,
            commands::peers::get_ember_dht_store,
            commands::peers::add_ember_dht_contact,
            commands::peers::ember_dht_ping_peer,
            commands::peers::ember_dht_find_node,
            commands::peers::ember_dht_iterative_find_node,
            commands::peers::ember_dht_publish_keyword,
            commands::peers::ember_dht_find_value,
            commands::peers::ember_dht_run_maintenance,
            commands::peers::ember_request_sources,
            commands::settings::get_settings,
            commands::settings::update_settings,
            commands::settings::download_nodes_dat,
            commands::settings::download_ipfilter,
            commands::settings::hide_to_tray,
            commands::settings::show_main_window,
            commands::settings::quit_app,
            commands::settings::set_close_behavior,
            commands::settings::take_pending_close_request,
            commands::settings::take_pending_ember_default_on_notice,
            commands::settings::open_ember_website,
            commands::security::get_security_policy_state,
            commands::security::acknowledge_security_policy_reset,
            commands::security::get_ip_filter_stats,
            commands::security::add_ip_filter_range,
            commands::security::remove_ip_filter_range,
            commands::security::set_ip_filter_enabled,
            commands::security::set_block_private_ips,
            commands::security::download_and_load_ipfilter,
            commands::security::update_ipfilter_from_url,
            commands::security::pick_and_import_ipfilter_file,
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
            commands::collections::pick_and_load_collection,
            commands::collections::create_collection,
            commands::collections::create_collection_with_dialog,
            commands::collections::download_collection_files,
            commands::preview::preview_file,
            commands::speed_test::run_speed_test,
            commands::deeplink::take_pending_deep_links,
            commands::deeplink::list_pending_deep_links,
            commands::deeplink::ack_pending_deep_link,
            commands::deeplink::preview_deep_link,
            commands::deeplink::open_pending_collection,
            commands::updater::secure_updater_check,
            commands::updater::secure_updater_install,
            commands::updater::secure_updater_handoff_status,
            commands::updater::secure_updater_run_saved_installer,
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

            // Files and folders dropped onto the window. Handled here rather
            // than in the webview's own drag-drop event because that is what
            // makes the paths usable at all: `add_shared_folder` is not an
            // invokable command, so a path arriving from the renderer is not
            // authorization, while one the OS delivered to this window is. The
            // frontend still draws the drop overlay; it just no longer decides
            // what was dropped.
            if let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                let app_handle = window.app_handle().clone();
                let paths = paths.clone();
                tauri::async_runtime::spawn(async move {
                    commands::sharing::share_dropped_paths(app_handle, paths).await;
                });
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
                    // The frontend listener is registered asynchronously
                    // during startup. Record the request first so it can be
                    // consumed after registration if this emit is missed.
                    state
                        .pending_close_request
                        .store(true, std::sync::atomic::Ordering::Release);
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
                // Exit is delivered on the main thread, outside the async
                // runtime, and the process is torn down the moment this
                // returns — block here until the teardown has finished
                // flushing rather than letting it race the exit.
                tauri::async_runtime::handle()
                    .block_on(run_graceful_shutdown(app_handle, SHUTDOWN_WAIT));
            }
        });
}
