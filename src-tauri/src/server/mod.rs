//! `emberd`: Ember with no window, driven from a web browser
//! (`docs/headless.md`). The same startup, network and commands as the
//! desktop app; this module adds the config file, the login, the web
//! interface and the command line.
#![warn(dead_code, unused_imports)]

mod auth;
mod config;
mod ctl;
mod http;
pub(crate) mod uploads;

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use tracing::{error, info, warn};

use crate::host::AppHandle;

const USAGE: &str = "\
emberd: Ember without a window, used from a web browser.

Usage:
  emberd [--config FILE]               Run Ember and its web interface
  emberd passwd [--config FILE] [--stdin]
                                       Set the web interface's password
  emberd ctl COMMAND...                Downloads and search from a shell;
                                       emberd ctl --help says more
  emberd --version                     Print the version
  emberd --help                        Print this

The config file is optional; see docs/headless.md for its keys and the
EMBERD_* environment variables. Without one, the web interface is at
http://localhost:4711 and only this computer can reach it.";

enum Command {
    Run { config: Option<PathBuf> },
    Passwd { config: Option<PathBuf>, stdin: bool },
    Ctl(Vec<String>),
    Version,
    Help,
}

fn parse(args: &[String]) -> Result<Command, String> {
    // Everything after `ctl` is its own.
    if args.first().map(String::as_str) == Some("ctl") {
        return Ok(Command::Ctl(args[1..].to_vec()));
    }
    let mut config = None;
    let mut stdin = false;
    let mut subcommand: Option<&str> = None;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" | "help" => return Ok(Command::Help),
            "-V" | "--version" | "version" => return Ok(Command::Version),
            "-c" | "--config" => {
                let value = iter.next().ok_or("--config needs a file")?;
                config = Some(PathBuf::from(value));
            }
            "--stdin" => stdin = true,
            "run" | "passwd" if subcommand.is_none() => subcommand = Some(arg.as_str()),
            other => {
                if let Some(value) = other.strip_prefix("--config=") {
                    config = Some(PathBuf::from(value));
                } else {
                    return Err(format!("emberd: unknown argument \"{other}\""));
                }
            }
        }
    }
    match subcommand {
        Some("passwd") => Ok(Command::Passwd { config, stdin }),
        _ if stdin => Err("emberd: --stdin only goes with passwd".to_string()),
        _ => Ok(Command::Run { config }),
    }
}

/// `emberd`'s `main`. The exit status: 0 stopped cleanly, 1 could not start,
/// 2 the command line or config was wrong.
pub fn main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            0
        }
        Ok(Command::Version) => {
            println!("emberd {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Ok(Command::Run { config }) => run(config.as_deref()),
        Ok(Command::Passwd { config, stdin }) => passwd(config.as_deref(), stdin),
        Ok(Command::Ctl(args)) => ctl::run(&args),
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            2
        }
    }
}

/// Read the config and point Ember's data folder at the one it names. Before
/// any thread starts: the data folder is an environment variable.
fn prepare(config_path: Option<&Path>) -> Result<config::Config, String> {
    let config = config::load(config_path)?;
    if let Some(dir) = &config.data_dir {
        std::env::set_var(crate::storage::paths::EMBER_DATA_DIR_ENV, dir);
    }
    Ok(config)
}

/// Held while `emberd` runs: the same lock the desktop app takes, so the two
/// can never use one data folder at once.
fn take_instance_lock(data_dir: &Path) -> Result<std::fs::File, String> {
    use fs2::FileExt;
    let path = data_dir.join("instance.lock");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("Could not open {}: {e}", path.display()))?;
    file.try_lock_exclusive().map_err(|_| {
        format!(
            "Another Ember is using the data folder {} (emberd, or the desktop app). Stop it first.",
            data_dir.display()
        )
    })?;
    Ok(file)
}

/// The exit status that asks for a restart rather than a stop.
pub(crate) const RESTART: i32 = -75;

/// The control socket `emberd ctl` talks to.
const SOCKET_NAME: &str = "emberd.sock";

/// Where emberd opens its control socket: `EMBERD_SOCKET`, else the runtime
/// folder systemd gives the service (`RuntimeDirectory=`), else the data
/// folder.
#[cfg(unix)]
fn control_socket_path(data_dir: &Path) -> PathBuf {
    if let Some(socket) = std::env::var_os("EMBERD_SOCKET") {
        return PathBuf::from(socket);
    }
    if let Some(runtime) = std::env::var_os("RUNTIME_DIRECTORY") {
        if let Some(first) = std::env::split_paths(&runtime).next() {
            return first.join(SOCKET_NAME);
        }
    }
    data_dir.join(SOCKET_NAME)
}

fn run(config_path: Option<&Path>) -> i32 {
    let config = match prepare(config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("emberd: {e}");
            return 2;
        }
    };
    let log_guard = crate::init_process();
    let code = crate::host::async_runtime::block_on(serve_until_stopped(config));
    if code != RESTART {
        return code;
    }
    // Everything is saved and the lock is let go: start again in place.
    drop(log_guard);
    restart_in_place()
}

/// Run `emberd` again with the same arguments. On Unix the same process
/// becomes the new one, keeping its id, so systemd and Docker see one service
/// throughout; descriptors close on exec, the instance lock among them.
fn restart_in_place() -> i32 {
    let Ok(exe) = std::env::current_exe() else {
        eprintln!("emberd: could not find its own program to restart");
        return 1;
    };
    let mut command = std::process::Command::new(exe);
    command.args(std::env::args_os().skip(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        eprintln!("emberd: could not restart: {error}");
        1
    }
    #[cfg(not(unix))]
    {
        match command.spawn() {
            Ok(_) => 0,
            Err(error) => {
                eprintln!("emberd: could not restart: {error}");
                1
            }
        }
    }
}

async fn serve_until_stopped(config: config::Config) -> i32 {
    let data_dir = crate::storage::paths::resolve_data_dir();
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        error!("Could not create the data folder {}: {e}", data_dir.display());
        return 1;
    }
    let _lock = match take_instance_lock(&data_dir) {
        Ok(lock) => lock,
        Err(e) => {
            error!("{e}");
            return 1;
        }
    };
    info!("emberd {} using the data folder {}", env!("CARGO_PKG_VERSION"), data_dir.display());
    // A backup the last run made for a page, or was sent for a restore, is
    // done with: a restore staged from one does not need it.
    for name in [crate::commands::backup::DOWNLOAD_BACKUP, crate::commands::backup::UPLOADED_BACKUP] {
        let file = data_dir.join(name);
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(file.with_extension("partial"));
    }
    uploads::tidy(&data_dir);
    let tidy_dir = data_dir.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(std::time::Duration::from_secs(6 * 60 * 60));
        every.tick().await;
        loop {
            every.tick().await;
            let dir = tidy_dir.clone();
            let _ = tokio::task::spawn_blocking(move || uploads::tidy_sent(&dir)).await;
        }
    });
    if let Some(path) = &config.path {
        info!("Config read from {}", path.display());
    }
    if !http::web_root_usable(&config.web_root) {
        warn!(
            "The web UI's files are not at {}; set web.root (EMBERD_WEB_ROOT) to the folder holding index.html",
            config.web_root.display()
        );
    }
    let (auth, setup_code) = match auth::Auth::load(&data_dir) {
        Ok(loaded) => loaded,
        Err(e) => {
            error!("{e}");
            return 1;
        }
    };
    if let Err(e) = auth.ensure_cli_token() {
        warn!("{e}");
    }
    let _ = OPERATOR.set(config.folders.clone());
    let shown = |path: &Path| crate::commands::share_browser::display_fs_path(path);
    let _ = OVERVIEW.set(ServerOverview {
        version: env!("CARGO_PKG_VERSION").to_string(),
        config_file: config.path.as_deref().map(shown),
        data_folder: shown(&data_dir),
        web_address: format!(
            "{}://{}",
            if config.tls.is_some() { "https" } else { "http" },
            http::display_address(config.listen)
        ),
        https: config.tls.is_some(),
        download_folder: config.folders.download.as_deref().map(shown),
        shared_folders: config.folders.shared.iter().map(|p| shown(p)).collect(),
        browse_under: config.folders.browse_under.iter().map(|p| shown(p)).collect(),
        min_password_chars: auth::MIN_PASSWORD_CHARS,
    });
    let key_file = config.key_file.clone().unwrap_or_else(|| data_dir.join(KEY_FILE));
    if cfg!(windows) {
        // Windows seals with the service account's DPAPI key instead.
        if config.key_file.is_some() {
            warn!("key_file is not used on Windows, where the account's own key seals Ember's secrets");
        }
    } else {
        crate::storage::secret_store::use_key_file(key_file);
    }

    let app = AppHandle::new(config.resource_dir.clone());
    let setup_app = app.clone();
    // As the desktop app runs it, on a thread outside the async runtime:
    // parts of it block on futures of their own.
    match tokio::task::spawn_blocking(move || crate::setup(&setup_app).map_err(|e| e.to_string())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            error!("Ember could not start: {e}");
            return 1;
        }
        Err(e) => {
            error!("Ember's startup failed: {e}");
            return 1;
        }
    }

    let web = Arc::new(http::Web::new(app.clone(), Arc::new(auth), &config));
    let (stop_web, stop_rx) = tokio::sync::watch::channel(false);
    let address = http::display_address(config.listen);
    let scheme = if config.tls.is_some() { "https" } else { "http" };
    let web_config = config.clone();
    let mut server = tokio::spawn(async move { http::serve(web, &web_config, stop_rx).await });
    if let Some(code) = setup_code {
        warn!("");
        warn!("No password is set for the web interface yet. Open {scheme}://{address}");
        warn!("and enter this setup code to choose one: {code}");
        warn!("(The code is also in {}.)", data_dir.join(auth::SETUP_CODE_FILE).display());
        warn!("");
    }
    if config.tls.is_none() && !config.loopback_only() {
        warn!(
            "The web interface is reachable from other computers over plain HTTP: the password and \
             everything you do there travel unencrypted. Use it on a network you trust, or give it a \
             certificate (web.tls_cert and web.tls_key) or put it behind a reverse proxy with HTTPS."
        );
    }

    let code = tokio::select! {
        code = wait_for_stop(&app) => code,
        result = &mut server => {
            match result {
                Ok(Err(e)) => error!("The web interface stopped: {e}"),
                Ok(Ok(())) => {}
                Err(e) => error!("The web interface stopped: {e}"),
            }
            1
        }
    };
    info!("Stopping Ember");
    let _ = stop_web.send(true);
    crate::run_graceful_shutdown(&app, crate::SHUTDOWN_WAIT).await;
    info!("Ember stopped");
    code
}

/// Until the service manager, a terminal or Ember itself asks to stop.
async fn wait_for_stop(app: &AppHandle) -> i32 {
    let mut exit = app.exit_requested();
    let asked = async move {
        loop {
            if let Some(code) = *exit.borrow_and_update() {
                return code;
            }
            if exit.changed().await.is_err() {
                return 0;
            }
        }
    };
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut terminate), Ok(mut interrupt)) = (signal(SignalKind::terminate()), signal(SignalKind::interrupt()))
        else {
            return asked.await;
        };
        tokio::select! {
            _ = terminate.recv() => { info!("SIGTERM received"); 0 }
            _ = interrupt.recv() => { info!("SIGINT received"); 0 }
            code = asked => code,
        }
    }
    #[cfg(not(unix))]
    {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => { info!("Ctrl+C received"); 0 }
            code = asked => code,
        }
    }
}

/// The key file Ember's identity is sealed with, in the data folder unless
/// the config names one.
const KEY_FILE: &str = "emberd-secret.key";

/// The operator's folders, for the startup and the shared-folder commands.
static OPERATOR: OnceLock<config::Folders> = OnceLock::new();

/// What the web page's "This server" settings show: how emberd was started.
#[derive(Clone, serde::Serialize)]
pub struct ServerOverview {
    version: String,
    config_file: Option<String>,
    data_folder: String,
    web_address: String,
    https: bool,
    download_folder: Option<String>,
    shared_folders: Vec<String>,
    browse_under: Vec<String>,
    min_password_chars: usize,
}

static OVERVIEW: OnceLock<ServerOverview> = OnceLock::new();

#[ember_macros::command(server)]
pub fn server_overview() -> Option<ServerOverview> {
    OVERVIEW.get().cloned()
}

/// Where the folders the last start named are remembered, so one taken out of
/// the config stops being shared rather than staying shared for good.
const OPERATOR_FOLDERS_FILE: &str = "emberd-folders.json";

/// How Ember spells a folder in its settings.
fn folder_key(path: &Path) -> String {
    crate::commands::share_browser::display_fs_path(&std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
}

/// The shared folders the config names, as the settings spell them.
pub(crate) fn operator_shared_folders() -> Vec<String> {
    OPERATOR.get().map(|f| f.shared.iter().map(|p| folder_key(p)).collect()).unwrap_or_default()
}

/// The folders under which the web interface may share more.
pub(crate) fn browse_under() -> Vec<PathBuf> {
    OPERATOR.get().map(|f| f.browse_under.clone()).unwrap_or_default()
}

/// Put the operator's folders in the settings before the approved roots are
/// read, and return them to be approved: naming a folder in the config is the
/// operator's say-so, as picking it in a dialog is the desktop user's.
pub(crate) fn apply_operator_folders(config: &mut crate::storage::config::AppConfig, data_dir: &Path) -> Vec<String> {
    let Some(folders) = OPERATOR.get() else {
        return Vec::new();
    };
    let mut settings = config.settings.clone();
    let mut approve = Vec::new();
    if let Some(download) = &folders.download {
        if let Err(e) = std::fs::create_dir_all(download) {
            warn!("Could not create the download folder {}: {e}", download.display());
        }
        let key = folder_key(download);
        settings.download_folder = key.clone();
        approve.push(key);
    }
    let named: Vec<String> = folders
        .shared
        .iter()
        .filter(|folder| {
            let there = folder.is_dir();
            if !there {
                warn!("The shared folder {} is not there; it is shared once it is", folder.display());
            }
            there
        })
        .map(|folder| folder_key(folder))
        .collect();
    let remembered_path = data_dir.join(OPERATOR_FOLDERS_FILE);
    let remembered: Vec<String> = std::fs::read(&remembered_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    // Taken out of the config since the last start: not shared any more.
    settings.shared_folders.retain(|folder| named.contains(folder) || !remembered.contains(folder));
    for folder in &named {
        if !settings.shared_folders.contains(folder) {
            settings.shared_folders.push(folder.clone());
        }
        approve.push(folder.clone());
    }
    if let Ok(text) = serde_json::to_vec(&named) {
        if let Err(e) = crate::security::atomic_write(&remembered_path, &text, true) {
            warn!("Could not write {}: {e}", remembered_path.display());
        }
    }
    if settings.download_folder != config.settings.download_folder
        || settings.shared_folders != config.settings.shared_folders
    {
        match config.prepare_save_settings(&settings) {
            Ok((text, tmp, path)) => {
                if let Err(e) = crate::storage::config::AppConfig::write_to_disk(&text, &tmp, &path) {
                    warn!("Could not save the folders from the config: {e}");
                }
            }
            Err(e) => warn!("Could not save the folders from the config: {e}"),
        }
        config.settings = settings;
    }
    approve
}

fn passwd(config_path: Option<&Path>, stdin: bool) -> i32 {
    if let Err(e) = prepare(config_path) {
        eprintln!("emberd: {e}");
        return 2;
    }
    let data_dir = crate::storage::paths::resolve_data_dir();
    if let Err(e) = std::fs::create_dir_all(&data_dir) {
        eprintln!("emberd: could not create {}: {e}", data_dir.display());
        return 1;
    }
    // The running emberd keeps the password in memory and would write over
    // a change made beside it.
    let _lock = match take_instance_lock(&data_dir) {
        Ok(lock) => lock,
        Err(_) => {
            eprintln!("emberd is running on {}. Stop it, set the password, then start it again.", data_dir.display());
            return 1;
        }
    };
    let password = if stdin {
        read_line_hidden(None)
    } else {
        let first = read_line_hidden(Some("New password: "));
        let second = read_line_hidden(Some("Again: "));
        match (first, second) {
            (Ok(a), Ok(b)) if a == b => Ok(a),
            (Ok(_), Ok(_)) => {
                eprintln!("The two did not match; nothing was changed.");
                return 1;
            }
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    };
    let password = match password {
        Ok(password) => password,
        Err(e) => {
            eprintln!("emberd: could not read the password: {e}");
            return 1;
        }
    };
    let auth = match auth::Auth::load(&data_dir) {
        Ok((auth, _)) => auth,
        Err(e) => {
            eprintln!("emberd: {e}");
            return 1;
        }
    };
    match auth.set_password(&password) {
        Ok(()) => {
            println!("The password is set. Every browser has to log in again.");
            0
        }
        Err(e) => {
            eprintln!("emberd: {e}");
            1
        }
    }
}

/// A line from standard input, not echoed when it is a terminal.
fn read_line_hidden(prompt: Option<&str>) -> std::io::Result<String> {
    use std::io::{BufRead, Write};
    if let Some(prompt) = prompt {
        eprint!("{prompt}");
        std::io::stderr().flush()?;
    }
    #[cfg(unix)]
    let restore = {
        let fd = libc::STDIN_FILENO;
        // SAFETY: `termios` is plain data that `tcgetattr` fills in.
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: `term` is a valid termios for `tcgetattr` to write.
        if unsafe { libc::tcgetattr(fd, &mut term) } == 0 {
            let mut hidden = term;
            hidden.c_lflag &= !libc::ECHO;
            // SAFETY: `hidden` is the terminal's own settings with echo off.
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) };
            Some(term)
        } else {
            None
        }
    };
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    #[cfg(unix)]
    if let Some(term) = restore {
        // SAFETY: putting back the settings `tcgetattr` read.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &term) };
        if prompt.is_some() {
            eprintln!();
        }
    }
    read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_command_line_reads_as_documented() {
        assert!(matches!(parse(&args(&[])), Ok(Command::Run { config: None })));
        assert!(matches!(parse(&args(&["--config", "/e.toml"])), Ok(Command::Run { config: Some(_) })));
        assert!(matches!(parse(&args(&["--config=/e.toml"])), Ok(Command::Run { config: Some(_) })));
        assert!(matches!(parse(&args(&["passwd", "--stdin"])), Ok(Command::Passwd { stdin: true, .. })));
        assert!(matches!(parse(&args(&["--version"])), Ok(Command::Version)));
        assert!(matches!(parse(&args(&["-h"])), Ok(Command::Help)));
        assert!(
            matches!(parse(&args(&["ctl", "--help"])), Ok(Command::Ctl(rest)) if rest == ["--help"]),
            "everything after ctl is its own, --help included"
        );
        assert!(parse(&args(&["--config"])).is_err());
        assert!(parse(&args(&["--stdin"])).is_err());
        assert!(parse(&args(&["frobnicate"])).is_err());
    }
}
