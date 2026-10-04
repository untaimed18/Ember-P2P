//! `update-resume.json`: the session an update restart comes back to.
//!
//! Written just before an update shuts Ember down, while the state it records is
//! still live, and consumed once by the next launch: the window as it was
//! (hidden in the tray, minimized, maximized or where it sat), the eD2K server
//! it was on, the page it showed, its search tabs and a popped-out chat window.
//!
//! The file is input, not instructions. Anything running as the user can write
//! the data directory, so every field is validated on the way in, a stale file
//! is not applied, and nothing in it names an executable, a URL or a version to
//! install. It is deleted before it is applied, so a crash while applying it
//! cannot turn into a loop.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};

use crate::app_state::AppState;
use crate::commands::chat_window::CHAT_WINDOW_LABEL;

pub const RESUME_FILE: &str = "update-resume.json";
/// Emitted to the main window to ask for its page and search tabs.
pub const UI_SNAPSHOT_REQUEST_EVENT: &str = "ember:resume-ui-request";

const SCHEMA: u32 = 1;
/// Older than this, the machine rebooted or something else intervened, and the
/// session the file describes is not the one the user left.
const MAX_AGE_SECS: i64 = 2 * 3600;
/// A file stamped a little in the future is a clock adjustment, not a forgery
/// worth refusing; much further means the clock is wrong and age says nothing.
const MAX_FUTURE_SKEW_SECS: i64 = 5 * 60;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SEARCH_TABS_BYTES: usize = 6 * 1024 * 1024;
const MAX_VERSION_CHARS: usize = 64;
const MAX_LAUNCH_LINKS: usize = 32;
/// How long after the launch that read the resume file the links it lists are
/// still dropped. The installer's relaunch can come after another launch (the
/// watchdog's, or the user opening Ember) and then reaches the running Ember
/// through the single-instance plugin; past this, a link is one somebody
/// clicked.
const REPLAYED_LINKS_WINDOW: Duration = Duration::from_secs(10 * 60);
/// How long the frontend has to hand over its page and search tabs. A webview
/// throttled in the tray still answers events; one that is hung must not hold
/// up the update.
const UI_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(3);
const SERVER_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
/// Far past any real monitor; bounds larger than this are corrupt.
const MAX_EXTENT: i64 = 16_384;
const MIN_WINDOW_EXTENT: u32 = 200;

/// Top-level pages a restored session may land on.
const ROUTES: &[&str] = &[
    "/",
    "/transfers",
    "/search",
    "/library",
    "/friends",
    "/channels",
    "/servers",
    "/kad",
    "/kad-network",
    "/ember",
    "/statistics",
    "/security",
    "/settings",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeReason {
    /// Ember updated itself while the user was away.
    Silent,
    /// The user pressed Install.
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    /// Hidden, with only the tray icon showing.
    Tray,
    Minimized,
    Normal,
}

/// The outer frame's top-left and the client area's size, in physical pixels:
/// what `set_position` and `set_size` take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Bounds {
    fn is_sane(&self) -> bool {
        i64::from(self.x).abs() <= MAX_EXTENT
            && i64::from(self.y).abs() <= MAX_EXTENT
            && (MIN_WINDOW_EXTENT..=MAX_EXTENT as u32).contains(&self.width)
            && (MIN_WINDOW_EXTENT..=MAX_EXTENT as u32).contains(&self.height)
    }
}

/// A point on the desktop in physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    fn is_sane(&self) -> bool {
        i64::from(self.x).abs() <= MAX_EXTENT && i64::from(self.y).abs() <= MAX_EXTENT
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSnapshot {
    pub visibility: Visibility,
    #[serde(default)]
    pub maximized: bool,
    /// Absent while maximized or minimized, when the OS reports the maximized
    /// frame or an off-screen parking spot rather than where the window sits.
    #[serde(default)]
    pub bounds: Option<Bounds>,
    /// While maximized, the centre of the maximized frame: the monitor to
    /// maximize on again.
    #[serde(default)]
    pub maximized_center: Option<Point>,
    /// The chat was popped out into its own window. Its position is kept by the
    /// chat window itself.
    #[serde(default)]
    pub chat_window_open: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerSnapshot {
    pub ip: String,
    pub port: u16,
}

/// What only the frontend knows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiSnapshot {
    #[serde(default)]
    pub route: Option<String>,
    /// The search store's own persisted payload, verbatim. The frontend parses
    /// it with the same validation it applies to session storage.
    #[serde(default)]
    pub search_tabs: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeState {
    pub schema: u32,
    pub written_at: i64,
    pub reason: ResumeReason,
    pub from_version: String,
    pub target_version: String,
    pub window: WindowSnapshot,
    #[serde(default)]
    pub ed2k: Option<ServerSnapshot>,
    #[serde(default)]
    pub ui: UiSnapshot,
    /// SHA-256, in hex, of each deep link the writing process was launched
    /// with, and of the pieces of one holding spaces that still read as links.
    /// The relaunch after an update is handed those arguments again (the NSIS
    /// installer's `/ARGS`, `AppHandle::restart`), and they are not links
    /// anyone just clicked.
    #[serde(default)]
    pub launch_links: Vec<String>,
}

/// How the update the file was written for turned out, judged by the version
/// this launch is running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateOutcome {
    pub reason: ResumeReason,
    pub from_version: String,
    pub target_version: String,
    pub installed: bool,
}

/// What a launch found in the resume file.
#[derive(Debug, Default)]
pub struct LaunchResume {
    /// Present whenever a well-formed file was found, fresh or not: a stale file
    /// still says whether the update it was written for landed.
    pub outcome: Option<UpdateOutcome>,
    /// Present only when the file is fresh enough to describe this session.
    pub state: Option<ResumeState>,
    /// [`ResumeState::launch_links`], fresh or not: however long the relaunch
    /// took, its arguments are still the old process's.
    pub replayed_links: Vec<String>,
}

/// The frontend's half of a restored session, handed over once.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UiResume {
    pub route: Option<String>,
    pub search_tabs: Option<String>,
    pub reopen_chat_window: bool,
}

/// Managed state for a resumed session and for capturing the next one.
#[derive(Default)]
pub struct ResumeService {
    launch_ui: parking_lot::Mutex<Option<UiResume>>,
    outcome: parking_lot::Mutex<Option<UpdateOutcome>>,
    pending_ui: parking_lot::Mutex<Option<(u64, tokio::sync::oneshot::Sender<UiSnapshot>)>>,
    next_request: AtomicU64,
    /// Restored hidden in the tray from a maximized window: maximizing a hidden
    /// window shows it on some platforms, so it is maximized the first time it
    /// is shown instead.
    maximize_on_show: AtomicBool,
    replayed_links: parking_lot::Mutex<ReplayedLinks>,
}

/// [`ResumeState::launch_links`], dropped for [`REPLAYED_LINKS_WINDOW`] after
/// the launch that read them.
#[derive(Default)]
struct ReplayedLinks {
    digests: Vec<String>,
    until: Option<Instant>,
}

impl ReplayedLinks {
    fn arm(&mut self, digests: Vec<String>, now: Instant) {
        self.digests = digests;
        self.until = Some(now + REPLAYED_LINKS_WINDOW);
    }

    /// `payloads` less the listed ones, each listing used up by the link it
    /// drops, so the same link clicked again afterwards goes through.
    fn drop_from(&mut self, payloads: Vec<String>, now: Instant) -> Vec<String> {
        if self.until.is_none_or(|until| now >= until) {
            self.digests.clear();
        }
        payloads
            .into_iter()
            .filter(|payload| {
                let digest = link_digest(payload);
                match self.digests.iter().position(|listed| *listed == digest) {
                    Some(index) => {
                        self.digests.swap_remove(index);
                        false
                    }
                    None => true,
                }
            })
            .collect()
    }
}

impl ResumeService {
    /// How the update this launch resumed from turned out, if it was one.
    pub fn outcome(&self) -> Option<UpdateOutcome> {
        self.outcome.lock().clone()
    }

    /// The same, handed over once.
    pub fn take_outcome(&self) -> Option<UpdateOutcome> {
        self.outcome.lock().take()
    }

    /// Report an outcome learned some other way than the resume file.
    pub fn set_outcome(&self, outcome: UpdateOutcome) {
        *self.outcome.lock() = Some(outcome);
    }
}

/// The server a resumed launch should reconnect to, taken once by the network
/// task as it starts.
static RESUME_SERVER: parking_lot::Mutex<Option<(String, u16)>> = parking_lot::Mutex::new(None);

pub fn take_resume_server() -> Option<(String, u16)> {
    RESUME_SERVER.lock().take()
}

fn link_digest(payload: &str) -> String {
    hex::encode(Sha256::digest(payload.as_bytes()))
}

/// Digests of the deep links in `args`, as [`ResumeState::launch_links`]
/// records them. The NSIS installer hands the arguments back with the quotes
/// that kept each one whole stripped, so one holding spaces comes back in
/// pieces.
fn launch_link_digests(args: &[String]) -> Vec<String> {
    use crate::commands::deeplink::extract_deep_link_payloads;
    let pieces: Vec<String> = std::iter::once(String::new())
        .chain(
            args.iter()
                .skip(1)
                .flat_map(|arg| arg.split([' ', '\t']))
                .map(str::to_string),
        )
        .collect();
    let mut digests: Vec<String> = extract_deep_link_payloads(args)
        .iter()
        .map(|payload| link_digest(payload))
        .collect();
    for piece in extract_deep_link_payloads(&pieces) {
        let digest = link_digest(&piece);
        if !digests.contains(&digest) {
            digests.push(digest);
        }
    }
    digests.truncate(MAX_LAUNCH_LINKS);
    digests
}

/// A launch's deep links, less those an update restart handed back from the
/// process it replaced, whether on this launch's own command line or forwarded
/// by the single-instance plugin from a later one. Matching each link rather
/// than dropping them all keeps one the user clicked while the update was
/// relaunching Ember.
pub fn without_replayed_links(app: &AppHandle, payloads: Vec<String>) -> Vec<String> {
    if payloads.is_empty() {
        return payloads;
    }
    let given = payloads.len();
    let kept = app
        .state::<ResumeService>()
        .replayed_links
        .lock()
        .drop_from(payloads, Instant::now());
    if kept.len() < given {
        tracing::info!(
            "Not offering again the {} deep link(s) this update restart was relaunched with",
            given - kept.len()
        );
    }
    kept
}

// ── Consuming ───────────────────────────────────────────────────────────────

/// Read, delete and validate the resume file in `dir`.
pub fn take_from(dir: &Path, running_version: &str, now: i64) -> LaunchResume {
    let path = dir.join(RESUME_FILE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > MAX_FILE_BYTES => {
            tracing::warn!("Discarding an oversized {RESUME_FILE}");
            let _ = std::fs::remove_file(&path);
            return LaunchResume::default();
        }
        Ok(_) => {}
        Err(_) => return LaunchResume::default(),
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!("Could not read {RESUME_FILE}: {error}");
            return LaunchResume::default();
        }
    };
    // Gone before anything in it is acted on. If it cannot be removed it is not
    // applied either: applying a file that will still be there next launch is
    // how one bad value becomes a loop.
    if let Err(error) = std::fs::remove_file(&path) {
        tracing::warn!("Not resuming: could not remove {RESUME_FILE}: {error}");
        return LaunchResume::default();
    }
    let state: ResumeState = match serde_json::from_slice(&bytes) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!("Discarding an unreadable {RESUME_FILE}: {error}");
            return LaunchResume::default();
        }
    };
    if state.schema != SCHEMA
        || !plausible_version(&state.from_version)
        || !plausible_version(&state.target_version)
    {
        tracing::warn!("Discarding a {RESUME_FILE} this build does not understand");
        return LaunchResume::default();
    }

    let outcome = UpdateOutcome {
        reason: state.reason,
        from_version: state.from_version.clone(),
        target_version: state.target_version.clone(),
        installed: running_version == state.target_version,
    };
    let replayed_links = plausible_digests(&state.launch_links);
    let age = now.saturating_sub(state.written_at);
    let fresh = (-MAX_FUTURE_SKEW_SECS..=MAX_AGE_SECS).contains(&age);
    if !fresh {
        tracing::info!("Not restoring the session from a {RESUME_FILE} written {age}s ago");
    }
    LaunchResume {
        outcome: Some(outcome),
        state: fresh.then(|| sanitize(state)),
        replayed_links,
    }
}

/// The digests that look like ones this build writes. A forged list can only
/// keep a link from being offered, which deleting it from the queue does too.
fn plausible_digests(digests: &[String]) -> Vec<String> {
    digests
        .iter()
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
        .take(MAX_LAUNCH_LINKS)
        .map(|digest| digest.to_ascii_lowercase())
        .collect()
}

fn plausible_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_CHARS
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

/// Drop every field that is not something this build would have written.
fn sanitize(mut state: ResumeState) -> ResumeState {
    state.window.bounds = state.window.bounds.filter(Bounds::is_sane);
    state.window.maximized_center = state.window.maximized_center.filter(Point::is_sane);
    state.ed2k = state.ed2k.filter(|server| {
        server.port != 0 && server.ip.parse::<std::net::IpAddr>().is_ok()
    });
    state.ui.route = state.ui.route.filter(|route| ROUTES.contains(&route.as_str()));
    state.ui.search_tabs = state
        .ui
        .search_tabs
        .filter(|tabs| !tabs.is_empty() && tabs.len() <= MAX_SEARCH_TABS_BYTES);
    state.launch_links = plausible_digests(&state.launch_links);
    state
}

/// Take the resume file at launch and stage each part for whoever applies it:
/// the network task's server, the frontend's page and tabs, and the window,
/// which `show_main_window` places.
pub fn begin_launch(app: &AppHandle, dir: &Path) -> Option<WindowSnapshot> {
    let running = app.package_info().version.to_string();
    let launch = take_from(dir, &running, chrono::Utc::now().timestamp());
    let service = app.state::<ResumeService>();
    if let Some(outcome) = &launch.outcome {
        tracing::info!(
            "Resuming after an update from {} to {} ({:?}): {}",
            outcome.from_version,
            outcome.target_version,
            outcome.reason,
            if outcome.installed { "installed" } else { "not installed" }
        );
    }
    *service.outcome.lock() = launch.outcome;
    service.replayed_links.lock().arm(launch.replayed_links, Instant::now());
    let state = launch.state?;
    *RESUME_SERVER.lock() = state.ed2k.map(|server| (server.ip, server.port));
    *service.launch_ui.lock() = Some(UiResume {
        route: state.ui.route,
        search_tabs: state.ui.search_tabs,
        reopen_chat_window: state.window.chat_window_open
            && state.window.visibility == Visibility::Normal,
    });
    Some(state.window)
}

/// Whether the top-left of `bounds`, where the title bar is grabbed, lands on
/// a monitor that is still attached. A window restored onto a monitor that was
/// unplugged since opens where nobody can see it.
fn title_bar_on_screen(bounds: &Bounds, monitors: &[(i64, i64, i64, i64)]) -> bool {
    let grab_x = i64::from(bounds.x) + i64::from(bounds.width.min(240)) / 2;
    let grab_y = i64::from(bounds.y) + 12;
    monitors.iter().any(|&(left, top, width, height)| {
        grab_x >= left && grab_x < left + width && grab_y >= top && grab_y < top + height
    })
}

/// The work area of the attached monitor that `point` lands on.
fn monitor_at(point: &Point, monitors: &[(i64, i64, i64, i64)]) -> Option<(i64, i64, i64, i64)> {
    let (x, y) = (i64::from(point.x), i64::from(point.y));
    monitors.iter().copied().find(|&(left, top, width, height)| {
        x >= left && x < left + width && y >= top && y < top + height
    })
}

/// The top-left that centres a `width` x `height` frame in `area`.
fn centred_in(area: (i64, i64, i64, i64), width: u32, height: u32) -> (i32, i32) {
    let (left, top, area_width, area_height) = area;
    let x = left + (area_width - i64::from(width)) / 2;
    let y = top + (area_height - i64::from(height)) / 2;
    (
        i32::try_from(x).unwrap_or(i32::MAX),
        i32::try_from(y).unwrap_or(i32::MAX),
    )
}

fn work_areas(app: &AppHandle) -> Vec<(i64, i64, i64, i64)> {
    app.available_monitors()
        .unwrap_or_default()
        .iter()
        .map(|monitor| {
            let area = monitor.work_area();
            (
                i64::from(area.position.x),
                i64::from(area.position.y),
                i64::from(area.size.width),
                i64::from(area.size.height),
            )
        })
        .collect()
}

/// Show the main window the way the session left it, or the ordinary way when
/// there is nothing to resume. Every launch comes through here: the window is
/// created hidden (`tauri.conf.json`) so that a session restored to the tray
/// never flashes onto the desktop first.
pub fn show_main_window(
    app: &AppHandle,
    snapshot: Option<&WindowSnapshot>,
    tray_available: bool,
    launch_maximized: bool,
) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let Some(snapshot) = snapshot else {
        if launch_maximized {
            let _ = window.maximize();
        }
        let _ = window.show();
        return;
    };

    if let Some(bounds) = snapshot.bounds {
        if title_bar_on_screen(&bounds, &work_areas(app)) {
            // Moved first: a move onto a monitor with another scale rescales
            // whatever size the window has by then.
            let _ = window.set_position(tauri::PhysicalPosition::new(bounds.x, bounds.y));
            let _ = window.set_size(tauri::PhysicalSize::new(bounds.width, bounds.height));
        }
    } else if let Some(center) = snapshot.maximized_center.filter(|_| snapshot.maximized) {
        // A window maximizes on the monitor it is on.
        let area = monitor_at(&center, &work_areas(app));
        if let (Some(area), Ok(size)) = (area, window.outer_size()) {
            let (x, y) = centred_in(area, size.width, size.height);
            let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
        }
    }

    match snapshot.visibility {
        // Without a tray icon a hidden window could never be reached again.
        Visibility::Tray if tray_available => {
            if snapshot.maximized {
                app.state::<ResumeService>()
                    .maximize_on_show
                    .store(true, Ordering::Release);
            }
        }
        Visibility::Minimized => {
            if snapshot.maximized {
                let _ = window.maximize();
            }
            let _ = window.show();
            let _ = window.minimize();
        }
        Visibility::Tray | Visibility::Normal => {
            if snapshot.maximized {
                let _ = window.maximize();
            }
            let _ = window.show();
        }
    }
}

/// The main window gained focus, which is how it being shown from the tray
/// reaches us: apply a maximize held back while it was hidden.
pub fn on_main_window_focused(window: &tauri::Window) {
    let Some(service) = window.app_handle().try_state::<ResumeService>() else {
        return;
    };
    if service.maximize_on_show.swap(false, Ordering::AcqRel) {
        let _ = window.maximize();
    }
}

// ── Capturing ───────────────────────────────────────────────────────────────

fn capture_window(app: &AppHandle) -> WindowSnapshot {
    let chat_window_open = app.get_webview_window(CHAT_WINDOW_LABEL).is_some();
    let Some(window) = app.get_webview_window("main") else {
        return WindowSnapshot {
            visibility: Visibility::Normal,
            maximized: false,
            bounds: None,
            maximized_center: None,
            chat_window_open,
        };
    };
    let visible = window.is_visible().unwrap_or(true);
    let minimized = window.is_minimized().unwrap_or(false);
    let zoomed = window.is_maximized().unwrap_or(false);
    // A session restored to the tray from a maximized window is maximized only
    // once it is shown, and is still maximized to the user until then.
    let maximized = zoomed
        || app
            .state::<ResumeService>()
            .maximize_on_show
            .load(Ordering::Acquire);
    let visibility = if !visible {
        Visibility::Tray
    } else if minimized {
        Visibility::Minimized
    } else {
        Visibility::Normal
    };
    let position = window.outer_position().ok();
    let bounds = if zoomed || minimized {
        None
    } else {
        match (position, window.inner_size()) {
            (Some(position), Ok(size)) => Some(Bounds {
                x: position.x,
                y: position.y,
                width: size.width,
                height: size.height,
            })
            .filter(Bounds::is_sane),
            _ => None,
        }
    };
    let maximized_center = match (zoomed && !minimized, position, window.outer_size()) {
        (true, Some(position), Ok(size)) => Some(Point {
            x: position.x.saturating_add_unsigned(size.width / 2),
            y: position.y.saturating_add_unsigned(size.height / 2),
        })
        .filter(Point::is_sane),
        _ => None,
    };
    WindowSnapshot {
        visibility,
        maximized,
        bounds,
        maximized_center,
        chat_window_open,
    }
}

async fn query_server_intent(app: &AppHandle) -> Option<ServerSnapshot> {
    let state = app.try_state::<AppState>()?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(crate::network::NetworkCommand::GetEd2kServerIntent { tx })
        .ok()?;
    let (ip, port) = tokio::time::timeout(SERVER_QUERY_TIMEOUT, rx)
        .await
        .ok()?
        .ok()??;
    Some(ServerSnapshot { ip, port })
}

async fn request_ui_snapshot(app: &AppHandle) -> UiSnapshot {
    let service = app.state::<ResumeService>();
    let id = service.next_request.fetch_add(1, Ordering::AcqRel) + 1;
    let (tx, rx) = tokio::sync::oneshot::channel();
    *service.pending_ui.lock() = Some((id, tx));
    if let Err(error) = app.emit_to("main", UI_SNAPSHOT_REQUEST_EVENT, serde_json::json!({ "id": id })) {
        tracing::debug!("Could not ask the main window for its session: {error}");
        service.pending_ui.lock().take();
        return UiSnapshot::default();
    }
    match tokio::time::timeout(UI_SNAPSHOT_TIMEOUT, rx).await {
        Ok(Ok(snapshot)) => snapshot,
        _ => {
            tracing::info!("The main window did not hand over its page and search tabs in time");
            service.pending_ui.lock().take();
            UiSnapshot::default()
        }
    }
}

/// Everything a restart for an update should come back to, taken now.
pub async fn capture(app: &AppHandle, reason: ResumeReason, target_version: &str) -> ResumeState {
    let window = capture_window(app);
    let (ed2k, ui) = tokio::join!(query_server_intent(app), request_ui_snapshot(app));
    ResumeState {
        schema: SCHEMA,
        written_at: chrono::Utc::now().timestamp(),
        reason,
        from_version: app.package_info().version.to_string(),
        target_version: target_version.to_string(),
        window,
        ed2k,
        ui,
        launch_links: launch_link_digests(
            &std::env::args_os()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        ),
    }
}

/// Capture the session and write it where the next launch will look.
/// Best-effort: an update is not refused because its session could not be saved.
pub async fn write_before_install(app: &AppHandle, reason: ResumeReason, target_version: &str) {
    let state = capture(app, reason, target_version).await;
    let dir = match crate::storage::paths::ensure_data_dir() {
        Ok(dir) => dir,
        Err(error) => {
            tracing::warn!("Not saving the session for the update restart: {error}");
            return;
        }
    };
    if let Err(error) = write_to(&dir, &state) {
        tracing::warn!("Not saving the session for the update restart: {error:#}");
    }
}

fn write_to(dir: &Path, state: &ResumeState) -> anyhow::Result<()> {
    let mut bytes = serde_json::to_vec(state)?;
    let tabs_too_big = state
        .ui
        .search_tabs
        .as_ref()
        .is_some_and(|tabs| tabs.len() > MAX_SEARCH_TABS_BYTES);
    if tabs_too_big || bytes.len() as u64 > MAX_FILE_BYTES {
        // The reader drops tabs past their cap and a file past its own unread,
        // window, server and page with it. The tabs are the part to lose.
        tracing::warn!("Leaving the search tabs out of {RESUME_FILE}: too large");
        let mut trimmed = state.clone();
        trimmed.ui.search_tabs = None;
        bytes = serde_json::to_vec(&trimmed)?;
    }
    crate::security::atomic_write(&dir.join(RESUME_FILE), &bytes, true)?;
    Ok(())
}

// ── Commands ────────────────────────────────────────────────────────────────

/// The main window's answer to [`UI_SNAPSHOT_REQUEST_EVENT`].
#[tauri::command]
pub fn submit_resume_ui_snapshot(
    service: tauri::State<'_, ResumeService>,
    id: u64,
    route: Option<String>,
    search_tabs: Option<String>,
) {
    let mut pending = service.pending_ui.lock();
    if pending.as_ref().is_some_and(|(want, _)| *want == id) {
        if let Some((_, tx)) = pending.take() {
            let _ = tx.send(UiSnapshot { route, search_tabs });
        }
    }
}

/// The page, search tabs and chat window a resumed launch should restore.
/// Handed over once; later calls get nothing.
#[tauri::command]
pub fn take_update_resume_ui(service: tauri::State<'_, ResumeService>) -> Option<UiResume> {
    service.launch_ui.lock().take()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "ember-resume-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> ResumeState {
        ResumeState {
            schema: SCHEMA,
            written_at: NOW,
            reason: ResumeReason::Silent,
            from_version: "1.7.1".to_string(),
            target_version: "1.8.0".to_string(),
            window: WindowSnapshot {
                visibility: Visibility::Tray,
                maximized: false,
                bounds: Some(Bounds { x: 120, y: 80, width: 1400, height: 900 }),
                maximized_center: None,
                chat_window_open: false,
            },
            ed2k: Some(ServerSnapshot { ip: "203.0.113.10".to_string(), port: 4661 }),
            ui: UiSnapshot {
                route: Some("/transfers".to_string()),
                search_tabs: Some("{\"tabs\":[],\"activeId\":null}".to_string()),
            },
            launch_links: Vec::new(),
        }
    }

    #[test]
    fn round_trips_once_and_reports_the_outcome() {
        let dir = scratch_dir("round-trip");
        write_to(&dir, &sample()).unwrap();

        let launch = take_from(&dir, "1.8.0", NOW + 90);
        assert_eq!(launch.state, Some(sample()));
        let outcome = launch.outcome.unwrap();
        assert!(outcome.installed);
        assert_eq!(outcome.from_version, "1.7.1");

        // Consumed: a second launch finds nothing.
        assert!(!dir.join(RESUME_FILE).exists());
        let again = take_from(&dir, "1.8.0", NOW + 120);
        assert!(again.outcome.is_none() && again.state.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_old_version_coming_back_is_an_update_that_did_not_install() {
        let dir = scratch_dir("not-installed");
        write_to(&dir, &sample()).unwrap();
        let launch = take_from(&dir, "1.7.1", NOW + 90);
        assert!(!launch.outcome.unwrap().installed);
        assert!(launch.state.is_some(), "the session is still restored");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_file_reports_its_outcome_but_restores_nothing() {
        let dir = scratch_dir("stale");
        write_to(&dir, &sample()).unwrap();
        let launch = take_from(&dir, "1.8.0", NOW + MAX_AGE_SECS + 1);
        assert!(launch.outcome.unwrap().installed);
        assert!(launch.state.is_none());
        assert!(!dir.join(RESUME_FILE).exists());

        write_to(&dir, &sample()).unwrap();
        let from_the_future = take_from(&dir, "1.8.0", NOW - MAX_FUTURE_SKEW_SECS - 1);
        assert!(from_the_future.state.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn values_this_build_would_never_write_are_dropped() {
        let dir = scratch_dir("sanitize");
        let mut state = sample();
        state.window.bounds = Some(Bounds { x: 0, y: 0, width: 10, height: 10 });
        state.window.maximized_center = Some(Point { x: 0, y: i32::MIN });
        state.ed2k = Some(ServerSnapshot { ip: "not-an-ip".to_string(), port: 4661 });
        state.ui.route = Some("https://example.com/".to_string());
        state.ui.search_tabs = Some(String::new());
        write_to(&dir, &state).unwrap();

        let restored = take_from(&dir, "1.8.0", NOW).state.unwrap();
        assert_eq!(restored.window.bounds, None);
        assert_eq!(restored.window.maximized_center, None);
        assert_eq!(restored.ed2k, None);
        assert_eq!(restored.ui.route, None);
        assert_eq!(restored.ui.search_tabs, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_and_unknown_schemas_are_discarded() {
        let dir = scratch_dir("garbage");
        std::fs::write(dir.join(RESUME_FILE), b"{not json").unwrap();
        assert!(take_from(&dir, "1.8.0", NOW).outcome.is_none());
        assert!(!dir.join(RESUME_FILE).exists());

        let mut future = sample();
        future.schema = SCHEMA + 1;
        write_to(&dir, &future).unwrap();
        assert!(take_from(&dir, "1.8.0", NOW).outcome.is_none());

        let mut odd = sample();
        odd.target_version = "1.8.0; rm -rf /".to_string();
        write_to(&dir, &odd).unwrap();
        assert!(take_from(&dir, "1.8.0", NOW).outcome.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Search tabs too big to restore are left out at write time, so the
    /// window, server and page still come back.
    #[test]
    fn oversized_search_tabs_cost_only_the_tabs() {
        let dir = scratch_dir("big-tabs");
        let mut state = sample();
        state.ui.search_tabs = Some(format!("\"{}\"", "\\\"".repeat(MAX_SEARCH_TABS_BYTES / 2)));
        write_to(&dir, &state).unwrap();
        let taken = take_from(&dir, &state.target_version, NOW);
        let restored = taken.state.expect("the rest of the session survives");
        assert_eq!(restored.ui.search_tabs, None);
        assert_eq!(restored.ui.route, state.ui.route);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_oversized_file_is_removed_unread() {
        let dir = scratch_dir("oversized");
        std::fs::write(dir.join(RESUME_FILE), vec![b' '; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(take_from(&dir, "1.8.0", NOW).outcome.is_none());
        assert!(!dir.join(RESUME_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An update restart is handed the old process's arguments again, so the
    /// link Ember was first opened with must not be offered a second time,
    /// while one clicked during the relaunch still is.
    #[test]
    fn links_the_relaunch_was_handed_back_are_not_offered_again() {
        let dir = scratch_dir("launch-links");
        let old = "ed2k://|file|a.iso|1024|0123456789ABCDEF0123456789ABCDEF|/";
        let args = vec!["ember.exe".to_string(), old.to_string()];
        let mut state = sample();
        state.launch_links = launch_link_digests(&args);
        assert_eq!(state.launch_links.len(), 1);
        write_to(&dir, &state).unwrap();

        // However long the relaunch took.
        let taken = take_from(&dir, "1.8.0", NOW + MAX_AGE_SECS + 1);
        assert!(taken.state.is_none());
        let now = Instant::now();
        let mut replayed = ReplayedLinks::default();
        replayed.arm(taken.replayed_links, now);

        let fresh = "ed2k://|file|b.iso|2048|FEDCBA9876543210FEDCBA9876543210|/";
        let clicked = crate::commands::deeplink::extract_deep_link_payloads(&[
            "ember.exe".to_string(),
            fresh.to_string(),
        ]);
        assert_eq!(clicked.len(), 1);
        assert_eq!(replayed.drop_from(clicked.clone(), now), clicked);

        let relaunch = crate::commands::deeplink::extract_deep_link_payloads(&args);
        assert!(replayed.drop_from(relaunch.clone(), now).is_empty());
        assert_eq!(
            replayed.drop_from(relaunch.clone(), now),
            relaunch,
            "the same link clicked again afterwards is a new one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The installer's relaunch can arrive after a launch with no links at all
    /// (the watchdog's, a shortcut), forwarded by the single-instance plugin.
    #[test]
    fn replayed_links_wait_for_the_relaunch_but_not_forever() {
        let old = "ed2k://|file|a.iso|1024|0123456789ABCDEF0123456789ABCDEF|/".to_string();
        let digests = launch_link_digests(&["ember.exe".to_string(), old.clone()]);
        let now = Instant::now();

        let mut replayed = ReplayedLinks::default();
        replayed.arm(digests.clone(), now);
        assert!(replayed.drop_from(Vec::new(), now).is_empty());
        let later = now + REPLAYED_LINKS_WINDOW - Duration::from_secs(1);
        assert!(replayed.drop_from(vec![old.clone()], later).is_empty());

        let mut replayed = ReplayedLinks::default();
        replayed.arm(digests, now);
        assert_eq!(
            replayed.drop_from(vec![old.clone()], now + REPLAYED_LINKS_WINDOW),
            vec![old]
        );
    }

    /// The NSIS installer relaunches with each argument's quotes stripped, so
    /// one holding spaces comes back as several.
    #[test]
    fn a_link_split_at_its_spaces_by_the_relaunch_is_not_offered_again() {
        fn split(args: &[String]) -> Vec<String> {
            args.iter().flat_map(|arg| arg.split(' ')).map(str::to_string).collect()
        }
        let collection = std::env::temp_dir()
            .join("John Smith")
            .join("Downloads")
            .join("set.emulecollection")
            .to_string_lossy()
            .into_owned();
        let link = "ed2k://|file|my file.iso|1024|0123456789ABCDEF0123456789ABCDEF|/".to_string();
        for arg in [collection, link] {
            let args = vec!["ember.exe".to_string(), arg];
            let now = Instant::now();
            let mut replayed = ReplayedLinks::default();
            replayed.arm(launch_link_digests(&args), now);
            let relaunch = crate::commands::deeplink::extract_deep_link_payloads(&split(&args));
            assert!(replayed.drop_from(relaunch, now).is_empty(), "{args:?}");
        }
    }

    #[test]
    fn launch_link_digests_this_build_would_not_write_are_dropped() {
        let dir = scratch_dir("launch-link-garbage");
        let good = link_digest("ed2k://|server|203.0.113.8|4661|/");
        let mut state = sample();
        state.launch_links = vec![
            good.clone(),
            "not-a-digest".to_string(),
            "g".repeat(64),
            good.to_ascii_uppercase(),
        ];
        write_to(&dir, &state).unwrap();
        let taken = take_from(&dir, "1.8.0", NOW);
        assert_eq!(taken.replayed_links, vec![good.clone(), good]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_window_is_only_restored_onto_a_monitor_that_is_still_there() {
        let bounds = Bounds { x: 120, y: 80, width: 1400, height: 900 };
        let primary = (0, 0, 1920, 1040);
        assert!(title_bar_on_screen(&bounds, &[primary]));
        assert!(!title_bar_on_screen(&bounds, &[]));
        let on_unplugged_right = Bounds { x: 2200, ..bounds };
        assert!(!title_bar_on_screen(&on_unplugged_right, &[primary]));
        assert!(title_bar_on_screen(&on_unplugged_right, &[primary, (1920, 0, 1920, 1080)]));
    }

    #[test]
    fn a_maximized_window_goes_back_to_its_monitor_before_maximizing() {
        let primary = (0, 0, 1920, 1040);
        let right = (1920, 0, 2560, 1400);
        // The maximized frame on the right monitor overhangs its edges.
        let center = Point { x: 1912 + 2576 / 2, y: -8 + 1416 / 2 };
        let area = monitor_at(&center, &[primary, right]).unwrap();
        assert_eq!(area, right);
        let (x, y) = centred_in(area, 1416, 939);
        assert_eq!((x, y), (1920 + (2560 - 1416) / 2, (1400 - 939) / 2));
        assert_eq!(monitor_at(&center, &[primary]), None, "unplugged since");
    }
}
