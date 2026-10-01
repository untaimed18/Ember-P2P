//! Silent updates: install a release while nobody is using Ember.
//!
//! Once an automatic check has found a release, it is downloaded, verified and
//! staged in the background. Ember then waits until nothing is moving — no
//! transfer sending or receiving, nothing hashing or verifying — and no one has
//! touched it for a while, warns for a minute with a way to cancel, and hands
//! over to the installer. The session comes back through `resume`.
//!
//! Everything that decides *when* lives here rather than in the webview: a
//! window hidden in the tray is throttled by the OS, and that is exactly the
//! case this feature is for. The frontend renders the state this publishes
//! ([`STATUS_EVENT`]) and sends the user's choices back.
//!
//! It never forces a restart while bytes are moving. A machine that is never
//! idle is told, after a week, that the update is waiting, and nothing more.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures::FutureExt;
use serde::Serialize;
use tauri::menu::MenuItem;
use tauri::{AppHandle, Emitter, Manager, Wry};

use super::record::{self, Attempt, LastSuccess, ReadySince, UpdateRecord};
use super::resume::{ResumeReason, ResumeService, UpdateOutcome};
use crate::app_state::AppState;
use crate::commands::updater::{self, UpdaterService};
use crate::types::TransferStatus;

/// Emitted with a [`SilentUpdateStatus`] whenever it changes.
pub const STATUS_EVENT: &str = "ember:silent-update";
/// Emitted when a countdown gives way to a transfer or local work, the one
/// reason for leaving it that the user is told about.
pub const BUSY_EVENT: &str = "ember:silent-update-busy";
/// Tray menu entry shown during the countdown.
pub const TRAY_CANCEL_ID: &str = "tray_cancel_update";

const TICK: Duration = Duration::from_secs(1);
/// How long every quiet condition must hold before the warning starts.
const QUIET_PERIOD: Duration = Duration::from_secs(10 * 60);
/// No input in any Ember window for this long is the user being away.
const USER_AWAY_SECS: i64 = 10 * 60;
/// A session younger than this is never interrupted, so an update never lands
/// right after someone opened Ember.
const SETTLE_PERIOD: Duration = Duration::from_secs(30 * 60);
const COUNTDOWN: Duration = Duration::from_secs(60);
const POSTPONE_SECS: i64 = 24 * 3600;
/// After this long waiting for a quiet moment, the user is told once.
const LONG_WAIT_SECS: i64 = 7 * 24 * 3600;
/// Combined throughput above this is traffic; below it is protocol chatter
/// (KAD, server pings, DHT upkeep) that never stops.
const BUSY_THROUGHPUT_BPS: u64 = 2 * 1024;
const PREPARE_RETRY: Duration = Duration::from_secs(3600);
/// How often activity is sampled while waiting. Every tick during a countdown.
const ACTIVITY_SAMPLE: Duration = Duration::from_secs(5);
const NETWORK_QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const RESTART_DELAY: Duration = Duration::from_secs(30);
/// A gap this long between one-second ticks means the machine slept (or the
/// clock jumped). Neither clock can be trusted across it: Windows' monotonic
/// clock keeps counting through sleep, so a countdown would end the instant the
/// lid opens, and Linux's stops, so one would sit frozen at 0:00.
const SUSPEND_GAP: Duration = Duration::from_secs(15);

/// Why this copy of Ember cannot update itself silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unsupported {
    /// A `.deb` (or `.rpm`): the package manager installs it behind a password
    /// prompt nobody is there to answer.
    Deb,
    /// A per-machine MSI install, which needs administrator approval.
    Msi,
    /// A development build, or a bundle this build cannot identify.
    Other,
}

/// Whether this install can update itself without anyone at the keyboard.
pub fn support() -> Result<(), Unsupported> {
    use tauri::utils::config::BundleType;
    if cfg!(debug_assertions) {
        return Err(Unsupported::Other);
    }
    match tauri::utils::platform::bundle_type() {
        Some(BundleType::Nsis) | Some(BundleType::AppImage) => Ok(()),
        Some(BundleType::Deb) | Some(BundleType::Rpm) => Err(Unsupported::Deb),
        Some(BundleType::Msi) => Err(Unsupported::Msi),
        _ => Err(Unsupported::Other),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Switched off, or not possible on this install.
    #[default]
    Off,
    /// No update known.
    Idle,
    /// Downloading and verifying the update in the background.
    Preparing,
    /// Ready; waiting for nothing to be moving and the user to be away.
    Waiting,
    /// The user said "Not now".
    Postponed,
    /// This version was skipped, or failed to install silently once.
    Held,
    /// The one-minute warning is running.
    Countdown,
    /// Handing over to the installer.
    Installing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LastSuccessStatus {
    pub from: String,
    pub to: String,
    /// Unix milliseconds.
    pub at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SilentUpdateStatus {
    pub supported: bool,
    pub unsupported_reason: Option<Unsupported>,
    pub enabled: bool,
    pub phase: Phase,
    pub version: Option<String>,
    /// Unix milliseconds.
    pub countdown_ends_at: Option<i64>,
    /// Unix milliseconds.
    pub postponed_until: Option<i64>,
    pub last_success: Option<LastSuccessStatus>,
    /// Ready for a week without a quiet moment: the ordinary notice should say
    /// the update is waiting.
    pub waiting_long: bool,
    /// The last attempt to download the update failed; it is retried hourly.
    /// The ordinary notice should offer it meanwhile.
    pub prepare_failed: bool,
}

// ── Shared state the commands and the tray reach ────────────────────────────

/// Unix seconds of the last keyboard or mouse input in any Ember window.
static LAST_INPUT: AtomicI64 = AtomicI64::new(0);
/// Seconds left on the countdown, for the tray tooltip; `u64::MAX` when none.
static COUNTDOWN_LEFT: AtomicU64 = AtomicU64::new(u64::MAX);
/// "Update now" from the countdown dialog.
static INSTALL_NOW: AtomicBool = AtomicBool::new(false);
/// A command changed the record; the driver should re-read it now.
static RECORD_DIRTY: AtomicBool = AtomicBool::new(true);
static LAST_STATUS: parking_lot::Mutex<Option<SilentUpdateStatus>> = parking_lot::Mutex::new(None);
/// The countdown's tray entry while it is shown. Only touched on the main
/// thread.
static TRAY_CANCEL: parking_lot::Mutex<Option<MenuItem<Wry>>> = parking_lot::Mutex::new(None);

/// Keyboard or mouse input in an Ember window, or one of them gaining focus.
pub fn note_user_activity_now() {
    LAST_INPUT.store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
}

/// Seconds left on a running countdown.
pub fn countdown_remaining_secs() -> Option<u64> {
    match COUNTDOWN_LEFT.load(Ordering::Relaxed) {
        u64::MAX => None,
        secs => Some(secs),
    }
}

/// `m:ss`, for the tray.
pub fn format_countdown(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

// ── Pure decisions ──────────────────────────────────────────────────────────

/// What was observed on one sample of the machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Activity {
    /// A download receiving, an upload sending, or a transfer verifying,
    /// completing or hashing.
    pub transfers_moving: bool,
    /// Ember Transfers sending, receiving or verifying.
    pub ember_transfers: usize,
    /// A shared-folder scan or hash pass running.
    pub local_work: bool,
    /// Combined smoothed throughput, bytes per second.
    pub throughput_bps: u64,
}

impl Activity {
    /// Would restarting now cut off bytes in flight or work that must finish?
    pub fn busy(&self) -> bool {
        self.transfers_moving
            || self.ember_transfers > 0
            || self.local_work
            || self.throughput_bps >= BUSY_THROUGHPUT_BPS
    }
}

/// Whether one transfer row is doing something a restart would cut off.
///
/// Deliberately narrower than the sleep inhibitor's count in `background.rs`,
/// which treats every non-stalled `Active` download as working — including one
/// only sitting in other peers' queues. The long-tail downloads this feature is
/// for sit like that for weeks, and they come back from a restart intact.
pub fn transfer_busy(status: &TransferStatus, speed: u64) -> bool {
    match status {
        TransferStatus::Verifying | TransferStatus::Completing | TransferStatus::Hashing => true,
        TransferStatus::Active => speed > 0,
        _ => false,
    }
}

/// Why the record keeps this version from installing silently right now.
fn held_by_record(record: &UpdateRecord, version: &str, now_unix: i64) -> Option<Phase> {
    // An attempt still on record outside an install is one whose launch could
    // not write down how it went: as good as failed.
    if record.skipped_version.as_deref() == Some(version)
        || record.failed_version.as_deref() == Some(version)
        || record.attempting.as_ref().is_some_and(|attempt| attempt.to == version)
    {
        return Some(Phase::Held);
    }
    if postponed_until(record, now_unix).is_some() {
        return Some(Phase::Postponed);
    }
    None
}

/// A "Not now" still in force, never further off than one postpone from now.
/// One beyond that was stamped before the clock stepped back, or by hand; it
/// still holds, and [`rebased_postpone`] stops it holding for longer.
fn postponed_until(record: &UpdateRecord, now_unix: i64) -> Option<i64> {
    record
        .postponed_until
        .filter(|until| *until > now_unix)
        .map(|until| until.min(now_unix.saturating_add(POSTPONE_SECS)))
}

/// What to store in place of a "Not now" further off than a click can reach,
/// so that it runs out one postpone after it was noticed rather than when wall
/// time catches up with it.
fn rebased_postpone(record: &UpdateRecord, now_unix: i64) -> Option<i64> {
    record
        .postponed_until
        .filter(|until| *until > now_unix.saturating_add(POSTPONE_SECS + 3600))
        .map(|_| now_unix.saturating_add(POSTPONE_SECS))
}

/// Whether a silent install that failed before anything was stopped failed
/// because of the update itself: the staged copy had vanished or changed
/// (antivirus, most likely, which will do it again), which `install_locked`
/// answers by dropping the copy. `pending` is the updater's state after the
/// failure.
fn staged_copy_failed(pending: Option<Option<(String, bool)>>, version: &str) -> bool {
    pending.is_some_and(|pending| {
        pending.is_some_and(|(pending, prepared)| pending == version && !prepared)
    })
}

/// Whether the user has been away from every Ember window long enough.
fn user_away(last_input_unix: i64, now_unix: i64) -> bool {
    now_unix.saturating_sub(last_input_unix) >= USER_AWAY_SECS
}

fn waiting_long(record: &UpdateRecord, version: &str, now_unix: i64) -> bool {
    record
        .ready_since
        .as_ref()
        .is_some_and(|ready| {
            ready.version == version && now_unix.saturating_sub(ready.at) >= LONG_WAIT_SECS
        })
}

// ── The driver ──────────────────────────────────────────────────────────────

#[derive(Default)]
struct Driver {
    phase: Phase,
    version: Option<String>,
    quiet_since: Option<Instant>,
    countdown_ends: Option<(Instant, i64)>,
    prepare_task: Option<tauri::async_runtime::JoinHandle<Result<Option<String>, String>>>,
    next_prepare_at: Option<Instant>,
    activity: Option<(Instant, Activity)>,
    record: UpdateRecord,
    record_read_at: Option<Instant>,
    /// The countdown's tray entry has been asked for.
    tray_cancel: bool,
    /// Not installed silently again this session: its install failed for a
    /// reason that says nothing about the release, or could not be recorded.
    held_for_session: Option<String>,
    clock: TickClock,
    prepare_failed: bool,
    /// The countdown ran out or "Update now" was pressed, and the install is
    /// waiting for the updater to be free.
    install_due: bool,
    /// A restart has been asked for; nothing is left to decide.
    restarting: bool,
}

/// Both clocks at the previous tick, to notice a sleep in between.
#[derive(Default)]
struct TickClock {
    last: Option<(Instant, i64)>,
}

impl TickClock {
    /// Whether more time passed since the last tick than a tick explains, by
    /// either clock, and remember this tick for the next.
    fn woke_from_gap(&mut self, now: Instant, now_ms: i64) -> bool {
        let gap = self.last.map(|(at, at_ms)| {
            let monotonic = now.saturating_duration_since(at);
            let wall = Duration::from_millis(now_ms.saturating_sub(at_ms).max(0) as u64);
            monotonic.max(wall)
        });
        self.last = Some((now, now_ms));
        gap.is_some_and(|gap| gap >= SUSPEND_GAP)
    }
}

/// Start the silent-update driver. Call once, after `AppState` is managed and
/// the tray exists.
pub fn spawn(app: AppHandle) {
    note_user_activity_now();
    tauri::async_runtime::spawn(async move {
        loop {
            let result = std::panic::AssertUnwindSafe(run(app.clone()))
                .catch_unwind()
                .await;
            if result.is_ok() {
                return;
            }
            tracing::error!("Silent-update driver panicked; restarting it");
            // Whatever countdown was running went with it; so does its tray
            // entry, which would otherwise stay and postpone on a click.
            COUNTDOWN_LEFT.store(u64::MAX, Ordering::Relaxed);
            on_main_thread(&app, hide_tray_cancel);
            tokio::time::sleep(RESTART_DELAY).await;
        }
    });
}

async fn run(app: AppHandle) {
    let started = Instant::now();
    let mut driver = Driver::default();
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        driver.tick(&app, started).await;
    }
}

impl Driver {
    async fn tick(&mut self, app: &AppHandle, started: Instant) {
        if self.restarting {
            return;
        }
        let Some(state) = app.try_state::<AppState>() else {
            return;
        };
        // Ember is closing: nothing may start an install now.
        if state.quit_confirmed.load(Ordering::Acquire) || state.bw_shutdown.load(Ordering::Acquire) {
            return;
        }
        self.refresh_tray_labels(app);
        let enabled = {
            let config = state.config.read().await;
            config.settings.silent_update_enabled && config.settings.auto_check_updates
        };
        let support = support();
        let now = Instant::now();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let now_unix = now_ms.div_euclid(1000);
        self.refresh_record(now_unix);

        if self.clock.woke_from_gap(now, now_ms) {
            // Someone opening the lid is someone at the machine: the quiet
            // period and the away time both start again, and a countdown the
            // sleep interrupted is not resumed.
            tracing::info!("Silent update: the machine slept; waiting for a fresh quiet period");
            self.leave_countdown(app);
            self.quiet_since = None;
            self.activity = None;
            note_user_activity_now();
        }

        if !enabled || support.is_err() {
            self.leave_countdown(app);
            self.stop_preparing();
            self.phase = Phase::Off;
            self.quiet_since = None;
            self.publish(app, enabled, support, now_unix);
            return;
        }

        self.reap_prepare(now);
        let service = app.state::<UpdaterService>();
        // Never waiting: the tick must keep running (and the countdown keep
        // counting) whatever the updater is doing.
        let pending = match updater::try_pending_update_state(&service) {
            Some(pending) => pending,
            None => {
                self.publish(app, enabled, support, now_unix);
                return;
            }
        };

        let Some((version, prepared)) = pending else {
            self.leave_countdown(app);
            self.phase = Phase::Idle;
            self.version = None;
            self.quiet_since = None;
            self.publish(app, enabled, support, now_unix);
            return;
        };
        if self.version.as_deref() != Some(version.as_str()) {
            self.leave_countdown(app);
            self.start_version(version.clone());
        }

        if let Some(held) = self.held(&self.record, &version, now_unix) {
            self.leave_countdown(app);
            self.phase = held;
            self.quiet_since = None;
            self.publish(app, enabled, support, now_unix);
            return;
        }

        if !prepared {
            self.leave_countdown(app);
            self.phase = Phase::Preparing;
            if self.prepare_task.is_none() && self.next_prepare_at.is_none_or(|at| now >= at) {
                let task_app = app.clone();
                self.prepare_task = Some(tauri::async_runtime::spawn(async move {
                    let service = task_app.state::<UpdaterService>();
                    updater::prepare_pending_update(&task_app, &service).await
                }));
            }
            self.publish(app, enabled, support, now_unix);
            return;
        }

        if self.record.ready_since.as_ref().is_none_or(|ready| ready.version != version) {
            let since = ReadySince { version: version.clone(), at: now_unix };
            let _ = record::update_stored(|record| record.ready_since = Some(since.clone()));
            self.record.ready_since = Some(since);
        }

        let in_countdown = self.countdown_ends.is_some();
        let activity = self.sample_activity(&state, now, in_countdown).await;

        if let Some((ends, _)) = self.countdown_ends {
            if INSTALL_NOW.swap(false, Ordering::AcqRel) || now >= ends {
                self.install_due = true;
            }
            if self.install_due && !activity.busy() {
                if self.install(app, &state, &version, enabled, support, now_unix).await {
                    return;
                }
                // A check or a manual install holds the updater. The warning
                // stays up, so an answer given meanwhile still counts, and the
                // next tick tries again.
            }
            // Input does not abort the countdown: the dialog is how a user who
            // is here answers it, and clicking it is input. A transfer that
            // starts moving does.
            if activity.busy() {
                self.abort_countdown_busy(app);
            } else {
                self.update_countdown_tray(app, ends.saturating_duration_since(now).as_secs());
                self.phase = Phase::Countdown;
            }
            self.publish(app, enabled, support, now_unix);
            return;
        }
        INSTALL_NOW.store(false, Ordering::Release);

        // Three conditions, each measured on its own clock: nothing has moved
        // for the quiet period, nobody has touched Ember for the away time, and
        // the session is old enough. Chaining the first two made the effective
        // wait their sum.
        if activity.busy() {
            self.quiet_since = None;
        } else {
            let since = *self.quiet_since.get_or_insert(now);
            if now.duration_since(since) >= QUIET_PERIOD
                && user_away(LAST_INPUT.load(Ordering::Relaxed), now_unix)
                && started.elapsed() >= SETTLE_PERIOD
            {
                self.enter_countdown(app, now, now_ms);
                self.publish(app, enabled, support, now_unix);
                return;
            }
        }
        self.phase = Phase::Waiting;
        self.publish(app, enabled, support, now_unix);
    }

    fn refresh_record(&mut self, now_unix: i64) {
        let stale = self
            .record_read_at
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(30));
        if !RECORD_DIRTY.swap(false, Ordering::AcqRel) && !stale {
            return;
        }
        self.record_read_at = Some(Instant::now());
        // Kept as it was when the file cannot be read right now, rather than
        // replaced by one without its skip or postpone.
        match record::read_stored() {
            Ok(record) => self.record = record,
            Err(error) => tracing::debug!("Silent update: keeping the last record read: {error}"),
        }
        if let Some(until) = rebased_postpone(&self.record, now_unix) {
            let stamped = self.record.postponed_until;
            let _ = record::update_stored(|record| {
                if record.postponed_until == stamped {
                    record.postponed_until = Some(until);
                }
            });
            self.record.postponed_until = Some(until);
        }
    }

    /// Why this version is not to install silently right now.
    fn held(&self, record: &UpdateRecord, version: &str, now_unix: i64) -> Option<Phase> {
        if self.held_for_session.as_deref() == Some(version) {
            return Some(Phase::Held);
        }
        held_by_record(record, version, now_unix)
    }

    /// A different release is pending: nothing learned about the last one
    /// applies to it, including a download of it that failed.
    fn start_version(&mut self, version: String) {
        self.quiet_since = None;
        self.next_prepare_at = None;
        self.prepare_failed = false;
        self.version = Some(version);
    }

    /// Silent updates went off: no background download goes on without them.
    fn stop_preparing(&mut self) {
        if let Some(task) = self.prepare_task.take() {
            tracing::info!("Silent update: switched off; stopping the background download");
            task.abort();
        }
        self.next_prepare_at = None;
        self.prepare_failed = false;
    }

    fn reap_prepare(&mut self, now: Instant) {
        let Some(task) = self.prepare_task.as_mut() else {
            return;
        };
        let Some(result) = task.now_or_never() else {
            return;
        };
        self.prepare_task = None;
        match result {
            Ok(Ok(Some(version))) => {
                tracing::info!("Silent update: {version} is downloaded, verified and staged");
                self.next_prepare_at = None;
                self.prepare_failed = false;
            }
            Ok(Ok(None)) => {
                self.next_prepare_at = None;
                self.prepare_failed = false;
            }
            Ok(Err(error)) => {
                tracing::warn!("Silent update could not prepare the update: {error}");
                self.next_prepare_at = Some(now + PREPARE_RETRY);
                self.prepare_failed = true;
            }
            Err(error) => {
                tracing::warn!("Silent update preparation task failed: {error}");
                self.next_prepare_at = Some(now + PREPARE_RETRY);
                self.prepare_failed = true;
            }
        }
    }

    async fn sample_activity(&mut self, state: &AppState, now: Instant, every_tick: bool) -> Activity {
        if let Some((at, activity)) = self.activity {
            if !every_tick && now.duration_since(at) < ACTIVITY_SAMPLE {
                return activity;
            }
        }
        let activity = observe_activity(state).await;
        self.activity = Some((now, activity));
        activity
    }

    fn enter_countdown(&mut self, app: &AppHandle, now: Instant, now_ms: i64) {
        let ends = now + COUNTDOWN;
        let ends_ms = now_ms.saturating_add(COUNTDOWN.as_millis() as i64);
        self.countdown_ends = Some((ends, ends_ms));
        self.install_due = false;
        self.phase = Phase::Countdown;
        tracing::info!(
            "Silent update: nothing has moved for {} minutes and nobody is at Ember; warning before installing {}",
            QUIET_PERIOD.as_secs() / 60,
            self.version.as_deref().unwrap_or("?")
        );
        let label = cancel_label(COUNTDOWN.as_secs());
        on_main_thread(app, move |app| show_tray_cancel(app, &label));
        self.tray_cancel = true;
        COUNTDOWN_LEFT.store(COUNTDOWN.as_secs(), Ordering::Relaxed);
    }

    fn update_countdown_tray(&self, app: &AppHandle, secs: u64) {
        COUNTDOWN_LEFT.store(secs, Ordering::Relaxed);
        if self.tray_cancel {
            let label = cancel_label(secs);
            on_main_thread(app, move |_| {
                let item = TRAY_CANCEL.lock().clone();
                if let Some(item) = item {
                    let _ = item.set_text(label);
                }
            });
        }
    }

    /// Build the tray menu again once the frontend has sent the labels in its
    /// language, keeping the countdown's entry if one is running.
    fn refresh_tray_labels(&self, app: &AppHandle) {
        if !crate::tray::take_changed() {
            return;
        }
        let label = cancel_label(countdown_remaining_secs().unwrap_or(0));
        on_main_thread(app, move |app| {
            let item = TRAY_CANCEL.lock().clone();
            let Some(item) = item else {
                restore_tray_menu(app);
                return;
            };
            let _ = item.set_text(label);
            if let Some(tray) = app.tray_by_id("main") {
                match crate::build_tray_menu(app, Some(&item)) {
                    Ok(menu) => {
                        let _ = tray.set_menu(Some(menu));
                    }
                    Err(error) => tracing::warn!("Could not rebuild the tray menu: {error}"),
                }
            }
        });
    }

    fn leave_countdown(&mut self, app: &AppHandle) {
        self.install_due = false;
        if self.countdown_ends.take().is_none() {
            return;
        }
        COUNTDOWN_LEFT.store(u64::MAX, Ordering::Relaxed);
        if std::mem::take(&mut self.tray_cancel) {
            on_main_thread(app, hide_tray_cancel);
        }
    }

    /// A transfer or local work started during the countdown: back to waiting
    /// for a quiet moment, without counting as a postpone.
    fn abort_countdown_busy(&mut self, app: &AppHandle) {
        tracing::info!("Silent update countdown aborted: Ember is busy again");
        self.leave_countdown(app);
        self.quiet_since = None;
        self.phase = Phase::Waiting;
        if let Err(error) = app.emit(BUSY_EVENT, ()) {
            tracing::debug!("Could not emit the silent-update busy event: {error}");
        }
    }

    /// Install now, unless the countdown's answer changed first. Returns false,
    /// leaving everything as it was, when it cannot tell yet: mostly a check
    /// or a manual install holding the updater. Waiting for it here would
    /// leave nothing on screen to say "Not now" with, and a manual install
    /// that got there first must not be reported next launch as one that
    /// happened while the user was away.
    async fn install(
        &mut self,
        app: &AppHandle,
        state: &AppState,
        version: &str,
        enabled: bool,
        support: Result<(), Unsupported>,
        now_unix: i64,
    ) -> bool {
        let service = app.state::<UpdaterService>();
        let Some(operation) = updater::try_lock_operation(&service) else {
            return false;
        };
        // A check that finished since this tick looked may have swapped in a
        // re-published copy of this version, still to be downloaded. The next
        // tick plans around whatever is pending now.
        if updater::try_pending_update_state(&service) != Some(Some((version.to_string(), true))) {
            return false;
        }
        // Straight from disk, and from the machine, now that nothing else can
        // start an install: a "Not now", a skip or a transfer that arrived
        // since this tick began must win over the clock.
        let fresh = match record::read_stored() {
            Ok(fresh) => fresh,
            Err(error) => {
                tracing::warn!("Silent update of {version} waits: its record cannot be read ({error})");
                return false;
            }
        };
        if let Some(held) = self.held(&fresh, version, now_unix) {
            self.record = fresh;
            self.leave_countdown(app);
            self.phase = held;
            self.publish(app, enabled, support, now_unix);
            return true;
        }
        let activity = observe_activity(state).await;
        if activity.busy() {
            self.activity = Some((Instant::now(), activity));
            self.abort_countdown_busy(app);
            self.publish(app, enabled, support, now_unix);
            return true;
        }

        self.leave_countdown(app);
        self.phase = Phase::Installing;
        self.publish(app, enabled, support, now_unix);
        tracing::info!("Silent update: installing {version}");

        // Before the hand-off, in the one file this module owns: how the next
        // launch knows this install was tried, even with no resume file.
        // Without it a failed install looks like none at all and is tried
        // again, so on a full disk every half hour of idle would end in a
        // restart that stops every transfer.
        let attempt = Attempt {
            from: app.package_info().version.to_string(),
            to: version.to_string(),
            at: now_unix,
        };
        if let Err(error) = record::update_stored(|record| record.attempting = Some(attempt)) {
            tracing::warn!("Silent update of {version} not started: the attempt could not be recorded ({error})");
            let _ = record::update_stored(|record| record.attempting = None);
            self.hold_after_failure(app, version, enabled, support, now_unix);
            return true;
        }

        match updater::install_prepared_update(app, &service, operation, ResumeReason::Silent).await {
            // In-process installs (the AppImage) land here; Windows exits inside.
            Ok(()) => {
                tracing::info!("Silent update installed {version}; restarting into it");
                self.restart(app);
            }
            Err(error) if error.contains("updater_install_failed_services_stopped") => {
                // The network is already down for the install, so staying up
                // helps nobody. Come back on this version, with the session the
                // resume file holds, and never try this version silently again.
                tracing::warn!("Silent update of {version} failed after shutdown: {error}");
                let failed = version.to_string();
                let _ = record::update_stored(|record| record.failed_version = Some(failed));
                self.restart(app);
            }
            Err(error) => {
                // Failed before anything was stopped, so nothing restarts. Only
                // a staged copy that failed marks the version for good; a floor
                // file that could not be read, or the update superseded, holds
                // it for this session. Either way it is not tried again now, or
                // every quiet spell would count down anew.
                tracing::warn!("Silent update of {version} did not start: {error}");
                let lasting = staged_copy_failed(updater::try_pending_update_state(&service), version);
                let failed = version.to_string();
                let _ = record::update_stored(|record| {
                    record.attempting = None;
                    if lasting {
                        record.failed_version = Some(failed);
                    }
                });
                self.hold_after_failure(app, version, enabled, support, now_unix);
            }
        }
        true
    }

    /// Stop trying `version` silently for this session after an install that
    /// did not start. Not left to the record alone, which may not have taken it.
    fn hold_after_failure(
        &mut self,
        app: &AppHandle,
        version: &str,
        enabled: bool,
        support: Result<(), Unsupported>,
        now_unix: i64,
    ) {
        self.held_for_session = Some(version.to_string());
        RECORD_DIRTY.store(true, Ordering::Release);
        self.phase = Phase::Held;
        self.quiet_since = None;
        self.publish(app, enabled, support, now_unix);
    }

    /// Ask the event loop to exit and start Ember again, and stop deciding
    /// anything meanwhile. `AppHandle::restart` from this task would park a
    /// runtime worker forever while the shutdown still needs it.
    fn restart(&mut self, app: &AppHandle) {
        self.restarting = true;
        if let Some(state) = app.try_state::<AppState>() {
            state.quit_confirmed.store(true, Ordering::Release);
        }
        app.request_restart();
    }

    fn publish(
        &self,
        app: &AppHandle,
        enabled: bool,
        support: Result<(), Unsupported>,
        now_unix: i64,
    ) {
        let version = self.version.clone();
        let status = SilentUpdateStatus {
            supported: support.is_ok(),
            unsupported_reason: support.err(),
            enabled,
            phase: self.phase,
            waiting_long: version
                .as_deref()
                .is_some_and(|v| waiting_long(&self.record, v, now_unix)),
            version: if self.phase == Phase::Off || self.phase == Phase::Idle {
                None
            } else {
                version
            },
            countdown_ends_at: self.countdown_ends.map(|(_, ms)| ms),
            postponed_until: postponed_until(&self.record, now_unix)
                .map(|until| until.saturating_mul(1000)),
            last_success: self.record.last_success.as_ref().map(|last| LastSuccessStatus {
                from: last.from.clone(),
                to: last.to.clone(),
                at: last.at.saturating_mul(1000),
            }),
            prepare_failed: self.phase == Phase::Preparing && self.prepare_failed,
        };
        let mut last = LAST_STATUS.lock();
        if last.as_ref() != Some(&status) {
            if let Err(error) = app.emit(STATUS_EVENT, &status) {
                tracing::debug!("Could not emit the silent-update status: {error}");
            }
            *last = Some(status);
        }
    }
}

fn cancel_label(secs: u64) -> String {
    crate::tray::labels().cancel_update_with(&format_countdown(secs))
}

/// Run `change` on the main thread without waiting for it. Every tray and menu
/// call blocks its caller until the main thread has run it, and while Ember
/// exits the main thread is running the shutdown, which needs the runtime
/// worker such a call would park.
fn on_main_thread(app: &AppHandle, change: impl FnOnce(&AppHandle) + Send + 'static) {
    let handle = app.clone();
    if let Err(error) = app.run_on_main_thread(move || change(&handle)) {
        tracing::debug!("Could not reach the main thread to update the tray: {error}");
    }
}

/// Put the countdown's "Cancel update" entry above the tray's others. Main
/// thread only.
fn show_tray_cancel(app: &AppHandle, label: &str) {
    let item = match MenuItem::with_id(app, TRAY_CANCEL_ID, label, true, None::<&str>) {
        Ok(item) => item,
        Err(error) => {
            tracing::warn!("Could not create the tray's cancel entry: {error}");
            return;
        }
    };
    let Some(tray) = app.tray_by_id("main") else {
        return;
    };
    match crate::build_tray_menu(app, Some(&item)) {
        Ok(menu) => {
            let _ = tray.set_menu(Some(menu));
            *TRAY_CANCEL.lock() = Some(item);
        }
        Err(error) => tracing::warn!("Could not add the tray's cancel entry: {error}"),
    }
}

/// Take the countdown's entry off the tray menu. Main thread only.
fn hide_tray_cancel(app: &AppHandle) {
    TRAY_CANCEL.lock().take();
    restore_tray_menu(app);
}

/// Put the tray back to its ordinary menu, without a "Cancel update" entry.
/// Main thread only.
fn restore_tray_menu(app: &AppHandle) {
    if let Some(tray) = app.tray_by_id("main") {
        if let Ok(menu) = crate::build_tray_menu(app, None) {
            let _ = tray.set_menu(Some(menu));
        }
    }
}

async fn observe_activity(state: &AppState) -> Activity {
    let transfers_moving = {
        let manager = state.transfer_manager.read().await;
        manager
            .active
            .values()
            .any(|transfer| transfer_busy(&transfer.status, transfer.speed))
    };
    let local_work = state.scanning_count.load(Ordering::Relaxed) > 0
        || !state.hash_cancel_flags.read().await.is_empty()
        || crate::commands::sharing::hash_top_up_running();
    let throughput_bps = state
        .bandwidth_limiter
        .smoothed_download_speed()
        .saturating_add(state.bandwidth_limiter.smoothed_upload_speed());
    // A network task that does not answer is treated as busy: guessing idle is
    // the direction that interrupts someone.
    let ember_transfers = query_ember_transfers(state).await.unwrap_or(1);
    Activity {
        transfers_moving,
        ember_transfers,
        local_work,
        throughput_bps,
    }
}

async fn query_ember_transfers(state: &AppState) -> Option<usize> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(crate::network::NetworkCommand::GetEmberTransferActivity { tx })
        .ok()?;
    tokio::time::timeout(NETWORK_QUERY_TIMEOUT, rx).await.ok()?.ok()
}

// ── Launch ──────────────────────────────────────────────────────────────────

/// Record how the silent update this launch resumed from turned out: a success
/// for Settings → About, a failure so that version is never tried silently
/// again. Call once, after `resume::begin_launch`.
pub fn note_launch_outcome(app: &AppHandle) {
    let service = app.state::<ResumeService>();
    let resumed = service
        .outcome()
        .filter(|outcome| outcome.reason == ResumeReason::Silent);
    let attempt = record::load_stored().attempting;
    // The resume file says how the update went when it could be written; the
    // attempt recorded before the hand-off covers it when it could not.
    let outcome = match (resumed, attempt) {
        (Some(outcome), _) => outcome,
        (None, Some(attempt)) => {
            let outcome = outcome_of_attempt(&attempt, &app.package_info().version.to_string());
            service.set_outcome(outcome.clone());
            outcome
        }
        (None, None) => return,
    };
    let now_unix = chrono::Utc::now().timestamp();
    // Should this not land, the attempt stays on record, which holds the
    // version all the same.
    let _ = record::update_stored(|record| {
        record.attempting = None;
        if outcome.installed {
            record.last_success = Some(LastSuccess {
                from: outcome.from_version.clone(),
                to: outcome.target_version.clone(),
                at: now_unix,
            });
            record.ready_since = None;
            record.postponed_until = None;
            if record.failed_version.as_deref() == Some(outcome.target_version.as_str()) {
                record.failed_version = None;
            }
        } else {
            record.failed_version = Some(outcome.target_version.clone());
        }
    });
    RECORD_DIRTY.store(true, Ordering::Release);
}

/// How an install attempt turned out, judged by the version now running.
fn outcome_of_attempt(attempt: &Attempt, running: &str) -> UpdateOutcome {
    UpdateOutcome {
        reason: ResumeReason::Silent,
        from_version: attempt.from.clone(),
        target_version: attempt.to.clone(),
        installed: attempt.to == running,
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

/// The current silent-update state, as last published.
#[tauri::command]
pub fn get_silent_update_status() -> SilentUpdateStatus {
    if let Some(status) = LAST_STATUS.lock().clone() {
        return status;
    }
    let support = support();
    SilentUpdateStatus {
        supported: support.is_ok(),
        unsupported_reason: support.err(),
        enabled: false,
        phase: Phase::Off,
        version: None,
        countdown_ends_at: None,
        postponed_until: None,
        last_success: None,
        waiting_long: false,
        prepare_failed: false,
    }
}

/// "Update now" on the countdown.
#[tauri::command]
pub fn silent_update_now() {
    INSTALL_NOW.store(true, Ordering::Release);
}

/// "Not now": no silent install for the next 24 hours.
#[tauri::command]
pub fn silent_update_postpone() {
    postpone();
}

/// The tray's cancel entry does the same as "Not now".
pub fn postpone() {
    let until = chrono::Utc::now().timestamp() + POSTPONE_SECS;
    let _ = record::update_stored(|record| record.postponed_until = Some(until));
    INSTALL_NOW.store(false, Ordering::Release);
    RECORD_DIRTY.store(true, Ordering::Release);
}

/// "Skip this version": never install it silently. The ordinary notice still
/// offers it, and the next release is handled normally.
#[tauri::command]
pub fn silent_update_skip(version: String) {
    let version: String = version.chars().take(64).collect();
    let _ = record::update_stored(|record| record.skipped_version = Some(version));
    INSTALL_NOW.store(false, Ordering::Release);
    RECORD_DIRTY.store(true, Ordering::Release);
}

/// Lift a "Not now" early, from Settings → About.
#[tauri::command]
pub fn silent_update_resume() {
    let _ = record::update_stored(|record| record.postponed_until = None);
    RECORD_DIRTY.store(true, Ordering::Release);
}

/// Keyboard or mouse input in a webview. The frontend throttles these.
#[tauri::command]
pub fn note_user_activity() {
    note_user_activity_now();
}

/// How the silent update this launch resumed from turned out, once, so the
/// frontend can say so. Manual installs are not reported: the user was there.
#[tauri::command]
pub fn take_update_outcome(service: tauri::State<'_, ResumeService>) -> Option<UpdateOutcome> {
    service
        .take_outcome()
        .filter(|outcome| outcome.reason == ResumeReason::Silent)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000;

    #[test]
    fn a_download_waiting_in_remote_queues_is_idle() {
        assert!(!transfer_busy(&TransferStatus::Active, 0));
        assert!(!transfer_busy(&TransferStatus::Queued, 0));
        assert!(!transfer_busy(&TransferStatus::Searching, 0));
        assert!(!transfer_busy(&TransferStatus::Paused, 0));
    }

    #[test]
    fn bytes_moving_or_local_work_is_busy() {
        assert!(transfer_busy(&TransferStatus::Active, 1));
        assert!(transfer_busy(&TransferStatus::Hashing, 0));
        assert!(transfer_busy(&TransferStatus::Verifying, 0));
        assert!(transfer_busy(&TransferStatus::Completing, 0));

        let idle = Activity::default();
        assert!(!idle.busy());
        assert!(Activity { transfers_moving: true, ..idle }.busy());
        assert!(Activity { ember_transfers: 1, ..idle }.busy());
        assert!(Activity { local_work: true, ..idle }.busy());
        assert!(Activity { throughput_bps: BUSY_THROUGHPUT_BPS, ..idle }.busy());
        assert!(
            !Activity { throughput_bps: BUSY_THROUGHPUT_BPS - 1, ..idle }.busy(),
            "protocol chatter is not traffic"
        );
    }

    #[test]
    fn away_means_no_input_for_ten_minutes() {
        assert!(!user_away(NOW - 60, NOW));
        assert!(!user_away(NOW - USER_AWAY_SECS + 1, NOW));
        assert!(user_away(NOW - USER_AWAY_SECS, NOW));
    }

    #[test]
    fn skipped_failed_and_postponed_versions_are_held() {
        let mut record = UpdateRecord::default();
        assert_eq!(held_by_record(&record, "1.8.0", NOW), None);

        record.skipped_version = Some("1.8.0".to_string());
        assert_eq!(held_by_record(&record, "1.8.0", NOW), Some(Phase::Held));
        assert_eq!(held_by_record(&record, "1.8.1", NOW), None, "the next release is handled normally");

        let failed = UpdateRecord { failed_version: Some("1.8.0".to_string()), ..Default::default() };
        assert_eq!(held_by_record(&failed, "1.8.0", NOW), Some(Phase::Held));

        let postponed = UpdateRecord { postponed_until: Some(NOW + 60), ..Default::default() };
        assert_eq!(held_by_record(&postponed, "1.8.0", NOW), Some(Phase::Postponed));
        assert_eq!(held_by_record(&postponed, "1.8.0", NOW + 61), None, "a postpone runs out");

        let attempted = UpdateRecord {
            attempting: Some(Attempt { from: "1.7.1".to_string(), to: "1.8.0".to_string(), at: NOW }),
            ..Default::default()
        };
        assert_eq!(
            held_by_record(&attempted, "1.8.0", NOW),
            Some(Phase::Held),
            "an attempt whose launch could not record how it went"
        );
        assert_eq!(held_by_record(&attempted, "1.8.1", NOW), None);
    }

    /// A "Not now" made before the clock stepped back reaches further than a
    /// click can. It still holds, for one postpone from when it is noticed.
    #[test]
    fn a_postpone_beyond_reach_holds_for_one_postpone_from_now() {
        let behind = UpdateRecord { postponed_until: Some(NOW + POSTPONE_SECS + 2 * 3600), ..Default::default() };
        assert_eq!(held_by_record(&behind, "1.8.0", NOW), Some(Phase::Postponed));
        assert_eq!(postponed_until(&behind, NOW), Some(NOW + POSTPONE_SECS));
        assert_eq!(rebased_postpone(&behind, NOW), Some(NOW + POSTPONE_SECS));

        let ahead = UpdateRecord { postponed_until: Some(NOW + 30 * 24 * 3600), ..Default::default() };
        assert_eq!(rebased_postpone(&ahead, NOW), Some(NOW + POSTPONE_SECS));

        let clicked = UpdateRecord { postponed_until: Some(NOW + POSTPONE_SECS), ..Default::default() };
        assert_eq!(rebased_postpone(&clicked, NOW), None, "an ordinary Not now is left alone");
        assert_eq!(postponed_until(&clicked, NOW), Some(NOW + POSTPONE_SECS));
    }

    #[test]
    fn only_a_staged_copy_that_failed_is_the_update_failing() {
        let staged = |prepared| Some(Some(("1.8.0".to_string(), prepared)));
        assert!(staged_copy_failed(staged(false), "1.8.0"), "install_locked dropped the copy");
        assert!(!staged_copy_failed(staged(true), "1.8.0"), "the floor could not be read");
        assert!(!staged_copy_failed(Some(None), "1.8.0"), "superseded and dropped");
        assert!(!staged_copy_failed(None, "1.8.0"), "the updater was busy");
        assert!(!staged_copy_failed(Some(Some(("1.8.1".to_string(), false))), "1.8.0"));
    }

    #[test]
    fn a_new_release_does_not_inherit_the_last_ones_download_failure() {
        let mut driver = Driver {
            version: Some("1.8.0".to_string()),
            prepare_failed: true,
            next_prepare_at: Some(Instant::now() + PREPARE_RETRY),
            quiet_since: Some(Instant::now()),
            ..Default::default()
        };
        driver.start_version("1.8.1".to_string());
        assert_eq!(driver.version.as_deref(), Some("1.8.1"));
        assert!(!driver.prepare_failed);
        assert!(driver.next_prepare_at.is_none(), "downloaded at once, not an hour later");
        assert!(driver.quiet_since.is_none());
    }

    #[test]
    fn a_version_held_for_the_session_stays_held_whatever_the_record_says() {
        let driver = Driver { held_for_session: Some("1.8.0".to_string()), ..Default::default() };
        let record = UpdateRecord::default();
        assert_eq!(driver.held(&record, "1.8.0", NOW), Some(Phase::Held));
        assert_eq!(driver.held(&record, "1.8.1", NOW), None, "the next release is handled normally");
    }

    #[test]
    fn a_week_without_a_quiet_moment_is_a_long_wait() {
        let record = UpdateRecord {
            ready_since: Some(ReadySince { version: "1.8.0".to_string(), at: NOW }),
            ..Default::default()
        };
        assert!(!waiting_long(&record, "1.8.0", NOW + LONG_WAIT_SECS - 1));
        assert!(waiting_long(&record, "1.8.0", NOW + LONG_WAIT_SECS));
        assert!(!waiting_long(&record, "1.8.1", NOW + LONG_WAIT_SECS), "a new release starts over");
    }

    #[test]
    fn a_gap_on_either_clock_is_a_sleep() {
        let mut clock = TickClock::default();
        let start = Instant::now();
        let ms = NOW * 1000;
        assert!(!clock.woke_from_gap(start, ms), "the first tick has nothing to compare");
        assert!(!clock.woke_from_gap(start + TICK, ms + 1000), "an ordinary tick");

        // Windows: the monotonic clock ran on through the sleep.
        let later = start + TICK + SUSPEND_GAP;
        assert!(clock.woke_from_gap(later, ms + 1000 + SUSPEND_GAP.as_millis() as i64));

        // Linux: it stopped, and only the wall clock moved.
        let next = later + TICK;
        assert!(clock.woke_from_gap(next, ms + 10 * 60 * 1000));
        assert!(!clock.woke_from_gap(next + TICK, ms + 10 * 60 * 1000 + 1000));
    }

    #[test]
    fn an_attempt_is_judged_by_the_version_that_came_back() {
        let attempt = Attempt { from: "1.7.1".to_string(), to: "1.8.0".to_string(), at: NOW };
        let landed = outcome_of_attempt(&attempt, "1.8.0");
        assert!(landed.installed);
        assert_eq!(landed.reason, ResumeReason::Silent);
        assert!(!outcome_of_attempt(&attempt, "1.7.1").installed);
    }

    #[test]
    fn the_countdown_reads_as_minutes_and_seconds() {
        assert_eq!(format_countdown(60), "1:00");
        assert_eq!(format_countdown(45), "0:45");
        assert_eq!(format_countdown(5), "0:05");
    }
}
