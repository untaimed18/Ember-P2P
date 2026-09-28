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

use super::record::{self, LastSuccess, ReadySince, UpdateRecord};
use super::resume::{ResumeReason, ResumeService, UpdateOutcome};
use crate::app_state::AppState;
use crate::commands::updater::{self, UpdaterService};
use crate::types::TransferStatus;

/// Emitted with a [`SilentUpdateStatus`] whenever it changes.
pub const STATUS_EVENT: &str = "ember:silent-update";
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
    if record.skipped_version.as_deref() == Some(version)
        || record.failed_version.as_deref() == Some(version)
    {
        return Some(Phase::Held);
    }
    if record.postponed_until.is_some_and(|until| until > now_unix) {
        return Some(Phase::Postponed);
    }
    None
}

/// Whether the user has been away from every Ember window long enough.
fn user_away(last_input_unix: i64, now_unix: i64) -> bool {
    now_unix.saturating_sub(last_input_unix) >= USER_AWAY_SECS
}

fn waiting_long(record: &UpdateRecord, version: &str, now_unix: i64) -> bool {
    record
        .ready_since
        .as_ref()
        .is_some_and(|ready| ready.version == version && now_unix - ready.at >= LONG_WAIT_SECS)
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
    tray_cancel: Option<MenuItem<Wry>>,
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
            COUNTDOWN_LEFT.store(u64::MAX, Ordering::Relaxed);
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
        let Some(state) = app.try_state::<AppState>() else {
            return;
        };
        let enabled = {
            let config = state.config.read().await;
            config.settings.silent_update_enabled && config.settings.auto_check_updates
        };
        let support = support();
        self.refresh_record();
        let now = Instant::now();
        let now_unix = chrono::Utc::now().timestamp();

        if !enabled || support.is_err() {
            self.leave_countdown(app);
            self.phase = Phase::Off;
            self.quiet_since = None;
            self.publish(app, enabled, support, now_unix);
            return;
        }

        self.reap_prepare(now);
        let service = app.state::<UpdaterService>();
        // Not while a preparation holds the lock: that is a download, and the
        // tick must keep running (and the countdown keep counting) meanwhile.
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
            self.quiet_since = None;
            self.version = Some(version.clone());
        }

        if let Some(held) = held_by_record(&self.record, &version, now_unix) {
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
            record::update_stored(|record| record.ready_since = Some(since.clone()));
            self.record.ready_since = Some(since);
        }

        let in_countdown = self.countdown_ends.is_some();
        let activity = self.sample_activity(&state, now, in_countdown).await;

        if let Some((ends, _)) = self.countdown_ends {
            if INSTALL_NOW.swap(false, Ordering::AcqRel) || now >= ends {
                self.install(app, &version, enabled, support, now_unix).await;
                return;
            }
            // Input does not abort the countdown: the dialog is how a user who
            // is here answers it, and clicking it is input. A transfer that
            // starts moving does.
            if activity.busy() {
                tracing::info!("Silent update countdown aborted: Ember is busy again");
                self.leave_countdown(app);
                self.quiet_since = None;
                self.phase = Phase::Waiting;
            } else {
                self.update_countdown_tray(ends.saturating_duration_since(now).as_secs());
                self.phase = Phase::Countdown;
            }
            self.publish(app, enabled, support, now_unix);
            return;
        }
        INSTALL_NOW.store(false, Ordering::Release);

        let quiet = !activity.busy()
            && user_away(LAST_INPUT.load(Ordering::Relaxed), now_unix)
            && started.elapsed() >= SETTLE_PERIOD;
        if quiet {
            let since = *self.quiet_since.get_or_insert(now);
            if now.duration_since(since) >= QUIET_PERIOD {
                self.enter_countdown(app, now, now_unix);
                self.publish(app, enabled, support, now_unix);
                return;
            }
        } else {
            self.quiet_since = None;
        }
        self.phase = Phase::Waiting;
        self.publish(app, enabled, support, now_unix);
    }

    fn refresh_record(&mut self) {
        let stale = self
            .record_read_at
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(30));
        if RECORD_DIRTY.swap(false, Ordering::AcqRel) || stale {
            self.record = record::load_stored();
            self.record_read_at = Some(Instant::now());
        }
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
            }
            Ok(Ok(None)) => self.next_prepare_at = None,
            Ok(Err(error)) => {
                tracing::warn!("Silent update could not prepare the update: {error}");
                self.next_prepare_at = Some(now + PREPARE_RETRY);
            }
            Err(error) => {
                tracing::warn!("Silent update preparation task failed: {error}");
                self.next_prepare_at = Some(now + PREPARE_RETRY);
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

    fn enter_countdown(&mut self, app: &AppHandle, now: Instant, now_unix: i64) {
        let ends = now + COUNTDOWN;
        let ends_ms = now_unix.saturating_mul(1000) + COUNTDOWN.as_millis() as i64;
        self.countdown_ends = Some((ends, ends_ms));
        self.phase = Phase::Countdown;
        tracing::info!(
            "Silent update: nothing has moved for {} minutes and nobody is at Ember; warning before installing {}",
            QUIET_PERIOD.as_secs() / 60,
            self.version.as_deref().unwrap_or("?")
        );
        let label = cancel_label(COUNTDOWN.as_secs());
        match MenuItem::with_id(app, TRAY_CANCEL_ID, &label, true, None::<&str>) {
            Ok(item) => {
                if let Some(tray) = app.tray_by_id("main") {
                    match crate::build_tray_menu(app, Some(&item)) {
                        Ok(menu) => {
                            let _ = tray.set_menu(Some(menu));
                            self.tray_cancel = Some(item);
                        }
                        Err(error) => tracing::warn!("Could not add the tray's cancel entry: {error}"),
                    }
                }
            }
            Err(error) => tracing::warn!("Could not create the tray's cancel entry: {error}"),
        }
        COUNTDOWN_LEFT.store(COUNTDOWN.as_secs(), Ordering::Relaxed);
    }

    fn update_countdown_tray(&self, secs: u64) {
        COUNTDOWN_LEFT.store(secs, Ordering::Relaxed);
        if let Some(item) = &self.tray_cancel {
            let _ = item.set_text(cancel_label(secs));
        }
    }

    fn leave_countdown(&mut self, app: &AppHandle) {
        if self.countdown_ends.take().is_none() {
            return;
        }
        COUNTDOWN_LEFT.store(u64::MAX, Ordering::Relaxed);
        if self.tray_cancel.take().is_some() {
            if let Some(tray) = app.tray_by_id("main") {
                if let Ok(menu) = crate::build_tray_menu(app, None) {
                    let _ = tray.set_menu(Some(menu));
                }
            }
        }
    }

    async fn install(
        &mut self,
        app: &AppHandle,
        version: &str,
        enabled: bool,
        support: Result<(), Unsupported>,
        now_unix: i64,
    ) {
        self.leave_countdown(app);
        self.phase = Phase::Installing;
        self.publish(app, enabled, support, now_unix);
        tracing::info!("Silent update: installing {version}");

        let service = app.state::<UpdaterService>();
        match updater::install_prepared_update(app, &service, ResumeReason::Silent).await {
            // In-process installs (the AppImage) land here; Windows exits inside.
            Ok(()) => {
                tracing::info!("Silent update installed {version}; restarting into it");
                app.restart();
            }
            Err(error) if error.contains("updater_install_failed_services_stopped") => {
                // The network is already down for the install, so staying up
                // helps nobody. Come back on this version, with the session the
                // resume file holds, and never try this version silently again.
                tracing::warn!("Silent update of {version} failed after shutdown: {error}");
                let failed = version.to_string();
                record::update_stored(|record| record.failed_version = Some(failed));
                app.restart();
            }
            Err(error) => {
                // Failed before anything was stopped: the staged copy vanished
                // or the floor moved. Nothing restarts; the next tick prepares
                // again or stands down.
                tracing::warn!("Silent update of {version} did not start: {error}");
                self.phase = Phase::Waiting;
                self.quiet_since = None;
                self.publish(app, enabled, support, now_unix);
            }
        }
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
            postponed_until: self
                .record
                .postponed_until
                .filter(|until| *until > now_unix)
                .map(|until| until.saturating_mul(1000)),
            last_success: self.record.last_success.as_ref().map(|last| LastSuccessStatus {
                from: last.from.clone(),
                to: last.to.clone(),
                at: last.at.saturating_mul(1000),
            }),
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
    format!("Cancel update ({})", format_countdown(secs))
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
        || !state.hash_cancel_flags.read().await.is_empty();
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
    let Some(outcome) = app.state::<ResumeService>().outcome() else {
        return;
    };
    if outcome.reason != ResumeReason::Silent {
        return;
    }
    let now_unix = chrono::Utc::now().timestamp();
    record::update_stored(|record| {
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
    record::update_stored(|record| record.postponed_until = Some(until));
    INSTALL_NOW.store(false, Ordering::Release);
    RECORD_DIRTY.store(true, Ordering::Release);
}

/// "Skip this version": never install it silently. The ordinary notice still
/// offers it, and the next release is handled normally.
#[tauri::command]
pub fn silent_update_skip(version: String) {
    let version: String = version.chars().take(64).collect();
    record::update_stored(|record| record.skipped_version = Some(version));
    INSTALL_NOW.store(false, Ordering::Release);
    RECORD_DIRTY.store(true, Ordering::Release);
}

/// Lift a "Not now" early, from Settings → About.
#[tauri::command]
pub fn silent_update_resume() {
    record::update_stored(|record| record.postponed_until = None);
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
    fn the_countdown_reads_as_minutes_and_seconds() {
        assert_eq!(format_countdown(60), "1:00");
        assert_eq!(format_countdown(45), "0:45");
        assert_eq!(format_countdown(5), "0:05");
    }
}
