//! "When downloads finish": exit Ember or put the computer to sleep once the
//! download list has run dry.
//!
//! Session-only on purpose. A choice that survived a restart would put a
//! machine to sleep the next evening for a reason nobody remembers setting, so
//! every launch starts at "do nothing".
//!
//! The background monitor drives it once a second, and the backend owns the
//! clock: a webview hidden in the tray is throttled and cannot be trusted to
//! end a countdown on time, or at all.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

use crate::app_state::AppState;
use crate::commands::errors::coded;
use crate::sharing::manager::TransferManager;
use crate::types::{Transfer, TransferDirection, TransferStatus};

/// How long the user has to change their mind once the last download is done.
const COUNTDOWN: Duration = Duration::from_secs(60);

const STATUS_EVENT: &str = "ember:finish-action";

/// The tray's "Cancel exit" / "Cancel sleep" entry, shown while the countdown runs.
pub const TRAY_CANCEL_ID: &str = "tray_finish_action_cancel";

/// Whether the tray menu was last built with the countdown's entry.
static TRAY_SHOWS_CANCEL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishAction {
    #[default]
    None,
    Exit,
    Sleep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishActionStatus {
    pub action: FinishAction,
    pub sleep_supported: bool,
    /// Armed, but no download has been seen running since, so finishing has
    /// not started to mean anything yet.
    pub waiting_for_downloads: bool,
    /// Unix milliseconds.
    pub countdown_ends_at: Option<i64>,
}

#[derive(Debug, Default)]
struct Machine {
    action: FinishAction,
    saw_pending: bool,
    deadline: Option<(Instant, i64)>,
}

/// What a tick decided.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Nothing,
    Changed,
    Run(FinishAction),
}

impl Machine {
    fn arm(&mut self, action: FinishAction) {
        *self = Machine {
            action,
            ..Machine::default()
        };
    }

    fn tick(&mut self, pending: usize, now: Instant, now_ms: i64) -> Step {
        if self.action == FinishAction::None {
            return Step::Nothing;
        }
        if pending > 0 {
            let changed = !self.saw_pending || self.deadline.is_some();
            // A download added during the countdown means the list is not
            // finished after all; the countdown starts over when it is.
            self.saw_pending = true;
            self.deadline = None;
            return if changed { Step::Changed } else { Step::Nothing };
        }
        if !self.saw_pending {
            return Step::Nothing;
        }
        match self.deadline {
            None => {
                let ms = i64::try_from(COUNTDOWN.as_millis()).unwrap_or(i64::MAX);
                self.deadline = Some((now + COUNTDOWN, now_ms.saturating_add(ms)));
                Step::Changed
            }
            Some((at, _)) if now >= at => {
                let action = self.action;
                *self = Machine::default();
                Step::Run(action)
            }
            Some(_) => Step::Nothing,
        }
    }

    fn status(&self) -> FinishActionStatus {
        FinishActionStatus {
            action: self.action,
            sleep_supported: sleep_supported(),
            waiting_for_downloads: self.action != FinishAction::None && !self.saw_pending,
            countdown_ends_at: self.deadline.map(|(_, ms)| ms),
        }
    }
}

static MACHINE: parking_lot::Mutex<Machine> = parking_lot::Mutex::new(Machine {
    action: FinishAction::None,
    saw_pending: false,
    deadline: None,
});

/// When this asked the computer to sleep, so the monitor stops holding it
/// awake for a while either side of the request.
static SLEEP_REQUESTED_AT: parking_lot::Mutex<Option<Instant>> = parking_lot::Mutex::new(None);
const WAKE_LOCK_RELEASE: Duration = Duration::from_millis(2_500);
const WAKE_LOCK_HOLD_OFF: Duration = Duration::from_secs(60);

/// Whether the sleep inhibitor must stay released because Ember itself just
/// asked for sleep. Without it, an upload still running would re-take the
/// lock on the next tick and, on Linux, veto the very suspend that was asked
/// for.
pub fn wake_lock_held_off() -> bool {
    SLEEP_REQUESTED_AT
        .lock()
        .is_some_and(|at| at.elapsed() < WAKE_LOCK_HOLD_OFF)
}

pub const fn sleep_supported() -> bool {
    cfg!(any(windows, target_os = "linux", target_os = "macos"))
}

/// Downloads that will still finish on their own. Paused and stopped rows wait
/// for the user, and a disk-full one for free space, so none of those holds
/// the action back — otherwise one forgotten paused file would keep the
/// machine awake all night.
pub fn pending_downloads(manager: &TransferManager) -> usize {
    pending_download_rows(manager).count()
}

/// The rows [`pending_downloads`] counts.
pub fn pending_download_rows(manager: &TransferManager) -> impl Iterator<Item = &Transfer> {
    manager
        .active
        .values()
        .chain(manager.queue.iter())
        .filter(|t| t.direction == TransferDirection::Download)
        .filter(|t| {
            !matches!(
                t.status,
                TransferStatus::Paused
                    | TransferStatus::Stopped
                    | TransferStatus::Insufficient
                    | TransferStatus::Completed
                    | TransferStatus::Failed
            )
        })
}

/// Seconds left on the countdown, for the tray tooltip.
pub fn countdown_remaining_secs() -> Option<(FinishAction, u64)> {
    let machine = MACHINE.lock();
    machine
        .deadline
        .map(|(at, _)| (machine.action, at.saturating_duration_since(Instant::now()).as_secs()))
}

fn publish(app: &AppHandle, status: &FinishActionStatus) {
    if let Err(error) = app.emit(STATUS_EVENT, status) {
        tracing::debug!("Could not emit the finish action status: {error}");
    }
    let counting = status.countdown_ends_at.is_some();
    if TRAY_SHOWS_CANCEL.swap(counting, std::sync::atomic::Ordering::AcqRel) != counting {
        crate::auto_update::silent::rebuild_tray_menu(app);
    }
}

/// One step of the monitor. `pending` is [`pending_downloads`] right now.
pub fn tick(app: &AppHandle, pending: usize) {
    let (step, status) = {
        let mut machine = MACHINE.lock();
        let step = machine.tick(
            pending,
            Instant::now(),
            chrono::Utc::now().timestamp_millis(),
        );
        (step, machine.status())
    };
    match step {
        Step::Nothing => {}
        Step::Changed => publish(app, &status),
        Step::Run(action) => {
            publish(app, &status);
            run(app, action);
        }
    }
}

fn run(app: &AppHandle, action: FinishAction) {
    match action {
        FinishAction::None => {}
        FinishAction::Exit => {
            tracing::info!("Downloads finished; exiting as asked");
            if let Some(state) = app.try_state::<AppState>() {
                state
                    .quit_confirmed
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            app.exit(0);
        }
        FinishAction::Sleep => {
            tracing::info!("Downloads finished; putting the computer to sleep as asked");
            *SLEEP_REQUESTED_AT.lock() = Some(Instant::now());
            tauri::async_runtime::spawn_blocking(|| {
                // Long enough for the monitor's next tick to let go of the
                // sleep inhibitor it holds while uploads run; logind refuses
                // a suspend while a block lock is held, ours included.
                std::thread::sleep(WAKE_LOCK_RELEASE);
                if let Err(error) = suspend() {
                    tracing::warn!("Could not put the computer to sleep: {error}");
                }
            });
        }
    }
}

#[cfg(windows)]
fn suspend() -> Result<(), String> {
    // Sleep, not hibernate (the first argument), and wake events stay enabled
    // (the third): a scheduled task or a wake-on-LAN should still be able to
    // bring the machine back.
    let ok = unsafe { windows_sys::Win32::System::Power::SetSuspendState(false, false, false) };
    if !ok {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn suspend() -> Result<(), String> {
    let connection = zbus::blocking::Connection::system().map_err(|e| e.to_string())?;
    connection
        .call_method(
            Some("org.freedesktop.login1"),
            "/org/freedesktop/login1",
            Some("org.freedesktop.login1.Manager"),
            "Suspend",
            // Not interactive: there is nobody at the keyboard to answer a
            // polkit prompt, which is the point of the feature.
            &(false,),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "macos")]
fn suspend() -> Result<(), String> {
    let status = std::process::Command::new("/usr/bin/pmset")
        .arg("sleepnow")
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("pmset exited with {status}"))
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn suspend() -> Result<(), String> {
    Err("not supported on this platform".to_string())
}

#[tauri::command]
pub fn get_finish_action() -> FinishActionStatus {
    MACHINE.lock().status()
}

#[tauri::command]
pub async fn set_finish_action(
    app: AppHandle,
    state: tauri::State<'_, AppState>,
    action: FinishAction,
) -> Result<FinishActionStatus, String> {
    if action == FinishAction::Sleep && !sleep_supported() {
        return Err(coded(
            "finish_action_sleep_unsupported",
            "Sleep is not supported on this platform",
        ));
    }
    let pending = pending_downloads(&*state.transfer_manager.read().await);
    let status = {
        let mut machine = MACHINE.lock();
        machine.arm(action);
        // Settled now rather than on the next tick, so the reply already says
        // whether there is anything to wait for.
        if action != FinishAction::None && pending > 0 {
            machine.saw_pending = true;
        }
        machine.status()
    };
    publish(&app, &status);
    Ok(status)
}

/// "Cancel" in the countdown: the choice goes back to doing nothing.
#[tauri::command]
pub fn cancel_finish_action(app: AppHandle) -> FinishActionStatus {
    let status = {
        let mut machine = MACHINE.lock();
        machine.arm(FinishAction::None);
        machine.status()
    };
    publish(&app, &status);
    status
}

/// "Now" in the countdown. Only while one is running, so a stale dialog
/// cannot fire an action the countdown already gave up on.
#[tauri::command]
pub fn run_finish_action_now(app: AppHandle) -> FinishActionStatus {
    let (action, status) = {
        let mut machine = MACHINE.lock();
        let action = if machine.deadline.is_some() {
            let action = machine.action;
            *machine = Machine::default();
            Some(action)
        } else {
            None
        };
        (action, machine.status())
    };
    publish(&app, &status);
    if let Some(action) = action {
        run(&app, action);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    fn armed(action: FinishAction) -> Machine {
        let mut machine = Machine::default();
        machine.arm(action);
        machine
    }

    #[test]
    fn nothing_happens_until_a_download_has_been_seen() {
        let start = Instant::now();
        let mut machine = armed(FinishAction::Exit);
        assert_eq!(machine.tick(0, start, 0), Step::Nothing);
        assert!(machine.status().waiting_for_downloads);
        assert_eq!(machine.tick(0, start + COUNTDOWN * 5, 0), Step::Nothing);
    }

    #[test]
    fn the_countdown_starts_when_the_last_download_finishes_and_then_runs() {
        let start = Instant::now();
        let mut machine = armed(FinishAction::Sleep);
        assert_eq!(machine.tick(2, start, 1_000), Step::Changed);
        assert_eq!(machine.tick(1, start, 1_000), Step::Nothing);
        assert_eq!(machine.tick(0, start, 1_000), Step::Changed);
        assert_eq!(machine.status().countdown_ends_at, Some(61_000));
        assert_eq!(machine.tick(0, start + COUNTDOWN / 2, 31_000), Step::Nothing);
        assert_eq!(
            machine.tick(0, start + COUNTDOWN, 61_000),
            Step::Run(FinishAction::Sleep)
        );
        assert_eq!(machine.status().action, FinishAction::None, "one-shot");
        assert_eq!(machine.tick(0, start + COUNTDOWN * 2, 0), Step::Nothing);
    }

    #[test]
    fn a_new_download_during_the_countdown_calls_it_off() {
        let start = Instant::now();
        let mut machine = armed(FinishAction::Exit);
        machine.tick(1, start, 0);
        machine.tick(0, start, 0);
        assert!(machine.status().countdown_ends_at.is_some());
        assert_eq!(machine.tick(1, start + COUNTDOWN, 0), Step::Changed);
        assert_eq!(machine.status().countdown_ends_at, None);
        assert_eq!(machine.status().action, FinishAction::Exit, "still armed");
    }

    #[test]
    fn disarmed_never_runs() {
        let start = Instant::now();
        let mut machine = Machine::default();
        assert_eq!(machine.tick(1, start, 0), Step::Nothing);
        assert_eq!(machine.tick(0, start + COUNTDOWN * 2, 0), Step::Nothing);
    }
}
