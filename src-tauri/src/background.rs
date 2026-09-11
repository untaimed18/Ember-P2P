//! Once-a-second housekeeping that lives outside the network event loop.
//!
//! Three jobs, all of which have to happen on a clock rather than in response
//! to a command:
//!
//! - **Bandwidth schedule.** A window opens at 23:00 with nobody at the
//!   keyboard, so the caps have to be re-resolved on a tick.
//! - **Sleep inhibitor.** Held while transfers are working, released when they
//!   stop — again with nobody watching.
//! - **Tray tooltip.** The one status surface available while the window is
//!   hidden.
//!
//! Deliberately *not* folded into `network/mod.rs`'s `stats_timer`: nothing
//! here touches network state, and that loop's arms already run long enough
//! that adding a config read and two syscalls to them is how a UDP timer
//! starts slipping. This task only reads shared state — the config lock, the
//! transfer manager, the bandwidth limiter — and never sends a network command.

use std::time::Duration;

use tauri::{Emitter, Manager};

use crate::app_state::AppState;
use crate::bandwidth::schedule;
use crate::power::WakeLock;
use crate::types::{RuntimeStatus, TransferHealth, TransferStatus};

/// Housekeeping cadence. One second matches the limiter's own speed tick, and
/// is the coarsest interval at which a schedule boundary still lands within a
/// second of the minute the user typed.
const TICK: Duration = Duration::from_secs(1);

/// Spawn the monitor. Call once, after `AppState` is managed.
pub fn spawn(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move { run(app).await });
}

async fn run(app: tauri::AppHandle) {
    let wake_lock = WakeLock::new();
    let sleep_inhibit_supported = wake_lock.is_running();

    // Every "last applied" value starts unset so the first tick establishes
    // the world rather than trusting that startup already matched it.
    let mut applied_limits: Option<(u64, u64)> = None;
    let mut published: Option<RuntimeStatus> = None;
    let mut applied_tooltip: Option<String> = None;
    let mut holding_wake_lock = false;

    let mut ticker = tokio::time::interval(TICK);
    // Skip, not Burst: after a runtime stall (or a machine resuming from the
    // sleep this task exists to defer) Burst would replay one iteration per
    // missed tick, and every one of them would re-resolve the same schedule
    // and re-emit the same status. Every timer in `network/mod.rs` is Skip for
    // the same reason.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        // `try_state` rather than `state`: this task is spawned from `setup`
        // alongside everything else, and a panic here would take the
        // housekeeping down for the session rather than retrying next second.
        let Some(state) = app.try_state::<AppState>() else {
            continue;
        };

        let (weekday, minute) = schedule::local_now();
        let (resolved, prevent_sleep) = {
            let config = state.config.read().await;
            (
                schedule::resolve_settings(&config.settings, weekday, minute),
                config.settings.prevent_sleep_while_active,
            )
        };

        // Only on change. `set_configured_limits` is idempotent, but it also
        // arbitrates with the USS controller, and re-running that arbitration
        // once a second for no reason is how a throttle starts flickering.
        let target = (resolved.max_upload_speed, resolved.max_download_speed);
        if applied_limits != Some(target) {
            state
                .bandwidth_limiter
                .set_configured_limits(target.0, target.1);
            if let Some(previous) = applied_limits {
                // Not necessarily *caused* by the schedule: a settings save
                // changes the target too, and this tick is where the monitor
                // notices. So the line reports the new source rather than
                // claiming a cause it cannot know.
                tracing::info!(
                    "Effective bandwidth limits now up {} (was {}), down {} (was {}); source: {}",
                    target.0,
                    previous.0,
                    target.1,
                    previous.1,
                    resolved
                        .active
                        .as_ref()
                        .map(|rule| format!("schedule rule {}", rule.id))
                        .unwrap_or_else(|| "manual limits".to_string()),
                );
            }
            applied_limits = Some(target);
        }

        let working = count_working_transfers(&state).await;
        // `sleep_inhibit_supported` is part of the condition rather than only a
        // display flag: on a platform with no implementation `set` is a no-op,
        // so without it `holding_wake_lock` would report an inhibitor that was
        // never taken.
        let want_awake = sleep_inhibit_supported && prevent_sleep && working > 0;
        if want_awake != holding_wake_lock {
            wake_lock.set(want_awake);
            holding_wake_lock = want_awake;
        }

        let status = RuntimeStatus {
            effective_upload_speed: target.0,
            effective_download_speed: target.1,
            schedule: resolved.active,
            sleep_inhibit_supported,
            sleep_inhibit_held: holding_wake_lock,
        };
        if published.as_ref() != Some(&status) {
            *state.runtime_status.write() = status.clone();
            if let Err(error) = app.emit("ember:runtime-status", &status) {
                tracing::debug!("Could not emit runtime status: {error}");
            }
            published = Some(status);
        }

        let tooltip = tray_tooltip(&state, working);
        if applied_tooltip.as_deref() != Some(tooltip.as_str()) {
            set_tray_tooltip(&app, tooltip.clone());
            applied_tooltip = Some(tooltip);
        }
    }
}

/// How many transfers are doing work the machine must stay awake for.
///
/// `Searching` and `Queued` deliberately do not count: a download with no
/// sources would otherwise pin a laptop awake indefinitely, which is the
/// failure mode that makes users turn the whole feature off. Neither does a row
/// the app's own health model has already called `Stalled` — that is precisely
/// its judgement that nothing is happening.
async fn count_working_transfers(state: &AppState) -> usize {
    let manager = state.transfer_manager.read().await;
    manager
        .active
        .values()
        .filter(|transfer| match transfer.status {
            // Local work with a definite end. Interrupting a hash or a
            // completion move is worse than deferring sleep for a minute.
            TransferStatus::Verifying
            | TransferStatus::Completing
            | TransferStatus::Hashing => true,
            TransferStatus::Active => transfer.health != TransferHealth::Stalled,
            _ => false,
        })
        .count()
}

/// Tooltip for the tray icon: the current rates, or just the app name when
/// nothing is moving.
///
/// Composed from symbols and byte units rather than words because the tray is
/// owned by the backend, which has no idea which of the nine shipped locales
/// the user is reading. `↓`/`↑` and `MB/s` need no translation; "3 downloads"
/// would.
fn tray_tooltip(state: &AppState, working: usize) -> String {
    let down = state.bandwidth_limiter.smoothed_download_speed();
    let up = state.bandwidth_limiter.smoothed_upload_speed();
    if working == 0 && down == 0 && up == 0 {
        return "Ember".to_string();
    }
    format!(
        "Ember\n\u{2193} {}  \u{2191} {}",
        format_rate(down),
        format_rate(up)
    )
}

/// Decimal (not binary) units, matching `formatSpeed` in `src/lib/utils.ts` so
/// the tooltip and the status bar cannot disagree about the same number.
fn format_rate(bytes_per_sec: u64) -> String {
    if bytes_per_sec >= 1_000_000_000 {
        format!("{:.2} GB/s", bytes_per_sec as f64 / 1_000_000_000.0)
    } else if bytes_per_sec >= 1_000_000 {
        format!("{:.1} MB/s", bytes_per_sec as f64 / 1_000_000.0)
    } else if bytes_per_sec >= 1_000 {
        format!("{:.0} KB/s", bytes_per_sec as f64 / 1_000.0)
    } else {
        format!("{bytes_per_sec} B/s")
    }
}

/// Update the tray tooltip from the main thread.
///
/// `tray-icon` requires its shell notifications to be issued on the thread that
/// owns the icon, which is the GUI thread — not whichever Tokio worker this
/// task happens to be parked on. `run_on_main_thread` is the only safe hop.
/// Best-effort: the tray may legitimately not exist (its builder is allowed to
/// fail at startup on a session with no notification area).
fn set_tray_tooltip(app: &tauri::AppHandle, tooltip: String) {
    let handle = app.clone();
    if let Err(error) = app.run_on_main_thread(move || {
        if let Some(tray) = handle.tray_by_id("main") {
            if let Err(error) = tray.set_tooltip(Some(&tooltip)) {
                tracing::debug!("Could not set tray tooltip: {error}");
            }
        }
    }) {
        tracing::debug!("Could not reach the main thread to set the tray tooltip: {error}");
    }
}

/// Resolve the caps in force right now, for callers outside this task.
///
/// `update_settings` needs exactly this: applying the freshly-typed manual
/// limits while a schedule window is open would undo the schedule for up to a
/// tick, and the visible result is a limit that moves on its own moments after
/// being saved.
pub fn effective_limits_now(settings: &crate::types::AppSettings) -> (u64, u64) {
    let (weekday, minute) = schedule::local_now();
    let resolved = schedule::resolve_settings(settings, weekday, minute);
    (resolved.max_upload_speed, resolved.max_download_speed)
}

/// Wake the monitor's decisions up early after a settings save.
///
/// The tick would get there within a second regardless, but the schedule can
/// switch off mid-save and the limits it left behind should not outlive the
/// command that removed them.
pub fn apply_effective_limits(state: &AppState, settings: &crate::types::AppSettings) {
    let (upload, download) = effective_limits_now(settings);
    state
        .bandwidth_limiter
        .set_configured_limits(upload, download);
}

/// The runtime snapshot for a first paint. Kept here so the shape of the
/// status has one owner.
pub fn snapshot(state: &AppState) -> RuntimeStatus {
    state.runtime_status.read().clone()
}

/// Seed the cached status before the first tick lands.
///
/// Settings can be opened inside the first second of a launch, and an
/// all-zeroes snapshot would report "no schedule, unlimited" for a profile
/// whose overnight window is open right now.
pub fn seed_status(state: &AppState, settings: &crate::types::AppSettings) {
    let (weekday, minute) = schedule::local_now();
    let resolved = schedule::resolve_settings(settings, weekday, minute);
    *state.runtime_status.write() = RuntimeStatus {
        effective_upload_speed: resolved.max_upload_speed,
        effective_download_speed: resolved.max_download_speed,
        schedule: resolved.active,
        sleep_inhibit_supported: crate::power::supported(),
        sleep_inhibit_held: false,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tooltip is read by hovering, so it has to say something even when
    /// idle, and must never render a bare "0 B/s ↓ 0 B/s ↑" wall.
    #[test]
    fn rates_format_the_way_the_status_bar_does() {
        assert_eq!(format_rate(0), "0 B/s");
        assert_eq!(format_rate(999), "999 B/s");
        assert_eq!(format_rate(1_000), "1 KB/s");
        assert_eq!(format_rate(1_500), "2 KB/s");
        assert_eq!(format_rate(1_000_000), "1.0 MB/s");
        assert_eq!(format_rate(12_300_000), "12.3 MB/s");
        assert_eq!(format_rate(2_500_000_000), "2.50 GB/s");
    }
}
