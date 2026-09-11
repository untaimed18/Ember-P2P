//! Keep the machine awake while Ember is moving bytes.
//!
//! A six-hour download does not survive the OS idle timer, and "the machine
//! went to sleep" is indistinguishable from "the transfer stalled" from the
//! Transfers page. This holds a *system* sleep inhibitor while work is in
//! flight and releases it the moment there is none.
//!
//! Deliberately only the system, not the display: the screen is welcome to
//! turn off, and an app that keeps a monitor lit all night to seed a file is
//! worse than the problem it solves.
//!
//! ## Why a dedicated thread
//!
//! On Windows the inhibitor is [`SetThreadExecutionState`], which is
//! **thread-affine**: the state belongs to the calling thread and is released
//! when that thread exits. A Tokio task is the wrong owner — it is not pinned
//! to a worker thread, so the request could land on one thread and the release
//! on another, leaving the first thread's inhibitor set forever. So one plain
//! OS thread owns the state for the process's lifetime and mirrors an atomic
//! that callers flip.
//!
//! [`SetThreadExecutionState`]: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadexecutionstate

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How often the owning thread notices a change. Matched to the once-a-second
/// cadence of the caller that decides, so a finer poll could only burn wakeups.
const POLL_INTERVAL: Duration = Duration::from_millis(1000);

/// Re-assert an already-held inhibitor this often. `ES_CONTINUOUS` needs no
/// refresh, so this is belt-and-braces against anything else in the process
/// clearing the thread's state; it costs one syscall a minute while active.
const REASSERT_INTERVAL: Duration = Duration::from_secs(60);

/// Whether this build can actually hold a sleep inhibitor.
///
/// The UI asks so it can disable the toggle rather than offer a switch that
/// does nothing. Linux would want an org.freedesktop.login1 `Inhibit` lease
/// over D-Bus, which is a dependency this tree does not carry and a daemon that
/// may not be running; until then the honest answer there is "no".
pub const fn supported() -> bool {
    cfg!(windows)
}

/// A held-or-released system sleep inhibitor.
///
/// Cheap to construct once and keep for the process's lifetime. Dropping it
/// releases the inhibitor and stops the owning thread.
pub struct WakeLock {
    desired: Arc<AtomicBool>,
    /// What the OS last *accepted*, as opposed to what was asked for.
    ///
    /// Separate from `desired` because the two legitimately disagree: a refused
    /// `SetThreadExecutionState` is backed off rather than retried every poll,
    /// and for that whole window the request stands while nothing is held. The
    /// UI publishes this one, because "sleep is being deferred" is a claim
    /// about the machine and reporting the request instead would tell a user
    /// their transfers are safe overnight when the box is free to suspend —
    /// exactly the "did it stall or did it sleep?" ambiguity this module exists
    /// to remove.
    effective: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    /// Whether the owning thread actually started. A thread-spawn failure must
    /// not turn every later `set` into a silent lie, so it is reported once
    /// here and `is_running` stays false.
    running: bool,
}

impl WakeLock {
    /// Spawn the owning thread. On a platform without an implementation this
    /// allocates the atomics and spawns nothing, so callers need no `cfg`.
    pub fn new() -> Self {
        let desired = Arc::new(AtomicBool::new(false));
        let effective = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        if !supported() {
            return Self {
                desired,
                effective,
                stop,
                running: false,
            };
        }
        let thread_desired = desired.clone();
        let thread_effective = effective.clone();
        let thread_stop = stop.clone();
        let spawned = std::thread::Builder::new()
            .name("ember-wake-lock".to_string())
            .spawn(move || {
                own_execution_state(thread_desired, thread_effective, thread_stop)
            });
        match spawned {
            Ok(_handle) => Self {
                desired,
                effective,
                stop,
                running: true,
            },
            Err(error) => {
                tracing::warn!(
                    "Could not start the sleep-inhibitor thread ({error}); \
                     the system may sleep during transfers"
                );
                Self {
                    desired,
                    effective,
                    stop,
                    running: false,
                }
            }
        }
    }

    /// Request or release the inhibitor. Idempotent, and safe to call on every
    /// tick — the owning thread only issues a syscall when the value changes.
    pub fn set(&self, keep_awake: bool) {
        self.desired.store(keep_awake, Ordering::Relaxed);
    }

    /// Whether a request can be honored at all: a supported platform whose
    /// owning thread started. `false` means [`set`](Self::set) is a no-op.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Whether an inhibitor is actually held right now, as last accepted by the
    /// OS. This is what the UI should report — see [`WakeLock::effective`].
    ///
    /// Lags a [`POLL_INTERVAL`] behind a `set`, which is the same lag the
    /// inhibitor itself has.
    pub fn is_held(&self) -> bool {
        self.effective.load(Ordering::Relaxed)
    }
}

impl Drop for WakeLock {
    fn drop(&mut self) {
        // Release first, then stop: the thread re-reads `desired` before it
        // checks `stop`, and its own exit path releases anything still held, so
        // either ordering ends with the inhibitor down. Setting it here as well
        // keeps that true even if the thread is already gone.
        self.desired.store(false, Ordering::Relaxed);
        self.stop.store(true, Ordering::Release);
    }
}

impl Default for WakeLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Body of the owning thread: mirror `desired` into this thread's execution
/// state until `stop`, then release.
fn own_execution_state(
    desired: Arc<AtomicBool>,
    effective: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    let mut applied = false;
    let mut last_apply = Instant::now();
    let mut warned = false;
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        let want = desired.load(Ordering::Relaxed);
        if want != applied || (want && last_apply.elapsed() >= REASSERT_INTERVAL) {
            if apply(want) {
                if want != applied {
                    tracing::debug!(
                        "System sleep inhibitor {}",
                        if want { "held" } else { "released" }
                    );
                }
                applied = want;
                effective.store(want, Ordering::Relaxed);
                last_apply = Instant::now();
            } else if !warned {
                // Once only: a platform that refuses the call refuses it every
                // second, and a log line a second is worse than the fault.
                warned = true;
                tracing::warn!(
                    "The OS refused a sleep-inhibitor change; the system may sleep during transfers"
                );
                // Treat it as applied so the retry follows the re-assert
                // cadence rather than hammering once per poll. `effective` is
                // deliberately *not* moved with it: backing off is a decision
                // about how often to retry, and it must not become a claim that
                // the machine is being held awake when it is not.
                applied = want;
                last_apply = Instant::now();
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    if applied {
        apply(false);
    }
    effective.store(false, Ordering::Relaxed);
}

/// Set or clear this thread's inhibitor. Returns whether the OS accepted it.
#[cfg(windows)]
fn apply(keep_awake: bool) -> bool {
    use windows_sys::Win32::System::Power::{
        SetThreadExecutionState, ES_CONTINUOUS, ES_SYSTEM_REQUIRED,
    };
    // `ES_CONTINUOUS` alone is the documented way to clear a previously
    // continuous request; sending it with `ES_SYSTEM_REQUIRED` is what makes
    // the request stick until we say otherwise, rather than resetting the idle
    // timer exactly once.
    let flags = if keep_awake {
        ES_CONTINUOUS | ES_SYSTEM_REQUIRED
    } else {
        ES_CONTINUOUS
    };
    // SAFETY: no pointers or handles are involved. The call only reads the
    // flags by value and mutates the execution state of the calling thread,
    // which is this thread and lives for the whole loop above.
    let previous = unsafe { SetThreadExecutionState(flags) };
    previous != 0
}

#[cfg(not(windows))]
fn apply(_keep_awake: bool) -> bool {
    // No implementation on this platform (see `supported`). Reported as
    // accepted so the owning thread — which is never spawned here anyway —
    // could not spin on a refusal.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of the type is that a request is cheap and repeatable.
    /// Constructing one must not depend on a display, a session, or a
    /// D-Bus daemon, because it happens during startup on every platform.
    #[test]
    fn construct_set_and_drop_is_inert_on_every_platform() {
        let lock = WakeLock::new();
        assert_eq!(
            lock.is_running(),
            supported(),
            "the owning thread runs exactly where an inhibitor exists"
        );
        lock.set(true);
        lock.set(true);
        lock.set(false);
        drop(lock);
    }

    /// Drop has to leave the inhibitor down even while it is being held, or a
    /// restart-in-place (the updater's flush path) would leak it for the rest
    /// of the process's life.
    #[test]
    fn drop_releases_a_held_inhibitor() {
        let lock = WakeLock::new();
        lock.set(true);
        // Long enough for the owning thread to take it up before we drop.
        std::thread::sleep(POLL_INTERVAL + Duration::from_millis(250));
        let desired = lock.desired.clone();
        drop(lock);
        assert!(
            !desired.load(Ordering::Relaxed),
            "drop must clear the request"
        );
    }

    /// A request is not a fact. The UI reports "sleep is being deferred", so it
    /// has to read what the OS accepted rather than what was asked for —
    /// otherwise a platform that refuses the call, or one where the owning
    /// thread never started, shows a badge claiming transfers are safe
    /// overnight on a machine that is free to suspend.
    #[test]
    fn held_reports_the_os_answer_not_the_request() {
        let lock = WakeLock::new();
        assert!(!lock.is_held(), "nothing is held before anything is asked");

        lock.set(true);
        if !supported() {
            // No owning thread here, so a request can never become a hold.
            std::thread::sleep(POLL_INTERVAL + Duration::from_millis(250));
            assert!(
                !lock.is_held(),
                "an unsupported platform must never report a hold"
            );
            return;
        }
        std::thread::sleep(POLL_INTERVAL + Duration::from_millis(250));
        assert!(lock.is_held(), "an accepted request has to read as held");

        lock.set(false);
        std::thread::sleep(POLL_INTERVAL + Duration::from_millis(250));
        assert!(!lock.is_held(), "and a release has to read as released");
    }
}
