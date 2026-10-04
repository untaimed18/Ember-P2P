//! The update watchdog: brings Ember back if an installer never does.
//!
//! On Windows an update ends with Ember exiting and the NSIS installer taking
//! over, and the installer relaunches Ember only when it succeeds. An antivirus
//! that blocks it, a user who kills it, a disk that fills halfway: each leaves
//! Ember closed with nothing left to notice. For someone who keeps Ember in the
//! tray that can mean days of sharing nothing before anyone looks.
//!
//! So before handing over, Ember starts a copy of itself in watchdog mode. It
//! waits for Ember to exit, then for Ember to be running again, and if that has
//! not happened within a few minutes it starts the installed executable itself.
//! That launch finds the resume file, restores the session and reports the
//! update that did not land. An Ember that comes back but exits before taking
//! the resume file failed in its own setup, and is started once more.
//!
//! Two details keep it out of the installer's way. It runs from a copy in the
//! data folder under its own name, because running the installed executable
//! would lock the file the installer must replace, and the installer's
//! running-app check would kill it by path. And it tells whether Ember is
//! running from [`LOCK_FILE`], a lock every Ember holds for its lifetime,
//! rather than by process name or by simply starting a second copy — which the
//! single-instance plugin would answer by showing the window.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use fs2::FileExt;

/// First argument that puts this executable in watchdog mode.
pub const ARG: &str = "--update-watchdog";
const DATA_DIR_ARG: &str = "--data-dir";
const LAUNCH_ARG: &str = "--launch";

/// Held exclusively by every running Ember.
pub const LOCK_FILE: &str = "instance.lock";
const DIR: &str = "update-watchdog";
const EXE_NAME: &str = "ember-update-watchdog.exe";
/// Left by an Ember whose install failed without ending it, so a watchdog
/// started for that install does not relaunch Ember after the user quits.
const STAND_DOWN_FILE: &str = "stand-down";
const LOG_FILE: &str = "update-watchdog.log";
const MAX_LOG_BYTES: u64 = 64 * 1024;

/// How long Ember has to exit once the watchdog is started. An install that
/// fails before exiting keeps Ember running, and then there is nothing to
/// watch.
const PARENT_EXIT_DEADLINE: Duration = Duration::from_secs(3 * 60);
/// How long the installer has to bring Ember back before the watchdog does.
const RELAUNCH_DEADLINE: Duration = Duration::from_secs(5 * 60);
/// The same for an MSI install, whose elevation prompt waits as long as nobody
/// answers it. An Ember started meanwhile holds the files the install must
/// then replace.
const MSI_RELAUNCH_DEADLINE: Duration = Duration::from_secs(30 * 60);
/// How long an Ember that came back is watched until it has taken the resume
/// file, which it does early in setup, once the database and settings opened.
const SETTLE_PERIOD: Duration = Duration::from_secs(2 * 60);
const POLL: Duration = Duration::from_secs(2);
/// A poll that overran by this much means the machine slept. `Instant` counts
/// through sleep on Windows, so every deadline has passed on waking, while the
/// installer, asleep just as long, has not moved on.
const SLEEP_GAP: Duration = Duration::from_secs(15);
/// Before trying a failed launch once more: an antivirus may still be scanning
/// an executable the installer just wrote.
const RELAUNCH_RETRY: Duration = Duration::from_secs(10);
/// A starting Ember retries the lock this often, so the watchdog's own
/// instantaneous probe can never make it give up.
const LOCK_ATTEMPTS: u32 = 10;
const LOCK_RETRY: Duration = Duration::from_millis(200);
/// How long a relaunched Ember waits before deleting the watchdog's copy, which
/// cannot be deleted while it is still running its last poll.
const CLEANUP_DELAY: Duration = Duration::from_secs(60);
/// A watchdog that missed Ember restarting between two of its polls keeps
/// polling until its own deadline, minutes later.
const CLEANUP_ATTEMPTS: u32 = 10;

static INSTANCE_LOCK: OnceLock<File> = OnceLock::new();
/// This process started a watchdog, which now owns the folder.
static STARTED: AtomicBool = AtomicBool::new(false);

fn open_lock(data_dir: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(data_dir.join(LOCK_FILE))
}

fn is_contended(error: &std::io::Error) -> bool {
    error.raw_os_error().is_some()
        && error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

/// Take the instance lock for the life of this process. Best-effort: a lock
/// that cannot be taken costs only the watchdog's ability to tell whether this
/// Ember is running, so the watchdog is simply not started later.
pub fn hold_instance_lock(data_dir: &Path) {
    let file = match open_lock(data_dir) {
        Ok(file) => file,
        Err(error) => {
            tracing::warn!("Could not open {LOCK_FILE}: {error}");
            return;
        }
    };
    for attempt in 1..=LOCK_ATTEMPTS {
        match file.try_lock_exclusive() {
            Ok(()) => {
                let _ = INSTANCE_LOCK.set(file);
                return;
            }
            Err(error) if is_contended(&error) && attempt < LOCK_ATTEMPTS => {
                std::thread::sleep(LOCK_RETRY);
            }
            Err(error) => {
                tracing::warn!("Could not take {LOCK_FILE}: {error}");
                return;
            }
        }
    }
}

/// Whether some Ember holds the instance lock right now. Probes by taking and
/// immediately releasing it.
fn lock_is_held(data_dir: &Path) -> std::io::Result<bool> {
    let file = open_lock(data_dir)?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            let _ = FileExt::unlock(&file);
            Ok(false)
        }
        Err(error) if is_contended(&error) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Delete the copy a previous update's watchdog ran from, once it has had time
/// to exit.
pub fn schedule_cleanup(data_dir: &Path) {
    let dir = data_dir.join(DIR);
    if !dir.exists() {
        return;
    }
    tauri::async_runtime::spawn(async move {
        for attempt in 1..=CLEANUP_ATTEMPTS {
            tokio::time::sleep(CLEANUP_DELAY).await;
            if STARTED.load(Ordering::Acquire) {
                return;
            }
            match std::fs::remove_dir_all(&dir) {
                Ok(()) => return,
                Err(_) if !dir.exists() => return,
                Err(error) if attempt == CLEANUP_ATTEMPTS => {
                    tracing::debug!("Could not remove the update watchdog's copy: {error}");
                }
                Err(_) => {}
            }
        }
    });
}

/// Start the watchdog just before handing over to an installer that will end
/// this process. Windows only: elsewhere the install runs in process and a
/// failure comes back as an error. Best-effort — an update is not refused for
/// want of a safety net.
pub fn spawn_for_install() {
    if !cfg!(windows) {
        return;
    }
    if INSTANCE_LOCK.get().is_none() {
        // Without our own lock held the watchdog could not tell this process
        // apart from a relaunch, and would start a second copy beside it.
        tracing::warn!("Not starting the update watchdog: this process does not hold {LOCK_FILE}");
        return;
    }
    if let Err(error) = try_spawn() {
        tracing::warn!("Could not start the update watchdog: {error:#}");
    }
}

/// The install this watchdog was started for failed and Ember is still
/// running: tell it there is nothing to bring back. Best-effort.
pub fn stand_down() {
    if !cfg!(windows) {
        return;
    }
    if let Ok(data_dir) = crate::storage::paths::ensure_data_dir() {
        let dir = data_dir.join(DIR);
        if dir.exists() {
            let _ = std::fs::write(dir.join(STAND_DOWN_FILE), b"1");
        }
    }
}

fn stood_down(data_dir: &Path) -> bool {
    data_dir.join(DIR).join(STAND_DOWN_FILE).exists()
}

fn try_spawn() -> anyhow::Result<()> {
    STARTED.store(true, Ordering::Release);
    let data_dir = crate::storage::paths::ensure_data_dir()?;
    let exe = std::env::current_exe()?;
    let dir = data_dir.join(DIR);
    std::fs::create_dir_all(&dir)?;
    let _ = std::fs::remove_file(dir.join(STAND_DOWN_FILE));
    let copy = dir.join(EXE_NAME);
    std::fs::copy(&exe, &copy)?;
    let mut command = std::process::Command::new(&copy);
    command
        .arg(ARG)
        .arg(DATA_DIR_ARG)
        .arg(&data_dir)
        .arg(LAUNCH_ARG)
        .arg(&exe);
    detach(&mut command)?;
    tracing::info!("Started the update watchdog");
    Ok(())
}

/// Spawn `command` outside this process's console and job, so it outlives us.
#[cfg(windows)]
fn detach(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
    // Breaking away from a job fails where the job forbids it; without it the
    // child still outlives a parent that simply exits.
    match command.creation_flags(base | CREATE_BREAKAWAY_FROM_JOB).spawn() {
        Ok(child) => Ok(child),
        Err(_) => command.creation_flags(base).spawn(),
    }
}

#[cfg(not(windows))]
fn detach(command: &mut std::process::Command) -> std::io::Result<std::process::Child> {
    command.spawn()
}

// ── Watchdog mode ───────────────────────────────────────────────────────────

struct Args {
    data_dir: PathBuf,
    launch: PathBuf,
}

fn parse_args(args: &[OsString]) -> Option<Args> {
    if args.get(1)?.to_str()? != ARG {
        return None;
    }
    let mut data_dir = None;
    let mut launch = None;
    let mut rest = args[2..].iter();
    while let Some(flag) = rest.next() {
        match flag.to_str()? {
            DATA_DIR_ARG => data_dir = Some(PathBuf::from(rest.next()?)),
            LAUNCH_ARG => launch = Some(PathBuf::from(rest.next()?)),
            _ => return None,
        }
    }
    let args = Args {
        data_dir: data_dir?,
        launch: launch?,
    };
    (args.data_dir.is_absolute() && args.launch.is_absolute()).then_some(args)
}

/// Run as the watchdog when this process was started as one. Returns whether it
/// was; the caller then exits instead of starting Ember.
pub fn run_if_requested() -> bool {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.get(1).and_then(|arg| arg.to_str()) != Some(ARG) {
        return false;
    }
    if let Some(args) = parse_args(&args) {
        watch(&args);
    }
    true
}

fn log(data_dir: &Path, line: &str) {
    let path = data_dir.join(LOG_FILE);
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() > MAX_LOG_BYTES) {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{} {line}", chrono::Utc::now().to_rfc3339());
    }
}

/// How long each stage of [`watch`] waits. The production values are the
/// constants above; tests shorten them.
#[derive(Clone, Copy)]
struct Timings {
    parent_exit: Duration,
    relaunch: Duration,
    settle: Duration,
    poll: Duration,
    sleep_gap: Duration,
    retry: Duration,
}

const TIMINGS: Timings = Timings {
    parent_exit: PARENT_EXIT_DEADLINE,
    relaunch: RELAUNCH_DEADLINE,
    settle: SETTLE_PERIOD,
    poll: POLL,
    sleep_gap: SLEEP_GAP,
    retry: RELAUNCH_RETRY,
};

/// What the watchdog ended up doing.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Ember never exited, so no install started.
    NeverExited,
    /// The installer brought Ember back.
    CameBack,
    /// Something brought Ember back, but it exited before restoring its
    /// session, so the watchdog started it once more.
    StartedAgain,
    /// Nothing did, so the watchdog started Ember itself.
    Relaunched,
    /// There was nothing it could start.
    NothingToLaunch,
    /// The install failed with Ember still running, which told it to stop.
    StoodDown,
}

fn watch(args: &Args) {
    use tauri::utils::config::BundleType;
    let timings = match tauri::utils::platform::bundle_type() {
        Some(BundleType::Msi) => Timings {
            relaunch: MSI_RELAUNCH_DEADLINE,
            ..TIMINGS
        },
        _ => TIMINGS,
    };
    watch_with(args, timings);
}

/// Sleep for `interval`, and say whether the machine slept through it.
fn nap(interval: Duration, timings: Timings) -> bool {
    let started = Instant::now();
    std::thread::sleep(interval);
    started.elapsed() >= interval + timings.sleep_gap
}

fn watch_with(args: &Args, timings: Timings) -> Verdict {
    if !args.launch.is_file() {
        log(&args.data_dir, "The executable to relaunch does not exist; nothing to do");
        return Verdict::NothingToLaunch;
    }
    log(&args.data_dir, "Watching for Ember to exit for its update");

    let mut waiting = Instant::now();
    loop {
        if stood_down(&args.data_dir) {
            log(&args.data_dir, "The install failed with Ember still running; standing down");
            return Verdict::StoodDown;
        }
        if matches!(lock_is_held(&args.data_dir), Ok(false)) {
            break;
        }
        if waiting.elapsed() >= timings.parent_exit {
            log(
                &args.data_dir,
                "Ember is still running: it never exited for the install, or restarted \
                 between two checks; nothing to watch",
            );
            return Verdict::NeverExited;
        }
        if nap(timings.poll / 2, timings) {
            log(&args.data_dir, "The machine slept; waiting as long again for Ember to exit");
            waiting = Instant::now();
        }
    }

    log(&args.data_dir, "Ember exited; waiting for it to come back");
    let mut waiting = Instant::now();
    while waiting.elapsed() < timings.relaunch {
        let slept = nap(timings.poll, timings);
        if stood_down(&args.data_dir) {
            log(&args.data_dir, "The install failed and Ember was quit; standing down");
            return Verdict::StoodDown;
        }
        if matches!(lock_is_held(&args.data_dir), Ok(true)) {
            log(&args.data_dir, "Ember is running again");
            if settled(args, timings) {
                return Verdict::CameBack;
            }
            log(
                &args.data_dir,
                "Ember exited before restoring its session; starting it once more",
            );
            relaunch(args, timings);
            return Verdict::StartedAgain;
        }
        if slept {
            log(&args.data_dir, "The machine slept; giving the installer as long again");
            waiting = Instant::now();
        }
    }

    log(&args.data_dir, "Ember did not come back after the update; starting it");
    relaunch(args, timings);
    Verdict::Relaunched
}

/// Whether an Ember that came back stays up until it has taken the resume
/// file. Without one there is no telling a failed start from a quick quit,
/// and it counts as settled.
fn settled(args: &Args, timings: Timings) -> bool {
    let resume = args.data_dir.join(crate::auto_update::resume::RESUME_FILE);
    let watching = Instant::now();
    while resume.exists() && watching.elapsed() < timings.settle {
        if matches!(lock_is_held(&args.data_dir), Ok(false)) {
            return !resume.exists();
        }
        std::thread::sleep(timings.poll);
    }
    true
}

/// Start the installed Ember, once more after a pause if that fails.
fn relaunch(args: &Args, timings: Timings) {
    let start = || detach(&mut std::process::Command::new(&args.launch));
    if let Err(error) = start() {
        log(&args.data_dir, &format!("Could not start Ember: {error}; trying once more"));
        std::thread::sleep(timings.retry);
        if let Err(error) = start() {
            log(&args.data_dir, &format!("Could not start Ember: {error}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let unique = format!(
            "ember-watchdog-{}-{}-{name}",
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

    #[test]
    fn only_a_complete_absolute_watchdog_command_line_is_accepted() {
        let data = std::env::temp_dir();
        let exe = std::env::current_exe().unwrap();
        let (data, exe) = (data.to_str().unwrap(), exe.to_str().unwrap());

        let ok = parse_args(&os(&["ember", ARG, DATA_DIR_ARG, data, LAUNCH_ARG, exe])).unwrap();
        assert_eq!(ok.data_dir, PathBuf::from(data));
        assert_eq!(ok.launch, PathBuf::from(exe));

        assert!(parse_args(&os(&["ember"])).is_none(), "an ordinary launch");
        assert!(parse_args(&os(&["ember", ARG, DATA_DIR_ARG, data])).is_none(), "no launch target");
        assert!(parse_args(&os(&["ember", ARG, DATA_DIR_ARG, "relative", LAUNCH_ARG, exe])).is_none());
        assert!(parse_args(&os(&["ember", ARG, "--other", data])).is_none());
        assert!(parse_args(&os(&["ember", "ed2k://|file|x|1|00|/", ARG])).is_none());
    }

    #[test]
    fn the_lock_tells_a_running_ember_from_an_exited_one() {
        let dir = scratch_dir("lock");
        assert!(!lock_is_held(&dir).unwrap(), "nobody holds it yet");

        let holder = open_lock(&dir).unwrap();
        holder.try_lock_exclusive().unwrap();
        assert!(lock_is_held(&dir).unwrap(), "a running Ember holds it");
        assert!(lock_is_held(&dir).unwrap(), "and probing does not take it away");

        FileExt::unlock(&holder).unwrap();
        drop(holder);
        assert!(!lock_is_held(&dir).unwrap(), "an exited Ember releases it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    const FAST: Timings = Timings {
        parent_exit: Duration::from_millis(600),
        relaunch: Duration::from_millis(600),
        settle: Duration::from_millis(600),
        poll: Duration::from_millis(50),
        sleep_gap: Duration::from_secs(60),
        retry: Duration::from_millis(50),
    };

    /// Something harmless that exits at once, standing in for Ember.
    fn harmless_exe() -> PathBuf {
        if cfg!(windows) {
            let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
            PathBuf::from(root).join(r"System32\whoami.exe")
        } else {
            PathBuf::from("/bin/true")
        }
    }

    fn hold(dir: &Path) -> File {
        let file = open_lock(dir).unwrap();
        file.try_lock_exclusive().unwrap();
        file
    }

    #[test]
    fn an_ember_that_never_exits_is_left_alone() {
        let dir = scratch_dir("never-exits");
        let _running = hold(&dir);
        let args = Args { data_dir: dir.clone(), launch: harmless_exe() };
        assert_eq!(watch_with(&args, FAST), Verdict::NeverExited);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ember_the_installer_brings_back_is_left_alone() {
        let dir = scratch_dir("comes-back");
        let old = hold(&dir);
        let args = Args { data_dir: dir.clone(), launch: harmless_exe() };
        let relaunch_dir = dir.clone();
        let installer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(old);
            std::thread::sleep(Duration::from_millis(150));
            let new = hold(&relaunch_dir);
            std::thread::sleep(Duration::from_millis(800));
            drop(new);
        });
        assert_eq!(watch_with(&args, FAST), Verdict::CameBack);
        installer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The new build takes the lock first thing, then fails opening its
    /// database, before it reaches the resume file.
    #[test]
    fn an_ember_that_exits_before_restoring_its_session_is_started_once_more() {
        let dir = scratch_dir("fails-setup");
        std::fs::write(dir.join(crate::auto_update::resume::RESUME_FILE), b"{}").unwrap();
        let old = hold(&dir);
        let args = Args { data_dir: dir.clone(), launch: harmless_exe() };
        let relaunch_dir = dir.clone();
        let installer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(old);
            std::thread::sleep(Duration::from_millis(150));
            let new = hold(&relaunch_dir);
            std::thread::sleep(Duration::from_millis(200));
            drop(new);
        });
        assert_eq!(watch_with(&args, FAST), Verdict::StartedAgain);
        installer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ember_quit_after_restoring_its_session_is_not_started_again() {
        let dir = scratch_dir("quit-after-resume");
        let resume = dir.join(crate::auto_update::resume::RESUME_FILE);
        std::fs::write(&resume, b"{}").unwrap();
        let old = hold(&dir);
        let args = Args { data_dir: dir.clone(), launch: harmless_exe() };
        let relaunch_dir = dir.clone();
        let installer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(old);
            std::thread::sleep(Duration::from_millis(150));
            let new = hold(&relaunch_dir);
            std::thread::sleep(Duration::from_millis(150));
            std::fs::remove_file(&resume).unwrap();
            drop(new);
        });
        assert_eq!(watch_with(&args, FAST), Verdict::CameBack);
        installer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `Instant` keeps counting while the machine sleeps, and the installer
    /// sleeps with it: on waking it still needs its time.
    #[test]
    fn a_machine_that_slept_gives_the_installer_its_time_again() {
        let every_poll_a_sleep = Timings { sleep_gap: Duration::ZERO, ..FAST };
        let dir = scratch_dir("slept");
        let old = hold(&dir);
        let args = Args { data_dir: dir.clone(), launch: harmless_exe() };
        let relaunch_dir = dir.clone();
        let installer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(old);
            std::thread::sleep(FAST.relaunch * 3);
            let new = hold(&relaunch_dir);
            std::thread::sleep(Duration::from_millis(800));
            drop(new);
        });
        assert_eq!(watch_with(&args, every_poll_a_sleep), Verdict::CameBack);
        installer.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_launch_that_fails_is_tried_once_more() {
        let dir = scratch_dir("cannot-start");
        let not_ember = dir.join("not-ember.exe");
        std::fs::write(&not_ember, b"not an executable").unwrap();
        let old = hold(&dir);
        let args = Args { data_dir: dir.clone(), launch: not_ember };
        let exit = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(old);
        });
        assert_eq!(watch_with(&args, FAST), Verdict::Relaunched);
        exit.join().unwrap();
        let log = std::fs::read_to_string(dir.join(LOG_FILE)).unwrap();
        assert_eq!(log.matches("Could not start Ember").count(), 2, "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_ember_nothing_brings_back_is_started_again() {
        let dir = scratch_dir("relaunch");
        let old = hold(&dir);
        let args = Args { data_dir: dir.clone(), launch: harmless_exe() };
        let exit = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(old);
        });
        assert_eq!(watch_with(&args, FAST), Verdict::Relaunched);
        exit.join().unwrap();
        let log = std::fs::read_to_string(dir.join(LOG_FILE)).unwrap();
        assert!(log.contains("starting it"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_install_that_kept_ember_running_stands_the_watchdog_down() {
        let dir = scratch_dir("stand-down");
        let old = hold(&dir);
        std::fs::create_dir_all(dir.join(DIR)).unwrap();
        let args = Args { data_dir: dir.clone(), launch: harmless_exe() };
        let marker = dir.join(DIR).join(STAND_DOWN_FILE);
        let user = std::thread::spawn(move || {
            // The install fails, Ember says so, and the user quits later.
            std::fs::write(&marker, b"1").unwrap();
            std::thread::sleep(Duration::from_millis(150));
            drop(old);
        });
        assert_eq!(watch_with(&args, FAST), Verdict::StoodDown);
        user.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_executable_is_never_started() {
        let dir = scratch_dir("missing");
        let args = Args { data_dir: dir.clone(), launch: dir.join("no-such-ember.exe") };
        assert_eq!(watch_with(&args, FAST), Verdict::NothingToLaunch);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
