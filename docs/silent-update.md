# Silent updates

Design for letting Ember update itself while nobody is using it, then reopen
exactly as the user left it.

**Status:** implemented for 1.7.1, in the seven steps under
[Implementation order](#implementation-order). What still needs a real install
and a published release to confirm is in `docs/release-checklist-1.7.1.md`.

## What the user gets

One switch in **Settings → About**: **Silent updates**, off by default.

With it on, a new release is downloaded and verified in the background. Ember
then waits until nothing is transferring and the user has not touched Ember for
a while, warns for one minute with a way to cancel, closes, updates, and
reopens:

- in the same window state: hidden in the tray, minimized, maximized or at the
  same size and position, on the same page;
- connected to the same eD2K server, if it was connected;
- with downloads in the same state (running ones resume, paused and stopped ones
  stay that way);
- with the same search tabs and chat window;
- holding the same upload waiting queue, so peers waiting on this user keep
  their place.

If anything goes wrong, Ember comes back on the old version in the same state,
says the update did not install, and stops trying that version silently. It
never forces a restart while bytes are moving, and never ends up closed and not
running.

The cases this is built for are the people who leave Ember in the tray for
weeks. Before this, they never learned about an update at all, because Ember
only checked once, a few seconds after launch, from a webview timer.

## Scope

**Supported:** Windows per-user NSIS installs (the default installer), and the
Linux AppImage.

**Not supported, and shown as such in Settings:**

- **Linux `.deb`** (and `.rpm`). The update is installed with `dpkg -i` behind a
  `pkexec` password prompt (`write_handoff_record` comment in
  `src-tauri/src/commands/updater.rs`). Nobody is there to type it. The switch is
  disabled with a hint that says so and that Ember will tell the user when an
  update is available.
- **MSI installs.** Per-machine MSI installs need elevation (UAC).

Which of these applies is read from the bundle marker Tauri writes into each
package (`tauri::utils::platform::bundle_type`, in `auto_update::silent::support`).
Development builds are never supported.

**Not in the first version:** installing on quit, preferred update hours, and a
separate "download but don't install" mode. None of them is needed for the
feature to work well, and each can be added on top of the scheduler below.

## How it works

Everything that decides *when* lives in Rust. A hidden webview is throttled by
the OS, so a countdown or idle timer running in JavaScript would drift or stop
exactly in the tray-hidden case this feature exists for. The frontend only
renders state that the backend emits and sends the user's choices back.

### States

The backend module `src-tauri/src/auto_update/` (`scheduler`, `silent`,
`resume`, `watchdog`, `record`) owns one state machine, driven once a second by
`silent.rs` (`Phase`):

| State | Meaning | Leaves when |
|-------|---------|-------------|
| `Off` | Setting off, or platform unsupported | Setting turned on |
| `Idle` | No update known | Periodic check finds one → `Preparing` |
| `Preparing` | Downloading and verifying the artifact | Verified and staged → `Waiting`; failure → retried after an hour |
| `Waiting` | Update ready; waiting for the idle conditions | Conditions hold continuously for the quiet period → `Countdown` |
| `Countdown` | 60-second warning on screen | Timer ends or "Update now" → `Installing`; Not now → `Postponed`; Skip → `Held`; a transfer moving → `Waiting` |
| `Postponed` | User said "Not now" | 24 h pass → `Waiting` |
| `Held` | Version skipped, or its silent install failed once | A newer release |
| `Installing` | Resume file written, shutdown running, installer handed off | Process exits (success path), or failure → relaunch current version |

Ember persists the scheduler's own record in `silent-update-state.json` in the
data directory. The record holds `last_check_at`, `postponed_until`,
`skipped_version`, `failed_version`, `ready_since { version, at }` (for the
week-long-wait notice) and `last_success { from, to, at }`. Like
`update-handoff.json`, the file is untrusted: it can only postpone or suppress
an update, never pick what gets installed.

### Periodic check

Fifteen seconds after launch, and then every 5 minutes, the scheduler
(`src-tauri/src/auto_update/scheduler.rs`) checks whether an update check is due
under `update_check_frequency` (hourly / daily / weekly / monthly), using
`last_check_at` from the state file. If one is due, it calls `run_check`, the
same function behind `secure_updater_check`, sharing `UpdaterService.operation`,
so it can never race a manual check or install. Every attempt, manual or
automatic, stamps `last_check_at`.

This check runs for **everyone with `auto_check_updates` on**, not only silent
update users. Without silent updates it only raises the existing "update
available" notice (`UpdateNotice.svelte`). That fixes, for everyone, the problem
that a long-running Ember never hears about new releases. The frontend's own
launch-time check moves over to this timer. Its `localStorage` timestamp
(`ember.updater.lastCheckedAt` in `src/lib/stores/updater.ts`) is replaced by the
backend's `last_check_at`.

The result is emitted as `ember:updater-check-result`. The backend also keeps
the last check's result, so a webview that was not listening when it was
emitted (still starting up, or reloaded since) fetches it with
`get_last_update_check_result` once its listener is registered, instead of
waiting for the next due check, which may be a month away. The offer in it is
brought up to date with what the updater still holds.

Silent updates require update checks, so turning **Silent updates** on also
turns on **Check for updates automatically**, and turning that off also turns
silent updates off.

### Prepare, then install

`secure_updater_install` used to download and install in one call. It is split
into two steps (`commands/updater.rs`):

1. **`prepare_staged`** downloads the artifact, verifies it against the signed
   manifest (same key, same rollback floor, same security epoch), and stages it
   on disk in the `updates/` staging directory, on every platform. A copy
   already staged for the same signed artifact, possibly by an earlier session,
   is reused once it re-verifies. Holding a 100 MB bundle in memory for days
   while waiting for idle is not acceptable, so the bytes live on disk; only if
   staging fails are they kept in memory, so an update the user asked for is
   not refused.

   A download can take up to 30 minutes, so it holds only the staging lock
   (`UpdaterService.staging`), never the operation lock that checks and
   installs share. It copies what it needs out of the pending update, downloads
   and stages, and then records the result against the pending update only if
   that is still the same signed artifact; if a check replaced it meanwhile,
   the staged copy is deleted and the new one is prepared on the next tick.
   Only one holder of the staging lock ever writes to `updates/`, so a
   background preparation and a manual install never write the same file. An
   **Install** pressed during a background download waits for it, showing that
   download's progress, and then installs the copy it produced.
2. **`install_locked`** re-checks the persisted security floor, re-reads the
   staged bytes and re-checks their size, hash and signature. Only then does it
   write the Windows `update-handoff.json` record (so the recovery path already
   built for stalled installs keeps working unchanged), write the resume file,
   run the graceful shutdown, start the watchdog and hand off to the installer.

The silent path reaches these through `prepare_pending_update` and
`install_prepared_update`.

The manual **Install** button calls both steps back to back, so its behaviour
does not change. Silent mode runs step 1 as soon as an update is found and step
2 only after the countdown. As a result, the downtime the user experiences is
shutdown, install and relaunch — no download in the middle.

A later check that finds the same signed artifact again (same URL, hash, size
and signature) keeps what was prepared for it, so an hourly check neither
re-hashes the staged bundle nor interrupts a countdown. If a download keeps
failing, it is retried hourly and the ordinary "update available" notice is
shown meanwhile, so the user can still install it. If a newer release appears
while one is staged, the scheduler prepares the newer one and discards the old. If the security floor rises past the staged version,
the staged update is dropped, exactly as the manual path does today
(`updater_pending_below_floor`).

### When Ember counts as idle

The countdown starts only when **all** of the following hold at once. Each is
measured on its own clock, so the longest of them is the wait, not their sum:

1. **Nothing has moved for 10 minutes.** No download row with `speed > 0`; no
   upload row with `speed > 0`; no Ember Transfer (room or friend) in progress;
   and combined throughput below 2 KiB/s, which also catches a remote slot
   whose first bytes have not yet shown up as a row's speed.
2. **No local work that must finish**, for the same 10 minutes. Nothing in
   `Verifying`, `Completing` or `Hashing`, and no shared-folder scan or hash
   top-up running (the same tasks `run_graceful_shutdown` cancels in
   `src-tauri/src/lib.rs`).
3. **The user is away from Ember.** No keyboard or mouse input in any Ember
   window, and no Ember window gaining focus, for 10 minutes. A hidden or
   minimized window counts as no input. The frontend reports input to the
   backend at most once every 30 seconds.
4. **The session has settled.** At least 30 minutes since Ember launched, so an
   update never lands right after the user opened it.
5. **Not postponed or skipped** under the state file.

A machine that sleeps restarts all of this. More than 15 seconds between the
driver's one-second ticks, by either the monotonic or the wall clock, counts as
a sleep: the quiet period and the away time start over and a running countdown
is abandoned. Windows' monotonic clock keeps counting through sleep, so without
this a countdown would end the moment the lid opened; Linux's stops, so one
would sit frozen at 0:00.

This is a new predicate, not `count_working_transfers` in
`src-tauri/src/background.rs`. That function is tuned for the sleep inhibitor
and counts every non-`Stalled` `Active` download as working, including a
download that is only sitting in other peers' queues. The long-tail users this
feature is for have downloads like that indefinitely, so reusing it would mean
they are never idle. The question here is narrower: *would restarting now cut
off bytes in flight?*

Waiting downloads are safe to restart through:

- `.part` / `.part.met` and the database already restore every download in its
  previous state (`event_loop/resume_downloads.rs`).
- Remote eMule clients keep a waiting peer for an hour after its last request
  (`MAX_PURGEQUEUETIME`), and Ember re-asks from `sources.met` on relaunch. A
  one- or two-minute restart therefore keeps Ember's place in other users'
  queues.

**No forced restarts.** If an update has been waiting 7 days without ever
reaching idle, Ember does not force it. It shows the normal "update available"
notice once, with a line saying the update is waiting for transfers to pause,
and keeps waiting.

### The one-minute warning

The warning is visible wherever the user can see Ember, and never pulls a
hidden window in front of whatever they are doing.

- **Window visible:** a modal countdown dialog built on `ConfirmDialog.svelte`.
  - Title: "Ember will update in 0:58"
  - Body: "Ember 1.8.0 is ready. Ember will close, update and reopen the way you
    left it. Your downloads carry on where they stopped."
  - Buttons: **Update now** and **Not now** (postpone 24 h), plus a
    **Skip this version** link.
- **Window hidden, minimized or unfocused:** one OS notification through the
  existing notification path (`src/lib/notifications.ts`, category
  `silent_update`): "Ember will update in 1 minute. Open Ember or use its tray
  icon to cancel." It follows only the master `notifications_enabled` switch.
  The notification plugin reports no clicks on desktop, so opening Ember from
  the tray or the taskbar is what brings up the dialog.
- **Always:** the tray menu gains a **Cancel update (0:45)** item above
  **Show** / **Quit**, and the tray tooltip reads "Ember ⟳ 0:45" (a symbol and
  the time, like the rest of the tooltip, which the backend composes without
  knowing the user's language). The menu's own words are in the user's
  language: the frontend sends the three labels (`set_tray_labels`, in
  `src-tauri/src/tray.rs`) on every page load, and a language change reloads
  the page. The backend checks each one (length, no control characters, the
  `{time}` placeholder exactly once in the cancel label), keeps English for any
  it refuses and until the first arrive, and rebuilds the menu, keeping a
  running countdown's entry. The tray is the one surface that works in every
  case, including notifications turned off.

The countdown aborts by itself if a transfer starts moving bytes, or local work
such as hashing starts. It returns to `Waiting` without counting as a
postpone, and a toast says "Update postponed: Ember is busy again." Input does
*not* abort it: the dialog is how a user who is there answers it, and clicking
it is input.

When the countdown ends (or **Update now** is pressed), the install starts only
once it holds the updater's operation lock, taken without waiting. If a check
or a manual install holds it, the dialog and the tray entry stay up at 0:00 and
the next tick tries again, so a **Not now** or a transfer arriving meanwhile is
still honoured. Once the lock is held, the state file is re-read and activity
sampled again; a postpone, a skip or a busy machine found then wins over the
clock.

**Not now** (or Escape) postpones for 24 hours. **Skip this version** stops
silent installs of that version; the normal "update available" notice still
shows it, and the next newer release is handled normally. While silent updates
are going to install an update, the corner "update available" notice stays
hidden; it comes back when the update is postponed or held, or after a week of
waiting.

The driver is `src-tauri/src/auto_update/silent.rs`; the dialog is
`src/lib/components/SilentUpdateCountdown.svelte` and the store
`src/lib/stores/silentUpdate.ts`. Input is reported from every Ember window by
`src/lib/userActivity.ts` (at most every 30 seconds), and any window gaining
focus counts as input too.

### Returning to the same state

Just before shutdown, while the state is still live, `install_locked` writes
`update-resume.json` to the data directory. The next launch reads it once,
deletes it, and applies it.

```json
{
  "schema": 1,
  "written_at": 1790000000,
  "reason": "silent",
  "from_version": "1.7.1",
  "target_version": "1.8.0",
  "window": {
    "visibility": "tray",
    "maximized": false,
    "bounds": { "x": 120, "y": 80, "width": 1400, "height": 900 },
    "chat_window_open": true
  },
  "ed2k": { "ip": "203.0.113.10", "port": 4661 },
  "ui": {
    "route": "/transfers",
    "search_tabs": "...same payload the search store keeps in sessionStorage..."
  },
  "launch_links": ["...SHA-256 of each deep link this process was started with..."]
}
```

`reason` is `silent` or `manual`, and `visibility` is one of `tray`,
`minimized` or `normal`. `bounds` is in physical pixels: the top-left of the
window's outer frame and the size of its client area, the pair the window is
restored with (restoring the outer size as the client size would grow the window
by its title bar and borders on every update). It is absent while maximized or
minimized; a maximized window records `maximized_center` instead, the centre of
its maximized frame, which names the monitor to maximize on again. `ed2k` is
absent when the user was not on a server. The chat window keeps its own
position.

`launch_links` exists because the relaunch is handed the old process's
arguments again: the NSIS installer is passed them as `/ARGS`
(`tauri-plugin-updater`), and `AppHandle::restart` reuses them too. An Ember
first opened by clicking an `ed2k://` link would otherwise offer that link again
after every update, and bring a tray-hidden window to the front to do it. The
arguments cannot be cleaned at the source, since the plugin reads them from the
app's startup environment and offers no way to replace them. Skipping every
cold-start link after an update would be simpler but would also swallow a link
the user clicked while the update was relaunching Ember. So for ten minutes
after the launch that reads the file, stale file or not, Ember drops each link
whose digest the file lists, once, and offers any other. That holds for the
launch's own arguments and for links the single-instance plugin forwards from a
later launch, which is how the installer's relaunch arrives when the watchdog's
relaunch or the user opening Ember got there first.

The installer hands the arguments back without the quotes that kept each one
whole (the NSIS template reads `/ARGS` with `GetOptions`, which strips them, and
passes the rest on as one string), so an argument holding spaces comes back in
pieces. The file therefore also lists the pieces that still read as links, and a
`.emulecollection` path is only taken as a deep link when it is absolute: what is
left of `C:\Users\John Smith\x.emulecollection` after the split is the relative
`Smith\x.emulecollection`, and a relative path would be opened against the
running Ember's working directory anyway.

On launch it is applied like this:

- **Window.** `tauri.conf.json` gets `"visible": false` on the main window, so
  every launch starts hidden and `setup` decides what to show
  (`auto_update::resume::show_main_window`, called once the tray exists). On a
  normal launch it shows the window, as happens now. From a resume file it:
  - restores the bounds, position first, since a move onto a monitor with
    another scale rescales whatever size the window has by then; unless the
    title bar would land on a monitor that is no longer attached, in which case
    the window opens centred;
  - maximizes the window if it was maximized, after centring it on the monitor
    `maximized_center` names if that monitor is still attached — for a window
    going back to the tray, the first time it is shown, since maximizing a
    hidden window shows it on some platforms. A tray session waiting for that
    first showing still counts as maximized if another update comes first;
  - then shows it, minimizes it, or leaves it hidden in the tray. Without a tray
    icon it is always shown, since a hidden window could never be reached.

  This is also the point where `launch_maximized` is applied (`lib.rs`), so both
  go through one path. Without this, every silent update would pop Ember onto
  the desktop of someone who keeps it in the tray, which is the one thing they
  would notice.

  Two gaps remain. A maximized or minimized window's normal size and place are
  not known, so un-maximizing after an update gives the default size, and a
  minimized window comes back on the primary monitor. Tauri does not report the
  normal bounds, and tracking them from move and resize events records the
  maximized frame, since on Windows the move arrives before the window counts as
  maximized; reading them needs `GetWindowPlacement`. And a minimized window is
  shown and then minimized, so it appears for a moment; `SetWindowPlacement`
  with `SW_SHOWMINNOACTIVE` would avoid that, but bypassing the window library
  leaves its own state saying the window is hidden, and its next change would
  hide it.
- **Server.** If `ed2k.connected` was true, the network task starts with
  `pending_auto_connect_server` set and that server as its explicit target,
  whatever `auto_connect_server` says (`network/mod.rs`, the deferred
  auto-connect block), provided that server is still in the user's own server
  list. If that server refuses, Ember reports it the way a failed auto-connect
  is reported today and does not hop to another server; the user chose that
  one. A connection that was still in progress at shutdown, or waiting out an
  auto-reconnect backoff, counts as connected, because that was the user's
  intent (`NetworkCommand::GetEd2kServerIntent`). KAD, the Ember Network,
  friends and channels already reconnect by themselves.
- **Page and search tabs.** The frontend fetches both through a new
  `take_update_resume_ui` command at boot. It navigates to the route if it is on
  an allowlist of top-level app routes, and hydrates the search store through the
  same validation `searchPersistence.ts` applies to `sessionStorage`. Searches
  that were still running come back with their results, not re-run.
- **Chat window.** If it was popped out and the main window comes back visible,
  it is reopened popped out at its old bounds. Chat tabs already persist in
  `localStorage`.

The page and search tabs are collected just before the shutdown, for manual and
silent installs alike (`install_locked` in `commands/updater.rs`): the backend
emits `ember:resume-ui-request` and waits up to 3 seconds for the frontend to
answer with its current page and tabs (`src/lib/updateResume.ts`). If a
throttled webview does not answer, they are skipped rather than holding up the
update. Because the file is written for manual installs too, pressing
**Install** also comes back the way the user left Ember.

**Upload waiting queue.** This lives only in memory today (`UploadQueueRef` in
`network/ed2k/upload.rs`), so every restart drops everyone waiting on this user.
On *every* graceful shutdown, not only updates, Ember saves a snapshot to
`upload-queue.json` for each `QueueEntry`. Each entry holds:

- `user_hash`, `file_hash`, `last_ip`, `tcp_port`, `udp_port`, `crypt_options`
  and `is_high_id`;
- `join_time` and `last_request`, converted to wall-clock time.

On launch, entries whose `last_request` is within `MAX_PURGEQUEUETIME_SECS` are
restored. Ember keeps the wait time, which is their seniority, but not their
standing: `ember_verified` and `is_friend_slot` start `false` and are
re-established when the peer re-asks on its normal ~29-minute cadence. Entries
past the purge window are discarded, as eMule would. This is the difference
between "Ember came back" and "Ember came back and nobody lost their place".

Restored rows do not join the live queue straight away
(`network/ed2k/upload_queue_store.rs`). At launch the library index is empty
until the startup scan has run, so the queue's own purge would evict every
restored waiter as one for a file Ember does not share, and a push-grant dialled
in that window would offer a file it cannot yet find. They are held until the
startup scan has put the library into the index and says so
(`NetworkCommand::StartupLibraryIndexed`, sent at once when there are no shared
folders). A reconcile is not enough: a settings save can send one while
discovery is still running. A 20-minute fallback covers a scan that fails
without saying so. Only rows for files Ember shares or is downloading are then
merged, under the live queue's own per-IP and size caps. The queue holds one row
per peer, so a peer that re-asked before the merge, for any file, keeps its live
row and inherits the older wait only from the same address; the saved file is
also reduced to one row per peer. Rows naming a private or special-use address
are dropped, since a restored HighID row is one the queue may dial.

**Not restored, on purpose:** open dialogs, unsaved Settings edits, and chat
drafts. The idle rule (no input for 10 minutes) means none of these should exist
when an update starts.

### Validating the resume file

Anything running as the user can write the data directory, so the resume file is
input, not instructions:

- It is ignored if `written_at` is more than 2 hours old, since that means the
  machine rebooted or something else intervened. The version comparison still
  runs, so a failure is reported.
- `route` must match the allowlist; anything else lands on the default page.
- The server address goes through the same IP filter and special-use-range checks
  as any other server connect.
- The search payload is size-capped and parsed by the existing restore path.
- The file never names an executable, a URL or a version to install.

### After the relaunch

The resume file carries `from_version` and `target_version`, and the launch
compares them with its own version:

- **Running `target_version`:** success. The state file records `last_success`.
  The next time the user opens the window, a toast says "Ember updated to 1.8.0
  while you were away". There is no OS notification, since the user is away.
  Settings → About shows "Updated to 1.8.0 automatically on …".
- **Running `from_version`:** the install did not happen. The state file records
  `failed_version`, so that version is never tried silently again. The existing
  stalled-install notice (`checkUpdateHandoff` / `phase: 'stalled'`) offers
  **Run installer** as it does today. The session is still restored first,
  because a failed update must not also cost the user their state.

The resume file is best-effort, and the full disk that stops it being written is
also a likely reason for an install to fail. So the silent path records the
attempt in `silent-update-state.json` (`attempting { from, to, at }`) before
handing over, and a launch with no resume file judges the attempt by the version
it is running, with the same notice and the same `failed_version`. It is written
only once the silent install holds the updater's operation lock, so a manual
**Install** that got there first is never reported as an update that happened
while the user was away.

### Failure safety

The worst outcome for an unattended update is that Ember closes and nothing
starts again. It could then sit closed for days, sharing nothing, before the user
notices. Each path is covered as follows.

**Install call returns an error** (the AppImage rewrite failed, or on Windows the
plugin could not write the installer out of the bundle). The graceful shutdown
has already stopped the network services. Today that leaves the error
`updater_install_failed_services_stopped`. In silent mode Ember instead restarts
itself (`AppHandle::request_restart`, which lets the event loop exit and run the
shutdown; `AppHandle::restart` called from the driver's task would park a
runtime worker forever). The resume file is already written, so the old version
comes back in the same state and reports the failure.

A Windows `ShellExecuteW` failure does *not* come back as an error: the plugin
ignores its result and exits the process either way. That case, the installer
never starting, is the watchdog's, below.

**Windows installer handed off but never starts or never finishes** (Windows
refuses to run it, antivirus blocks it, the user kills it, or it fails midway). The NSIS installer only relaunches Ember on
success: `.onInstSuccess` runs the app when `/R` is present, and the updater
passes `/P /R /UPDATE /ARGS …`. So before handing off, Ember starts a
**watchdog**:

- A copy of the current executable is written to
  `update-watchdog/ember-update-watchdog.exe` in the data folder and started,
  detached, with `--update-watchdog --data-dir <dir> --launch <installed exe>`
  (`src-tauri/src/auto_update/watchdog.rs`). `main.rs` checks for that flag
  before building Tauri, so watchdog mode starts no webview, no single-instance
  registration and no network. It keeps a short log in
  `update-watchdog.log`.
- It runs **outside the install directory and under a different file name**.
  Running from the installed `ember.exe` would lock the file the installer must
  replace, and the installer's running-app check would kill it by path.
- It waits up to 3 minutes for Ember to exit, then up to 5 minutes for Ember to
  be running again (30 for an MSI install, whose elevation prompt waits as long
  as nobody answers it; an Ember started meanwhile would hold the files the
  install must replace). It judges both by probing `instance.lock`, an exclusive
  lock
  every Ember takes as the very first step of startup (before migrations or an
  antivirus scan of a new build can hold it up, and retrying briefly, so the
  probe can never make it give up) and holds for its lifetime. It does not look
  up processes by name,
  and it does not launch a second copy that would trip the single-instance
  plugin, whose handler *shows* the window. It is only started by a process
  that holds the lock, so it can never mistake the Ember that started it for a
  relaunch.
- A poll that overruns by 15 seconds or more means the machine slept, and the
  wait in progress starts over. Windows' monotonic clock counts through sleep,
  so on waking every deadline would have passed while the installer, asleep
  just as long, had not moved on.
- An Ember that comes back is watched for up to 2 minutes more, until it has
  taken the resume file, which it does early in setup, once its database and
  settings have opened. One that lets go of the lock before then failed in its
  own setup, and the watchdog starts it once more. One that took the file and
  then exits was quit, and is left alone; so is one launched with no resume
  file to watch.
- If Ember is not running by the deadline, it launches the installed executable
  itself, using only the path it was given at spawn time, and tries once more
  ten seconds later if that fails. That Ember finds the resume file, restores
  the session, and reports the failed update. The watchdog then exits. The next
  Ember deletes the watchdog's copy a minute after it starts, and tries again
  each minute for ten minutes while the copy is still running: after a silent
  install that failed and restarted Ember, the watchdog can miss the moment
  nobody held the lock and polls on until its own deadline.
- A manual install whose installer call fails leaves Ember running and the user
  in charge, so Ember leaves a `stand-down` marker beside the watchdog's copy and
  the watchdog exits without relaunching anything, even after the user quits.

On the AppImage, the install runs in-process and returns a result, so no
watchdog is needed.

**Crash loop protection.** A version that fails silently once is never retried
silently (`failed_version`). The resume file is deleted before it is applied, so
a crash while applying it cannot loop.

### Quiet installer on Windows

`installMode: "passive"` shows a small NSIS progress window for the few seconds
the install takes, and the silent path uses it unchanged for now: the Tauri
NSIS template relaunches on `/R` in both passive and silent mode, but whether it
honours a quiet `/S` alongside the `/P` the configured mode already adds has not
been verified on a test VM. A brief progress bar with nobody at the keyboard is
harmless; a flag that stopped the relaunch would not be. Passing `/S` through the
updater builder's `installer_args` is the change to make once it is confirmed.

## Settings

A new field in `AppSettings` (`src-tauri/src/types.rs`), wired end to end:

- `silent_update_enabled: bool`, `#[serde(default)]` (false);
- `src/lib/types/index.ts`;
- the `update_settings` validation in `src-tauri/src/commands/settings.rs`;
- the About panel in `src/routes/settings/+page.svelte`;
- strings in all nine `messages/*.json` locales (see `docs/i18n.md`).

A `get_silent_update_status` command returns `supported` and a reason when it is
not, the current state, the staged version, `postponed_until`, and
`last_success`. The frontend never infers platform support itself.

About panel, under the existing update controls:

- **Silent updates** toggle. Hint: "When an update is ready, Ember waits until
  nothing is transferring and you are away, warns you for a minute, then updates
  and reopens the way you left it."
- A status line under it, one of:
  - "Downloading Ember 1.8.0 in the background" (or that it could not be
    downloaded yet)
  - "Ember 1.8.0 is ready — it will install when Ember is idle"
  - "Postponed until tomorrow, 3:10 PM" (with **Resume**)
  - "Ember 1.8.0 will not install by itself" (skipped, or failed once)
  - "Last updated automatically on 28 Sep 2026"
  - the unsupported reason

  With no update known (`Idle`) the line shows only the last automatic update,
  or nothing. There is no "Up to date" line here: `Idle` does not mean a check
  confirmed anything, and the update controls below already say "up to date"
  after a check that did.
- The existing **Check now**, **Install** and **Restart** buttons stay. A staged
  silent update can always be installed immediately with **Install**.

## Security

Silent mode adds no new trust. It installs only what the manual path would have
installed: the same signed manifest, the same public key, the same rollback
floor, and a re-check of the staged bytes immediately before handing them over.
It adds two new files the user account can write, the state file and the resume
file. Neither can choose what runs: the state file can only delay or suppress an
update, and the resume file is validated as described above. The watchdog
launches only the executable path it resolved itself.

## Implementation order

Each phase ships on its own and is useful without the next one. All seven are
done; each was its own commit.

1. **Periodic backend update check.** Scheduler skeleton, `last_check_at` in the
   state file, the launch-time check moved into the backend. Everyone with
   auto-check on starts hearing about updates while Ember stays running.
2. **Prepare / install split.** `prepare_staged` and `install_locked` in
   `commands/updater.rs`; the manual Install button calls both. No behaviour
   change yet.
3. **Resume state.** `update-resume.json` write and consume, hidden-by-default
   window with `setup` deciding visibility, server reconnect override, route,
   search tabs and chat window. The manual **Restart to update** path writes the
   same file, so manual updates also come back as the user left them.
4. **Upload queue snapshot.** Saved on every graceful shutdown and restored within
   the purge window. Benefits every restart, not only updates.
5. **Idle predicate, scheduler states, countdown.** Setting, dialog,
   notification, tray item and tooltip, postpone and skip.
6. **Failure safety.** Watchdog, `instance.lock`, self-restart on install error,
   `failed_version`.
7. **Release.** Settings copy in all locales (shipped with step 5, since the
   locale tests require every key everywhere), the Updates text, feature list
   and FAQ in `docs/index.html`, and `docs/release-checklist-1.7.1.md`. Ships
   with the switch off by default.

## Testing

**Unit tests (no clock, no network).**

- Idle predicate, driven by a table of transfer rows and timings:
  - a download waiting in remote queues counts as idle;
  - one byte per second of upload counts as busy;
  - hashing counts as busy;
  - a hidden window counts as away.
- The scheduler as a pure state machine with injected time: every transition in
  the table above, including abort on activity, postpone expiry, skip, the
  7-day notice, and a newer release arriving while one is staged.
- Resume file:
  - round trip;
  - stale file ignored but version still compared;
  - route off the allowlist;
  - oversized search payload;
  - special-use server address;
  - missing fields from an older schema.
- Upload queue snapshot: round trip, purge-window filtering, verified and friend
  flags cleared on restore.

**Manual runs on a Windows VM and Ubuntu 22.04, against a test manifest signed
with a test key.**

- Tray-hidden, connected to a server, three downloads (one running, one paused,
  one queued remotely), two search tabs, chat popped out. Update fires after the
  idle period and Ember comes back hidden, on the same server, with all of that
  intact.
- Countdown with the window visible, hidden, and with notifications off. Cancel
  from each surface. Start a download during the countdown and confirm it aborts.
- Maximized window, window on a monitor that is then disconnected, minimized to
  the taskbar.
- Failure drills:
  - delete the staged installer before hand-off;
  - block it with Defender;
  - kill the installer halfway.

  In each case Ember is running again within 5 minutes on the old version, in
  the same state, reports the failure, and does not retry.
- AppImage update and relaunch. Confirm the relaunch runs the new AppImage, not
  the old mount.
- `.deb` build shows the switch disabled with its reason.

## Open questions to settle during implementation

- Whether `/S` works alongside `/P` in the Tauri NSIS template (see "Quiet
  installer on Windows").
- Whether a restart (`AppHandle::request_restart`, which relaunches the same way
  `AppHandle::restart` does) resolves the AppImage path from `$APPIMAGE` or the
  mounted binary. If it is the mounted binary, relaunch through `$APPIMAGE`
  explicitly.
- Whether Ember Transfer and friend transfers appear in `TransferManager.active`.
  If not, the idle predicate reads their own state directly.
