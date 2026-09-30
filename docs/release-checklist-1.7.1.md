# 1.7.1 release checklist

What automated checks cannot cover before tagging `v1.7.1`: mostly silent
updates (`docs/silent-update.md`), which only show their real behaviour against
an installed build and a published release. Tick each box, and file anything
that fails before tagging rather than after.

## 0. Automated checks

- [ ] `npm test` and `npm run check` pass.
- [ ] `cargo clippy --tests` is clean and `cargo test --lib` passes in `src-tauri`.
- [ ] `node scripts/verify-release-policy.mjs` passes (1.7.1, Ember DHT wire
      version 4, security epoch 1).
- [ ] `node scripts/release-notes.mjs` prints the 1.7.1 notes, and they read
      correctly as Markdown.
- [ ] The download heading on the site says "Get Ember 1.7.1".

## 1. Test setup

Silent updates act on a real signed release, so these runs need two builds:
the one under test installed, and a newer one published to a test manifest
signed with a test key (swap the updater endpoint and public key in a local
build's `tauri.conf.json`; never ship that build). The session-settle and
quiet periods are 30 and 10 minutes; plan for waits, or run a local build with
`SETTLE_PERIOD` and `QUIET_PERIOD` in `auto_update/silent.rs` shortened.

Use a Windows 10 or 11 VM with the NSIS installer, and Ubuntu 22.04 with the
AppImage.

## 2. Periodic checks (all installs)

- [ ] With automatic checks on and Ember left open, a release published after
      launch is noticed within the cadence without restarting Ember.
- [ ] A manual Check postpones the next automatic check by the cadence.
- [ ] `silent-update-state.json` appears in the data folder with
      `last_check_at`.

## 3. Coming back the same way (manual Install)

Before pressing Install: window at a custom size and position, connected to a
server that is not the saved auto-connect one, three downloads (one
transferring, one paused, one only queued on remote peers), two search tabs,
the chat popped out, and a few peers waiting in the upload queue.

- [ ] After the update the window reopens at the same size and position, on
      the same page, connected to that server, with both search tabs and the
      chat popped out.
- [ ] Downloads are in the same states; the paused one is still paused.
- [ ] The Queue tab shows the earlier waiters once the library has loaded, with
      their waiting time kept.
- [ ] Repeat maximized, and minimized to the taskbar.
- [ ] Repeat hidden in the tray: Ember comes back hidden, with nothing flashing
      onto the desktop, and opening it from the tray shows it maximized if it
      was.
- [ ] Unplug the monitor the window was on before updating: it opens centred on
      one that is there.

## 4. Silent updates (Windows NSIS and AppImage)

- [ ] Settings > About: Silent updates is off by default; turning it on also
      turns on automatic checks, and turning checks off turns it off.
- [ ] With it on, a found release downloads in the background ("Downloading
      Ember x in the background", then "ready") and the corner notice stays
      hidden.
- [ ] Nothing happens while a download is receiving, an upload is sending, a
      folder is hashing, or an Ember Transfer runs; nothing happens during the
      first 30 minutes of a session, nor within 10 minutes of any input.
- [ ] A download that is only queued on remote peers does not hold it up.
- [ ] Countdown with the window visible: the dialog counts down; **Update now**,
      **Not now** (and Escape), and **Skip this version** each do what they say.
- [ ] Countdown with the window in the tray: a desktop notification appears,
      the tray shows **Cancel update (m:ss)** and the tooltip counts down, and
      the window is never brought to the front. Cancel from the tray works.
- [ ] Countdown with notifications turned off: the tray entry still works.
- [ ] A transfer starting mid-countdown aborts it, with the "busy again" toast.
- [ ] After **Not now**, Settings shows "postponed until ..." and **Resume**
      lifts it.
- [ ] After a silent update, the next time the window is opened a toast says
      Ember updated while you were away, and Settings shows "Updated to x
      automatically on ...".
- [ ] A `.deb` build and an MSI install show the switch disabled with their
      reason.

## 5. Failure drills (Windows)

In each case Ember must be running again within about five minutes, on the old
version, in the same session state, say the update did not install, and not
try that version silently again.

- [ ] Delete the staged installer from the data folder's `updates` folder just
      before the countdown ends.
- [ ] Let Defender (or another antivirus) block the staged installer.
- [ ] Kill the installer while it runs.
- [ ] `update-watchdog.log` in the data folder tells each story, and the
      `update-watchdog` folder is gone a minute after Ember comes back.
- [ ] A normal successful update leaves no watchdog running afterwards.

## 6. Open questions from the design

- [ ] NSIS: does the silent path's installer show its progress window? If a
      quiet install (`/S`) is wanted, confirm the Tauri template honours it
      alongside `/P` before adding it.
- [ ] AppImage: `AppHandle::restart` relaunches the *new* AppImage (from
      `$APPIMAGE`), not the old mount.

## 7. Translation review

1.7.1 adds 67 strings and changes three (`settings_auto_check_updates_hint`,
`settings_skip_compress_video` and its hint), in all eight non-English locales.
List them with:

```
git diff v1.7.0 -- messages/en.json
```

- [ ] Silent updates in Settings > About, the countdown dialog, its
      notification, and the done/failed toasts (`settings_silent_update_*`,
      `silent_update_*`).
- [ ] The new Settings copy: Hourly, Max sources per file, and the reworded
      video-compression switch (`settings_update_frequency_hourly`,
      `settings_max_sources_*`, `settings_skip_compress_video*`).
- [ ] The Search "results dropped" line, the folder-scan failure toasts and the
      Ctrl+V shortcut row (`search_results_shed`, `library_scan_failed*`,
      `shortcuts_transfers_paste_links`).
- [ ] The Add links dialog on Transfers and the transfer-rate graph on
      Statistics (`transfers_add_links_*`, `stats_graph_*`); the axis labels
      fit beside the legend at the narrowest window width.
- [ ] Download categories: the filter chips, the New category item and the
      categories dialog (`transfers_category_*`, `transfers_categories_*`,
      `transfers_ctx_category_new`); a long category name stays on one chip.
- [ ] German uses the formal *Sie*; the countdown title fits the dialog in every
      language.

## 8. Transfers, Statistics and Servers

- [ ] **Add links** on Transfers opens with the clipboard's eD2K links already
      in the box, counts them as you edit, and queues them.
- [ ] Statistics shows the rate graph filling in; the 1 hour view gains a point
      a minute and keeps its history across a sleep.
- [ ] Make a category from a download's Category menu with several rows
      selected: all of them get it, and its chip appears. Its chip narrows the
      list, and Stop All then stops only those. Removing it in Edit categories
      leaves them uncategorized.
- [ ] Import a large server.met (1,000+ servers): the Servers list scrolls
      smoothly to the last server, the stripes stay even, and sorting and the
      filter still work.
- [ ] On a busy install, the Queue and Known Peers tabs scroll through every row
      (Known Peers no longer stops at 1,000), and Trust badges fill in for rows
      scrolled into view.
- [ ] Share part of a folder (Library explorer, "Include subfolders" off): only
      those files are hashed and listed. Sharing the rest later picks it up
      without a manual reload. Unsharing one of them keeps it in the Library,
      unshared, across a reload and a restart, and it can be shared again from
      there.

## 9. Room transfers across versions

- [ ] 1.7.1 to 1.7.1: the prompt appears at once, and one prompt only.
- [ ] 1.7.1 to 1.7.0: the prompt appears at once; after 10 seconds no second
      prompt appears, whether the first is still open, accepted or finished.
- [ ] 1.7.1 to 1.6.x: the prompt appears after about 10 seconds and the transfer
      completes.

## 10. QUIC on the shared UDP port

- [ ] The log says `QUIC server+client endpoint ready on UDP port N (shared
      with KAD)`, with N the UDP port, and `QUIC legacy endpoint listening` on
      the TCP port when the two differ.
- [ ] Behind a VPN forwarding a single UDP port (and the same TCP port), a
      friend's chat attachment arrives over QUIC, not the TCP fallback, and a
      relayed LowID download through that node works.
- [ ] 1.7.1 and 1.7.0 in both directions: friend hole-punch, a chat attachment,
      and a relay for a KAD-only source (the 1.7.0 relay dials the TCP port
      number, which the legacy listener answers).
- [ ] KAD and Ember DHT keep working through a long QUIC transfer: searches
      answer, the KAD overhead statistic does not jump with the transfer, and
      the log shows no `UDP reader: ... queue full`.
- [ ] `"quic_shares_udp_port": false` in `config.json` brings back the separate
      socket: the endpoint line shows the TCP port and no "shared".
