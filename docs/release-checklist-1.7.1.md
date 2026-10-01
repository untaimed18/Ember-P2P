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
- [ ] After the automatic check has found a release, switch the language
      (which reloads the page): the "update available" notice is still there.
- [ ] `silent-update-state.json` appears in the data folder with
      `last_check_at`.

## 3. Coming back the same way (manual Install)

Before pressing Install: window at a custom size and position, connected to a
server that is not the saved auto-connect one, three downloads (one
transferring, one paused, one only queued on remote peers), two search tabs,
the chat popped out, and a few peers waiting in the upload queue.

- [ ] After the update the window reopens at the same size and position, on
      the same page, connected to that server, with both search tabs and the
      chat popped out. Update a second time: the window has not grown.
- [ ] With the window on a second monitor at a different display scale: it
      reopens there at the same size, not larger or smaller.
- [ ] Downloads are in the same states; the paused one is still paused.
- [ ] The Queue tab shows the earlier waiters once the library has loaded, with
      their waiting time kept.
- [ ] Repeat maximized, on the primary monitor and on a second one: it comes
      back maximized on the same monitor. Un-maximizing then gives the default
      size (known gap).
- [ ] Repeat minimized to the taskbar: it comes back minimized (it shows for a
      moment first, and on the primary monitor; known gaps).
- [ ] Repeat hidden in the tray: Ember comes back hidden, with nothing flashing
      onto the desktop, and opening it from the tray shows it maximized if it
      was. Update again without opening it in between: still maximized when
      opened.
- [ ] Unplug the monitor the window was on before updating: it opens centred on
      one that is there.
- [ ] Start Ember by clicking an `ed2k://` link, then update: the new version
      does not ask to add that link again, and a tray-hidden session stays in
      the tray. Repeat by opening a `.emulecollection` file from a folder whose
      path has a space in it.

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
- [ ] While the release is downloading in the background, **Check now**
      answers promptly, and **Install** shows that download's progress and then
      installs it without downloading it again.
- [ ] Press **Check now** in Settings a few seconds before the countdown ends:
      the dialog and tray entry stay at 0:00 until the check finishes, and
      **Not now** pressed meanwhile still postpones.
- [ ] Press **Install** in Settings during a countdown: after the update, no
      "updated while you were away" toast appears.
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
      `update-watchdog` folder is gone a minute after Ember comes back (within
      about five minutes after a silent install that failed and restarted
      Ember).
- [ ] A normal successful update leaves no watchdog running afterwards.

The watchdog's other paths, where the install itself succeeds:

- [ ] Make the new version's first start fail at its database: hold `ember.db`
      in the data folder open without sharing from another process during the
      update, and release it once `update-watchdog.log` says Ember is running
      again (or that it did not come back, if the failed start was quicker
      than the watchdog's two-second check). Ember is then started once more,
      on the new version, and restores the session.
- [ ] Start Ember by clicking an `ed2k://` link and press Install; the moment
      the installer's progress window closes, open Ember from the Start menu.
      Whichever start wins, the link is not offered again.
- [ ] MSI: press Install and leave the elevation prompt unanswered for more
      than five minutes, then accept it: the install completes and the old
      Ember was not started in the meantime.

## 6. Open questions from the design

- [ ] NSIS: does the silent path's installer show its progress window? If a
      quiet install (`/S`) is wanted, confirm the Tauri template honours it
      alongside `/P` before adding it.
- [ ] AppImage: the silent path's restart (`AppHandle::request_restart`)
      relaunches the *new* AppImage (from `$APPIMAGE`), not the old mount, and
      the old process exits cleanly rather than hanging in its shutdown.

## 7. Translation review

1.7.1 adds 70 strings and changes three (`settings_auto_check_updates_hint`,
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
- [ ] The tray menu (`tray_show`, `tray_quit`, `tray_cancel_update`): right-click
      the tray icon in each language and see Show, Quit and, during a countdown,
      Cancel update in that language. Switch language with Ember running and
      the menu follows within a second, also mid-countdown, with the Cancel
      entry kept.
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
      without a manual reload. Unsharing one of them takes it off the Library
      list, which shows only offered files; across a reload and a restart the
      Library explorer still lists it as not shared, and sharing it there
      offers it again.

## 9. Room transfers across versions

- [ ] 1.7.1 to 1.7.1: the recipient's prompt appears at once, and one prompt
      only. The sender's card never shows **Send standard offer**.
- [ ] 1.7.1 to 1.7.0, a member the sender has not seen type in a room, a file
      under 100 MB: the recipient's prompt appears at once. After about 10
      seconds the sender's card says there is no reply yet and offers **Send
      standard offer**; the question goes away when the recipient accepts or
      declines. Clicking it before then sends one standard offer, and the
      recipient sees no second prompt, whether the first is still open,
      accepted or finished.
- [ ] 1.7.1 to 1.7.0 after that member has typed in a room the sender is in
      (also after restarting the sender): no question appears on the sender's
      card.
- [ ] 1.7.1 to 1.6.x: nothing appears on the recipient's side until the sender
      clicks **Send standard offer** (about 10 seconds after offering); then the
      prompt appears and the transfer completes. Without the click the offer
      expires unseen. Clicking late, four minutes after offering, still leaves
      the recipient's prompt up for its full five minutes, and accepting near
      the end of them completes the transfer.
- [ ] 1.7.1 to 1.6.x with a file over 100 MB: the sender's card never shows
      **Send standard offer**, nothing appears on the recipient's side, and
      the offer expires with the message that members on 1.6 or earlier cannot
      receive files over 100 MB.
- [ ] With the members pane closed, the question opens it in a wide window and
      counts on the members button in a narrow one. On another page, or in
      another room, it shows a toast naming the room.
- [ ] A recipient that goes offline before answering: the sender's question
      stays until the transfer ends; clicking it while the member cannot be
      reached says so and leaves the button there to try again.

## 10. QUIC on the shared UDP port

- [ ] The log says `QUIC server+client endpoint ready on UDP port N (shared
      with KAD)`, with N the UDP port, and `QUIC legacy endpoint listening` on
      the TCP port when the two differ.
- [ ] Behind a VPN forwarding a single UDP port (and the same TCP port), a
      friend's chat attachment arrives over QUIC, not the TCP fallback, and a
      relayed LowID download through that node works.
- [ ] 1.7.1 and 1.7.0 in both directions: friend hole-punch, a chat attachment,
      and a relay for a KAD-only source (the relay, on either version, dials
      the source's TCP port number, which the legacy listener answers).
- [ ] The same KAD-only relay between two 1.7.1 nodes whose TCP and UDP ports
      differ.
- [ ] That relay again with UPnP off on the source's router, a NAT that keeps
      the port and does not filter by sender: it still connects, held open by
      the mapping keep-alive the legacy listener sends from the TCP port.
- [ ] KAD and Ember DHT keep working through a long QUIC transfer: searches
      answer, the KAD overhead statistic does not jump with the transfer, and
      the log shows no `UDP reader: ... queue full`.
- [ ] `"quic_shares_udp_port": false` in `config.json` brings back the separate
      socket: the endpoint line shows the TCP port and no "shared".
