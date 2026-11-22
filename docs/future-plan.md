# Future plan

Everything still open for Ember, gathered from every earlier plan. Each item
says what it is, why it matters, when to pick it up when it waits on evidence,
and where its full design is. When an item ships, take it out of this file and
put it in the release notes; when one is decided against, move it to
[Considered and dropped](#considered-and-dropped) with the reason.

The earlier plans are kept in [`archived-plans/`](archived-plans/) as history:
the `post-1.7.x.md` plans, the feed-reachability and update-mirror plans, and
the release checklists. They hold the full designs this file points to, and
what was decided along the way. The overlay's design record (decisions,
known limits, closed work) stays in [`ember-dht.md`](ember-dht.md), and the
Channels formats in [`channels-format.md`](channels-format.md).

## 1. Before 1.8.0 ships

1.8.0's Channels cut-over is built: the v2 chat frames go out alone with the
display flag, private membership records go out in v2 alone but for the
owner's own key copy, each owned private room is rotated once
(`take_channel_cut_over_rotations`) and once more where members were still on
1.7.x (`take_channel_relink_rotation`), the owned-rooms list is padded, and
room transfers send sealed offers only. Owners also renew the older epochs a
room keeps, and derive every rotated key from the room's seed so two devices
owning a room stay on one key. The 1.7 sending paths are gone; reading 15,
19, v1 records and plain offers stays. The detail is in `channels-format.md`,
"The cut-over in 1.8.0", "The transition, and the cut-over in 1.8.0" and
"Two devices owning a room".

The release notes are in `docs/index.html`; check the date against the tag.
The runs between two machines once planned here are not to be made (see
"Two-machine runs before 1.8.0" under Considered and dropped).

The AppImage built on Ubuntu 24.04 was checked on a local build made with the
release job's command (Ubuntu 24.04 under WSL): the runner records glibc
2.39; the most any of its binaries asks for is `GLIBC_2.39`, by `ember`
itself; FreeType is not bundled; and `add-linux-platforms.mjs`, run on that
file, writes `linux-x86_64-appimage-glibc` with a `min_glibc` of 2.39 and no
plain `linux-x86_64-appimage`. On Ubuntu 22.04 it does not start (`GLIBC_2.38`
not found), which is what the gated entry keeps from 1.7.x installs there. On
24.04 with a COLRv1 emoji font in place, as Fedora 40 and later have, it
starts and logs that the host FreeType 2.13.2 matches the bundled WebKit, so
fonts are left as they are. What only the tagged release can show: a 1.7.8
AppImage taking the update from the signed `latest.json` on 24.04, and on
22.04 saying it needs glibc 2.39; and an emoji drawn in the window on Fedora
itself, which WSL could not run here. `linux-test-build.yml` builds the same
AppImage on demand for the last.

## 2. Privacy

- **Membership traffic and feed lookups through a one-hop relay.** Private-room
  presence and key-epoch STOREs and lookups are signed under the member's
  long-term DHT identity and ride a Noise session keyed by its long-term
  static key, from its own address, so storers learn who is in private rooms
  (not which room, nor anything said in it), and feed lookups say who follows
  what. A throwaway key alone hides nothing: the Noise key and the address tie
  it back. The version worth building sends these through a one-hop relay, a
  reachable Ember peer (not the rendezvous server, whose one address would
  trip every storer's per-address limits), under a throwaway identity and
  Noise key, so the storer sees the relay's address and a key it has never
  seen. Designed in [membership-relay.md](membership-relay.md): leases on a
  port of the relay's own, the lookups still driven by the member, one
  throwaway identity per room or feed per lease of up to an hour, at most 4
  leases a relay and 8 identities a lease to stay inside older storers'
  limits, and direct sending, counted, where no relay is there. Its numbers
  want a relay's counters from a test run first. The same lease would reach
  friends behind a symmetric NAT, which friend meets skip.

## 3. Friends

- **Check friend meets on real restricted NATs.** 1.7.6 resends the first
  handshake message and carries the Noise key in the meet. Tests replay the
  failure, but no meet has run between two real restricted NATs. Compare
  `ember_dht_friend_meets` with `ember_dht_friend_meets_converted` in
  Diagnostics; conversions should be close to meets for friends not behind a
  symmetric NAT.

## 4. The Ember network

Detail for every item here is in `ember-dht.md`: "Outstanding work" items 1,
5 and 7, "Future improvements", and the 2026-08-18 audit notes.

**Do next:**

- **Validate firewalled publishing live.** The buddy `PROXY_STORE` chain has
  changed in three places none of which has been seen on a live network: an
  endorsement before the buddy proxies, no compatibility trailer, and the
  buddy's own replica attributed to the sender. Walk the chain by its counters,
  from `BUDDY_ENDORSE_REQ` to `ember_dht_callback_connects`, and check that a
  publisher with no endorsement publishes nothing for that file and lights
  `ember_dht_waiting_buddy` until one lands. Also still unexercised: a cold
  join from an empty contact file with no KAD, and republishing across a full
  record TTL on a large library.
- **Find out why rendezvous adverts do not become contacts.** On the 1.7.6
  run, 11 of 20 listed peers matched no contact. They are probably stale
  adverts or changed addresses, but if they are reachable nodes failing to
  join, that is a real loss. From 1.8.0 each listed peer gets a debug line
  saying why it is or is not dialable, then its ping and its answer
  (`Ember rendezvous advert` under `RUST_LOG=debug`); one run with those read
  settles it.

**Waiting on a number:**

- **Per-peer lookup timeouts from measured round trips,** instead of the fixed
  5 and 12 seconds. 1.8.0 lets source and presence lookups stop once the
  closest nodes have answered, and gives up on a silent first contact after 6
  seconds rather than 12; the 1.7.6 run averaged 20 seconds a lookup against
  9.7 on 1.7.3. *When:* the overall lookup average on 1.8.0 still stays well
  above "Keyword search avg. time".
- **Hole punching through an introducer** (BitTorrent's BEP 55 on the DHT), so
  a node that says it is firewalled can be a routing contact. *When:*
  `ember_dht_contacts_reach_firewalled` reaches tens of percent of verified
  contacts, once most run 1.7.7 or later. Gate it on a capability tag, take
  the requester's address from the UDP source, keep punched paths alive, and
  leave symmetric NATs out.
- **Offer records before sending them (`STORE_OFFER`).** *When:* nodes
  routinely run as selective storers (the republish backlog shows a number
  rather than "Paused (small network)"), or "Stores acked" grows faster than
  the overlay. Gate it on a capability, and never leave an older storer owing
  a reply.
- **Shard the rendezvous key space.** *When:* `ember_dht_rendezvous_key_load`
  reaches 90. The derivation is already versioned for it.
- **Richer keyword indexing** (stemming, more than space-split tokens).
  *When:* the recall counters show `kad_only` pulling ahead of `both`. Ember
  already indexes four-letter extensions KAD strips, so tuning toward KAD's
  tokenizer can lose recall.
- **Node identities that cost something** (proof of work on node ids, and
  lookups over disjoint paths, as S/Kademlia does). Node ids are free, so one
  host can mint as many as it likes; most caps are keyed on address and /24,
  but the store's per-publisher caps are not. It is a version bump and a flag
  day. *When:* before the overlay is worth attacking, or sooner if
  `ember_dht_store_addr_ceiling` climbs together with `ember_dht_rate_limited`.
  Binding keyword keys to the signed name was built and backed out (it is in
  `git stash`), because it would make the stemming item above a wire break.

**Larger work:**

- **Ember-native transfers.** Library downloads find sources over Ember and
  move bytes over eD2K. Ember Transfer moves files between room members over
  the room session, in 1008-byte blocks. Moving it onto QUIC would lift the
  throughput ceiling, and downloading from several Ember peers at once is what
  a swarm among a link-only feed's followers needs: found under a key derived
  from the feed, so nobody without its link can find it, and served over
  Ember's streams rather than eD2K, beyond what 1.8.0's "Share files from this
  feed" does over the public networks. Reach is the other limit: an arbitrary
  room member holding a file may not be dialable.
- **Retire the legacy QUIC listener.** It stays on the TCP port number for
  relays that dial a KAD-only source there. It can go once those sources have
  a relay target of their own.

## 5. Updates and releases

- **A second place to fetch updates from,** for users who cannot reach
  GitHub's download hosts and have no proxy (mainland China). The updater
  already uses the system proxy, and since 1.7.7 every release can be
  downloaded over eD2K by hand, but the updater itself still cannot update
  those users. The plan: a mirror host chosen by a real download test from
  China (Alibaba Cloud OSS Hong Kong or Cloudflare R2 behind a domain), a
  second manifest signed in `sign-publish` with the same key, a `mirror.yml`
  workflow that uploads on publish with credentials of its own, and an updater
  that tries the mirror only when GitHub is unreachable, sharing the one
  downgrade floor. Detail: `archived-plans/update-mirror-plan.md`.
- **Build the `.deb` on a newer distribution.** From 1.8.0 the AppImage is
  built on Ubuntu 24.04 and published under `linux-x86_64-appimage-glibc`
  alone, with its `min_glibc`. The `.deb` stays on 22.04 (glibc 2.35): a
  `.deb` before 1.8.0 asks for `linux-x86_64-deb` and checks no glibc, so a
  build from a newer distro would install on an older one and then not
  start. 1.8.0's `.deb` prefers `linux-x86_64-deb-glibc` when its system
  meets that entry's `min_glibc`, and says so when it cannot
  (`choose_glibc_target`). Once enough `.deb` installs are on 1.8.0 or later,
  a release can build the `.deb` on 24.04 and publish it there, with
  `add-linux-platforms.mjs` and the release policy following. Whether a 22.04
  build keeps the plain entry beside it, for `.deb` installs before 1.8.0 and
  systems older than 24.04, is the choice then; the two files would need
  different names, since both are `Ember_<version>_amd64.deb` today. It has
  to happen before GitHub retires its Ubuntu 22.04 runners, and until then
  the release policy holds `build-linux-deb` to `ubuntu-22.04`.
- **Flatpak and Snap packages.** Both bring their own runtime (Flatpak a
  GNOME runtime with WebKitGTK, Snap `core24` with its `gnome` extension), so
  one build would run on any distribution with Flatpak or snapd whatever its
  glibc or FreeType, and neither the glibc floors above nor the AppImage's
  emoji workaround would apply. The costs: updates come from Flathub or the
  Snap Store rather than Ember's signed manifest, so the updater has to stand
  aside for them (a build without a bundle marker already finds no entry and
  reports no update); Flathub builds from source on its own infrastructure,
  so what its users run is not the release's signed artifact; and the
  sandbox needs permissions for the download and shared folders, which Ember
  lets the user put anywhere, and for the tray and the `ed2k:` link handler.
  Pick it up when users ask for one, or if the `.deb` cannot leave 22.04 in
  time.
- **`emberd`,** the headless build for servers, NAS boxes and Docker, ships
  with 1.8.0: tarballs and `.deb`s for x86-64 and ARM64 and a Docker image,
  with `emberd ctl`, uploads from the browser and browser notifications. Left,
  as listed under *Still to do* in [headless.md](headless.md): a security
  review by a person who did not write it, and importing from eMule's folder
  and creating a collection from the browser. Then the desktop can offer the
  same web interface behind a switch, as *Decisions* there describes. Its
  server-side host types also give tests of the network loop an event sink
  without Tauri's `test` feature (see *Split `NetworkState` per stack* below).
  Found by the 1.8.0 checks, and hidden in the browser for now rather than
  built:
  - *Save to this computer* for what emberd keeps outside the Library: feed
    downloads (Feeds' Open, Show in folder and Open feed folder call
    `#[desktop]` commands), received chat attachments and room-library
    fetches. `/api/file` serves indexed files only, and these are never
    indexed; extending `open_library_file_for_download` to the feed and
    receive folders is the likely route.
  - *Share every Ember release* (`seed_ember_releases`): `release_share.rs`
    holds the setting and the seed folder, but the fetch is driven from
    `commands/updater.rs`, which emberd does not build. A server that stays on
    is what the switch is for, so move the release fetch out of the desktop
    updater.
  - *Watch the clipboard for ed2k links*: never started in the browser.
  - Library Delete on emberd goes to the user's trash, which nothing on a
    server empties. 1.8.0 stops walks entering `.Trash*` folders, so a file
    deleted from a mount's top folder is no longer shared again, but the
    space is not freed. Deleting outright on emberd (with its confirmation
    saying so) is the likely answer.
  - `get_security_policy_state` and the `security-policy-reset-required` event
    still carry the backend's raw reason, which can hold a path; the page
    only logs it now. Send a code instead.

## 6. Code health

- **Split `NetworkState` per stack.** One struct on one task is the model that
  produced the original starvation bug, and it is still the most pressing
  architectural risk in the codebase. Each stack would get its own task with
  an explicit message boundary. It is a redesign rather than code motion, so it
  needs integration testing against live peers. `network/command.rs` is
  separable and `NetworkDeps` gives the entry point a real signature. Today only
  `start_network` builds a `NetworkState`, from live sockets and managers; a
  state tests can build comes with the split, and with it a test of private
  messages through two network loops for their routing (the wire, storage and
  pacing are covered: `a_private_message_goes_end_to_end_between_two_members`,
  `dm_pacing_invariants_hold`). The receiver's events need an `AppHandle`,
  which Tauri's `test` feature provides.
- **Overnight runs of Ember itself, and property tests for more of it.** The
  fuzz loops and the `*_invariants_hold` property tests (the Ember routing
  table, the batch publisher, private-message pacing) run 200 times longer
  each night from a new seed (`soak.yml`, `src-tauri/src/fuzz.rs`). Still missing: a
  build left running against the live network, and the same kind of test for
  the record store and the KAD routing table.
- **Dependency advisories left open at 1.8.0** (`cargo audit --file
  src-tauri/Cargo.lock`; the rendezvous server's lock was clean):
  - *SQLite* (RUSTSEC-2026-0459): the SQLite `libsqlite3-sys` 0.38 bundles
    returns stale page-cache memory for a crafted database opened beside a
    `-wal` of another page size. Local only, a malicious backup being the way
    in. Fixed by `rusqlite` 0.41 (`libsqlite3-sys` 0.39, SQLite 3.54); a minor
    API bump across the database layer, so run both builds' full suites on
    Windows and Linux after it. Decided at 1.8.0 to take it after the release.
  - *`rsa` 0.9* (RUSTSEC-2023-0071, the Marvin timing attack): the SecIdent
    signatures any eMule peer can ask for are made with it. Hard to use over
    the internet's noise, and 0.10 is a new API (`crypto-bigint`), so it waits
    for a release with room to test SecIdent against eMule again.
  - *`zip` 4.6*, pulled in by `tauri-plugin-updater` 2.14.x, has six open
    advisories. Four are in `ZipArchive::extract` (SUID bits, symlinks out of
    the folder, permissions through symlinks, an abort on a large symlink
    entry), the only `zip` call the plugin makes, and only on an update
    archive whose minisign signature checked out, so only a signed release
    could use them. The other two, `ZipStreamReader` names and AES entries
    returned unchecked, are in APIs the plugin does not call.
    `.cargo/audit.toml` accepts the first three; add RUSTSEC-2026-0429, -0545
    and -0548 with the same reasoning, or `cargo audit` from `src-tauri`
    fails. Take the plugin release that moves to `zip` 9, or turn off its
    default `zip` feature once every platform's update artifact is known to
    need none of it.
  - Unmaintained, nothing to fix yet: `chrono`, `paste`, `proc-macro-error`,
    `zbus_names` and `zvariant` (through the notification and single-instance
    plugins), and `glib` 0.18 marked unsound (through WebKitGTK).
    `async-executor` 1.14.0, through `zbus`, has been yanked; a lock update
    moves it. `cargo audit` in `ci.yml` would catch the next one when it lands
    rather than at a release.
- **Find out why most known peers show verification as Needed.** SecureIdent is
  per session, which explains part of it. Run 30 to 60 minutes with
  `RUST_LOG=info,ember_lib::network::ed2k::transfer=debug` and compare each
  peer's `SecIdent:` state with its Known Clients row; if queued or
  download-side peers never get a challenge, send one when their session
  starts. Detail: `archived-plans/post-1.7.1.md` item 5.

## 7. Translations

- **A native speaker's read of the 1.8.0 Russian and Polish plurals.** The
  source-exchange tooltip and the cancel-and-remove confirmation now carry a
  form for 2 to 4 and show the count in their singular, which serves 21, 31
  and so on; `channels_reactors_others_*` needed nothing, as `ещё {count}`
  takes no noun.
- **A native speaker's read of the 1.8.0 rewrites in every language.** The
  wording audit rewrote about 370 strings and renamed rooms to channels in
  about 240, in all nine translations, by machine and checked by script only
  (placeholders, completeness, no word for "room" left). Most at risk: the
  grammatical gender every "channel" sentence changed in es, it, pt-BR, ru
  and pl (`channels_deleted_elsewhere_body` and the `Transferred` badge
  follow a name whose gender changed); Chinese, which calls the Library
  文件库, 资源库 and 媒体库 in different places, and zh-TW's 共享 against 分享
  for "share"; de `Kürzlich` and pl `Ugruntowany` for the KAD contact types
  *Recent* and *Established*; and es and ru, whose word for a channel ban is
  the one for blocking a friend.
- **`channels_deleted_elsewhere_body` is half a sentence** shown after the
  channel's name in bold, which several languages cannot word that way. Give
  it a `{name}` and draw the bold part inside it.

## 8. Left from the 1.8.0 checks

Found by the reviews of every area before 1.8.0 shipped, and left for after
it: each is low in severity, needs unusual conditions, or needs more change
than a release candidate should take. What was fixed then is in commit
`929f0c57` and the wording pass in `2fccc83d`.

**Channels** (rooms in the code):

- **Two owning devices, past the ban cap.** 1.8.0 merges the bans of a
  snapshot this device does not take (`take_owned_snapshot_bans_locked`) and
  dates owner unbans. If the two devices' bans together pass the 12 a snapshot
  carries, a republish drops the oldest and lifts them for the room. Refuse a
  ban past the cap, or rotate and carry the newest.
- **Two owning devices, the 6-hour republish.** An ordinary edit or a rotation
  no longer goes ahead without an answered read, but the owner pass still
  signs after `owner_republish_read_gate` has deferred for 6 hours. Owing a
  rotation then, it could mint an epoch number the other device already used.
  Apply the rotation rule (`owner_rotation_waits_for_first_read`) there too.
  A ban lifted this way is now taken back once the device reads the other's
  snapshot.
- **Two owning devices, evicted rows.** In a room past 256 members an
  unbanned member's row can be evicted, and an old cached snapshot that still
  banned them would ban them again. It errs toward keeping someone banned.
- **The unsigned deleted list blocks rejoining.** A room the rendezvous
  server lists as deleted walks its members out and refuses re-entry and new
  invites (`refuse_deleted_channel`, `enter_stored_channel`) until a complete
  list no longer names it, though only a verified delete proof removes its
  history. A buggy or compromised server could lock members out of a private
  room this way. Chosen in 1.8.0 so a deleted room cannot come back; the
  alternative keeps the walk-out and the *Deleted by its owner* label but
  lets members back in until a proof removes the room.
- **One member can stall room-mail collection.** Past the 120 stored an hour
  from one sender, that member's entries come back `Later`, and `left_behind`
  ends the batch; if the server's oldest 32 are all theirs, other
  conversations' mail waits for the hour (`room_dm_mail.rs`, `collect`).
  Fetch a member who is full apart, or leave their boxes out of the batch.
- **The "Ember Network is off" branches are dead.** The network is always on
  (`ember_native_enabled` is forced true on load and save), so `emberOff` on
  the Channels and Feeds pages is never true, and `channels_disabled_*`,
  `feeds_disabled_body`, `feeds_state_paused_off` and
  `feeds_discover_off_body` are never shown. The same goes for the
  `channels_ember_disabled` error the Rust side still returns
  (`commands/channels.rs`, `channel_recovery.rs`, `network/command.rs`).
  About twenty conditions on those two pages read it, with more in Search,
  the sidebar and the Library; take them out with the keys.

**Feeds and the Library:**

- **A partly shared parent folder.** When a download folder, or a folder
  holding it, is shared with only some files picked (or as an eMule flat
  share), *Share files from this feed* adds nothing (`feed_shares::plan`
  counts that share as covering the feed's folder) and the walk then refuses
  `Feeds/<feed>`, so the feed's finished files are never offered. Adding the
  folder as a root of its own breaks the no-overlap rule; add it to that
  share's allowlist instead.

**Network:**

- **The interface flapping just after the wait.** If the chosen interface goes
  away again between the wait ending (`hold_address`) and the upload listener
  binding, the bind fails with `AddrNotAvailable`, is reported as "TCP port
  already in use", and is never retried, so the session has no inbound TCP.
  The separate QUIC socket has the same window. Wait for the interface and
  retry when `net_bind` is configured, or at least say the interface is not
  connected.
- **Other commands sent during that wait are still dropped.** 1.8.0 keeps the
  settings ones (`hold_settings_before_start`); the rest are answered or
  failed as before. The shared-file reconcile at startup sends one
  (`SharedFilesChangedAck`), so `reconcile_shared_files` logs "Startup
  shared-file reconciliation failed" when Ember starts with its VPN down;
  harmless, as the network reads the index when it starts.
- **The KAD firewall tile says Firewalled before anything checked.** It does so
  as soon as KAD connects whenever UPnP did not map, while the TCP tile beside
  it still says Unknown (`NetworkStatusTiles.svelte`, `kad_firewall_*`). Show
  *Checking…* until KAD's TCP check has answered.

**Wording the 1.8.0 audit left:**

- The page texts name the bin "Recycle Bin (Trash)" in the delete
  confirmations and "Recycle Bin" alone elsewhere (the finished-download
  toasts and button, the permanent-delete confirmations,
  `error_sharing_delete_declined`, the Delete shortcut), on every platform.
  The native dialogs name it by platform (`TRASH_NAME`). Most languages use
  one word for both; English, Spanish and Chinese do not, so a platform-aware
  wording needs a placeholder or a second set of strings.
- The eD2K server log on the eD2K Servers page is English with raw OS errors
  (`emit_server_log` in `network/server.rs`, called across
  `network/event_loop/`). The eMule import's "cannot be Ember's download
  folder" error is English too (`emule_import/mod.rs`).
- Three file pickers have no translated title and English filter names: the
  IP filter (`commands/security.rs`), the backup save and open
  (`commands/backup.rs`) and the media player (`commands/settings.rs`).
- Spellings still split across the English: "this computer" and "this
  device", "your library" and "your Library", "checked" and "ticked",
  British and American spellings, and "Failed to…" beside "Could not…".

## Considered and dropped

Taken off the plan, with why, so they are not added back without a new reason.

- **Accepting only a member's known public address for a room transfer**
  (`post-1.7.0.md` item 4). Ember holds no STUN reading for other members and
  few past sessions with them, so it would refuse members whose address
  changed, and the connection already has to prove the member's key. Private
  and special-use ranges are already refused.
- **A shorter re-fetch window after an attachment is delivered**
  (`post-1.7.0.md` item 8). It would only take away the retry a failed save
  needs; the 24-hour grant already bounds it.
- **Re-checking friendship on attachment replies and cancels**
  (`post-1.7.0.md` item 9). For symmetry only: both already arrive on
  authenticated friend sessions and are matched against the attachment's
  friend.
- **A marker that lets relayed catch-up replies move the frontier**
  (`post-1.7.5.md`, "Already scheduled for 1.8.0"). A reply that reaches the
  asker through another member's relay still moves no catch-up frontier, so
  that range is asked for again: it costs bandwidth, never a line. Marking
  such replies needs a field the relay envelope has no room for, and the
  frozen formats send a new envelope version beside v1 until every build in
  the room reads it, which would double relayed catch-up traffic for that
  long. A signed note from the neighbor saying how far it served could carry
  the frontier past lines lost on the way, which is worse than asking twice.
- **Web mirrors in feed lists** (`post-1.7.5.md` item 6, step 3). It would let
  a publisher name a server it runs and learn who downloads and when, which it
  cannot learn today without being a source. Followers who opt in to share a
  feed's files (from 1.8.0) relieve the publisher without that.
- **Stronger observed-IP and STUN interplay, and tuning announce against bucket
  refresh** (`ember-dht.md`, "Future improvements"). Neither had a problem or a
  design behind it. Reopen with soak data that shows one.
- **Migration guidance for turning the DHT on beside KAD and eD2K**
  (`ember-dht.md`, "Product / UX"). The overlay is always on, with no switch.
- **Room mail for a stranger's first message.** A first message from someone
  with no conversation is a request the user answers; left in a mailbox, it
  would let anyone in a shared room fill one's box on the server while one is
  away. A first contact waiting for both to be online is the right gate, and
  the alternative needs a field the frozen presence record does not have.
- **Checking block-protocol room transfers chunk by chunk**
  (`post-1.7.0.md` item 2). The block protocol is the fallback for members
  who can only meet through a relay, and the finished file is still checked
  against the offer, so nothing bad is kept. What a bad sender can waste is
  bandwidth, up to the size of a file the user chose to accept from it: not
  worth a new frame on both ends.
- **Tuning Discover's spam folding as a plan item.** There is nothing to
  build; `LIKELY_SPAM_SCORE` and `DUPLICATE_NAME_FLOOD` are revisited when a
  report of a folded good room, or of spam getting through, comes in.
- **Carrying a feed to another device of the same identity.** A backup holds
  `ember.db`, a user's own feeds and their items included (`feeds_own`,
  `feeds_own_items`), so an identity restored from one brings its feeds.
  Keeping two running devices' feeds in step would be a sync feature Ember
  has nowhere else.
- **Sharing any folder without its subfolders from the folder picker.** Ember
  shares a folder with what is under it by design, and the share browser
  already unshares a subfolder, files added to it later included; only a
  subfolder made later is shared. The eMule import makes flat shares itself
  for users who expect eMule's way.
- **Two-machine runs before 1.8.0**: the cut-over from 1.7.8 and beside 1.7.4
  (its checklist: `git log --all -- docs/release-checklist-1.8.0.md`), room
  mail to a member gone offline, disappearing private messages, a friend's
  slot for a friends-only file over the secure dial
  (`secure_push_grant_target`), searching all of a friend's files (`EBR2`),
  and sharing a feed's files with the publisher offline. Not to be made: each
  has automated tests of its formats and paths, end to end where they exist
  (`a_private_message_goes_end_to_end_between_two_members` takes room mail
  too), and what only real machines would show is left to reports after the
  release. The cut-over has the most at stake: as the release notes say, a
  member on 1.7.4 or earlier cannot read a private room once its owner runs
  1.8.0.
- **A test of private messages through two network loops, on its own.** It
  needs a `NetworkState` that tests can build, which is the split's work, so
  it is part of that item (section 6).
- **Already done, found while gathering this plan:** digest corroboration
  across colluding storers (`post-1.7.0.md`; responders are counted per /24 and
  a contested digest is not pinned), and keeping withheld lists in a store of
  their own (`post-1.7.0.md`; 1.7.2 made the list name folders instead, see
  `post-1.7.1.md` item 2).
- **Already done, found since:** unsharing a folder inside a listed folder
  entry (`withhold_under` gives it an empty list of its own, so files added
  later stay unshared).
