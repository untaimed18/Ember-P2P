# 1.7.5 release checklist

What automated checks cannot cover before tagging `v1.7.5`. Tick each box, and
file anything that fails before tagging rather than after. 1.7.5 freezes the
Channels formats (`docs/post-1.7.4.md`, "Channels: the format freeze";
`docs/channels-format.md`, "What freezes at the end of the beta"), so this run
is the last chance to find a format problem cheaply. It repeats 1.7.4's run
(`docs/release-checklist-1.7.4.md`, the baseline) and adds what 1.7.5 changed.

## 0. Automated checks

- [ ] `npm test` and `npm run check` pass.
- [ ] `cargo clippy --tests` is clean and `cargo test --lib` passes in `src-tauri`.
- [ ] `node scripts/verify-release-policy.mjs` passes for 1.7.5.
- [ ] `node scripts/release-notes.mjs` prints the 1.7.5 notes, and they read
      correctly as Markdown.

## 1. Channels across real machines

Three or more computers, all on 1.7.5, at least one behind a firewall that is
not reachable from outside (no port forwarding, UPnP off). Call them A
(reachable), B (reachable) and C (firewalled). Run all of section 1 of the
1.7.4 checklist first; it must still pass unchanged. Then:

### Chat v2 (item 2)

- [ ] Chat in a public and a private room from all three. Every line arrives
      once on every machine, in order. No machine shows a "needs a newer
      Ember" notice.
- [ ] Send a line with emoji that use joiners (a family, a flag, a skin tone,
      👩‍💻). Between 1.7.5 machines it arrives whole, not split into parts.
- [ ] Reply to a line and edit one. Each change reaches the other two once,
      and an edited line is marked edited only where it was edited.
- [ ] Take C offline, send a few dozen lines with joiner emoji, bring C back.
      C catches up on every line once, with the emoji whole.
- [ ] Downgrade (a known limit; availability only). Back up B's data folder,
      then install 1.7.4 over it while B holds lines with joiner emoji and a
      line edited from a 1.7.5 machine. B opens the database and shows every
      line. With A offline, join the room from a fresh install so that only B
      can serve catch-up: lines without joiners arrive; the joiner lines and
      the edited line may not, since B's re-serve of them is rejected. Nothing
      else breaks. Reinstall 1.7.5 on B and restore the backup.

### Room settings and invites (items 1 and 7)

- [ ] A rotates a private room's key with C offline for longer than four
      rotations, so C falls behind past what it keeps. C is stuck as before;
      A sends C a fresh invite, and C gets back in from it without leaving.
- [ ] Hand-edit that invite's `k=` to a different 64-hex key and open it on
      C. The key is not taken: C stays behind, it does not start reading
      under the wrong key.
- [ ] A public room publishes no settings record; nothing about it changes.

### Admission (item 8)

- [ ] In a private room A bans B, then rotates. B, still holding the old key,
      keeps sending; C was offline across the rotation and stored some of B's
      old lines. When C serves catch-up, B is not put back on A's or C's
      roster, and A's next rotation is not sealed to B.
- [ ] A new member joins a private room from an invite and is on everyone's
      roster within a few minutes (by beacon or presence walk, not by
      chatting).
- [ ] If a pre-1.7.0 build is available: it joins a private room A owns, and
      reaches the rosters through the presence walk within about five
      minutes.

### Private membership records (item 9)

- [ ] Private rooms still find their members and rotated keys after a
      restart of every machine: presence lights up, a rotation reaches C.
- [ ] C several rotations behind (but within four) catches up one epoch at
      a time and reads the room again.

## 2. Friends: offers that wait

- [ ] A offers B a file over B's auto-accept ceiling while B is away. B
      answers an hour later: the file transfers.
- [ ] B answers after a day: the offer reads expired on both ends.
- [ ] A changes or moves the file before B answers. Within 30 to 60 seconds
      (it takes two looks in a row, half a minute apart) B's card says the
      file changed; Accept says so at once, without dialling.
- [ ] B quits Ember with an offer A holds waiting, and starts it again
      within five minutes of quitting. The offer is still on B's card under
      its file name; once their session is back A holds it again, and it
      still transfers when B accepts later that day, within a day of the
      offer.
- [ ] B quits with an offer waiting and stays away longer than five
      minutes. It lapses on both ends: A's five minutes after B's session
      ended, B's when it starts again.
- [ ] A offers a file from a USB drive, unplugs the drive for a minute
      while B is away, then plugs it back. The offer is still waiting, and
      B's Accept transfers the file.

## 3. Mixed versions (1.7.5 with 1.7.4)

Machine A on 1.7.5, machine B on 1.7.4, in the same rooms and mutual friends.

- [ ] Both read each other's lines, edits, replies and reactions in every
      room, each once. B shows no "needs a newer Ember" notice for A's lines.
- [ ] Joiner emoji from A reach B as 1.7.4 always showed them (split), and
      between two 1.7.5 machines in the same room whole.
- [ ] B (1.7.4) in a private room A (1.7.5) owns: B still finds the room's
      members and A's rotated key after a restart (v1 records are still
      published until 1.8.0).
- [ ] An offer from A to B, unanswered, lapses at five minutes on both, and
      A's card says so.
- [ ] Room files and friend chat attachments work both ways.
- [ ] A picks a language under Settings > Channels. In a public room and a
      private one, B lists A as before with no flag, and A lists B with
      none. A's flag shows at once on A's own row.

## 4. Library, backup and Discover

- [ ] Back up on one machine, reinstall Windows (or restore onto another
      PC), and restore. The backup file opens without a permission prompt,
      and the Library says the shared folders need approving; one
      "Re-approve folders" approves them all and their files are listed
      without Reload.
- [ ] Copy a new backup to a USB drive: no permission prompt.
- [ ] Leave Discover open for half an hour: rooms and their language flags
      stay.
- [ ] Two 1.7.5 machines in a public room and a private one: a language one
      picks under Settings > Channels shows as a flag beside their name in
      the other's member list within a presence walk, changes when it is
      changed, and goes when it is set back to "Not shown".

## 5. Translation review

All eight non-English locales. List what changed with
`git diff v1.7.4 -- messages/en.json`. In particular:

- [ ] Library: `library_unapproved_banner_*`, `library_empty_unapproved*`,
      `library_reapprove_all`, `library_folders_reapproved_other`,
      `library_files_grid_aria`.
- [ ] Backups: `error_backup_source_access_denied` (the Windows menu names
      must match each locale's Windows).
- [ ] Confirmations: `channels_claim_confirm*`,
      `channels_remove_moderator_confirm*`,
      `transfers_categories_remove_confirm*`, `browse_close_confirm`,
      `browse_keep_going`, `browse_stop_and_close`.
- [ ] Busy labels and the shortcut sheet: `channels_marking_all_read`,
      `channels_opening_successor`, `channels_searching`,
      `servers_updating`, `shortcuts_modal_close`, `shortcuts_modal_confirm`,
      `shortcuts_search_copy_links`.
- [ ] Friends: `error_peers_attach_source_gone`.
- [ ] Channels language: `settings_channel_language_*`,
      `channels_member_language`.
- [ ] Connection doctor: `doctor_*` (the router steps must stay generic:
      "port forwarding", not one router brand's menu names).
- [ ] Private messages: `channels_dm_*`, `error_channels_dm_*`,
      `settings_room_dm_policy*`, `chat_dock_section_private`.
- [ ] Feeds: `feeds_*`, `error_feeds_*`, `nav_feeds`, `deeplink_feed*`.
- [ ] Friend status and names: `friends_status_*` (Away and Busy are new),
      `friends_my_status_*`, `friends_self_name_title`,
      `friend_settings_name_hint`, `settings_auto_away_*`,
      `settings_group_status`.
- [ ] Website tag and file name tag: `settings_nickname_site_tag*`,
      `settings_tag_*`, `settings_group_name_tag`, `settings_name_tag_intro`,
      `library_tag_*`, `library_bulk_tag*`, `library_bulk_untag*`,
      `library_ctx_tag_count`, `library_ctx_untag_count`.
- [ ] Channels: `channels_deleted_elsewhere_*`, `channels_section_yours_*`,
      `channels_joined_*`, `channels_edit*` (with `channels_editing_title`).
- [ ] Transfers and updates: `transfers_parts_sent`,
      `transfers_*part_files_removed`, `error_updater_*_unreachable`.

## 6. Feeds

Two or more 1.7.5 machines, A publishing and B following; A and B mutual
friends unless a step says otherwise, and C a follower who is not A's friend.

- [ ] A creates a feed, adds files with the Add files dialog (type chips,
      filter, Shift ranges, Add to feed) and publishes. The button reads
      Publish for the draft, then a disabled Up to date with its tooltip.
- [ ] C follows by the `ember-feed:` link, and again (after unfollowing) by
      the `https://www.emberp2p.org/feed/...` and `https://emberp2p.org/feed/...`
      forms. The feed and its files appear within a few minutes of a lookup
      or Check now; the feed shows "Looking for it…" until then, not an
      error.
- [ ] A adds one file and removes another; the button reads Publish changes.
      After publishing, C sees the new file marked New and the removed one
      marked Removed (a file C downloaded from it stays on disk).
- [ ] Friend push: B, a friend, sees A's change within a minute of the
      publish, without Check now. Publishing again within five minutes is
      taken up by B five minutes after the first, not lost.
- [ ] A makes one of the feed's files friends-only, then saves the feed: the
      editor says which file was left out because it is no longer shared
      with everyone, and the publish leaves it out.
- [ ] Auto-download: on a feed B has just followed, the caps show 1024 and
      4096 MiB before it is turned on, and turning it on keeps them. A file
      over the per-file cap is not started, and files are started only up
      to the 24-hour cap; the rest wait for Download. Both caps set to 0
      and saved stay 0, and nothing is held back by size.
- [ ] Risky types (`.exe`, `.msi`, `.bat`, `.ps1`, `.lnk`, `.iso`, `.docm`,
      and `video.mp4.exe`) are never started automatically, whatever the
      caps; Download starts them by hand.
- [ ] Free space: B's download folder on a small drive with a large
      download already queued there. Auto-download starts nothing that
      would leave less than 64 MiB free once the queued download finishes.
- [ ] The list is never seen: on A and on B (which serves it while
      following) it is not in the Library, not in a friend's Browse, and not
      found by a KAD or eD2K server search for the feed's title or the
      list's file name.
- [ ] Two devices on one identity: restore A's backup on a second machine
      A2, which then holds the same feed. Publish a change on A2. Leave A
      running past its daily republish: it does not put its older list back,
      and followers keep A2's.
- [ ] Publish with the Ember network unreachable (block Ember's UDP port in
      the firewall, or disconnect after Ember has started). Publish says
      "Could not reach the Ember network to publish the feed", the feed
      stays marked changed, and followers keep the previous list. Publishing
      once reachable again works.
- [ ] A list that does not match its head is marked broken. With a build
      patched to sign a head whose item count or BLAKE3 does not match the
      list it names, publish: C shows "Could not verify the list" and does
      not fetch that list again; a correct publish after it clears the mark.
- [ ] A deletes the published list file under its data folder's `feeds\`
      while Ember is closed. At the next start it is written again and
      followers still fetch it.
- [ ] Unfollow: the feed and its list go, the list is no longer served, and
      files already downloaded stay.
- [ ] With Ember on, Alt+9 opens Feeds, Alt+0 Statistics, Security has no
      Alt key, and the shortcuts sheet (?) says the same. With Ember off,
      Channels and Feeds leave the sidebar and Alt+0 opens Settings.

## 7. Private messages

Three 1.7.5 machines in a shared room, none of them friends: A, B and C,
with C firewalled.

- [ ] Ask first (the default): A writes to B with Message privately. B sees
      a request banner on the Channels page, counted on its nav item rather
      than as unread, with Accept, Decline and Ignore. After Accept the
      conversation opens in the dock as "A (private)".
- [ ] Allow from anyone: A's first message opens a conversation on B at
      once. Off: A is told B does not take private messages, B's sending is
      blocked, and an open conversation stops too.
- [ ] Request caps: a request holds at most 20 messages until it is
      answered; a 21st from A, sent over more than a minute, is dropped. A
      sender cannot write more than 20 new private messages a minute
      through one room ("You are sending private messages too fast"). A
      room takes at most 5 new requests an hour (needs six senders).
- [ ] Decline: B declines A. A's next message says B does not take private
      messages from A, and A cannot write again for 7 days. Move both clocks
      forward eight days (or wait): A's message arrives as a new request; B
      declines again, and A's messages stop and A is told again.
- [ ] Ignore from a request: A's later messages never show or notify on B,
      and A is listed under Settings > Channels, where B can undo it.
- [ ] Receipts: each message shows Delivered 10 to 90 seconds after it
      arrives, not at once.
- [ ] B offline: A's message stays Sending… for 20 minutes, then shows "Not
      delivered" with Try again. Try again after B is back delivers it.
- [ ] A burst: A sends 20 messages while B is offline, B comes back within
      20 minutes. Every message arrives once and A sees each Delivered.
- [ ] The popped-out chat window opens and sends private conversations.
      Close a private conversation's tab: the dock's switcher lists it under
      "Private conversations" with its unread count, and opening it from
      there brings the tab back.
- [ ] Largest message: A sends text at the top size (3,651 bytes, mostly
      multi-byte emoji) to C, reached only through a relay. It arrives
      whole.
- [ ] Mixed versions: with A and C on 1.7.5 and a 1.7.4 member D as the only
      path between them, A's messages still reach C, and D shows nothing.

## 8. Connection doctor

- [ ] **Before tagging:** rendezvous-server 0.2.0, with `/v4/reachability`,
      is deployed to production, and `/v4/protocol` advertises
      `reachability`.
- [ ] From a home IPv4 connection against production, TCP and UDP from
      outside are tested (the answer is available), not "not checked".
- [ ] Ports forwarded by hand: Fully reachable, every check passed.
- [ ] UPnP on in Ember and the router, nothing forwarded by hand: Fully
      reachable, UPnP mapped. With the router's UPnP off: "Your router did
      not open the ports"; turn it on, Try UPnP again, and the check passes
      about ten seconds later.
- [ ] Behind carrier-grade NAT (a router whose WAN address is in
      `100.64.0.0/10`, read over UPnP): "Your internet
      provider shares one address between customers", and no port
      forwarding advice.
- [ ] Opened in the first minute after launch, before Kad's firewall check
      or a server ID: "Still checking" with "Check again in a few minutes"
      and no router fix. It settles once any TCP result comes in.
- [ ] Windows Firewall: delete Ember's inbound rules, check. "Add the rules"
      shows one Windows prompt; accepting adds them and the check passes;
      declining says Windows did not give permission. Repeat with Ember
      installed under a folder with spaces and an apostrophe.
- [ ] Another program on Ember's TCP port before Ember starts (eMule, or any
      listener): "Another program is using port …", TCP is never called
      reachable, and Choose another port brings up the port field.
- [ ] A saved port change without a restart: the first fix is "Restart
      Ember to use your new connection settings", and the checks describe
      the ports Ember is running on.
- [ ] LowID or Kad-firewalled: the status bar shows Check connection. Left
      in that state ten minutes, a toast offers the check once that session.
- [ ] Seven checks within an hour from one address: the seventh says the
      hourly limit is used up.
- [ ] Against a rendezvous server older than 0.2.0, the doctor still
      finishes from Kad and eD2K results and says the outside test did not
      run.
- [ ] Copy report masks addresses unless Include IP addresses is on, and is
      in the app's language.

## 9. Friends: status, names and labels

- [ ] A sets Busy, then Away, then Online. B sees each on A's card, in the
      chat dock and in A's friend settings within seconds.
- [ ] A, Online with "Show me as Away when idle" at 5 minutes, leaves the
      keyboard and mouse alone: B sees Away after 5 minutes and Online again
      once A moves the mouse. Busy is never changed by idle. On Linux the
      setting says it is not available.
- [ ] A quits: B sees Offline.
- [ ] B renames themselves. A's card, with no label, follows. A gives B a
      label; B renames again: A's card keeps the label and shows "The name
      they chose" with B's new name. Clearing the label shows B's name.
- [ ] B renames while A is offline: A sees the new name once they connect.
- [ ] 1.7.5 to 1.7.4 to 1.7.5: back up, install 1.7.4 over A's 1.7.5 with
      labelled and unlabelled friends. Every card shows the label or the
      friend's name. Rename one friend and add another on 1.7.4, then
      reinstall 1.7.5: every label is kept, the rename made on 1.7.4 is a
      label, and unlabelled cards still follow their friends' renames.

## 10. Website tag on the nickname

- [ ] A real eMule client downloading from or uploading to Ember shows its
      name as "Name [https://emberp2p.org]", and an eD2K server is sent the
      same at login (a server that lists users, or a packet capture).
- [ ] Ember friends and Ember peers see the name alone, on friend cards, in
      friend requests and in rooms.
- [ ] A 64-character nickname: eMule shows it whole with the tag after it,
      and a friend's card shows the 64 characters without the tag.
- [ ] A nickname already containing `emberp2p.org` is not tagged twice.
      With the switch off (Settings > General), eMule sees the plain name
      after reconnecting.

## 11. File name tag

- [ ] Tag a selection from the Library, and one file from its menu; Remove
      [Ember-P2P] takes it off. Undo restores the exact names, double
      spaces and all.
- [ ] Tag completed downloads on: a finished download is saved under the
      tag.
- [ ] Tag new shared files on: of files then dropped into a shared folder,
      only media, archives, disc images and documents are renamed; an
      `.exe`, `.txt`, `.html`, `.ts`, `.bin` or a file with no extension is
      not, and nothing inside a `.git` repository or a hidden or dot-named
      folder is. Files there before the switch went on keep their names, and
      a tag taken off by hand is not put back.
- [ ] A partly shared folder (some files shared, not the whole folder): tag
      one of its shared files and restart. It is still shared.
- [ ] Stop hashing, then Re-approve folders: hashing stays stopped, and the
      folders are walked when it resumes.

## 12. Smaller checks

- [ ] Upload slots: set Max uploads to Auto on 1.7.5, install 1.7.1 over it.
      1.7.1 shows four slots, not one.
- [ ] Unplugged drive: a download whose folder is on a USB drive, drive
      unplugged and Ember restarted. The download waits for the drive, is
      not marked "Stopped: part files removed", and continues once it is
      back.
- [ ] Per-part upload bars: an upload to a downloader taking parts from
      several sources fills each part's bar from its left edge, and the
      tooltip says how much of the file has been sent.
- [ ] Deleted elsewhere: own a room on two devices of one identity (restore
      a backup), delete it on one. The other offers Keep it here and Remove
      it here; Remove asks for confirmation first, and Keep is not asked
      again until a backup is restored.
- [ ] Channels lists joined rooms under Your public rooms and Your private
      rooms, favourites first in each. The arrow keys walk them in the order
      shown, and Mark all as read sits on the first section; a search that
      hides every joined room keeps a plain Your rooms header with it.
- [ ] Settings keep keys they do not know: with Ember closed, add
      `"zz_future_setting": 123` to `config.json`, start Ember, change any
      setting, close it. The key is still in the file.
- [ ] One malformed entry in `ignored_members` in `config.json` costs that
      entry only: every other setting loads as it was.
