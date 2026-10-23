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
- [ ] A changes or moves the file before B answers. Within about half a
      minute B's card says the file changed; Accept says so at once, without
      dialling.
- [ ] B quits Ember with an offer waiting. On both ends it lapses (B's when
      it quits, A's within five minutes).

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
