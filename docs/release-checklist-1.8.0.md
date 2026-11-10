# 1.8.0 release checklist

What automated checks cannot cover before tagging `v1.8.0`. Tick each box, and
file anything that fails before tagging rather than after. 1.8.0 is the
Channels cut-over: chat goes out in the v2 frame alone, private membership
records in v2 alone, and every private room is rotated once more
(`docs/channels-format.md`, "The cut-over in 1.8.0" and "The transition, and
the cut-over in 1.8.0"). Until this run passes, the 1.7 sending paths stay in
the code behind their switches (`docs/future-plan.md`, section 1), so a
failure here can be answered by turning one back on rather than by a fix
under pressure.

Run the sections in order. Once everything is ticked, delete those paths and
run sections 2 and 3 again: section 3 with a new private room that A makes
with B and C, in place of Q, which section 6 deletes; section 2 with fresh
1.7.8 and 1.7.4 installs on D and E, joined to the public room and R from new
invites, and without its last step (E in R), since the cut-over rotation it
watches is made once per database.

## 0. Automated checks and release notes

- [ ] `npm test`, `npm run check` and `node --test scripts/*.test.mjs` pass.
- [ ] `cargo clippy --all-targets -- -D warnings` is clean and
      `cargo test --lib` passes in `src-tauri`, on Windows and Linux.
- [ ] `npm run verify:release` passes for 1.8.0.
- [ ] The 1.8.0 notes are written in `docs/index.html` (`id="release-1-8-0"`),
      and `node scripts/release-notes.mjs --version 1.8.0` prints them as
      readable Markdown. They say plainly that members still on 1.7.4 or
      older stop reading private rooms once the owner updates, and should
      update.

## Machines and test aids

Three or more computers that will run 1.8.0: A (reachable), B (reachable)
and C behind a firewall that is not reachable from outside (no port
forwarding, UPnP off). Beside them D on 1.7.8 and E on 1.7.4, each its own
machine or virtual machine. A rotation an owner makes in the background (the
cut-over's in section 1, on A and on A3, and the second one in section 4)
waits until that device has heard from at least five other Ember nodes. On
the public Ember network that comes on its own; if these machines are the
only Ember nodes about, A and A3 see only B, C, D and E, so keep one more
Ember running through sections 1 and 4.

Later sections add members: F and G, who join a room late (section 5), and
X, Y, Z, X2 and Y2, who get banned (section 6). Each, like the extra Ember
above, can be a fresh install, or an extra Ember started on one of the PCs
with its own `EMBER_DATA_DIR` folder and ports, as A2 is below but restoring
no backup. Section 6 also needs A2, a second device on A's identity.

Everyone starts on 1.7.8 (E on 1.7.4), and the rooms are made there, before
anything is updated: a public room everyone joins; a private room R that A
owns, with B, C, D and E in it; and a private room Q that A owns, with B and
C only, so one room has no member on 1.7.x.

**Closed means quit.** Where a step says a machine is closed, quit Ember
from its tray menu (Quit Ember); closing the window can leave it running.

**Seeing a rotation.** A rotation made in the background shows nothing in
the window. Each one raises the room's `key_epoch` by one: with Ember closed
on that machine, `SELECT name, key_epoch FROM channels;` shows it (see the
next aids for how to read the file). Compare before and after.

**Shortening the long waits.** Some steps wait a week or twelve hours. Each
of those keeps its count in `ember.db`, a plain SQLite file in the data
folder: `%APPDATA%\ember\p2p\data` on Windows, `~/.local/share/p2p` on Linux,
or the `EMBER_DATA_DIR` folder. With Ember closed on that machine, open the
file in the `sqlite3` command-line tool (or DB Browser for SQLite), run the
statement the step gives, close the file and start Ember. A room's id comes
from `SELECT channel_id, name FROM channels;`. The statements only move a
clock forward, or, in one step of section 6, stage a fault on purpose; do
them on test rooms only.

**A second Ember on one PC.** With `EMBER_DATA_DIR` set, Ember keeps its
settings, identity and database in that folder and skips the check that
only one Ember runs. Give each instance a folder of its own. For A2, do this
at the start of section 6, not before: an older backup would make A2 rotate
rooms on its own (the 1.7.8 one takes the cut-over again, and the one from
section 1 lacks P and everything since).

1. Back A up (Settings > Backup & import).
2. Open PowerShell, set `$env:EMBER_DATA_DIR = "C:\EmberA2"` (an empty
   folder), and start Ember's executable from that window.
3. Restore that backup into it (Settings > Backup & import > Restore from a
   backup), and restart it the same way.
4. On A2, set its ports under Settings > Network to ones A does not use, and
   its download folder under Settings > Transfers to a folder of its own:
   the backup brings A's ports and download folder with it, and A2 would
   resume A's downloads there. Restart it again.

Every start of A2 has to come from a PowerShell window with the variable
set; started any other way, it is A. A2's window title ends in `[EmberA2]`,
but both tray icons read "Ember", so quit A2 from the icon whose Show Ember
opens that window. Close A2 for good once section 6 is done.

## 1. The cut-over rotation

With the rooms made on 1.7.8, note R's and Q's `key_epoch` on A, copy an
invite to R and one to Q from A, back A up (Settings > Backup & import), and
update B and C to 1.8.0. Then update A, in one of the two ways below.

- [ ] Start 1.8.0 on A with its network cable out and leave it a few
      minutes. Quit it and, still unplugged, check that R and Q still have the
      `key_epoch` they had on 1.7.8. Start A again, still unplugged, then plug
      the cable in: within a few minutes each rotates once. (Or start it
      online: each rotates within a few minutes of starting.) Afterwards
      neither invite copied before lets a fresh install in, while B, C and D
      keep reading and sending in R.
- [ ] Restart A twice. No room rotates again for the cut-over.
- [ ] Restore the backup made on 1.7.8 onto a fresh machine A3 running
      1.8.0. A3 gets the rooms A owns back with their names and keys, and
      each private one rotates once on A3, past the epoch A rotated to.
      Members follow the new key within a few minutes.
- [ ] Back up A on 1.8.0, then create a private room P on A. Restore that
      backup onto A3. A3 says a room you own was restored to this device,
      lists P with A's other rooms, and rotates P once. Close A3 for good
      afterwards: it is a third device on A's identity and would join the
      two-device checks.

## 2. Mixed versions (1.8.0 with 1.7.8 and 1.7.4)

Right after section 1: it needs D still on 1.7.8 (section 4 updates it) and
E still on 1.7.4 (the last step here updates E).

- [ ] D and E, not yet A's friends, each send A a friend request. Each
      arrives and can be accepted. Then A and D, and A and E, chat, see each
      other's status, and send files both ways: every transfer starts and
      finishes, and none is refused or stalls.
- [ ] D (1.7.8) and the 1.8.0 machines read each other's lines, replies,
      edits and reactions in the public room and R, each once, with no
      notice on either side that a newer Ember is needed.
- [ ] E (1.7.4), in the public room: lines from 1.8.0 members are not shown,
      and E shows its notice that messages came from a newer Ember, with a
      count. E's own lines reach everyone.
- [ ] A file sent in the public room reaches D and E, and one sent in R
      reaches D.
- [ ] Last, E in R: nothing sent in R since A's cut-over rotation reaches E,
      and E shows no notice about it, as documented. Update E to 1.8.0: it is
      let back in on R's current key and reads R again.

## 3. Chat between 1.8.0 machines

- [ ] Chat in the public room and in Q from A, B and C. Every line arrives
      once on every machine, in order, and none shows a notice that a newer
      Ember is needed. Replies, edits and reactions reach the other two once,
      and an edited line is marked edited.
- [ ] Send the longest line the composer accepts, with emoji that use joiners
      (a family, a flag, a skin tone, 👩‍💻), and a reply to it. Both arrive
      whole on the other two.
- [ ] Take C offline, send a few dozen lines, bring C back. C catches up on
      every line once.
- [ ] Send a file in each room. B and C receive the offer and the file.
- [ ] Restart every machine. The private rooms still find their members, and
      presence lights up within a few minutes.

## 4. A second rotation for rooms with members on 1.7.x

R, with D still on 1.7.8, past its cut-over rotation.

- [ ] With A running and D online for a few minutes, A records D: with A
      closed, `SELECT * FROM channel_v1_sightings;` shows R, at R's current
      key epoch (`SELECT key_epoch FROM channels WHERE channel_id = '<R>';`).
- [ ] Q, with no member on 1.7.x, has no row there, however long A runs.
- [ ] Update D to 1.8.0. Its last 1.7.x presence copies stay stored for up
      to 45 minutes, but A's walks ask only the current and previous
      15-minute presence keys, so they stop finding them within about half an
      hour; each one found starts the quiet span over. Leave A running for an
      hour and a half after D's update, then close it: R's `quiet_secs` is
      2,700 or more, the time A's walks ran after the last one that found an
      old copy. Leave A closed for an hour, then start it for ten minutes and
      close it again: the span has grown by those ten minutes and at most 20
      more, not by the hour A was closed.
- [ ] With A closed, run
      `UPDATE channel_v1_sightings SET quiet_secs = 604800 WHERE channel_id = '<R>';`
      and start A. Within a few minutes A rotates R a second time: an invite
      to R copied just before no longer works, and every member, D included,
      keeps reading. With A closed again,
      `SELECT * FROM channel_relink_rotations;` lists R.
- [ ] Start A again. R does not rotate a third time, and
      `channel_v1_sightings` no longer has R.

## 5. Older epochs

- [ ] F and G join Q from new invites after A has rotated Q at least twice
      (Rotate room key). Then A bans G. Close F and G: on each,
      `SELECT epoch FROM channel_key_epochs WHERE channel_id = '<Q>';` lists
      none of the epochs from before it joined. Close A and run
      `DELETE FROM channel_epoch_renewals WHERE channel_id = '<Q>';`, start
      A and leave it running for 20 minutes, then start F and G. Within a few
      minutes F holds Q's older epochs too, up to four in all, while G,
      banned before the renewal, gains no epoch. (The renewal starts as soon
      as A is running again, so the ban has to come before that restart. F
      has to start after the renewal: an older epoch it looked for in vain
      is not asked for again for six hours while it runs.)
- [ ] C offline across two rotations of Q, then back: C catches up one
      epoch at a time and reads the room again, older lines included.

## 6. Two devices owning one room

Set A2 up first (see "A second Ember on one PC"). A and A2 own Q; B and C
are members, and so are X, Y, Z, X2 and Y2. Between steps, check every
device is on one key: with each closed in turn,
`SELECT key_epoch FROM channels WHERE channel_id = '<Q>';` reads the same on
A, A2, B and C.

- [ ] Both open: A bans X. Within a few minutes A2 shows X as Banned, X
      stops seeing new lines, and every device is on one key.
- [ ] A2 closed: A bans Y (which rotates the key). Then A closed and A2
      started: change Q's topic on A2 straight away. Until A2 has read Q it
      refuses with "Ember is still loading this room's latest state from the
      network. Try again in a moment."; try again every few seconds. It goes
      through once A2 has read Q, and two minutes after the first refusal at
      the latest. Y is still banned afterwards, everywhere. A2 bans Z. Start
      A: X, Y and Z are all banned on every device, none of them sees new
      lines, and every device is on one key.
- [ ] Both open, A bans X2 and A2 bans Y2 within the same few seconds. After
      ten minutes every device is on one key, and whichever of the two is
      still listed Banned sees no new lines. (One of the two bans can be
      lost, as two people editing one document at once: the later snapshot
      wins. Ban that member again.)
- [ ] Rename Q on A. A2, running, shows the new name within about five
      minutes, keeps it after a restart, and B and C show it too. Renaming Q
      on A2 the same day is refused by the registry.
- [ ] A2 closed while A rotates Q twice. Start A2: within a few minutes it is
      on A's key and its lines reach B, C and the others.
- [ ] An epoch announced and never stored, staged on A2 with A and A2
      closed. Run these three statements, in order:

      ```sql
      UPDATE channels SET key_epoch_wanted = key_epoch + 1 WHERE channel_id = '<Q>';
      CREATE TABLE IF NOT EXISTS channel_owner_behind (
          channel_id TEXT PRIMARY KEY, epoch INTEGER NOT NULL,
          last_miss_at INTEGER NOT NULL, missed_secs INTEGER NOT NULL);
      INSERT INTO channel_owner_behind VALUES ('<Q>',
          (SELECT key_epoch_wanted FROM channels WHERE channel_id = '<Q>'),
          strftime('%s', 'now'), 43140);
      ```

      Start A2, with A still closed and B and C running. A miss counts only
      from a lookup that at least four Ember peers answered, and A2 makes the
      rotation that follows only once it has heard from at least five Ember
      nodes; B and C are only two: unless the public Ember network answers,
      keep at least three more Ember machines running (D, E and F, say).
      Within about ten minutes
      A2 rotates past that epoch, and B and C follow to the new one and can
      send in Q. (If A2's snapshot announcing the missing epoch reached them
      first, they could not send in Q until then.) Start A: it follows too.
- [ ] Last, delete Q on A2 (Delete room). An hour later A2 has fetched none
      of Q's keys back (with A2 closed, `channel_key_epochs` on A2 has
      nothing for Q). Restart A: within a few minutes it offers Keep it here
      and Remove it here, and Remove it here leaves A with none of Q's keys
      either.

## 7. What the cleanups touched

The transfers with friends on 1.7.8 and 1.7.4 are in section 2.

- [ ] Downloads from and uploads to a real eMule client, an eD2K server
      source and a KAD source all still work.
- [ ] A friend request A sends to B while they are connected through a
      friend's connect-back arrives and is accepted normally.

## 8. Translation review

All nine non-English locales. List what changed with
`git diff v1.7.8 -- messages/en.json`. In particular:

- [ ] `error_channels_owner_reading`: says the room is still being loaded
      and to try again in a moment, in the register of the locale's
      neighbouring `error_channels_owner_return_pending`.
