# 1.7.4 release checklist

What automated checks cannot cover before tagging `v1.7.4`. Tick each box, and
file anything that fails before tagging rather than after. Channels is still a
beta: this is the cross-machine run `docs/post-1.7.3.md` item 5 asks for, and
its results decide whether the formats can freeze.

## 0. Automated checks

- [ ] `npm test` and `npm run check` pass.
- [ ] `cargo clippy --tests` is clean and `cargo test --lib` passes in `src-tauri`.
- [ ] `node scripts/verify-release-policy.mjs` passes for 1.7.4.
- [ ] `node scripts/release-notes.mjs` prints the 1.7.4 notes, and they read
      correctly as Markdown.

## 1. Channels across real machines

Three or more computers, all on 1.7.4, at least one behind a firewall that is
not reachable from outside (no port forwarding, UPnP off). Call them A
(reachable), B (reachable) and C (firewalled).

### Rooms and chat

- [ ] A creates a public room and a private room; B and C join both, from the
      directory and from an invite.
- [ ] Chat in both rooms from all three. Every line arrives on every machine,
      in order, including C's, and C sees A's and B's.
- [ ] Edit a line, react to one, reply to one, pin one. Each change reaches
      the other two.
- [ ] Send a file in each room from A, B and C. Each completes on the other two.
- [ ] Take C offline for a while (an hour or more, with a few dozen lines sent
      meanwhile). When C comes back it catches up on the whole backlog, not just
      the newest lines.

### Moderation

- [ ] A bans a member. Their new lines stop reaching the room, and they see
      that they were banned.
- [ ] A makes B a moderator. B cannot ban or unban A, or another moderator.
- [ ] A rotates the private room's key with C offline. When C returns it reads
      the room again without leaving and rejoining.

### Ownership

- [ ] A names B as successor; let the claim window pass with A offline. B takes
      the room over and the others follow.
- [ ] A hands a room off to B directly. Members follow to the new room.
- [ ] Back up A and restore on another machine, once with A still running and
      once with A switched off first. The owned rooms are recovered and run
      from the restored machine.

### Files offered in a room

- [ ] Offer a file in a room, then save over it on the offering machine before
      anyone downloads it. The download fails as "source gone"; it does not
      arrive with the new contents.

## 2. Friends

- [ ] Mark a file friends-only and send it to a friend on 1.7.4 from the
      Library. It arrives, and on their machine it is friends-only too.
- [ ] Send the same file to a friend on 1.7.3 who has not browsed you since
      their session came up. It is refused with "your friend's Ember is too old
      to keep friends-only files private". After they browse you, it goes.
- [ ] Send a file that is not friends-only to the 1.7.3 friend. It goes as
      before.
- [ ] Browse a friend whose shares are in the hundreds of files: the listing
      arrives (the friend-session frame limit is now 512 KiB both ways).
- [ ] Leave a friend chat idle for half an hour with one side on 1.7.4 and the
      other on 1.7.3. Note whether the session drops (it may, until both run
      1.7.3 or later; see `docs/post-1.7.3.md`).

## 3. Mixed versions (1.7.4 with 1.7.3)

Machine A on 1.7.4, machine B on 1.7.3, in the same rooms and mutual friends.

- [ ] Both read each other's lines, edits and reactions in every room.
- [ ] Neither shows a "needs a newer Ember" notice: 1.7.4 sends no envelope
      1.7.3 cannot read. If one appears, note the room and what was sent.
- [ ] Room files and friend chat attachments work both ways.
- [ ] A friend request between them works both ways.

## 4. Translation review

New strings this release, in all eight non-English locales:

- [ ] `error_peers_offer_needs_newer_ember` (the friends-only refusal).
- [ ] `error_peers_offer_library_unconfirmed` (the same refusal while the
      library is still loading or was only read in part).
- [ ] `channels_newer_envelope` (members on a newer Ember).
- [ ] Channels UX pass: `channels_ban_confirm*` (the Ban confirmation),
      `channels_offers_waiting_*` and `channels_offers_review` (the file
      waiting banner), `channels_hide_listing_aria`, `channels_delivery_sending`,
      `channels_search_unavailable`, `channels_send_file_member_banned`,
      `channels_send_file_busy`.

List everything else that changed with `git diff v1.7.3 -- messages/en.json`.
