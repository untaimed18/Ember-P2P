# After 1.7.3: planned for 1.7.4

What 1.7.3 left. Two sources: everything from `docs/post-1.7.2.md` that 1.7.3
did not get to, carried over unchanged in substance, and what the 1.7.3
Friends and Channels audits found but deliberately did not fix, usually
because the fix changes a wire or DHT format older builds read.

1.7.4's scope is now settled: testing and small fixes, with no Channels format
change. 1.7.4 already carries a large amount of new code and has not been run
across machines; a format change on top would make a failed run hard to read,
and the mixed-version run in `docs/release-checklist-1.7.4.md` assumes 1.7.4
sends nothing 1.7.3 cannot read. The format freeze moves to 1.7.5. Everything
not in "Left for 1.7.4" below, including the full Channels freeze items,
the receiving half of waiting offers, and every known limit, has moved to
`docs/post-1.7.4.md`, the plan for 1.7.5. Anything on the list below that
1.7.4 does not finish moves there too.

1.7.3 already did these:

- Files sent in chat to a friend who cannot be reached directly are queued
  and offered when their session comes up, a few at a time. Queued files
  survive restarts, can be cancelled, and end as undelivered after 7 days.
  The receiving half of that tester request is planned for 1.7.5.
- The Friends audit fixes: idle sessions no longer drop every few minutes,
  unverified friend requests grant nothing, browse no longer tears down the
  session it runs on, friend requests and attachment offers are rate limited,
  friends-only files are listed only to builds that honour the marking.
- The Channels audit fixes: old frames are neither relayed nor charged to
  their author, a decoy under a frame's id cannot get it dropped, reactions
  are budgeted per room and written in one transaction, catch-up has its own
  allowance and a per-neighbor frontier, moderators cannot act on each other,
  room transfers serve only the file as offered.

1.7.4 has done these so far:

- Friends-only files are offered only to a friend whose session has shown it
  honours the marking (`EMBER_EXT_BROWSE_SCOPE_AWARE` or
  `EMBER_EXT_MAILBOX_AWARE`); anyone else is refused with
  `peers_offer_needs_newer_ember`.
- Unknown gossip and relay envelope versions are counted per room and raise the
  "needs a newer Ember" notice (the first half of the freeze plan's item 3).
- `docs/channels-format.md` exists (the freeze plan's item 4) and
  `docs/release-checklist-1.7.4.md` has the cross-machine Channels run.
- Smaller Friends follow-ups: the friend-session frame limit, the search-failed
  slot release, and `reseed_friend_endpoint`'s lock.
- **The room settings decision:** a second "room settings" record, kind 8,
  built in 1.7.5. Written into `docs/post-1.7.4.md` item 1 and
  `docs/channels-format.md`.
- **One limit on friend names:** 64 characters (`MAX_FRIEND_NICKNAME_CHARS`)
  for names a request brings in and names typed in Add Friend or the rename
  box alike, so accepting a request never stores a name the rename box then
  refuses. The limit was 64 bytes for typed names; the two error strings now
  say characters in all nine locales.
- **One punch per accepted transfer:** a repeated accept ack for the same
  request is ignored (`first_friend_xfer_accept`), so it neither publishes a
  second rendezvous punch registration nor counts twice in the stats.
- **Single-row friend lookups:** `process_inbound_friend_request` and
  `ask_unmatched_friend_through_rooms` read one row (`friend_mutual`,
  `get_friend_public_key`) instead of the whole friend list.
- **Room transfer disk work off the network task:** every `.part` delete goes
  through `discard_part_file` on the blocking pool, and an accept readies its
  part file in the background (`begin_xfer_accept`) and finishes in the Kad
  process tick (`apply_xfer_accept_prepared`), which re-checks the offer, the
  room, bans and the receive cap first. Accepts still in flight count against
  the cap and the free-space check.
- **Release notes** in `docs/index.html`, checked with
  `node scripts/release-notes.mjs` and `node scripts/verify-release-policy.mjs`.
  The date says October 18, 2026: set it to the day the tag is cut.

## Left for 1.7.4

### Run the rest of the release checklist

Section 0 of `docs/release-checklist-1.7.4.md`, the automated checks, has
passed. Sections 1 to 4 need people and machines: Channels on three or more
machines with one behind a firewall that is not reachable, Friends, mixed
versions with 1.7.3, and the translation review. File anything that fails
before tagging. The Channels run is also the baseline for 1.7.5's format
freeze: note anything that looks like a format problem in
`docs/post-1.7.4.md` rather than fixing it here.
