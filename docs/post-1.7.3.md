# After 1.7.3: planned for 1.7.4

What 1.7.3 left. Two sources: everything from `docs/post-1.7.2.md` that 1.7.3
did not get to, carried over unchanged in substance, and what the 1.7.3
Friends and Channels audits found but deliberately did not fix, usually
because the fix changes a wire or DHT format older builds read. Ordered by
priority within each section.

1.7.3 already did these:

- Files sent in chat to a friend who cannot be reached directly are queued
  and offered when their session comes up, a few at a time. Queued files
  survive restarts, can be cancelled, and end as undelivered after 7 days.
  The receiving half of that tester request is still open (see Friends).
- The Friends audit fixes: idle sessions no longer drop every few minutes,
  unverified friend requests grant nothing, browse no longer tears down the
  session it runs on, friend requests and attachment offers are rate limited,
  friends-only files are listed only to builds that honour the marking.
- The Channels audit fixes: old frames are neither relayed nor charged to
  their author, a decoy under a frame's id cannot get it dropped, reactions
  are budgeted per room and written in one transaction, catch-up has its own
  allowance and a per-neighbor frontier, moderators cannot act on each other,
  room transfers serve only the file as offered.

## Channels: before the BETA badge comes off

Items 1 to 6 are carried from the 1.7.2 plan; none was started in 1.7.3. Item
1 still needs a decision before items 2 and 4 can be finished, because it
decides what the formats freeze as. The 1.7.3 audit added items 7 to 9, which
change formats too and belong in the same freeze.

### 1. Decide the future of the room settings snapshot

**Why:** The owner's signed governance snapshot (`CHANNEL_KIND_MODERATION`)
is a whole replacement, and its worst case is 1164 of the 1165 bytes a STORE
carries (`MODERATION_TAIL_MAX_LEN` and the budget comment in
`network/ember/dht/publish.rs`). It has one byte of slack. Any new room
setting either takes that byte or squeezes the pins.

**Decision needed:** freeze it and put anything new in extension frames
(gossip only, not kept on the DHT), or add a second record, a "room
settings" kind signed by the room key under a key of its own, with a version
byte and room to grow. The recommendation is the second record.

**Then:** if it is the second record, define it (kind 8), with a storer rule,
a TTL equal to `CHANNEL_GOVERNANCE_TTL`, the owner republishing it, and a
rule for what members do when only one of the two records arrives. Item 7's
key commitment is a candidate field for it.

### 2. A second version of the chat message

**Why:** A chat line (`CHAT_PLAIN_VERSION`, 15) has a fixed layout. Replies,
mentions and attachments have each been fitted around it. A new message type
with optional fields (a version byte, then fields tagged by type and length
that a reader skips when it does not know them) would stop each new feature
needing a new number.

**To do:**

- Define the frame as an extension frame (kind 64 or up), which builds from
  1.7.2 on already relay.
- Send it beside today's line during a transition, so 1.7.1 and older still
  read the room. Receivers keep the first one that arrives under the `msg_id`.
- Give edits (`CHAT_EDIT_PLAIN_VERSION`) the same treatment.
- Carry the emoji joiners (ZWJ, ZWNJ, VS15/16) in the new frame. 1.7.3
  receivers already keep them (`sanitize_message_text`), but senders strip
  them (`sanitize_outgoing_message_text`) because 1.6–1.7.2 receivers strip
  them on receipt, which breaks the signature there: the line is not
  re-served in catch-up and an edit is not relayed at all. The new frame is
  the capability signal that lets a sender keep them.
- Decide which release stops sending the old line, and write it into the
  format spec (item 4).

**Tests:** both frames under one `msg_id` store one line; a reader that only
knows the old line still shows the conversation; unknown optional fields are
skipped; every signature covers the optional fields.

### 3. "Needs a newer Ember" for the two envelopes still silent

**Why:** The outer gossip envelope (`CHANNEL_MSG_VERSION`) and the overlay
relay envelope (`CHANNEL_RELAY_ENVELOPE_VERSION`) still drop a version they
do not know without a word. If either changes, members on older builds would
see a room go quiet.

**To do:** count unknown envelope versions per room, as `channel_newer_frames`
does for message kinds, and show the existing banner. Relay an unknown outer
version unopened, as extension frames are.

### 4. A short format spec

**To do:** `docs/channels-format.md`, covering every gossip frame number
(`*_PLAIN_VERSION`, in use and retired, never reused), every DHT channel
record kind with its storer rule (`channel_store_ok`) and TTL (`record_ttl`),
the extension-frame layout and display flag, the envelope-version rule (a
later epoch-envelope version needs a DHT key of its own), the owned-rooms
list prefix rule, the new `EMBER_EXT_BROWSE_SCOPE_AWARE` sub-type's meaning on
friend sessions, and what is frozen at the end of the beta.

### 5. Test across real machines

**To do:** add a Channels section to the release checklist
(`docs/release-checklist-1.7.0.md` is the model) and run it on three or more
machines, at least one behind a firewall that is not reachable: create public
and private rooms, chat, edit, react, pin, send a file; ban a member; rotate a
private room's key with a member offline; name a successor and let them take
over; hand a room off; back up and restore on another machine, once with the
original switched off; run a 1.7.1 build in the same room.

Add to it what the 1.7.3 audit changed: a member away for a while catches up
on the whole backlog, not just the newest lines; a moderator cannot ban
another moderator; a room file saved over after it was offered fails as
"source gone" rather than arriving.

### 6. Release with the formats frozen and the badge still on

Ship with items 1 to 4 and 7 to 9 done and the formats frozen. If that release
needs no format change, remove the BETA badge in the next one.

### 7. A way back in for a member behind a private room's key

**Why:** A member who falls behind past the retained epochs, or whose sealed
key record lapsed, is stuck until they leave and rejoin. 1.7.3 briefly took
the key from a fresh invite for a room already held, and backed it out: an
invite is unauthenticated, nothing signed commits to an epoch's key, and the
store keeps the first key it is given for an epoch, so a crafted invite would
have the device seal under a key its author reads and refuse the genuine one
later.

**To do:** have the owner's epoch announcement carry a commitment to each
epoch's key (for example `BLAKE3(domain || epoch || content_key)`), so an
invite's key can be checked before it is stored. Then re-enable taking it from
an invite when the room is behind and the commitment matches.

### 8. An authenticated marker on catch-up re-serves

**Why:** A catch-up reply is re-sealed by the responder under its current key
and sent at TTL 1, and TTL is the only thing marking it as not the author's own
seal. TTL is outside the AEAD, so a relay can raise it. That gets a line an
evicted member wrote, stored by a lagging member and later re-served, read as
live under the current key, which puts the evicted identity's new key on the
owner's roster and has the next epoch sealed to it. 1.7.3 narrowed it by also
requiring the line to be recent (`chat_author_joins_gossip_roster`), and did
not drop chat-based admission altogether because members on builds without
key-proven beacons are admitted only that way.

**To do:** mark re-serves inside the sealed part (a flag in the plaintext, or
the AAD), or admit new private-room members only through key-proven beacons
once the room runs builds that send them. Either is a format change.

### 9. Keep private-room membership out of the DHT

**Why:** A private room's presence record is stored under a key blinded with
the join secret, but its body carries the room id and the member's long-term
public key in the clear, so every storing node learns the roster. Key-epoch
records are worse: `epoch_key(channel_id, member_pubkey, epoch)` is built
from public values, so anyone who knows the room id (it is in every gossip
header) can test whether a given key is a member.

**To do:** derive epoch keys from the join secret, put a blinded member id in
`extra`, and for private presence records replace the room id and pubkey with
join-secret-derived values (or sign with a per-room pseudonymous key). Old and
new builds would no longer find each other's records, so it needs a version
cut-over like item 2's.

## Channels: smaller follow-ups from the 1.7.3 audit

- **Relayed catch-up replies do not move the frontier.** Progress is credited
  only to the neighbor asked, when its reply reaches us directly; a reply
  carried by another member hop cannot be told from that member's own TTL-1
  line. Such a neighbor is asked the same range again next round, which costs
  bandwidth but loses nothing. Item 8's marker would let relayed replies count.
- **Bans stored before 1.7.3 are not known to be the owner's** until the
  owner's next republish (about six hours), so a moderator could lift one in
  that window.
- **Room transfer quality:** derive the pairwise transfer key once per
  transfer on the receive side too (`channel_gossip.rs` derives it per inbound
  frame, a DH each); move the remaining synchronous `remove_file` calls on the
  network task to `spawn_blocking`; defer the accept handler's disk work to a
  task so the event loop does not wait on it.
- **Moderation lock and the registry.** Releasing `MODERATION_LOCK` across
  Rendezvous round-trips means two racing owner commands can briefly leave the
  registry on the older value until the next republish.
- **No component tests** for the 1.7.3 changes to `ChatConversation.svelte`
  and the Channels page (early delivery, pin cleanup, slow-mode announcements,
  coalesced refreshes); only the store logic is unit tested. A component
  harness would cover them.

## Owned-room recovery: known limits

Carried from the 1.7.2 plan, unchanged. Not beta blockers, but they belong in
the format spec and the release notes.

- **One identity on two devices at once.** Each device publishes its own
  owned-rooms list and the newer one wins, so the other device's rooms stay
  recoverable only until its next publish. A fix would read the network's
  list before every publish and merge it.
- **A taken-over private room lost before its first rotation.** Recovery
  derives the wrong key and nothing is pending to correct it. Sealing epoch 0
  to ourselves for rooms we did not create would close the gap.
- **Old backups keep rooms deleted since.** A room key signature on the
  deletion, served by the registry, would let it be trusted.
- **The list shows how many rooms an identity owns.** Padding it to a fixed
  size would hide that.
- **Older builds don't store record kind 7.** Absence is only concluded after
  four nodes have answered (`MIN_RESPONDERS_FOR_ABSENCE`).
- **Recovery has no end-to-end test**; item 5's restore run is the only cover
  for the network flow.

## Discover spam folding: follow-ups

Carried from the 1.7.2 plan.

- Member counts come from presence records, which anyone can sign. Friends in
  the room, or the listing's age, would be better signals.
- Tune `LIKELY_SPAM_SCORE` and `DUPLICATE_NAME_FLOOD` from real use.

## Friends

### Tester requests, carried from the 1.7.2 plan

- **Offers that wait for the friend: the receiving half.** 1.7.3 queues a
  sent file until the friend can be reached. An inbound offer still lapses
  after five minutes unanswered (`ATTACH_OFFER_TTL_SECS`), so a friend at
  their desk but away from it still misses a file over the auto-accept
  ceiling. To do: keep an inbound offer waiting until the user answers,
  decide how long the sender's grant holds for one (the 24-hour grant is the
  piece to build on), and what happens when the file moves first.
- **An Away status.** An "Away" or "Not at PC" state, set by hand and by idle
  time, sent as a new friend-session extension frame (older builds ignore
  unknown ones), shown in the friends list and the chat header.

### Known limits from the 1.7.3 audit

- **Idle sessions with a pre-1.7.3 friend still drop.** The fix paces each
  side's keepalive off its own writes; an older build still resets its timer
  on inbound traffic, so on an idle link it rarely sends and our reader hits
  the 180-second record timeout. Fully fixed once both ends run 1.7.3.
- **Friends on 1.7.0 to 1.7.2 no longer see our friends-only files in
  Browse.** They honour the scope marking but do not send
  `EMBER_EXT_BROWSE_SCOPE_AWARE`, and a friend session carries nothing else
  that tells them from 1.6.x, which would republish the files. Kept that way
  on purpose for 1.7.3, since a leak cannot be taken back and the gap closes
  as friends update. Say so in the release notes.
- **File offers still tell older builds a file is friends-only by a flag they
  may drop.** `OfferFileToFriend` sends a friends-only file to any mutual
  friend; a build that predates the flag files the copy as public. Refuse to
  offer a friends-only file to a friend whose session has not shown it reads
  the marking, as Browse now does.
- **The hash-probe exemption trusts a claimed user hash.** A request under a
  mutual friend's eD2K user hash is not counted toward the probe ban, so
  someone spoofing that hash can probe without being banned (the answers are
  the same either way). Matching the friend's live session address would
  close it.

### Smaller follow-ups

- The pop-out chat window runs its own copy of the friends store, so the
  shared offer-accept lock does not reach it; the backend's `already_queued`
  answer covers the double accept.
- Unread counts on startup can still miss one message if messages arrive
  during both seed fetches; the backend returning the newest message id with
  each count would make them exact.
- Derive the Friends page's firewall state from `$networkStats` instead of
  its own fetch and listener, and reuse `friendsList` in the layout instead of
  a second `getFriends`.
- `reseed_friend_endpoint` holds the transfer-manager read lock across an
  await on the source manager.
- Inbound friend nicknames are capped at 64 characters, local edits at 64
  bytes; accepting a request can store one the edit box then refuses.
- The friend session reader accepts 5 MB frames where the inbound path
  accepts 512 KiB; align them.
- The trailing `EmberFriendSearchFailed` that releases an outbound session
  slot carries no attempt id, so it can release a newer attempt's reservation.
- Duplicate accept acks for a punch transfer each start a fresh punch
  registration.
- `process_inbound_friend_request` and `ask_unmatched_friend_through_rooms`
  load the whole friend list to find one row.

## Known limits carried from the 1.7.2 audit

- **A claim the owner meets on its way back.** An owner back from a claimable
  silence follows its nominee's claim only in a copy signed before it
  returned, so a re-sign landing just before the owner's first successful
  fetch leaves it running a room its members have left.
- **Downgrading to 1.7.1 leaves one upload slot.** Auto is stored as
  `max_concurrent_uploads = 0`, which 1.7.1 repairs to 1 and saves. A separate
  `upload_slots_auto` flag, with the number kept in 1.7.1's range, would make
  the downgrade harmless. The 1.7.3 Auto changes did not touch this.

## Ember DHT

- Key-epoch records are still stored on our own table's closest nodes, not on
  the nodes a lookup finds. A lookup per member would flood the target-lookup
  queue in a large room; batching them, or resolving the room's neighbourhood
  once, would let them join the lookup-backed set. Item 9 changes these keys,
  so the two are best done together.
