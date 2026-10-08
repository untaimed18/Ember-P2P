# After 1.7.2: planned for 1.7.3

What is left before Channels can drop its BETA badge, plus the known limits
of the work 1.7.2 shipped. Ordered by priority. Item 1 needs a decision
before items 2 and 4 can be finished, because it decides what the formats
freeze as.

1.7.2 already did these:

- Message kinds from newer builds are relayed rather than dropped (extension
  frames, kinds 64 and up), and a room says when it needs a newer Ember.
- Room keys sealed in a newer envelope version are stored and carried, and a
  room whose key needs a newer Ember says so.
- An owner can recover every room they own from their identity alone: the
  owned-rooms list, record kind 7, read back by `commands/channel_recovery.rs`.
- Owners are asked to name a successor once a room has three other members.
- Members see that history stops where this device's does.
- Discover folds away listings that look like spam, and hiding a listing says
  what it does.
- Room governance, Discover listings, handoffs, claims and owned-rooms lists
  are stored on the nodes a lookup finds closest to their key, as library
  records are, rather than on the closest our own table holds.

## Channels: before the BETA badge comes off

### 1. Decide the future of the room settings snapshot

**Why:** The owner's signed governance snapshot (`CHANNEL_KIND_MODERATION`)
is a whole replacement, and its worst case is 1164 of the 1165 bytes a STORE
carries (`MODERATION_TAIL_MAX_LEN` and the budget comment in
`network/ember/dht/publish.rs`). It has one byte of slack. Any new room
setting either takes that byte or squeezes the pins, which already take only
what is left.

**Decision needed:**

- **Freeze it.** The current settings are final, and anything new goes in
  extension frames, which are gossip only and are not kept on the DHT.
- **Or add a second record**, a "room settings" kind signed by the room key
  under a key of its own, with a version byte and room to grow. Members
  read both.

The recommendation is the second record. Topic, bans, moderators and the key
epoch stay where they are; anything new goes in the new record.

**Then:** if it is the second record, define it (kind 8), with a storer rule,
a TTL equal to `CHANNEL_GOVERNANCE_TTL`, the owner republishing it, and a
rule for what members do when only one of the two records arrives.

### 2. A second version of the chat message

**Why:** A chat line (`CHAT_PLAIN_VERSION`, 15) has a fixed layout. Replies,
mentions and attachments have each been fitted around it instead of carried
in it. A new message type with optional fields (a version byte, then
fields tagged by type and length that a reader skips when it does not know
them) would stop each new feature needing a new number.

**To do:**

- Define the frame. An extension frame (kind 64 or up) is the natural home,
  since builds from 1.7.2 on already relay those.
- Send it beside today's line during a transition, so 1.7.1 and older still
  read the room. Receivers keep the first one that arrives under the
  `msg_id`.
- Give edits (`CHAT_EDIT_PLAIN_VERSION`) the same treatment.
- Decide which release stops sending the old line, and write it into the
  format spec (item 4).

**Tests:** both frames under one `msg_id` store one line; a reader that only
knows the old line still shows the conversation; unknown optional fields are
skipped; every signature covers the optional fields.

### 3. "Needs a newer Ember" for the two envelopes still silent

**Why:** Message kinds and room keys say when a newer build is needed, but
the outer gossip envelope (`CHANNEL_MSG_VERSION`, `channel.rs`) and the
overlay relay envelope (`CHANNEL_RELAY_ENVELOPE_VERSION`) still drop a version
they do not know without a word. If either changes, members on older builds
would see a room go quiet.

**To do:** count unknown envelope versions per room, as `channel_newer_frames`
does for message kinds, and show the existing banner. Relay an unknown
outer version unopened, as extension frames are, so the network carries it
before everyone has upgraded.

### 4. A short format spec

**Why:** The rules that keep old and new builds working together are spread
across code comments. Before the formats freeze they need writing down in one
place, for whoever changes them next.

**To do:** `docs/channels-format.md`, covering:

- Every gossip frame number (`*_PLAIN_VERSION`), in use and retired, with why
  each was retired. A retired number is never reused.
- Every DHT channel record kind (1 to 7, and 8 if item 1 adds it), with its
  storer rule (`channel_store_ok`) and TTL (`record_ttl`).
- Extension frames: the layout, the display flag, and that unknown kinds are
  relayed and counted.
- The envelope-version rule: a later epoch-envelope version needs a DHT key
  of its own, because a storer keeps one record per publisher under a key.
- The owned-rooms list: later versions keep the v1 layout as their prefix.
- What is frozen at the end of the beta.

### 5. Test across real machines

**To do:** add a Channels section to the release checklist
(`docs/release-checklist-1.7.0.md` is the model), and run it on three or more
machines, at least one behind a firewall that is not reachable:

- Create public and private rooms, join from the other machines, chat, edit,
  react, pin, and send a file.
- Ban a member: their key stops working, and the rest of the room carries on.
- Rotate a private room's key with a member offline; they catch up when they
  return.
- Name a successor, stay away past the window, and have them take over.
- Hand a room off.
- Back up, create more rooms, restore on another machine, and check that
  every room comes back with its bans, topic and current key. Do it once with
  the original machine switched off.
- Run a 1.7.1 build in the same room and check it still reads the chat.

### 6. Release with the formats frozen and the badge still on

Ship 1.7.3 with items 1 to 4 done and the formats frozen. If that release
needs no format change, remove the BETA badge in the next one.

## Owned-room recovery: known limits

These are not beta blockers, but they belong in the format spec and the
release notes.

- **One identity on two devices at once.** Each device publishes its own
  owned-rooms list, and the newer one wins on the network. The other
  device's rooms stay recoverable only until its next publish. A fix would
  read the network's list before every publish and merge it.
- **A taken-over private room lost before its first rotation.** A room taken
  over by handoff keeps the key it inherited until it rotates. If the device
  is lost in that window, recovery derives the wrong key and nothing is
  pending to correct it. Sealing epoch 0 to ourselves for rooms we did not
  create would close the gap.
- **Old backups keep rooms deleted since.** The registry's deleted list is
  the server's word, not the room key's, so it is only trusted to keep a room
  from coming back, never to put out a room a device already runs. A room key
  signature on the deletion, served by the registry, would let it do both.
- **The list shows how many rooms an identity owns.** The salts reveal nothing
  without the identity's secret key, but anyone with its public key can count
  them. Padding the list to a fixed size would hide that.
- **Older builds don't store record kind 7.** Until most of the network runs
  1.7.2 or later, fewer nodes hold the list. Absence is only concluded after
  four nodes have answered the lookup (`MIN_RESPONDERS_FOR_ABSENCE`).
- **Recovery has no end-to-end test.** The record and database layers are
  unit tested, and so are the pure parts of `channel_recovery.rs` (merging
  lists, handoffs and claims). The network flow is covered only by item 5's
  restore run.

## Discover spam folding: follow-ups

`src/lib/channelListingSpam.ts` scores listings on this device, from the name
and the reported size: a link in the name, repeated characters, all capitals,
mostly symbols, several copies of one name, an empty room.

- Member counts come from presence records, which anyone can sign, so a
  spammer can inflate them. Better signals would be friends who are in the
  room, or how long the listing has existed.
- Tune the thresholds (`LIKELY_SPAM_SCORE`, `DUPLICATE_NAME_FLOOD`) from what
  shows up in real use.

## Friends: tester requests

Friends is marked BETA from 1.7.2. Two requests from testing:

- **Offers that wait for the friend.** A chat attachment needs the friend
  connected to be offered, and lapses after five minutes unanswered
  (`ATTACH_OFFER_TTL_SECS`), so a file sent to someone at their desk but
  away from it disappears. Files up to the auto-accept ceiling (25 MB by
  default) already arrive unasked. To do: keep a sent file queued across
  restarts and re-offer it when the friend's session comes up; keep an
  inbound offer waiting until the user answers rather than five minutes;
  decide how long either side holds one, and what happens when the file
  moves first. "Try again" and the 24-hour grant are the pieces to build on.
- **An Away status.** Friends see online or offline only. An "Away" or "Not
  at PC" state, set by hand and by idle time, sent as a new friend-session
  extension frame (older builds ignore unknown ones), shown in the friends
  list and the chat header.

## Known limits from the 1.7.2 audit

- **A claim the owner meets on its way back.** An owner back from a
  claimable silence follows its nominee's claim only in a copy signed before
  it returned. The nominee re-signs every six hours, so a re-sign landing in
  the minutes before the owner's first successful fetch leaves it running a
  room its members have left. Dropping the signed-at rule would close it, at
  the cost of following a claim first published after the return; the
  members follow the owner's commitment either way.
- **Downgrading to 1.7.1 leaves one upload slot.** 1.7.2 stores
  Auto as `max_concurrent_uploads = 0`; 1.7.1 repairs that to 1 and saves
  it. A separate `upload_slots_auto` flag, with the number kept in 1.7.1's
  range, would make the downgrade harmless.

## Ember DHT

- Key-epoch records are still stored on our own table's closest nodes. A
  lookup per member would flood the target-lookup queue in a large room;
  batching them, or resolving the room's neighbourhood once, would let them
  join the lookup-backed set.
