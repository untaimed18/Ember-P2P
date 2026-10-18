# After 1.7.4: planned for 1.7.5

Written before 1.7.4 shipped, when its scope was settled: 1.7.4 is testing
and small fixes with no Channels format change, so it can be judged on its
own, and 1.7.5 is the release that freezes the Channels formats. Everything
in `docs/post-1.7.3.md` outside 1.7.4's list is here. If 1.7.4 does not
finish something on its list, move it here. Ordered by priority within each
section.

What 1.7.4 does is listed in `docs/post-1.7.3.md`. Two of its items feed this
plan: the decision on item 1 below (a kind 8 record), and the cross-machine
run in `docs/release-checklist-1.7.4.md`, which is the baseline item 5 is
measured against.

## Channels: the format freeze

All nine items ship together in 1.7.5, and the formats freeze with them.
Items 1, 2, 7, 8 and 9 each change a wire or DHT format; items 2 and 9 each
need a transition in which old and new builds share a room, and doing them in
one release means one cut-over to test. Item 1 decides what the formats
freeze as, so it comes first.

### 1. Decide the future of the room settings snapshot

**Why:** The owner's signed governance snapshot (`CHANNEL_KIND_MODERATION`)
is a whole replacement, and its worst case is 1164 of the 1165 bytes a STORE
carries (`MODERATION_TAIL_MAX_LEN` and the budget comment in
`network/ember/dht/publish.rs`). It has one byte of slack. Any new room
setting either takes that byte or squeezes the pins.

**Decided in 1.7.4:** a second record, a "room settings" kind signed by the
room key under a key of its own, with a version byte and room to grow. The
moderation snapshot freezes as it is. The alternative, freezing the snapshot
and putting anything new in extension frames, was turned down because
extension frames are gossip only and not kept on the DHT, so a member who was
offline when a setting changed would never learn it.

**To do:** define it as kind 8, with a storer rule, a TTL equal to
`CHANNEL_GOVERNANCE_TTL`, the owner republishing it, and a rule for what
members do when only one of the two records arrives. Item 7's key commitment
is a candidate field for it. Write the layout into `docs/channels-format.md`.

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

**Done in 1.7.4:** unknown outer gossip (`CHANNEL_MSG_VERSION`) and relay
(`CHANNEL_RELAY_ENVELOPE_VERSION`) envelope versions are counted per room in
`channel_newer_frames` (sources `envelope` and `relay`) and show the existing
banner, from hops on the room's roster only (`note_unread_channel_envelope`).
Every future version must keep the version at byte 0 and the room id at bytes
1 to 17, which is what the count reads.

**Still open:** relaying an unknown outer version unopened. Members forward
only frames that open (`handle_inbound_channel_relay`), which is what stops a
hop using them to spread junk; an unknown version cannot open, so carrying it
reopens that. Decide at the freeze whether a version bump is announced first
(for example in a signed governance field) so members know to carry it.

### 4. A short format spec

**Done in 1.7.4:** `docs/channels-format.md`. Keep it current with every
change in this section, and at the freeze mark what is frozen: every gossip
frame number, every DHT record kind with its storer rule and TTL, the
extension-frame layout, the envelope-version rule, the owned-rooms prefix
rule and the friend-session capability sub-types.

### 5. Test across real machines

1.7.4 runs `docs/release-checklist-1.7.4.md` section 1 on today's formats.
For 1.7.5, write `docs/release-checklist-1.7.5.md` from it and run it on
three or more machines, at least one behind a firewall that is not
reachable, adding what this section changes:

- Chat and edits in the new frame (item 2) between 1.7.5 machines, and with a
  1.7.4 machine in the same room during the transition: one line per
  `msg_id` everywhere, emoji joiners kept between 1.7.5 machines.
- The room settings record (item 1), if it is added: a setting change reaches
  every member, and a member that gets only one of the two records behaves as
  the rule says.
- A member behind a private room's key gets back in from a fresh invite
  (item 7), and a crafted invite with the wrong key is refused.
- A line an evicted member wrote, re-served by a lagging member, does not put
  the evicted identity back on the roster (item 8).
- Private rooms still find their presence and key records after item 9's
  cut-over, and a 1.7.4 member in the same room still reads it for as long as
  the transition promises.

### 6. Release with the formats frozen and the badge still on

Ship 1.7.5 with items 1 to 4 and 7 to 9 done and the formats frozen. If 1.7.6
needs no format change, remove the BETA badge in 1.7.6.

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

**With it:** key-epoch records are still stored on our own table's closest
nodes, not on the nodes a lookup finds. A lookup per member would flood the
target-lookup queue in a large room; batching them, or resolving the room's
neighbourhood once, would let them join the lookup-backed set. Item 9 changes
these keys, so do both together.

## Channels: smaller follow-ups

- **Relayed catch-up replies do not move the frontier.** Progress is credited
  only to the neighbor asked, when its reply reaches us directly; a reply
  carried by another member hop cannot be told from that member's own TTL-1
  line. Such a neighbor is asked the same range again next round, which costs
  bandwidth but loses nothing. Do it with item 8, whose marker lets relayed
  replies count.
- **Room transfer key derivation:** derive the pairwise transfer key once per
  transfer on the receive side too (`channel_gossip.rs` derives it per inbound
  frame, a DH each). 1.7.4 moved the disk-work half off the network task.
- **Moderation lock and the registry.** Releasing `MODERATION_LOCK` across
  Rendezvous round-trips means two racing owner commands can briefly leave the
  registry on the older value until the next republish.
- **Bans stored before 1.7.3 are not known to be the owner's** until the
  owner's next republish (about six hours), so a moderator could lift one in
  that window. It matters less with each release, since it applies only to
  bans no owner has republished since 1.7.3.

## Friends: offers that wait for the friend, the receiving half

Planned for 1.7.5. 1.7.3 queues a sent file until the friend can be reached.
An inbound offer still lapses after five minutes unanswered
(`ATTACH_OFFER_TTL_SECS`), so a friend at their desk but away from it still
misses a file over the auto-accept ceiling.

**Decided when 1.7.4's scope was set:**

- **Session only, first.** The receiver keeps a pending offer in memory
  (`state.attach_inbound`) until the user answers, the session ends, or
  `ATTACH_GRANT_TTL_SECS` (a day) passes. A restart still lapses it. Saving
  offers across restarts (it needs `AttachOffer`'s fields, not just the
  `awaiting` row) can follow later.
- **A capability signal of its own,** sent when the session comes up, not
  `EMBER_EXT_MAILBOX_AWARE`. 1.7.4 sends that flag and still drops offers at
  `ATTACH_OFFER_TTL_SECS`, so it cannot prove a receiver waits. The sender
  holds its grant past `ATTACH_OFFER_TTL_SECS` only for a session that sent
  the new signal; for anyone else, offers lapse as they do today.
- **The file moving first.** An accept after the file changed already ends as
  `source_gone` on the stream. The card should say so when the accept is
  pressed rather than after a dial.

**Tests:** an offer answered after an hour still transfers; one answered after
the grant lapses fails cleanly on both ends; a 1.7.4 receiver's offer still
lapses at five minutes and the sender's card says so; an accept after the
file changed says "source gone" without dialing.

## Later: not needed for the freeze

Not planned for 1.7.5. Take them on if there is room, or when real use says
they matter.

- **An Away status.** An "Away" or "Not at PC" state, set by hand and by idle
  time, sent as a new friend-session extension frame (older builds ignore
  unknown ones), shown in the friends list and the chat header.
- **No component tests** for the 1.7.3 changes to `ChatConversation.svelte`
  and the Channels page (early delivery, pin cleanup, slow-mode announcements,
  coalesced refreshes); only the store logic is unit tested. A component
  harness would cover them.
- **Discover spam folding.** Member counts come from presence records, which
  anyone can sign; friends in the room, or the listing's age, would be better
  signals. Tune `LIKELY_SPAM_SCORE` and `DUPLICATE_NAME_FLOOD` from real use.
- **Friends, smaller:**
  - The pop-out chat window runs its own copy of the friends store, so the
    shared offer-accept lock does not reach it; the backend's
    `already_queued` answer covers the double accept.
  - Unread counts on startup can still miss one message if messages arrive
    during both seed fetches; the backend returning the newest message id
    with each count would make them exact.
  - Derive the Friends page's firewall state from `$networkStats` instead of
    its own fetch and listener, and reuse `friendsList` in the layout instead
    of a second `getFriends`.
  - The hash-probe exemption trusts a claimed user hash. A request under a
    mutual friend's eD2K user hash is not counted toward the probe ban, so
    someone spoofing that hash can probe without being banned (the answers
    are the same either way). Matching the friend's live session address
    would close it.

## Known limits

Carried unchanged. Not beta blockers, but they belong in the format spec and
the release notes.

### Friends, from the 1.7.3 audit

- **Idle sessions with a pre-1.7.3 friend still drop.** The fix paces each
  side's keepalive off its own writes; an older build still resets its timer
  on inbound traffic, so on an idle link it rarely sends and our reader hits
  the 180-second record timeout. Fully fixed once both ends run 1.7.3.
- **Friends on 1.7.0 to 1.7.2 no longer see our friends-only files in
  Browse.** They honour the scope marking but do not send
  `EMBER_EXT_BROWSE_SCOPE_AWARE`, and a friend session carries nothing else
  that tells them from 1.6.x, which would republish the files. Kept that way
  on purpose, since a leak cannot be taken back and the gap closes as friends
  update.
- **Friends-only offers to 1.7.3 friends.** `OfferFileToFriend` refuses a
  friends-only file unless the session has shown it honours the marking
  (`EmberSessionHandle::honours_friends_only`). A 1.7.3 friend counts only
  once they have browsed us in that session, since 1.7.3 sends the scope
  frame only then.

### Owned-room recovery

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

### From the 1.7.2 audit

- **A claim the owner meets on its way back.** An owner back from a claimable
  silence follows its nominee's claim only in a copy signed before it
  returned, so a re-sign landing just before the owner's first successful
  fetch leaves it running a room its members have left.
- **Downgrading to 1.7.1 leaves one upload slot.** Auto is stored as
  `max_concurrent_uploads = 0`, which 1.7.1 repairs to 1 and saves. A separate
  `upload_slots_auto` flag, with the number kept in 1.7.1's range, would make
  the downgrade harmless.
