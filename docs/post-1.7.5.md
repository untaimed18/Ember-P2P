# After 1.7.5: planned for later releases

1.7.5 freezes the Channels formats (`docs/post-1.7.4.md`, "Channels: the
format freeze"; `docs/channels-format.md`, "What freezes at the end of the
beta"). What follows changes no frozen format, so none of it is tied to a
particular release: it can come in whichever release has room. If 1.7.6
needs no format change, it removes the BETA badge.

## 1. Private-room membership traffic under a throwaway DHT identity

**Why:** 1.7.5's v2 private membership records (item 9 of the 1.7.5 plan)
name neither the room nor the member in what a storer keeps. But every DHT
STORE and lookup that carries them is signed under the sender's long-term DHT
identity (`identity.ed25519_secret_key`, with `sender_id = BLAKE3(pubkey)`;
the engine signs every message with it), which is the key the member is known
by in its rooms. So storers still learn the member:

- **Presence.** A v2 presence record goes straight from the member to the
  storers nearest its key, every republish. A storer learns that this member
  is in some private room, though not which one.
- **Key lookups.** A member that is behind on a room's key looks up its own
  v2 key-epoch record. That record's header names the room, since the room
  key signs it, so the nodes answering learn that this member belongs to that
  room. This is the more revealing of the two.
- **Over time,** a node near many keys can tie one member's pseudonyms across
  rooms and rotations back to them.

It is a privacy limit, not a security one: nobody learns content, keys or
messages, and nobody can join a room or pass as a member. The room is hidden
from storers; who is in private rooms is not.

**To do:** send membership STOREs and lookups (presence, key epochs) under a
short-lived DHT identity of their own instead of the long-term one. Questions
to settle first:

- **Lifetime.** One identity per room, per publish, or per lookup. Shorter
  hides more and costs more handshakes.
- **The address.** Without a relay the storer still sees the sender's IP
  address, which for anyone watching the network is as identifying as the
  key. Route these messages through a relay (the existing relay and buddy
  paths are the place to start), or decide that hiding the key alone is
  worth it.
- **Routing standing.** A fresh identity is in nobody's routing table and has
  no history, so check that its STOREs are accepted and its lookups answered
  as readily as the long-term identity's.
- **Per-node limits.** Storers budget per publisher and per address
  (`publisher_index`, `MAX_RECORDS_PER_PUBLISHER_PER_KEY`, the per-IP caps).
  Make sure throwaway identities are neither refused as abuse nor a way to
  slip past those budgets.

**Not a format change.** Records, keys and storer rules stay as frozen in
1.7.5; only which identity signs the transport message changes, so it needs
no cut-over and old and new builds keep reading each other.

**Tests:** a membership STORE and lookup go out under an identity that is
not the long-term one, and a new one per the chosen lifetime; storers accept
and answer them; nothing else (friend sessions, file search, publishing a
library) changes identity; and the per-publisher and per-address budgets
still bind.

## Already scheduled for 1.8.0

Decided in 1.7.5 and written into the spec, so that a room has one cut-over to
test: stop sending chat frames 15 and 19 and set `EXT_FLAG_DISPLAY` on kinds
64 and 65; stop publishing v1 private membership records
(`PUBLISH_V1_MEMBERSHIP_RECORDS`), except the owner's own key copy; and
rotate every private room once as it does (`V1_CUT_OVER_ROTATES`, not built
yet; v1 cannot be switched off until it is). Whether to renew every retained
epoch's key records, not just the current one's, is also left to decide then.
Detail in `docs/post-1.7.4.md` items 2 and 9.

## Carried from the 1.7.5 plan

What `docs/post-1.7.4.md` leaves open, apart from the item above, which this
plan now owns: under "Later", the Away status, component tests, Discover spam
folding and the smaller Friends items; under "Channels: smaller follow-ups",
the relayed catch-up frontier, the moderation lock race and pre-1.7.3 bans;
and its "Known limits".
