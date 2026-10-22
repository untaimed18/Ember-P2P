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

## 2. Private messages between room members

**Why:** two people in a room have no way to talk privately except becoming
friends first, which is heavy for a quick word and grants browse and file
sharing along with it. Rooms already carry a message to one member that the
members relaying it cannot attribute (the room friend request, frame 27), and
frames encrypted to one recipient (21, 25, 26). A private message is the same
idea with a body.

**Decided:**

- **Carried by the room, encrypted to the recipient.** A new extension frame,
  kind 66, relayed through the room like chat. Not a direct connection: that
  would give each side the other's address and a new kind of session for
  people who are not friends.
- **First contact is a request.** The first message from someone arrives as a
  request to accept or ignore, and nothing about the conversation shows as
  unread until it is accepted. A setting offers "Ask first" (default), "Allow
  from anyone" and "Off".

**The frame (kind 66).** An ordinary extension frame, signed by the sender,
without `EXT_FLAG_DISPLAY`, so 1.7.2 and later relay it under chat's rules
(the sender's ban, retired-key roster check and chat rate) and no build shows
a "needs a newer Ember" line for it. Body: `version(1) || tag(16) ||
nonce(24) || ciphertext`.

- **Tag.** Pairwise and bound to the envelope's `msg_id`, as frame 27's is, so
  relays cannot group messages by recipient. A receiver derives one pairwise
  base per sender (cached) and one HMAC per frame to recognise its own.
- **Key.** `derive_pairwise_capability` with a purpose of its own
  (`ch-dm-v1 || channel_id`), never `derive_chat_key`: friend chat's key
  depends on the two identities only, so reusing it would make a room message
  a valid friend-chat ciphertext and the other way round. XChaCha20-Poly1305,
  with `channel_id || msg_id || timestamp || sender || tag` as associated
  data, so a body cannot be lifted into another envelope.
- **Plaintext.** `type(1) || fields`, one kind for everything so relays cannot
  tell a message from a receipt: message (`message_id(16) || text`), receipt
  (`message_id(16)`), accept, decline. Padded to fixed buckets (256, 1024,
  4096) so length says little. Text capped at `CHAT_TEXT_MAX_BYTES`.

**Delivery.** Extension frames are not stored for catch-up, so a message
reaches only a recipient online within the 10-minute relay window. The
recipient answers with a receipt; the sender resends under a fresh envelope
for a bounded time and then marks it "Not delivered — they may be offline or
on an older Ember". Offline delivery through the chat mailbox
(`derive_chat_mailbox_box` already works for any two identities) is a later
step, not part of the first version.

**Conversations.** One per person, keyed by their member key, carried through
a room both are in (the one it started in while both remain, else any shared
room, as `send_room_friend_request` picks). No shared room: sending is
unavailable and the conversation offers Add friend. Someone already a friend
gets friend chat instead.

**Safety.**

- **The sender is visible to relays,** since bans and rates need it: members
  passing a frame learn that someone sent a private message, not to whom or
  what. The help text says so.
- **Moderators cannot read them.** A room ban still stops them (relays drop
  a banned sender), and each message costs the sender a chat-rate charge.
- **The ignore list moves to the backend.** Today `ignoredMembers` lives in
  the webview's `localStorage` only; it moves into settings (migrated once
  from `localStorage`) so an ignored member's message is dropped before it
  is stored or notified. Ignoring from a request does the same.
- **Requests are capped** per room per hour, as room friend requests are
  (`ROOM_FRIEND_REQUESTS_PER_ROOM_HOUR`), and a declined sender cannot ask
  again for a while.
- **No forward secrecy:** static keys, as sealed offers and friend chat use.

**Storage.** New tables: threads (`member_pubkey`, state pending / accepted /
declined, room last used) and messages, the bodies encrypted with the chat
key like `chat_messages`. Deleting a conversation deletes both. Leaving or
being banned from a room does not delete history.

**UI.** "Message privately" in a member's menu; a chat tab in the dock,
labelled with the room; requests listed on the Channels page; notifications
under the message-notification settings; the new setting under Channels.
Strings in all nine languages.

**Spec.** Kind 66 goes into `channels-format.md` under Extension frames, and
into `UNDERSTOOD_EXT_KINDS`, in the release that builds it. Adding a kind is
what the freeze allows, so no frozen format changes and no cut-over is needed.

**Tests:** only the recipient recognises its tag, and tags differ for two
messages to the same person; a body does not open under another envelope,
room or sender; a friend-chat ciphertext does not open as a room message and
the other way round; 1.7.4's unknown-kind path relays the frame without
storing or counting it; a banned or ignored sender's message is dropped; the
first message is held as a request and not notified as unread; receipts stop
resends; a message to someone with no shared room is refused.

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
