# Channels: wire and DHT formats

The format spec for Channels, written before the formats freeze at the end of
the beta ([post-1.7.3 item 4](post-1.7.3.md#4-a-short-format-spec)). It covers
what goes over the gossip mesh, what is kept on the Ember DHT, and the one
friend-session sub-type the Channels audit added. Every number here is read
from the code; identifiers are in backticks so they can be grepped. Where the
code does not settle a question, this file says so rather than guessing.

Code: gossip bodies and envelopes in
[`network/ember/channel.rs`](../src-tauri/src/network/ember/channel.rs), their
handling in [`network/channel_gossip.rs`](../src-tauri/src/network/channel_gossip.rs),
DHT records in [`network/ember/dht/publish.rs`](../src-tauri/src/network/ember/dht/publish.rs)
and their lifetimes in [`network/ember/dht/store.rs`](../src-tauri/src/network/ember/dht/store.rs).

All integers are little-endian. Offsets are in bytes, half-open (`1..17` is
sixteen bytes starting at 1).

---

## Layers

A room frame is three layers deep:

1. A DHT frame on the overlay: `MSG_CHANNEL_MSG` (`0x11`) carries a gossip
   envelope, `MSG_CHANNEL_RELAY` (`0x12`) carries a relay envelope wrapping
   one. Both ride the Ember DHT transport and its own `EMBER_DHT_VERSION`,
   which this file does not cover.
2. The **gossip envelope** (`ChannelGossip`, version `CHANNEL_MSG_VERSION`): a
   cleartext header, then a body sealed under the room's content key.
3. The **plaintext** inside the seal. Its first byte says what it is: a frame
   number below 64 (`*_PLAIN_VERSION` and the transfer `*_SEALED_VERSION`
   constants), or an extension frame (64 and up).

## Gossip envelope

`ChannelGossip::encode` / `decode`. The fixed header is `GOSSIP_HEADER_LEN`
(50) bytes; the sealed body follows.

| Offset | Len | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | version | `CHANNEL_MSG_VERSION` = 1 |
| 1..17 | 16 | `channel_id` | `BLAKE3(channel_pubkey)[..16]` |
| 17..33 | 16 | `msg_id` | random per frame |
| 33 | 1 | `ttl` | hop budget; clamped on decode to `CHANNEL_MSG_TTL_DEFAULT` (8) |
| 34..42 | 8 | `timestamp` | `i64`, Unix seconds |
| 42..50 | 8 | `sender_counter` | `u64` |
| 50 | 1 | body version | `CHANNEL_MSG_VERSION` = 1, outside the seal |
| 51..75 | 24 | nonce | XChaCha20-Poly1305 |
| 75.. | n + 16 | ciphertext and tag | plaintext of `n` bytes |

`decode` refuses anything shorter than `GOSSIP_HEADER_LEN + 16`. The AAD is
`"ember-channel-gossip-v1\0" || channel_id || msg_id || sender_counter ||
timestamp` (`gossip_aad`). Neither version byte nor `ttl` is under the AEAD:
`ttl` has to change as the frame travels, which is why a relay can raise it
(see [post-1.7.3 item 8](post-1.7.3.md#8-an-authenticated-marker-on-catch-up-re-serves)).
`GOSSIP_ENVELOPE_OVERHEAD` (41) is the body version, nonce and tag.

## Relay envelope

`encode_channel_relay_envelope` / `decode_channel_relay_envelope`, carried in
`MSG_CHANNEL_RELAY` to an overlay contact that forwards it to a member it can
reach. The hop cannot open `inner`.

| Offset | Len | Field | Notes |
| --- | --- | --- | --- |
| 0 | 1 | version | `CHANNEL_RELAY_ENVELOPE_VERSION` = 1 |
| 1..17 | 16 | `channel_id` | must equal the inner frame's `channel_id` |
| 17..33 | 16 | `target_id` | the target's node id, `BLAKE3(member_pubkey)[..16]` |
| 33.. | rest | `inner` | an encoded gossip envelope; must be non-empty |

`CHANNEL_RELAY_ENVELOPE_HEADER` is 33. When `target_id` is our own node id,
`inner` is handled as gossip from the hop that relayed it.

## Envelope versions

Each envelope has exactly one version this build reads, tested by equality:
`gossip_envelope_version_supported` (outer header and sealed body alike),
`relay_envelope_version_supported`, and `epoch_envelope_version_supported`.

**Unknown gossip and relay versions.** A frame whose version is not read is
dropped, but no longer silently. `unread_envelope_room` takes byte 0 as the
version and bytes 1..17 as the room id; `note_unread_channel_envelope` then
records it against the room (`channel_newer_frames`, source `envelope` or
`relay`) and raises the room's "needs a newer Ember" banner. A v1 header
around a sealed body whose own version byte is unknown is noted the same way,
as `envelope`. Two limits, both deliberate:

- Only a hop on the room's roster counts, and only for a room this device is
  in. The frame is charged to the hop's per-frame budget first, like any
  other, because finding the room reads the database. The version byte is outside any seal, so anyone who has seen a room id
  in a gossip header could otherwise raise the banner there. A relay hop that
  is not a member goes unreported: that costs a banner, never a message.
- One row per room, source and version, and one database write per session
  for each (`NOTED_NEWER_ENVELOPES`). Dismissing the banner clears them;
  a member still sending them is noted again after Ember restarts.

**New rule for every future gossip and relay envelope version:** byte 0 stays
the version and bytes 1..17 stay the channel id. Builds from 1.7.4 on
read the room at that offset to show the notice; a version that moved it
would only go unreported. The same goes for the sealed body inside a v1
header: its byte 0 stays the body version.

**Not done: relaying an unknown version unopened.** Item 3 of the post-1.7.3
plan asked for it. It is not done because members only pass on frames that
open: `handle_inbound_channel_relay` forwards only for a room we are in
(`inbound_channel_relay_may_forward`), and refuses a frame that does not open
under one of the room's keys unless we are behind the room's key; gossip is
only fanned out after its body is read. That is
what stops a hop with a session using members to spread junk, and an unknown
version cannot be opened by definition. Listed as an open question below.

**Epoch-key envelope.** A member's sealed copy of one content-key epoch,
carried inside DHT record kind 5 (`seal_channel_key_epoch`):

| Offset | Len | Field |
| --- | --- | --- |
| 0 | 1 | `EPOCH_ENVELOPE_VERSION` = 1 |
| 1..25 | 24 | nonce |
| 25..73 | 48 | sealed 32-byte content key and tag |

`EPOCH_ENVELOPE_LEN` is 73. The AAD is `"ember-channel-key-epoch-v1\0" ||
channel_id || epoch`. Storers cannot open it, so `epoch_envelope_store_ok`
checks shape only: version 1 must be exactly 73 bytes; a later version is
kept on its leading byte with at least one byte after it, within the record
size every store enforces; version 0 is refused. A member that finds only a
version it cannot open for its own slot notes the room (`note_channel_newer_key`,
source `key`) instead of waiting for a key that will not come.

**A later epoch-envelope version needs a DHT key of its own.** A storer keeps
one record per publisher under a key, so a later version filed under
`epoch_key` replaces the v1 copy rather than sitting beside it, and members
still on v1 lose the key. A build that wants them to keep reading has to file
the new version under a different key and keep publishing v1 alongside.

## Plaintext frame numbers

The first byte of the opened plaintext. Numbers are never reused: a retired
number stays retired, so a peer still sending the old frame is refused rather
than misread. v1.6.x routes by this byte alone and drops a number it does
not know without scoring the hop (see the comment on `TYPING_PLAIN_VERSION`),
and fixed-length frames are decoded at exactly their length (every build so
far reads 17 only at 137 bytes), which is why each new frame got a new number
rather than a longer old one.

| No. | Constant | Status | What it is |
| --- | --- | --- | --- |
| 0 | — | unassigned | Nothing in the code says whether it was ever used |
| 1 | — | retired | Chat before it carried the author's signature |
| 2 | — | retired | Unsigned moderator action |
| 3 | — | retired | Unsigned sync request |
| 4, 5, 8 | — | retired | The withdrawn broadcast-attachment path; builds still running it are on the network |
| 6 | `HANDOFF_OFFER_PLAIN_VERSION` | in use | Handoff offer, signed by the channel key; 137 bytes |
| 7 | — | retired | Unsigned handoff-ready |
| 9 | `XFER_OFFER_PLAIN_VERSION` | in use | Transfer offer, readable by every member it passes |
| 10 | `XFER_REPLY_PLAIN_VERSION` | in use | Accept or deny |
| 11 | `XFER_BLOCK_REQUEST_PLAIN_VERSION` | in use | Receiver asks for blocks |
| 12 | — | retired | Block with its payload sealed only by the room key |
| 13 | `XFER_CANCEL_PLAIN_VERSION` | in use | Either side gives up |
| 14 | `XFER_DONE_PLAIN_VERSION` | in use | Transfer complete |
| 15 | `CHAT_PLAIN_VERSION` | in use | Signed chat line |
| 16 | `MOD_ACTION_PLAIN_VERSION` | in use | Signed ban or unban; 130 bytes |
| 17 | `HANDOFF_READY_PLAIN_VERSION` | in use | Signed handoff-ready, exactly 137 bytes; nominees still send it beside 29 |
| 18 | `SYNC_REQUEST_PLAIN_VERSION` | in use | Signed catch-up request; 105 bytes |
| 19 | `CHAT_EDIT_PLAIN_VERSION` | in use | Revision of a line, signed by its author |
| 20 | `REACTION_PLAIN_VERSION` | in use | Batch of reactions |
| 21 | `XFER_BLOCK_DATA_SEALED_VERSION` | in use | Block encrypted to the recipient alone |
| 22 | `PRESENCE_BEACON_PLAIN_VERSION` | in use | Batch of signed presence beacons |
| 23 | `TYPING_PLAIN_VERSION` | in use | Typing indicator; one hop (`CHANNEL_TYPING_TTL` = 1), never stored or re-served |
| 24 | — | retired | Stream frame with ports and address under the room key only; never shipped |
| 25 | `XFER_STREAM_SEALED_VERSION` | in use | Transfer QUIC port, encrypted to the other end |
| 26 | `XFER_OFFER_SEALED_VERSION` | in use | Offer encrypted to the recipient |
| 27 | `ROOM_FRIEND_REQUEST_PLAIN_VERSION` | in use | Friend request addressed by a pairwise tag |
| 28 | `XFER_SEEN_PLAIN_VERSION` | in use | "Your sealed offer arrived and I can read it" |
| 29 | `HANDOFF_READY_PROVEN_PLAIN_VERSION` | in use | Handoff-ready plus the successor key's signature; 201 bytes |
| 30–63 | — | unassigned | The code says they "stay unassigned" |
| 64–255 | `EXT_KIND_MIN` and up | extension | See below |

The transfer frames (9, 10, 11, 13, 14, 21, 25, 26, 28) share a header,
`version(1) || sender(32) || target(32) || xfer_id(16)` (`XFER_HEADER_LEN`, 81),
and end in a 16-byte pairwise authenticator (`XFER_MAC_LEN`) under
`derive_xfer_key`. 25, 26 and 28 are only sent by 1.7.0 and later, which is
what `xfer_frame_proves_sealed_reader` relies on.

Retired numbers have no constant left in the code; the table is built from
the comments beside the live constants and from the test that the retired
attachment numbers are not read as transfers
(`xfer_frames_do_not_decode_as_each_other`).

## Extension frames

Every plaintext whose first byte is `EXT_KIND_MIN` (64) or more is laid out as
`ChannelExtFrame` (`decode_channel_ext_frame`):

| Offset | Len | Field |
| --- | --- | --- |
| 0 | 1 | `kind`, 64–255 |
| 1 | 1 | `flags` |
| 2..34 | 32 | `sender`, the author's Ed25519 key |
| 34..98 | 64 | `signature` |
| 98.. | rest | `body`, defined per kind |

The signature covers `"ember-channel-ext-author-v1\0" || channel_id || msg_id
|| timestamp || kind || flags || sender || body` (`ext_sig_preimage`), so the
frame is bound to its room, id and time, and no member passing it on can
change its kind or flags. A frame whose signature does not check is dropped.

`EXT_FLAG_DISPLAY` (`0x01`) marks a frame a person would have seen. Other
flag bits are kept, not refused: they are signed and a later build may give
them a meaning.

No kind is defined yet. `UNDERSTOOD_EXT_KINDS` is empty, so
`ext_kind_understood` is false for every kind, and `encode_channel_ext_frame`
has no caller. A kind is added to that list by the build that first gives it
a meaning.

**How an unknown kind is handled** (`handle_inbound_channel_ext`). It is held
to what a chat line is held to: dropped from a banned member, dropped if it
opened under a retired key and its author is not on the roster, and dropped
if fresh but over its author's rate. Then:

- If it is displayable, of a kind this build does not understand and not our
  own, a row is written to `channel_newer_frames` (source `line`, keyed by
  `msg_id`, the kind kept). The newest `CHANNEL_NEWER_LINES_PER_ROOM` (200)
  are kept per room, and the banner counts them as lines needing a newer
  Ember. A row stops counting once an update teaches the build that kind.
- It is relayed, whatever its kind, if it is fresh by its signed time
  (`gossip_fresh_for_relay`, 10 minutes) and has hops left.
- It is not stored, so this build does not re-serve it in catch-up.

The post-1.7.3 plan states that builds from 1.7.2 on relay extension frames;
older builds drop them like any number they do not know.

## DHT channel records

All channel records are `RECORD_TYPE_CHANNEL` (`0x03`) signed records. The
fields that matter here sit in the fixed record header (`RECORD_HEADER_LEN`,
115 bytes):

| Offset | Len | Field | In a channel record |
| --- | --- | --- | --- |
| 0 | 1 | `record_type` | 3 |
| 1..17 | 16 | `keyword_hash` | the DHT key the record is filed under |
| 17..33 | 16 | `file_hash` | the channel id (kind 7: the identity's node id) |
| 33..65 | 32 | `ember_file_hash` | the channel pubkey (kind 7: the identity pubkey) |
| 65..73 | 8 | `file_size` | byte 65 kind, 66 flags, 67 language (index and moderation only) |
| 73..105 | 32 | `publisher_key` | the signer |
| 105..113 | 8 | `timestamp` | |
| 113..115 | 2 | `name_len` | then the name |

After the name comes the channel trailer: `CHANNEL_TRAILER_VERSION` (1),
`extra_len` (`u16`), then `extra`. The body must end exactly there. The
signature travels beside the body; see the
[DHT specification](ember-dht-specification.pdf) for the record as a whole.

**Storer rule.** A STORE of a channel record is kept only if
`channel_store_ok` passes (checked on the wire in `engine.rs`'s
`accept_record`, again when `store.rs` loads the persisted store at startup,
and by every `parse_channel_*` reader). For every kind,
`file_hash` must equal `BLAKE3(ember_file_hash)[..16]` with `ember_file_hash`
a valid Ed25519 key. A kind it does not know is refused, which is why adding a
kind needs no `EMBER_DHT_VERSION` bump and must not get one (the comment after
the `CHANNEL_KIND_*` constants). Per kind:

| Kind | Constant | Signed by | Storer also requires | TTL (`record_ttl`) |
| --- | --- | --- | --- | --- |
| 1 | `CHANNEL_KIND_INDEX` | channel key | publisher is the channel key; key is `index_key_for_channel` (one of 16 shards) | `CHANNEL_INDEX_TTL`, 7 days |
| 2 | `CHANNEL_KIND_PRESENCE` | member | publisher is a valid Ed25519 key; `presence_extra_store_ok` | `CHANNEL_PRESENCE_TTL`, 45 min; departed, the same 45 min |
| 3 | `CHANNEL_KIND_MODERATION` | channel key | publisher is the channel key; key is `moderation_key` | `CHANNEL_GOVERNANCE_TTL`, 30 days |
| 4 | `CHANNEL_KIND_HANDOFF` | old channel key | publisher is the channel key; key is `handoff_key`; `decode_handoff_extra` | `CHANNEL_HANDOFF_TTL`, 30 days |
| 5 | `CHANNEL_KIND_EPOCH` | channel key | publisher is the channel key; key is `epoch_key(channel_id, member, epoch)` from the extra; `epoch_envelope_store_ok` | `CHANNEL_GOVERNANCE_TTL`, 30 days |
| 6 | `CHANNEL_KIND_CLAIM` | nominee's user key | publisher is a valid Ed25519 key; key is `claim_key`; `decode_claim_extra` | `CHANNEL_HANDOFF_TTL`, 30 days |
| 7 | `CHANNEL_KIND_OWNED_ROOMS` | the identity | publisher is `ember_file_hash`; key is `owned_rooms_key(publisher)`; `decode_owned_rooms_extra` | `CHANNEL_GOVERNANCE_TTL`, 30 days |

`record_ttl` falls back to `KEYWORD_RECORD_TTL` (24 hours) for any other kind,
but `channel_store_ok` refuses those first. The `extra` each kind carries:

- **1, index.** Empty. The room name is the record name; flag
  `CHANNEL_FLAG_PRIVATE` (`0x01`).
- **2, presence.** Public room: the member's 32-byte Noise key, nickname in
  the name. Private room: `PRESENCE_EXTRA_ENC_LEN` (138) bytes led by
  `PRESENCE_EXTRA_ENC_VERSION` (1), nickname and Noise key sealed under the
  content key, name empty. The key folds in the join secret and a 15-minute
  epoch, so a storer cannot check it. `CHANNEL_FLAG_DEPARTED` (`0x02`) marks a
  leave; its TTL must not be shorter than a live record's, or a harvested
  live copy could be re-stored after the tombstone lapsed.
- **3, moderation.** The owner's whole governance snapshot (welcome, bans,
  moderators, `ModerationTail`). The storer does not check its shape; readers
  do. Worst case 1164 of 1165 bytes (see
  [post-1.7.3 item 1](post-1.7.3.md#1-decide-the-future-of-the-room-settings-snapshot)).
- **4, handoff.** `version(8) || successor_pubkey(32) || successor_id(16) ||
  flags(1)`, 57 bytes; `successor_id` must derive from `successor_pubkey`.
  `HANDOFF_FLAG_KEEP_JOIN_SECRET` (`0x01`) in the flags.
- **5, epoch.** `member(32) || epoch(8) || envelope`; the epoch must not be
  negative. Always flagged private.
- **6, claim.** `successor_pubkey(32) || witnessed_moderation_ts(8)`, exactly
  40 bytes, the key a valid point. `CHANNEL_FLAG_PRIVATE` here means keep the
  join secret. Whether a claim is legitimate only a member holding the owner's
  nomination can decide; the storer checks shape and slot.
- **7, owned rooms.** Below.

## The owned-rooms list (kind 7)

The salts of the rooms an identity owns, so one backup of the identity brings
back every room it owns. A room's seed is
`derive_owned_room_seed(identity_seed, salt)`; salts are 16 random bytes
(`OwnedRoomSalt`). The list is filed under `owned_rooms_key` =
`BLAKE3("ember:identity:owned-rooms:v1" || identity_pubkey)[..16]`, with an
empty name and kind flags 0.

`extra` is `version(1) || count(1) || salt(16) × count`:

- Version 1 (`OWNED_ROOMS_VERSION`): `count` at most `OWNED_ROOMS_MAX` (48),
  and the extra exactly `2 + 16 × count` bytes.
- **Prefix rule:** a later version keeps version 1's layout as its prefix and
  appends after it. A reader that knows only version 1 accepts any later
  version at least `2 + 16 × count` bytes long, reads the salts, and leaves the
  rest alone; storers keep it. No 48-salt cap is applied to a later version,
  only the record size.
- Version 0 is refused. An empty list is valid and is published, so a deleted
  last room stops being listed.

Publishing (`maybe_publish_owned_rooms_list`) waits until the network's list
has been read this launch, so an old database cannot overwrite a newer list.
It repeats every `MODERATION_REPUBLISH_SECS` (6 hours), and once more within
`OWNED_ROOMS_CONFIRM_SECS` (30 minutes) after the list changes. Recovery
(`commands/channel_recovery.rs`) merges the salts of every copy the identity
signed that comes back (`merged_lists`), and takes a lookup that finds
nothing as "no list" only once `MIN_RESPONDERS_FOR_ABSENCE` (4) nodes have
answered. Builds older than kind 7 do not store it. The known limits (one
identity on two devices, the list revealing a room count) are under
[Owned-room recovery](post-1.7.3.md#owned-room-recovery-known-limits).

## Friend sessions: `EMBER_EXT_BROWSE_SCOPE_AWARE`

Not a room format, but added by the same audit and frozen with it.
`EMBER_EXT_BROWSE_SCOPE_AWARE` (`0x0E`, in `network/ed2k/messages.rs`) is an
`OP_EMBER_EXT` sub-type with an empty body meaning "I understand
`EMBER_EXT_BROWSE_SCOPE`" (`0x0B`, the frame naming which entries of a browse
answer are friends-only). The requester sends it ahead of each
`OP_EMBER_BROWSE_REQ`, and the answerer remembers it for the session. The
`EBR1` request marker predates the scope frame, and a requester that drops the
scope frame as unknown would file friends-only entries as public and
republish them, so **Browse lists friends-only files only to a session that
has sent it** (`supports_scope` on `EmberBrowseRequest`).

**File offers, from 1.7.4.** A friend session that has sent
`EMBER_EXT_BROWSE_SCOPE_AWARE` or `EMBER_EXT_MAILBOX_AWARE` (`0x10`) is
treated as honouring friends-only markings: both sub-types are newer than the
file offer's friends-only flag. 1.7.3 sends only the first, and only ahead of
a browse; 1.7.4 sends the mailbox frame whenever a secure session comes up,
so a 1.7.4 friend qualifies at once. The reader marks the session
(`mark_honours_friends_only`) on either frame, whatever the mailbox frame's
yes-or-no byte, on inbound and outbound sessions alike (`upload.rs`,
`friend_connect.rs`). Every live secure session of a friend is the same
running build, so the mark is set on all of them at once, and a session opened
while one is marked starts marked; otherwise it starts false. In the
`OfferFileToFriend` arm of `network/command.rs`, an offer whose file is
friends-only (or might be, while `known.met` is not yet absorbed) is refused
with `peers_offer_needs_newer_ember` unless `honours_friends_only` is set on
the session; such a file still needs a mutual friend in any case.

Browse and offers do not use the same test: Browse still requires
`EMBER_EXT_BROWSE_SCOPE_AWARE` itself, while an offer also accepts the
mailbox frame. It makes no difference in practice, since every build that
browses sends the scope frame ahead of the request.

---

## What freezes at the end of the beta

**Fixed from then on:**

- The plaintext frame numbers above, in use and retired. Nothing is reused;
  30–63 stay unassigned; new kinds of frame are extension frames.
- The extension-frame layout, its signature preimage and `EXT_FLAG_DISPLAY`,
  and the rule that unknown kinds are relayed under chat's rules and counted
  when displayable.
- The gossip header and relay envelope layouts at their current versions, and
  the rule that every later version keeps byte 0 as the version and bytes
  1..17 as the channel id.
- Record kinds 1 to 7 with their storer rules and TTLs, the channel trailer
  version, and the rule that a new kind needs no DHT version bump.
- The owned-rooms prefix rule, and the rule that a later epoch-envelope
  version is filed under a key of its own.
- The meaning of `EMBER_EXT_BROWSE_SCOPE_AWARE`, and that it or
  `EMBER_EXT_MAILBOX_AWARE` marks a session as honouring friends-only files.

**Open, to decide before the freeze** (detail in
[post-1.7.3.md](post-1.7.3.md#channels-before-the-beta-badge-comes-off)):

- **Item 1, room settings.** Freeze the moderation snapshot and put new
  settings in extension frames, or add a "room settings" record as kind 8
  with its own storer rule and a TTL equal to `CHANNEL_GOVERNANCE_TTL`.
- **Item 2, chat v2.** A chat and edit format with tagged optional fields, as
  an extension kind sent beside today's line; which release stops sending
  15 and 19 is to be written here.
- **Item 7, key commitment.** The owner's epoch announcement commits to each
  epoch's key so an invite's key can be checked. A candidate field for kind 8.
- **Item 8, re-serve marker.** Mark catch-up re-serves inside the seal, or
  admit private-room members only through key-proven beacons.
- **Item 9, membership off the DHT.** Derive epoch keys from the join secret
  and blind private presence records. This changes the `epoch_key` and
  `presence_key` derivations and needs a version cut-over.
- **Unknown envelope versions, unopened.** Whether a member should relay a
  gossip or relay envelope of a version it cannot read. Today it does not, for
  the reason given under [Envelope versions](#envelope-versions); doing so
  would need some other way to stop hops spreading junk through members.
