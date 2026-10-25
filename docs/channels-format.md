# Channels: wire and DHT formats

The format spec for Channels, as frozen with 1.7.5
([post-1.7.4 item 4](post-1.7.4.md#4-a-short-format-spec); what is frozen is
listed at the end). It covers what goes over the gossip mesh, what is kept on
the Ember DHT, and the friend-session sub-types frozen with them. Every number here is read
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
(see [post-1.7.4 item 8](post-1.7.4.md#8-an-authenticated-marker-on-catch-up-re-serves)
and kind 8's [admission rule](#admission-item-8), which is how 1.7.5 answers it).
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

**An unknown version is not relayed, by decision.** Item 3 of the post-1.7.3
plan asked whether it should be; 1.7.5 settled that it is not. Members only
pass on frames that open: `handle_inbound_channel_relay` forwards only for a
room we are in (`inbound_channel_relay_may_forward`), and refuses a frame that
does not open under one of the room's keys unless we are behind the room's
key; gossip is only fanned out after its body is read. That is what stops a
hop with a session using members to spread junk, and an unknown version cannot
be opened by definition, whatever a signed field announced. **Rule for every
later envelope version:** it is sent beside a v1 envelope carrying the same
content while builds that read only v1 are in the room, as chat v2 is sent
beside the legacy line (below), and only then on its own.

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
| 15 | `CHAT_PLAIN_VERSION` | in use | Signed chat line; sent beside kind 64 until 1.8.0 ([Chat v2](#chat-v2-kinds-64-and-65)) |
| 16 | `MOD_ACTION_PLAIN_VERSION` | in use | Signed ban or unban; 130 bytes |
| 17 | `HANDOFF_READY_PLAIN_VERSION` | in use | Signed handoff-ready, exactly 137 bytes; nominees still send it beside 29 |
| 18 | `SYNC_REQUEST_PLAIN_VERSION` | in use | Signed catch-up request; 105 bytes |
| 19 | `CHAT_EDIT_PLAIN_VERSION` | in use | Revision of a line, signed by its author; sent beside kind 65 until 1.8.0 |
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
| 66 | `EXT_KIND_PRIVATE_MESSAGE` | in use (from 1.7.5) | [Private message](#private-messages-kind-66), sealed to one member |

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

**Kinds defined.** From 1.7.5, `UNDERSTOOD_EXT_KINDS` holds 64
(`EXT_KIND_CHAT_LINE`) and 65 (`EXT_KIND_CHAT_EDIT`), the second version of
the chat line and of its revision, under [Chat v2](#chat-v2-kinds-64-and-65),
and 66 (`EXT_KIND_PRIVATE_MESSAGE`), under
[Private messages](#private-messages-kind-66). 67–255 are unassigned. A kind
is added to that list by the build that first
gives it a meaning; `ext_kind_understood` is true for those kinds only, and a
`channel_newer_frames` row of such a kind stops counting once a build knows it.

**How an unknown kind is handled** (`handle_inbound_channel_ext`; kinds 64
and 65 are handled ahead of it, as chat). It is held
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

## Chat v2 (kinds 64 and 65)

From 1.7.5. It fills in
[post-1.7.4 item 2](post-1.7.4.md#2-a-second-version-of-the-chat-message).
A chat line (15) and its revision (19) have fixed layouts, so replies were
fitted inside the signed text as tag characters (`with_reply_trailer`) and
any further field would have needed another frame number. The second version
of each is an extension frame whose body is a tagged field list, so a later
field needs only a new tag. Code: `decode_chat_v2_body`,
`encode_chat_v2_body`, `outgoing_chat_line`, `outgoing_chat_edit`,
`chat_legacy_text`, `chat_v2_outgoing_text` and `ChatTwinCredits` in
`channel.rs`; `handle_inbound_channel_chat` and `handle_inbound_channel_edit`
in `channel_gossip.rs`; `ingest_channel_chat_v2_line`,
`adopt_channel_line_signature` and `apply_channel_message_edit_with` in
`storage/database.rs`.

### Frame

An ordinary [extension frame](#extension-frames): `kind || flags || sender
|| signature || body`, signed over `ext_sig_preimage`, so the author's
signature covers the room, the frame's own envelope `msg_id` and timestamp,
the kind, the flags and every byte of the body, optional and unknown fields
included. A frame whose signature does not check is dropped before its body
is read.

- **Kind 64, line.** The envelope timestamp is the line's send time.
- **Kind 65, revision.** The envelope timestamp is the revision's time
  (`edited_at`); the original send time is in the body.

### Body

`version(1) || (tag(1) || len(2) || value(len))*`, version
`CHAT_V2_BODY_VERSION` = 1: the framing of kind 8's `extra`, shared as
`tagged_fields`. Tags appear in ascending order, each at most once, and must
fill the body exactly; version 0, a length running past the end, bytes left
over, or tags out of order or repeated make the body malformed, and the frame
is dropped and not relayed. A later version keeps this framing, and a reader
that knows only 1 reads its fields the same way. A tag this build does not
know is skipped. A known tag keeps its layout in every version and in both
kinds; a later build that needs another layout takes a new tag.

| Tag | Field | Value | Kind 64 | Kind 65 |
| --- | --- | --- | --- | --- |
| 1 | line id | 16 bytes: for 64, the line's own id, which is its legacy twin's `msg_id`; for 65, the line revised | required | required |
| 2 | text | UTF-8, not empty, without a reply trailer; emoji joiners kept | required | required |
| 3 | reply parent | 16 bytes, the id of the line this one answers; absent for a line that is not a reply | optional | optional |
| 4 | original time | `i64`, the revised line's send time | ignored | required |

Tags 5–255 are unassigned. Nothing else that rides in a legacy line's text
moves into a field: the reply trailer is the only hidden field the legacy
text carries (mentions and links are plain text and stay in tag 2).

**Readers** (`decode_chat_v2_body`) also refuse a tag 2 that itself ends in a
reply trailer, since stored with the trailer that tag 3 maps to it would read
as a reply, and a body whose two forms would not read alike
(`chat_v2_text_reads_alike`): the stored text and its legacy text
(`chat_legacy_text`) must each name tag 3 as their parent, or none, and each
leave a body that is not empty. That refuses a trailer hidden behind an emoji
joiner (which builds before 1.7.5 would read as a reply and this build would
not) and a tag 2 of joiners alone (whose legacy text is a bare trailer, read
there as no reply). Tag characters are not refused as such; subdivision flags
are spelled with them. The stored text of a v2 line is tag 2 followed by the
reply trailer for tag 3 (`ChatV2Body::stored_text`), so the `reply_to` column,
display and quotes are read the same way for both forms, and pairing, which
swaps only the text, leaves `reply_to` true.

**A line's id has to be its author's.** A kind 64 frame is dropped unless its
tag 1 is bound to the frame's signer and signed time
(`chat_msg_id_binds`, the id `new_chat_msg_id` mints; every build that sends
kind 64 mints those). So a v2 line can name only its own author's line, sent
at its own time, whether or not that line is held here. A kind 65 frame is
held to what an edit frame is: the editor must be the line's author, or for a
line not held, the id must bind the editor at tag 4's time.

**Line id derivation** (`chat_msg_id_from_nonce` in `channel.rs`). A bound
line id is 16 bytes:

```
nonce(6) || BLAKE3("ember-channel-chat-msg-id-v1\0" || channel_id || author || timestamp || nonce)[..10]
```

- `nonce` is 6 random bytes, and is also the id's first 6 bytes.
- The domain string is the 28 ASCII bytes `ember-channel-chat-msg-id-v1`
  followed by one zero byte, 29 bytes in all.
- `channel_id` is the room's 16-byte id, the one in the gossip header.
- `author` is the line author's 32-byte Ed25519 key: the extension frame's
  `sender` for kind 64 and 65, the signer of a line 15 or edit 19.
- `timestamp` is the line's send time as an `i64`, 8 bytes little-endian:
  the time the line is signed and sealed with, which is kind 64's envelope
  timestamp and kind 65's tag 4.
- The hash is plain, unkeyed BLAKE3 over the concatenation, and the id takes
  the first 10 bytes of its 32-byte output.

An id binds an author and a time when recomputing it from its own first 6
bytes and that author and time gives the whole id. Ids minted by builds
before the binding are 16 random bytes and bind nobody but by chance
(2^-80). For kind 65 the check is against the editor and tag 4. When the
line is held, the editor must also be the held row's author. When it is
not held, a revision whose id does not bind the editor is refused rather
than stored under the editor's name. One that binds creates the line from
the revision, as received, with its edit window judged on the author's
clock (`apply_channel_message_edit_with`). A held row from another author
whose id does not bind that author gives way to a revision whose id binds
the editor.

### Pairing with the legacy frames

During the transition every line goes out twice: as chat line 15 under the
line's id, and as kind 64 under a **`msg_id` of its own** (random), naming the
line in tag 1. Every build drops a frame whose `msg_id` it has seen; had the
two shared one, a 1.7.4 build that met the v2 frame first would drop the
legacy line as a duplicate and never show it. Revisions go out as 19 and 65,
each under its own random envelope id, as 19 already did.

Receivers on 1.7.5 keep one row per line, under the line's id; whichever form
arrives first makes it:

- **v2 after its legacy line** (same author, same time, not yet revised): its
  text replaces the stored text, which brings back the emoji joiners the
  legacy text had stripped, and the frame is kept beside the row. Nothing
  else about the row moves. The bubble is updated with
  `ember:channel-message-edited` at `edited_at` 0.
- **Legacy after its v2 line:** a no-op, except that its signature is kept so
  the line can be re-served to builds that read only 15.
- **The two must agree.** Either is taken beside the other only if the legacy
  text is the v2 text with its trailer and with the emoji joiners (ZWNJ, ZWJ,
  VS15, VS16) taken out (`chat_legacy_text`), and only if the row is the
  author's at the same time: a legacy line may travel under any id, so its
  author can put one under the id of a line sent at another time. Otherwise
  the first to arrive stands, the second changes nothing, and it is not
  relayed (`ChannelV2LineOutcome::Unpaired`, `ChannelLegacyTwinOutcome::Unpaired`).
  A second v2 frame of a row already holding a v2 text is held to that text
  the same way. So no row holds two forms that say different things, a
  stored row's legacy text is always derivable from it, and a 1.7.5 member
  passes on only the form that arrived first. An author can still send each
  build different words, the legacy line to one part of the room and the v2
  frame to another; the members who see both keep the first.
- **A v2 line sanitising changes is dropped.** The receive-side rules
  (`sanitize_message_text`) must leave the v2 text as signed, as for a
  revision; otherwise its row could hold neither form's signature and never
  take the legacy twin's, so the legacy twin is left to make the row.
- **Under another author's line:** a v2 frame naming a line whose row has a
  different author is dropped (`ChannelV2LineOutcome::NotAuthor`), and not
  relayed. An unbound row squatting on the id gives way, as for chat.
- **Revisions** pair the same way against the revision held at the same
  `edited_at` (`ChannelEditOutcome::Paired`): a v2 revision's text replaces
  the legacy revision's when they agree, and an edit frame arriving after its
  v2 twin keeps only its signature and is relayed. One that does not pair is
  `NotNewer` and not relayed. Only a row already revised pairs: an edit frame
  at `edited_at` 0 names no revision. A different `edited_at` is an ordinary
  newer-wins revision.

**Relay.** A form that made the row or paired with it is relayed, if fresh
by its signed time and with hops left. A form that finds the line held and
changes nothing is relayed too, as a line always was, except a variant (a
frame under an envelope id seen with another body). A form that does not pair,
or names another author's line, is not relayed. A legacy variant of a line
held is settled before the rate charge, as before; a v2 variant is not, since
its envelope id is its own and in the clear, and the genuine frame may arrive
behind one a member sent first under that id. It goes to the database, which
pairs it or finds it held.

**Rate.** Both forms of a line or revision count once against the author's
`CHANNEL_GOSSIP_PER_AUTHOR_PER_SEC`, whichever arrives first
(`chat_author_allow`): the first form pays and leaves a credit, and only the
other form spends it. The credit is keyed by room, author, line id, revision
time (0 for the line) and the time both forms sign: the line's send time,
which is the legacy envelope's and the v2 frame's, or the revision's
`edited_at`. A line leaves or spends one only when its id binds its author at
that time (`chat_msg_id_binds`), as every id minted beside a v2 frame does; a
legacy line under any other id is charged on its own. A credit lasts
`CHAT_TWIN_CREDIT_TTL` (5 seconds): a sender hands both frames to the network
together and every hop passes them on in that order, so honest twins arrive
back to back, and one form sent alone cannot bank a free frame for a burst
later. At most `CHAT_TWIN_CREDITS_CAP` (4096) are held. A third frame for the
same line is charged, so an author cannot turn one line into a stream of v2
frames under fresh envelope ids. The sender counts the pair as one message for
its own per-room limit (`LOCAL_SEND_PER_MINUTE`) and for slow mode, and hands
both frames to the network task as one command (`FanoutChannelChat`), legacy
first.

**Budgets count frames.** The relay allowance (`CHANNEL_GOSSIP_OUT_PER_SEC`,
16 a second), the per-hop inbound allowance derived from it, and a catch-up
reply's frame budget (`CHANNEL_HISTORY_SYNC_FRAME_MAX`, 40) count frames, not
lines. While both forms go out, a line or revision is two frames, so each
carries half as many lines as it did: 8 relayed a second, and as few as 20
lines in a catch-up reply. A twin whose credit was spent is not exempted from
them: the relay allowance is this node's own bound on what it forwards, and
it is spent per frame sent.

**Sending.** The legacy frame carries the text as before, joiners stripped
(`sanitize_outgoing_message_text`). The v2 frame carries what was typed under
the receive-side rules (`sanitize_message_text`, joiners kept), unless that
would not pair with the legacy text or would take the stored text past 4096
bytes (`CHAT_TEXT_MAX_BYTES`), in which case it carries the legacy body
(`chat_v2_outgoing_text`). The local row holds the v2 text and both frames'
signatures.

**Display flag.** While the legacy frames go out, kinds 64 and 65 are sent
**without** `EXT_FLAG_DISPLAY` (`CHAT_V2_FLAGS` = 0). Builds 1.7.2–1.7.4 count
a displayable frame of a kind they cannot read as a line needing a newer
Ember, and with the flag set every line would raise that banner there even
though its legacy twin shows it. Builds before 1.7.2 drop the frame as an
unknown number.

**Builds before 1.7.5** charge both frames against the author's rate (four a
second), so a member there sees a 1.7.5 author's lines capped at two a second.
The legacy frame is sent first, so it is the one such a build admits when an
author is at the edge.

### Storage and catch-up

Each `channel_messages` row keeps one v2 frame, the one of the text it holds
now: the line's (64) until revised, then the revision's (65). Columns
`v2_kind`, `v2_flags`, `v2_frame_id`, `v2_signed_at`, `v2_sig`, and
`v2_body` sealed under the chat key and bound to the row, the kind and the
frame id (`seal_channel_v2_body`). They are added when the database opens
(`shape_channel_messages_v2_locked`), not by a numbered migration, so the
schema stays at 62 and 1.7.0 still opens the database. A revision 1.7.0
applies leaves the columns naming the revision before, so a frame is read only
when `v2_signed_at` is the row's time (64) or its `edited_at` (65)
(`channel_v2_form_current`).

Catch-up (`reply_channel_history_sync`) re-serves every form held: the legacy
frame, over the row's legacy text, then the v2 frame under its own envelope id
and signed time, both of which its signature binds. A row holding only one
form is served in that form alone; one holding neither is not served. Each
frame counts against the reply's frame budget.

**After a downgrade** to 1.7.0–1.7.4, those builds serve a row's legacy frame
over the stored text itself. For a paired line whose v2 text has emoji
joiners, that is not the text the signature covers, so every receiver rejects
the re-serve; and a row only a v2 revision changed holds no edit signature
for them to serve the revision with. The lines stay readable on the device
that downgraded; only re-serving them is lost.

### The cut-over in 1.8.0

1.8.0 stops sending 15 and 19 and sets `EXT_FLAG_DISPLAY` on 64 and 65, so a
build that cannot read them says so. It is one constant,
`SEND_LEGACY_CHAT_FRAMES`, which also drives `CHAT_V2_FLAGS`. With no legacy
frame to shadow, a kind 64 frame then takes the line's id as its own envelope
id, so the line's delivery is settled by the frame that carries it; receivers
already accept that. 1.8.0 still reads 15 and 19 from members on older
builds, and pairs them as above. 1.8.0 is also the release that stops
publishing v1 membership records
([item 9](#the-transition-and-the-cut-over-in-180)), so a room has one
cut-over to test.

## Private messages (kind 66)

A message from one member to another, carried by the room like chat and
sealed to the recipient (`network/ember/room_dm.rs`). From 1.7.5, as an
extension kind, so nothing else in the format changes for it. `flags`
is always 0, and a frame of this kind with any flag set is dropped unread: a
displayable one would have older builds tell the room a private message
passed. A build that cannot read the kind relays it under chat's rules (ban,
retired-key roster check, author rate) and shows nothing. It is not stored
for catch-up.

Body: `version(1) = 1 || tag(16) || nonce(24) || ciphertext`.

- **Pairwise secret.** `derive_pairwise_capability(seed, peer, "ch-dm-v1" ||
  channel_id, 0)`, never `derive_chat_key`, whose key depends on the two
  identities alone and would make a room message open as friend chat.
  `tag_key = BLAKE3_derive_key("ember room private message tag v1", secret)`
  and `seal_key = BLAKE3_derive_key("ember room private message key v1",
  secret)` (`PairwiseBase`).
- **Tag.** `BLAKE3_keyed(tag_key, msg_id)[..16]`: only the two members can
  compute it, and it differs on every envelope, so relays cannot group frames
  by recipient. A receiver keeps one `PairwiseBase` per sender and room, and
  derives one only for a sender on the room's roster.
- **Ciphertext.** XChaCha20-Poly1305 under `seal_key` with a random 24-byte
  nonce, associated data `"ember-room-dm-v1\0" || channel_id || msg_id ||
  timestamp (i64 LE) || sender || tag`, so a body cannot be moved into
  another envelope, room or sender.
- **Plaintext.** `type(1) || len(2, LE) || fields`, zero-padded to exactly
  256, 960 or `DM_TOP_BUCKET` bytes. Any other length, a non-zero pad byte, or
  a body shorter than the smallest bucket's (313 bytes) is refused. 960 keeps
  a middle-sized frame unfragmented, relay envelope and all.
  `DM_TOP_BUCKET` is what one datagram leaves once the overlay relay envelope
  (33), the gossip envelope, the extension header and the body's own 57 bytes
  are counted (3670); the text cap, `DM_TEXT_MAX_BYTES`, is that less `type ||
  len || message_id` (3651). Types and their fields, exactly: 1 message
  (`message_id(16) || UTF-8 text`), 2 receipt (`message_id(16)`), 3 accept
  (none), 4 decline (none). One kind of frame for all four, so relays cannot
  tell a message from a receipt.

**Receiving** (`network::room_dm::on_private_message`). Only after the frame
met the relay rules, only under the room's current key, only within
`DM_MAX_AGE_SECS` of its envelope time (the 10-minute relay window, inside
which a frame is also charged to its author; at most 5 minutes ahead), only
from a sender on the roster, and never our own. A sender the user ignores
(`settings.ignored_members`, everywhere or in that room) is dropped before
anything is kept or answered. A message is kept only from a member the room's
roster has seen and not banned; then `room_dm_policy` decides: `off` declines
everything, a resend of something already held included; `anyone` opens a
conversation; `ask` (the default) holds a new one as a request, at most
`DM_REQUESTS_PER_ROOM_HOUR` (5) new requests per room an hour. A request
holds at most `DM_REQUEST_MESSAGES_MAX` (20) messages until answered, at most
`DM_STORED_PER_SENDER_HOUR` (120) are kept from one member an hour, and a
conversation keeps its newest `DM_THREAD_MESSAGES_KEPT` (2000). A sender the
user declined, or whose request was deleted, is declined for
`DM_DECLINE_MEMORY_SECS` (7 days). Ignoring a sender whose request waits
removes it and what it held without any reply, and keeps no refusal: nothing
goes to them, not even a reply already queued, so their messages go
undelivered as if we were offline.

A kept message or a resend of one is answered with a receipt, a declined one
with a decline; anything over a cap is dropped unanswered. Replies wait a
random 10 to 90 seconds (`queue_reply`): every member sees who sent each
frame, and a receipt right behind a message would say whom it was for. A
member draws at most 30 replies and one decline from us in 10 minutes, so
nobody can spend our author rate for us and crowd out our chat. When its time
comes a queued reply is checked again, and again if it then waits on the send
pace: nothing goes to a member ignored or banned
since, and a decline goes only while it is still the answer (the
policy is `off`, or our refusal of them holds). An accept or decline is
recorded only in a conversation open on our side (one we wrote in or
accepted), and only if its envelope is newer than the answer already held, so
a replayed old one cannot undo a later one. Their decline stops our pending
messages and lasts 7 days, as ours does. Answers are dated by their envelope
timestamp: a decline stays recorded after its 7 days, so one sent after it
ran out counts again and stops our pending messages again, while a newer copy
of the decline in force only dates it. A message from them is their implicit
accept, dated by its own timestamp, so a decline sent before it cannot undo
it, and it does not undo an answer dated after it.

**Sending** (`commands::room_dm`). Through a room both are in, the one the
conversation last used while both remain. Each message keeps its
`message_id` and is resent under a fresh envelope 2 minutes after each
attempt plus 0 to 30 seconds at random, until a receipt, for 20 minutes, then
marked not delivered. A device writes at most 20 new private messages a
minute through one room, Try again included. Every frame of this kind it
sends, new messages, resends, replies and the user's answers alike, goes
through one queue: at most 2 into a room in any 1.2 seconds, a second and a
margin for jitter, and a backlog drained one a room per tick of its
one-second drain, below the relays' per-author rate (4 a second, chat
included); a frame over that waits its turn rather than going out to be
dropped, a room's answers ahead of its other frames. Past 256 waiting, a
receipt, decline or message is dropped (a message goes again with its next
resend), and an answer takes the place of the oldest frame that is not one. A
frame that waited goes only if it still holds: a reply as above, an answer
while its member is on the roster unbanned and not ignored, a message while
it is still being sent and the policy is not `off`. One that waited over 60
seconds is dropped, and everything queued is dropped while Ember is off or
chat is locked. Nothing to a friend (friend chat is the place), to someone
whose decline holds, with no shared room, or while `room_dm_policy` is `off`,
which also stops what is still being sent; Try again meets the same rules.

**Limits.** The ed25519 signature covers the ciphertext, so a message is not
deniable: a recipient who gives away `seal_key` (which does not give away
their identity) lets anyone check that the sender wrote that text. There is
no forward secrecy. Members passing a frame learn that its sender sent a
private message, and the delayed reply blurs, but does not remove, the link
to whoever answers.

## DHT channel records

All channel records are `RECORD_TYPE_CHANNEL` (`0x03`) signed records. The
fields that matter here sit in the fixed record header (`RECORD_HEADER_LEN`,
115 bytes):

| Offset | Len | Field | In a channel record |
| --- | --- | --- | --- |
| 0 | 1 | `record_type` | 3 |
| 1..17 | 16 | `keyword_hash` | the DHT key the record is filed under |
| 17..33 | 16 | `file_hash` | the channel id (kind 7: the identity's node id; kind 2 v2: the room-blind id) |
| 33..65 | 32 | `ember_file_hash` | the channel pubkey (kind 7: the identity pubkey; kind 2 v2: the room-blind key) |
| 65..73 | 8 | `file_size` | byte 65 kind, 66 flags, 67 language (index, moderation, and from 1.7.5 a public room's presence) |
| 73..105 | 32 | `publisher_key` | the signer (kind 2 v2: the member's pseudonym for the room) |
| 105..113 | 8 | `timestamp` | |
| 113..115 | 2 | `name_len` | then the name |

After the name comes the channel trailer: `CHANNEL_TRAILER_VERSION` (1),
`extra_len` (`u16`), then `extra`. The body must end exactly there. The
signature travels beside the body; see the
[DHT specification](ember-dht-specification.pdf) for the record as a whole.

**Language wire ids** (`CHANNEL_LANGUAGES` in `network/ember/dht/publish.rs`,
mirrored by `src/lib/channelLanguages.ts`). Byte 67 of `file_size`, and the
language byte in a private room's presence seal (kind 2 below), carry a
language as its position in this list plus one; 0 is no language:

| Id | Code | Id | Code | Id | Code | Id | Code |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `en` | 2 | `es` | 3 | `fr` | 4 | `de` |
| 5 | `pt` | 6 | `it` | 7 | `ru` | 8 | `zh` |
| 9 | `ja` | 10 | `ko` | 11 | `ar` | 12 | `hi` |
| 13 | `tr` | 14 | `pl` | 15 | `nl` | 16 | `sv` |
| 17 | `uk` | 18 | `vi` | 19 | `id` | 20 | `th` |
| 21 | `fa` | 22 | `he` | 23 | `el` | 24 | `cs` |
| 25 | `ro` | 26 | `hu` | 27 | `da` | 28 | `fi` |
| 29 | `no` | 30 | `bn` | 31 | `ms` | 32 | `fil` |
| 33 | `bg` | 34 | `hr` | 35 | `sr` | 36 | `sk` |
| 37 | `ca` | | | | | | |

The list is append-only. An entry is never removed or moved, since that
would relabel every record carrying a later id; a new language takes the
next id, and the list stays under 255 entries. A reader with no entry for an
id, which is a later build's longer list, reads it as no language.

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
| 2 | `CHANNEL_KIND_PRESENCE` | member (v2: the member's pseudonym) | publisher is a valid Ed25519 key; `presence_extra_store_ok`: extra of 32 bytes, or 138 led by 1, or (from 1.7.5) 234 led by 2 | `CHANNEL_PRESENCE_TTL`, 45 min; departed, the same 45 min |
| 3 | `CHANNEL_KIND_MODERATION` | channel key | publisher is the channel key; key is `moderation_key` | `CHANNEL_GOVERNANCE_TTL`, 30 days |
| 4 | `CHANNEL_KIND_HANDOFF` | old channel key | publisher is the channel key; key is `handoff_key`; `decode_handoff_extra` | `CHANNEL_HANDOFF_TTL`, 30 days |
| 5 | `CHANNEL_KIND_EPOCH` | channel key | publisher is the channel key; `epoch_envelope_store_ok`; unflagged, key is `epoch_key(channel_id, member, epoch)` from the extra; flagged `CHANNEL_FLAG_BLINDED` (from 1.7.5), epoch at least 1 and key is `epoch_key_v2(channel_id, member_id, epoch)` from the extra | `CHANNEL_GOVERNANCE_TTL`, 30 days |
| 6 | `CHANNEL_KIND_CLAIM` | nominee's user key | publisher is a valid Ed25519 key; key is `claim_key`; `decode_claim_extra` | `CHANNEL_HANDOFF_TTL`, 30 days |
| 7 | `CHANNEL_KIND_OWNED_ROOMS` | the identity | publisher is `ember_file_hash`; key is `owned_rooms_key(publisher)`; `decode_owned_rooms_extra` | `CHANNEL_GOVERNANCE_TTL`, 30 days |
| 8 | `CHANNEL_KIND_SETTINGS` | channel key | publisher is the channel key; key is `settings_key`; within `MAX_STORE_RECORD_BYTES`; `settings_fields` | `CHANNEL_GOVERNANCE_TTL`, 30 days |

`record_ttl` falls back to `KEYWORD_RECORD_TTL` (24 hours) for any other kind,
but `channel_store_ok` refuses those first. The `extra` each kind carries:

- **1, index.** Empty. The room name is the record name; flag
  `CHANNEL_FLAG_PRIVATE` (`0x01`).
- **2, presence.** Public room: the member's 32-byte Noise key, nickname in
  the name. Private room, v1: `PRESENCE_EXTRA_ENC_LEN` (138) bytes led by
  `PRESENCE_EXTRA_ENC_VERSION` (1), nickname and Noise key sealed under the
  content key, name empty. A private room's reader drops a v1 record that is
  not flagged private or carries the 32-byte public extra: that shape is
  sealed under nothing, so anyone knowing the room's id and pubkey could sign
  one, and it must not pass for proof of the current key
  (`parse_channel_presence_member_in_room`). Private room, v2 (from 1.7.5):
  `PRESENCE_EXTRA_V2_LEN` (234) bytes led by `PRESENCE_EXTRA_V2_VERSION` (2),
  signed by a pseudonym, under
  [Private membership records, v2](#private-membership-records-v2-item-9).
  The key folds in the join secret and a 15-minute epoch, so a storer cannot
  check it. `CHANNEL_FLAG_DEPARTED` (`0x02`) marks a leave; its TTL must not
  be shorter than a live record's, or a harvested live copy could be
  re-stored after the tombstone lapsed.

  **The member's language** (from 1.7.5), the one they chose to show beside
  their name, as a `CHANNEL_LANGUAGES` wire id (position plus one, 0 for
  none), where the nickname is: byte 67 of a public room's record, and the
  last byte of the 64-byte nickname pad inside a private room's seal, v1 and
  v2 alike, never the header, so a storer cannot read it. The pad byte counts
  only while `nick_len` is under 64. Builds before it zero-fill the pad and
  read only `nick_len` bytes of it, and mask `file_size` to its first two
  bytes, so their records read as none and ours read to them as before. A
  leave carries none. A reader takes it only from the member's own record:
  beacons, chat lines and snapshots never set or clear it.
- **3, moderation.** The owner's whole governance snapshot (welcome, bans,
  moderators, `ModerationTail`). The storer does not check its shape; readers
  do. Worst case 1164 of 1165 bytes (see
  [post-1.7.4 item 1](post-1.7.4.md#1-decide-the-future-of-the-room-settings-snapshot)).
  From 1.7.5 this record is frozen as it is, and new room settings go in
  kind 8.
- **4, handoff.** `version(8) || successor_pubkey(32) || successor_id(16) ||
  flags(1)`, 57 bytes; `successor_id` must derive from `successor_pubkey`.
  `HANDOFF_FLAG_KEEP_JOIN_SECRET` (`0x01`) in the flags.
- **5, epoch.** `member(32) || epoch(8) || envelope`; the epoch must not be
  negative. Always flagged private. In v2 (from 1.7.5, flagged
  `CHANNEL_FLAG_BLINDED`, `0x04`) the first 32 bytes are a blinded member id
  and the key is built from it; see
  [Private membership records, v2](#private-membership-records-v2-item-9).
- **6, claim.** `successor_pubkey(32) || witnessed_moderation_ts(8)`, exactly
  40 bytes, the key a valid point. `CHANNEL_FLAG_PRIVATE` here means keep the
  join secret. Whether a claim is legitimate only a member holding the owner's
  nomination can decide; the storer checks shape and slot.
- **7, owned rooms.** Below.
- **8, room settings.** Below.

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
- **Padding (read from 1.7.5, published from 1.8.0).** A list is padded to
  8, 16, 32 or 48 salts, the smallest that holds it, and put in byte order
  (`pad_owned_rooms_list`). A pad is
  `BLAKE3_derive_key("ember-identity-owned-rooms-pad-v1",
  identity_seed || index)[..16]`, so it reads like any salt to everyone but the
  identity, whose recovery drops it before any lookup (`is_owned_rooms_pad`).
  Nothing in the format changes. 1.7.5 drops pads from what it reads but does
  not publish them (`PAD_OWNED_ROOMS_LIST`): a build before it, on the same
  identity, looks the pads up, finds no room, carries them as unsettled and
  publishes them back in its own list.

Publishing (`maybe_publish_owned_rooms_list`) waits until the network's list
has been read this launch, so an old database cannot overwrite a newer list.
It repeats every `MODERATION_REPUBLISH_SECS` (6 hours), and once more within
`OWNED_ROOMS_CONFIRM_SECS` (30 minutes) after the list changes. From 1.7.5 a
device reads the network's list again while it runs, about ten minutes before
its own next publish and at least every `SETTLED_REREAD_SECS` (3 hours), and
carries the salts it did not know, so the same identity on another device does
not have its newer rooms dropped by this one's next publish. Those rooms are
carried, not run here, until the next launch or a look from Settings. Every
publish, changed or scheduled, goes out only after a look that began within
the last 15 minutes (`owned_rooms_publish_waits`,
`OWNED_ROOMS_READ_FRESH_SECS`); without one the publish asks the read loop to
look at once and goes out when that look ends, whether or not it could read
the list, or after 10 minutes if none ends (`OWNED_ROOMS_READ_WAIT_SECS`). A
carried salt is listed for 60 days (`CHANNEL_CARRIED_SALT_SECS`) from when it
was first carried, or from the latest look that found the room's snapshot,
so a room another device runs stays listed while it runs there.
Recovery (`commands/channel_recovery.rs`) merges the salts of every copy the
identity signed that comes back (`merged_lists`), and takes a lookup that
finds nothing as "no list" only once `MIN_RESPONDERS_FOR_ABSENCE` (4) nodes
have answered. Builds older than kind 7 do not store it. The known limits are
under [Owned-room recovery](post-1.7.4.md#owned-room-recovery).

## Room settings (kind 8)

From 1.7.5. It fills in
[post-1.7.4 item 1](post-1.7.4.md#1-decide-the-future-of-the-room-settings-snapshot)
and carries [item 7](post-1.7.4.md#7-a-way-back-in-for-a-member-behind-a-private-rooms-key)'s
key commitment and [item 8](post-1.7.4.md#8-an-authenticated-marker-on-catch-up-re-serves)'s
admission rule. Code: `SignedRecord::channel_settings_at`,
`parse_channel_settings`, `encode_settings_extra` and `settings_fields` in
`publish.rs`; `settings_key`, `key_commitment` and `RosterAdmission` in
`channel.rs`; the schedules in `network/channel_membership.rs`.

### Why a record of its own, under a key of its own

Kind 3 is frozen as it is: its worst case is 1164 of 1165 bytes. A storer
keeps one record per DHT key, publisher and `file_hash`, and a kind 8 record
shares kind 3's publisher (the channel key) and `file_hash` (the channel id),
so filed under `moderation_key` it would replace the snapshot. It has its own
key:

`settings_key(channel_id) = BLAKE3("ember:channel:settings:v1" ||
channel_id)[..16]` (`SETTINGS_KEY_PREFIX`).

### Header

| Field | Value |
| --- | --- |
| `keyword_hash` | `settings_key(channel_id)` |
| `file_hash` | the channel id |
| `ember_file_hash` | the channel pubkey |
| `file_size` | byte 65 kind 8, byte 66 flags (`CHANNEL_FLAG_PRIVATE` as the room is), byte 67 zero |
| `publisher_key` | the channel key |
| `timestamp` | strictly increasing per publish (`Database::stamp_channel_settings`) |
| name | empty |

### `extra`

`version(1) || field*`, version `SETTINGS_VERSION` = 1. Each field is
`tag(1) || len(2) || value(len)`. Tags appear in ascending order, each at
most once. A record with every setting off is the version byte alone.

Tagged rather than kind 3's append-only tail. A tail can only grow at its end
and older builds refuse bytes they cannot place, which is how every new kind 3
field ended up costing older members the whole snapshot (see
`ModerationTail`). With tags a writer leaves out what is off, and a reader
skips a tag it does not know by its length.

**Readers** (`parse_channel_settings`) read the fields they know and skip the
rest. A record whose fields do not exactly fill `extra` (a length running past
the end, or bytes left over) is malformed and ignored as a whole, as is one
with tags out of order or repeated. A later `version` keeps this framing; a
reader that knows only 1 reads its fields the same way.

**A tag keeps its value's layout once assigned.** A tag this build knows is
held to its layout in every version, by readers and storers alike, so a
version 2 record with a malformed tag 1 is refused as one at version 1 is. A
later build that needs another layout takes a new tag.

**Storers** (`channel_store_ok`, kind 8): the publisher is the channel key;
the key is `settings_key`; the record is within `MAX_STORE_RECORD_BYTES`;
`settings_fields` passes: `version` is not 0, the fields frame exactly, in
ascending order without repeats, and each known tag's value is well formed
(tag 1 as `decode_key_commitments` reads it, tag 2 exactly one byte).
Unknown tags and versions are kept, so a later build's settings reach its
members through storers on this build.

**TTL:** `CHANNEL_GOVERNANCE_TTL`, 30 days, as kind 3.

### Fields in version 1

| Tag | Field | Value | Storer rule |
| --- | --- | --- | --- |
| 1 | key commitments | private rooms only: `count(1) || (epoch(8) || commitment(32)) × count` | `decode_key_commitments` reads it |
| 2 | admission | private rooms only: one byte, 1 = newcomers admitted only on proof of the current content key; left out for 0 | exactly 1 byte, any value |

**Key commitments (item 7).** One entry per rotated content-key epoch the
owner still keeps, newest first, at most `SETTINGS_KEY_COMMITMENTS_MAX`, which
is `CHANNEL_KEY_EPOCHS_KEPT` (4), so 161 bytes at most. The epoch is an `i64`,
little-endian, at least 1, strictly decreasing along the list; a list that
breaks that, or whose length is not exactly `1 + 40 × count`, is malformed
(`decode_key_commitments`). The commitment (`key_commitment`) is
`blake3::derive_key("ember channel key commitment v1", channel_id ||
epoch || content_key(join_secret))`. It reveals no key: the join secret is 32
random bytes. Nor does it reveal anything kind 3 does not already, since
`key_epoch` there says how many epochs there have been. A public room
writes no tag 1: its content key derives from a secret everyone holds. Nor
does epoch 0, the secret a private room was created with, which no rotation
made and which invites minted before any rotation carry.

How a member uses it (`committed_key_epoch` and `take_offered_key` in
`network/channel_membership.rs`, from `join_channel`): an invite carries a join
secret and its epoch (`ChannelInvite::key_epoch`). For a private room this
device already holds, an invite with `key_epoch` above 0 has its secret taken
for that epoch only if the newest kind 8 record held names that epoch with a
matching commitment to the secret's content key, and either this device is
behind the room's key by the owner's announcement (`key_epoch_wanted` beyond
the newest epoch it holds) or the invite names an epoch past the newest it
holds. Behind by the announcement, that is any epoch the record commits to,
one below the newest held included: such a key fills an epoch this device
never received, which it needs for lines sent under it. It never replaces a
held key. Held keys the commitments contradict are dropped first
(`settle_channel_keys`), so a slot still holding a key at that epoch holds
the committed one; `insert_channel_key_epoch` refuses a slot holding a
different key, and never moves the room's current epoch back. The key is
then stored, and joining goes on as a re-entry. A public invite is refused,
as is one at epoch 0, which does not say which epoch its secret belongs to,
and, while this device is not behind by the announcement, one for an epoch
at or below the newest it holds. A first join still takes the invite as it
stands, since there is nothing yet to check it against.

**Pending invites.** The view an invite is checked against can be stale:
kind 3 and kind 8 are looked up only while the room is entered, so a member
who left and is coming back, one just launched, or one whose lookup fell
between a rotation's kind 3 and its kind 8, holds no commitment to the
invite's epoch yet. An invite whose epoch is at or past the newest this device
holds, for which it does not already hold the same key, is then kept in
memory, never on disk, for 30 minutes (`PENDING_INVITE_KEY_SECS`), at most 16
at once across every room (`PENDING_INVITE_KEYS_MAX`, the oldest giving way),
and the room's kind 3 and kind 8 are looked up at once
(`NetworkCommand::RefreshChannelOwnerRecords`). After each kind 3 or kind 8
lookup for the room the check runs again (`settle_channel_keys`), and the key
is taken once it passes. Only that check takes a waiting key, so a crafted
one waits and lapses.

**A held key the commitments contradict.** The store keeps the first key an
epoch is given, so a crafted first-join invite (any secret at the room's
current epoch, or at any epoch up to the invite's cap) would otherwise pin the
device: the genuine key could never be stored for that epoch. After each kind
8 record it newly holds, after each kind 3 lookup that applied the room's
first snapshot or raised `key_epoch_wanted` (`moderation_pass_rechecks_keys`),
and before checking an invite, a member compares the keys it holds for a room
it does not own with the commitments (`epochs_contradicting_commitments`). An
epoch the record names under a different commitment is treated as not held.
So is an epoch past both the newest the record names and the owner's
announced `key_epoch` (only an unchecked first join stores one: the key-epoch
loop fetches nothing past `key_epoch_wanted`), but only once a snapshot has
been applied for the room (`moderation_updated_at` above 0). Before that
`key_epoch_wanted` is still 0, and kind 3 and kind 8 are separate lookups
written in separate batches, so a first join's genuine key could otherwise be
judged against a kind 8 from before the rotation to its epoch and dropped. The
re-check after the snapshot lands is what still drops a crafted one promptly.
Its key is dropped (`Database::drop_channel_key_epochs`) and `key_epoch` falls
back to the newest still held, so the device stops sealing under it and
reading with it, and is behind again. The drop is made against the key judged,
not the epoch number: each row is deleted only if it still holds that secret,
checked in the same transaction, so a settle judging on an older read (the
ingest's and a join's can interleave) never deletes the genuine key another
has stored in the slot since. The dropped key waits in memory as a pending
invite does, in case a later record vouches for it after all. The genuine key
then fills the slot from an invite that checks or from the owner's sealed
epoch record, which the key-epoch loop looks for again; nothing else does,
since re-entry takes only checked keys. A drop or take made while joining is
handled as one an ingest makes: the room's epoch fetch stamp is cleared and
the room redrawn (`NetworkCommand::ChannelKeysChanged`). A record without tag
1 contradicts nothing, and epoch 0, which has no commitment, is never judged.

A key equal to the room's join secret is not spared the check: every first
join stores its invite's key as both, crafted or genuine, so sparing it would
spare the case the check exists for. What is left is a first join whose newest
reachable kind 3 and kind 8 both predate the rotation to the invite's epoch
(an owner gone before either landed): the genuine key is then past everything
announced and is dropped like a crafted one. It waits in memory for 30
minutes, taken back if a kind 8 naming it arrives, and otherwise the room is
behind and gets the key from the owner's sealed record once the owner's
renewal reaches this member.

### Admission (item 8)

Tag 2 says how a private room admits a member its roster does not hold
(`RosterAdmission`, read by `RosterAdmission::from_setting`):

- **0, or tag 2 absent, or no kind 8 held:** as before 1.7.5. A live chat
  line under the current key, at a TTL above 1 and fresh by its signed time,
  also puts its author on the roster (`chat_author_joins_gossip_roster`).
- **1:** only proof of the current content key admits; a chat line never does.
  Members already on the roster stay, and a line from one still refreshes
  their `last_seen`.
- **Any other value reads as 1.** A later build may give a value above 1 only
  to a rule at least as strict as 1, since builds from 1.7.5 on apply 1 to it.

Writers leave the tag out for 0. The value is one byte in every version, and
the tag keeps that layout from here on, as tag 1 keeps its own.

Why: a catch-up re-serve is re-sealed by the responder under its current key
and sent at TTL 1, and the TTL is outside the AEAD, so a relay can raise it.
A line an evicted member wrote, stored by a lagging member and re-served
recently enough, then reads as a live line under the current key, puts the
evicted identity on the roster, and the owner's next rotation seals the new
epoch to it. 1.7.5 closes that by dropping chat-based admission rather than by
marking re-serves inside the seal, so the gossip formats do not change.

**Who applies it.** An owner on 1.7.5 writes 1 for every private room it owns,
and applies 1 to its own rooms from launch, whatever it holds. A member
applies the newest kind 8 it holds for the room (`private_room_admission`),
kept in `channel_settings.admission`; a failed read counts as 1. Public rooms
never admit by chat anyway, so the tag means nothing there.

**Every path that adds a row to a private room's roster**, and what 1 does to
it:

| Path | Code | Under 1 |
| --- | --- | --- |
| Live chat line | `chat_author_joins_gossip_roster`, from `chat_line_admits_author` in `channel_gossip.rs`, the chat handler's one roster write | closed; a member already held is still refreshed (`note_channel_member_alive`) |
| Presence beacon | `apply_channel_presence_beacons`, `beacon_admits_newcomer` | unchanged: a newcomer needs their own `PresenceBeacon::proves_key` against the current key whatever the rule, as since 1.7.0 |
| DHT presence record (kind 2) | `ingest_channel_presence_records` | a member not held is admitted only by a v2 record that opens under the current key and whose binding verifies; a v1 record refreshes a member already held and admits nobody |
| Our own row | `record_self_member`, `maybe_publish_channel_presence` | unchanged; only ever our own key |
| Owner's snapshot (kind 3) | `apply_channel_moderation` | unchanged: banned and moderator rows on the owner's signature |
| Moderator's ban or unban | `apply_channel_ban_action` | unchanged: a moderator the owner named is an authority over who is in the room |
| Handoff | `channel_handoff_transition_locked` copying the old room's roster | unchanged: rows already held |

**A DHT presence record counts as proof of the current key.** It is the
member's own signed record, filed under `presence_key` from the current
epoch's join secret, with its extra sealed under the current content key, and
it has to stay: it is how a newcomer finds the room's members and how they
find the newcomer, before either has anyone to send a beacon to. In v1 the
seal's AAD names the room but not the member (`presence_extra_aad`), so a
storer holding a current member's record could copy the sealed extra into a
record it signs itself, and every device that counted it would put the
storer's key on the roster for the owner to seal the next epoch to. Every
member publishes a v1 copy until 1.8.0, not only members on 1.7.4, so any
storer of the room's presence slot holds one. Only the v2 form from
[item 9](#private-membership-records-v2-item-9) counts in a private room: its
AAD names the pseudonym that signs the record and the seal carries the
member's signature binding them. A v1 record is still read, refreshing a
member already held, and admits nobody (`merge_channel_presence_blobs`). A
newcomer on 1.7.0 to 1.7.4 publishes only v1 and is admitted by the key proof
in their own beacon instead, which room digests carry to every member.

**Older members.** Builds before 1.7.0 send no key proofs. In a room whose
owner runs 1.7.5 they are no longer admitted through their chat lines, but
every build since 1.6.0 seals its presence record under the current epoch, so
they still join rosters on the presence walk (`PRESENCE_FETCH_SECS`, five
minutes; twenty seconds for the room on screen) rather than at their first
line.

### When only one of the two records arrives

The two records never carry the same setting: kind 3 is frozen, so every
setting added from 1.7.5 on lives only in kind 8. Each is applied on its own,
newest first by `moderation_supersedes` against the last held copy of the
same kind:

- **Kind 3 without kind 8:** governance as today; every kind 8 setting stays
  at its last held value, or its default if none was ever held. A missing
  tag 1 means invites cannot be checked, so a held room takes none, keeping
  each in memory for its 30 minutes in case kind 8 arrives (pending invites,
  above); a missing tag 2 means chat lines admit as before 1.7.5.
- **Kind 8 without kind 3:** its settings apply; governance stays as last held.
- **Neither:** nothing changes. Absence is not a reset for either record.

Defaults are chosen so that a room whose owner never publishes kind 8 behaves
exactly as it did in 1.7.4, which is also what members see while an owner is
still on 1.7.4. A newer kind 8 that leaves a tag out turns that setting off:
the record is the owner's whole settings, and a writer leaves out what is off.

Members keep the newest copy per room in the `channel_settings` table:
its timestamp, signature, tag 1's value and tag 2's byte as written
(`admission`, 0 when absent) (`Database::ingest_channel_settings`).
The table is created on first use rather than by a numbered migration, so the
schema stays at 62 and 1.7.0 still opens the database. A table made before
`admission` gains it when the database opens
(`shape_channel_settings_locked`), its rows reading 0. The row goes with the
room when it is forgotten or deleted.

### Publishing and fetching

**Owner** (`maybe_publish_channel_settings`, on the Ember maintenance tick,
once a minute, beside the kind 3 republish and under the same gates, and at
once after a rotation committed from a command,
`NetworkCommand::PublishOwnedChannelSettings`). It publishes kind 8 as soon as
the commitment list differs from the one it last published, both read from
the room's epochs when signed, so every key rotation and every rotation taken
back goes out, including one taken back and minted again under the same epoch
with another key; then once more within 30 minutes
(`CHANNEL_SETTINGS_CONFIRM_SECS`), and otherwise on kind 3's republish cadence
(`MODERATION_REPUBLISH_SECS`, 6 hours) and once each launch. The first of a
launch is confirmed within 30 minutes too when its commitments differ from
those of the copy held, so a rotation committed just before a quit, or before
the launch's first pass, gets its confirm. A room's keys are
read only when its key generation has moved (`Database::channel_key_generation`,
moved by every write to the room's epochs) or its schedule has come
(`channel_settings_read_due`, `channel_settings_publish_plan`), and reading,
decrypting and signing run on the blocking pool (`read_owned_channel_settings`),
so a settled room costs a pass nothing. A publish that could not start, or that
no node acknowledged, is tried again a minute later
(`CHANNEL_SETTINGS_RETRY_SECS`); a room the gates hold back is looked at again
after five minutes (`CHANNEL_SETTINGS_HELD_BACK_SECS`), or as soon as its keys
move. It goes to the same lookup-backed replica set as kind 3
(`start_own_channel_publish`). Every private room it owns publishes one, since
each states tag 2 = 1 (`owner_publishes_channel_settings`,
`own_channel_settings`): a room that has never rotated publishes tag 2 alone,
and one whose commitments run out keeps publishing without them, so
commitments it no longer stands behind are taken back. A public room publishes
nothing. Each copy is held locally once its publish has started and before it
goes out, so the next stamp counts on from it.

A rotation's sealed key records go out only once the kind 3 snapshot
announcing it has committed (`rotate_and_commit`), so a rotation taken back
hands its key to nobody. Nor does its commitment: the snapshot is checked for
size before the key is stored, and from just before the key is stored until
the commit or the rollback is done the room is marked as rotating
(`RotatingRoom`), and a settings pass signs nothing for it. The pass also
signs nothing from a read during which the room's key generation moved, which
is what a rollback finishing between its read and its check leaves; ending the
rotation moves the generation, so the room is read again on the next pass. A
moderator's ban rotated from the owner loop needs no mark: it stores the key
and starts the snapshot on the network task, which the settings pass also
runs on. Records a rolled-back rotation sent before this build cannot be withdrawn.
They share their DHT keys with the records of the key minted next under the
same epoch, which replace them on every storer that receives both and which a
member reading both takes first (newest first, in
`ingest_channel_epoch_records`); a member that stored the rolled-back key all
the same drops it once kind 8 commits to the new one (above).

**Members** (`maybe_refresh_channel_settings`). Decided for 1.7.5: kind 8 is
looked up on every third kind 3 pass, the first included, which with
`MODERATION_FETCH_SECS` (5 minutes) is every 15 minutes
(`CHANNEL_SETTINGS_FETCH_EVERY_PASSES`), and at once after a kind 3 pass
(`settings_owed_after_pass`) whose snapshot moved `key_epoch` past any before
it, or while this device is behind (`key_epoch_wanted` beyond the newest epoch
it holds) and the kind 8 it holds does not name `key_epoch_wanted`. The second
covers a lookup that fell between a rotation's kind 3 and its kind 8: the next
kind 3 pass asks again rather than leaving it for 15 minutes. Those extra
lookups back off while the room stays behind on the same epochs and no kind
8 lands (`settings_lookup_backoff_allows`): the first at once, the next a pass
later, then each twice as long after the one before, up to 6 hours
(`SETTINGS_LOOKUP_BACKOFF_MAX_SECS`). An owner on 1.7.4 never publishes kind
8, and a member behind its key would otherwise look it up after every pass.
A move of `key_epoch_wanted` or of the newest epoch held, or a kind 8 landing,
starts over; the lookup on every third pass goes on regardless. A lookup given up
on before it finished (`release_ember_search_state`) leaves the room owed one,
and an invite that could not be checked looks both records up at once (pending
invites, above). This build reads tags 1 and 2, both meaningful only in a private
room, and an owner applies its own tag 2, so it looks kind 8 up for private
rooms it does not own; a build that gives public rooms a kind 8 setting widens
that (`channel_settings_fetched_for`). A record is held only if its signer is
the room key this device joined and it parses, and only if it supersedes the
copy held (`moderation_supersedes`); a lookup that finds nothing writes nothing.

### Builds before 1.7.5

They do not store or read kind 8 (`channel_store_ok` refuses an unknown kind),
so until the network updates fewer nodes keep it, as for kind 7. They are
unaffected otherwise: nothing they rely on moves out of kind 3.

## Private membership records, v2 (item 9)

From 1.7.5. It fills in
[post-1.7.4 item 9](post-1.7.4.md#9-keep-private-room-membership-out-of-the-dht).
In v1 a private room's presence record names the room (`file_hash`,
`ember_file_hash`) and the member (`publisher_key`) in its header, so every
storer learns the roster, and its seal binds the room but not the member, so
a storer could copy the seal into a record it signs itself. A v1 key-epoch
record is filed under `epoch_key(channel_id, member, epoch)`, all public
values, with the member's key in the clear, so anyone who knows the room id
can test whether a key is a member. Both kinds gain a second form. Code:
`presence_pseudonym`, `presence_room_blind`, `encode_presence_extra_v2`,
`decode_presence_extra_v2`, `epoch_blind`, `epoch_member_id`, `epoch_key_v2`,
`PUBLISH_V1_MEMBERSHIP_RECORDS` and `V1_CUT_OVER_ROTATES` in `channel.rs`;
`SignedRecord::channel_presence_v2_at`, `parse_channel_presence_member_v2`,
`channel_key_epoch_at` and the two `*_forms` builders in `publish.rs`;
`merge_channel_presence_blobs`, `ingest_channel_epoch_records`,
`maybe_refresh_channel_key_epoch` and `channel_epoch_lookup` in
`network/channel_membership.rs`. Public rooms keep v1 only: their join secret
is derivable by anyone, so blinding with it hides nothing.

v2 takes the room and the member out of the records. It does not take the
member out of the DHT traffic that carries them; see
[What storers still learn](#what-storers-still-learn).

### Presence, v2

Every derivation below takes `join_secret`, the secret the room seals new
traffic with, which is the one `presence_key` already folds in.

| Field | Value |
| --- | --- |
| `keyword_hash` | `presence_key(channel_id, join_secret, presence_epoch(timestamp))`, as v1 |
| `file_hash` | room-blind id: `BLAKE3(room-blind key)[..16]` |
| `ember_file_hash` | room-blind key: the Ed25519 public key whose seed is `blake3::derive_key("ember channel presence room v1", channel_id || join_secret)` |
| `file_size` | byte 65 kind 2, byte 66 `CHANNEL_FLAG_PRIVATE`, with `CHANNEL_FLAG_DEPARTED` for a leave |
| `publisher_key` | the pseudonym: the Ed25519 public key whose seed is `blake3::derive_key("ember channel presence pseudonym v1", member_seed || channel_id || join_secret)`, `member_seed` being the member's long-term Ed25519 seed |
| `timestamp` | the record is filed under the presence epoch of this stamp |
| name | empty |

The room-blind key is a valid point and `file_hash` derives from it, so the
storer rule every kind shares holds unchanged, and the record names neither
the room nor the member. (The STORE that carries it still names the member:
see [What storers still learn](#what-storers-still-learn).) The pseudonym is
the same across presence epochs while the join secret stands, so a tombstone
replaces the live record under the one store key, as in v1.

`extra`, `PRESENCE_EXTRA_V2_LEN` = 234 bytes:

| Offset | Len | Field |
| --- | --- | --- |
| 0 | 1 | `PRESENCE_EXTRA_V2_VERSION` = 2 |
| 1..25 | 24 | nonce |
| 25..234 | 209 | 193-byte plaintext sealed under `content_key(join_secret)`, and tag |

The plaintext is v1's, then the member: `noise_pub(32) || nick_len(1) ||
nickname padded to 64 || member_pubkey(32) || binding(64)`, the pad's last
byte carrying the member's language as in v1 (see kind 2 above). The AAD is
`"ember-channel-presence-extra-v2\0" || channel_id || pseudonym_pubkey`
(`presence_extra_v2_aad`). The binding is the member's long-term key's
signature over `"ember-channel-presence-binding-v2\0" || channel_id ||
pseudonym_pubkey || presence_epoch(8) || departed(1, 0 or 1) || timestamp(8)`
(`presence_binding_preimage`).

**Readers** (`parse_channel_presence_member_v2`): for each join secret held,
newest first, a blob whose `file_hash` is that secret's room-blind id is
read as v2 and only as v2. It is kept only if the pseudonym's signature
checks, `ember_file_hash` is the room-blind key, the record is kind 2 flagged
private, `keyword_hash` is `presence_key` for the presence epoch of its
stamp, the seal opens under the pseudonym's AAD, and the binding verifies for
that pseudonym, epoch, flag and stamp. The member is then the key the seal
names, not the signer. A v2 record that fails any of these is dropped. A seal
copied into a record another key signs fails the AAD; a seal re-made for
another pseudonym by someone holding the content key opens, and fails the
binding, which names the member's own pseudonym. The record opened under the
current secret counts as proof of the current key for
[admission](#admission-item-8); in a private room a v1 record does not.

### Key epochs, v2

For epoch `E` (at least 1), sealed by the owner to one member. The blind is
derived from the owner–member pairwise secret, the static X25519 DH between
the owner's identity key and the member's that the envelope's wrapping key
(`derive_channel_epoch_secret`) already uses, under a purpose of its own and
with the epoch fixed at 0, so it is per room and per member and does not
change with the epoch. The owner computes it from its seed and the member's
key, the member from its seed and the owner's key, which kind 3 names.

- `pairwise = derive_pairwise_capability(seed, peer_pubkey,
  "ch-epoch-blind-v2" || channel_id, 0)` (HKDF-SHA256 over the DH, as every
  pairwise capability; `EPOCH_BLIND_PURPOSE`).
- `blind = blake3::derive_key("ember channel epoch blind v2", pairwise)`
  (`epoch_blind`).
- `member_id = blake3::derive_key("ember channel epoch member v2", blind ||
  E as i64 little-endian)` (`epoch_member_id`), a different one in every
  epoch, so a storer cannot link one member's key records across rotations
  once v1 stops going out. Until then it can: see
  [the transition](#the-transition-and-the-cut-over-in-180).
- `keyword_hash = BLAKE3("ember:channel:epoch:v2" || channel_id ||
  member_id || E as i64 little-endian)[..16]` (`epoch_key_v2`), with
  `channel_id` the record's `file_hash`.
- `extra` = `member_id(32) || E(8) || envelope`: v1's layout and length.
- `file_size` flags `CHANNEL_FLAG_PRIVATE | CHANNEL_FLAG_BLINDED` (`0x04`, a
  bit no kind used before). Header otherwise as v1: the channel id and pubkey,
  signed by the channel key. The envelope is unchanged.

The key is built only from what the record carries, so a storer recomputes it
as it does `epoch_key` (below); only someone holding the member's blind can
compute the member id to find or test the slot by. That holds for the v2
record alone: while the v1 copy beside it goes out, its key, `epoch_key`, is
built from the room id, the member's key and `E`, all public values, so
anyone who knows the room can still test whether a key is a member. A reader
takes a flagged record as its own when `member_id` is the one it derives
against the owner's key; the parse has already checked `keyword_hash` against
`member_id` and `E`.

**A member computes its record's key for any epoch directly,** whatever it
holds or missed: one several epochs behind, one whose copy of a rotation was
never published, and one unbanned after rotations it was left out of all look
up the current epoch's record as a member who never fell behind does. Each
pass looks up the newest epoch in the retention window the member is missing
(`channel_epoch_lookup`, which reads epoch numbers only, on the blocking
pool), so history under the epochs in between comes after the current key. A
key stored clears the room's fetch stamp, so the next missing epoch is looked
up on the next maintenance tick (`EMBER_MAINT_INTERVAL`, a minute) rather than
possibly the one after, the fetch interval (`CHANNEL_EPOCH_FETCH_SECS`) being a
minute too. A room with nothing to look up is stamped like one looked up.

### Storer rules on 1.7.5

- **Kind 2:** unchanged except that `presence_extra_store_ok` also takes 234
  bytes led by 2. A storer cannot open the seal or check the binding.
- **Kind 5:** the publisher is the channel key (`ember_file_hash`, of which
  `file_hash` is the hash) and `epoch_envelope_store_ok` passes. Unflagged,
  the key must be `epoch_key(file_hash, member, E)` from the extra, as before.
  Flagged `CHANNEL_FLAG_BLINDED`, `E` must be at least 1 and the key must be
  `epoch_key_v2(file_hash, member_id, E)` from the extra. Either way a record
  is kept only under the one key it derives; any key pair can be a room's, so
  what the rule holds a signer to is that derivation, not who signs.

**Builds before 1.7.5 keep neither:** `presence_extra_store_ok` there knows
32 and 138 bytes only, and a v1 storer recomputes `epoch_key` from a v2
record's extra and finds it filed elsewhere. Like kinds 7 and 8, v2 lives on
1.7.5 storers only until the network updates.

### The transition, and the cut-over in 1.8.0

**Publishing.** This build publishes both forms
(`SignedRecord::channel_presence_forms`, `channel_key_epoch_forms`), stamped
alike. A private presence record goes out as v2 and v1, under the same
presence key; the two never share a store slot (publisher and `file_hash`
both differ), so neither replaces the other. A republish or a leave counts as
landed when either form stored (`any_publish_stored`), since a reader takes
either. A key-epoch record always goes out as v2 (every rotated epoch is at
least 1), and as v1 as `epoch_record_publishes_v1` says. Rotation, the
owner's renewal of the current epoch (`republish_channel_key_epoch`, whose
key read, DH and seals run on the blocking pool,
`seal_current_epoch_records`) and an unban's re-seal
(`reseal_current_epoch_to_member`) publish the same forms.

**What the transition gives away.** A key-epoch record's v2 and v1 copies go
out together, stamped the same second and carrying the same envelope, and the
v1 copy names the member. A storer that holds both links the v2 copy's
`member_id` to that member, so until 1.8.0 one member's key records can be
linked across rotations after all, and each v1 copy's key stays testable from
public values (above). The v2 ids are per epoch, so this needs no cut-over
rotation of its own: the first epoch minted after v1 stops has ids nothing
published before linked.

**Reading.** Presence: one walk of the presence keys, as before, returns
both forms; each blob is read as v2 first and as v1 only if it is not v2, and
the newest record per member wins, with the v2 copy standing over a v1 copy
signed the same second (`merge_channel_presence_blobs`). Key epochs: each
pass looks up the newest missing epoch under its v2 key and its v1 key; the
two lookups are held until both end and read together
(`buffer_channel_epoch_records`), newest first and v2 first among copies
signed the same second.

**1.8.0 stops publishing v1,** the same release that stops sending the old
chat frames (item 2), so a room has one cut-over to test. The switch is one
constant, `PUBLISH_V1_MEMBERSHIP_RECORDS`. The owner's own key-epoch copy
stays v1 past it (`epoch_record_publishes_v1`): kind 3 already names the
owner, so v1 hides nothing there, and it is the form a device restored from a
backup reads its keys back from (`catch_up_own_epochs`). 1.8.0 still reads
v1, which is what members on 1.7.4 publish; stopping that, and with it
admission on a v1 presence record, is left until no such members remain.

**The cut-over also rotates every private room once.** During the
transition a member's v1 and v2 presence copies sit side by side under one
presence key with the same stamp and flags, so a storer keeping a table can
link pseudonym `P` and room-blind key `R` to member `M` and room `C`. `P`
and `R` change only when the join secret does, so without a rotation the v2
records after the cut-over would carry ids the transition already linked.
Owners therefore rotate each private room they own once when they stop
publishing v1, and the v2 ids after it are unlinkable to the transition's
(as far as the records go; see below). `V1_CUT_OVER_ROTATES` stands next to
the switch, and this build refuses to compile with v1 turned off until that
rotation is built. Key-epoch records do not need it, since their ids change
with every epoch, but the same rotation is what gives them their first epoch
past the transition.

### What storers still learn

v2 hides the room from storers but not the member. Every DHT STORE and
FIND_VALUE is signed under the sender's long-term DHT identity
(`identity.ed25519_secret_key`, with `sender_id = BLAKE3(pubkey)[..16]`),
which is the same key a member is known by in its rooms. A v2 presence record
goes straight from the member to its storers, and a member's key-epoch
lookups come from the member, so a storer sees which member stored or asked
for which presence key and which key-epoch key, and with that the
pseudonym, room-blind key and blinded member id that member uses. It still
cannot tell from the records which room those belong to. Sending membership
STOREs and lookups under a throwaway DHT identity, ideally through a relay,
would close this; it is transport behaviour, not a record format, and is
planned in [post-1.7.5 item 1](post-1.7.5.md#1-private-room-membership-traffic-under-a-throwaway-dht-identity).

## Feed heads (record type 0x04)

Not a room format, but a DHT record with the same header and trailer framing
as channel records (`network/ember/feed.rs`, `SignedRecord::feed_head_record`).
A feed is a signed, updatable list of files under a publisher's identity; the
head points at the current list, which is an ordinary collection file
fetched like any download. Design: [post-1.7.5 item 3](post-1.7.5.md#3-follow-a-publisher-feeds).

**Header.** `record_type` `RECORD_TYPE_FEED` (`0x04`), signed by the
publisher's identity key. The header's own fields carry what fits:

- `keyword_hash` is `feed_key = BLAKE3("ember-feed-v1" || publisher || salt)[..16]`;
- `file_hash` is the feed's 16-byte salt, so the per-publisher dedupe keeps one
  head per feed;
- `ember_file_hash` is the list's BLAKE3 and `file_size` its size;
- the name is the title, at most 64 bytes.

**Trailer.** Framed as the channel trailer, little-endian: `version(1) = 1 ||
sequence(8) || list_ed2k_hash(16) || item_count(4) || description_len(2) ||
description`, with the description at most 256 bytes and nothing after it.
`sequence` is the publisher's clock in milliseconds, never less than one past
the last it published (`next_sequence`), so the latest publish wins on any of
the publisher's devices; a device's republish first looks for a newer
head and leaves it in place. A follower takes the highest `sequence` it has
seen and never goes back.

**Storers** that know the type (`accept_record`, `feed_store_ok`) refuse a head
whose `keyword_hash` is not the `feed_key` of its signer and salt, whose
trailer does not parse, or which names no list. They keep it
`CHANNEL_GOVERNANCE_TTL` (30 days), replicate it, and among a feed's heads keep
the newest timestamp. Builds before it file it as an unknown type for
`KEYWORD_RECORD_TTL` (24 hours) without replicating or reading it. The
publisher republishes hourly while it runs, and on every publish: while most
storers are such builds, a head stored a day ago has often lost every node
that held it. Each republish is also pushed to friends with a session, as a
publish is, so a friend who followed since takes it whatever the DHT holds.

**Followers** look a feed up every 30 minutes, and every 3 minutes while it
has never been found, for a day after following it. A lookup whose key gives
no head reads the feed's index shard (below), at most every 15 minutes, and
takes the head the newest listing of the feed carries, unless it withdraws
it.

**The list** is a format-v2 collection (`network/ed2k/collection.rs`) of at
most 2,000 entries, each with name, size, eD2K, AICH and Ember BLAKE3. An entry
may carry a note, tag `FT_EMBER_NOTE` (`0xE3`, a string of at most 256 bytes),
which eMule's reader skips as unknown. A follower uses a list only if its size,
eD2K hash and BLAKE3 all match the head, it parses, it holds `item_count`
entries and every entry names a file one could fetch; otherwise the feed is
marked broken. A list is at most 2 MiB (`MAX_LIST_BYTES`): a publisher refuses
to publish a larger one, and a follower that finds the newest head naming a
larger one says so and fetches neither it nor an older head's list.
The list is shared hidden by its publisher and by every follower holding it:
served to whoever asks for its hash, with Ember source records, and never in
the Library, a browse answer, a keyword record, KAD or a server. Its source
records go out ahead of the library's, so a publisher with a large library
behind a firewall is found as a source of a new list within one publishing
pass. A follower connected to the publisher as a friend also asks the friend
directly. A fetch is given up after 30 minutes with no byte and no source
(queued at one counts as a source), or 6 hours in all, keeping what it has,
and tried again 30 minutes later.

**Links.** `ember-feed:` followed by `publisher(32) || salt(16)` in lowercase
unpadded RFC 4648 base32 (77 characters in all), or the same after
`https://emberp2p.org/feed/` or `https://www.emberp2p.org/feed/`, read in
either case and with whitespace around it. Only the one canonical encoding of
the 48 bytes is accepted (no character more than they need, padding bits
zero), so two texts never name one feed. A link whose publisher is not a
valid Ed25519 key is refused.

## Feed listings (record type 0x05)

A publisher may list a feed in a public index, for anyone to find in the Feeds
page's Discover tab without its link; a feed not listed is found only by its
link, as before (`network/ember/feed.rs`, `SignedRecord::feed_listing_record`).
The choice is made when the feed is created and can be changed at any time.
There is no directory server: the index is sixteen DHT keys.

**Header.** `record_type` `RECORD_TYPE_FEED_LISTING` (`0x05`), signed by the
publisher's identity key. Every field is the head's, as published, but for the
key:

- `keyword_hash` is the index shard key `BLAKE3("ember-feed-index-v1" ||
  shard)[..16]`, where `shard` is one byte, `feed_key[0] % 16`;
- `file_hash` is the salt, so the per-publisher dedupe keeps one listing per
  feed in a shard;
- `ember_file_hash`, `file_size` and the name are the head's.

**Trailer.** Framed as the channel trailer: `flags(1) ||` the head's trailer
whole (`version(1) = 1 || sequence(8) || list_ed2k_hash(16) || item_count(4) ||
description_len(2) || description`). Flag `0x01` withdraws the feed from the
index; other bits are kept for later builds. A listing names its feed by
publisher and salt, which is all its link holds, so Discover follows it as it
would the link. A withdrawal carries a
fixed placeholder head (`withdrawal_head`: title `-`, every hash byte `0xFF`,
size 1, no items) rather than the feed's, so it says nothing of the feed but
what the listing it displaces already said.

**Storers** that know the type (`feed_listing_store_ok`) refuse a listing whose
`keyword_hash` is not the shard key of its signer and salt, so one cannot be
aimed at whichever shard key lies nearest a storer, or whose trailer does not
parse into a valid head. They keep it `CHANNEL_GOVERNANCE_TTL` (30 days),
replicate it, and keep the newest timestamp per feed (the larger signature on
a tie). One publisher may hold at most 16 records under a shard key
(`MAX_FEED_LISTINGS_PER_PUBLISHER_PER_KEY`, twice the feeds one identity
keeps, for withdrawals of deleted ones), against 150 under other keys; a
replacement of one it holds is always taken. Older builds file it as an
unknown type for 24 hours.

**The publisher** signs its listing anew with every publish and every hourly
republish while the feed is listed. Each listing or withdrawal of a feed is
stamped at least a second after the last, a stamp kept in the database across
restarts, and whether the feed is listed is read as it is stamped, so a
change of mind is never a tie nor outranked by a listing decided before it.
Taking a feed out of the index sends a withdrawal, the listing with flag
`0x01`, which displaces the last at each storer, and again with each
republish until 30 days after the last listing sent, by when it has lapsed. A
feed never listed while published sends none: no listing named it. Deleting a
listed feed keeps its salt as a tombstone, whose withdrawal the feeds service
sends within a minute while the Ember Network is on and daily after, until
the same 30 days have passed.

**Discover** walks the sixteen shard keys, as rooms' Discover does, and keeps
the newest listing of each feed (the larger signature on a tie), signed and
stamped within the last 30 days and no more than ten minutes ahead of the
local clock. A head's `sequence` past the listing's own time is cut to it, as a
head is published before its listing is signed. Discover drops withdrawn feeds,
takes at most eight listed feeds from one publisher (the most one identity
keeps), the last listed, and cleans titles and descriptions as any remote
text. A listing signed in the last 3 hours shows its publisher as active.
What a walk finds is cached: a shard that too few nodes answered keeps its
cached feeds, and one that settled without a cached feed forgets it. The user
can hide a feed or a publisher from Discover, locally.

## Feed file stream (type 0x09)

A follower fetches a feed's file from its publisher first over the file
stream chat attachments (`0x07`) and room transfers (`0x08`) use
(`network/ember/attach.rs`, `attach_stream.rs`), under a first byte of its
own, `FEED_STREAM_MSG_TYPE` (`0x09`). Neither side need be the other's friend
or share a room with it (`network/feed_direct.rs`).

**Carriers.** The follower dials QUIC to the publisher, with the
publisher's node id pinned in the TLS verifier, at the address and QUIC port
of the publisher's own signed Ember source record for the file, a reachable
one (not firewalled, a TCP port set, not a special-use address; TCP alone when
it names no QUIC port), or for a
friend publisher at the address of their last session, at once. After 3
seconds without QUIC (`TCP_HEAD_START`) it dials the publisher's TCP upload
port beside it, as a Noise secure stream that must prove the same node id,
whose first byte after the handshake is `0x09`. Never over a relay.

**Request.** The shared 46-byte request: `0x09 || version(1) = 1 ||
reserved(4) || xfer_id(16) || tag(16) || start_chunk(4, LE)`, where
`xfer_id = BLAKE3_derive_key("Ember feed stream id v1", publisher(32) ||
salt(16) || ed2k(16))[..16]`, the tag is `BLAKE3_keyed(capability,
"ember-attach-stream-tag-v1" || xfer_id)[..16]`, and `capability =
BLAKE3_derive_key("Ember feed stream capability v1", publisher || salt ||
ed2k)`. Both are public to whoever holds the feed's link and list; what they
show is that the dialer does, and they name one file of one feed.

**Answer.** A status byte (`0` ok, `1` unknown, `2` unauthorized, `3`
source gone, `4` bad cursor), then for `0` the file's size (8, LE), its chunk
count (4, LE) and the BLAKE3 of each 256 KiB chunk, then the chunks from
`start_chunk` to the end. A file may be up to 8 GiB (`FEED_STREAM_MAX_BYTES`)
here, against 2 GiB for the other two types; a larger one is fetched over
eD2K. No root is agreed ahead, as a feed's list names its files by whole-file
digests: the follower checks each chunk against the list, every later stream
of the download against the first one's list, and the finished file against
the list's eD2K, AICH and BLAKE3. Once it has read the last chunk it closes
QUIC with `attach done`, or writes `0x01` on TCP.

**The publisher** serves a file under its `xfer_id` while the file is in a
feed it has published, is still shared with everyone and has the BLAKE3 the
feed names; the table is rebuilt each minute and on every publish or delete.
It answers `1` to an id it does not serve, and to any request while 8 feed
streams already run (`MAX_SERVES`). A file whose chunk list is not cached is
hashed for followers one at a time, at most 32 GiB of such reads an hour
(`FEED_HASH_BUDGET`), since anyone with the link may ask for any of a feed's
files; past that it answers `1` too. A stream is a priority upload, ahead of
the eD2K slots, within the upload limit.

**The follower** writes each verified chunk's missing bytes into the
download's part file, as any source does, and asks again from the next missing
chunk when the next four are held already. Three failed dials or streams in a
row, a refusal or a chunk that does not verify end it, and every network is
asked for the file.

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

**Chat attachment offers that wait, from 1.7.5.** `EMBER_EXT_ATTACH_WAITS`
(`0x12`) has two forms.

- **Empty, either way:** "an offer you make me can wait for my answer, and
  tell me again which of mine you keep". Each side sends it when a secure
  session comes up, and a sender sends it again over the session it routes
  through when another of the friend's sessions ended and it let held offers
  go. The reader marks the session (`mark_holds_offers`), spread across the
  friend's live sessions like the friends-only mark. A receiver that gets it
  puts every offer from that friend the friend had said it holds back on
  `ATTACH_OFFER_TTL_SECS` from then, and names every offer of theirs still
  waiting and not lapsed that the friend does not hold.
- **`ATTACH_VERSION (1) || xfer_id (16)`** (`encode_attach_held`), whose
  meaning follows from which end of the offer sends it. From the offer's
  receiver: "I am keeping your offer of this file for my user", sent only to
  a marked session, when the offer is left waiting on the user and again
  when the friend's empty form arrives or a session with them ends while
  another still routes. From the offer's sender, in answer: "I hold it".

Either form that finds the session's queue full is sent again on the next
few half-minute ticks.

The sender holds its grant past `ATTACH_OFFER_TTL_SECS` only on the
receiver's note, and the receiver waits past it only on the sender's echo.
The first hold is taken only while the offer is unanswered and still on its
five minutes, and runs `ATTACH_GRANT_TTL_SECS` plus five minutes from then; a
repeat while held moves nothing and is echoed again. The receiver keeps an
echoed offer `ATTACH_GRANT_TTL_SECS` from its arrival, so it lets go first. A
sender that will not hold an offer still answerable does not echo, and the
receiver keeps the five minutes; one whose offer is over answers with
`EMBER_EXT_ATTACH_CANCEL`. An offer reopened by the receiver's "Try again" is
never held. Any secure session with the friend ending — the routed one, a
retired one, or a duplicate beside the routed one — releases the sender's
holds and puts the receiver's back on five minutes from then; a release
allows one hold again on the next note, while the offer is in date and only
to where the first hold ended. Any other body
names no offer. `EMBER_EXT_MAILBOX_AWARE` says nothing about waiting: 1.7.4
sends it and still drops an offer at five minutes, and 1.7.4 sends neither
form, so nothing waits with it.

**Friend status, from 1.7.5.** `EMBER_EXT_STATUS` (`0x13`) carries the
status a user shows friends while connected. Its body is a chat envelope
(`encrypt_chat_status`) under the friend's chat key, sealing `"STA1" ||
status(1)`: 0 online, 1 away, 2 busy, and any other value read as online.
Bytes after the status are read past, so a later build may add fields; an
envelope over `MAX_CHAT_STATUS_WIRE_LEN` is dropped. Each side sends it when
a secure session comes up, whatever the status, and again to every live
session when the user changes it (`send_friend_status`,
`announce_friend_status`). A sender whose user chose Online sends Away on
its own while they are idle (`auto_away_minutes`, `friend_status.rs`) and
Online again when they return; to the receiver that is the same status. The
receiver shows it only while the friend is online and drops it when their
session ends, so a friend with no session always shows offline; a friend who
never sends one shows online.
Older builds log the sub-type as unknown and ignore it.

**Feed heads, from 1.7.5.** `EMBER_EXT_FEED_HEAD` (`0x14`) pushes a feed head
the sender just published, so friends who follow it see the update without
waiting for their next lookup. Its body is a chat envelope
(`encrypt_chat_for_peer`) under the friend's chat key, sealing the signed
record as a DHT value blob; an envelope over `MAX_CHAT_WIRE_LEN` is dropped.
The receiver checks the record exactly as one found in the DHT and takes it
only for a feed it follows whose publisher is the friend who sent it; a head
signed by anyone else, or forwarded, is ignored. Older builds log the sub-type as unknown and ignore it.

---

## What freezes at the end of the beta

**Fixed from then on:**

- The plaintext frame numbers above, in use and retired. Nothing is reused;
  30–63 stay unassigned; new kinds of frame are extension frames.
- The extension-frame layout, its signature preimage and `EXT_FLAG_DISPLAY`,
  and the rule that unknown kinds are relayed under chat's rules and counted
  when displayable.
- Chat v2, decided and built in 1.7.5 for item 2: kinds 64 and 65, the
  tagged body at version 1 with the kind 8 framing, tags 1 to 4 and their
  layouts, the rule that a known tag keeps its layout and unknown tags are
  skipped, the line id bound to its author and signed time, the rule that a
  body's two forms name the same reply parent, the pairing rules (one row per
  line id, the legacy text being the v2 text without emoji joiners at the same
  signed time, first to arrive standing and the second not relayed when they
  disagree, one rate charge for both forms), and the transition: both forms
  sent, the v2 frame under an
  envelope id of its own and without `EXT_FLAG_DISPLAY`, until 1.8.0, which
  stops sending 15 and 19 and sets the flag.
- The gossip header and relay envelope layouts at their current versions, the
  rule that every later version keeps byte 0 as the version and bytes 1..17 as
  the channel id, and the rule that an unknown version is never relayed, so a
  later one is sent beside v1 until every build in the room reads it.
- Record kinds 1 to 8 with their storer rules and TTLs, the channel trailer
  version, and the rule that a new kind needs no DHT version bump.
- Kind 8's tagged framing, the rule that a tag keeps its value's layout once
  assigned, tag 1's layout and the key-commitment derivation.
- Kind 8 tag 2 (admission), decided and built in 1.7.5 for item 8: one byte,
  0 or absent the rule before 1.7.5, 1 admitting newcomers only on proof of
  the current key, and every other value read as 1, so a later value may only
  name a rule at least as strict. Catch-up re-serves stay unmarked: the gossip
  envelope and its seal do not change for item 8.
- The owned-rooms prefix rule, and the rule that a later epoch-envelope
  version is filed under a key of its own.
- The v2 private membership records, decided and built in 1.7.5 for item 9:
  the presence pseudonym and room-blind derivations, the 234-byte v2 presence
  extra, its AAD and binding preimage, the rule that a v2 presence record is
  filed under the presence epoch of its own stamp; the v2 epoch blind derived
  from the owner–member pairwise secret (purpose `ch-epoch-blind-v2` ||
  channel id, epoch 0, then `ember channel epoch blind v2`), the blinded
  member id from the blind and the epoch (`ember channel epoch member v2`),
  and the v2 epoch
  key from the channel id, member id and epoch, which storers recompute;
  `CHANNEL_FLAG_BLINDED` (`0x04`) on kind 5; both storer rules; and the
  transition: both forms published until 1.8.0, which stops publishing v1
  except the owner's own key copy and rotates every private room once.
  Sending membership traffic under a throwaway DHT identity is not part of
  the format and can come later (`docs/post-1.7.5.md` item 1).
- A member's language in their presence record: byte 67 in a public room,
  the nickname pad's last byte in a private room's seal, a
  `CHANNEL_LANGUAGES` wire id with 0 for none, and the rule that only the
  member's own presence record sets or clears it.
- The `CHANNEL_LANGUAGES` wire ids 1 to 37 as tabled under
  [DHT channel records](#dht-channel-records), and the rule that the list
  only grows at its end.
- The meaning of `EMBER_EXT_BROWSE_SCOPE_AWARE`, and that it or
  `EMBER_EXT_MAILBOX_AWARE` marks a session as honouring friends-only files.
- Both forms of `EMBER_EXT_ATTACH_WAITS`: the empty one asking for the named
  ones again, and the named one meaning "keep" from an offer's receiver and
  "held" from its sender; that a sender holds past five minutes only on the
  receiver's note and a receiver waits past five minutes only on the
  sender's echo; and that any session's end releases both, to be named and
  held again no further than the first hold reached.

**Nothing is left open.** Every question the post-1.7.4 plan listed for the
freeze was decided in 1.7.5; the decisions are above and in
[post-1.7.4.md](post-1.7.4.md#channels-the-format-freeze). What changes next is
already scheduled: **1.8.0** stops sending chat frames 15 and 19 (and sets
`EXT_FLAG_DISPLAY` on kinds 64 and 65), and stops publishing v1 private
membership records, rotating every private room once as it does, so a room
has one cut-over to test. It also adds a marker that says a catch-up reply
was relayed, so such a reply moves the asker's catch-up frontier; today a
relayed reply cannot be told from the hop's own TTL-1 line, and the range is
asked for again (see
[post-1.7.5.md](post-1.7.5.md#already-scheduled-for-180)).
