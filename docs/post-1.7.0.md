# After 1.7.0

Work deliberately left out of 1.7.0, with why it waited and what it needs.
Ordered by priority within each section.

## Room transfers (Ember Transfer)

### 1. Send encrypted offers

**Why:** An offer carries the file name and size. It is encrypted only with the
room's content key, so when it travels through other members (no direct session
and no relay outbox) each of them can read it. The file contents, the stream
ports and the public addresses are already encrypted to the recipient alone.

**Done in 1.7.0:** Receivers understand the sealed offer (`XFER_OFFER_SEALED_VERSION`
26, `encode_xfer_offer_sealed` / `decode_xfer_offer_sealed` in
`src-tauri/src/network/ember/channel.rs`). Senders still send the plain offer
(`encode_xfer_offer` in the `OfferChannelTransfer` handler, `network/command.rs`),
because v1.6.x reads only that and a sender cannot tell which build a relayed
member runs.

**To do, either:**

- **1.7.1, with a fallback:** send the sealed offer; the recipient answers at once
  with a new "offer seen" frame (separate from Accept/Deny, which can take
  minutes). With no answer in about 10 seconds, send the plain offer. A duplicate
  is harmless — the first offer for an `xfer_id` wins. Costs a new frame type and
  a ~10 s delay before 1.6 members see the prompt.
- **Later, without one:** once 1.6 members are rare, send only the sealed offer.

### 2. Check block-protocol data as it arrives

**Why:** The direct stream verifies every 256 KiB chunk against the offered root
before writing it. The block protocol (the fallback) only hashes the finished
file, so a sender the user accepted can waste bandwidth up to the offered size
before the transfer is thrown away. The free-space check added in 1.7.0 stops it
filling the disk.

**To do:** Send the chunk-hash list first (as the stream does) and verify each
256 KiB run of blocks as it completes; drop and re-request a bad run instead of
the whole file. Needs a new frame and a version bump on both ends.

### 3. Replay protection for control frames (low)

Transfer frames are authenticated pairwise but carry no sequence number. Replays
of the other end's own frames are contained by the state machines (first offer
wins, accept once, peer checks), not by cryptography. Consider binding frames to
a per-transfer counter or phase.

### 4. Tighter use of claimed public addresses (low)

A member can make us attempt one connection per transfer to a public address it
names (private and special-use ranges are refused, and the connection must prove
that member's key). Consider only accepting addresses that match what STUN or a
past session has seen for that member.

## Networking

### 5. Share the open UDP port with QUIC

**Why:** QUIC listens on its own UDP port. Setups that forward a single port (a
VPN such as ProtonVPN, many routers) leave it unreachable. 1.7.0 covers this
with a secure TCP fallback on the upload listener, which also works where UDP is
blocked entirely.

**To do:** Demultiplex QUIC packets on the existing KAD / Ember UDP socket, so
the one forwarded port carries everything. Deferred because it changes how every
inbound UDP packet is read (KAD, Ember DHT, room chat, presence); it needs
careful packet classification and broad testing.

## Friend chat attachments

### 6. Warn about executable files (UX)

Opening already refuses to launch executables and disguised files (they are shown
in their folder instead). The cards could also say so up front: flag names such
as `report.pdf.exe`, `.bat`, `.lnk`, `.scr` in the chat card and the room
transfer drawer.

### 7. Refuse non-friend dials earlier (low)

Any Ember user can complete the QUIC or Noise handshake and open a chat
attachment stream (type `0x07`) before being refused. They get nothing, but the
handshake costs CPU. Close the connection as soon as the proven identity is not
a friend, before reading the stream. Room transfer streams (`0x08`) cannot use
this check, since room members are not friends; their grant check stays as is.

### 8. Shorter re-fetch window after delivery (info)

A delivered attachment stays fetchable until its 24 h grant expires, so a failed
save can retry. Consider shortening the window once the sender has seen delivery
confirmed.

### 9. Friend re-check on reply and cancel (info)

The event loop re-checks friendship for offers but not for replies and cancels.
Those are already limited to authenticated friend sessions and matched against
the attachment's friend, so this is for symmetry only.

## Friend Browse

### 10. Browse or search past 1,000 files

The request format is checked for an exact value, so an extended request makes
older friends fall back to the old reply. Needs a new request version with
fallback handling and testing across versions. (1.7.0 already shows
"1,000 of N" using a backward-compatible trailer.)

### 11. Folder view

Needs folder names on the wire, which is a privacy decision: folder paths
relative to the shared folder, and opt-in.

### 12. Media details

Duration, bitrate and similar. Makes the reply larger; needs a format change.
