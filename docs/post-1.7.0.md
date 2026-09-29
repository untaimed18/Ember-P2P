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

## Ember DHT

### Resume `FIND_VALUE` pages by record, not by index

**Why:** A responder pages a key's records by position in its live list. When a
record lapses between two page requests, or a secondary key's intersection
turns empty, every later index shifts and one record is skipped for that walk.
Duplicates are harmless (the searcher dedupes); a skip is a lost result.

**To do:** Resume from the last blob's signature prefix instead of an index, as
an additive field on `FIND_VALUE` / `FOUND_VALUE`, keeping the index as the
fallback for peers that do not send it.

### Digest corroboration against colluding storers (low)

Automatic digest pinning needs two publishers vouched for by two different
responders. Two colluding nodes on the same shortlist can still meet that bar
for a bogus digest; the download then fails its BLAKE3 check and the pin is
cleared. Consider requiring responders from different /24s, or weighting by
how long each responder has been a verified contact.

## Friend chat attachments

### 7. Refuse non-friend dials earlier (low) — done in 1.7.1

A chat attachment stream (type `0x07`) from a non-friend is now refused as soon
as its type is known: the QUIC accept path closes the connection after the
7-byte header, using the friend check the handshake already made, and the TCP
fallback refuses on the first byte. The handshake itself still has to complete,
since that is what proves who the peer is. Room transfer streams (`0x08`)
cannot use this check, since room members are not friends; their grant check
stays as is.

### 8. Shorter re-fetch window after delivery (info)

Progress events already never revive a finished row (`emit_progress` reads the
stored status first); this is only about how long the grant stays servable.

A delivered attachment stays fetchable until its 24 h grant expires, so a failed
save can retry. Consider shortening the window once the sender has seen delivery
confirmed.

### 9. Friend re-check on reply and cancel (info)

The event loop re-checks friendship for offers but not for replies and cancels.
Those are already limited to authenticated friend sessions and matched against
the attachment's friend, so this is for symmetry only.

## Sharing and library

### Prune deletes on paged reloads of very large shares

A share root over 100,000 files is walked in pages (`MAX_DISCOVERED_FILES` in
`sharing/indexer.rs`); every page after the first is `partial`, so a full reload
never reconciles deletions for such a root. File-system events cover the usual
case, but a file deleted while hashing is paused (events deferred, then a paged
full reload) stays in the index and offerable until "Remove missing". Fix: track
the paths seen across one complete cursor cycle and reconcile once the last page
lands.

### "Share without subfolders" still walks the whole tree — done in 1.7.1

Discovery of a folder with an allowlist now walks only the allowlisted files
and folders and the folders that lead to them (`DiscoveryScope` in
`sharing/indexer.rs`), in every scan: startup, add, full reload and
filesystem events. Nothing else in the folder is hashed or indexed, so it no
longer shows in the Library as an unshared file. Sharing a file again from the
Library puts it back on the allowlist, and widening a partial share queues a
scan of what it newly offers.

### eMule import: offer eMule's one-folder sharing

Ember shares a folder with its subfolders; eMule shares exactly the folders
listed. The import says so per folder ("{count} folders eMule did not share will
be shared") and each folder can be unticked, but there is no way to import a
folder the eMule way. Offer "without subfolders" per imported folder, reusing the
allowlist.

## App-wide

### Chat pop-out polish

Relaunching with the chat popped out remembers the mode but does not reopen the
chat window until a conversation is opened. Decide whether it should reopen at
launch.

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
