# After 1.7.0

Work deliberately left out of 1.7.0, with why it waited and what it needs.
Ordered by priority within each section.

## Room transfers (Ember Transfer)

### 1. Send encrypted offers — done in 1.7.1, with a fallback the sender approves

**Done in 1.7.1:** Senders send the sealed offer and hold the plain one back.
The recipient answers a sealed offer at once with an "offer seen" frame
(`XFER_SEEN_PLAIN_VERSION` 28). Anything the recipient says about the transfer
cancels the plain offer. With nothing heard in `XFER_PLAIN_OFFER_FALLBACK_SECS`
(10 s) the plain offer is **not** sent on its own: the sender's transfer card
says there is no reply yet, that the recipient may be on an older Ember, and
that a standard offer lets the members relaying it see the file's name and size,
with a **Send standard offer** button (`send_channel_transfer_standard_offer`).
That sends the held offer once, and only while the transfer is still waiting
and unread. A 1.7.0 recipient ignores it as a repeat; a 1.6 recipient prompts
on it. A forwarder that drops "seen" can bring the question up but cannot make
the offer go out.

Members proven to read sealed offers are remembered in the database
(`sealed_offer_readers`, created on first use so the schema stays at 62 and
1.7.0 can still open it after a downgrade) for 180 days
(`SEALED_OFFER_READER_KEEP_SECS`). No plain offer is held for them, so they are
never asked about. The proof is a frame 1.6.x never sends whose authentication
names the member: a "seen", sealed offer or sealed stream frame (pairwise
transfer key), a typing signal or a room friend request (the member's
signature). Only members on the room's roster are recorded. A 1.7.0 recipient
never sends "seen", so its sender is asked until that member has typed, sent a
sealed offer or stream frame, or asked for a friendship in a shared room.

The sealed offer pads the name with NULs to `XFER_NAME_MAX` (160 bytes), so
every sealed offer is the same length. 1.7.0's decoder takes the padding as
part of the name (valid UTF-8, within the limit), and `sanitize_filename` strips
NULs before the name is used, so its prompt reads the same.

What remains is the second option below: stop holding the plain offer once 1.6
members are rare.

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

### 5. Share the open UDP port with QUIC — done in 1.7.1

**Done in 1.7.1:** as designed below, in `network/ember/udp_mux.rs`. QUIC runs
on the KAD / Ember socket, a listen-only endpoint stays on the TCP port number
for peers that guess it, and `quic_shares_udp_port: false` in `config.json`
restores the separate socket. The guessers are not only 1.7.0: a relay asked to
reach a source known only from KAD dials the source's TCP port number, because
a KAD record has nowhere to carry a QUIC port, and 1.7.1 requesters still ask
for that. The legacy listener keeps the old socket's UPnP mapping and Windows
Firewall rule, since those relays dial it from outside the NAT. One cost the
design did not name: the shared socket cannot set don't-fragment, because Ember
frames up to 4 KiB rely on fragmentation, so quinn skips path-MTU discovery and
stays at 1200-byte packets. What remains: the legacy listener can go only once
nothing dials the TCP port for QUIC, which needs a relay target for KAD-only
sources first.

**Why:** QUIC listens on its own UDP port. Setups that forward a single port (a
VPN such as ProtonVPN, many routers) leave it unreachable. 1.7.0 covers this
with a secure TCP fallback on the upload listener, which also works where UDP is
blocked entirely.

**To do:** Demultiplex QUIC packets on the existing KAD / Ember UDP socket, so
the one forwarded port carries everything. Deferred because it changes how every
inbound UDP packet is read (KAD, Ember DHT, room chat, presence); it needs
careful packet classification and broad testing.

It also settles which port a relay should dial. Today QUIC binds its own socket
on the TCP port number (or +1 to +4, or an OS-chosen port) and STUNs it
separately, so a peer's QUIC port has to be advertised on its own. 1.7.1 added
it to firewalled source records (contact flag bit 7) for that reason. Once QUIC
shares the socket, that field and every other advertised QUIC port are simply
the public UDP port.

#### Design

**Today.** The main loop owns `recv_from` on the KAD socket and routes each
datagram in order: STUN replies (`route_stun_binding_packet`), Ember frames
(magic `0xEB 0x3E`), then everything else to `handle_udp_packet` (KAD, eD2K
UDP, and their eMule-obfuscated forms). QUIC has a separate `quinn::Endpoint`
on its own socket (`build_server_client_endpoint`).

**One reader, four destinations.** A dedicated task owns `recv_from` on the
shared socket and classifies each datagram before anything else sees it:

1. STUN: unchanged.
2. Ember: the magic bytes, unchanged.
3. QUIC: sent straight to quinn over a channel.
4. Everything else: to the main loop over a bounded channel, which replaces its
   `udp_socket.recv_from` arm.

QUIC must not go through the main loop. Relayed transfers, attachments and room
streams all ride QUIC, and the main loop awaits inside its handlers, so its
latency would become their throughput. The channels drop on full, as UDP does,
and count the drops.

**Classifying QUIC.** Plain KAD and eD2K begin with `0xE3`, `0xE4`, `0xE5`,
`0xC5` or `0xD4`, and `0xE4` / `0xE5` are also valid QUIC long-header first
bytes. Obfuscated eMule packets begin with random bytes. So the first byte alone
decides nothing:

- **Long header** (first two bits `11`): QUIC only when bytes 1 to 4 are a
  version we speak (`0x00000001`, or `0` for version negotiation) and the
  connection-ID lengths that follow fit the datagram. A KAD packet would need
  opcode `0x00` followed by `00 00 01`. A random obfuscated packet matches about
  one time in 2^34.
- **Short header** (first two bits `01`): QUIC only when the destination
  connection ID is one we issued. Plain KAD and eD2K never start in `0x40` to
  `0x7F`, so only obfuscated packets can land here. Two quinn settings make the
  test sound:
  - A custom `ConnectionIdGenerator` issues 16-byte IDs: 8 random bytes plus an
    8-byte keyed BLAKE3 tag. The classifier and `validate` both check the tag,
    so a random packet passes about one time in 2^64. quinn's own
    `HashedConnectionIdGenerator` is too thin for this, with a 5-byte FxHash tag
    and a 3-byte nonce.
  - `EndpointConfig::grease_quic_bit(false)`, so every QUIC packet we are sent
    keeps the fixed bit set.

A packet sent the wrong way costs only that packet. QUIC routed to
`handle_udp_packet` fails deobfuscation and is dropped. Obfuscated KAD routed to
quinn fails CID validation, so quinn neither answers it nor sends a stateless
reset. One known loss: a stateless reset sent to us looks random, reaches
`handle_udp_packet`, and is dropped, so such a connection ends by idle timeout
instead of at once.

**The quinn side.** `Endpoint::new_with_abstract_socket` with an
`AsyncUdpSocket` whose:

- `poll_recv` drains the QUIC channel;
- `try_send` calls `try_send_to` on the shared tokio socket;
- segment counts are 1.

This gives up GSO, GRO and ECN, which quinn-udp would otherwise enable. They
matter little at our rates. Do not create a `quinn_udp::UdpSocketState` on the
shared socket: on Linux it turns on GRO, which coalesces datagrams and breaks
the KAD reader.

**What changes around it:**

- `state.quic_port` becomes `udp_port`, and `advertised_quic_port` becomes
  `advertised_udp_port`: one socket, one NAT mapping, one STUN reading, one
  keep-alive. The separate QUIC STUN probe and its mapping keep-alive go away.
- UPnP already skips the QUIC mapping when `quic_port == udp_port`
  (`upnp.rs` `map_all`), and the Windows firewall already skips the dedicated
  QUIC rule (`dedicated_quic_udp_port`). The firewall call site passes
  `tcp_port` as the QUIC port and must pass the real one.
- Everything that advertises our QUIC port reads `advertised_quic_port`, so it
  follows with no wire change. That covers rendezvous registration, friend
  presence, punch records, relay attestations, attachment offers and the source
  record field.
- KAD's per-IP rate limiter and overhead statistics must count only what reaches
  `handle_udp_packet`, not QUIC bulk data. QUIC keeps its own admission limits
  (`QUIC_PENDING_PER_IP` and the rest) in the accept loop.

**Compatibility.** Peers dial whatever port we advertise, so 1.7.x peers reach a
shared-port node without change, and it reaches them the same way. The one gap
is a peer that guesses instead of reading an advertisement: an old relay dialling
a KAD-sourced target on its TCP port number. To cover it, keep a second endpoint
on the old port for one release. It uses the same server config and accept loop,
and opens no new firewall or UPnP mapping. Keep a hidden config switch that goes
back to the separate socket in case classification misbehaves in the field.

**Tests before shipping:**

- The classifier never calls obfuscated KAD or eD2K traffic (real captures plus
  fuzz) QUIC, and always recognises packets carrying our own CIDs.
- Loopback: two nodes on shared sockets carry KAD pings, Ember DHT traffic and a
  QUIC bulk stream at the same time, with no loss on the KAD side and QUIC
  throughput within reach of the separate-socket build.
- Interop with a 1.7.1 node in both directions: relay, punch and attachments.
- The motivating case: a single forwarded UDP port (a VPN such as ProtonVPN)
  reaching QUIC with no TCP fallback.

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

### Prune deletes on paged reloads of very large shares — done in 1.7.1

A share root over 100,000 files is walked in pages (`MAX_DISCOVERED_FILES` in
`sharing/indexer.rs`), and no page after the first may reconcile deletions.
`sharing/paged_cycle.rs` now follows each such root through one cursor cycle,
collecting what every page saw, and the page that finishes the folder removes
the rows indexed when the cycle began that no page found. Rows indexed during
the cycle are kept, paths found by filesystem-event rescans count as seen, and
a cycle that skips a stretch (a page out of sequence, a trimmed frontier) is
abandoned rather than trusted.

### "Share without subfolders" still walks the whole tree — done in 1.7.1

Discovery of a folder with an allowlist now walks only the allowlisted files
and folders and the folders that lead to them (`DiscoveryScope` in
`sharing/indexer.rs`), in every scan: startup, add, full reload and
filesystem events. Files never picked are not hashed or indexed, so they do not
show in the Library. A file unshared from a partial share goes onto the
folder's withheld list (`withheld_folder_files`), which discovery walks too, so
it stays in the Library as an unshared file just as in a folder shared whole;
sharing it again puts it back on the allowlist. Widening a partial share queues
a scan of what it newly offers.

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
