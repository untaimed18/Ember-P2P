# Plan: chat attachments for friends reachable only through a relay

Status: proposed. Nothing here is implemented yet.

## Where things stand

A chat attachment's bytes move over a **direct QUIC connection** from the
recipient to the sender. The friend session only carries the offer, the reply
and a cancel. The recipient dials the IP the friend session came from and the
port the offer named, and the connection is authorized three ways:

1. the sender's QUIC certificate is pinned to the friend's identity;
2. the grant row (`chat_attachments`) is looked up by transfer id **and**
   friend;
3. the stream request carries a capability tag derived from both identity
   keys.

A friend session can instead run through a relay:

- the **rendezvous server's WebSocket relay** (`FallbackTransport::Relay` in
  `friend_connect.rs`, the responder side in `network/mod.rs`); or
- an **Ember peer relay** (`RELAY_REQUEST` / `RELAY_CONNECT` in
  `ember/relay.rs`), today used for LowID eD2K transfers.

Such a session has no direct address. Since this change, `EmberSessionHandle`
records that (`is_relayed()`). `chat_attach::offer_preflight` refuses to offer a
file over one, before the file picker opens, with `peers_attach_relayed`. A
receive that never connects ends as `unreachable` on both sides rather than a
bare "Transfer failed".

What's left is making these transfers actually work.

## What any relay path has to keep

- **End-to-end identity.** Through a relay, the QUIC certificate belongs to
  the relay, so check 1 above no longer names the friend. The stream has to
  authenticate the friend itself before any grant lookup. The friend
  session's Noise IK handshake (`secure_stream::initiate` / `accept`) already
  does this over arbitrary `AsyncRead`/`AsyncWrite` halves and is the obvious
  reuse.
- **Confidentiality from the relay.** The relay must only ever see ciphertext.
  Noise gives this for free.
- **The same grant and tag checks.** They move unchanged to run after the
  handshake.
- **Chunk verification and resume.** These already hold over any transport.
  `serve_attachment` and `fetch_attachment` are generic over the stream, and
  every chunk is checked against the offered BLAKE3 root, so a relay cannot
  corrupt a file silently. It can only stall it.

## Options

### A. Coordinated hole punch for the attachment itself (cheap, do first)

The attachment now relies on a simultaneous dial: the sender's `spawn_punch`
races the recipient's dial. Friend sessions already use a stronger
rendezvous-coordinated punch (`punch_from_register` / `poll_punch` /
`ack_punch`). Running that for the attachment's QUIC connection would recover
the cases where:

- the session went through the relay only because the relay won the race; or
- the punch wasn't attempted for the session (for example, the external
  address was unknown at the time).

It doesn't help a symmetric NAT on either side.

- **Touches:**
  - `chat_attach.rs`: `accept_offer`, `receive_with_retries` and
    `spawn_punch`.
  - `friend_connect.rs`: the punch helpers, factored out.
- **Wire:** none. The punch is coordinated through the rendezvous server.
- **Cost:** small. No new servers, no new trust.

### B. Ember peer relay with Noise IK inside (the real fix)

Open a peer-relayed QUIC stream to the sender, the same way LowID eD2K
transfers already do, and run Noise IK over it, then the attachment protocol
inside that.

- **Receiving side:**
  - After direct attempts fail, `receive_with_retries` picks a relay from the
    friend's relay offers. These are already exchanged:
    `UploadEventKind::EmberRelayOffer`.
  - It sends `RELAY_REQUEST`, runs `secure_stream::initiate` pinned to the
    friend, then `fetch_attachment`.
- **Sending side:**
  - `run_quic_accept_loop`'s `RELAY_CONNECT` branch today hands every stream
    to the eD2K upload listener. It needs to tell an attachment stream apart,
    for example by a first byte after the relay header, as the direct path
    does with `ATTACH_STREAM_MSG_TYPE`.
  - It then runs `secure_stream::accept` and `serve_attachment`.
  - The grant lookup keys on the friend identity Noise proved, instead of the
    QUIC certificate.
- **Preflight:** `offer_preflight` allows a relayed session when at least one
  relay offer from that friend is known.
- **Limits:**
  - Relays are volunteers with finite capacity, so cap what a relayed transfer
    may use: a per-transfer size limit (for example 256 MB) and the relay's
    existing rate limit.
  - Say so in the UI when a file goes over a relay.
- **Wire:** a new first byte on relayed streams. The attachment protocol
  hasn't shipped (it arrived during 1.7.0), so this is free to change before
  release.

### C. Rendezvous WebSocket relay (last resort; needs an operator decision)

Offer a dedicated relay ticket for the transfer, not multiplexed onto the chat
session, and run Noise IK plus the attachment protocol over it. It works
whenever the friend session itself works, but **every byte goes through the
rendezvous server**, up to 2 GiB per file.

- It needs server-side caps: a per-ticket byte limit, a rate limit, and a
  concurrency limit per identity.
- It needs the server operator to accept the bandwidth cost.
- If it's done at all, it should cap the size well below the direct-path
  limit.

## Recommended order

1. **A:** a coordinated punch for attachments. Small, and helps immediately.
2. **B:** a peer relay with Noise IK, behind a relayed-size cap.
3. **C:** only if B leaves too many friends unserved, and only with server
   caps agreed.

## Decisions needed

- The size cap for relayed transfers, if any, and whether it differs between
  B and C.
- Whether the rendezvous server may carry attachment bytes at all (C).
- Whether a relayed transfer should need an explicit click even under the
  auto-accept ceiling, since it spends someone else's bandwidth.

## Testing

- **Multi-node harness:** one node behind a simulated symmetric NAT, so only
  the relay connects. Check that the transfer completes, resumes after the
  relay drops mid-file, and that a tampered relay (flipped bytes) is caught by
  chunk verification.
- **Relay confidentiality:** confirm the relay never sees plaintext, by
  checking that Noise is established before the first attachment byte.
- **Authorization:** a relayed stream from a non-friend, or from a friend
  without a grant, is refused exactly as on the direct path.
