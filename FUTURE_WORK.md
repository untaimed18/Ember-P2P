# Future Work

## Friends System

### F2 — Ember Hash Authentication (Protocol Change)
**Priority:** HIGH (security) | **Effort:** Large
**Status:** DONE on the security-critical paths; one
gap remaining on the multi-source download read loop (see
"Remaining gaps" below).

Ember Ed25519 identity authentication is wired into the two TCP
code paths that actually grant trust: friend-connect dials
(which fire when the user accepts a friend request) get full
proof of possession, and regular upload sessions accept inbound
PoP from any peer that initiates it.

**Wire protocol.** Peers advertise their 32-byte Ed25519 public
key in `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` (private opcodes
0xF8/0xF9; vanilla eMule ignores them). After `OP_EMBER_HELLO`
exchange, peers run a challenge-response over `OP_EMBER_AUTH_CHALLENGE`
(0xF6) and `OP_EMBER_AUTH_RESPONSE` (0xF7): each side sends a
fresh 32-byte random nonce, then signs the *other* side's nonce
with their Ed25519 secret key and returns `pubkey || signature`
(96 bytes). The receiver verifies the embedded pubkey matches
the advertised one, that `BLAKE3(pubkey)[0..16] ==
advertised_ember_hash`, and that the signature decodes against
their own nonce.

**Code paths.**

- **`friend_connect.rs`** (`connect_and_send_friend_request` and
  `open_friend_session`): both functions now call
  `exchange_ember_hello` synchronously right after the EmuleInfo
  round-trip; that populates `hello_caps.ember_pubkey` so the
  existing `perform_ember_auth` call actually runs. This also
  fixed a pre-existing bug where the `is_ember` bail at the top
  of these functions always fired (because the public Hello /
  EmuleInfo no longer signal Ember-ness), making the whole
  friend-connect path silently broken.

- **`multi_source.rs`** (download side): runs the offline
  `verify_ember_hash_binding` check only. Inline
  `perform_ember_auth` was tried and reverted because the
  uploader sends OP_SECIDENTSTATE (and optionally EPX)
  proactively immediately after its OP_EMBER_HELLO — those
  packets queue ahead of the uploader's CHALLENGE response,
  and `perform_ember_auth`'s synchronous read would consume +
  discard them with a wrong-opcode error, breaking SecIdent
  credit accounting on every download session. The binding
  check still rejects hash-only spoofers; the `verified`
  flag is threaded into every `DownloadEvent::EmberFriendRequest`.

- **`upload.rs`** (responder side): cannot run a synchronous
  `perform_ember_auth` from the dispatcher because its reader is
  owned by a dedicated `reader_task`. Instead the dispatcher
  hosts a small reactive state machine
  (`ed2k::ember_auth::EmberAuthState` with full unit-test
  coverage) that handles inbound `OP_EMBER_AUTH_CHALLENGE` and
  `OP_EMBER_AUTH_RESPONSE`. On CHALLENGE: generates a nonce,
  emits both our CHALLENGE and our RESPONSE in sequence (TCP
  preserves order so the initiator reads them correctly). On
  RESPONSE: verifies pubkey, binding, and signature; transitions
  to `Verified` or `Failed`. Replay attempts (second CHALLENGE
  in `Verified`, second RESPONSE, etc.) are rejected and never
  downgrade an already-Verified state.

**End-to-end signal.** Verified state is persisted in the
`friend_requests.verified` column (DB v14 migration with monotonic
`MAX(verified, excluded.verified)` upsert so a spoofer flooding
unverified requests cannot downgrade an already-verified row),
surfaced in `FriendRequestInfo.verified`, and rendered as a
Verified / Unverified badge on the Friends page.

**Remaining gaps (intentional, scoped follow-ups).**

- **Multi-source download path PoP.** Closing this requires a
  packet-buffering wrapper around `perform_ember_auth` that
  defers any non-AUTH opcode it reads (notably
  OP_SECIDENTSTATE) back into the main dispatch loop instead
  of dropping it. With that wrapper, the inline call in
  `multi_source.rs`'s OP_EMBER_HELLO handlers would be safe.
  The keys (`ed25519_public_key` + `_ed25519_secret_key`) are
  already plumbed onto `MultiSourceDownload` and through
  `download_parts_from_source` for that purpose.

- **Single-source `transfer.rs` download.** Doesn't parse
  `OP_EMBER_HELLO` at all today, so `EmberFriendRequest` emits
  from that path always carry `verified: false`. Mirror the
  OP_EMBER_HELLO parsing block from `multi_source.rs`;
  `Ed2kDownload` already carries the keys.

- **Friend-slot priority** (`upload.rs::is_friend`): currently
  gated on `friend_hashes` membership only, which is set after
  the user accepts a request. Accept triggers
  `friend_connect::open_and_run_friend_session`, which DOES
  run full PoP on the dial-back — so spoofers who pass the
  initial offline binding check still hit the cryptographic
  wall when their session opens. Tightening upload's
  is_friend check to *also* require `ember_auth_state.is_verified()`
  (i.e. PoP on the same TCP session, not a side-channel
  session) would close the residual window where a spoofer
  could ride the friend's hash on a regular upload session.

### U4 — Pass Friend as Download Source in Browse Dialog
**Priority:** MEDIUM (performance) | **Effort:** Small
**Status:** DONE

`BrowseFriendDialog` now receives `friendLastIp`/`friendLastPort` from the friends page and calls `startDownload()` (the real `start_download` command) with the friend as the initial source.
