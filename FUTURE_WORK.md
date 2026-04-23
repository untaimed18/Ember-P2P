# Future Work

## Friends System

### F2 — Ember Hash Authentication (Protocol Change)
**Priority:** HIGH (security) | **Effort:** Large
**Status:** DONE across every code path that can grant trust —
friend-connect dial, upload dispatcher, multi-source download,
and single-source download all run full Ed25519 proof of
possession. Privilege-bearing friend opcodes (chat, browse,
keepalive) are gated on PoP verification on both the upload
and download sides.

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

- **`multi_source.rs`** (download side): runs both the offline
  `verify_ember_hash_binding` check AND full Ed25519 PoP via
  `friend_connect::perform_ember_auth_buffered`. The buffered
  variant defers any non-AUTH packets it reads (notably
  `OP_SECIDENTSTATE` / EPX frames that the uploader sends
  proactively after its OP_EMBER_HELLO) into a per-session
  FIFO; the pre-control and file-status-wait loops drain that
  FIFO before reading fresh bytes from the stream, so SecIdent
  credit accounting and EPX source-injection still work for
  Ember-to-Ember downloads. `DownloadEvent::EmberFriendRequest.verified`
  now carries `ember_auth_verified || ember_hash_binding_verified`
  so the Friends UI can distinguish PoP-backed verification
  from the binding-only fallback (older Ember peers that
  haven't yet shipped the AUTH opcodes). The privilege-bearing
  friend opcodes in the runtime loop (`OP_EMBER_CHAT_MSG`,
  `OP_EMBER_BROWSE_RES`) additionally require
  `ember_auth_verified` so a peer that merely claims a
  friend's hash cannot pose as the friend.

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

  Privilege-bearing friend opcodes (`OP_EMBER_CHAT_MSG`,
  `OP_EMBER_BROWSE_REQ`, `OP_EMBER_BROWSE_RES`,
  `OP_EMBER_KEEPALIVE`) are gated on
  `is_ember_friend && ember_auth_state.is_verified()` in the
  match arm — not just on `is_ember_friend`. Without that
  extra clause a peer who had harvested our friend's
  `ember_hash` from KAD / EPX / trackers could ride the
  friend's identity on an ordinary upload session (inject
  chat rendered as from-the-friend in the Friends UI,
  silently hold the friend's ember slot via keepalives,
  etc.). Requiring a fresh-nonce signature per session
  closes that window — only the friend's Ed25519 secret key
  can produce the signature we check.

**End-to-end signal.** Verified state is persisted in the
`friend_requests.verified` column (DB v14 migration with monotonic
`MAX(verified, excluded.verified)` upsert so a spoofer flooding
unverified requests cannot downgrade an already-verified row),
surfaced in `FriendRequestInfo.verified`, and rendered as a
Verified / Unverified badge on the Friends page.

**Phase 1 follow-ups — all completed.**

- **Multi-source download path PoP** — DONE.
  `perform_ember_auth_buffered` lives in `friend_connect.rs`
  and is invoked from both the pre-control loop and the
  file-status-wait loop in `multi_source.rs`. Captured
  non-AUTH packets are drained back into the normal dispatch
  match arms so SecIdent credit and EPX source-injection are
  unaffected.

- **Single-source `transfer.rs` download** — DONE.
  `transfer.rs` now mirrors `multi_source.rs`: parses
  `OP_EMBER_HELLO(ANSWER)`, runs the offline binding check,
  and then runs the buffered PoP in both the pre-control and
  file-status-wait phases. The `EmberFriendRequest.verified`
  field now reflects `ember_auth_verified || ember_hash_binding_verified`
  instead of the old binding-only signal, and the
  data-loop `OP_EMBER_CHAT_MSG` arm requires PoP.

- **Friend-slot privileges** — DONE. The upload-side
  dispatcher already gates queue insertion and scoring on
  `is_verified_friend = is_friend && ember_auth_state.is_verified()`,
  and the four privilege-bearing Ember friend opcodes
  (CHAT_MSG, BROWSE_REQ, BROWSE_RES, KEEPALIVE) are now
  gated the same way in both `upload.rs` and
  `multi_source.rs` runtime loops.

### U4 — Pass Friend as Download Source in Browse Dialog
**Priority:** MEDIUM (performance) | **Effort:** Small
**Status:** DONE

`BrowseFriendDialog` now receives `friendLastIp`/`friendLastPort` from the friends page and calls `startDownload()` (the real `start_download` command) with the friend as the initial source.
