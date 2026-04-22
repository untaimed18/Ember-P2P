# Future Work

## Friends System

### F2 — Ember Hash Authentication (Protocol Change)
**Priority:** HIGH (security) | **Effort:** Large
**Status:** PARTIAL — Phase 1 (binding check) done; Phase 2 (proof of possession) pending

**Phase 1 (DONE):** Peers now advertise their 32-byte Ed25519 public
key in `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` (private opcodes
0xF8/0xF9 — vanilla eMule ignores them). On both the upload side
(`upload.rs`) and the multi-source download side (`multi_source.rs`),
every receipt of an OP_EMBER_HELLO with a pubkey runs
`verify_ember_hash_binding`: `BLAKE3(pubkey)[0..16] ==
advertised_ember_hash`. The result is cached in a session-scoped
`ember_hash_binding_verified` flag and threaded into every
`EmberFriendRequest` event as `verified: bool`, then through the DB
(`friend_requests.verified` column) and into the Friends UI as a
"Verified" / "Unverified" badge. This rejects the trivial spoofing
case where an attacker claims a victim's `ember_hash` without also
having the victim's public key (since they cannot brute-force a
matching key in 2^128 time).

**Phase 2 (PENDING):** The full Ed25519 challenge-response (the
existing `friend_connect::perform_ember_auth` helper) is wired to
the friend-connect dial path but its guard is gated on
`hello_caps.ember_pubkey`, which `friend_connect.rs` doesn't
populate today because the dedicated friend-session handshake
doesn't exchange `OP_EMBER_HELLO`. Closing this requires:

  1. Add a synchronous `OP_EMBER_HELLO` exchange to
     `connect_and_send_friend_request` and `open_friend_session`
     after the EmuleInfo round-trip and before
     `perform_ember_auth`. Once `hello_caps.ember_pubkey` is
     populated, the existing call will fire and PoP will land for
     friend-connect dials.
  2. Build a reactive auth state machine in `upload.rs`'s main
     packet dispatcher that handles incoming
     `OP_EMBER_AUTH_CHALLENGE` / `OP_EMBER_AUTH_RESPONSE` (today
     these fall through to the default `_ => debug!("ignoring")`
     arm). The upload reader is owned by a dedicated `reader_task`
     so a synchronous `perform_ember_auth` call from the dispatcher
     site is not feasible — the state machine must be event-driven
     across multiple packet arrivals.
  3. Once #2 lands, add the inline `perform_ember_auth` call in
     `multi_source.rs`'s OP_EMBER_HELLO handler (it was tried in
     an earlier patch and reverted because the upload peer would
     never respond, causing a 10-second timeout per session and
     occasional packet loss when an unrelated packet arrived
     during the window).

The wire format and helper plumbing for Phase 2 are already in
place: `OP_EMBER_AUTH_CHALLENGE` (0xF6), `OP_EMBER_AUTH_RESPONSE`
(0xF7), `friend_connect::perform_ember_auth` (with `?Sized`
generic bounds so it can drive a `Box<dyn AsyncRead/Write>`), and
the secret key is plumbed through `MultiSourceDownload` to the
per-source loop as `_ed25519_secret_key`.

### U4 — Pass Friend as Download Source in Browse Dialog
**Priority:** MEDIUM (performance) | **Effort:** Small
**Status:** DONE

`BrowseFriendDialog` now receives `friendLastIp`/`friendLastPort` from the friends page and calls `startDownload()` (the real `start_download` command) with the friend as the initial source.
