# Future Work

## Friends System

### F2 — Ember Hash Authentication (Protocol Change)
**Priority:** HIGH (security) | **Effort:** Large
**Status:** DONE

Implemented Ed25519 challenge-response authentication for friend sessions. After EmuleInfo exchange, both peers exchange `OP_EMBER_AUTH_CHALLENGE` (32-byte nonce) and `OP_EMBER_AUTH_RESPONSE` (pubkey + signature). Verification confirms `BLAKE3(pubkey)[0..16] == ember_hash` and the signature is valid. The Ed25519 public key is advertised via a new `ET_EMBER_PUBKEY` (0x57) blob tag in EmuleInfo. Authentication is enforced when both sides support it and skipped gracefully for legacy clients.

### U4 — Pass Friend as Download Source in Browse Dialog
**Priority:** MEDIUM (performance) | **Effort:** Small
**Status:** DONE

`BrowseFriendDialog` now receives `friendLastIp`/`friendLastPort` from the friends page and calls `startDownload()` (the real `start_download` command) with the friend as the initial source.
