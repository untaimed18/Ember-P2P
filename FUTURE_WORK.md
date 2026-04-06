# Future Work

## Friends System

### F2 — Ember Hash Authentication (Protocol Change)
**Priority:** HIGH (security) | **Effort:** Large
**Status:** Deferred — requires protocol-level redesign

The `ember_hash` used to identify friends is entirely self-reported during the EmuleInfo handshake. There is no cryptographic proof of ownership. An attacker who knows a target friend's ember_hash can impersonate them — receiving chat messages, browsing shared files, and having their messages attributed to the real friend.

**Fix:** Add a challenge-response authentication step after EmuleInfo exchange. The remote must sign a random nonce with a private key corresponding to their claimed `ember_hash`. The hash should be derived from the public key (e.g., `ember_hash = truncated_hash(public_key)`). This is a protocol-breaking change that requires coordination between Ember versions.

### U4 — Pass Friend as Download Source in Browse Dialog
**Priority:** MEDIUM (performance) | **Effort:** Small
**Status:** Deferred — needs backend source format investigation

When downloading a file from a friend's browse list in `BrowseFriendDialog.svelte`, the `start_download_from_search` call passes `sources: []`. The friend who owns the file isn't included as a source, forcing re-discovery on the network. The fix requires understanding the exact `Source` struct shape expected by the backend and passing the friend's connection info as a source.
