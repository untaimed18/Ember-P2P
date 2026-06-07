# Ember Survival Plan

This document captures two things:

1. **Inventory** — every Ember-specific capability that exists beyond
   the eMule-compatible eD2K/KAD baseline.
2. **Survival roadmap** — what would still need to be built for Ember
   to keep working if eD2K servers or the KAD network were ever
   permanently shut down.

---

## Part 1 — What Ember already does beyond eD2K and KAD

### Ember-exclusive networking

| Capability | Source | Status |
| --- | --- | --- |
| **EPX (Ember Peer Exchange v4)** — source-list and Ember-peer hint exchange between Ember peers over the eMule extended-protocol opcode `0xF0`. Carries AICH roots, UDP ports, and capability flags. | [`src-tauri/src/network/ember/mod.rs`](../src-tauri/src/network/ember/mod.rs) | Live |
| **LowID-to-LowID broker** — STUN-based NAT detection → QUIC hole-punch → peer relay → rendezvous WebSocket relay. | [`src-tauri/src/network/ember/broker.rs`](../src-tauri/src/network/ember/broker.rs) | Live |
| **Connection broker stats** — punch/relay attempts, successes, and failures tracked on the broker itself. | [`src-tauri/src/network/ember/broker.rs`](../src-tauri/src/network/ember/broker.rs) | Live |
| **Ember capability advertisement on KAD** — source publishes carry the `"ember"` tag (`EMBER_CAP_RELAY_PUNCH_V1`) so peers know which sources speak the relay/punch protocol. | [`src-tauri/src/network/kad/publish.rs`](../src-tauri/src/network/kad/publish.rs) | Live |
| **Ember-native Noise transport** — Noise IK/XX over UDP using X25519 + ChaCha20-Poly1305 + BLAKE2s. Feature-flagged via `ember_native_enabled`. | [`src-tauri/src/network/ember/transport.rs`](../src-tauri/src/network/ember/transport.rs) | Live (flagged) |
| **EmberControlMessage Ping/Pong** — minimal authenticated control protocol over the Noise transport. | [`src-tauri/src/network/ember/transport.rs`](../src-tauri/src/network/ember/transport.rs) | Live (flagged) |
| **KAD-distributed Noise pubkeys** — `EMBER_NOISE_PUB_TAG`. KAD source publishes carry the 32-byte X25519 key so other Ember peers can dial each other's native UDP without manual key exchange. | [`src-tauri/src/network/kad/publish.rs`](../src-tauri/src/network/kad/publish.rs) | Live |
| **Ember mesh peer cache** — `known_ember_peers` and `ember_noise_keys` in `NetworkState`, TTL-bounded and LRU-evicted. | [`src-tauri/src/network/mod.rs`](../src-tauri/src/network/mod.rs) | Live |

### Rendezvous service

| Capability | Source | Status |
| --- | --- | --- |
| **Rendezvous server** — Axum binary providing friend presence registration (SHA-256 hashed Friend IDs), NAT hole-punch coordination, and WebSocket relay fallback. | [`rendezvous-server/`](../rendezvous-server/) | Live |
| **Rendezvous client** — runs in every Ember client. | [`src-tauri/src/network/rendezvous.rs`](../src-tauri/src/network/rendezvous.rs) | Live |

### Friends system

| Capability | Source | Status |
| --- | --- | --- |
| **Friend ID = Ember Hash** — distinct 16-byte BLAKE3 hash, separate from eMule `user_hash`. | [`src-tauri/src/storage/identity.rs`](../src-tauri/src/storage/identity.rs) | Live |
| **Friend discovery via rendezvous** — sub-second lookup by Friend ID. | [`src-tauri/src/network/ed2k/friend_connect.rs`](../src-tauri/src/network/ed2k/friend_connect.rs) | Live |
| **Mutual friend requests** — accept/reject before chat/browse activate. | [`src-tauri/src/network/mod.rs`](../src-tauri/src/network/mod.rs) | Live |
| **Real-time online status** — `ember:friend-online` / `ember:friend-offline` events. | [`src-tauri/src/network/ed2k/friend_connect.rs`](../src-tauri/src/network/ed2k/friend_connect.rs) | Live |
| **Direct messaging** — chat persisted locally per friend. | [`src-tauri/src/network/ed2k/upload.rs`](../src-tauri/src/network/ed2k/upload.rs) | Live |
| **Remote file browsing** — friends can browse each other's shared library. | [`src-tauri/src/network/ed2k/upload.rs`](../src-tauri/src/network/ed2k/upload.rs) | Live |
| **Priority upload slots** — mutual friends get queue priority. | [`src-tauri/src/network/ed2k/upload.rs`](../src-tauri/src/network/ed2k/upload.rs) | Live |
| **Friend session encryption** — RC4 obfuscation on the friend TCP session. | [`src-tauri/src/network/ed2k/friend_connect.rs`](../src-tauri/src/network/ed2k/friend_connect.rs) | Live |

### Identity & cryptography

| Capability | Source | Status |
| --- | --- | --- |
| **Persistent ed25519 keypair** — for signing DHT records and challenge-response. | [`src-tauri/src/storage/identity.rs`](../src-tauri/src/storage/identity.rs) | Live |
| **Persistent X25519 Noise keypair** — for the Noise transport. | [`src-tauri/src/storage/identity.rs`](../src-tauri/src/storage/identity.rs) | Live |
| **Ember Hash binding** — `BLAKE3(ed25519_pub)[0..16] == ember_hash`. Prevents pubkey spoofing on every authenticated path. | [`src-tauri/src/network/ember/crypto.rs`](../src-tauri/src/network/ember/crypto.rs) | Live |
| **Ember authentication challenge-response** — fresh-nonce signature scheme separate from eMule SecIdent. | [`src-tauri/src/network/ed2k/ember_auth.rs`](../src-tauri/src/network/ed2k/ember_auth.rs) | Live |
| **Reputation tracker** — per-peer scoring based on success/failure events; persisted to `reputation.json`; consulted for ban decisions. | [`src-tauri/src/network/ember/reputation.rs`](../src-tauri/src/network/ember/reputation.rs) | Live |

### Partially wired

| Module | Source | Status |
| --- | --- | --- |
| **Ember-native DHT** — routing, store, search, publish, bootstrap, messages | [`src-tauri/src/network/ember/dht/`](../src-tauri/src/network/ember/dht/) | All of Phase 1 (slices 1–7, flagged) is live over the Noise transport: routing table, signed `PING`/`PONG`, single-hop `FIND_NODE`/`FOUND_NODE`, the iterative multi-hop lookup driver, signed `STORE`/`FIND_VALUE` (publish a keyword record on the k closest nodes; retrieve it via iterative `FIND_VALUE`, verifying ed25519 signatures on receive), the maintenance loop (bucket refresh + liveness-ping/evict + record republish), and persistent contacts (`nodes_ember.dat` saved periodically + on shutdown, reloaded at startup). The **cold-start rendezvous bootstrap is now wired too**: clients publish their Noise key on `/register` (DHT-on only), the server `/bootstrap` route serves a rotating pool, and a fresh node with no `nodes_ember.dat` fetches + seeds it then self-looks-up — so both warm *and* cold starts are KAD-free. What remains: a signed, load-weighted bootstrap pool, plus Phase 2 (multi-keyword search, real-file publishing). See [`ember-dht-slice.md`](./ember-dht-slice.md). |

### Scaffolded but not yet wired

| Module | Source | Lines |
| --- | --- | --- |
| **Ember-native chunk transfer** — BLAKE3 hash tree, 256 KiB chunk requests | [`src-tauri/src/network/ember/transfer.rs`](../src-tauri/src/network/ember/transfer.rs) | ~430 |

### Observability & tooling

| Capability | Source | Status |
| --- | --- | --- |
| **`EmberDiagnostics`** — counters for EPX events, broker outcomes, native-transport sessions, ping/pong success, mesh-peer cache size, local Noise pubkey, DHT node ID / Ed25519 key / contact count / DHT ping-pong / find-node counters, the active-search gauge, the slice-5 store gauges/counters (stored keys & records, stores received, find-values received, active publishes), and the slice-6 maintenance counters (bucket refreshes, liveness pings sent, contacts evicted, records republished). Surfaced via `get_ember_diagnostics`. | [`src-tauri/src/types.rs`](../src-tauri/src/types.rs), [`src-tauri/src/commands/peers.rs`](../src-tauri/src/commands/peers.rs) | Live |
| **Dev panel** at `/dev/ember` — live diagnostics, copy-pubkey button, control + DHT ping forms, single-hop `FIND_NODE` form and iterative multi-hop lookup form (both with returned-contacts view), `STORE` (publish keyword record) and `FIND_VALUE` (find value) forms, a **Run maintenance** button (force a slice-6 cycle), DHT routing-table view, manual "seed contact" form, port-mismatch warning. | [`src/routes/dev/ember/+page.svelte`](../src/routes/dev/ember/+page.svelte) | Live |
| **Local multi-node harness** — `EMBER_DATA_DIR` override + single-instance gating + harness PowerShell script. | [`scripts/harness.ps1`](../scripts/harness.ps1), [`src-tauri/src/storage/paths.rs`](../src-tauri/src/storage/paths.rs) | Live |
| **`harness` cargo feature** — enables Tauri devtools in release builds for harness use only. | [`src-tauri/Cargo.toml`](../src-tauri/Cargo.toml) | Live |

### Modern client-shell features

These set Ember apart from eMule even before any new networking work:

- Tauri v2 + SvelteKit + Svelte 5 desktop shell. ~15 MB installed,
  no bundled browser.
- First-time setup wizard, dark-mode-first UI, keyboard shortcuts.
- Real-time transfer monitoring (virtual-scrolling tables, per-source
  detail drawers, archive recovery).
- Inline search spam detection (multi-signal scoring with
  relaxed/balanced/aggressive profiles).
- Anti-leech client filter (pattern-based, editable).
- GeoIP integration (MaxMind dbip-country-lite) for per-source flags.
- Bandwidth limiter with adaptive Upload Speed Sense (RTT-based).

---

## Part 2 — What's left for Ember to survive without eD2K or KAD

The Ember-compatible features above are valuable but are **layered on
top of** the eMule eD2K/KAD network for the actual peer discovery and
search. If eMule's networks were ever shut down, the following gaps
would have to be closed for Ember to continue functioning as a
standalone P2P file-sharing network.

### What still works without eD2K and KAD

- **Peer-to-peer file transfer** — the eD2K client-to-client protocol
  works peer-to-peer with no server involvement. Two Ember peers who
  know each other's address can transfer files indefinitely.
- **EPX (source exchange between Ember peers)** — works peer-to-peer.
- **Friends system + rendezvous server** — completely independent.
- **LowID-to-LowID broker** — uses rendezvous, not KAD.
- **Identity, signing, reputation, anti-leech, ipfilter** — all local.
- **Modern UI, transfers, bandwidth limits, statistics** — local.

So the floor is: a known set of Ember peers can already function as a
private file-sharing network without any external service except the
rendezvous server.

### What stops working without eD2K and KAD

| Capability | Today's source | Failure mode |
| --- | --- | --- |
| **Discovering new peers** | KAD routing table, KAD source publishes, eD2K servers | Nodes start with zero peers and have no way to find any. |
| **Searching for files by name** | KAD keyword publishes, eD2K server search | No way to find a file you don't already know the hash of. |
| **Finding sources for a known hash** | KAD source search, eD2K server `OP_GETSOURCES` | No way to find who has the file. |
| **Bootstrapping a new install** | `nodes.dat` (KAD) or `server.met` (eD2K) | Fresh installs have nothing to dial. |
| **NAT-traversal hints from the network** | KAD firewall checks, eD2K LowID server-relay | Falls back to rendezvous + broker only (already mostly fine). |

### Survival roadmap, in dependency order

The Ember-native DHT (already scaffolded under
[`src-tauri/src/network/ember/dht/`](../src-tauri/src/network/ember/dht/))
is the central piece. Once it functions, Ember can replace every KAD
and eD2K network function the client depends on today.

#### Phase 1 — Make the Ember DHT functional — **complete** (slices 1–7, flagged)

| # | Slice | Replaces | Status |
| --- | --- | --- | --- |
| 1 | Spawn `RoutingTable` in `NetworkState`. Surface contacts in the dev panel. Add a manual "Add Ember Contact" command for harness work. | KAD routing table | **Done** ([slice doc](./ember-dht-slice.md)) |
| 2 | Wire DHT message dispatch through `EmberTransport`. Implement DHT-level `PING` → `PONG` to populate the routing table on incoming traffic. | KAD `KADEMLIA2_PING` / `PONG` | **Done** ([slice doc](./ember-dht-slice.md)) |
| 3 | Implement `FIND_NODE` → `FOUND_NODES`: receivers return their k closest contacts to a target ID. Single-hop "Find node" dev-panel trigger. | KAD `KADEMLIA2_REQ` | **Done** ([slice doc](./ember-dht-slice.md)) |
| 4 | Iterative-lookup driver in `search.rs::SearchManager`: loop the slice-3 `FIND_NODE` across the closest returned contacts for multi-hop discovery via intermediate peers. | KAD search engine | **Done** ([slice doc](./ember-dht-slice.md)) |
| 5 | `STORE` / `FIND_VALUE` for signed records. Verify ed25519 signatures on receive. | KAD source/keyword publishes | **Done** ([slice doc](./ember-dht-slice.md)) |
| 6 | Periodic timers — routing-table refresh (random target lookups), ping oldest contacts in each bucket, republish stored records on a schedule. | KAD maintenance loop | **Done** ([slice doc](./ember-dht-slice.md)) |
| 7 | Persistent contacts — Ember `nodes.dat` equivalent saved on shutdown, loaded at startup. | KAD `nodes.dat` | **Done** ([slice doc](./ember-dht-slice.md)) |
| 7+ | Cold-start rendezvous bootstrap — clients publish their Noise key on `/register` (DHT-on only); the server `/bootstrap` route serves a rotating pool; a fresh node (no `nodes_ember.dat`) fetches + seeds it, then self-looks-up. | KAD-fed Noise keys for first contact | **Done** ([slice doc](./ember-dht-slice.md)) |

After phase 1, two Ember peers who know one common third peer can
discover each other automatically and exchange signed records. With
persistent contacts (slice 7) a node rejoins the DHT after a restart on
its own; the cold-start rendezvous bootstrap (slice 7+) lets even a
brand-new install find its first peers without KAD; and the maintenance
loop (slice 6) keeps the table and stored records healthy as peers churn.
This is a working, self-sustaining DHT that bootstraps — warm or cold —
with no eD2K/KAD involvement.

#### Phase 2 — Replace eD2K search semantics

| # | Slice | Replaces |
| --- | --- | --- |
| 8 | **Keyword publish/find** on the Ember DHT. Hash each keyword, publish a signed record `(keyword_hash → file_hash)`. | KAD keyword publish, eD2K server search |
| 9 | **Source publish/find** on the Ember DHT. Hash the file, publish a signed record `(file_hash → (addr, noise_pub, capability_flags))`. | KAD source publish, eD2K server `OP_GETSOURCES` |
| 10 | UI integration — search results from the Ember DHT alongside (or instead of) KAD/eD2K results. | eMule search UX |

After phase 2, full search and source-discovery work entirely on the
Ember network.

#### Phase 3 — Bootstrap and network health

| # | Slice | Why |
| --- | --- | --- |
| 11 | **Hardcoded seed peers** — a small list of known-good Ember bootstrap addresses + pubkeys baked into the build (similar to eMule's hardcoded server list). Updateable via a signed manifest. | New installs with zero prior peers need to start somewhere. |
| 12 | **Optional DNS seed list** — `_ember._udp.<domain>` SRV records pointing at a rotating set of bootstrap nodes. Falls back to hardcoded seeds. | Lets the seed list be updated without client releases. |
| 13 | **KAD-bridge bootstrap** — for as long as KAD still exists, use the existing `EMBER_NOISE_PUB_TAG` distribution to learn Ember peers from the eMule network. Already partially in place. | Free, smooth migration during the transition. |
| 14 | **Spam / flood protection** — per-IP rate limits on DHT messages, malformed-message rejection, signature replay protection. | The DHT will be hostile-Internet-facing. |
| 15 | **DHT-level firewall awareness** — detect when our own UDP is unreachable; surface to the user; consider a "buddy"-equivalent (could reuse the existing rendezvous server). | Firewalled peers can't host DHT records otherwise. |

#### Phase 4 — Polish and parity

| # | Slice | Why |
| --- | --- | --- |
| 16 | **Diagnostic UI** for the Ember DHT mirroring `/kad-network` (contact list, in-flight searches, store counts). | Day-to-day operability and debugging. |
| 17 | **Statistics counters** (rounds, hits, misses, store success, replication factor) in `EmberDiagnostics`. | Observability for hardening. |
| 18 | **Hash format decision** — keep ed2k MD4 for backward compatibility with existing `.met` files and collections, OR migrate to BLAKE3. Pragmatic answer: keep MD4 as the file identifier and add BLAKE3 alongside as a stronger integrity check. | Backward compatibility with users' existing libraries. |
| 19 | **Long-tail hardening** — fuzzing, malformed-message survival, version negotiation, observed-IP voting. | Match KAD's robustness over time. |

### What does *not* need replacing

- **Peer-to-peer transfer protocol** stays as-is (eD2K c2c is just a
  wire format; it works peer-to-peer with no server).
- **AICH** (post-corruption recovery) stays as-is.
- **Friends + rendezvous** are already independent of eD2K/KAD.
- **LowID-to-LowID broker** is already independent of eD2K/KAD.
- **EPX** is already peer-to-peer.
- **All client-shell features** (UI, transfers, settings, identity)
  are already independent.

### Strategic notes

- **Phases 1 + 2 + 3 are the survival floor.** Without them, Ember
  cannot operate without eMule's networks. With them, it can.
- **Phase 4 is polish.** Ember can survive long-term without it, but
  it would feel rougher than KAD on day one.
- **Bootstrap is the long-term sustainability question.** The protocol
  can be perfect, but if no one is running an Ember bootstrap node,
  new installs have nothing to dial. The **rendezvous `/bootstrap` pool**
  (slice 7+) now covers cold start today — every DHT-on client we already
  run for friend presence doubles as a seed — and the KAD-bridge
  bootstrap (slice 13) is the transition crutch; hardcoded + DNS seeds
  (slices 11–12) remain the permanent, rendezvous-independent answer.
- **Migration story matters.** Today every Ember client is also an
  eMule KAD client. The transition to a self-sufficient network does
  not have to be all-or-nothing — Ember can run on both networks
  simultaneously for years, with the Ember DHT growing while the eMule
  networks remain available.

### Estimated effort

If slices stay the size we've been doing (each session ends with passing
tests and a verifiable dev-panel feature), phases 1 and 2 together are
roughly **9–10 focused sessions**. Phase 3 adds another 4–5. Phase 4 is
indefinite — it's the long tail of "what eMule learned over 20 years."

The shortest path to "Ember can technically survive without eD2K/KAD"
is roughly **13–15 sessions**. The shortest path to "Ember is genuinely
pleasant to use without eD2K/KAD" is significantly longer.
