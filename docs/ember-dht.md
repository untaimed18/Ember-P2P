# Ember DHT — remaining work and future improvements

Status: **protocol slices complete** and the overlay is **on by default**
(`ember_native_enabled`, with a one-shot migration for profiles created
before the default flipped). Keyword/source publish, iterative search,
join via the KAD rendezvous key, buddy `PROXY_STORE`, peer announce,
BLAKE3 integrity digests, network-size-adaptive abuse limits, and
diagnostics are live on `develop`.

Code: [`src-tauri/src/network/ember/dht/`](../src-tauri/src/network/ember/dht/).

---

## How a node joins

There is no central bootstrap and no shipped address list. A cold node
gets in through, in rough order of who arrives first:

1. **The KAD rendezvous key.** Ember nodes advertise themselves under one
   fixed KAD key as an ordinary source record carrying their Noise pubkey
   tag; a node with a near-empty table runs a plain source lookup there.
   Re-advertised every 5 hours (`EMBER_RENDEZVOUS_REPUBLISH_SECS`, matching
   KAD's source TTL) and only while the node is reachable and already
   publishing something, so a leecher never generates publish traffic
   purely to list itself. Lookups are spaced 10 minutes apart and stop
   once the table reaches one k-bucket.
2. **The KAD bridge.** Ember peers noticed in ordinary KAD traffic get
   DHT-pinged so their signed `PONG` folds them into the routing table.
   Capped at `EMBER_KAD_BRIDGE_MAX_PINGS` per maintenance cycle and quiet
   above `EMBER_KAD_BRIDGE_UNTIL_CONTACTS`.
3. **eD2K client-to-client sessions.** Peers that advertise the Ember
   capability bit over a normal eD2K transfer are cached with their UDP
   port and bridged too, via Noise_XX when no static key is known. This is
   the path for a client running with no KAD at all.
4. **DHT gossip** (`FOUND_NODE` / `PEER_LIST` / `ANNOUNCE_PEER`) and
   **`nodes_ember.dat`** (up to `EMBER_PERSIST_MAX_CONTACTS` = 200) once
   the node has been online before.

The rendezvous server is still used for *friend* NAT traversal and relay.
It has no role in DHT bootstrap: that pool, its endpoint, and the pinned
key it verified were deleted, because the server and client never agreed
on the envelope format and restoring it would have handed the operator an
identity-to-IP map of every participant.

---

## What's left

### 1. Ember-native transfers are dormant

[`network/ember/transfer.rs`](../src-tauri/src/network/ember/transfer.rs)
holds the 256 KiB chunk protocol and the BLAKE3 hash tree, but nothing
imports it — there is no reference to `ember::transfer::` anywhere in the
tree. Ember discovers the source; the bytes still move over eD2K
client-to-client. Wiring it up is the largest remaining piece if the goal
is a network that does not need the eMule wire at all.

### 2. Wire versioning rejects cleanly but cannot negotiate

The last wire change touched five places (control version, batched store and
its ack, contact-list trimming, payload limits), so `EMBER_DHT_VERSION` is now
**2** and `EMBER_DHT_MIN_VERSION` is 2 alongside it: the decoder accepts a
*range*, and a frame outside it is refused at the version byte instead of
becoming a malformed-frame counter that reads like packet loss. A change that
only adds to the format can lower the minimum rather than raising both.

What is still missing is the part that needs a decision. Two peers on
incompatible versions now fail cleanly, but neither is told why and there is no
upgrade prompt — they simply never fold each other into a routing table. That
was tolerable while the overlay shipped off by default; it now ships **on**, so
the next breaking change reaches users who will not all update at once.

### 3. Cold join when eMule is not available

Every path in the list above except `nodes_ember.dat` presupposes either a
live KAD connection or an eD2K transfer with an Ember-capable peer. A
first-run user with KAD off and no servers has no way in, and seed lists
are deliberately not planned. Either accept and document that Ember rides
eMule's bootstrap, or add a path that does not.

### 4. Validation past the happy path

Search → download over a live network is confirmed working. Still
unexercised end to end:

- LowID / firewalled publishing through buddy `PROXY_STORE`.
- A cold join from an empty contact file with no KAD.
- Republish behaviour across a full record TTL on a large library.

For a local two-node test where neither side can reach KAD, the dev
*commands* remain even though the dev page is gone —
`add_ember_dht_contact` is the only way to introduce two nodes directly,
alongside `ember_dht_ping_peer`, `ember_dht_find_node`,
`ember_dht_iterative_find_node`, `ember_dht_publish_keyword`,
`ember_dht_find_value`, and `ember_dht_run_maintenance`.

---

## Known limits (document for users / release notes)

- Multi-keyword search uses sparse DHT intersection (missing secondary
  keys are skipped) plus a filename match at emit time — not a strict
  worldwide AND of every keyword key.
- Gossip contacts are unverified until the node hears from them directly
  (same as Kademlia). Admission is bounded by the diversity caps in
  [`scale.rs`](../src-tauri/src/network/ember/dht/scale.rs), but there is
  no reputation scoring on gossip itself.
- Download content transfer is still eD2K c2c (see item 1 above).
- BLAKE3 verify runs when an expected digest is available (search hit, DHT
  source record, known.met / library). Deep links without a digest still
  complete and hash for future share.

---

## Future improvements

Ordered roughly by leverage. None block a release if the items above are
settled.

### Bootstrap and network health

- Monitoring for rendezvous-key health: how many nodes are listed, how
  often a cold lookup returns nothing.
- Stronger observed-IP / STUN interplay under awkward NATs (needs soak
  data).
- Shard the rendezvous key space. The derivation is already versioned for
  this; it matters once one KAD bucket's 1000-entry cap is in sight.
- Table quality: tune announce versus bucket-refresh balance under load.

### Search and publish

- Richer keyword indexing (stemming, more than space-split tokens) if
  recall lags KAD on real libraries.
- Clearer search UI when Ember is joining (empty table) versus
  enabled-but-quiet.
- Storer-side replication telemetry. The publish side now logs an
  `Ember publish cycle` heartbeat each minute — due, selected, awaiting
  placement, queued, in flight, sent, held over, dropped, acked, failed — which
  is what says whether selected work is reaching the wire. There is no
  equivalent view of what this node is republishing on others' behalf.

### Integrity and downloads

- Surface BLAKE3 verify pass/fail in the transfer UI.
- Seed `emberFileHash` from more UI entry points when the digest is
  already known.

### Hardening and ops

- Longer fuzz / property tests in CI; overnight soak jobs.
- Score gossip to limit table poisoning under Sybil pressure, beyond the
  per-IP and per-subnet admission caps.

### Product / UX

- Migration guidance when turning the DHT on alongside existing KAD/eD2K.

### Explicitly not planned

- Hardcoded `seeds.txt` or DNS SRV seed lists — join stays the KAD
  rendezvous key, the bridges, gossip, and the persisted contact file.
- A rendezvous-hosted bootstrap pool. It leaks an identity-to-IP roster of
  every participant to whoever runs the server.

---

## Quick reference

| Area | Location |
| --- | --- |
| DHT engine / wire | `src-tauri/src/network/ember/dht/` |
| Network loop / publish / search drivers | `src-tauri/src/network/mod.rs` |
| Adaptive abuse limits | `src-tauri/src/network/ember/dht/scale.rs` |
| Dormant native transfer | `src-tauri/src/network/ember/transfer.rs` |
| Settings toggle | Settings → Network (`ember_native_enabled`, on by default) |
| User-facing status | `/ember` (Ember Network page) |
| Library publish badges | `shared_ember` on `FileInfo` → Library "Shared" column |

Protocol constants live in
[`dht/mod.rs`](../src-tauri/src/network/ember/dht/mod.rs): 128-bit node IDs
(BLAKE3 of the Ed25519 public key), k = 20, α = 5, 20 contacts per
response.
