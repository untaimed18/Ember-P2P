# Ember DHT — Phase 1, Slices 1–7

Status: **routing table live + DHT PING/PONG + single-hop FIND_NODE +
iterative multi-hop lookup + signed STORE / FIND_VALUE + maintenance loop
+ persistent contacts (`nodes_ember.dat`) + cold-start rendezvous
bootstrap over the Noise transport, behind the `ember_native_enabled`
flag.**

This is the first work that makes the scaffolded Ember DHT
([`src-tauri/src/network/ember/dht/`](../src-tauri/src/network/ember/dht/))
actually run inside a live node. It covers all seven slices of Phase 1 in
the [survival plan](./ember-survival-plan.md):

- **Slice 1** — spawn the Ember `RoutingTable` in `NetworkState`,
  surface it in the dev panel, and add a manual "add contact" command.
- **Slice 2** — route signed DHT frames through `EmberTransport` and
  answer `PING` with `PONG`, learning contacts from inbound traffic.
- **Slice 3** — answer `FIND_NODE` with the k closest contacts
  (`FOUND_NODE`), learn the returned contacts, and expose a single-hop
  "find node" dev trigger.
- **Slice 4** — drive an iterative, multi-hop lookup: loop `FIND_NODE`
  across the closest contacts learned until the search converges.
- **Slice 5** — `STORE` / `FIND_VALUE` for **signed records**: publish a
  keyword record onto the closest nodes (verifying the publisher's
  Ed25519 signature on receive), and retrieve it with an iterative
  `FIND_VALUE` that returns the records or hops toward a node that has
  them.
- **Slice 6** — a periodic **maintenance loop**: refresh stale buckets
  with random-target lookups, liveness-ping stale contacts (evicting the
  dead), and republish stored records so they survive node churn.
- **Slice 7** — **persistent contacts**: save the routing table to
  `nodes_ember.dat` and reload it at startup, so a node rejoins the DHT
  after a restart without depending on KAD — the last piece for
  demonstrable KAD-free operation.

It stays narrow, in the same spirit as the
[native-transport slice](./ember-native-transport-slice.md):

- Off by default (`AppSettings::ember_native_enabled = false`). With the
  flag off, Ember-magic packets are dropped before they reach the DHT.
- Toggled from the UI: **Settings → Network** has an "Ember Network" switch,
  and the dedicated **Ember Network** page (`/ember` in the sidebar) is a
  one-click power switch + live status read-out. Both drive
  `ember_native_enabled` through `update_settings`; the network loop applies
  the off→on transition live (it kicks the same cold bootstrap as startup, so
  enabling joins the DHT without a restart) and tears sessions down on
  disable. `config.json` still works for headless/harness nodes.
- No new sockets or ports — DHT frames ride the existing KAD UDP socket
  inside the Noise session, exactly like the control Ping/Pong.
- DHT frames are distinguished from the 10-byte control frame purely by
  length (a DHT frame's Ed25519 signature alone is 64 bytes), so no new
  wire discriminator was needed and the control path is untouched.

## What landed

### The DHT engine

- New [`dht::engine::EmberDht`](../src-tauri/src/network/ember/dht/engine.rs):
  owns our Ed25519 DHT identity, derives our 128-bit node ID
  (`BLAKE3(ed25519_pub)[..16]`, equal to the `ember_hash`), holds the
  Kademlia `RoutingTable`, and drives PING/PONG. It is IO-free and
  transport-agnostic, so the protocol logic is unit-tested without a
  socket or a `NetworkState`.
- `EmberDht::handle_message` decodes an inbound frame, **verifies the
  Ed25519 signature and the `sender_id == BLAKE3(pubkey)` binding**
  (so a peer cannot poison the table under a forged ID), learns the
  sender as a contact (with the Noise key taken from the live session),
  and dispatches by type:
  - `PING` → signed `PONG`.
  - `FIND_NODE { target }` → signed `FOUND_NODE` carrying the up-to-`k`
    contacts closest (XOR distance) to `target`, straight from the
    routing table.
  - `FOUND_NODE { contacts }` → merge every returned contact into the
    table (each unverified until pinged) and hand the list back to the
    caller via `DhtInbound::found_node` so a pending lookup can resolve.
  - `FOUND_NODE` additionally surfaces the verified `sender_id` so the
    lookup driver can correlate the answer to an in-flight query.
  - `STORE_RECORD { key, record, signature }` → parse + verify the
    publisher-signed record, enforce `key == record.keyword_hash` (so a
    publisher can't scatter a record under unrelated keys), insert it into
    the local store, and reply with a signed `STORE_ACK`. A record that
    fails to verify or whose key doesn't match its content is dropped with
    no ack.
  - `FIND_VALUE { keys }` → reply with `FOUND_VALUE` carrying the records
    for the first requested key we hold; otherwise fall back to
    `FOUND_NODE` with the closest contacts so the searcher keeps walking.
  - `STORE_ACK` / `FOUND_VALUE` surface their `request_id` (and, for
    `FOUND_VALUE`, the record blobs) so the publish / value-lookup drivers
    can correlate the answer.
- The engine now also owns a [`dht::store::DhtStore`](../src-tauri/src/network/ember/dht/store.rs):
  a signed key→records map (signature verified on every insert, per-key
  and total caps, 24 h TTL) that it serves to `FIND_VALUE` queries.
- `NetworkState` gains `ember_dht`, an `ember_dht_pending_pings` waiter
  map, and an `ember_dht_pending_finds` waiter map (all mirroring the
  control-ping plumbing), constructed at startup like `ember_transport`.

### Iterative lookup driver (slice 4)

The shortlist state machine already existed in
[`dht::search`](../src-tauri/src/network/ember/dht/search.rs)
(`SearchManager` / `IterativeSearch`: α-parallel `next_to_query`,
`process_response`, convergence). Slice 4 adds the **driver** that runs
it against the live network, entirely inside the network task:

- `NetworkState` gains `ember_search` (the `SearchManager`), an
  `ember_dht_search_requests` map (wire `request_id` → in-flight query),
  and an `ember_dht_pending_lookups` map (`search_id` → caller waiter).
- `drive_ember_search` pulls the next α-bounded batch, sends each contact
  a signed `FIND_NODE` over the Noise transport (dialing newly-learned
  nodes via their advertised Noise key), and records the wire requests.
- A `FOUND_NODE` whose `request_id` matches a search request is fed to
  `process_response` (gated on `(per_search_req_id, sender_id)` so a
  forged answer can't advance the search), then the next round is driven.
  Discovered contacts are merged into the routing table by the engine, so
  a lookup naturally broadens the table as it runs.
- A 1 s sweep (`ember_search_timer`) expires queries unanswered for more
  than `EMBER_SEARCH_QUERY_TIMEOUT` (5 s) so one dead hop can't stall a
  lookup, drives the affected searches, and reaps long-expired searches —
  failing their waiters so no Tauri command hangs.
- On convergence the driver resolves the waiter with the closest contacts
  that responded.

### Signed STORE / FIND_VALUE (slice 5)

The record machinery already existed in
[`dht::store`](../src-tauri/src/network/ember/dht/store.rs) (the verifying
key→records store) and
[`dht::publish`](../src-tauri/src/network/ember/dht/publish.rs)
(`SignedRecord` building/verification + a `PublishManager` that tracks
which of the k closest nodes have acked). Slice 5 adds the two **drivers**
that run them against the live network, mirroring the slice-4 lookup:

- **Publish.** `NetworkState` gains `ember_publish` (the `PublishManager`),
  an `ember_dht_publish_requests` map (wire `request_id` → in-flight
  store), and an `ember_dht_pending_publishes` map (`publish_id` → caller
  waiter). `drive_ember_publish` signs the record with our identity, picks
  the closest known contacts, sends each a `STORE_RECORD`, and resolves the
  waiter (with a stored-on / targets tally) once every target has acked,
  failed, or timed out.
- **Find value.** A `FIND_VALUE` lookup reuses the slice-4 search driver:
  the same `SearchManager` runs a `SearchType::FindValue` search, but
  `drive_ember_search` sends `FIND_VALUE` frames (keyed by the record key)
  instead of `FIND_NODE`. A `FOUND_VALUE` feeds the records into the
  search; a `FOUND_NODE` (peer has no record) advances it toward closer
  nodes. On convergence the value waiter
  (`ember_dht_pending_value_lookups`) resolves with the gathered record
  blobs.
- Each `FOUND_VALUE` blob is `record_data || 64-byte publisher signature`,
  so the command layer re-verifies every record's signature before
  surfacing it (the frame's own signature only proves who *relayed* it).
- The 1 s `ember_search_timer` now also sweeps stale publish stores (same
  5 s per-query timeout) and reaps long-expired publishes, and the 5 min
  store-maintenance tick expires aged records from `DhtStore`.

### Maintenance loop (slice 6)

A 60 s `ember_maintenance_timer` runs `run_ember_maintenance`, which does
the three classic Kademlia housekeeping jobs. Each is internally gated on
its own (much longer) staleness interval and bounded per cycle, so the
timer is cheap when nothing is due; it skips entirely when the transport
is off or the table is empty:

- **Bucket refresh.** `RoutingTable::buckets_for_refresh` picks the
  stalest non-empty buckets (idle > `EMBER_BUCKET_REFRESH_SECS`, 1 h);
  for each, `EmberDht::random_target_in_bucket` synthesises a random ID
  whose XOR distance from us has its leading bit exactly in that bucket,
  and the driver launches a normal iterative `FIND_NODE` for it. The
  search has no waiter — its side effect (learning contacts, marking the
  bucket active) is the point.
- **Liveness pings.** `EmberDht::contacts_due_for_ping` returns contacts
  not heard from in > `EMBER_CONTACT_PING_SECS` (10 min), stalest first.
  Each gets a DHT `PING` tracked in `ember_dht_maint_pings`. A `PONG`
  clears the entry (the inbound path already refreshed the contact); the
  1 s sweep faults any entry older than `EMBER_MAINT_PING_TIMEOUT` (8 s)
  via `mark_failed`, and once a contact has missed `MAX_FAILED_QUERIES`
  (3) in a row it is evicted (`evict_and_replace` promotes a replacement
  from the bucket's cache).
- **Republish.** `DhtStore::take_republish_batch` hands back records not
  re-pushed within `EMBER_RECORD_REPUBLISH_SECS` (1 h); each is rebuilt
  into a `SignedRecord` and re-`STORE`d on the *current* closest nodes via
  the slice-5 publish driver, so records survive churn as the closest-set
  changes (Kademlia replication). The publisher signature is preserved, so
  authorship is unchanged.

The on-demand `ember_dht_run_maintenance` command runs the same cycle with
`force = true`, bypassing the staleness gates so a refresh / ping /
republish can be observed immediately in the harness.

### Persistent contacts (slice 7)

The routing table is now persisted to `nodes_ember.dat` (the native
equivalent of KAD's `nodes.dat`), reusing the existing
[`dht::bootstrap`](../src-tauri/src/network/ember/dht/bootstrap.rs)
`save_nodes` / `load_nodes` (atomic write, magic/version header,
truncated-load backup):

- **At startup** the file is loaded and its contacts seeded into the
  routing table (unconditionally — cheap and in-memory; only used once the
  transport is enabled).
- **Periodically** the existing 5 min `nodes_save_timer` also writes the
  Ember table (skipped when empty so a zero-contact file never clobbers a
  populated one), and the same write runs **on graceful shutdown**.

This closes the warm-start bootstrap loop: a node that learned contacts in
one session rejoins the DHT on the next launch with no KAD involvement.

### Cold-start rendezvous bootstrap

Persistence only helps a node that has *already* joined once. A brand-new
install — or one whose `nodes_ember.dat` is missing/corrupt — still came up
with an empty table and, until now, leaned on KAD-fed Noise keys to find
its first DHT peer. This wires the long-noted follow-on so cold start is
KAD-free too, reusing the existing
[`bootstrap::fetch_bootstrap_nodes`](../src-tauri/src/network/ember/dht/bootstrap.rs)
probe and the rendezvous server we already run for friend presence.

- **Server `/bootstrap` pool.** The rendezvous `/bootstrap` route (a
  stub that returned `[]`) now serves a rotating sample of registered
  nodes. To populate it, `/register` accepts an **optional** `noise_pub`
  (the client's X25519 Noise static key); entries that carry one are
  bootstrap-eligible. The response is `[{ addr, noise_pub, ed25519_pub }]`
  — no `node_id`, because the client derives it.
- **Clients publish their Noise key.** `rendezvous::register` now sends
  `noise_pub`, but **only while `ember_native_enabled`** — a node with the
  DHT off never advertises a contact that can't be dialled. The key is
  deliberately *not* part of the signed registration message: a node only
  ever publishes its own key, and the DHT re-verifies every contact's
  Ed25519 binding on first PING, so an unsigned value can at worst yield an
  unreachable contact (the Noise handshake just fails) — it cannot poison a
  table.
- **`node_id` is derived, never trusted.** `BootstrapNode::to_contact`
  computes `node_id = BLAKE3(ed25519_pub)[..16]` itself (and rejects keys
  that aren't valid Ed25519 points), so a misbehaving rendezvous can't
  bucket a contact under a forged ID.
- **Cold-start fetch + self-lookup.** At startup, when the table came up
  empty *and* the transport is enabled *and* a rendezvous URL is
  configured, the network task spawns the `/bootstrap` fetch off the
  critical path and hands the parsed contacts back over a one-shot mpsc
  (`ember_boot_rx`) — so a 10 s HTTPS round trip never blocks the loop.
  Seeding the contacts then kicks a `FIND_NODE` for our own ID, the
  standard Kademlia self-lookup that fills the neighbourhood. Warm starts
  skip the whole path.

The trust anchor throughout is the DHT's own PING-time verification, so the
pool stays unsigned and best-effort; a signed, load-weighted pool can come
later without changing the client.

### Hardcoded seed peers (slice 11)

A second, rendezvous-independent cold-start source: a small list of
known-good bootstrap peers baked into the build, the Ember equivalent of
eMule's hardcoded server list.

- **Where it lives.** [`dht/seeds.txt`](../src-tauri/src/network/ember/dht/seeds.txt)
  — one peer per line, `host:port ed25519_pub_hex noise_pub_hex`,
  `#` comments and blank lines ignored — is embedded at compile time via
  `include_str!` in [`dht/seeds.rs`](../src-tauri/src/network/ember/dht/seeds.rs).
  Each line is parsed into a `BootstrapNode` and validated through the same
  `to_contact` path as a rendezvous node (so the node ID is derived from
  the Ed25519 key and re-verified on the first PING — a baked-in seed is no
  more trusted than any other contact).
- **How it's wired.** `maybe_spawn_ember_cold_bootstrap` now seeds the
  hardcoded peers first (no I/O, available even when the rendezvous URL is
  empty or down), then runs the `/bootstrap` fetch; both flow through the
  same `ember_boot_rx` seed-and-self-lookup arm. The helper no longer
  requires a rendezvous URL — hardcoded seeds alone are enough to start.
- **Ships empty.** The list is intentionally empty until long-lived Ember
  seed nodes are deployed; populating it is a one-line *data* change to
  `seeds.txt`. An `embedded_seeds_are_all_valid` test fails the build if a
  baked-in line is malformed, so a typo'd seed can never ship.

### KAD-bridge bootstrap (slice 13)

A third cold-start source that costs nothing while the eMule KAD network is
still up: every Ember client is also a KAD client, and KAD source publishes
already carry the publisher's Noise key (`EMBER_NOISE_PUB_TAG`), cached in
`ember_noise_keys` (`(ip, port) → noise_pub`). That cache previously only
fed `ember_ping_peer`; slice 13 folds it into the DHT.

- **Ping, don't insert.** A KAD entry has the peer's *Noise* key but not its
  *Ed25519* key — and the DHT node ID is `BLAKE3(ed25519_pub)`. So we can't
  synthesise a contact; instead the maintenance loop sends a DHT `PING` to
  `(addr, noise_pub)` and the peer's signed `PONG` carries the Ed25519 key,
  which the normal inbound path verifies and learns as a contact.
- **Only while sparse.** The bridge runs only while the table holds fewer
  than `EMBER_KAD_BRIDGE_UNTIL_CONTACTS` (one k-bucket) contacts, capped at
  `EMBER_KAD_BRIDGE_MAX_PINGS` per cycle. `kad_bridge_candidates` returns
  freshest-first peers not yet in `ember_kad_bridge_attempted`, so the bridge
  walks the whole cache (one ping per peer) and self-disables once the DHT is
  bootstrapped — steady-state KAD traffic never sprays DHT pings.
- **Empty-table tick.** The periodic maintenance gate now also fires when the
  table is empty but `ember_noise_keys` is non-empty, so the bridge can seed
  a brand-new table (the other maintenance steps no-op with zero contacts).
- **Observability.** `ember_dht_kad_bridge_pings` (diagnostics) and the
  `kad_bridge_pings_sent` field on the maintenance result / dev-panel "Run
  maintenance" output count the bridge pings.

### Transport plumbing

- `DispatchOutcome` now carries `app_payload` (a decrypted, non-control
  frame) and `remote_noise_pub` (the session's peer key). The native UDP
  handler routes `app_payload` into a new `handle_ember_dht_message`,
  which feeds the engine, encrypts any reply over the same session, and
  updates counters / resolves the pending PING and FIND_NODE waiters.
- A DHT `PING` can ride **Noise IK message 1**, so the very first packet
  to a new peer both completes the handshake and delivers the ping; the
  `PONG` comes back on the freshly-established session.

### Developer / harness surface

- New Tauri commands (registered in `lib.rs`):
  - `get_ember_dht_contacts` → routing-table snapshot.
  - `add_ember_dht_contact(peer_ip, peer_port, ed25519_pubkey_hex,
    noise_pubkey_hex)` → manually seed a contact.
  - `ember_dht_ping_peer(peer_ip, peer_port, peer_pubkey_hex?,
    timeout_ms?)` → send a DHT PING and await the PONG (RTT or error),
    like `ember_ping_peer` but on the DHT path.
  - `ember_dht_find_node(peer_ip, peer_port, target_hex?, peer_pubkey_hex?,
    timeout_ms?)` → send one `FIND_NODE` and return the contacts the peer
    answered with (blank `target_hex` ⇒ a random target). Single hop.
  - `ember_dht_iterative_find_node(target_hex?, timeout_ms?)` → run a
    multi-hop lookup seeded from the local routing table and return the
    closest contacts that responded (blank `target_hex` ⇒ a random
    self-style probe). No peer address — it walks the network itself.
  - `ember_dht_publish_keyword(keyword, file_name, file_size,
    file_hash_hex?, timeout_ms?)` → sign a keyword record with this node's
    identity and `STORE` it on the closest contacts, returning the DHT key
    it landed under and how many nodes acked (blank `file_hash_hex` ⇒ a
    random hash).
  - `ember_dht_find_value(keyword, timeout_ms?)` → run an iterative
    `FIND_VALUE` for the keyword and return the records whose publisher
    signature verifies.
  - `ember_dht_run_maintenance()` → force one maintenance cycle (slice 6)
    and return a tally of buckets refreshed / liveness pings sent /
    records republished.
- `EmberDiagnostics` now reports `ember_dht_node_id`,
  `local_ed25519_public_key`, `ember_dht_contacts`, the DHT ping/pong
  counters, `ember_dht_find_nodes_sent` / `ember_dht_find_nodes_received`,
  the `ember_dht_active_searches` gauge, the slice-5 store gauges /
  counters (`ember_dht_stored_keys`, `ember_dht_stored_records`,
  `ember_dht_stores_received`, `ember_dht_find_values_received`,
  `ember_dht_active_publishes`), plus the slice-6 maintenance counters:
  `ember_dht_refreshes`, `ember_dht_liveness_pings_sent`,
  `ember_dht_contacts_evicted`, and `ember_dht_records_republished`.
- The `/dev/ember` panel gained an **Ember DHT** card (node ID, Ed25519
  key with copy button, counters, a **Run maintenance** button, live
  routing-table view), a **Seed a DHT contact** form, a **DHT ping a
  peer** form, a **Find node on a peer** form (single hop), an
  **Iterative lookup** form (multi-hop), a **Publish keyword record**
  form, and a **Find value** form (rendering the discovered records
  inline).

## Out of scope for these slices

Multi-keyword search (intersecting several keyword hashes, Phase 2
slice 8) — a `FIND_VALUE` carries the wire support for multiple keys, but
the dev `find_value` queries a single keyword. Proximity-gated storage
(`DhtStore::should_store`, a maturity concern) is not yet enforced: in the
early/small network every directed `STORE` is accepted, bounded only by
signature + key-binding + capacity caps. The native **rendezvous
bootstrap** is now wired end-to-end (server pool + client cold-start fetch
+ self-lookup, above), so both warm and cold starts are KAD-free; what
remains deferred there is a **signed, load-weighted** bootstrap pool (the
current pool is unsigned and best-effort, leaning on PING-time
verification). Also deferred: wiring publishes to real shared files
(today's publish command signs a dev record). Inbound `ANNOUNCE_PEER` /
`PEER_LIST` are decoded and the sender is learned, but their handlers are
deferred.

## Verifying the round-trip

Tests (`cargo test --lib network::ember`):

- `dht::engine::tests::ping_pong_round_trip_learns_both_contacts` — A
  pings B; B answers and learns A; A learns B from the PONG; the learned
  contact carries the session's Noise key.
- `dht::engine::tests::find_node_returns_closest_and_asker_learns_them` —
  A asks B (which knows a third contact C) to `FIND_NODE`; B answers with
  its closest set; A learns both C (from the list) and B (the responder),
  and the `FOUND_NODE` echoes the request id.
- `dht::search::tests::search_discovers_closer_node_multi_hop` — a lookup
  that starts knowing only B hops to the closer C that B reveals, then
  converges with both responded (the slice-4 convergence invariant).
- `dht::search::tests::poll_complete_finishes_empty_search` — a lookup
  seeded from an empty table completes immediately instead of stalling.
- `dht::engine::tests::store_then_find_value_round_trip` — A signs a
  keyword record and `STORE`s it on B; B verifies + stores it and acks; A
  then `FIND_VALUE`s the key and B returns the record, which re-verifies
  end-to-end and matches.
- `dht::engine::tests::find_value_without_record_returns_closest_nodes` —
  a `FIND_VALUE` for a key B doesn't hold falls back to `FOUND_NODE`.
- `dht::engine::tests::store_rejects_key_content_mismatch` — a `STORE`
  whose key ≠ the record's content key is rejected with no ack.
- `dht::engine::tests::random_target_lands_in_requested_bucket` — every
  bucket index yields a refresh target whose XOR distance has its leading
  bit exactly in that bucket (the slice-6 bucket-refresh invariant).
- `dht::store::tests::republish_batch_respects_interval_and_force` — a
  fresh record isn't due for republish; `force` overrides the interval and
  `max` bounds the batch.
- `dht::bootstrap::tests::save_load_round_trip` /
  `save_load_with_ipv6` — `nodes_ember.dat` survives a save/reload with
  contacts intact (slice 7 persistence format).
- `dht::bootstrap::tests::bootstrap_node_to_contact` — a `/bootstrap`
  entry parses into a contact whose `node_id` is **derived** from
  `ed25519_pub` (never read from the wire); `rejects_invalid_bootstrap_node`
  rejects a bad address and a wrong-length Noise key.
- `dht::engine::tests::tampered_frame_is_rejected_and_teaches_nothing`.
- `transport::tests::dispatch_surfaces_non_control_payload_as_app_payload`.

With two harness nodes (`scripts\harness.ps1 node -Node a` / `-Node b`)
and `ember_native_enabled: true` in each `config.json`:

1. On `/dev/ember` for node A, note the **UDP port** and the **Noise
   key**.
2. On node B's "DHT ping a peer" form, enter A's IP, A's UDP port, and
   A's Noise key; send. Expect `OK` with an RTT.
3. Both panels' **Routing contacts** should tick to 1 and list each
   other; A's `ember_dht_pongs_received` and B's
   `ember_dht_pings_received` should each be 1.
4. (Slice 3) Introduce a third node C and DHT-ping it from B so B knows
   both A and C. From A's "Find node on a peer" form, target B (leave the
   target ID blank for a random one); expect `OK` with B's contacts
   listed (including C). A's **Routing contacts** then grows to include C,
   B's `ember_dht_find_nodes_received` and A's `ember_dht_find_nodes_sent`
   each tick to 1.
5. (Slice 4) With A knowing only B, and B knowing C (but A not), run A's
   **Iterative lookup** (blank target). A queries B, learns C, hops to C,
   and converges; the result lists the responders and A's **Routing
   contacts** now includes C — multi-hop discovery via an intermediary.
   `ember_dht_find_nodes_sent` climbs by one per hop.
6. (Slice 5) With A and B knowing each other, on A's **Publish keyword
   record** form enter a keyword (e.g. `ubuntu`) and a file name; publish.
   Expect `OK` with `stored on 1 / 1` and a key. B's **Stores received**
   and **Stored records** tick to 1. Then on B's **Find value** form enter
   the same keyword; expect `OK` listing the record (file name, size,
   publisher) — a signed record published on one node and retrieved from
   another. A's `ember_dht_find_values_received` ticks as B's lookup
   reaches it.
7. (Slice 6) With A and B knowing each other and a record stored on B
   (from step 6), click **Run maintenance** on A. Expect `OK` reporting at
   least one bucket refreshed and/or ping sent; A's **Bucket refreshes**
   and **Liveness pings sent** counters tick. Force it on B and its
   **Records republished** ticks (the record it holds is re-stored). Kill
   a contact's node and run maintenance repeatedly — after three missed
   pings A's **Contacts evicted** ticks and the dead row leaves the table.
8. (Slice 7) Stop node A, confirm `nodes_ember.dat` exists in its data
   dir, then relaunch. A's **Routing contacts** is non-zero immediately on
   startup (seeded from disk), and the log shows "Loaded N Ember DHT
   contacts from nodes_ember.dat" — the table survived the restart with no
   KAD involvement.
9. (Cold bootstrap) Run a long-lived node B (DHT on) so it `/register`s
   with its Noise key and joins the rendezvous `/bootstrap` pool. On a
   fresh node A, delete `nodes_ember.dat` and launch with the DHT on: the
   log shows "Ember DHT cold bootstrap: fetched N node(s) from rendezvous"
   then "seeded … (routing table 0 → N)", A's **Routing contacts** is
   non-zero with no KAD running, and the self-lookup populates nearby
   buckets. `GET <rendezvous>/bootstrap` should list B's `addr` /
   `noise_pub` / `ed25519_pub`.

## Follow-on order

1. ~~Hardcoded seed peers (slice 11).~~ **Done** — see "Hardcoded seed
   peers" above. Baked-in `seeds.txt`, wired into the cold-start path.
2. ~~KAD-bridge bootstrap (slice 13).~~ **Done** — see "KAD-bridge
   bootstrap" above. KAD-learned Ember peers are DHT-pinged into the table
   while it's sparse.
3. **DNS seed list** (slice 12, deferred) — `_ember._udp.<domain>` SRV/TXT
   records so the seed set can rotate without a client release; falls back
   to the hardcoded list. Deferred until a seed domain actually exists
   (needs a DNS-resolver dependency, inert until then).
4. A **signed, load-weighted** rendezvous `/bootstrap` pool (the current
   pool is unsigned + best-effort, leaning on the DHT's PING-time
   verification as the trust anchor).
5. Multi-keyword search + real shared-file publishing (Phase 2).
