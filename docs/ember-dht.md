# Ember DHT — remaining work and future improvements

Status: **protocol slices complete** and the overlay is **on by default**
(`ember_native_enabled`, with a one-shot migration for profiles created
before the default flipped). Keyword/source publish, iterative search,
join via the KAD rendezvous key, buddy `PROXY_STORE`, peer announce,
BLAKE3 integrity digests, network-size-adaptive abuse limits, streamed
search results, and diagnostics are live on `develop`.

Start at [Planned next](#planned-next--from-the-kad-comparison-aug-2026) — it is
the current plan, ordered by leverage and backed by a constant-for-constant
comparison against this repo's KAD stack. The sections after it are older
standing work that the comparison did not change.

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
- A peer serves roughly five records per keyword query and there is no
  pagination, so recall is bounded by nodes-walked × 5. Successive queries
  rotate which window is served, so a late publisher is no longer stuck
  behind the oldest handful on that node. See
  [Planned next, item 1](#1-the-serving-ceiling--do-this-first).
- One publisher may hold 45 records under any one keyword, network-wide, so a
  user sharing many files with a word in common will not have all of them
  findable under it.
- Gossip contacts are unverified until the node hears from them directly
  (same as Kademlia). Admission is bounded by the diversity caps in
  [`scale.rs`](../src-tauri/src/network/ember/dht/scale.rs), but there is
  no reputation scoring on gossip itself.
- Download content transfer is still eD2K c2c (see item 1 above).
- BLAKE3 verify runs when an expected digest is available (search hit, DHT
  source record, known.met / library). Deep links without a digest still
  complete and hash for future share.

---

## Planned next — from the KAD comparison (Aug 2026)

Ember was compared against this repo's own KAD stack, constant for constant, to
answer whether it matches or exceeds it operationally. On design it already
does: twice the replicas (20 vs 10), three times the TTL margin on sources where
KAD has none, a replacement cache KAD lacks entirely, storer-side replication
KAD lacks entirely, a store that survives restart, roughly half the round trips
per lookup (α=5 against KAD's 1 for `FindNode`), and a much richer diagnostic
surface. The items below are where it does not, in leverage order.

Everything here was verified in the code, not inferred from comments. Four
silent-breakage bugs and five performance defects found by the same comparison
were fixed before 1.5.3 and are not repeated here.

**Shipped in 1.5.3:** item 3 (streaming) in full, item 6 (the republish cadence)
in full, and the truncation counter that items 1 and 8 both depend on. Their
sections below are kept rather than deleted, because each records why the change
was made and what to watch now that it is live.

**Shipped after 1.5.3 (no wire change):** item 1's cheap path (rotate the served
window), item 5 (persist the Ember source publish schedule), item 6's leftover
replication heartbeat, and item 8's store-rejection causes, search-quality
averages, and persisted verified-contact high-water. Pagination, firewalled
consume, and dropping `node_id` still wait on a version bump. Item 2 remains
blocked on measuring whether truncation still binds after rotation.

Items 4 and 7 are untouched and remain in this order.

### 1. The serving ceiling — do this first

A peer answers a keyword query with **about five records**. `MAX_FOUND_VALUE_RECORD_BYTES`
is 1235, a keyword blob for a 40-character filename costs 221, and packing used
to fill from the front of insertion order, so the oldest five were the only ones
that node would ever serve.

**Cheap path, shipped:** successive `FIND_VALUE`s rotate the served window per
key. The cursor advances by how many records the reply actually carried, and
only when the reply withholds some — if everything fits, rotation is a no-op.
`local_records` (seeding our own search) does not inherit this packing. Blob-hash
dedup in `search.rs` is content-based, so rotating windows can only gather more.

Still missing, and what KAD does:

- **Add `start_position` to `FIND_VALUE`/`FOUND_VALUE`.** The real fix. Costs an
  `EMBER_DHT_VERSION` bump (see "Wire versioning" above — this is the breaking
  change that section warns about) and multiplies query traffic on hot keywords.

The truncation counter this was waiting on **shipped in 1.5.3**: an inbound
`FIND_VALUE` we answer now reports how many live matching records the datagram
could not carry, surfaced on the Ember page as truncated answers over withheld
records. Read it before paying for pagination. Truncation near zero means the
ceiling is theoretical on the network as it currently is and item 2 is the
better buy; a high withheld-per-truncated ratio is the case that justifies the
wire change, because it says the records exist and nothing can reach them.

### 2. Per-publisher keyword capacity — blocked on 1

`MAX_RECORDS_PER_PUBLISHER_PER_KEY` is 45 of `MAX_RECORDS_PER_KEY` 300. KAD's
equivalent is 150 of 1000. Both are 15%, but the absolute number is what a user
feels: every storer applies the same cap to the same publisher key, so the
ceiling is network-wide, not per-node. **A user sharing 200 files that share a
common word gets 45 of them findable under that word, anywhere** — 30% of what
KAD serves.

Raising both to KAD's numbers keeps the ratio and triples capacity. Do not do it
before item 1: if a peer only ever serves ~5 records per reply, the extra stored
records have no way to reach a searcher, and the only certain effect is more
storer-replication traffic.

### 3. Stream search results as they arrive — done in 1.5.3

Ember used to buffer everything and emit on completion; `FIND_VALUE` is
deliberately excluded from early convergence, so on a cold table a user waited
most of the 60-second cap while KAD hits were already on screen.

The Ember keyword search now carries a cursor into the search's append-only
result list, and the 1-second sweep emits everything past it on the same cadence
the KAD path uses: the first record immediately, then every 20. Records seeded
from the local store therefore reach the UI on the first tick. Batches run
through `dedup_streamed_batch` / `mark_streamed_hashes`, so a hash KAD already
streamed arrives as an availability update rather than a duplicate row, and only
the batch flagged final clears `ember_pending` — the completion batch is still
queued when it is empty, so that happens exactly once.

Worth knowing when reading this code: the timeout backstop that reaps an expired
keyword search runs earlier in the same sweep than both the streaming step and
the emit step, and it removes the search from `ember_keyword_searches`. That
ordering is what stops a reaped search from being streamed after its
`search-complete`, and it is not obvious from either site alone.

### 4. Firewalled sources are discoverable but not dialable

This is the largest genuine functional gap against KAD. The publish side is
complete — a firewalled node sets `SOURCE_FLAG_FIREWALLED`, asks HighID contacts
to `PROXY_STORE`, and storers attribute the record to the forwarder. The consume
side has nothing: `SourceContact` carries no buddy address or buddy hash, so
there is no Ember equivalent of KAD's `TAG_BUDDYHASH` plus
`KADEMLIA_CALLBACK_REQ`. Such peers only work today because they are usually also
on eD2K/KAD.

A protocol addition: a buddy field in the source record and a callback message.
Sizeable, and it should follow item 1 so both wire changes land in one version
bump.

### 5. Persist the Ember source publish schedule — done

`ember_source_publish_at` is keyed on `Instant`, so every restart used to mark
the whole library as never-published and slam the backlog-drain term to its
ceiling.

The last successful source-publish is now written to known.met as
`FT_EMBER_SOURCE_PUBLISH` (0xE4), distinct from KAD's `last_source_publish`.
On start, a stamp still inside `EMBER_SOURCE_REPUBLISH` (2h) is hydrated back
to an `Instant`; a stamp older than the interval, or one that cannot be
represented because the process has not been up that long, is omitted and the
file is due immediately — republish-too-eager, the safe direction. Keyword
schedule is still session-only.

### 6. Storer-side replication costs more than it buys

**Halved in 1.5.3**: `EMBER_RECORD_REPUBLISH_SECS` is now 7200.

At 200 records per cycle to 20 replicas, hourly was roughly **48,000 frames an
hour** — Ember's single largest traffic item, about double its entire publish
load. Two-hourly saves about half of that.

The reasoning matters more than the number, because it is the argument against
ever putting the cadence back. Replication cannot extend a record's lifetime:
expiry is derived from the publisher's *signed* creation timestamp, and a storer
re-sends the identical bytes, so every recipient computes the same absolute death
time. What it buys is churn coverage, copies reaching nodes that joined since the
publisher's last round, and two hours buys that as well as one given each record
already has 20 replicas and lives at most 24 h. A shorter cadence would have to
be justified on churn coverage measured, not on record survival.

Still missing was any view of what this node republishes on others' behalf. The
publish side logs a cycle heartbeat; this, the larger of the two traffic items,
had no equivalent. **Shipped:** each maintenance cycle now logs an
`Ember replication cycle` heartbeat — due, selected, queued, re-armed, leftover
backlog — on the same cadence as the 60s maintenance tick. The two-hourly
republish interval is unchanged.

### 7. Contact encoding wastes 18% of every response

Each wire contact carries both `node_id` (16 bytes) and `ed25519_pub` (32), but
the ID *is* BLAKE3 of that key and the receiver re-derives and checks it anyway.
Dropping it takes a contact from 87 to 71 bytes: **17 contacts per `FOUND_NODE`
instead of 14**, which also buys a fraction of a hop. Free, but it is a wire
change, so bundle it with item 1's version bump.

### 8. Observability gaps

The diagnostic surface is already better than KAD's. Three things are still
missing that matter specifically for judging health after a long unattended run:

- ~~**Nothing reports a truncated `FOUND_VALUE`.**~~ Shipped in 1.5.3, as
  `ember_dht_found_value_truncated` and `ember_dht_found_value_withheld`. This
  was the prerequisite for item 1; see there for how to read it.
- ~~**Store rejections have no cause breakdown.**~~ Counted: verify, signature,
  timestamp, anti-reflection IP, per-IP cap, publisher cap, per-key cap,
  proximity, plus the existing key-cap counter.
- ~~**No search outcome quality.**~~ Completed `FIND_VALUE`s (including
  timeouts) accumulate nodes answered, elapsed milliseconds, and records
  returned; the Ember page shows the averages.
- ~~**Every counter resets on restart.**~~ A persisted daily and all-time
  high-water of verified contacts (`ember_dht_highwater.json`) answers "is this
  growing?" across restarts.

### Outside the DHT

- **Transport session keying.** Sessions are keyed by address alone, so the
  shadow-session map can protect an established peer from a key-churning spoofer
  but cannot protect a peer whose *first* contact arrives at an address whose
  shadow allowance is already full. Keying by `(address, static key)` removes the
  need to rank indistinguishable claimants at all. Named in `install_session`.
- **Updater recovery only protects 1.5.3 onward.** The 1.5.2 → 1.5.3 hop runs
  1.5.2's updater, so if a hand-off fails silently again the user still sees
  nothing and must install by hand. The root cause of the original failure was
  never established; the recovery path is a mitigation for the symptom.

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
- Storer-side replication telemetry. The publish side logs an
  `Ember publish cycle` heartbeat each minute; maintenance now logs an
  `Ember replication cycle` heartbeat as well (see
  [Planned next, item 6](#6-storer-side-replication-costs-more-than-it-buys)).

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
(BLAKE3 of the Ed25519 public key), k = 20, α = 5.

`MAX_CONTACTS_PER_RESPONSE` is 20 but is not reachable: `encode_contact_list`
trims by bytes, and at 87 bytes per IPv4 contact (16 id + 7 address + 32 Noise
key + 32 Ed25519 key) only 14 fit the 1253-byte payload budget. A `FOUND_NODE`
therefore never carries a full k-bucket. See "Contact encoding" below.
