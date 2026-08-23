# Ember DHT — remaining work and future improvements

The protocol specification is
[ember-dht-specification.pdf](ember-dht-specification.pdf), written against wire
version 2 as implemented in Ember 1.5.6. **The wire is now version 3 and the PDF
is behind it** — see [item 1](#1-the-serving-ceiling--done-wire-v3) and
[item 7](#7-contact-encoding-wasted-18-of-every-response--done-wire-v3) for the
two frame changes. This file is the standing work log: what is left, what was
compared against KAD, and what is explicitly not planned.

Status: **protocol slices complete** and the overlay is **always on**
(`ember_native_enabled`; profiles that still had it off are turned on at
load). Keyword/source publish, iterative search,
join via the KAD rendezvous key, buddy `PROXY_STORE`, peer announce,
BLAKE3 integrity digests, network-size-adaptive abuse limits, streamed
search results, `FIND_VALUE` paging, and diagnostics are live on `develop`.

Start at [Planned next](#planned-next--from-the-kad-comparison-aug-2026) — every
item in it is now done, and each section records why the change was made and what
to watch. The sections after it are older standing work the comparison did not
change.

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

`EMBER_DHT_VERSION` is now **3**, with `EMBER_DHT_MIN_VERSION` 3 alongside it:
the decoder accepts a *range*, and a frame outside it is refused at the version
byte instead of becoming a malformed-frame counter that reads like packet loss. A
change that only adds to the format can lower the minimum rather than raising
both — v3 could not, because it changed the shape of two existing frames
(contact lists lost `node_id`, `FOUND_VALUE` gained two positions), and a v2
peer reads both at fixed offsets.

**This is the breaking change the section used to warn about**, and it has now
landed on an overlay that ships **on**. Two peers on incompatible versions fail
cleanly, but neither is told why and there is no upgrade prompt — they simply
never fold each other into a routing table. A v2 node therefore sees the network
shrink as peers update, with nothing in the UI to explain it, until it updates
too. Worth a release note; the negotiation gap itself is still open.

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
- A peer serves roughly five records per keyword *datagram*, but a searcher can
  now page a node until its key is exhausted, bounded by 8 follow-ups per node
  and the existing per-node result allowance. See
  [Planned next, item 1](#1-the-serving-ceiling--done-wire-v3).
- One publisher may hold 150 records under any one keyword, network-wide (KAD's
  own allowance), so a user sharing more files than that with a word in common
  still will not have all of them findable under it.
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
averages, and persisted verified-contact high-water. Firewalled consume shipped
as an additive record trailer plus two new message types that older v2 peers
ignore.

**Shipped in 1.5.5 (no wire change):** Ember BLAKE3 pin mismatch is a permanent
download failure with a visible fail badge (it used to reopen every part and
re-queue the search); keyword-publish stamps persist across restart like source
stamps; transport sessions are keyed on `(address, static key)`; Connected /
Search readiness use verified contacts so gossip does not look like a join.
The anti-leech filter matches the software label plus the mod tag (outside
the DHT).

**Shipped as wire v3 — breaking.** The two items that needed a version bump went
together, since one bump pays for both and item 2 was only worth having once item
1 could serve the extra records:

- Item 1's real fix: `start_position` paging on `FIND_VALUE`/`FOUND_VALUE`,
  replacing the responder-side rotation cursor.
- Item 7: `node_id` dropped from wire contacts (87 → 71 bytes, 14 → 17 contacts
  per response).
- Item 2, unblocked by the above: keyword capacity raised to KAD's 150 of 1000.

**Every item in this list is now done.** What remains for the overlay is the
standing work in the sections above (native transfers, version negotiation, cold
join without eMule, validation past the happy path) and the "Future improvements"
below — not this comparison.

### 1. The serving ceiling — done (wire v3)

A peer answers a keyword query with **about five records**. `MAX_FOUND_VALUE_RECORD_BYTES`
is 1231, a keyword blob for a 40-character filename costs 221, and packing used
to fill from the front of insertion order, so the oldest five were the only ones
that node would ever serve.

**Shipped, cheap path (1.5.3–1.5.5):** successive `FIND_VALUE`s rotated the
served window per key, using a cursor the *responder* advanced.

**Shipped, real fix (v3):** `FIND_VALUE` carries a `start_position` and
`FOUND_VALUE` answers with `next_position` plus `total_available`. The searcher
owns the offset, so a walk pages a well-stocked node until the key is exhausted
instead of hoping its window had moved.

The rotation cursor is **gone**, not kept alongside. It could not tell "this
searcher wants the next page" from "a different searcher wants the first", so two
searchers on the same hot key advanced each other's window and neither saw a
contiguous run. Serving is now deterministic: the same request gets the same
answer every time.

`next_position` is reported rather than inferred. The packer skips a record too
large for the budget *left* on a page and keeps scanning for one that still fits,
so the records a page serves are not always a contiguous run, and `start + len`
would step over the skipped position — the big record is then never first, so
never faces an empty budget, so never served at all, while `get_live` and the
diagnostics go on reporting it as held. A page therefore resumes at the earliest
record it passed over, which costs re-sending the ones after it (absorbed by
content dedup in `search.rs`) and guarantees nothing is stranded.
`local_records` (seeding our own search) still does no packing at all.

Paging is the one mechanism here where a *responder* influences how many queries
we send, so the searcher bounds it independently of what `total_available`
claims: `MAX_PAGES_PER_NODE` (8) follow-ups per node, each required to name an
offset strictly past the one it answered, and the existing
`MAX_RESULTS_PER_NODE` allowance still caps what one peer may contribute.
Positions are advisory — the responder's list shifts as records expire — so
paging may repeat or skip an entry, which content-based dedup in `search.rs`
already absorbs.

The truncation counters (`ember_dht_found_value_truncated` /
`ember_dht_found_value_withheld`, shipped 1.5.3) are still the way to read how
far the datagram ceiling actually binds on real keys.

### 2. Per-publisher keyword capacity — done

`MAX_RECORDS_PER_PUBLISHER_PER_KEY` was 45 of `MAX_RECORDS_PER_KEY` 300 against
KAD's 150 of 1000. Both are 15%, but the absolute number is what a user feels:
every storer applies the same cap to the same publisher key, so the ceiling is
network-wide, not per-node. A user sharing 200 files with a common word got 45 of
them findable under that word *anywhere* — 30% of what KAD serves.

Both are now KAD's numbers, which keeps the ratio and triples capacity.
`keyword_capacity_matches_kad` pins them together, since raising either alone
breaks the property that no identity holds more than about a sixth of a key.

This deliberately waited on item 1, and shipped in the same version: while a peer
could only ever serve its first window, the extra stored records had no way to
reach a searcher and the one certain effect would have been more
storer-replication traffic.

`MAX_STORE_BYTES` is unchanged at 48 MiB, so per-key capacity went up without
raising what the process may resident-hold. When the byte budget binds first it
still sheds the records this node is least responsible for (furthest key, then
nearest expiry) rather than refusing newcomers.

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

### 4. Firewalled sources are discoverable but not dialable — done

Publish was already complete: a firewalled node sets `SOURCE_FLAG_FIREWALLED`,
asks the named HighID to `PROXY_STORE`, and storers attribute the record to the
forwarder. Consume now matches KAD's buddy callback without a DHT version bump.

A firewalled source record may append a 70-byte trailer (publisher eD2K user
hash + buddy IPv4 + buddy UDP port + buddy Noise key + 16-byte callback token)
after the existing 41-byte contact. HighID records stay 41 bytes. New message
types `CALLBACK_REQ` (0x0F) and `CALLBACK` (0x10) decode as `Unknown` on older
peers.

A reachable searcher sends `CALLBACK_REQ` (including the token from the signed
trailer) to the named buddy. The buddy forwards `CALLBACK` only for a publisher
it recently `PROXY_STORE`d for, copies the searcher's *observed* UDP address
rather than a claimed IP, and copies the token. The publisher overlay-`STORE`s
the firewalled record only after that buddy `PROXY_STORE_ACK`s, so `FIND_VALUE`
cannot name a buddy that cannot bounce. The publisher accepts `CALLBACK` only
from a buddy that ACKed a `PROXY_STORE` for that file, and only when the token
matches the one it published. It then connects eD2K TCP back (the same
upload-listener path as KAD `OP_CALLBACK`). Firewalled Ember DHT contacts are
never registered in SourceManager (that map has no firewalled bit, so pending
promotion would TCP-dial the claimed NAT IP). `WaitCallbackKad` rows are also
kept out of TCP reask and pause/resume seeding; only `CALLBACK_REQ` retries
them. A searcher that itself is
TCP-firewalled (LowID, or KAD/server `Firewalled` — not the UPnP-pessimistic
startup flag) does not send `CALLBACK_REQ`. Firewalled Ember DHT records also
set `SOURCE_FLAG_RELAY_CAPABLE`, so ingest starts the same Ember punch/relay
broker KAD uses for Ember-capable LowID sources instead of leaving both sides
parked. An unusable named buddy still parks — including Searching-only pending
downloads — rather than dropping the source. The broker still needs admitted
ERAT candidates; it does not invent a relay.

Diagnostics: `ember_dht_callback_sent / forwards / connects` on the Ember page.

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
stamps use the same pattern (`FT_EMBER_KEYWORD_PUBLISH` = 0xE5) against
`EMBER_KEYWORD_REPUBLISH` (12h), so a restart no longer republishes the whole
library.

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

### 7. Contact encoding wasted 18% of every response — done (wire v3)

Each wire contact used to carry both `node_id` (16 bytes) and `ed25519_pub` (32),
but the ID *is* BLAKE3 of that key and every decoder re-derived and checked it
rather than trusting the wire — so the only thing those bytes could do was
disagree with the key beside them.

Dropping them took a contact from 87 to 71 bytes: **17 contacts per `FOUND_NODE`
instead of 14**, which is most of a hop on a sparse table. Bundled with item 1's
version bump as planned. `a_found_node_carries_more_contacts_than_v2_could` pins
both the 71-byte size and the resulting count, because the gain is purely a
function of the byte budget and any field a future version adds to a contact
spends it silently.

Note this is the *wire* format only. `nodes_ember.dat` still persists a node ID
per contact (advisory; `to_contact` re-derives the authoritative one), because
changing the file format would cost every user their bootstrap set for no
bandwidth saving.

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

- ~~**Transport session keying.**~~ Sessions are keyed on `(address, static key)`,
  so claimants at one address coexist (capped at four, the old 1-live-plus-3-shadow
  budget). A genuine first contact at an address already full of spoof sessions
  is kept; a named outgoing identity no longer discards another key at that
  address. Named in `install_session`.
- **Updater recovery only protects 1.5.3 onward.** The 1.5.2 → 1.5.3 hop runs
  1.5.2's updater, so if a hand-off fails silently again the user still sees
  nothing and must install by hand. The root cause of the original failure was
  never established; the recovery path is a mitigation for the symptom.

---

## Future improvements

Ordered roughly by leverage. None block a release if the items above are
settled.

### Bootstrap and network health

- ~~Monitoring for rendezvous-key health: how many nodes are listed, how
  often a cold lookup returns nothing.~~ Surfaced as `ember_dht_rendezvous_*`
  on the Ember page (listed / lookups / empty).
- Stronger observed-IP / STUN interplay under awkward NATs (needs soak
  data).
- Shard the rendezvous key space. The derivation is already versioned for
  this; it matters once one KAD bucket's 1000-entry cap is in sight.
- Table quality: tune announce versus bucket-refresh balance under load.

### Search and publish

- Richer keyword indexing (stemming, more than space-split tokens) if
  recall lags KAD on real libraries.
- ~~Clearer search UI when Ember is joining (empty table) versus
  enabled-but-quiet.~~ Search, the Ember page, and the status bar wait for
  a verified contact; gossip-only no longer looks connected. After the
  join timeout with still-zero verified peers, Search shows the muted
  no-peers hint.
- Storer-side replication telemetry. The publish side logs an
  `Ember publish cycle` heartbeat each minute; maintenance now logs an
  `Ember replication cycle` heartbeat as well (see
  [Planned next, item 6](#6-storer-side-replication-costs-more-than-it-buys)).

### Integrity and downloads

- ~~Surface BLAKE3 verify pass/fail in the transfer UI.~~ Pass is the Ember
  badge on a completed row (`ember_verified`). Fail is a permanent download
  failure with a red Ember badge; a mismatch no longer reopens parts that
  already matched the ed2k hash, and the download is not re-queued.
- ~~Seed `emberFileHash` from more UI entry points when the digest is
  already known.~~ ed2k `eh=` links, friend-browse trailers, file-offer
  trailers, paste/deep-link, library copy, and friend accept all pass it
  when present. Old peers ignore the extra bytes.

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
| Settings toggle | Settings → Network (`ember_native_enabled`, always on; switch is visible but disabled) |
| User-facing status | `/ember` (Ember Network page) |
| Library publish badges | `shared_ember` on `FileInfo` → Library "Shared" column |

Protocol constants live in
[`dht/mod.rs`](../src-tauri/src/network/ember/dht/mod.rs): 128-bit node IDs
(BLAKE3 of the Ed25519 public key), k = 20, α = 5, wire version 3.

`MAX_CONTACTS_PER_RESPONSE` is 20 but is still not reachable: `encode_contact_list`
trims by bytes, and at 71 bytes per IPv4 contact (7 address + 32 Noise key + 32
Ed25519 key) 17 fit the 1253-byte payload budget — up from 14 while contacts also
carried a redundant 16-byte ID. A `FOUND_NODE` therefore never carries a full
k-bucket. See item 7 above.
