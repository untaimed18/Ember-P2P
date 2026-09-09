# Ember DHT — plan

The protocol specification is
[ember-dht-specification.pdf](ember-dht-specification.pdf), written against wire
version 4 and rebuilt from [its HTML source](ember-dht-specification.html) with
[`scripts/build-ember-dht-spec.sh`](../scripts/build-ember-dht-spec.sh). It carries
the v3 frame changes, what moved it to v4 (see
[item 2](#2-wire-versioning-rejects-cleanly-and-now-advertises-but-still-cannot-route-around-old-peers)),
and every additive change since — each marked as additive, since that is the
distinction an implementer needs.

**This is the single plan for the overlay.** It replaces the separate
`ember-dht-search-plan.md`, whose live content — the friend-browse filter design,
the extension decision, and the standing "already better than KAD" list — is folded
in below. Finished work is no longer narrated item by item; it is listed in
[Closed](#closed), and the reasoning behind each closed item is in git history and
in the specification.

Status: **protocol slices complete** and the overlay is **always on**
(`ember_native_enabled`; profiles that still had it off are turned on at load).
Keyword/source publish, iterative search, join via the KAD rendezvous key, buddy
`PROXY_STORE`, peer announce, BLAKE3 integrity digests, network-size-adaptive
abuse limits, streamed search results, `FIND_VALUE` paging, and diagnostics are
live. Start at [Outstanding work](#outstanding-work); everything below it is
reference, decisions already taken, or closed.

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
4. **A friend's routing table, over the friend session.** While below one
   k-bucket of verified contacts, live friend sessions are asked for the
   contacts they hold (`EMBER_EXT_DHT_CONTACT_REQ`). This is the only path that
   needs no dialable UDP address for the peer introducing us.
5. **DHT gossip** (`FOUND_NODE` / `PEER_LIST` / `ANNOUNCE_PEER`) and
   **`nodes_ember.dat`** (up to `EMBER_PERSIST_MAX_CONTACTS` = 200) once
   the node has been online before.

The rendezvous server is still used for *friend* NAT traversal and relay.
It has no role in DHT bootstrap: that pool, its endpoint, and the pinned
key it verified were deleted, because the server and client never agreed
on the envelope format and restoring it would have handed the operator an
identity-to-IP map of every participant.

---

## Outstanding work

### 1. Ember-native transfers are partly wired

[`network/ember/transfer.rs`](../src-tauri/src/network/ember/transfer.rs)
holds the 256 KiB chunk protocol and the BLAKE3 hash tree. Its `HashTree` is
now live: **Ember Transfer**
([`network/ember/xfer.rs`](../src-tauri/src/network/ember/xfer.rs)) uses it to
identify a file that one channel member hands to another, over the
authenticated Noise/UDP session the room already provides. One sender, one
recipient, an explicit accept before any bytes move, receiver-driven block
requests, and its own send budget so a transfer never starves chat.

Every transfer frame is authenticated to the two members it is between. The
room's content key is shared by all of them, so on its own it proves only that
a frame came from *somebody* in the room — enough for chat, not enough for a
prompt that names who is sending you a file. Each frame therefore carries a
16-byte tag under a key derived from static X25519 Diffie-Hellman between the
two Ed25519 identities the presence records already publish
(`channel::derive_xfer_key`), bound to the room and the transfer id. A member
cannot forge another member's offer, accept, cancel, block request, or block
data; a non-member cannot produce a frame at all. Symmetric rather than a
signature because 64 bytes per frame would push a block past the unfragmented
datagram budget, and nothing here needs to be provable to a third party.

What is still dormant is the rest of that module — the QUIC stream framing
(`MSG_REQUEST_CHUNKS` and friends) and any multi-source notion. Ordinary
library downloads still discover sources over Ember and move bytes over eD2K
client-to-client. The two remaining pieces, if the goal is a network that
does not need the eMule wire at all:

- **Reach.** Rendezvous publishes presence for the 8 XOR-closest members of at
  most 4 rooms, so an arbitrary member holding a file may not be dialable.
  Ember Transfer falls back to the channel relay, which works but is slower
  than a direct session.
- **Throughput.** Blocks are 1008 bytes and paced by
  `XFER_BLOCKS_OUT_PER_SEC`, sized so the block plus its authenticator, gossip
  envelope, and relay header stay inside one unfragmented datagram
  (`xfer_block_frame_fits_one_unfragmented_datagram` pins the arithmetic).
  Moving the same offers onto QUIC would lift that ceiling without changing the
  offer/accept handshake, which is why the file is identified by its hash-tree
  root rather than by anything transport-specific.

### 2. Wire versioning rejects cleanly and now advertises, but still cannot route around old peers

`EMBER_DHT_VERSION` is now **4**, with `EMBER_DHT_MIN_VERSION` 4 alongside it:
the decoder accepts a *range*, and a frame outside it is refused at the version
byte instead of becoming a malformed-frame counter that reads like packet loss. A
change that only adds to the format can lower the minimum rather than raising
both — neither of the last two could. v3 changed the shape of two existing frames
(contact lists lost `node_id`, `FOUND_VALUE` gained two positions), which a v2
peer reads at fixed offsets. v4 appends the sender's own Noise static key to the
*signed* bytes without transmitting it, binding a frame to the session it
arrives on so a signed frame stops being a bearer token any prior recipient can
replay; a v3 signature cannot verify here and ours cannot verify there, so the
version byte has to move with it.

**This is the breaking change the section used to warn about**, and it has now
landed on an overlay that ships **on**. Two peers on incompatible versions fail
cleanly and never fold each other into a routing table.

The local half of that is no longer silent, and this section used to say it was.
A refused frame is counted as `ember_dht_version_mismatch`, split into
`ember_dht_version_peer_older` and `ember_dht_version_peer_newer`, and `/ember`
raises a banner while older peers are being turned away — so a node on this
build can tell a thin table from packet loss. What cannot be fixed from here is
the other half: the peer that needs to update is by definition the one that
cannot decode anything we send, and it is running a build from before those
counters existed. It sees the network shrink with nothing to explain it. That is
a release-note problem, not a code one.

**The negotiation half is now started, and it had to start before it could be
useful.** A `PING` and a `PONG` carry the range this build can decode —
`VersionRange`, tag/len/value trailing the payload, `OUR_VERSION_RANGE` pinned to
the two constants `decode_message` actually enforces — and the receiver keeps it
per peer (`peer_versions`, pruned to the routing table each maintenance tick).
`ember_dht_version_advertisers` on `/ember` is the number to read against
verified contacts.

Additive on exactly the terms the closed `FIND_VALUE` constraint and record
metadata changes turned out to be (see [Closed](#closed)), and the version
deliberately did **not** move: `MSG_PING`
discards its payload entirely and `MSG_PONG` reads its address through
`decode_socket_addr`, which checks only a minimum length and reports what it
consumed, so a v4 build reads both frames exactly as it does today. Bumping for
this would have been self-defeating — the peers it exists to reach are the ones
that would refuse the frame carrying it.
`the_version_block_is_invisible_to_a_decoder_that_ignores_it` pins that property
at the payload codec, since that is precisely where a v4 peer differs from us.

Two shapes are load-bearing. The block only ever trails a field a reader parses
first, so an addressless `PONG` — the pre-slice-19 shape — carries none: with no
address in front of it an older build would read the tag byte as an address type
and reject the whole frame. And absent, truncated and nonsensical all read as
"this peer told us nothing" rather than as a range or as an error, because an
advisory field must not be able to drop a frame.

What this does not do yet is *use* the answer. `peer_accepts_version` has no
production caller and cannot have one: `EMBER_DHT_MIN_VERSION` equals
`EMBER_DHT_VERSION`, so every peer we can exchange a frame with speaks exactly
one version and there is no decision to make. Its first caller is whatever
encodes the next wire change, and the ordering is the point — the ranges have to
be arriving from the field *before* a bump can route around the peers that lack
them, or the first peer to advertise one is also the first to need it. So the
standing gap is now narrower and different: not "nothing advertises a range" but
"a shape change still partitions every peer running a build older than this
one", which the advertiser count is what measures.

### 3. Meeting a friend we cannot dial — designed, not started

Still open on this path: nothing uses the friend session to carry a *live*
introduction, so a friend we cannot dial never becomes an overlay contact however
long the session lasts. This section used to say "that needs relay, not another
ask". Having costed the relay, that conclusion was wrong, and the cheaper
mechanism is also the better one.

**What is actually blocked.** `note_connected_ember_peer` returns at
`udp_port == 0` — "the peer is now a known Ember host and will never be a DHT
contact: the overlay rides the shared UDP socket, so with no port there is nothing
to bridge to". That is the normal case for a friend reached by relay or NAT
traversal, and it is a dead end rather than a slow path: no retry policy helps
something that is never attempted. A friend that *did* advertise a port but sits
behind a NAT that drops unsolicited datagrams is the same dead end one step later,
because the bridge ping is unsolicited by definition.

**Why not relay.** Three reasons, in increasing order of how much they cost:

- The DHT does not need direct pairs. A record is found on whichever nodes are
  closest to its key, so A does not need B as a contact to find B's files — it
  needs *any* twenty working nodes. Making two specific peers contacts of each
  other is close to worthless on its own.
- A relayed contact is a fiction the routing table cannot hold. `is_verified()`
  means we heard a signed frame *directly*; refreshing `last_seen` from relayed
  traffic tells the liveness model an address works when it does not, and the
  address is then gossiped onward in `FOUND_NODE` to peers for whom it certainly
  does not.
- It would duplicate the channel relay for the only population that genuinely
  cannot punch — both ends symmetric — and that population already has the friend
  session itself for chat, browse and file offers, plus the channel relay for
  rooms. The marginal gain is a routing-table entry nobody can use.

**The mechanism instead: a friend-coordinated simultaneous open.** The friend
session is an authenticated, live, bidirectional channel to exactly the peer we
want to meet. That is all a UDP simultaneous open needs, and it needs no third
party, no rendezvous server and no new trust relationship.

One new `EMBER_EXT` sub-type (`0x07`; `0x06` is the highest in use), sent over the
friend session: *"I am sending you a DHT `PING` from my Ember UDP socket now — send
me one too."* Both sides send immediately, each outbound datagram opens the return
path through its own NAT, and whichever `PING` lands first is answered with a
signed `PONG` that folds the sender into the routing table through the ordinary
path. Nothing new touches the table.

Four details carry the design:

- **Observed IP, claimed port.** Take the friend's IP from the TCP connection we
  are already talking to them on, and the UDP port from the payload — the port
  cannot be observed and must be asserted, exactly as `BUDDY_ENDORSE` has a buddy
  assert its own endpoint. Never take the IP from the payload; that is the rule
  `CALLBACK` states as "a claimed address would let anyone aim the publisher at a
  third party", and it applies here for the same reason.
- **The frame grants nothing.** It is a request to *try*, not an introduction to
  be believed. Only a real `PONG` creates a contact, so a friend that lies about
  its port costs us one datagram and gets nothing — no table entry, no session, no
  gossip.
- **Fire it when it can help, not on a timer.** The condition is precise: we hold
  no verified contact for this friend. That is cheaper than the starvation gate the
  contact ask uses (`verified_len() < EMBER_KAD_BRIDGE_UNTIL_CONTACTS`) and correct
  at any table size. Add a per-friend interval on the same stamp-before-send
  pattern as `EMBER_FRIEND_CONTACT_ASK_INTERVAL`, and the same
  least-recently-asked rotation, so a handful of friends cannot monopolise it.
- **It composes with the ask already there.** A friend hands over the contacts it
  holds *and* can now become one. For a small overlay that is the difference
  between a friend being a phone book and being a peer.

**Where it stops.** Both-ends-symmetric fails a simultaneous open, and that is
where this design ends rather than falling back. `NatType::can_punch_with` already
states that case as unpunchable, and the live gate is narrower still — it checks
only that *our own* type is not `Symmetric`, because the peer's type is not known
until a punch is already in flight. Worth knowing when reading that predicate: STUN
here only ever assigns `Open`, `Symmetric`, `PortRestricted` or `Unknown`, so
`FullCone` and `RestrictedCone` are dead branches and the common real answer is
`PortRestricted`, which punches.

Diagnostics, mirroring `ember_dht_friend_contact_asks` against
`ember_dht_friend_contacts_learned`: meets attempted against contacts gained. Those
two are also the evidence that would justify revisiting the relay — a population
whose attempts never convert is the both-symmetric case, measured rather than
assumed.

### 4. Cold join when eMule is not available

Every path in the list above except `nodes_ember.dat` used to presuppose either
a live KAD connection or an eD2K transfer with an Ember-capable peer, so a
first-run user with KAD off and no servers had no way in. Seed lists are
deliberately not planned.

**Narrowed, not closed.** The friend contact exchange — now closed, see
[Closed](#closed) — needs neither: a friend session is
reached by stored address or through the rendezvous server, so a user who has
added one friend can now join with KAD off and no servers. What is still
uncovered is the user who has *nobody* — no friend, no KAD, no server — and for
them the answer remains that Ember rides eMule's bootstrap. That is now a
documentation matter rather than a gap for most first runs, but the shape of the
hole has not changed.

### 5. Validation past the happy path

Search → download over a live network is confirmed working. Still
unexercised end to end:

- LowID / firewalled publishing through buddy `PROXY_STORE`. **The priority of
  the three**, because three parts of it changed in `df849818` and none has been
  seen on a live network: the buddy now requires an endorsement before it will
  proxy at all, the publish side no longer emits the compatibility trailer, and
  the buddy's own replica is attributed to the sender. Each has unit coverage,
  which says nothing about whether the chain completes.

  The chain to walk, with the counter that shows each hop:
  `BUDDY_ENDORSE_REQ` → endorsement absorbed → `PROXY_STORE` accepted
  (`ember_dht_buddy_publishes`) → `PROXY_STORE_ACK` → overlay `STORE` → searcher
  finds the record → `CALLBACK_REQ` (`ember_dht_callback_sent`) → buddy bounces
  `CALLBACK` (`ember_dht_callback_forwards`) → publisher connects back
  (`ember_dht_callback_connects`).

  One behaviour to confirm specifically: with the compatibility trailer gone, a
  publisher that never obtains an endorsement publishes *nothing* for that file
  rather than a record no searcher would dial, and `ember_dht_waiting_buddy` is
  the only evidence that state exists. Check it lights, and then clears once an
  endorsement lands.
- A cold join from an empty contact file with no KAD.
- Republish behaviour across a full record TTL on a large library.

For a local two-node test where neither side can reach KAD, the dev
*commands* remain even though the dev page is gone —
`add_ember_dht_contact` is the only way to introduce two nodes directly,
alongside `ember_dht_ping_peer`, `ember_dht_find_node`,
`ember_dht_iterative_find_node`, `ember_dht_publish_keyword`,
`ember_dht_find_value`, and `ember_dht_run_maintenance`.

### 6. Filter the friend browse on the wire — designed, not started

What the constraint cannot do is answer "show me every `.mp3`" with no keyword at
all. Kademlia has to walk *toward* something, and the only key such a query could
name is the hotspot above — so if browsing by type is wanted, it must not be a DHT
feature.

**The three open questions this section used to carry are answered by where the
feature has to live**, so they are recorded as decided rather than left open.

`OP_EMBER_EXT` — the envelope the sketch proposed — is gated on
`friend_privileges_allowed(secure_v2_authenticated, is_ember_friend)`, so an
ember-ext sub-type is friends-only with proof of possession *by construction*. And
a dedicated friend browse already exists beside it: `OP_EMBER_BROWSE_REQ` (0xF2) /
`OP_EMBER_BROWSE_RES` (0xF3), over a secure-v2 friend session, gated on mutual
friendship and `friend_browse_disabled`, answering with the `EBR1` format that
carries AICH roots and Ember digests. So:

1. **Who may ask** — friends, and only friends. Not a new policy and not a new
   setting: a stranger cannot get the frame past the opcode gate. Mutual friends
   already see `friends_only` shares (`is_friend_visible()` is `shared` alone,
   against `is_public_listable()`'s `shared && !friends_only`), so the filter
   exposes nothing a friend could not already ask for.
2. **Where it surfaces** — in the Friend Browse dialog, which is where browse
   already lives. Not a search method: presenting it beside "Ember Only" invites
   the comparison it loses, because it can only show what one friend holds.
3. **How results merge** — they do not. One friend's answer is one friend's list,
   so no availability semantics, no publisher corroboration, no digest rules.

**What the user actually gains**, which is the reason to build it: the friend
browse answer is capped at `MAX_BROWSE_ANSWER_FILES` = 1000 files and
`MAX_BROWSE_ANSWER_BYTES` = 400 KiB, and the parse and UI sides cap at 1000 too
(`MAX_BROWSE_ENTRIES`, `MAX_BROWSE_FILES`). The filter that exists today is
*client-side*, so browsing a friend with 40,000 shared files filters an arbitrary
thousand of them. Filtering before the cap is what turns "some of your friend's
files" into "your friend's FLACs".

### The trap: the request marker is compared for equality

`browse_request_supports_v1` is `payload == BROWSE_RESPONSE_V1_MAGIC` — an exact
comparison of the whole payload, not a prefix test. So appending a filter block to
the existing request does **not** read as additive: an unpatched answerer sees a
payload that is not exactly `EBR1`, decides the requester is a legacy peer, and
replies in the pre-v1 format *without* AICH roots or Ember digests. A new client
browsing an old friend would get a worse answer than it gets today.

That is the same class of mistake the trailing-block trick avoids everywhere else,
and it does not apply here, because there is no field in front of the marker for a
block to trail.

### The prerequisite: the friend handshake cannot advertise anything

There is no feature or protocol version in `PeerCapabilities` — only `is_ember`,
`ember_hash` and `ember_pubkey`. The ext envelope degrades well for *unknown
sub-types* (they are logged and ignored, which is the whole point of it), but
nothing lets a sender know in advance whether a peer speaks one, so every new
sub-type is fire-and-forget. That is the same gap the DHT wire had until `PING`
and `PONG` began carrying a version range, and it wants the same shape of fix.

`OP_EMBER_HELLO` can carry it additively. `parse_ember_hello` reads
`version(1) ‖ flags(1) ‖ ember_hash(16) ‖ len-prefixed mod_version ‖
len-prefixed nickname ‖ optional ed25519_pubkey(32)`, taking every field from a
length prefix or a flag bit and **never checking that the payload ends** — so
bytes past the pubkey are already valid and ignored by every build. Only bit 0 of
`flags` is in use.

So: **set `flags` bit 1 and append a feature-bits field.** An older peer ignores
it; a newer peer learns what this one speaks before it sends anything. Do this
first, and the browse filter becomes a plain negotiated feature instead of an
optimistic guess with a fallback dance. It is also reusable by every friend-session
feature after this one, which is most of the value.

### Design

1. **Feature bits on the Ember hello.** `flags & 0x02` ⇒ a `u32` LE of feature
   bits follows the optional pubkey. Bit 0 = filtered browse. Surface it on
   `PeerCapabilities` beside `is_ember`. Pin the additivity the way the DHT block
   is pinned: a test asserting that a hello carrying feature bits parses
   identically on the field-for-field path an older build takes.
2. **A new request marker, sent only to a peer that advertised the bit.**
   `EBR2` ‖ filter block. Keep `browse_request_supports_v1`'s exact comparison
   untouched, and add an exact comparison for `EBR2`; do not loosen either to a
   prefix test, or the next addition inherits this same trap.
3. **Reuse `ValueConstraints` for the filter.** Its four content fields —
   `min_size`, `max_size`, `file_type`, `file_extension` — are exactly the
   browse filter, and its encoder already skips unknown tags, truncates
   over-long strings and writes *nothing* when the filter is empty. `extra_keys`
   is DHT-specific and stays unset. One encoder and one decoder then serve both
   the keyword walk and the browse, which is the only way the two stay agreed on
   what `Video` means — both must derive type from the extension with
   `search::index::infer_file_type`, as the DHT path already does.
4. **Apply the filter before the caps, and report the total.** Filtering after
   the 1000-file cap would reproduce the bug being fixed. The answer carries
   `total_matched` alongside the entries, so the dialog can say "showing 1000 of
   3400 — narrow the filter" instead of silently truncating. That is `FOUND_VALUE`'s
   `total_available` reasoning applied to a browse, and it is cheaper than paging.
5. **Rate-limit the answer, stamped before the work.** A filter makes the request
   cheap to send and the answer expensive to build — an index walk over every
   shared file — which is the wrong asymmetry to leave open. Copy
   `EMBER_FRIEND_CONTACT_SERVE_INTERVAL` exactly, including recording the stamp
   *before* the walk rather than after a successful send, so a friend whose writer
   queue is full cannot buy an unthrottled walk per request.

**Not a confidentiality change, and worth saying so explicitly** so nobody
"hardens" it later by accident: a mutual friend can already see every `shared`
file, `friends_only` included. What the filter changes is how much of that they can
retrieve per request, so the rate limit is about CPU and bandwidth, not about
exposure.

**Deliberately out of scope:** filtering the *vanilla* `OP_ASKSHAREDFILES` browse.
That one answers any peer, is off by default (`allow_shared_files_browse`),
excludes `friends_only`, and refuses explicitly with `OP_ASKSHAREDDENIEDANS`. A
filter there would let a stranger enumerate a library far past the single capped
packet the setting was reasoned about, which is a genuine exposure change and a
separate decision.

---

## Already better than KAD — do not "fix" these

Worth recording, because each one looks like a gap until you check the other side.

- **Republish cadence.** Keyword records live 24 h (`KEYWORD_RECORD_TTL`) and are
  re-announced every 12 h (`EMBER_KEYWORD_REPUBLISH`), against KAD's 24 h TTL and
  ~20 h republish. Ember has twice the margin.
- **Availability is counted, not claimed.** Ember's number is distinct Ed25519
  publishers of a signed record. KAD's `TAG_SOURCES` / `TAG_COMPLETE_SOURCES` is
  one peer's assertion about a swarm it cannot observe.
- **Streaming and completion ordering.** Partial batches stream while the walk is
  still running, the closing batch is rebuilt cumulatively so per-batch
  aggregates cannot under-count, and `search-complete` cannot fire before the
  final results. `dedup_streamed_batch` turns a re-emitted row into an
  availability update rather than a duplicate.
- **Empty `source_addresses` is deliberate.** A keyword hit identifies a file;
  source discovery is the separate slice-9 lookup at download time. Download,
  bulk download and link copying all work from the hash.

---

## Decisions on the record

### Searching by extension — a constraint, never a keyword

Settled: an extension is a **constraint**, never a keyword key.

Indexing it was the tempting version and it is the harmful one. A key holds
`MAX_RECORDS_PER_KEY` = 1000 records, `MAX_RECORDS_PER_PUBLISHER_PER_KEY` = 150 per
publisher, and `MD4("mp3")` would immediately be the hottest key on the network:
every mp3 anyone shares competing for a thousand slots on the twenty nodes closest
to one key. A full key *refuses* new records rather than evicting incumbents
(`a_full_keyword_never_evicts_an_incumbent`), so most of those publishes would be
rejected after spending publish budget; the results a searcher got back would be an
arbitrary three hundred files out of millions, which reads as broken rather than
thin; and it would park a permanent load hotspot on whichever peers are unlucky
enough to sit near the key — a concentration worth an attacker's attention. On top
of that it is one extra record per file against an
`EMBER_KEYWORDS_PER_FILE_ESTIMATE` of eight, so ~12% more keyword publish traffic
for the worst-behaved key we would own.

As a `ValueConstraints` field it costs no key, no publish traffic and no hotspot:
the searcher still walks a real word, and the responder drops everything that is
not an `.mp3` before it packs a page. Ember-only by construction, since only Ember
reads the block.

A bare `.mp3` typed on Ember or KAD now moves itself into the Extension box and
asks for a word, rather than running a search whose only hits can be the user's own
library.

**A quirk to know:** four-letter extensions already are keywords, by accident. The
publisher strips a trailing token only when it is *exactly* three characters and
three bytes, so `flac`, `webm` and `epub` are indexed while `mp3`, `mkv` and `avi`
are not. "flac" as a query has always worked; "mp3" never has. Nothing here changes
that, and the constraint makes both behave the same as a filter.

### Future wire additions cannot advertise in the version byte

The version byte is range-checked on receive
(`decode_message`, and [item 2](#2-wire-versioning-rejects-cleanly-and-now-advertises-but-still-cannot-route-around-old-peers)),
so raising `EMBER_DHT_VERSION` partitions the overlay on the day it ships
regardless of where `EMBER_DHT_MIN_VERSION` sits — the *other* side is what
refuses, and it is running the old range. Lowering the minimum only helps a build
that already speaks the higher number.

So a change that wants to stay compatible cannot advertise itself in the version
byte. It has to go where an existing decoder does not look: after the fields a
payload's parser reads at fixed offsets, or after a record's length-prefixed name.
Both `FIND_VALUE` and keyword records have that room, which is why the constraint
block and record metadata both landed without touching the version at all. (The
per-node result ceiling is searcher-local policy and touches no wire format, so it
never faced the question.)

A change that needs to alter an existing field still has no path but a bump. What
has changed is that the bump no longer has to be blind: `PING` and `PONG` now
carry the range each side can decode, by the same trailing-block trick and with
the version deliberately left alone, so a v5 encoder can ask per peer instead of
assuming. That only helps against peers running a build with the advertisement in
it — `ember_dht_version_advertisers` against verified contacts is how to tell
when that is most of them — so the flag day is now a measurable risk rather than
a certainty, which is not the same as gone.

### Explicitly not planned

- Hardcoded `seeds.txt` or DNS SRV seed lists — join stays the KAD
  rendezvous key, the bridges, gossip, and the persisted contact file.
- A rendezvous-hosted bootstrap pool. It leaks an identity-to-IP roster of
  every participant to whoever runs the server.

---

## Known limits (document for users / release notes)

- Multi-keyword search uses sparse DHT intersection (missing secondary
  keys are skipped) plus a filename match at emit time — not a strict
  worldwide AND of every keyword key.
- A peer serves only a few records per keyword *datagram* — five for a bare
  record, four for one carrying media, two in the worst case — but a searcher can
  now page a node until its key is exhausted, bounded by the per-node result
  allowance and the page ceiling that allowance sizes. Both are two-tier: a peer
  is held to a quarter of the budget while the walk still has somewhere to go, and
  may spend the rest of it once the shortlist is exhausted. See
  [Closed](#closed).
- A keyword search may name up to `MAX_FIND_VALUE_KEYS_TOTAL` (23) keywords, but
  only the first eight travel in the count-prefixed run that every build reads.
  The rest ride the constraint block, so a peer predating it intersects on eight
  and leaves the remainder to the filename match at emit.
- A keyword record may carry media (length, bitrate, codec, artist, album,
  title). A peer predating that block ignores it and reads the record correctly;
  a record published by a build predating it simply has none, so the columns stay
  empty until that publisher's next republish.
- One publisher may hold 150 records under any one keyword, network-wide (KAD's
  own allowance), so a user sharing more files than that with a word in common
  still will not have all of them findable under it.
- Gossip contacts are unverified until the node hears from them directly
  (same as Kademlia). Admission is bounded by the diversity caps in
  [`scale.rs`](../src-tauri/src/network/ember/dht/scale.rs), but there is
  no reputation scoring on gossip itself.
- The diversity caps now apply to *residents* as well as to admission.
  `RoutingTable::enforce_scale_quotas` runs on the maintenance tick and
  demotes over-quota contacts to their bucket's replacement cache once the
  table has grown a margin past the tier boundary (13 verified for `Small`,
  100 for `Established`, against admission's 10 and 80). Before it, a peer
  admitted under the cold-start allowance held its share of a bucket for the
  life of the process — a contact that answers liveness pings is never stale,
  never faults out, and is never displaced — and bucket occupancy is
  geometric, so that share sat in the bucket deciding most of what
  `find_closest` serves. The margin and the one-way ratchet on the enforced
  tier are what stop a table on a boundary demoting and re-admitting the same
  contacts. Demotion is not eviction: the cache is where a contact the caps
  turn away already waits, and promotion brings it back if a slot frees up.

  Those two were not sufficient on their own, and the gap is worth recording
  because it made the whole pass a no-op in the case it was written for.
  Demotion moves contacts out of the buckets, and `scale()` counts bucket
  residents — so pruning a crowded table drops the very reading that chose the
  tier, and `promote_cached_contacts`, which runs immediately afterwards in
  the same tick, read the loosened tier and re-admitted what had just been
  demoted. The ratchet stopped `enforce_scale_quotas` re-running; it did
  nothing about the promotion pass. Admission and promotion now read
  `RoutingTable::admission_scale` — the stricter of the live tier and the
  enforced one — and `promotion_does_not_re_admit_what_the_quota_pass_just_demoted`
  pins it.
- Download content transfer is still eD2K c2c (see item 1 above).
- BLAKE3 verify runs when an expected digest is available (search hit, DHT
  source record, known.met / library). Deep links without a digest still
  complete and hash for future share.

---

## Future improvements

Ordered roughly by leverage. None block a release if the items above are
settled.

### Bootstrap and network health

- ~~Monitoring for rendezvous-key health: how many nodes are listed, how
  often a cold lookup returns nothing.~~ Surfaced as `ember_dht_rendezvous_*`
  on the Ember page (listed / lookups / empty).
- ~~Weight a gossip contact by whether the leads its introducer gave us turned
  out to be reachable.~~ Done — see the Sybil note under Hardening and ops.
- Stronger observed-IP / STUN interplay under awkward NATs (needs soak
  data).
- Shard the rendezvous key space. The derivation is already versioned for
  this; it matters once one KAD bucket's 1000-entry cap is in sight.

  **Its trigger is now observable, and the obvious gauge could not see it.**
  `ember_dht_rendezvous_last_peers` counts what one lookup *returned*, and a
  KAD source search stops querying at `SOURCE_SEARCH_STOP_THRESHOLD` (20) — so
  it saturates two orders of magnitude below `MAX_ENTRIES_PER_KEY` (1000) and
  can never report approaching it. That gauge is a bootstrap canary ("did a cold
  lookup find anyone"), not an occupancy one.

  What can see it is the storer's own load byte, which already arrives on every
  advert we place and is the same signal the keyword publish path backs off on
  at 90. `ember_dht_rendezvous_key_load` is the highest any storer has reported
  for the rendezvous key this session — highest rather than latest, because the
  twenty nodes closest to the key fill at different rates and the first one to
  run out is what decides whether the advert still lands. Read 90 or above as
  due.
- Table quality: tune announce versus bucket-refresh balance under load.

### Search and publish

The gaps against KAD's *keyword search* specifically are closed — wire-side
constraint filtering, record metadata and the per-node result ceiling are all in
[Closed](#closed). This list stays the home for indexing ideas that are not gaps
against KAD.

- Richer keyword indexing (stemming, more than space-split tokens) if
  recall lags KAD on real libraries.

  **That condition is now measured**, which it was not: the search-quality
  averages describe how a walk ran — nodes answered, milliseconds, records
  returned — not whether Ember found the files KAD did. For searches where both
  legs actually ran (`ember_dht_recall_searches`, the denominator), each file is
  scored as found by both, by KAD only, or by Ember only. `both` climbing with
  the two `_only` counts near zero is the tokenizers agreeing and the case for
  doing nothing; `kad_only` pulling ahead is the lag this item is conditional
  on, and by how much.

  `ember_only` is the half worth having before anyone tunes the Ember tokenizer
  toward KAD's — Ember already indexes four-letter extensions that KAD strips
  (`flac`, `webm`, `epub`), so the two are not ordered by quality and "fixing"
  one toward the other can lose recall. Presence rather than availability, so
  Ember counting publishers where KAD counts a claimed swarm does not matter;
  the sample is bounded by what `note_dht_availability` tracks, which caps the
  cost of a diagnostic nobody is waiting on.
- ~~Clearer search UI when Ember is joining (empty table) versus
  enabled-but-quiet.~~ Search, the Ember page, and the status bar wait for
  a verified contact; gossip-only no longer looks connected. After the
  join timeout with still-zero verified peers, Search shows the muted
  no-peers hint.
- Storer-side replication telemetry. The publish side logs an
  `Ember publish cycle` heartbeat each minute; maintenance now logs an
  `Ember replication cycle` heartbeat as well (see
  [Closed](#closed)).

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
- **Sybil pressure: what is bounded and what is not.** Worth stating plainly,
  because the two halves of the overlay are in very different shape.

  The *routing table* is anchored on something scarce. Its caps are keyed on
  address and /24, not on identity, so a keypair buys nothing on its own — and
  `enforce_scale_quotas` closed the last hole, where a share admitted under the
  cold-start tier was kept for the life of the process.

  **Gossip is now scored, which was the remaining gap here.** Naming a contact
  was free and unpriced: a peer could hand out addresses that never answer,
  forever, for the cost of one frame, and each name cost us a probe — a
  datagram, usually a Noise handshake behind it, and a slot in the in-flight
  ping map a real lead then could not have. One `FOUND_NODE` carries up to 17 of
  them, and eleven consecutive `Too many active Ember searches` in two
  milliseconds is what that looks like from inside.
  [`dht/gossip.rs`](../src-tauri/src/network/ember/dht/gossip.rs) tracks, per
  introducer, how many of the leads we *probed* went on to answer, and trickles
  the probes for one whose leads almost never do.

  Four properties are deliberate, because each is a way this could cost more
  than the problem:

  - **An introducer with no record is funded.** The first contacts a node ever
    hears about arrive by gossip, so a scheme that must earn trust before
    granting any closes the only door in.
  - **It never refuses a contact.** Only probing is rationed; the table's own
    caps still decide what may hold a slot, and a lead that answers is worth
    having however it arrived.
  - **It is not consulted while the table is starved.** A node with nothing has
    to try everything: probing junk costs bandwidth, failing to join costs the
    overlay.
  - **A rationed introducer is still sampled**, one lead in eight, and tallies
    halve past 64 outcomes — so a peer whose contacts went dark in a netsplit
    recovers instead of being written off for the life of the process.

  Attribution starts at the probe, not at the naming, or an introducer would be
  charged for our own budget running out. An answer is credited on any signed
  frame rather than only a `PONG`, because the question a probe asks is whether
  the address is real. Diagnostics: `ember_dht_gossip_leads_rationed` and the
  introducer gauge beside it separate "nobody is naming anyone reachable" from
  "a few peers are naming a great many unreachable ones".

  What this does *not* price is identity rotation: a Sybil can spend a fresh
  keypair per round to reset its record. That costs it a keypair per round of
  leads and buys it no more than it had before, so it is a rate limit rather
  than a defence — the volume half still needs something scarcer, which is the
  proof-of-work note below.

  The *store* is not, and its caps cannot be fixed the same way. They —
  `MAX_RECORDS_PER_PUBLISHER_PER_KEY` (150), `MAX_KEYS_PER_PUBLISHER` (6,250),
  `MAX_BYTES_PER_PUBLISHER` (6 MiB) — are all keyed on `publisher_key`, so a
  Sybil spending one identity per record is never over its share and the rule
  never engages. The comments on those constants explain why the obvious fix is
  worse than the gap: a per-publisher rule that *moves* capacity rather than
  withholding it is an eviction primitive, since an arrival holding nothing
  always outranks an incumbent. Attributing keyword records to the sender's
  address instead is what closed the equivalent hole for *source* records, but
  it cannot be extended, because storer-side replication legitimately relays
  many publishers' records from one address — the author/relayer split is
  load-bearing.

  **The aiming is the half that would hurt, and binding it was tried and
  rejected.** Both eviction rankers order victims by XOR distance from our own
  node ID, so a publisher choosing keys next to us makes every honest key look
  further out and therefore evictable. For keyword records that choice is free:
  the word is not on the wire, so `key == keyword_hash` is the only check
  available and the publisher writes both sides of it.

  It *is* closable. The file name is on the wire, signed beside the key, and the
  publish loop derives its keywords from that name with `extract_keywords`, so a
  storer can recompute the set and require the key to be one of its hashes. That
  was implemented, tested and then backed out; it is in `git stash` if the threat
  ever becomes real. Two reasons it is not worth shipping now:

  - The benefit does not reach the user. The store is what a node *serves to
    others* — a user's own searches walk outward, and their own records enter
    through `store_own_record`, which never touches this path. Poisoning costs
    the network aggregate index quality, not the operator anything they would
    notice, and the magnitude is already bounded by `MAX_STORE_BYTES` and
    `MAX_STORE_IDENTITIES_PER_ADDR` (8).
  - The cost lands on planned work. It makes record *validity* depend on the
    tokenizer, so the "richer keyword indexing (stemming, more than space-split
    tokens)" item under Search and publish stops being a drop-in change: new
    publishers' records would be refused by every storer still on the old
    tokenizer. Today that improvement needs no version bump. Binding the key
    turns it into a wire break of the same class that forced v3 and v4.

  **The cheap precursor is now shipped, as measurement rather than enforcement**:
  `ember_dht_keyword_key_off_name` counts verified inbound keyword records whose
  key no word in their own signed name hashes to (`name_hashes_to_key`, applied
  in `accept_record`). Zero-risk, because nothing is refused on the answer and so
  no record's validity depends on the tokenizer.

  Where it is counted is the load-bearing part. Past `from_wire` and past the
  replay collapse, so unsigned junk cannot appear in it and a retransmit storm
  cannot inflate it into a publisher that looks like it aimed thousands of times;
  before the proximity gate and the store's caps, because the question is what
  publishers are doing rather than what we happened to keep.

  Read the shape rather than the number. Climbing against a few publishers is
  someone choosing keys instead of deriving them, which is the evidence that
  would justify enforcing the rule. Climbing broadly across publishers is far
  more likely to be our own two tokenizers having drifted apart — the second
  reason this counter is worth having, since the stemming item above is exactly
  the change that would cause that.

  Volume is the other half, and that genuinely needs something scarcer than a
  keypair: a proof-of-work constraint on `BLAKE3(ed25519_pub)` is the only
  measure that prices identity directly, and being a one-time cost it prices
  mass Sybils rather than a hundred-identity one. The honest alternative is to
  accept the bound and rely on the byte ceiling and the per-address STORE cap to
  keep the damage to bandwidth and memory rather than correctness. Nothing here
  is a correctness break today: a flood cannot forge a record, displace a validly
  signed one, or make a search return something unsigned.

  **"If abuse appears" is now a number rather than a judgement.**
  `MAX_STORE_IDENTITIES_PER_ADDR` (8) is the only cap keyed on something a
  keypair cannot mint, so it is the only place a rotating-identity flood shows
  up as a refusal rather than as ordinary traffic — and every refusal in
  `protection.rs` used to land in one lumped `dropped_rate`, itself never
  surfaced (`dropped_rate_limited` carried a stale `#[allow(dead_code)]` saying
  it was "kept for the diagnostics surface to report drops"). Both are now on
  `/ember`: `ember_dht_store_addr_ceiling` for that cap alone and
  `ember_dht_rate_limited` for the total. The total climbing while the ceiling
  stays flat is pacing; the two climbing together is the case proof-of-work
  would be for.

### Product / UX

- Migration guidance when turning the DHT on alongside existing KAD/eD2K.

---

## Closed

Every item here is finished. They were each carried as a numbered section with its
own rationale; that detail is in git history rather than deleted, and the wire-level
outcomes are in the specification. Kept as a ledger so this file reads as a plan.

**From the KAD comparison (Aug 2026)** — the whole pass is done:

- The serving ceiling — done, wire v3.
- Per-publisher keyword capacity.
- Stream search results as they arrive — done in 1.5.3.
- Firewalled sources are discoverable but not dialable.
- The pre-endorsement buddy trailer — retired rather than fixed.
- Persist the Ember source publish schedule.
- Storer-side replication costs more than it buys — settled, with an
  `Ember replication cycle` heartbeat now logged each maintenance tick.
- Contact encoding wasted 18% of every response — done, wire v3.
- Search slots were held by searches that had finished.
- A truncated `nodes_ember.dat` could still shrink itself away.
- Transport hardening — one done, two decided against.
- Observability gaps, and the items outside the DHT proper.

**From the search comparison (Sep 2026)** — the whole pass is done, and none of the
wire additions needed a version bump:

- `FIND_VALUE` carries no constraints — done additively, and bumping would have
  been actively wrong: the peers a bump exists to reach are the ones that would
  refuse the frame carrying it.
- Keyword records carry no metadata — media now rides the record.
- Per-node result ceiling was an eighth of KAD's.
- A corrected digest does not reach the row.
- "Sources" meant two different things in one column.
- Smaller items: surplus keywords ride the constraint block past
  `MAX_FIND_VALUE_KEYS`; tab overflow sheds within an origin class instead of
  dropping every Ember row; spam heuristics needed no Ember exemption; and
  `CancelEmberSearch` was closed by the shared `release_ember_search_state`
  teardown, with the buffered-batch half turning out to be unreachable rather
  than unfixed.

**From the standing list:**

- Bootstrapping from a friend — a friend now hands over the contacts it holds
  (`EMBER_EXT_DHT_CONTACT_REQ` / `EMBER_EXT_DHT_CONTACTS`), asked
  least-recently-first, answered only from verified contacts, and the retry
  interval no longer backs off while the table is starved.
- `store_attributed` binds the key but not the author or the date — all three are
  now derived from the one signed body rather than trusted from the caller.

---

## Carried over from the 2026-08-18 audit

That audit's remediation plan closed all 33 of its findings and has been removed;
these are the parts that outlived it.

**`NetworkState` is still one struct on one task.** The parameter bundling and the
6,251-line move out of `network/mod.rs` both landed, but the single-task ownership
model that produced the original starvation bug is unchanged. Splitting
`NetworkState` per stack and giving each stack its own task with an explicit message
boundary is a redesign rather than code motion: it cannot be compiler-verified the
way that pass was, and it needs integration testing against live peers. **This
remains the single most pressing architectural risk in the codebase.** The
groundwork is in place — `command.rs` is separable and `NetworkDeps` gives the entry
point a real signature.

**The clippy backlog is gone, which makes a CI change actionable.** That plan
recorded 123 remaining library warnings, down from 415. `cargo clippy --all-targets`
now reports **zero** at default lint levels. [`ci.yml`](../.github/workflows/ci.yml)
says to tighten the lint step to `-- -D warnings` "once that backlog is at zero",
and the condition is now met. The crate-level baseline in `lib.rs` still allows
exactly four families, each with a written justification; anything outside those
four is expected to stay at zero.

## Working notes for this tree

Not Ember-specific, but they cost time to rediscover and had no other home.

- `src-tauri/src/network/mod.rs` is large enough that repo-wide search tools may
  skip it on size. Search it explicitly if a result matters —
  `Select-String -Path ...\network\mod.rs` — or you can draw the wrong conclusion.
  This has already produced one false "dead code" finding.
- The shell here is PowerShell: chain with `;`, not `&&`, and `head`/`tail` do not
  exist. Backticks are the escape character, so they need care inside patterns.
- Adding a `coded("...")` error requires `error_<code>` in all nine
  `messages/*.json`, or an entry in `KNOWN_UNTRANSLATED` in
  `scripts/error-codes.test.mjs`, or `npm test` fails.

---

## Quick reference

| Area | Location |
| --- | --- |
| DHT engine / wire | `src-tauri/src/network/ember/dht/` |
| Network loop / publish / search drivers | `src-tauri/src/network/mod.rs` |
| Adaptive abuse limits | `src-tauri/src/network/ember/dht/scale.rs` |
| Dormant native transfer | `src-tauri/src/network/ember/transfer.rs` |
| Overlay enable flag | `ember_native_enabled` — always on, with no UI control anywhere |
| User-facing status | `/ember` (Ember Network page) |
| Library publish badges | `shared_ember` on `FileInfo` → Library "Shared" column |

Protocol constants live in
[`dht/mod.rs`](../src-tauri/src/network/ember/dht/mod.rs): 128-bit node IDs
(BLAKE3 of the Ed25519 public key), k = 20, α = 5, wire version 4.

`MAX_CONTACTS_PER_RESPONSE` is 20 but is still not reachable: `encode_contact_list`
trims by bytes, and at 71 bytes per IPv4 contact (7 address + 32 Noise key + 32
Ed25519 key) 17 fit the 1253-byte payload budget — up from 14 while contacts also
carried a redundant 16-byte ID. A `FOUND_NODE` therefore never carries a full
k-bucket. The contact-encoding change that got it from 14 to 17 is in
[Closed](#closed).
