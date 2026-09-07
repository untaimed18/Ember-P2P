# Ember DHT search — plan to match and beat KAD

Working plan for the search half of the overlay, written after a constant-for-constant
comparison of the Ember keyword path against this repo's own KAD keyword path
(Sep 2026). The goal is the one stated for the overlay generally: **as good as KAD
on every axis, better where we can afford to be.** Search is the axis where it is
currently behind.

Companion to [ember-dht.md](ember-dht.md), which is the standing work log for the
overlay as a whole; its
[Search and publish](ember-dht.md#search-and-publish) list stays the home for
indexing ideas that are not gaps against KAD.

Code: [`ember/dht/search.rs`](../src-tauri/src/network/ember/dht/search.rs),
[`ember/dht/messages.rs`](../src-tauri/src/network/ember/dht/messages.rs),
[`ember/dht/publish.rs`](../src-tauri/src/network/ember/dht/publish.rs),
`build_ember_keyword_built` in [`network/mod.rs`](../src-tauri/src/network/mod.rs),
[`search/merge.rs`](../src-tauri/src/search/merge.rs).

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

## Closed in this pass (Sep 2026)

Every item here is done and the extension question is decided. None of the wire
additions needed a version bump — see item 1 for why bumping would have been
actively wrong. What remains is one *new* feature rather than a gap, now designed
rather than sketched:
[filter the friend browse on the wire](#next-filter-the-friend-browse-on-the-wire--designed-not-started).
The `CancelEmberSearch` tidy that used to be listed under item 6 is closed too,
though not by anything in this pass — see there for which half was fixed elsewhere
and which half turned out to be unreachable.

The two kinds of change this overlay is for, and which each item was:

- **Parity with KAD**, where KAD was the baseline and Ember was behind: the
  per-node result ceiling (item 3), wire-side constraints (item 1), the
  complete-source count and search progress.
- **Ahead of KAD**, doing something eMule has no answer for: media on keyword
  records (item 2), a digest corroborated across publishers (item 4), availability
  counted from signatures rather than claimed (item 5).

- **`complete_sources` was `0` on every Ember row**, which every consumer reads as
  "none": the Min Complete filter silently dropped all of them, the Complete
  column read as unknown, and `sort_search_results` ranks that field first and so
  put Ember last. Now the distinct-publisher count, which is a floor rather than a
  guess — only complete public shares are keyword-published
  (`is_ember_publishable`).
- **No progress for an Ember-only search.** KAD emits `search-progress` (nodes
  contacted, results so far, phase) every second; Ember emitted nothing, so a walk
  on a cold table sat behind a bare spinner for much of its 60 s cap. Now reports
  the same three fields, reusing KAD's phase labels.

---

## 1. `FIND_VALUE` carries no constraints — done, and without a version bump

**Highest leverage item here.** KAD encodes the query's size / type / availability
constraints into the search request (`build_search_expression_with_node`), and the
responder evaluates them against each entry's tags *before* it truncates to its
page (`search_keywords_page` with `matches_search_expr_for_tags`). Ember sends
keyword hashes and a paging offset and nothing else (`build_find_value`), then
applies `result_matches_client_filters` at emit time.

The cost is not cosmetic. A search has a 300-file budget (`MAX_SEARCH_RESULTS`)
and a 1200-blob remote ceiling; with a tight filter, both can be spent entirely on
records that are then discarded, while the matching files sit behind the peers the
walk never got to. `kad/messages.rs` says this outright in the comment above its
own constraint encoding — a purely client-side filter cannot recover what the
remote already truncated away.

**Done.** `ValueConstraints` — min size, max size, file type, file extension, and
the keyword hashes that would not fit the count-prefixed run — rides an optional
TLV block trailing the `FIND_VALUE` payload; the responder applies it in
`intersect_find_value_records` *before* packing, so `total_available` counts
matches and a searcher pages through matches rather than through positions it
would discard. A key where nothing matches is answered with contacts, exactly as
a key we do not hold is. The searcher keeps `result_matches_client_filters` at
emit as defence in depth, because the block is advisory.

**Availability is deliberately not sent.** KAD can filter on it because its
keyword entries carry a publisher-claimed `TAG_SOURCES`; an Ember record carries
no source count, and the number the search page shows counts distinct publishers
*across the network*, which no single responder can see. A constraint no
responder could evaluate honestly is worse than none.

**The version did not move, and must not have.** The plan assumed this needed a
bump that could lower `EMBER_DHT_MIN_VERSION` instead of raising both. That was
wrong in a way worth recording: `decode_message` range-checks the version byte on
*receive*, so a frame stamped 5 is refused outright by every v4 build — bumping
would have partitioned the overlay, which is the opposite of graceful. What makes
this additive is the decoder, not the version: `MSG_FIND_VALUE` has always
required only a *minimum* length and read its fields at fixed offsets, so bytes
past `start_position` have always been valid and ignored. The block trails them,
and an unconstrained query encodes byte-for-byte as it did before.

Type inference is the one thing shared across the wire: both sides derive it from
the name's extension with `search::index::infer_file_type`, so they cannot
disagree about what `Video` means.

## 2. Keyword records carry no metadata — done

A record body is type, keyword hash, file hash, Ember digest, size, name. KAD
rows arrive with media tags, so on an Ember-only hit the Length, Bitrate, Codec,
Artist, Album and Title columns are always empty, and there is no rating or
comment. `build_ember_keyword_built` sets `media`, `rating` and `comment` to
`None` because there is nothing on the wire to fill them from.

**The reader shipped one commit before the writer, on purpose.** A keyword
record may now carry an optional media block after its name — `version(1)` then
`tag/len/value` triples for duration, bitrate, codec, artist, album and title —
parsed into `SignedRecord::media` and through to the row's `media`. Additive on
the same terms item 1 turned out to be: `parse_unverified` reads the name from its
length prefix and does not length-check a keyword record, so an older build parses
a longer body correctly and ignores the tail, and a storer relays the bytes it was
handed. The name budget charges the block, the way the channel trailer already
does, and the signature covers it so a relay cannot rewrite it.

Shipping the reader before the writer is the right order for a wire change: by the
time anything publishes a block, the builds that will receive it already
understand it.

**Publishing it needed somewhere to publish *from*.** "the media fields the library
already has" was wrong — the library had none. `extract_media_metadata` was an
on-demand `lofty` header read, exposed one file at a time by
`get_file_media_metadata`, and nothing kept the result.

It is now persisted in `known.met` under Ember-only tags `0xE6`–`0xEC`: duration,
bitrate, codec, artist, album, title, and a **scanned marker**. The marker is the
load-bearing part — most of a library has no media, so "probed, found nothing" has
to be as durable as a positive result or every archive is re-read on every pass to
learn the same nothing.

The probe rides the keyword publish tick rather than a second schedule beside it,
and is held to `MEDIA_PROBES_PER_TICK` (8) rather than to the tick's own budget.
That second bound matters: the probe is awaited from the network `select!`, so its
duration is time eD2K, KAD and Ember are all suspended, and the tick can select up
to 96 files — 96 header reads on a slow or networked disk is a visible stall in
every transfer. A file whose turn has not come publishes without media now and
gains it on republish, so nothing is lost by going slower, and a library of several
thousand is still fully probed inside one republish interval. Each file is read once,
off-thread, ever; a rehash carries the result forward, because rehashing does not
change the bytes' media.

Not a gap against KAD as such: our own `build_keyword_entry` does not publish media
tags either, so KAD-to-KAD is no better. Ember rows read empty where a *server*
result would be populated, and this puts Ember ahead rather than level — the second
kind of change this overlay is for.

**Watch for:** the publisher-supplied strings are capped
(`MEDIA_MAX_CODEC_BYTES` / `MEDIA_MAX_TEXT_BYTES`), refused rather than shown when
over-long, and required to be real UTF-8 — they decide sort keys and column widths.
They must not become a second name field that disagrees with `file_name`.

## 3. Per-node result ceiling is an eighth of KAD's — done

Ember admits `MAX_RESULTS_PER_NODE` = `MAX_SEARCH_RESULTS / 4` = **75** distinct
blobs from one node, paged at roughly 5 records per datagram
(`RECORDS_PER_UNFRAGMENTED_PAGE`) for at most `MAX_PAGES_PER_NODE` = 15 follow-ups.
KAD fetches `FETCH_PAGE_SIZE` = 200 per page for up to `MAX_PAGES_PER_PEER` = 3,
so **600** from a single peer.

That gap costs nothing where twenty nodes hold a keyword and everything where one
or two do — which is what a young overlay, or any unpopular keyword on a mature
one, looks like. The comment on `MAX_PAGES_PER_NODE` already notes KAD does not
ration this at all.

**Done** as a two-tier rule: the quarter share while the shortlist holds an
unqueried hop *or* a query is outstanding, the remainder of the budget once
neither is true. With nothing left to walk to there is no hop the extra records
can crowd out, which is the whole reason the share existed.

The page ceiling had to move with it, or round trips stay the binding limit. That
half is earned rather than granted — past the base ceiling a node gets one more
page per page's worth of records it has actually delivered — because handing an
exhausted shortlist the full page allowance outright would have quadrupled what a
peer serving one record per page while claiming sixty thousand can buy.

## 4. A corrected digest does not reach the row — done

`merge_into` fills `ember_file_hash` only when the existing one is empty. The
closing batch deliberately rebuilds from *every* record the walk gathered, so it
carries the plurality digest across all publishers — but it arrives as a resight,
so a digest already set from an earlier slice wins. A file whose publishers
straddled two batches therefore keeps a slice-local plurality.

This one matters more than its size suggests: the digest is what a transfer
*enforces* at completion, and getting it wrong fails verification on every retry.
The corroboration rule (two agreeing publishers before automatic seeding) exists
precisely to prevent that, and this bypasses it.

**Done.** The corrected value already reached the UI —
`emit_search_resight_updates` emits whole rows — so only the merge rule needed
changing. `pick_ember_digest` / `pickEmberDigest` now let a later network digest
replace an earlier one, while a `Local` digest (computed from the bytes on this
disk) still wins over any network claim. Both sides are pinned by
`ember_digest_cases` in the shared merge contract.

## 5. "Sources" means two different things in one column — done

Ember's `availability` is publishers; KAD's and the servers' is a swarm estimate.
The column is labelled Sources for both, and the default sort is Sources
descending, so an Ember hit with three publishers ranks below a KAD hit claiming
fifty regardless of which is actually fetchable. Min Sources reads as "minimum
publishers" for an Ember-only row, both in the UI and in the backend
`min_availability` filter.

**Explained rather than normalised**, because normalising would mean inventing a
swarm size for an Ember record and that number is genuinely unknown. An
Ember-bearing row's Sources cell now carries a tooltip saying the count is
confirmed publishers that each hold the whole file, with different wording when
the row was also found elsewhere and the number is the highest any one network
reported. Sorting by Sources breaks an exact tie toward the Ember row, on the
grounds that N counted signatures is better evidence than N claimed peers.

Still open by design: the primary sort order. An Ember row with three publishers
sits below a KAD row claiming fifty, and there is no honest conversion between
them.

## 6. Smaller items

- ~~More than eight keywords lose wire intersection.~~ **Done.**
  `MAX_FIND_VALUE_KEYS` stays 8 and has to: a peer refuses a higher count at
  decode and answers nothing, so raising it would cost the whole query timeout
  against older builds. The surplus rides in the same constraint block instead
  (`MAX_FIND_VALUE_EXTRA_KEYS`, 15, bounded by the one-byte TLV length), and the
  responder merges both runs before intersecting, holding the total to
  `MAX_FIND_VALUE_KEYS_TOTAL`. `OR` queries still send no extra keys, because
  intersecting them would be AND semantics.
- ~~Tab overflow evicts Ember rows first.~~ **Done.** Rows are ranked within
  their own origin class before shedding
  ([`searchOverflow.ts`](../src/lib/searchOverflow.ts)), so each class sheds its
  own weakest instead of Ember losing every row to a swarm estimate it cannot be
  compared against.
- ~~Extensions are not keywords.~~ **Decided** — they stay out of the index and
  travel as a constraint instead. See
  [Searching by extension](#searching-by-extension--decided-and-why-not-as-a-keyword).
- ~~Spam heuristics have no Ember exemption.~~ **Nothing to do — checked.**
  `origin_is_kad_publisher_only` guards exactly two things, the hot-IP
  accumulation loop in `absorb` and `source_concentrated`, and both walk
  `source_addresses`. Ember keyword rows carry none, so neither can fire on them
  and widening the predicate would be dead code. The batch
  same-name-many-hashes rule *can* flag an Ember row, but it is not gated by
  that predicate and treats KAD identically, so it is not an Ember gap.
- ~~**`CancelEmberSearch` is incomplete.**~~ **Closed, and it was closed
  elsewhere.** The claim was that it clears `ember_search` but not
  `ember_keyword_searches` or buffered result batches. The first half is gone:
  cancel and the expiry backstop now share `release_ember_search_state`, which
  drops the keyword entry, clears `ember_pending` and re-checks
  `search-complete` — it had to, because `alloc_id` only refuses ids still
  present in `searches`, so releasing the slot alone let the same id be handed
  to an unrelated walk whose records were then delivered into the abandoned
  caller's map. That is a worse bug than the one this bullet described, and
  fixing it subsumed it.

  The second half is unreachable rather than fixed, which is worth writing down
  so nobody adds a guard for it. Buffered batches do not survive between ticks:
  the sweep's streaming step queues them and its emit step drains all of them
  with `mem::take` in the same tick, and the sweep cannot skip that step while
  the buffer is non-empty because `ember_pending_keyword_results.is_empty()` is
  one of the conditions in its own idle early-return. The one queue that does
  cross a tick is the closing batch from `maybe_finish_ember_search` — and that
  removes the search from `ember_keyword_searches` before pushing, so a cancel
  arriving behind it finds no keyword entry, takes neither branch, and leaves
  the batch to emit and clear `ember_pending` on its own terms.

  Worth noting the command is no longer debug-only either: a channel presence
  probe that outruns its timeout cancels through it (`find_raw_keys_within`),
  which is why the shared teardown matters rather than a reason to leave it
  thin. Nothing on that path queues keyword batches, so the unreachable half
  stays unreachable.

---

## Searching by extension — decided, and why not as a keyword

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

## Next: filter the friend browse on the wire — designed, not started

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

## A note on future wire additions

The version byte is range-checked on receive
(`decode_message`, and [ember-dht.md item 2](ember-dht.md#2-wire-versioning-rejects-cleanly-and-now-advertises-but-still-cannot-route-around-old-peers)),
so raising `EMBER_DHT_VERSION` partitions the overlay on the day it ships
regardless of where `EMBER_DHT_MIN_VERSION` sits — the *other* side is what
refuses, and it is running the old range. Lowering the minimum only helps a build
that already speaks the higher number.

So a change that wants to stay compatible cannot advertise itself in the version
byte. It has to go where an existing decoder does not look: after the fields a
payload's parser reads at fixed offsets, or after a record's length-prefixed name.
Both `FIND_VALUE` and keyword records have that room, which is why items 1 and 2
landed without touching the version at all. (Item 3 is searcher-local policy and
touches no wire format, so it never faced the question.)

A change that needs to alter an existing field still has no path but a bump. What
has changed is that the bump no longer has to be blind: `PING` and `PONG` now
carry the range each side can decode, by the same trailing-block trick and with
the version deliberately left alone, so a v5 encoder can ask per peer instead of
assuming. That only helps against peers running a build with the advertisement in
it — `ember_dht_version_advertisers` against verified contacts is how to tell
when that is most of them — so the flag day is now a measurable risk rather than
a certainty, which is not the same as gone.
