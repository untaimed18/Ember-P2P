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

Everything except [item 2](#2-keyword-records-carry-no-metadata) is done. The
wire additions turned out not to need a version bump at all — see item 1 for why
bumping would have been actively wrong — so what is left is item 2, which is
blocked on something else entirely: media metadata is not persisted anywhere to
publish *from*.

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

**Done.** `ValueConstraints` (min size, max size, file type) rides an optional
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

## 2. Keyword records carry no metadata

A record body is type, keyword hash, file hash, Ember digest, size, name. KAD
rows arrive with media tags, so on an Ember-only hit the Length, Bitrate, Codec,
Artist, Album and Title columns are always empty, and there is no rating or
comment. `build_ember_keyword_built` sets `media`, `rating` and `comment` to
`None` because there is nothing on the wire to fill them from.

**Plan.** Extend the keyword record with an optional trailing tag area and publish
the media fields. The record side is additive on the same terms item 1 turned out
to be: `parse_unverified` reads the name from its length prefix and does not
length-check a keyword record, so an older build parses a longer body correctly
and ignores the tail, and a storer relays the bytes it was given. The name budget
has to charge the tag area, the way the channel trailer already does.

**Blocked on where the metadata comes from.** "the media fields the library
already has" was wrong — the library has none. `extract_media_metadata` in
`commands/sharing.rs` is an on-demand `lofty` header read from a path, exposed for
one file at a time by the `get_file_media_metadata` command, and nothing persists
the result. Publishing it needs either a lofty read per file inside the publish
tick (a blocking disk read on the network task, repeated every republish cycle) or
somewhere to keep it — a `known.met` tag block or a table, filled by a background
pass over the library. The second is the right shape and is most of the work.

Worth noting this is not a gap against KAD as such: our own `build_keyword_entry`
does not publish media tags either, so KAD-to-KAD is no better. Ember rows read
empty where a *server* result would be populated, and doing it here would put
Ember ahead rather than level.

**Watch for:** anything added is publisher-controlled text that lands in the UI
and in sort keys, so it needs the length caps and sanitisation the eD2K tag path
applies, and it must not become a second name field that disagrees with
`file_name`.

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
- **Extensions are not keywords.** Publishers strip a trailing three-character,
  three-byte token before indexing (`tokenize_keywords`), so `.mp3` and `.mp4`
  walk a key almost nobody has written. The search page now says so. A real fix
  means an extension or type index key, which diverges from eMule's keyword
  index — decide whether that divergence is wanted before building it.
- ~~Spam heuristics have no Ember exemption.~~ **Nothing to do — checked.**
  `origin_is_kad_publisher_only` guards exactly two things, the hot-IP
  accumulation loop in `absorb` and `source_concentrated`, and both walk
  `source_addresses`. Ember keyword rows carry none, so neither can fire on them
  and widening the predicate would be dead code. The batch
  same-name-many-hashes rule *can* flag an Ember row, but it is not gated by
  that predicate and treats KAD identically, so it is not an Ember gap.
- **`CancelEmberSearch` is incomplete.** It clears `ember_search` but not
  `ember_keyword_searches` or buffered result batches. Debug-only command; the
  user-facing cancel path (`cancel_search_request`) is correct.

---

## What is left

1. **Item 2** (record metadata), once there is somewhere to publish media from.
   The record and wire work is small; persisting the metadata is the task.
2. The extension-index question under item 6, which needs a decision about
   diverging from eMule's keyword index before it needs code.

## A note on future wire additions

The version byte is range-checked on receive
(`decode_message`, and [ember-dht.md item 2](ember-dht.md#2-wire-versioning-rejects-cleanly-but-cannot-negotiate)),
so raising `EMBER_DHT_VERSION` partitions the overlay on the day it ships
regardless of where `EMBER_DHT_MIN_VERSION` sits — the *other* side is what
refuses, and it is running the old range. Lowering the minimum only helps a build
that already speaks the higher number.

So a change that wants to stay compatible cannot advertise itself in the version
byte. It has to go where an existing decoder does not look: after the fields a
payload's parser reads at fixed offsets, or after a record's length-prefixed name.
Both `FIND_VALUE` and keyword records have that room, which is why items 1 and 3
landed without touching the version at all. A change that needs to alter an
existing field still has no path but a bump, and that is still the standing gap.
