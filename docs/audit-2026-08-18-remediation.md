# Multi-agent audit — remediation plan (2026-08-18)

Findings from a seven-agent read-only audit of Ember 1.5.8 at commit `5c2e11e2`
(~188k lines Rust, ~45k lines Svelte/TS). Severity uses the audit's definitions:

- **Critical** — app-crashing bugs, data corruption, or severe security vulnerabilities.
- **High** — broken core functionality or major performance degradation with no obvious workaround.
- **Medium** — sub-optimal behaviour, minor logic flaws, or edge-case bugs with a viable workaround.
- **Low** — code smells, minor UI inconsistencies, or non-breaking anti-patterns.

Status legend: `[x]` fixed in this pass · `[ ]` open · `[~]` partially addressed.

## Final status — all 33 findings closed

Every item in this document is fixed. Work ran in three passes: an initial pass on the
Critical/High items, a five-workstream parallel pass on the Mediums and Lows, and an
architectural pass on M12–M14 plus the clippy sweep.

| Verification | Before | After |
|---|---|---|
| `cargo check --all-targets` | clean | clean, **zero warnings** |
| `cargo test --lib` | 1,322 passed | **1,354 passed, 0 failed** (+32 new tests) |
| `cargo clippy` library warnings | 415 | **123** (−70%) |
| `npm run check` (svelte-check) | **1 error** | 0 errors, 0 warnings |
| `npm test` | 24 passed | **30 passed**, 1 skipped, 0 failed (+6 new) |

70 files changed (+3,096 / −7,065), plus 8 new files. `network/mod.rs` went from 49,764 to
43,513 lines.

### Three cross-file follow-ups found during remediation

These were discovered *by* the fixes and closed in the same effort:

1. **Updater i18n regression (would have shipped).** Converting the updater to `coded()`
   envelopes (M7) would have rendered raw `{"__coded":…}` JSON to users, because
   `src/lib/stores/updater.ts` used a local `toMessage()` instead of `translateError`. Fixed
   at all six error surfaces in that store, including the two in-band `result.error` paths
   that `secure_updater_check` returns rather than throwing.
2. **L6 completed properly.** The unpinned QUIC dials were fixed at the two call sites that
   matter (`ed2k/friend_connect.rs`, `network/mod.rs`) via a new
   `broker::punch_quic_pinned`, rather than left as a follow-up. Both already authenticate
   the peer against the rendezvous record before dialling, and `friend_ember_hash` is
   `BLAKE3(ed25519_pub)[..16]` — exactly the value `EmberCertVerifier` recomputes.
3. **Listener leak in `transfers.ts`.** Its catch block dropped already-registered
   `UnlistenFn`s without calling them, so a partial init leaked handlers and a retry
   double-applied every progress event.

---

## Critical

### [x] C1 — Ember refuses to launch when the download folder is unreachable

`src-tauri/src/lib.rs:544-551`

`std::fs::create_dir_all(download_folder/"Downloads")?` propagated out of the Tauri
`.setup` closure, so `build()` returned `Err` and hit `std::process::exit(1)` at
`lib.rs:1904`. With the download folder on an unplugged USB drive, an offline NAS or an
unmapped share the process exited code 1 with no window and no dialog, and repeated
every launch. `validate_settings` checks path length and forbidden roots but never
reachability, so the unusable value survives config load.

**Fix applied:** downgrade both `create_dir_all` calls to best-effort with a `tracing::error!`
so the app always reaches a window where the user can correct the setting. Paired with C1b
so the transient case self-heals without a restart.

### [x] C1b — Download directories were only ever created at startup

`src-tauri/src/network/ed2k/write_coordinator.rs:224-244`

`<download_folder>/{Downloads,Temp}` had exactly one creation site (the startup call in
C1), so once C1 became non-fatal a download started against a reconnected drive would
still fail to open its `.part` file.

**Fix applied:** best-effort `create_dir_all` of the part file's parent in the
`OpenMode::CreateOrOpen` arm of `open_file`, before `open_or_create_approved`. The
security check is unchanged — `open_or_create_approved` still performs all approved-root
and reparse-point validation on the final path.

---

## High

### [x] H1 — Unbounded tracker read on the UDP path can stall the whole event loop

`src-tauri/src/network/mod.rs:9563-9566` colliding with `src-tauri/src/network/ed2k/multi_source.rs:7501-7537`

`udp_reask_serveable_parts` did `tracker.read().await` with no timeout, inline in the main
`select!` UDP branch which drains up to 20 datagrams per turn. Meanwhile a source worker
holds `tracker.write().await` across `output.write(...).await`, whose ack is an mpsc
round-trip to a single per-file writer thread whose FIFO also carries other workers'
`sync_data()` and `hash_part_md4()`. A peer's routine `OP_REASKFILEPING` could therefore
head-of-line block UDP recv, frontend IPC and all 41 timers for the length of an unrelated
fsync or 9.28 MB MD4, overflowing the 1 MiB recv buffer and dropping KAD/Ember packets.

**Fix applied:** bound the read with a 20 ms `tokio::time::timeout`
(`TRACKER_READ_BUDGET`). All three call sites (`mod.rs:27859`, `:31181`, `:39222`) already
handle `None`; the UDP one falls back to rebuilding from the `.part.met` sidecar on the
blocking pool, which is off-loop and can only *under*-report availability (the sidecar lags
the live tracker), so we never advertise a part we would then refuse to serve. Worst case
becomes ~400 ms for a full 20-datagram turn of entirely contended reasks, against unbounded
before.

Note for whoever touches this: the timeout result must be bound with a `let` rather than
returned as the tail expression, or the read guard's temporary outlives the `Arc` it borrows
from (`E0597`).

**Still open (H1b, below):** the writer-side lock discipline.

### [x] H1b — Source worker holds the tracker write guard across the disk write

`src-tauri/src/network/ed2k/multi_source.rs:7500-7537`

H1 bounds the *reader*, which removes the outage. The underlying cause is that the writer
holds an exclusive guard across an `.await` on another thread's queue. The comment at
`:7495-7499` documents why (a competing source must not fill the same gap between the
snapshot and the write, which would duplicate bytes and credit), so this is a deliberate
trade-off, not an oversight.

**Fix applied:** `part_tracker` gained `write_reservations` plus
`reserve_write_subranges` / `commit_write_reservation` / `release_write_reservation`, and
`multi_source` gained a `WriteReservation` RAII guard modelled on `InProgressGuard`. The
write path is now reserve → write with no lock held → commit, i.e. two short critical
sections. Reservations never touch the gap list; they are purely an exclusion set, capped at
1024 entries. Error semantics are byte-identical: ENOSPC still bails with
`stage:insufficient_disk`, and `finish` runs *before* the bail so bytes that reached disk are
never left unrepresented in the gap map. The compressed write path was converted too — it
calls `fillable_subranges`, which does not consult reservations, so leaving it out would have
let it write over a reserved range. Four tests cover drop-without-commit, overlapping
reservation refusal, and partial-failure prefix commit.

### [x] H2 — `.part.met` never recovers from an interrupted atomic replace

`src-tauri/src/network/ed2k/part_tracker.rs:723`

`load_inner` read the sidecar directly, and was the only state loader in the tree missing a
`recover_interrupted_replace` call — `config.rs:154`, `identity.rs:130`,
`known_files.rs:185` and `:1035`, `share_intent.rs:171`, `database.rs:216`, `credits.rs:391`
and `filesystem.rs:543` all have it. A crash inside `atomic_write`'s Windows
replace-fallback window parks the only copy at `<id>.part.met.ember-replace-bak` and leaves
`.part.met` absent; `load()` reads absence as "nothing downloaded", calls
`reset_to_incomplete()`, and the next save overwrites the recovered backup. A partial
multi-GB download silently restarted at 0% and the persisted verified bitmap was lost.

**Fix applied:** call `crate::security::recover_interrupted_replace(&self.met_path)` at the
top of `load_inner`, matching the documented "call before reading a file whose absence means
first run" contract.

**Regression test added:** `load_recovers_a_part_met_parked_by_an_interrupted_replace`
(`part_tracker.rs`) saves 70% progress, renames the sidecar to the fixed
`.ember-replace-bak` name to reproduce the crash window, and asserts a fresh tracker reads
back 70% rather than resetting. Non-vacuous: without the recovery call `std::fs::read` fails
on the absent path and `load()` falls through to `reset_to_incomplete()`.

---

## Medium

### [x] M1 — Download persistence swallows its database errors

`src-tauri/src/network/mod.rs:43204-43257`

The `spawn_blocking` task that persists a new download discarded both results
(`let _ = db_ref.update_transfer_status(...)`, `let _ = db_ref.save_transfer(...)`) and
dropped its `JoinHandle`. A failed write meant the transfer silently never resumed after
restart, with no log line. Siblings at `:17554`, `:17650` and `:17717` log the same error.

**Fix applied:** both calls now log via `warn!` on failure, matching the sibling convention.

### [x] M2 — Bandwidth refill timer uses default `Burst` missed-tick behaviour

`src-tauri/src/bandwidth/limiter.rs:421`

The only `tokio::time::interval` in the crate not set to `Skip`; all 41 timers in
`network/mod.rs` set it explicitly per the rationale at `mod.rs:16716-16719`. After any
runtime stall the loop burst-drained one iteration per missed 100 ms tick, firing
`uss.compute_limit()` once per simulated second against unchanged `ping_history`;
`uss.rs:264` cuts 20% per call, so ~11 catch-up iterations collapsed the upload cap to the
10% floor, needing 15-20 real seconds to recover.

**Fix applied:** `interval.set_missed_tick_behavior(MissedTickBehavior::Skip)`.

### [x] M3 — `npm run check` is red

`src/routes/security/+page.svelte:75`

`let matchedCount = $derived(stats?.matched_count ?? 0);` failed with
`Property 'matched_count' does not exist on type 'never'`. `stats` was declared
`let stats: IpFilterStats | null = $state(null)` and only reassigned inside function bodies,
so TypeScript's control-flow analysis narrowed the top-level binding to `null` and the
non-null branch to `never`. Runtime behaviour was correct; the type-check gate was not.

**Fix applied:** moved the annotation into the rune —
`let stats = $state<IpFilterStats | null>(null)` — which is the pattern the rest of the
file already uses and which CFA does not narrow.

### [x] M4 — Unverified corruption-blackbox records grow without bound

`src-tauri/src/network/ed2k/corruption_blackbox.rs:120-161`, driven from `mod.rs:19591`

`compact` only folds blocks where `b.verified && !b.corrupt`, so the
`MAX_BLOCKS_BEFORE_COMPACT` guard cannot enforce its cap. When a download's hashset never
arrives nothing is ever marked verified, the per-file `Vec<RecordedBlock>` grows one entry
per received block, and `record_data` does a full `drain(..)` and rebuild per event on the
main network task — O(n²), ~23k entries for a 4 GB file.

**Fix applied:** `compact` is now four phases, cheapest loss first: fold verified blocks per
IP (lossless), merge adjacent same-IP ranges within one part (lossless for attribution), fold
the *oldest* live ranges into their IP's aggregate (the only lossy step, corrupt blocks
sacrificed last since they are the actual evidence), then drop the smallest per-IP totals
that could never have reached `MIN_BYTES_FOR_BAN_DECISION`. A low-water
`COMPACT_TARGET_BLOCKS` amortises the rebuild over ~1000 events instead of firing on nearly
every one, and a no-overlap fast path removes the per-block reallocation on the network task.
Eviction is deliberately biased to under-attribute: aggregates carry a synthetic range and
are excluded from `corrupted_part_contributors`, so a dropped range can only suppress a ban,
never invent one against an honest peer.

### [x] M5 — Part claims are a bool, not a refcount

`src-tauri/src/network/ed2k/multi_source.rs:732-757` vs the endgame fallback at `:8951-8983`

`set_in_progress` writes a plain `bool` (`part_tracker.rs:1024`) but the endgame fallback
deliberately re-selects with `vec![false; part_count]`, so two sources can claim one part;
`Drop` then unconditionally clears the flag, freeing a part another source is still pulling.
Costs duplicated wire bytes and connection slots. No corruption — gap-trimmed writes discard
the duplicates. The comment at `:8975` claiming teardown "unmarks correctly even when
another source also claimed it" is wrong and should go with the fix.

**Fix applied:** `in_progress: Vec<bool>` became a private `in_progress_claims: Vec<u16>`
behind `is_in_progress` / `in_progress_flags` / `claim_in_progress` / `release_in_progress`,
all using `saturating_add`/`saturating_sub` so an unpaired release cannot underflow-panic.
`InProgressGuard` is now the only thing that touches the count, and its `claim` is idempotent
per guard (the `active` vec doubles as a dedup set) — without that, the pre-existing
"idempotent, pipelined state already did this" call site would have incremented twice against
one decrement and leaked a claim forever. Zero external readers, confirmed via `Select-String`
on `network/mod.rs`. The false comment claiming teardown already handled this was replaced.

### [x] M6 — Files beyond 100,000 per folder are never indexed without manual reloads

`src-tauri/src/sharing/indexer.rs:15`; `src-tauri/src/lib.rs:961`; `src-tauri/src/commands/sharing.rs:3209-3222`

`MAX_DISCOVERED_FILES = 100_000` caps a discovery page and returns `next_cursor`, but
startup resets the cursor to `None` and only user-initiated calls advance it. A 500k-file
share needs ~5 manual Reload clicks.

**Fix applied:** `reload_shared_files` is now a thin wrapper over a paging
`reload_shared_files_page`, and a page whose discovery hit the cap queues the next one. Four
things keep it safe: a hard ceiling of 8 chained pages per trigger (~900k files) with no
fan-out; a forward-progress gate so a page only chains if its cursor both *changed* and was
successfully persisted (otherwise a failed save would rescan the same page forever); a 60 s
delay between pages; and registration via `register_background_scan` so shutdown can abort
it, waiting in 250 ms slices against `bw_shutdown` and `hashing_paused` so exit is not
delayed and a user's Stop is not undone. `MAX_DISCOVERED_FILES` is unchanged.

### [x] M7 — Updater errors are hardcoded English and bypass the i18n ratchet

`src-tauri/src/commands/updater.rs:1413, 1419, 1450, 1490, 1637, 1652, 1662, 1670, 1750`

Zero `coded()` calls in the file; `errors.rs:16` renders non-envelope errors verbatim, and
`scripts/error-codes.test.mjs:124-127` only scans `coded()`/`await_reply` sites, so nine
user-facing failures escape the translation gate on a nine-locale app.

**Fix applied:** 16 new `error_updater_*` keys with real translations in all nine locales
(literal UTF-8, matched to each file's existing updater vocabulary). Twelve raw-`String`
returns were converted — three more than the audit listed, because those were written as
`map_err` closures and a `return Err("` grep missed them. `public_failure` was also converted
via an `UpdaterOperation` enum with four codes; it is the most-hit user-visible failure (an
ordinary offline check lands there), so leaving it would have made the fix cosmetic. The
codes stay as **literals at the `coded()` call site** rather than being passed in as a
parameter, because `scripts/error-codes.test.mjs` only scans construction sites — threading
the code through an argument would have recreated the exact ratchet bypass this finding is
about. Internal `anyhow` context in `download_artifact` and the verification helpers was
deliberately left alone; coding it would cost log detail and buy nothing. No control flow
changed: every `pending.take()`, `clear_handoff`, floor re-read, and the double
`verified_installer_path` call before spawn are identical.

**Required companion fix (see cross-file follow-up 1 above):** without the `updater.ts`
change this would have shipped raw JSON to users.

### [x] M8 — Log pseudonym key is regenerated every launch

`src-tauri/src/security/mod.rs:77-86`; `src-tauri/src/lib.rs:308-310`

`pseudonym()` seeds its BLAKE3 key from `OsRng` per process, so `<ip:…>`, `<id:…>` and
`<path:…>` tokens for the same entity differ across restarts. A user's log cannot be used to
trace one stuck download across sessions. The only escape hatch,
`EMBER_VERBOSE_DIAGNOSTICS`, appears nowhere else in the repo.

**Fix applied:** the key is now `blake3::derive_key("ember.log.pseudonym.v1",
identity.ed25519_secret_key)`, installed immediately after the identity loads. It is derived
from the **secret** half deliberately: the public key is handed to every peer we talk to, so
deriving from it would let anyone with a log file plus our public key rebuild the key and
enumerate the IPv4 space to undo `<ip:…>` tokens. BLAKE3 KDF mode is one-way and
context-bound, the key is never logged or persisted, and a 6-byte keyed digest is not
invertible without it. Identity loading order is untouched; the pre-identity window uses a
throwaway key and closes before the network task starts, so no peer address can appear in it.
`EMBER_VERBOSE_DIAGNOSTICS` is now documented at its read site.

### [x] M9 — Identity private keys are serialized into a non-zeroized buffer

`src-tauri/src/storage/identity.rs:229` and `:273`

`serde_json::to_vec_pretty(&id)?` puts the Ed25519 secret key and Noise X25519 private key
as plaintext JSON on the heap, dropped without wiping — the exact threat
`secret_store.rs:71-75` documents and that `backup.rs:642` defends against with `Zeroizing`.

**Fix applied:** both serializations wrapped in `Zeroizing`, and so is the `protect(...)`
*return* value — `secret_store::protect` is a documented pass-through on non-Windows, so its
output is plaintext keys there too (which is why `backup.rs:1308` wraps it). The
`database.rs` chat key had a genuine window: `[u8; 32]` is `Copy`, so returning it through
`Option<[u8; 32]>` left un-wiped copies in the local, the return slot, and the caller, while
`Zeroizing::new` at the struct literal only protected the last one. `Zeroizing` was pushed
down into the function's return type so the key is owned by a wiping type from creation.

### [x] M10 — Speed test bypasses the app's own fetch policy

`src-tauri/src/commands/speed_test.rs:36-39`

Builds a bare `reqwest::Client` with neither `https_only(true)` nor `no_proxy()` and the
default 10-hop redirect policy, while every other outbound fetch goes through
`security::fetch_pinned_get` (`security/mod.rs:584-655`) which sets all three and DNS-pins
each hop specifically to stop redirect-based SSRF.

**Fix applied:** the standalone client is gone. The download leg goes through
`security::fetch_pinned_get` for full parity including per-hop re-validation. The upload leg
cannot — `fetch_pinned_get` is GET-only — so it calls `security::validate_fetch_url` and
passes the resolved addresses to `security::build_pinned_client`, the same client the pinned
path uses, giving it `https_only`, `no_proxy`, `redirect(Policy::none())` *and* DNS pinning
plus private/loopback rejection. Validation and DNS run before `Instant::now()` so they do
not skew the measured throughput.

### [x] M11 — Phantom "unsaved changes" on the settings page

`src/routes/settings/+page.svelte:1462-1466`

The USS invariant effect writes `settings.uss_enabled = false` without patching the
`originalSettings` baseline, so loading a config with `max_upload_speed === 0 &&
uss_enabled === true` marks the page dirty with no user edit and arms both leave guards.
Every other programmatic mutation patches the baseline (`:1285`, `:783`, `:818`).

**Fix applied:** the effect patches `originalSettings`, but *only* when the baseline itself
carries the invalid `max_upload_speed === 0 && uss_enabled` combination — precisely the case
where the clear is ours rather than the user's. A user-driven switch to Unlimited leaves the
baseline alone (its cap is still non-zero at that point), so that disable remains a genuine
unsaved change and is still persisted by Save rather than silently dropped. The baseline read
is wrapped in the file's existing `untrack` so the effect does not subscribe to what it
writes.

### [x] M12 — `start_network` is a 19,483-line function

`src-tauri/src/network/mod.rs:15473-34955`

25 parameters (clippy: 25/7), owning a ~235-field `NetworkState` and driving all three
protocol stacks on one tokio task. `app_state.rs:104-117` records this already shipping a
starvation bug — a synchronous re-read starved KAD UDP, timers and IPC for a whole hash pass
— patched with a side-channel cache rather than a boundary. H1 is a second instance.

**Fix applied:** all 25 parameters moved into `pub struct NetworkDeps`, so the signature is
`start_network(deps: NetworkDeps)`. The ~19k-line body is untouched — a single destructuring
`let NetworkDeps { app_handle, mut cmd_rx, … } = deps;` rebinds every field to its identical
local name, which keeps the change provably behaviour-preserving and the diff reviewable.
Field order matches the original parameter order so binding and drop order are unchanged.
Fields are grouped and documented (runtime handles, config and identity, storage and index,
transfers and bandwidth, the eight IPC snapshot caches, sharing and friends, USS scheduling,
search services). One call site, `lib.rs`.

**Still open by design:** splitting `NetworkState` per stack and moving each stack's timers
onto its own task. That is the part that would actually remove the single-task starvation
class, and it is a genuine redesign rather than code motion — see the note at the end.

### [x] M13 — `network/mod.rs` is 47,786 lines

25% of the 188k-line backend in one file: 68 top-level `async fn`, 235 `fn`, 58 structs, 10
enums, 105 consts, mixing ed2k, KAD, Ember DHT, rendezvous, UPnP, search, browse and
transfer. It also silently escapes repo-wide `rg`/Grep by size, which caused one audit agent
to misjudge `StatsManager` as dead code — worth knowing when working in this tree.

**Fix applied:** four new sibling modules, **49,764 → 43,513 lines** (−6,251). The file had
already grown past the audited figure.

| Module | Lines | Contents |
|---|---|---|
| `network/command.rs` | 5,640 | `handle_command`, `handle_command_inner` |
| `network/ember_publish.rs` | 390 | 9 `Ember*` publish/batch types, 8 pacing consts, `impl EmberBatchPublisher` |
| `network/browse.rs` | 255 | `PendingBrowseRequest`, queue helpers, `dispatch_browse_head` |
| `network/health.rs` | 144 | 16 background-job result and diagnostic-snapshot types |

The move was cheap because child modules can see their parent's private items, including
struct fields — so none of `NetworkState`'s ~235 fields needed widening and nothing new
became `pub`. `command.rs` uses `use super::*` deliberately: `handle_command_inner` reaches
100+ parent helpers, and an explicit import list would churn on every edit while buying no
isolation, since `NetworkState` is still shared. The boundary it draws is "command dispatch
is edited here", not a dependency firewall; that trade-off is documented in the file header.
Deliberately left in `mod.rs`: `retire_ember_session` (used by both browse and friend
removal, so not browse-owned) and `tcp_port_confirmation` the function, keeping `health.rs`
pure data.

### [x] M14 — Protocol-independent DHT glue is implemented twice

`src-tauri/src/network/kad/` (15,653 lines) vs `src-tauri/src/network/ember/dht/` (11,883 lines)

The routing algorithms genuinely differ (eMule split-tree zones vs flat buckets with a
replacement cache), so this is **not** copy-paste and merging them would be a rewrite. But
~13 protocol-independent responsibilities are duplicated: `set_ip_filter`,
`set_block_private_ips`, `evict_filtered_contacts`, `remove_stale`,
`export_bootstrap_contacts`, `all_contacts`, `get_contact`, `verified_len`, `add_contact`,
`remove_contact`, `find_closest`, `find_closest_prefer_verified`, network-size estimation.

**Fix applied:** new `network/kad/dht_common.rs` (271 lines) holding `xor16`, an
`IpAdmissionGate` (owns `block_private_ips` and the shared `ipfilter.dat` snapshot, answering
both the fail-closed insert question and the fail-open eviction question), a
`PolicyEvictable` trait with a shared `evict_blocked_contacts` sweep, and `is_stale`. Both
routing tables now implement the trait over their own storage. It lives under `kad/` rather
than `network/` because only `network/mod.rs` could declare a top-level sibling and that file
was owned by the concurrent M13 work; `kad/` is the right second choice anyway, since the
`ip_filter` primitives it builds on already live there and `ember::dht` already depends on
them. No `network/mod.rs` edit was needed.

**Only 3 of the 13 audited responsibilities were genuinely shareable**, and that analysis is
the valuable part. Shared: `set_ip_filter`, the `set_block_private_ips` policy edge, and the
`evict_filtered_contacts` predicate plus sweep (also the XOR fold and the staleness age
comparison). Left separate, each for a concrete behavioural reason:

- `remove_stale` — KAD ages every contact and retires on eMule's per-type TTL; Ember ages
  only verified ones (contacts restored from `nodes_ember.dat` arrive with `last_seen == 0`
  and a regression test asserts the first maintenance tick must not purge them), honours an
  `in_use` set for in-flight searches, and has no `consolidate()` step.
- `export_bootstrap_contacts` — eMule `TopDepth` tree walk with random child descent vs.
  distance-ranking from our own ID; different selection criterion and health filter.
- `all_contacts` — KAD returns a borrow-free iterator, Ember an owned `Vec`; unifying would
  turn ~30 `network/mod.rs` call sites into allocations.
- `get_contact` — KAD needs a leaf-scan fallback because a zone split re-homes contacts;
  Ember must search its replacement cache. Neither fallback means anything in the other.
- `verified_len` — same shape, different predicate: KAD means "Kad2 handshake done and UDP
  key echoed", Ember means "has ever answered us".
- `add_contact` / `remove_contact`, `find_closest` — the core routing algorithms, out of
  scope. Their removal paths now meet at the trait's `evict_contact`.
- `find_closest_prefer_verified` — Ember sorts strictly by distance and its comment records
  that health-based ranking was **tried and reverted**, because publishing must aim at the
  genuinely closest nodes or the storer's `store_proximity_ok` gate refuses the record.
  Unifying would silently reintroduce reverted behaviour.
- Network-size estimation — KAD extrapolates from zone-tree depth; a flat array has no depth.

**Two findings worth recording.** First, the audit's assumption that bucket-index derivation
is identical mathematics is **false**: `KadId` stores eMule `CUInt128` wire order (four
little-endian u32 chunks), so its bit 0 is the MSB of byte 3 and its `Ord` compares
chunk-wise, while `EmberNodeId` stores plain MSB-first bytes and orders byte-lexicographically.
The same sixteen bytes yield a different bucket index *and* a different total order, so only
the XOR fold was safe to share. Second, the per-IP/per-subnet caps stay separate: eMule's
per-bin cap is a *tree-position* rule whose bin membership changes on split/consolidate,
which a fixed bucket array cannot express, and Ember deliberately allows 2 per IP rather
than 1 because keypair-bound node IDs make two instances behind one NAT distinguishable.

---

## Low

All 14 are fixed. The last column records what actually shipped, which differs from the
original proposal in a few places.

| ID | Location | Issue | Fix applied |
|---|---|---|---|
| L1 | `network/ed2k/chunk_selection.rs:144-161` | Score sums `zone*1000 + active_bonus(50) + completion_score(0-100) + freq(0-65535)`, so the weights don't implement the lexicographic order the doc comment at `:75` promises; above ~1000 sources `freq` swamps both heuristics. | Sort by a `(zone, !active, completion_score, freq)` tuple. |
| L2 | `src/routes/+layout.svelte:191-199` | `Promise.all` over five store initializers makes startup all-or-nothing; one transient `listen()` failure discards four successes and renders a blocking error screen. | `Promise.allSettled`; only network/settings fatal. |
| L3 | `src-tauri/tauri.conf.json:25` | CSP omits `form-action`, which does not fall back to `default-src`, so injected renderer code could exfiltrate via form submission despite the locked-down `connect-src`. | Add `form-action 'none'` and `worker-src 'none'`. |
| L4 | `security/filesystem.rs:1876`; `security/firewall.rs:22,44,60,93,127` | `Command::new("explorer"/"netsh"/"powershell.exe")` by unqualified name; `CreateProcessW` searches the exe dir and CWD before `System32`. Mitigated — a same-user attacker could already replace `Ember.exe`. | Shared `#[cfg(windows)] pub(crate) windows_system_path` helper in `filesystem.rs`, reached from `firewall.rs` without touching `security/mod.rs`. Takes a caller-supplied relative path because **`explorer.exe` is in `%SystemRoot%` while `netsh`/PowerShell are under `System32`** — getting that backwards would break "Show in folder". Falls back to `C:\Windows`. |
| L5 | `network/kad/messages.rs:1298-1373` | `search_expression_uses_64bit::walk` recurses unbounded (depth N/2 for N bytes) — a stack overflow `panic = "unwind"` cannot catch. **Not reachable today**: zero non-test callers. | `MAX_EXPR_DEPTH = 32`, bailing into the existing `unwrap_or(false)` so malformed input reports exactly as it always did. Two tests: a 4,096-byte `0x00` run (which would have recursed ~2,000 deep) returns `false`, and a 16-deep AND chain still resolves, pinning the limit above anything legitimate. |
| L6 | `network/ember/quic.rs:307-341` | `EmberCertVerifier` with `expected_node_id: None` proves key possession but binds it to no identity. Documented trade-off at `:288-306`. | Fixed at the two call sites, not deferred. New `broker::punch_quic_pinned` derives our cert from the identity secret; `ed2k/friend_connect.rs` and `network/mod.rs` now pass the friend's hash. The unpinned path was deliberately **not** tightened — requiring the cert's `ember-{hex}` label to match its SPKI would reject peers on the older cert generator, i.e. break first contact. |
| L7 | `network/ember/crypto.rs:372-379` | Chat envelope version byte checked outside the AEAD, not passed as AAD. Harmless at one version; a downgrade lever the moment a v2 exists. | Bound as AAD via `Payload { msg, aad }` on **both** encrypt and decrypt. **Wire-format break: both peers must run this version or later** — a mismatched pair fails Poly1305 and chat drops silently, by design (no plaintext fallback). No at-rest impact; chat history uses the database key with its own row AAD. Release-note this. |
| L8 | `network/mod.rs:11761-11765` | `unwrap_or_default()` on the verified-highwater load, then saved back over the real file — load-then-overwrite data loss, bounded to a statistics counter. | Log and return without overwriting, like `kad/bootstrap.rs:120-131`. |
| L9 | `lib.rs:332-337` | `Rotation::DAILY` without `.max_log_files(n)`; `cleanup_old_logs` only runs at startup, so a months-long session accumulates logs unbounded. | `.max_log_files(7)`. |
| L10 | `src/lib/stores/search.ts:63-170` vs `search/merge.rs:82-263` | The result-merge contract is hand-mirrored in two languages with only a comment keeping `MAX_PLAUSIBLE_SOURCES` aligned. | Shared golden-vector test or generated constants. |
| L11 | `network/ed2k/server.rs` (26 of 72 repo-wide) | `#[allow(dead_code)]` without justification; genuinely dead eMule scaffolding is indistinguishable from not-yet-wired code. | **2 deleted, 24 kept and documented.** The decisive finding: the live search path uses `kad::messages::build_search_expression_with_node`, so everything under the "Boolean search tree support" header is a parallel implementation reachable only from its own 10 tests — live under `cargo test`, dead under `cargo build`, which is why it needs the allows. Deleted `send_search_async` and `send_search_expression_async` (unreferenced API wrappers, no wire surface lost). Kept the four unused comparison opcodes so 0x00/0x01/0x02/0x05 are not holes for the next `SearchExpression` variant. |
| L12 | `commands/settings.rs:1503,1537,1556,1567,1627`, `deeplink.rs:249,258,270`, `peers.rs:536,1262,1271,1431`, `sharing.rs:3278,3283` | ~20 of 187 `#[tauri::command]` fns are `async` with no `.await`. | **14 converted, 2 deliberately left async.** Kept async: `open_ember_website` (`opener::open` → `ShellExecuteW` can block for hundreds of ms) and `ack_pending_deep_link` (`persist_pending_queue` does a synchronous `atomic_write` under a mutex). Both would stall the UI thread as sync handlers. The runtime was checked rather than assumed: in `tauri-runtime-wry` 2.11.4 the window/tray calls execute inline when already on the main thread without blocking on a reply, and `AppHandle::exit` always posts `RequestExit` to the event loop, so `quit_app` still returns before the shutdown flush. |
| L13 | `sharing/manager.rs` (1,295 lines), `network/ed2k/server_crypt.rs` (312) | The only consequential files >300 lines with zero tests, against 1,146 elsewhere. `manager.rs` holds the transfer state machine; `server_crypt.rs` holds DH + RC4 derivation. | **14 tests.** `manager.rs` (9): slot handoff on complete, `fail` promoting only for active rows, both copies of the 1,000-entry ring drain walked past the boundary (an off-by-one there is an unsigned-underflow panic), the stop-then-cancel race, and all five `queued_wait_status` branches. `server_crypt.rs` (5): a real end-to-end DH handshake against a `TcpListener` playing the server half written to the wire format (so it fails if the recipe drifts), a negative test with a positive control, and three `biguint_to_be_padded` boundaries including the zero-width edge where the length subtraction would underflow. |
| L14 | Whole crate | 415 clippy warnings, 268 auto-fixable; two functions take 47 and 53 arguments (`multi_source.rs:3909`, `upload.rs:2409`). The noise floor hides new warnings. | **415 → 123 (−70%).** 160 machine-applied fixes across 36 files, then a documented crate-level baseline. A blanket `--fix` does **not** work here and reverts everything: `collapsible_if` emits let-chains (edition 2024, this crate is 2021) and `manual_div_ceil` hits E0689 on ambiguous numeric literals. The working invocation is an explicit allow-list — see the note below. |

---

## Verified safe (checked, not defects)

Recording these so they are not re-audited. Each was actively investigated and the guard
located:

- **Wire parsers** bound-check before slicing throughout; `ed2k/messages.rs`,
  `kad/messages.rs`, `ember/dht/messages.rs`, `collection.rs`, `nat.rs` STUN, and the EPX
  parser were all traced without a break.
- **DHT identity binding** — `decode_message` refuses `has_pub_key = false`, verifies Ed25519
  over the frame, and enforces `node_id == BLAKE3(pubkey)[..16]`, so a peer cannot claim
  another node's id.
- **UDP amplification** — the DHT-request-inside-unauthenticated-IK_INIT vector is closed by
  deferring the payload (`transport.rs:1688-1715`); the reply is smaller than the request.
- **Zip-Slip / zip bombs** — `backup.rs:1026-1042` allow-lists bare names, caps against bytes
  actually read, and BLAKE3-verifies every entry.
- **Updater** — in-memory verification (length match, size cap, SHA-256, minisign against the
  embedded pubkey), anti-rollback floor re-read after download and before spawning a staged
  installer.
- **SQL** — every query uses bound `params![]`; the only `format!`-built SQL is the migration
  helper behind an identifier validity check.
- **Path sanitization** — `FILE_FLAG_OPEN_REPARSE_POINT` everywhere, volume-serial + file-id
  pinning, correct truncation → trailing-dot-trim → reserved-name ordering, ADS colon strip.
- **Panic safety** — zero `lock().unwrap()`; ~110 of 1,537 `unwrap`/`expect` outside tests,
  all infallible `Vec<u8>` writes or documented invariants; unsigned subtraction, division
  and `Instant` math guarded at every site opened.
- **Frontend XSS** — zero `{@html}`, `innerHTML`, `document.write` or `window.open`; remote
  text renders through `<bdi dir="auto">` over Rust-side `sanitize_remote_text`.
- **Svelte teardown** — all four listener-owning stores collect and call `UnlistenFn`s with
  per-step rollback; all client-side arrays are capped.
- **Frontend↔backend contract** — all 174 `invoke()` names matched against 185
  `#[tauri::command]` definitions with no drift.
- **ed2k/Kad protocol conformance** — part size 9,728,000, the `MD4("")` exact-multiple rule,
  `K=10`/`ALPHA=3`/`KBASE=4`/`KK=5`, and eMule's republish intervals all match.
- **Release engineering** — all five manifests plus WiX consistent at 1.5.8 and enforced by
  `verify-release-policy.mjs`; actions SHA-pinned; signing confined to a protected
  environment.

---

## What is deliberately NOT done

Two things, both stated plainly rather than quietly dropped.

**1. `NetworkState` is still one struct on one task.** M12 bundled the parameters and M13
moved 6,251 lines out, but the single-task ownership model that produced the original
starvation bug (`app_state.rs:104-117`) and H1 is unchanged. Splitting `NetworkState` per
stack and giving each stack its own task with an explicit message boundary is a redesign, not
code motion — it cannot be compiler-verified the way this pass was, and it needs integration
testing against live peers that a static refactor cannot substitute for. **This remains the
single most pressing architectural risk in the codebase.** The groundwork is now in place:
`command.rs` is separable, and `NetworkDeps` gives the entry point a real signature.

**2. 123 clippy warnings remain**, down from 415. The residue is: ~55 further auto-fixable
suggestions the allow-list did not cover, `sort_by_key` rewrites that need a human to confirm
the key is cheap to compute, and genuine judgement calls (`large_enum_variant`,
`if_same_then_else` on branches that are intentionally identical, three
`MutexGuard`-across-await warnings that are all `#[cfg(test)]`). None are correctness bugs.

### Reproducing the clippy sweep

A plain `cargo clippy --fix` fails and reverts every change. Use the allow-list form:

```
cargo clippy --fix --lib -p ember --allow-dirty -- -A clippy::all \
  -W clippy::needless_borrow -W clippy::unnecessary_map_or -W clippy::unnecessary_sort_by \
  -W clippy::explicit_auto_deref -W clippy::needless_borrows_for_generic_args \
  -W clippy::manual_is_multiple_of -W clippy::io_other_error -W clippy::identity_op \
  -W clippy::doc_overindented_list_items -W clippy::redundant_closure \
  -W clippy::manual_range_contains -W clippy::manual_pattern_char_comparison
```

The crate-level baseline in `lib.rs` allows exactly four families, each with a written
justification: `collapsible_if` and `manual_div_ceil` (not fixable on this edition / not
resolvable), and `too_many_arguments` and `type_complexity` (wire-protocol surfaces where the
shapes mirror packet layouts). Anything outside those four is expected to stay at zero — fix
new warnings rather than extending the list.

## Notes for future work in this tree

- `src-tauri/src/network/mod.rs` (47,786 lines) is **silently skipped by repo-wide `rg` and
  the Grep tool** on size. Search it explicitly (`Select-String -Path ...\network\mod.rs`)
  or you will draw wrong conclusions — this already produced one false "dead code" finding
  during the audit.
- The shell here is PowerShell: chain with `;`, not `&&`, and `head`/`tail` do not exist.
- Adding a `coded("...")` error requires `error_<code>` in all nine `messages/*.json` or an
  entry in `KNOWN_UNTRANSLATED` in `scripts/error-codes.test.mjs`, or `npm test` fails.
