# After 1.7.1

Work found by the 1.7.1 audit and deliberately left for 1.7.2, with why it
waited and what it needs. Ordered by priority. Items 1 and 2 are done; each
says how.

## Sharing

### 1. Widening a partial share must not re-share what the user unshared

**Why:** Widening a partly shared folder to the whole folder (the share
browser's "widened" confirmation, or the folder picker) re-offers files the
user unshared themselves while the folder was still shared whole. The user
confirmed the widening, so this is not silent, but the prompt says nothing
about those files, and an explicit "unshare" is overridden by a broader
"share".

The cause is that two different unshares are stored the same way:

- **Automatic:** when 1.7.0 limited a folder to a list, `keep_unlisted_copies_unshared`
  (`commands/sharing.rs`) unshared every copy outside the list.
- **The user's own:** unsharing a file or a selection in the Library.

Both end up as `is_shared = false` in known.met and a `denied` entry in the
share-intent store (`storage/share_intent.rs`). `admit_known_files` /
`newly_admitted_unshared` cannot tell them apart, so widening writes an
explicit allow over both.

**Done.** `PersistedShareIntent` records an origin for each denial through
two subsets of `denied`, as `UnshareOrigin`:

- `auto_denied`: written by the two places a list withholds known files at
  add time, the only automatic unshares (`keep_unlisted_copies_unshared`
  turned out to revert Library rows only and writes no denial).
- `origin_unknown`: denials the store could not attribute, plus re-asserted
  ones (the reconcile's, known.met's on load, a rolled-back share).

Only the user's own unshare relabels a hash that is already denied, and a
share clears both sets. Widening (`admit_known_files`) re-shares only
`auto_denied` content and keeps the user's own unshares. For unknown-origin
content it asks in a second native dialog after the widen confirmation
("Share N more files?"), which defaults to keeping them unshared and says
they stay listed in the Library.
A store without `origins_recorded`, from before 1.7.2 or rewritten by 1.7.1
after a downgrade, loads with every denial unknown. 1.7.1 ignores the new
fields.

Tests: `an_unshare_keeps_who_made_it`,
`a_store_without_origins_loads_its_denials_as_unknown`,
`widening_sorts_what_it_finds_by_who_unshared_it`,
`the_earlier_unshared_question_counts_the_files`.

### 2. Keep the withheld-files list out of `config.json`

**Why:** Unsharing a folder that is shared whole, or a large part of a partial
share, records every indexed path under it in
`settings.withheld_folder_files`. For a 100,000-file share that is several
megabytes in `config.json`, which has no size cap and is rewritten and synced
to disk on every settings save (scan cursors and pending intents save often).
`tidy_withheld` also walks the whole list on each save. 1.7.1 made this more
likely: Unshare folder on a whole share now gives it an empty allowlist and
withholds its indexed files (the M4 fix in the 1.7.1 audit).

**Done, differently from the plan.** The withheld entries never keep anything
unshared: what is offered is the allowlist alone. They only keep discovery
walking those files so the Library lists them, and discovery scopes by the
shared root's list alone. So an entry can name a folder rather than every
file in it. `withhold_under` now withholds what the lists stop offering as
it was listed: a dropped folder entry stays one entry, and a folder that was
offered whole is withheld as itself. Discovery walks the same files as
before, and the list is no larger than the allowlists it came from. That
removes the large case without a store of its own. A separate store would
also have meant handling backups, restores and the eMule import, which all
carry `config.json`.

- Downgrade is safe: 1.7.1 reads folder entries the same way. The exception
  is a withheld drive root, which needed the separator fix in
  `allowlist_permits` / `path_key_covers`; 1.7.1 then lists none of those
  rows, and still offers nothing.
- A file added later to a folder unshared as a whole now shows in the Library
  as unshared, as it already did in an unshared subfolder of a whole share.
- Lists already written by 1.7.1 keep their per-file entries; nothing can
  tell which of them came from a whole folder.

Tests: `unsharing_a_whole_share_stops_its_later_files`,
`unsharing_a_partial_share_keeps_it_limited_and_its_files_listed`,
`a_file_inside_a_withheld_folder_is_not_listed_again`,
`a_drive_root_entry_covers_the_drive`,
`a_withheld_folder_keeps_every_file_under_it_unshared_on_widening`.

## Cleanup

### 3. Remove the legacy friend authentication

**Why:** `LEGACY_FRIEND_AUTH_ENABLED` (`network/ed2k/mod.rs`) is a `const
false`, and nothing turns it on: v1 signed nonces the peer chose, which made
it a signing oracle, so it was retired. The path it guards is still compiled:
`ed2k/ember_auth.rs`, the four `LEGACY_FRIEND_AUTH_ENABLED` branches in
`ed2k/multi_source.rs` and the one in `ed2k/upload.rs`, plus the compile-time
assert that keeps it off. The dead-code pass left it because the compiler
does not report a `const false` branch as unused.

**To do:**

- Delete the branches and the state and helpers only they reach, then
  `ember_auth.rs` itself once nothing else uses it.
- Keep the arms that log and ignore `OP_EMBER_AUTH_CHALLENGE` and
  `OP_EMBER_AUTH_RESPONSE`: an old client may still send them, and they must
  not fall through to another handler.

**Tests:** the full suite, and both retired opcodes received from a peer are
ignored without changing that peer's state.

### 4. Fold the `user_offline` flag

**Why:** `user_offline` (`network/state.rs`) is an `AtomicBool` set to `false`
at startup; the four places that still store to it store `false`. About 25
sites clone it into tasks or check it (`friend_connect.rs`,
`command.rs`, `downloads.rs`, `search.rs`, `server_tick.rs`, `friends.rs`,
`download_event.rs`, `server.rs`). Every check is false, so each guarded
branch is dead.

**To do:** remove the field and its clones, and inline each check as `false`:
drop the early returns it guards and keep the code that runs when online.
`search.rs`'s `user_offline` parameter goes with it. Read `server.rs`'s
comment about the KAD-disconnect exemption first: it explains an earlier bug
around this flag and has to stay true afterwards.

**Tests:** the full suite. Nothing should change behaviour; a test that needs
`user_offline = true` (`friend_connect.rs` has one) was testing a mode the app
no longer has and goes with it.

## Investigation

### 5. Why most known peers show verification as Needed

**Why:** In the Known Clients list, the earlier session showed only 1 of 74
recently seen peers as Verified and none as Failed. SecureIdent verification
is per session, so a stored Verified or Failed loads as Needed, and the list
includes peers not seen this session. That explains part of it, not all.
A short session with debug logging showed upload-side verification working
(2 of 2 genuine peers). Queued peers or the download side may never reach the
signature step.

**To do:** run 30 to 60 minutes with
`RUST_LOG=info,ember_lib::network::ed2k::transfer=debug` (the `SecIdent:` lines)
and compare, per peer, the state reached with the Known Clients row. If queued
or download-side peers never get a challenge, send one when their session
starts rather than at the first upload.

## Considered and left as they are

From the same audit, not planned unless they start to matter:

- **Completed-download disk read on the network loop:** the handler for a
  finished download waits for the file's modification time
  (`event_loop/download_event.rs`). Normally microseconds; only slow network
  drives notice. Moving it needs a new field on `DownloadEvent::Completed`
  across six send sites.
- **`FRIENDS_SCOPE_CHANGE` held across the known.met parse** in
  `prune_pending_intents_for_hashed`: a friends-only toggle made as a scan
  finishes can wait a few seconds. Nothing is lost.
- **Sealed-offer proofs dropped at the queue cap** are kept in memory only.
  The table holds no more than that many anyway; the cost is one extra
  "do they read sealed offers?" question after a restart.
- **Replayed IK_INIT on a crossed dial** (`ember/transport.rs`): already
  deferred in `docs/ember-dht.md`. A fix is a protocol change; the effect is
  lost messages until the next handshake, not exposure.
