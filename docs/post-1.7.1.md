# After 1.7.1

Work found by the 1.7.1 audit and deliberately left for 1.7.2, with why it
waited and what it needs. Ordered by priority.

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

**To do:**

- Record where an unshare came from. Add an `auto_denied` set (or an origin
  per `denied` entry) to `PersistedShareIntent`, written only by the
  allowlist path (`keep_unlisted_copies_unshared` and the withhold helpers).
  An explicit unshare removes the hash from `auto_denied`; an explicit share
  removes it from both.
- Widening re-admits only `auto_denied` content. Content that is merely
  `denied` stays unshared.
- Entries written before 1.7.2 carry no origin. Treat them as the user's, so
  nothing is re-shared that might have been, and have the widen confirmation
  say how many files stay unshared, with a choice to include them.
- `#[serde(default)]` on the new field, so a 1.7.1 that reads the store after
  a downgrade ignores it and keeps today's behaviour.

**Tests:** widening after an automatic unshare re-shares; after a Library
unshare it does not; a legacy store re-shares nothing without the user's
choice; an explicit share or unshare moves the hash between the sets.

### 2. Keep the withheld-files list out of `config.json`

**Why:** Unsharing a folder that is shared whole, or a large part of a partial
share, records every indexed path under it in
`settings.withheld_folder_files`. For a 100,000-file share that is several
megabytes in `config.json`, which has no size cap and is rewritten and synced
to disk on every settings save (scan cursors and pending intents save often).
`tidy_withheld` also walks the whole list on each save. 1.7.1 made this more
likely: Unshare folder on a whole share now gives it an empty allowlist and
withholds its indexed files (the M4 fix in the 1.7.1 audit).

**To do:**

- First check whether a folder with an **empty** allowlist needs per-path
  withheld entries at all. The empty list already keeps every file under it
  unshared. If the entries only keep those rows showing as "unshared" in the
  Library, derive that from the allowlist instead and stop writing them for
  empty lists. This alone removes the large case.
- For what remains (partial lists), move the withheld set into its own store:
  a table in `ember.db`, or a dedicated file next to `share_intent.json`.
  Either way it is written incrementally rather than rewritten with every
  settings save.
- Migrate on first load: move the entries out of `config.json` and clear the
  field.
- Downgrade: find out what 1.7.1 does with the field empty before choosing.
  If it would then offer files that should stay withheld, keep writing a
  bounded copy to `config.json` (for example only for folders under some size)
  until the next release that can drop downgrade support.

**Tests:** migration moves the entries and leaves `config.json` small; a
100,000-file Unshare folder adds nothing large to `config.json`; withheld rows
still show and stay unshared across a restart; a re-share clears them.

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
