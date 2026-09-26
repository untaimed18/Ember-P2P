<script lang="ts" module>
  import type { BrowseFileEntry as ListedFile } from '$lib/api/friends';

  interface CachedListing {
    files: ListedFile[];
    /** Distinct files the friend shares with us, when their build reports it. */
    total: number | null;
    /** Rows in the answer before de-duplication. */
    received: number;
    /** Unix seconds. */
    fetchedAt: number;
  }

  /** Each friend's last listing for this app session, most recently used
   *  last. Memory only: reopening the dialog shows it at once while a refresh
   *  runs, and it is gone on restart. */
  const listingCache = new Map<string, CachedListing>();
  const LISTING_CACHE_MAX = 20;

  function rememberListing(friend: string, listing: CachedListing) {
    listingCache.delete(friend);
    listingCache.set(friend, listing);
    while (listingCache.size > LISTING_CACHE_MAX) {
      const oldest = listingCache.keys().next().value;
      if (oldest === undefined) break;
      listingCache.delete(oldest);
    }
  }
</script>

<script lang="ts">
  import { onDestroy, untrack } from 'svelte';
  import { goto } from '$app/navigation';
  import { listen, type UnlistenFn } from '@tauri-apps/api/event';
  import {
    browseFriend,
    cancelBrowseFriend,
    type BrowseFileEntry,
  } from '$lib/api/friends';
  import { startDownload } from '$lib/api/transfers';
  import { formatEd2kLinks, getDownloadHistory } from '$lib/api/search';
  import { libraryHasHashes } from '$lib/api/sharing';
  import { transfers } from '$lib/stores/transfers';
  import {
    FILE_TYPE_FILTERS,
    extensionFromPath,
    fileTypeFilterLabel,
    fileTypeKey,
    type FileTypeFilter,
    type FileTypeKey,
  } from '$lib/fileTypes';
  import { copyToClipboard, formatClockTime, formatNumber, formatSize } from '$lib/utils';
  import * as m from '$lib/paraglide/messages';
  import { translateError } from '$lib/i18n';
  import { inertBackground, trapTabKey } from '$lib/a11y';
  import IconX from '$lib/components/IconX.svelte';

  interface Props {
    open: boolean;
    friendHash: string;
    friendName: string;
    friendLastIp: string;
    friendLastPort: number;
    onclose: () => void;
  }

  let { open = $bindable(), friendHash, friendName, friendLastIp, friendLastPort, onclose }: Props = $props();

  let files: BrowseFileEntry[] = $state([]);
  let filterQuery = $state('');
  let loading = $state(false);
  let error: string | null = $state(null);
  let unlisten: UnlistenFn | null = null;
  let listenerGen = 0;
  let browseTimeout: ReturnType<typeof setTimeout> | undefined;
  const MAX_BROWSE_FILES = 1_000;
  const instanceId = Math.random().toString(36).slice(2, 10);
  // M4: per-request gen used to disambiguate result/error events
  // from successive browses. Without it, a late error from request
  // N is dropped by the `loading` guard if request N+1 already
  // finished; with it, only events whose payload carries the gen
  // we're currently tracking land in the UI, so a real failure
  // never gets silently swallowed.
  let currentBrowseGen = 0;
  // Generation the listeners currently accept. requestBrowse assigns this
  // to myGen so a late result from a prior open can't land after reopen.
  let expectedBrowseGen = 0;
  let expectedRequestId = '';

  let typeFilter: FileTypeFilter = $state('All');
  type SortKey = 'name' | 'size';
  let sortKey: SortKey = $state('name');
  let sortAsc = $state(true);
  let hideOwned = $state(false);
  /** See {@link CachedListing}. */
  let total: number | null = $state(null);
  let received = $state(0);
  let listFetchedAt = $state(0);
  /** A request is in flight while a list (cached, or the previous one) stays
   *  on screen. `loading` is the other case: nothing to show yet. */
  let refreshing = $state(false);
  /** Why the last background refresh failed; the list on screen is older. */
  let refreshError: string | null = $state(null);
  let selectedHashes: Set<string> = $state(new Set());
  let selectionAnchor: string | null = null;
  let bulkDownloading = $state(false);
  let bulkConfirming = $state(false);
  let bulkStopRequested = $state(false);
  let bulkDone = $state(0);
  let bulkTotal = $state(0);
  let copyState: 'idle' | 'copying' | 'copied' = $state('idle');
  let copyResetTimer: ReturnType<typeof setTimeout> | undefined;
  /** Downloads queued since the dialog opened. */
  let queuedCount = $state(0);

  const BULK_CONFIRM_COUNT = 25;
  const BULK_CONFIRM_BYTES = 10 * 1024 ** 3;

  const VIEW_PREFS_KEY = 'browse-friend-view';
  try {
    const saved = JSON.parse(localStorage.getItem(VIEW_PREFS_KEY) ?? 'null');
    if (saved?.sortKey === 'name' || saved?.sortKey === 'size') sortKey = saved.sortKey;
    if (typeof saved?.sortAsc === 'boolean') sortAsc = saved.sortAsc;
    if (typeof saved?.hideOwned === 'boolean') hideOwned = saved.hideOwned;
  } catch {
    // Storage unavailable or the value corrupt: keep the defaults.
  }
  $effect(() => {
    const prefs = JSON.stringify({ sortKey, sortAsc, hideOwned });
    try {
      localStorage.setItem(VIEW_PREFS_KEY, prefs);
    } catch {
      // Not persisting a sort order is harmless.
    }
  });
  /** Hashes (lowercase) with a completed row in the download history. */
  let historyDoneHashes: Set<string> = $state(new Set());
  /** Hashes (lowercase) already in the user's library, however they got there. */
  let libraryHashes: Set<string> = $state(new Set());
  /** Hashes (lowercase) of downloads still in flight / already completed in
   *  the transfer list. Replaced only when membership changes, so the
   *  per-second progress ticks of `$transfers` don't re-render every row. */
  let inTransferHashes: Set<string> = $state(new Set());
  let completedTransferHashes: Set<string> = $state(new Set());

  const IN_FLIGHT_STATUSES: ReadonlySet<string> = new Set([
    'searching', 'queued', 'active', 'paused', 'stopped',
    'verifying', 'completing', 'hashing', 'insufficient', 'noneneeded',
  ]);
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

  let typeByHash = $derived(
    new Map<string, FileTypeKey | ''>(
      files.map((f) => [f.hash, fileTypeKey(extensionFromPath(f.name))]),
    ),
  );

  let ownedCount = $derived(libraryHashes.size === 0 ? 0 : files.filter(isInLibrary).length);
  let hidingOwned = $derived(hideOwned && ownedCount > 0);

  let textMatchedFiles = $derived.by(() => {
    const q = filterQuery.trim().toLowerCase();
    const base = hidingOwned ? files.filter((f) => !isInLibrary(f)) : files;
    if (!q) return base;
    return base.filter((file) => {
      const name = file.name.toLowerCase();
      const hash = file.hash.toLowerCase();
      return name.includes(q) || hash.includes(q);
    });
  });

  /** Per-category counts of the files the text filter leaves, so the bar shows
   *  where the matches are rather than what the friend shares overall. */
  let typeCounts = $derived.by(() => {
    const counts: Record<FileTypeFilter, number> = {
      All: textMatchedFiles.length, Audio: 0, Video: 0, Image: 0, Archive: 0, Document: 0, 'CD/DVD': 0,
    };
    for (const f of textMatchedFiles) {
      const key = typeByHash.get(f.hash);
      if (key) counts[key]++;
    }
    return counts;
  });

  let filteredFiles = $derived.by(() => {
    const list = typeFilter === 'All'
      ? [...textMatchedFiles]
      : textMatchedFiles.filter((f) => typeByHash.get(f.hash) === typeFilter);
    list.sort(
      sortKey === 'size'
        ? (a, b) => a.size - b.size || collator.compare(a.name, b.name)
        : (a, b) => collator.compare(a.name, b.name),
    );
    if (!sortAsc) list.reverse();
    return list;
  });

  let filteredTotalSize = $derived(filteredFiles.reduce((sum, f) => sum + f.size, 0));
  let isFiltered = $derived(Boolean(filterQuery.trim()) || typeFilter !== 'All' || hidingOwned);

  /** `known`: the friend reported more files than fit in one answer.
   *  `maybe`: an older friend filled the answer, the only hint there may be
   *  more. An older friend's answer cut short by its byte budget is invisible. */
  let truncation = $derived.by((): 'known' | 'maybe' | null => {
    if (total !== null) return total > files.length ? 'known' : null;
    return received >= MAX_BROWSE_FILES ? 'maybe' : null;
  });

  function isInLibrary(file: BrowseFileEntry): boolean {
    return libraryHashes.has(file.hash.toLowerCase());
  }

  function isDownloadedBefore(file: BrowseFileEntry): boolean {
    const h = file.hash.toLowerCase();
    return historyDoneHashes.has(h) || completedTransferHashes.has(h);
  }

  function isSelectable(file: BrowseFileEntry): boolean {
    return (
      !downloadedHashes.has(file.hash) &&
      !downloadingHashes.has(file.hash) &&
      !inTransferHashes.has(file.hash.toLowerCase())
    );
  }

  /** Selection survives switching category, so files can be picked across
   *  several; anything that became queued or started elsewhere drops out. */
  let selectedFiles = $derived(files.filter((f) => selectedHashes.has(f.hash) && isSelectable(f)));
  let selectedTotalSize = $derived(selectedFiles.reduce((sum, f) => sum + f.size, 0));
  /** What "select all" ticks. Files already in the library stay individually
   *  selectable — the library keeps rows whose file was deleted from disk, so
   *  re-fetching one is legitimate — but a blanket select shouldn't queue them. */
  let selectableVisible = $derived(filteredFiles.filter((f) => isSelectable(f) && !isInLibrary(f)));
  let allVisibleSelected = $derived(
    selectableVisible.length > 0 && selectableVisible.every((f) => selectedHashes.has(f.hash)),
  );
  let someVisibleSelected = $derived(selectableVisible.some((f) => selectedHashes.has(f.hash)));

  let needsBulkConfirm = $derived(
    selectedFiles.length > BULK_CONFIRM_COUNT ||
      (selectedFiles.length > 1 && selectedTotalSize > BULK_CONFIRM_BYTES),
  );

  function setSelection(next: Set<string>) {
    selectedHashes = next;
    // A confirmation names a count and size; a changed selection voids it.
    bulkConfirming = false;
  }

  /** Shift extends from the last row clicked to this one, taking the clicked
   *  row's new state; rows that can't be selected in between are skipped. */
  function onRowCheckboxClick(e: MouseEvent, file: BrowseFileEntry) {
    const next = new Set(selectedHashes);
    const select = !next.has(file.hash);
    const from = e.shiftKey && selectionAnchor
      ? filteredFiles.findIndex((f) => f.hash === selectionAnchor)
      : -1;
    const to = from === -1 ? -1 : filteredFiles.findIndex((f) => f.hash === file.hash);
    if (from !== -1 && to !== -1) {
      for (const f of filteredFiles.slice(Math.min(from, to), Math.max(from, to) + 1)) {
        if (!isSelectable(f)) continue;
        if (select) next.add(f.hash);
        else next.delete(f.hash);
      }
    } else if (select) {
      next.add(file.hash);
    } else {
      next.delete(file.hash);
    }
    selectionAnchor = file.hash;
    setSelection(next);
  }

  function toggleSelectAllVisible() {
    const next = new Set(selectedHashes);
    if (allVisibleSelected) {
      for (const f of selectableVisible) next.delete(f.hash);
    } else {
      for (const f of selectableVisible) next.add(f.hash);
    }
    setSelection(next);
  }

  function setSort(key: SortKey) {
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      // Largest first is the useful default for size; A→Z for names.
      sortAsc = key === 'name';
    }
  }

  function ariaSort(key: SortKey): 'ascending' | 'descending' | 'none' {
    if (sortKey !== key) return 'none';
    return sortAsc ? 'ascending' : 'descending';
  }

  function sameSet(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
    if (a.size !== b.size) return false;
    for (const v of a) if (!b.has(v)) return false;
    return true;
  }

  $effect(() => {
    if (!open) return;
    const active = new Set<string>();
    const done = new Set<string>();
    for (const t of $transfers) {
      if (t.direction !== 'download' || !t.file_hash) continue;
      const h = t.file_hash.toLowerCase();
      if (IN_FLIGHT_STATUSES.has(t.status)) active.add(h);
      else if (t.status === 'completed') done.add(h);
    }
    untrack(() => {
      if (!sameSet(active, inTransferHashes)) inTransferHashes = active;
      if (!sameSet(done, completedTransferHashes)) completedTransferHashes = done;
    });
  });

  /** Marks which listed files the user already has. Either lookup failing only
   *  loses its badges; the list itself stays usable. */
  async function loadOwnership(list: BrowseFileEntry[], gen: number) {
    if (list.length === 0) return;
    const hashes = list.map((f) => f.hash);
    const [history, library] = await Promise.allSettled([
      getDownloadHistory(hashes),
      libraryHasHashes(hashes),
    ]);
    if (gen !== listenerGen || !open) return;
    if (history.status === 'fulfilled') {
      const done = new Set<string>();
      for (const [h, status] of Object.entries(history.value)) {
        if (status === 'completed') done.add(h.toLowerCase());
      }
      historyDoneHashes = done;
    } else {
      console.warn('BrowseFriendDialog: failed to load download history', history.reason);
    }
    if (library.status === 'fulfilled') {
      libraryHashes = new Set(library.value.map((h) => h.toLowerCase()));
    } else {
      console.warn('BrowseFriendDialog: failed to check library', library.reason);
    }
  }

  /** Per-result view state. Sort order and the category survive a refresh;
   *  opening the dialog resets the category separately. */
  function resetResultViewState() {
    total = null;
    received = 0;
    listFetchedAt = 0;
    refreshing = false;
    refreshError = null;
    selectedHashes = new Set();
    selectionAnchor = null;
    historyDoneHashes = new Set();
    libraryHashes = new Set();
    bulkDownloading = false;
    bulkConfirming = false;
  }

  function applyListing(listing: CachedListing) {
    files = listing.files;
    total = listing.total;
    received = listing.received;
    listFetchedAt = listing.fetchedAt;
  }

  /** A failure keeps a list already on screen (cached, or the one a refresh
   *  was replacing) and says it is stale; with nothing to show, the failure
   *  takes the body. */
  function failBrowse(message: string) {
    loading = false;
    if (files.length > 0) {
      refreshing = false;
      refreshError = message;
    } else {
      error = message;
    }
  }

  let hasUsableFriendAddress = $derived(
    Boolean(
      friendLastIp?.trim() &&
        friendLastIp.trim() !== '0.0.0.0' &&
        friendLastPort > 0,
    ),
  );

  $effect(() => {
    // Capture outside the `if` so cleanup can cancel the in-flight
    // request even after `open` has already gone false (the previous
    // `hash` lived inside the branch and was out of scope on close).
    const hash = friendHash;
    if (open && hash) {
      // Capture the generation BEFORE awaiting so we can detect a
      // close/re-open race: if the user closes the dialog (or
      // switches friend) while `setupListener` is still awaiting,
      // the cleanup destructor bumps `listenerGen` and we abort
      // before issuing a stale `requestBrowse()`. Without this, a
      // closed dialog could still fire IPC and corrupt the next
      // session's state.
      const gen = ++listenerGen;
      // Clear previous session synchronously so reopen never paints
      // the prior friend's file list (or allows downloads from it)
      // while listeners are still being registered.
      loading = true;
      error = null;
      downloadError = null;
      downloadNote = null;
      listenerWarning = null;
      files = [];
      filterQuery = '';
      typeFilter = 'All';
      resetResultViewState();
      queuedCount = 0;
      downloadedHashes = new Set();
      downloadingHashes = new Set();
      const cached = listingCache.get(hash);
      if (cached) {
        applyListing(cached);
        loading = false;
        void loadOwnership(cached.files, gen);
      }
      (async () => {
        try {
          const ok = await setupListener(gen, hash);
          if (!ok || gen !== listenerGen || !open) {
            if (gen === listenerGen && open) loading = false;
            return;
          }
          await requestBrowse(hash, true);
        } catch (e: unknown) {
          if (gen === listenerGen && open) {
            failBrowse(translateError(e, m.browse_failed_to_browse()));
          }
        }
      })();
    }
    return () => {
      if (expectedRequestId && hash) {
        void cancelBrowseFriend(hash, expectedRequestId).catch((e) =>
          console.error('Failed to cancel friend browse:', e),
        );
      }
      listenerGen++;
      currentBrowseGen = 0;
      expectedBrowseGen = 0;
      expectedRequestId = '';
      loading = false;
      files = [];
      filterQuery = '';
      resetResultViewState();
      queuedCount = 0;
      clearTimeout(copyResetTimer);
      copyState = 'idle';
      error = null;
      downloadError = null;
      downloadNote = null;
      listenerWarning = null;
      downloadedHashes = new Set();
      downloadingHashes = new Set();
      clearTimeout(browseTimeout);
      if (unlisten) { unlisten(); unlisten = null; }
      if (unlistenError) { unlistenError(); unlistenError = null; }
    };
  });

  let unlistenError: UnlistenFn | null = null;

  /**
   * Retry the whole browse, listeners included.
   *
   * Not just `requestBrowse`: the error on screen may be the listener
   * registration itself having failed, in which case nothing is attached and a
   * bare re-request puts the dialog back on its spinner while results arrive to
   * no handler at all. Reopening the dialog was the only way out, because that is
   * what re-runs the effect above. This is that effect's body, on demand.
   *
   * With a list on screen it refreshes in place: the list stays usable and is
   * swapped when the answer lands, or kept (marked stale) if none does.
   */
  async function retryBrowse() {
    const hash = friendHash;
    if (!hash) return;
    const keepList = files.length > 0;
    const gen = ++listenerGen;
    error = null;
    listenerWarning = null;
    if (keepList) {
      refreshing = true;
      refreshError = null;
    } else {
      loading = true;
      downloadError = null;
      downloadNote = null;
      files = [];
      resetResultViewState();
    }
    try {
      const ok = await setupListener(gen, hash);
      if (!ok || gen !== listenerGen || !open) {
        if (gen === listenerGen && open) {
          loading = false;
          refreshing = false;
        }
        return;
      }
      await requestBrowse(hash, keepList);
    } catch (e: unknown) {
      if (gen === listenerGen && open) {
        failBrowse(translateError(e, m.browse_failed_to_browse()));
      }
    }
  }

  /// Returns true on success, false if either listener registration
  /// failed (caller should NOT proceed to requestBrowse — without
  /// the listeners we'd never see results / errors and the user
  /// would just stare at a spinner). The previous implementation
  /// `return`ed on failure but the caller still called
  /// `requestBrowse()` afterward — which then ran `error = null`
  /// and wiped the actionable error message before the user saw it.
  async function setupListener(gen: number, hash: string): Promise<boolean> {
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenError) { unlistenError(); unlistenError = null; }
    let fn: UnlistenFn;
    try {
      fn = await listen<{
        user_hash: string;
        request_id: string;
        files: BrowseFileEntry[];
        total?: number | null;
      }>('ember:browse-result', (event) => {
        if (event.payload.user_hash !== hash) return;
        // Only accept results for the in-flight browse generation.
        // `currentBrowseGen === 0` means dismissed; mismatch vs
        // `expectedBrowseGen` means a stale result from a prior open.
        if (
          currentBrowseGen === 0 ||
          currentBrowseGen !== expectedBrowseGen ||
          event.payload.request_id !== expectedRequestId
        ) return;
        clearTimeout(browseTimeout);
        // Defensive: treat missing/invalid `files` as empty rather than
        // crashing the dialog if the backend ever emits a malformed payload.
        // De-duplicate by hash before rendering: the sharer's index is keyed
        // by path, so two copies of one file under a shared folder arrive as
        // two entries with the same hash — and the table keys on hash, which
        // Svelte 5 turns into a thrown error on collision.
        const raw = Array.isArray(event.payload.files) ? event.payload.files : [];
        const unique = [...new Map(raw.map((f) => [f.hash, f])).values()];
        const reported = event.payload.total;
        const listing: CachedListing = {
          files: unique.slice(0, MAX_BROWSE_FILES),
          total:
            typeof reported === 'number' && Number.isSafeInteger(reported) && reported >= 0
              ? reported
              : null,
          received: raw.length,
          fetchedAt: Math.floor(Date.now() / 1000),
        };
        rememberListing(hash, listing);
        const wasEmpty = files.length === 0;
        const present = new Set(listing.files.map((f) => f.hash));
        selectedHashes = new Set([...selectedHashes].filter((h) => present.has(h)));
        applyListing(listing);
        loading = false;
        refreshing = false;
        refreshError = null;
        void loadOwnership(listing.files, gen);
        // Successful result terminates this browse generation; a
        // later error for the same friend is most likely from a
        // separate (subsequent) request and shouldn't replace the
        // result we just rendered.
        currentBrowseGen = 0;
        // Only on a first paint: a refresh landing mid-interaction must not
        // pull focus away from whatever the user is doing.
        if (wasEmpty) requestAnimationFrame(() => filterInputEl?.focus());
      });
    } catch (e) {
      console.warn('BrowseFriendDialog: failed to register browse-result listener', e);
      failBrowse(m.browse_listener_failed());
      return false;
    }
    if (gen !== listenerGen) { fn(); return false; }
    unlisten = fn;

    let errFn: UnlistenFn;
    try {
      errFn = await listen<{ user_hash: string; request_id: string; reason: string }>('ember:browse-error', (event) => {
        if (event.payload.user_hash !== hash) return;
        // M4: key on browse generation so a late error after a
        // successful result (gen cleared) is discarded, and a stale
        // error from a prior open can't land after reopen.
        if (
          currentBrowseGen === 0 ||
          currentBrowseGen !== expectedBrowseGen ||
          event.payload.request_id !== expectedRequestId
        ) return;
        clearTimeout(browseTimeout);
        // Run the backend reason through `translateError` so a coded error is
        // localized; a plain string falls through unchanged, and an empty
        // reason uses the friendly offline fallback.
        failBrowse(
          event.payload.reason
            ? translateError(event.payload.reason, m.browse_failed_offline())
            : m.browse_failed_offline(),
        );
        currentBrowseGen = 0;
      });
    } catch (e) {
      console.warn('BrowseFriendDialog: failed to register browse-error listener', e);
      // Soft warning only — result listener is still live. Kept separate
      // from `error` so requestBrowse() does not wipe it immediately.
      listenerWarning = m.browse_error_notifications_unavailable();
      // Returning true: the result listener is live and the caller
      // can still request browse. We just won't see backend errors
      // until the next dialog open.
      return true;
    }
    if (gen !== listenerGen) { errFn(); return false; }
    unlistenError = errFn;
    return true;
  }

  /** `keepList` refreshes behind a list already on screen instead of clearing
   *  it; ignored when there is none. */
  async function requestBrowse(hash: string, keepList = false) {
    error = null;
    if (keepList && files.length > 0) {
      refreshing = true;
      refreshError = null;
    } else {
      loading = true;
      downloadError = null;
      downloadNote = null;
      downloadedHashes = new Set();
      downloadingHashes = new Set();
      filterQuery = '';
      files = [];
      resetResultViewState();
    }
    clearTimeout(browseTimeout);
    // Open a fresh browse generation so the listeners above will
    // accept events for THIS request even if a result and a late
    // error race each other on the wire.
    currentBrowseGen++;
    const myGen = currentBrowseGen;
    expectedBrowseGen = myGen;
    expectedRequestId = typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${instanceId}-${Date.now()}-${myGen}`;
    const myRequestId = expectedRequestId;
    try {
      await browseFriend(hash, myRequestId);
      browseTimeout = setTimeout(() => {
        if (
          currentBrowseGen === myGen &&
          expectedRequestId === myRequestId &&
          (loading || refreshing)
        ) {
          failBrowse(m.browse_request_timed_out());
          void cancelBrowseFriend(hash, myRequestId).catch((e) =>
            console.error('Failed to cancel friend browse:', e),
          );
          currentBrowseGen = 0;
        }
      }, 30_000);
    } catch (e: unknown) {
      failBrowse(translateError(e, m.browse_failed_to_browse()));
      if (currentBrowseGen === myGen) currentBrowseGen = 0;
    }
  }

  let downloadError: string | null = $state(null);
  let downloadNote: string | null = $state(null);
  let listenerWarning: string | null = $state(null);
  let downloadedHashes: Set<string> = $state(new Set());
  // Tracks hashes with a `startDownload` call currently in flight. The
  // `downloadedHashes` guard alone only prevents a re-click AFTER the first
  // call resolves — a fast double-click on the download button fires both
  // clicks before either `await` settles, so both would call `startDownload`
  // for the same file without this.
  let downloadingHashes: Set<string> = $state(new Set());

  /** Returns whether the download was queued. `quiet` leaves `downloadError`
   *  to the caller, which the bulk path uses to report one summary instead of
   *  whichever failure happened last. */
  async function downloadFile(file: BrowseFileEntry, quiet = false): Promise<boolean> {
    if (downloadedHashes.has(file.hash) || downloadingHashes.has(file.hash)) return false;
    if (!quiet) downloadError = null;
    downloadingHashes = new Set(downloadingHashes).add(file.hash);
    const peerIp = hasUsableFriendAddress ? friendLastIp.trim() : '';
    const peerPort = hasUsableFriendAddress ? friendLastPort : 0;
    try {
      await startDownload(
        file.hash,
        file.name,
        file.size,
        peerIp,
        peerPort,
        undefined,
        file.ember_file_hash,
        file.aich_hash,
        friendHash,
      );
      downloadedHashes = new Set(downloadedHashes).add(file.hash);
      queuedCount++;
      if (!hasUsableFriendAddress) {
        downloadNote = m.browse_download_discovery_note();
      }
      return true;
    } catch (e: unknown) {
      if (!quiet) downloadError = translateError(e, m.browse_download_failed());
      else console.error('Friend browse download failed:', e);
      return false;
    } finally {
      const next = new Set(downloadingHashes);
      next.delete(file.hash);
      downloadingHashes = next;
    }
  }

  /** Large selections ask once, inline, before anything is queued. */
  function requestDownloadSelected() {
    if (bulkDownloading || selectedFiles.length === 0) return;
    if (needsBulkConfirm && !bulkConfirming) {
      bulkConfirming = true;
      return;
    }
    bulkConfirming = false;
    void downloadSelected();
  }

  async function downloadSelected() {
    const targets = selectedFiles;
    const gen = listenerGen;
    bulkDownloading = true;
    bulkStopRequested = false;
    bulkDone = 0;
    bulkTotal = targets.length;
    downloadError = null;
    let failed = 0;
    let attempted = 0;
    try {
      for (const file of targets) {
        // Closed, refreshed or switched friend: stop rather than queue files
        // from a listing the user is no longer looking at.
        if (gen !== listenerGen || !open) return;
        if (bulkStopRequested) break;
        // Queued meanwhile through its own row button: not a failure.
        if (isSelectable(file)) {
          attempted++;
          if (!(await downloadFile(file, true))) failed++;
        }
        bulkDone++;
      }
      // Failures and anything Stop left unreached stay ticked, ready for
      // another go.
      setSelection(new Set([...selectedHashes].filter((h) => !downloadedHashes.has(h))));
      if (failed > 0) {
        downloadError = m.browse_download_selected_failed({ failed, total: attempted });
      }
    } finally {
      if (gen === listenerGen) bulkDownloading = false;
    }
  }

  async function copySelectedLinks() {
    if (copyState === 'copying' || selectedFiles.length === 0) return;
    copyState = 'copying';
    clearTimeout(copyResetTimer);
    try {
      const text = await formatEd2kLinks(
        selectedFiles.map((f) => ({
          name: f.name,
          size: f.size,
          hash: f.hash,
          emberFileHash: f.ember_file_hash || undefined,
        })),
      );
      if (!(await copyToClipboard(text))) {
        copyState = 'idle';
        downloadError = m.search_copy_failed();
        return;
      }
      copyState = 'copied';
      copyResetTimer = setTimeout(() => (copyState = 'idle'), 2_000);
    } catch (e: unknown) {
      copyState = 'idle';
      downloadError = translateError(e, m.search_copy_failed());
    }
  }

  function viewTransfers() {
    onclose();
    void goto('/transfers');
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopPropagation();
      if (bulkConfirming) {
        bulkConfirming = false;
        return;
      }
      onclose();
      return;
    }
    trapTabKey(e, modalEl);
  }

  let modalEl: HTMLDivElement | undefined = $state(undefined);
  let dialogRootEl: HTMLDivElement | undefined = $state(undefined);
  let filterInputEl: HTMLInputElement | undefined = $state(undefined);
  let returnFocusEl: HTMLElement | null = null;

  $effect(() => {
    if (open) {
      const active = typeof document !== 'undefined' ? document.activeElement : null;
      if (active instanceof HTMLElement && active !== document.body) returnFocusEl = active;
      requestAnimationFrame(() => {
        modalEl?.querySelector<HTMLButtonElement>('button:not([disabled])')?.focus();
      });
    }
    return () => {
      if (!open && returnFocusEl) {
        const el = returnFocusEl;
        returnFocusEl = null;
        requestAnimationFrame(() => {
          if (typeof document !== 'undefined' && document.contains(el)) el.focus();
        });
      }
    };
  });

  $effect(() => {
    if (!open || !dialogRootEl) return;
    return inertBackground(dialogRootEl);
  });

  onDestroy(() => {
    clearTimeout(browseTimeout);
    clearTimeout(copyResetTimer);
    if (unlisten) { unlisten(); unlisten = null; }
    if (unlistenError) { unlistenError(); unlistenError = null; }
  });
</script>

<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
{#if open}
  <div bind:this={dialogRootEl}>
    <!-- svelte-ignore a11y_click_events_have_key_events -->
    <!-- svelte-ignore a11y_no_static_element_interactions -->
    <div class="browse-overlay" onclick={onclose}></div>
    <!-- svelte-ignore a11y_interactive_supports_focus -->
    <div
      class="browse-modal"
      role="dialog"
      aria-modal="true"
      aria-labelledby="browse-title-{instanceId}"
      tabindex="-1"
      bind:this={modalEl}
      onkeydown={handleKeydown}
    >
      <div class="browse-header">
        <div class="browse-header-text">
          <h3 id="browse-title-{instanceId}">{m.browse_title_prefix()}</h3>
          <p class="browse-subtitle" title={friendName || friendHash}>
            <bdi dir="auto">{friendName || friendHash.slice(0, 8) + '\u2026'}</bdi>
          </p>
        </div>
        <div class="browse-header-actions">
          <button
            type="button"
            class="browse-icon-btn"
            class:spinning={loading || refreshing}
            onclick={() => void retryBrowse()}
            disabled={loading || refreshing || bulkDownloading}
            aria-busy={loading || refreshing}
            title={m.common_refresh()}
            aria-label={m.common_refresh()}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><polyline points="13.5 2.5 13.5 5.5 10.5 5.5"/>
            </svg>
          </button>
          <button type="button" class="browse-close" onclick={onclose} title={m.common_close()} aria-label={m.common_close()}>
            <IconX size={16} />
          </button>
        </div>
      </div>

      <div class="browse-body">
        {#if loading}
          <div class="browse-status">{m.browse_requesting()}</div>
        {:else if error}
          <div class="browse-error">
            <p>{error}</p>
            <button type="button" class="browse-retry" onclick={() => void retryBrowse()}>{m.common_retry()}</button>
          </div>
        {:else if files.length === 0}
          <div class="browse-status">{m.browse_no_files()}</div>
        {:else}
          <div class="browse-toolbar">
            <div class="browse-categories" role="group" aria-label={m.library_type_filter_aria()}>
              {#each FILE_TYPE_FILTERS as opt (opt)}
                <button
                  type="button"
                  class="browse-category"
                  class:active={typeFilter === opt}
                  aria-pressed={typeFilter === opt}
                  disabled={opt !== 'All' && opt !== typeFilter && typeCounts[opt] === 0}
                  onclick={() => (typeFilter = opt)}
                >
                  <span>{fileTypeFilterLabel(opt)}</span>
                  <span class="browse-category-count">{formatNumber(typeCounts[opt])}</span>
                </button>
              {/each}
            </div>
            <div class="browse-filter-row">
              <div class="browse-filter">
                <span class="browse-filter-icon" aria-hidden="true">
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round">
                    <circle cx="7" cy="7" r="4.5"/><line x1="10.5" y1="10.5" x2="13.5" y2="13.5"/>
                  </svg>
                </span>
                <input
                  bind:this={filterInputEl}
                  class="browse-filter-input"
                  type="search"
                  bind:value={filterQuery}
                  placeholder={m.browse_filter_placeholder()}
                  aria-label={m.browse_filter_placeholder()}
                />
                {#if filterQuery.trim()}
                  <button
                    type="button"
                    class="browse-filter-clear"
                    onclick={() => {
                      filterQuery = '';
                      filterInputEl?.focus();
                    }}
                    title={m.common_clear()}
                    aria-label={m.common_clear()}
                  ><IconX size={14} /></button>
                {/if}
              </div>
              {#if ownedCount > 0}
                <button
                  type="button"
                  class="browse-category browse-toggle"
                  class:active={hideOwned}
                  aria-pressed={hideOwned}
                  onclick={() => (hideOwned = !hideOwned)}
                >
                  <span class="browse-toggle-box" aria-hidden="true">
                    {#if hideOwned}
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="3.5 8.5 6.5 11.5 12.5 5"/>
                      </svg>
                    {/if}
                  </span>
                  <span>{m.browse_hide_owned()}</span>
                  <span class="browse-category-count">{formatNumber(ownedCount)}</span>
                </button>
              {/if}
            </div>
            <div class="browse-count-row">
              <div class="browse-count">
                {#if isFiltered}
                  {m.browse_count_filtered({ filtered: filteredFiles.length, total: files.length })}
                {:else if files.length === 1}
                  {m.browse_count_one()}
                {:else}
                  {m.browse_count_other({ count: files.length })}
                {/if}
                <span aria-hidden="true">·</span>
                {formatSize(filteredTotalSize)}
              </div>
              {#if bulkDownloading}
                <div class="browse-selection" role="status">
                  <span class="dl-spinner" aria-hidden="true"></span>
                  <span class="browse-selection-summary">
                    {m.browse_bulk_progress({ done: formatNumber(bulkDone), total: formatNumber(bulkTotal) })}
                  </span>
                  <button
                    type="button"
                    class="browse-secondary-btn"
                    onclick={() => (bulkStopRequested = true)}
                    disabled={bulkStopRequested}
                  >{m.common_stop()}</button>
                </div>
              {:else if bulkConfirming && selectedFiles.length > 0}
                <div class="browse-selection browse-selection-confirm" role="alert">
                  <span class="browse-selection-summary">
                    {m.browse_bulk_confirm({ count: formatNumber(selectedFiles.length), size: formatSize(selectedTotalSize) })}
                  </span>
                  <button
                    type="button"
                    class="browse-secondary-btn"
                    onclick={() => (bulkConfirming = false)}
                  >{m.common_cancel()}</button>
                  <button
                    type="button"
                    class="dl-btn"
                    onclick={requestDownloadSelected}
                    {@attach (el: HTMLButtonElement) => el.focus()}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                    </svg>
                    <span>{m.browse_download()}</span>
                  </button>
                </div>
              {:else if selectedFiles.length > 0}
                <div class="browse-selection">
                  <span class="browse-selection-summary">
                    {m.browse_selected_summary({ count: formatNumber(selectedFiles.length), size: formatSize(selectedTotalSize) })}
                  </span>
                  <button
                    type="button"
                    class="browse-link-btn"
                    onclick={() => setSelection(new Set())}
                  >{m.common_clear()}</button>
                  <button
                    type="button"
                    class="browse-secondary-btn"
                    onclick={() => void copySelectedLinks()}
                    disabled={copyState === 'copying'}
                    aria-live="polite"
                  >
                    {#if copyState === 'copied'}
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <polyline points="3 8 7 12 13 4"/>
                      </svg>
                      <span>{m.common_copied()}</span>
                    {:else}
                      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                        <path d="M6.5 9.5a3 3 0 0 0 4.2 0l2.1-2.1a3 3 0 0 0-4.2-4.2l-.7.7"/><path d="M9.5 6.5a3 3 0 0 0-4.2 0L3.2 8.6a3 3 0 0 0 4.2 4.2l.7-.7"/>
                      </svg>
                      <span>{m.browse_copy_links()}</span>
                    {/if}
                  </button>
                  <button
                    type="button"
                    class="dl-btn"
                    onclick={requestDownloadSelected}
                  >
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                    </svg>
                    <span>{m.browse_download_selected()}</span>
                  </button>
                </div>
              {/if}
            </div>
          </div>

          {#if refreshError}
            <div class="browse-banner browse-banner-error" role="alert" title={refreshError}>
              <span>{m.browse_refresh_failed({ time: formatClockTime(listFetchedAt, { hour: 'numeric', minute: '2-digit' }) })}</span>
              <button type="button" class="browse-link-btn" onclick={() => void retryBrowse()}>{m.common_retry()}</button>
            </div>
          {/if}
          {#if truncation === 'known'}
            <div class="browse-banner browse-banner-note" role="status">
              {m.browse_showing_of_total({ shown: formatNumber(files.length), total: formatNumber(total ?? 0) })}
            </div>
          {:else if truncation === 'maybe'}
            <div class="browse-banner browse-banner-note" role="status">{m.browse_may_share_more()}</div>
          {/if}
          {#if queuedCount > 0}
            <div class="browse-banner browse-banner-success" role="status">
              <span>{queuedCount === 1 ? m.browse_added_one() : m.browse_added_other({ count: formatNumber(queuedCount) })}</span>
              <button type="button" class="browse-link-btn" onclick={viewTransfers}>{m.browse_view_transfers()}</button>
            </div>
          {/if}
          {#if listenerWarning}
            <div class="browse-banner browse-banner-note" role="status">{listenerWarning}</div>
          {/if}
          {#if downloadError}
            <div class="browse-banner browse-banner-error" role="alert">{downloadError}</div>
          {/if}
          {#if downloadNote}
            <div class="browse-banner browse-banner-note" role="status">{downloadNote}</div>
          {/if}

          {#if filteredFiles.length === 0}
            <div class="browse-status browse-status-compact">{m.browse_no_match()}</div>
          {:else}
            <div class="browse-table-wrap">
              <table class="browse-table">
                <thead>
                  <tr>
                    <th class="col-select">
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        {@attach (el: HTMLInputElement) => {
                          el.indeterminate = someVisibleSelected && !allVisibleSelected;
                        }}
                        disabled={selectableVisible.length === 0 || bulkDownloading}
                        onchange={toggleSelectAllVisible}
                        title={m.common_select_all()}
                        aria-label={m.common_select_all()}
                      />
                    </th>
                    <th class="col-name" aria-sort={ariaSort('name')}>
                      <button type="button" class="sort-btn" onclick={() => setSort('name')}>
                        {m.browse_col_name()}
                        {#if sortKey === 'name'}<span class="sort-arrow" aria-hidden="true">{sortAsc ? '▲' : '▼'}</span>{/if}
                      </button>
                    </th>
                    <th class="col-size" aria-sort={ariaSort('size')}>
                      <button type="button" class="sort-btn" onclick={() => setSort('size')}>
                        {m.browse_col_size()}
                        {#if sortKey === 'size'}<span class="sort-arrow" aria-hidden="true">{sortAsc ? '▲' : '▼'}</span>{/if}
                      </button>
                    </th>
                    <th class="col-action">{m.browse_col_action()}</th>
                  </tr>
                </thead>
                <tbody>
                  {#each filteredFiles as file (file.hash)}
                    {@const selectable = isSelectable(file)}
                    <tr class:selected={selectable && selectedHashes.has(file.hash)}>
                      <td class="col-select">
                        <input
                          type="checkbox"
                          checked={selectable && selectedHashes.has(file.hash)}
                          disabled={!selectable || bulkDownloading}
                          onmousedown={(e) => {
                            // Shift-click would otherwise select the text between rows.
                            if (e.shiftKey) e.preventDefault();
                          }}
                          onclick={(e) => onRowCheckboxClick(e, file)}
                          title={m.browse_range_hint()}
                          aria-label={m.browse_select_file({ name: file.name })}
                        />
                      </td>
                      <!--
                        M14: file names come from the remote peer and
                        can contain RTL/LTR override characters that
                        reorder neighbouring elements ("Trojan Source"
                        style spoof). `<bdi>` isolates each name's
                        bidi influence to the cell, so a malicious
                        name can't reverse the size column or action
                        button next to it. The text itself is still
                        rendered exactly as written.
                      -->
                      <td class="col-name" title={file.name}>
                        <div class="name-cell">
                          <bdi dir="auto" class="name-text">{file.name}</bdi>
                          {#if file.friends_only}
                            <span class="file-tag tag-friends" title={m.browse_friends_only_title()}>{m.library_friends_only_badge()}</span>
                          {/if}
                          {#if isInLibrary(file)}
                            <span class="file-tag tag-done" title={m.search_history_in_library_title()}>{m.search_history_in_library()}</span>
                          {:else if isDownloadedBefore(file)}
                            <span class="file-tag tag-done" title={m.browse_downloaded_before_title()}>{m.search_history_downloaded()}</span>
                          {/if}
                        </div>
                      </td>
                      <td class="col-size">{formatSize(file.size)}</td>
                      <td class="col-action">
                        {#if downloadedHashes.has(file.hash)}
                          <span class="dl-done" title={m.browse_queued()} aria-label={m.browse_queued()}>
                            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                              <polyline points="3 8 7 12 13 4"/>
                            </svg>
                            <span>{m.browse_queued()}</span>
                          </span>
                        {:else if inTransferHashes.has(file.hash.toLowerCase())}
                          <span class="dl-state">{m.browse_in_transfers()}</span>
                        {:else}
                          <button
                            type="button"
                            class="dl-btn"
                            onclick={() => downloadFile(file)}
                            disabled={downloadingHashes.has(file.hash)}
                            title={downloadingHashes.has(file.hash) ? m.browse_downloading() : m.browse_download()}
                            aria-label={downloadingHashes.has(file.hash) ? m.browse_downloading() : m.browse_download()}
                          >
                            {#if downloadingHashes.has(file.hash)}
                              <span class="dl-spinner" aria-hidden="true"></span>
                              <span>{m.browse_downloading()}</span>
                            {:else}
                              <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                <path d="M8 2v9M4 8l4 4 4-4"/><line x1="3" y1="14" x2="13" y2="14"/>
                              </svg>
                              <span>{m.browse_download()}</span>
                            {/if}
                          </button>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  .browse-overlay {
    position: fixed;
    inset: 0;
    background: var(--overlay-bg);
    z-index: 10000;
    animation: browse-fade-in 0.15s ease;
  }

  :global([data-theme='dark']) .browse-overlay {
    backdrop-filter: blur(6px) saturate(1.15);
    -webkit-backdrop-filter: blur(6px) saturate(1.15);
  }

  .browse-modal {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 820px;
    max-width: 94vw;
    max-height: 80vh;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    z-index: 10001;
    display: flex;
    flex-direction: column;
    box-shadow:
      inset 0 1px 0 var(--surface-highlight),
      var(--shadow-lg);
    animation: browse-pop-in 0.2s ease;
  }

  /* Keyframe keeps the translate centering while scaling/fading in. */
  @keyframes browse-fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes browse-pop-in {
    from { opacity: 0; transform: translate(-50%, -50%) scale(0.96); }
    to { opacity: 1; transform: translate(-50%, -50%) scale(1); }
  }

  .browse-header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .browse-header-text {
    min-width: 0;
  }

  .browse-header h3 {
    margin: 0;
    font-size: 15px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .browse-subtitle {
    margin: 4px 0 0;
    font-size: 13px;
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .browse-close {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    flex-shrink: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
    line-height: 1;
    font-weight: 500;
  }

  .browse-close:hover {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .browse-header-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  }

  .browse-icon-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
  }

  .browse-icon-btn svg {
    width: 15px;
    height: 15px;
  }

  .browse-icon-btn:hover:not(:disabled) {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .browse-icon-btn:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .browse-icon-btn.spinning:disabled {
    opacity: 0.8;
  }

  .browse-icon-btn.spinning svg {
    animation: browse-spin 0.9s linear infinite;
  }

  @media (prefers-reduced-motion: reduce) {
    .browse-icon-btn.spinning svg {
      animation: none;
    }
  }

  .browse-categories {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
  }

  .browse-category {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font: inherit;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
  }

  .browse-category:hover:not(:disabled):not(.active) {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .browse-category.active {
    color: var(--accent);
    border-color: color-mix(in srgb, var(--accent) 55%, var(--border));
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .browse-category:disabled {
    opacity: 0.45;
    cursor: default;
  }

  .browse-category-count {
    font-size: 11px;
    font-variant-numeric: tabular-nums;
    color: var(--text-muted);
  }

  .browse-category.active .browse-category-count {
    color: inherit;
  }

  .browse-body {
    flex: 1;
    min-height: 0;
    overflow: hidden;
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .browse-status,
  .browse-error {
    text-align: center;
    padding: 32px 16px;
    font-size: 13px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
  }

  .browse-error p {
    margin: 0;
  }

  .browse-retry {
    font: inherit;
    font-size: 13px;
    padding: 6px 12px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
  }

  .browse-retry:hover {
    background: var(--bg-hover);
  }

  .browse-status-compact {
    padding: 24px 16px;
  }

  .browse-status { color: var(--text-muted); }
  .browse-error { color: var(--danger); }

  .browse-toolbar {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex-shrink: 0;
  }

  .browse-filter-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .browse-filter {
    position: relative;
    display: flex;
    align-items: center;
    flex: 1;
    min-width: 0;
  }

  .browse-toggle {
    flex-shrink: 0;
    white-space: nowrap;
    padding-top: 7px;
    padding-bottom: 7px;
  }

  .browse-toggle-box {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 14px;
    height: 14px;
    border: 1.5px solid currentColor;
    border-radius: 4px;
    opacity: 0.8;
  }

  .browse-toggle-box svg {
    width: 11px;
    height: 11px;
  }

  .browse-filter-icon {
    position: absolute;
    left: 10px;
    color: var(--text-muted);
    display: flex;
    pointer-events: none;
  }

  .browse-filter-icon svg {
    width: 14px;
    height: 14px;
  }

  .browse-filter-input {
    width: 100%;
    padding: 8px 32px 8px 32px;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: var(--bg-input);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
  }

  .browse-filter-input:focus {
    border-color: var(--accent);
    outline: none;
  }

  .browse-filter-clear {
    position: absolute;
    right: 6px;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    line-height: 1;
  }

  .browse-filter-clear:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .browse-count-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
    min-height: 30px;
  }

  .browse-count {
    font-size: 12px;
    color: var(--text-muted);
  }

  .browse-selection {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .browse-selection-summary {
    font-size: 12px;
    color: var(--text-secondary);
    font-variant-numeric: tabular-nums;
  }

  .browse-selection-confirm .browse-selection-summary {
    color: var(--text-primary);
    font-weight: 600;
  }

  .browse-secondary-btn {
    min-height: 30px;
    padding: 0 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font: inherit;
    font-size: 12px;
    font-weight: 500;
    transition: background var(--transition-fast), border-color var(--transition-fast);
  }

  .browse-secondary-btn:hover:not(:disabled) {
    background: var(--bg-hover);
  }

  .browse-secondary-btn:disabled {
    opacity: 0.6;
    cursor: default;
  }

  .browse-secondary-btn svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  .browse-link-btn {
    padding: 0;
    border: none;
    background: none;
    color: var(--text-muted);
    font: inherit;
    font-size: 12px;
    cursor: pointer;
    text-decoration: underline;
    text-underline-offset: 2px;
  }

  .browse-link-btn:hover:not(:disabled) {
    color: var(--text-primary);
  }

  .browse-link-btn:disabled {
    opacity: 0.5;
    cursor: default;
  }

  .browse-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    font-size: 12px;
    padding: 8px 10px;
    border-radius: var(--radius-md);
    flex-shrink: 0;
  }

  .browse-banner .browse-link-btn {
    flex-shrink: 0;
    color: inherit;
    font-weight: 600;
  }

  .browse-banner-success {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 12%, transparent);
  }

  .browse-banner-error {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .browse-banner-note {
    color: var(--text-muted);
    background: color-mix(in srgb, var(--accent) 10%, transparent);
  }

  .browse-table-wrap {
    flex: 1;
    min-height: 0;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .browse-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  .browse-table th {
    position: sticky;
    top: 0;
    z-index: 1;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--text-muted);
    padding: 8px 10px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    background: var(--bg-primary);
  }

  .browse-table td {
    padding: 8px 10px;
    border-bottom: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
    color: var(--text-primary);
    vertical-align: middle;
  }

  .browse-table tbody tr:hover td {
    background: color-mix(in srgb, var(--bg-hover) 70%, transparent);
  }

  .browse-table tbody tr.selected td {
    background: color-mix(in srgb, var(--accent) 8%, transparent);
  }

  .sort-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 0;
    border: none;
    background: none;
    color: inherit;
    font: inherit;
    letter-spacing: inherit;
    text-transform: inherit;
    cursor: pointer;
  }

  .sort-btn:hover {
    color: var(--text-primary);
  }

  .sort-arrow {
    font-size: 8px;
  }

  .browse-table .col-select {
    width: 32px;
    padding-right: 0;
    text-align: center;
  }

  .col-select input {
    margin: 0;
    cursor: pointer;
    accent-color: var(--accent);
  }

  .col-select input:disabled {
    cursor: default;
  }

  .col-name {
    max-width: 0;
    width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .name-cell {
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: 0;
  }

  .name-text {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .file-tag {
    flex-shrink: 0;
    padding: 1px 6px;
    border-radius: var(--radius-pill);
    font-size: 10px;
    font-weight: 600;
    line-height: 16px;
  }

  .tag-friends {
    color: var(--accent);
    background: color-mix(in srgb, var(--accent) 14%, transparent);
  }

  .tag-done {
    color: var(--success);
    background: color-mix(in srgb, var(--success) 14%, transparent);
  }

  .dl-state {
    display: inline-flex;
    align-items: center;
    min-height: 30px;
    padding: 0 10px;
    font-size: 12px;
    font-weight: 600;
    color: var(--text-muted);
  }

  .col-size {
    width: 96px;
    white-space: nowrap;
    color: var(--text-muted);
  }

  .col-action {
    width: 132px;
    text-align: right;
    white-space: nowrap;
  }

  .dl-btn {
    min-height: 30px;
    padding: 0 10px;
    border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font-size: 12px;
    font-weight: 600;
    font-family: inherit;
    transition: background var(--transition-fast), border-color var(--transition-fast), color var(--transition-fast);
  }

  .dl-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--accent) 22%, transparent);
    border-color: var(--accent);
  }

  .dl-btn:disabled {
    opacity: 0.7;
    cursor: default;
  }

  .dl-btn svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }

  .dl-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid color-mix(in srgb, var(--accent) 30%, transparent);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: browse-spin 0.7s linear infinite;
    flex-shrink: 0;
  }

  @keyframes browse-spin {
    to { transform: rotate(360deg); }
  }

  .dl-done {
    min-height: 30px;
    padding: 0 10px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    color: var(--success);
    font-size: 12px;
    font-weight: 600;
  }

  .dl-done svg {
    width: 14px;
    height: 14px;
    flex-shrink: 0;
  }
</style>
