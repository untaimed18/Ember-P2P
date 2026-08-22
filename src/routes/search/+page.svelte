<script lang="ts">
  import SearchBar from '$lib/components/SearchBar.svelte';
  import { searchFiles, cancelSearch, findNotes, publishNote, markSpam, markNotSpam, explainSpamResult, getDownloadHistory, removeDownloadHistoryEntry, formatEd2kLink, formatEd2kLinks, type SearchMethod } from '$lib/api/search';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { getSettings } from '$lib/api/settings';
  import { getEmberDiagnostics } from '$lib/api/ember';
  import { startDownload } from '$lib/api/transfers';
  import { transfers } from '$lib/stores/transfers';
  import type { Transfer } from '$lib/types';
  import { appSettings } from '$lib/stores/settings';
  import {
    activeSearchTabId,
    appendSearchResults,
    clearPendingSearchResults,
    closeSearchTab,
    newSearchNonce,
    openSearchTab,
    patchSearchTabByRequestId,
    patchSpamFlagByHash,
    searchTabs,
    setActiveSearchTab,
    spamFilterEpoch,
    type SearchTab,
  } from '$lib/stores/search';
  import { networkStats, serverStatus } from '$lib/stores/network';
  import { onDestroy, onMount, untrack } from 'svelte';
  import { get } from 'svelte/store';
  import { listen } from '@tauri-apps/api/event';
  import type { SearchResult, SpamExplanation } from '$lib/types';
  import { formatSize, formatSpeed, copyToClipboard } from '$lib/utils';
  import { EMBER_JOIN_TIMEOUT_MS } from '$lib/emberJoin';
  import { addToast } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';
  import { translateError, degradedReasonText } from '$lib/i18n';

  const searchTimeouts = new Map<number, ReturnType<typeof setTimeout>>();
  /** Request ids whose invoke has settled (success or error). Prevents a late
   * getSettings() from re-arming the cancel watchdog after completion grace
   * is already in `searchTimeouts`. */
  const searchInvokeSettled = new Set<number>();

  /// Upper bound on a search query length sent over IPC. ed2k keywords are
  /// short; this just guards against pathologically long pasted input.
  const MAX_SEARCH_QUERY_LEN = 256;

  let searchMethod: SearchMethod = $state('global');
  let searchFileType: string = $state('');

  let barQuery = $state('');

  let activeTab = $derived.by(() => {
    const id = $activeSearchTabId;
    if (!id) return null;
    return $searchTabs.find((t) => t.id === id) ?? null;
  });

  let searchResultsList = $derived(activeTab?.results ?? []);

  // Every consumer below — the filter + sort, the checked-key reconcile, the
  // download-history prefetch — walks the whole accumulated result set, and
  // the store hands us a new snapshot on every animation-frame flush while a
  // search streams. Throttle the list they read to ~2.5x/sec: leading edge
  // plus one coalesced trailing sync, the same shape `downloadsByHash` uses
  // for the transfers store further down. The trailing timer is what
  // guarantees the last batch of a finished search always lands, so the table
  // never settles on a stale count.
  const RESULTS_SYNC_MIN_INTERVAL_MS = 400;
  // `$state.raw`, not `$state`: this array is only ever replaced wholesale by
  // `syncVisibleResults`, never mutated, and at up to `MAX_TAB_RESULTS` rows a
  // deep proxy would register a dependency per field read in `filterPass` —
  // working against the throttle this snapshot exists to feed.
  let visibleResults = $state.raw<SearchResult[]>([]);
  let resultsSyncedAt = 0;
  let resultsSyncTimer: ReturnType<typeof setTimeout> | null = null;
  let syncedTabId: string | null = null;
  let syncedLength = 0;

  function syncVisibleResults(list: SearchResult[], tabId: string | null) {
    if (resultsSyncTimer !== null) {
      clearTimeout(resultsSyncTimer);
      resultsSyncTimer = null;
    }
    syncedTabId = tabId;
    syncedLength = list.length;
    resultsSyncedAt = Date.now();
    visibleResults = list;
  }

  $effect(() => {
    const list = searchResultsList;
    const tabId = $activeSearchTabId;
    const elapsed = Date.now() - resultsSyncedAt;
    // Bypass the throttle on: tab switch; a shorter list (Clear / close / cap
    // eviction); the 400ms interval; and the first 0→N fill. Empty states read
    // this snapshot, so delaying the first hits until after search-complete
    // flashes "No results" on a fast Ember complete.
    if (
      tabId !== syncedTabId ||
      list.length < syncedLength ||
      elapsed >= RESULTS_SYNC_MIN_INTERVAL_MS ||
      (syncedLength === 0 && list.length > 0)
    ) {
      syncVisibleResults(list, tabId);
    } else if (resultsSyncTimer === null) {
      resultsSyncTimer = setTimeout(() => {
        resultsSyncTimer = null;
        if (destroyed) return;
        syncVisibleResults(searchResultsList, syncedTabId);
      }, RESULTS_SYNC_MIN_INTERVAL_MS - elapsed);
    }
  });

  let downloadHistoryMap = $state<Record<string, string>>({});
  let historyFetchedHashes = new Set<string>();
  let historyPendingHashes = new Set<string>();
  let historyFetchTimer: ReturnType<typeof setTimeout> | null = null;
  // Per-hash sequence for optimistic mark/unmark so out-of-order IPC
  // completions cannot desync the UI from the latest user action.
  const spamToggleGen = new Map<string, number>();
  // Per-hash "last applied generation". `getDownloadHistory` IPC
  // round-trips can resolve out of order (cold DB vs warm cache),
  // and the previous merge happily let an older batch overwrite a
  // fresher per-hash status. Tracking the dispatch generation per
  // hash lets us skip the merge for any hash whose newer entry has
  // already landed — without throwing away unrelated hashes the
  // older batch fetched (which would happen with a single global
  // "latest" counter when batches query disjoint hash sets).
  let historyFetchGen = 0;
  const historyHashGen = new Map<string, number>();
  const HISTORY_BATCH_LIMIT = 5_000;
  /** Ceiling on the per-hash history bookkeeping. `pruneHistoryToVisible`
   *  already drops hashes no open tab references, but it only runs on tab
   *  close / clear results, and the search store now evicts low-availability
   *  rows from a full tab — so a hash can leave the visible set with nothing
   *  watching. Same shape as `SPAM_CACHE_MAX` below: object keys and Set/Map
   *  entries keep insertion order, so dropping from the front evicts the
   *  least-recently-added hash. Sits above what one tab can hold so ordinary
   *  browsing never evicts a hash that is still on screen (which would just
   *  make `queueHistoryFetch` re-request it). */
  const HISTORY_CACHE_MAX = 20_000;

  function trimHistoryHashSets() {
    while (historyFetchedHashes.size > HISTORY_CACHE_MAX) {
      const oldest = historyFetchedHashes.values().next().value;
      if (oldest === undefined) break;
      historyFetchedHashes.delete(oldest);
    }
    while (historyHashGen.size > HISTORY_CACHE_MAX) {
      const oldest = historyHashGen.keys().next().value;
      if (oldest === undefined) break;
      historyHashGen.delete(oldest);
    }
  }

  /** Only ever called from the debounced flush below, never from inside an
   *  effect: `Object.keys` on a `$state` proxy registers a dependency on the
   *  key set, so trimming from a tracked context would schedule the very
   *  effect that refills the map. `historyFetchedHashes` / `historyHashGen`
   *  are plain collections and safe to trim anywhere, hence the split. */
  function trimHistoryCaches() {
    const keys = Object.keys(downloadHistoryMap);
    for (let i = 0; i < keys.length - HISTORY_CACHE_MAX; i++) {
      delete downloadHistoryMap[keys[i]];
    }
    trimHistoryHashSets();
  }
  /** Consecutive failed flushes, bounding the retry loop below. */
  let historyFetchFailures = 0;
  const HISTORY_MAX_RETRIES = 3;

  async function flushHistoryFetch() {
    historyFetchTimer = null;
    if (historyPendingHashes.size === 0) return;
    const batch = [...historyPendingHashes].slice(0, HISTORY_BATCH_LIMIT);
    const remaining = historyPendingHashes.size > HISTORY_BATCH_LIMIT;
    for (const h of batch) historyPendingHashes.delete(h);
    const myGen = ++historyFetchGen;
    for (const h of batch) historyHashGen.set(h, myGen);
    try {
      const result = await getDownloadHistory(batch);
      if (destroyed) return;
      // Per-hash freshness check: only apply keys for which our gen
      // is still the most recent dispatch. Written key-by-key rather than
      // spread into a replacement object: `downloadHistoryMap` is `$state`,
      // so a keyed write is already reactive, and the spread copied every
      // hash ever seen on every batch.
      let applied = 0;
      for (const [h, status] of Object.entries(result)) {
        if (historyHashGen.get(h) === myGen) {
          downloadHistoryMap[h] = status;
          applied++;
        }
      }
      if (applied > 0) trimHistoryCaches();
      historyFetchFailures = 0;
    } catch (e) {
      console.error('Failed to fetch download history:', e);
      // Failed batch — forget the "already fetched" mark so they retry next cycle.
      for (const h of batch) {
        historyFetchedHashes.delete(h);
        // Clear our gen claim too so a future batch can re-attempt
        // without the stale-gen filter rejecting its results.
        if (historyHashGen.get(h) === myGen) historyHashGen.delete(h);
      }
      // Nothing else re-queues these: `queueHistoryFetch` only runs when the
      // result list or transfer state changes, so after a finished search the
      // badges would stay blank for good. Bounded so a persistently failing
      // history DB can't turn this into a hot poll.
      if (++historyFetchFailures <= HISTORY_MAX_RETRIES) {
        for (const h of batch) historyPendingHashes.add(h);
      }
    } finally {
      if (!destroyed && !historyFetchTimer && (remaining || historyPendingHashes.size > 0)) {
        historyFetchTimer = setTimeout(flushHistoryFetch, remaining ? 0 : 1_000);
      }
    }
  }

  function queueHistoryFetch(hashes: string[]) {
    let added = false;
    for (const h of hashes) {
      if (!h || historyFetchedHashes.has(h)) continue;
      historyFetchedHashes.add(h);
      historyPendingHashes.add(h);
      added = true;
    }
    if (!added) return;
    trimHistoryHashSets();
    // Coalesce high-frequency streaming updates into a single batched fetch.
    if (historyFetchTimer) return;
    historyFetchTimer = setTimeout(flushHistoryFetch, 250);
  }

  $effect(() => {
    // Touch the list length so the effect re-runs as streaming batches arrive,
    // but do the diffing inside queueHistoryFetch to avoid re-sending known
    // hashes. The actual invoke is debounced. Reads the throttled list so a
    // fast stream can't drive this whole-list pass at flush rate.
    const hashes = visibleResults.map(r => r.file.hash);
    if (hashes.length > 0) queueHistoryFetch(hashes);
  });

  // Force a re-fetch of the cached download-history status for a hash. Without
  // this, `queueHistoryFetch` permanently skips any hash already in
  // `historyFetchedHashes`, so a download that finishes (or a history entry
  // that's removed) never updated the row badge until a full page reload.
  function invalidateHistory(hash: string) {
    if (!hash) return;
    historyFetchedHashes.delete(hash);
    historyHashGen.delete(hash);
  }

  // React to downloads finishing or being cancelled while results are on
  // screen: drop the stale "already fetched" mark for the file and re-queue,
  // so its completed/cancelled badge appears without a reload. A
  // `completedHandled` guard keeps this from re-firing on every transfers-store
  // tick for hashes that stay terminal in the list.
  const completedHandled = new Set<string>();
  // Bound the dedupe set so a very long session with thousands of completed
  // downloads can't grow it without limit. Sets preserve insertion order, so
  // dropping the oldest entry evicts the least-recently-completed hash.
  const COMPLETED_HANDLED_CAP = 2000;
  const seenDownloadHashes = new Set<string>();
  $effect(() => {
    const list = $transfers;
    if (destroyed) return;
    const present = new Set<string>();
    for (const t of list) {
      if (t.direction !== 'download' || !t.file_hash) continue;
      present.add(t.file_hash);
      seenDownloadHashes.add(t.file_hash);
      // Non-terminal download for this hash means a retry is in flight —
      // allow a later completed/failed to refresh history again (SF10).
      if (t.status !== 'completed' && t.status !== 'failed') {
        completedHandled.delete(t.file_hash);
        continue;
      }
      if (completedHandled.has(t.file_hash)) continue;
      completedHandled.add(t.file_hash);
      if (completedHandled.size > COMPLETED_HANDLED_CAP) {
        const oldest = completedHandled.values().next().value;
        if (oldest !== undefined) completedHandled.delete(oldest);
      }
      invalidateHistory(t.file_hash);
      queueHistoryFetch([t.file_hash]);
    }
    // Hash left the transfer list (cancel/remove) — refresh history badge.
    for (const hash of [...seenDownloadHashes]) {
      if (present.has(hash)) continue;
      seenDownloadHashes.delete(hash);
      if (completedHandled.has(hash)) continue;
      completedHandled.add(hash);
      if (completedHandled.size > COMPLETED_HANDLED_CAP) {
        const oldest = completedHandled.values().next().value;
        if (oldest !== undefined) completedHandled.delete(oldest);
      }
      invalidateHistory(hash);
      queueHistoryFetch([hash]);
    }
  });

  // Destructive-action confirmation state. Shared by "Clear Results" and
  // "Close Tab". Skip confirmation for empty / non-destructive cases.
  type ConfirmAction =
    | { kind: 'clear-results' }
    | { kind: 'close-tab'; tab: SearchTab }
    | { kind: 'copy-all-links'; results: SearchResult[] };
  let pendingConfirm: ConfirmAction | null = $state(null);
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmMessage = $state('');

  // Shown when the user tries to search with no usable network connected.
  let networkAlertOpen = $state(false);

  function searchNetworkHint(method: SearchMethod): string {
    if (method === 'kad') return m.search_network_need_kad_hint();
    if (method === 'server') return m.search_network_need_server_hint();
    if (method === 'ember') {
      if (!emberEnabled) return m.search_network_need_ember_hint();
      if (emberContacts === 0 && !emberJoinTimedOut) {
        return m.search_network_ember_joining_hint();
      }
      return m.search_network_need_ember_hint();
    }
    // Global with neither eMule net up: Ember may still be usable.
    if (emberEnabled && !kadUpLive && !serverUpLive) {
      return emberContacts === 0 && !emberJoinTimedOut
        ? m.search_network_ember_joining_hint()
        : m.search_network_global_ember_only_hint();
    }
    return m.search_network_disconnected_hint();
  }

  function searchNetworkAlertMessage(method: SearchMethod): string {
    if (method === 'kad') return m.search_no_network_kad_message();
    if (method === 'server') return m.search_no_network_server_message();
    if (method === 'ember') return m.search_no_network_ember_message();
    return m.search_no_network_message();
  }

  // Live network readiness used by hints (must stay reactive).
  let kadUpLive = $derived($networkStats.status === 'connected');
  let serverUpLive = $derived($serverStatus === 'connected');

  let selectedResultKey = $state<string | null>(null);
  let checkedKeys = $state(new Set<string>());
  let lastCheckedKey = $state<string | null>(null);
  let bulkDownloadPending = $state(false);
  let bulkDownloadMessage = $state('');
  // Track failure flag separately so the CSS class doesn't depend on
  // substring matching against the (now localized) status text.
  let bulkDownloadHasFailures = $state(false);
  let checkedCount = $derived(checkedKeys.size);
  let spamExplainCache = $state<Record<string, SpamExplanation>>({});
  const SPAM_CACHE_MAX = 500;
  function setSpamCache(key: string, val: SpamExplanation) {
    const keys = Object.keys(spamExplainCache);
    if (keys.length >= SPAM_CACHE_MAX) {
      for (const k of keys.slice(0, keys.length - SPAM_CACHE_MAX + 1)) {
        delete spamExplainCache[k];
      }
    }
    spamExplainCache[key] = val;
  }
  let selectedResult = $derived.by(() => {
    if (!selectedResultKey) return null;
    return searchResultsList.find((r) => resultKey(r) === selectedResultKey) ?? null;
  });
  let notes: SearchResult[] = $state([]);
  let loadingNotes = $state(false);
  let noteRating = $state(0);
  let noteComment = $state('');
  let publishMessage = $state('');
  let publishSuccess = $state(true);
  let spamExplainLoading = $state(false);
  let spamExplainError: string | null = $state(null);
  let notesError: string | null = $state(null);
  let spamExplainPending = $state<Record<string, boolean>>({});
  let spamExplainErrors = $state<Record<string, string>>({});
  let spamTooltipKey = $state<string | null>(null);

  $effect(() => {
    void $spamFilterEpoch;
    untrack(() => {
      spamExplainCache = {};
      spamExplainPending = {};
      spamExplainErrors = {};
      spamExplainError = null;
    });
  });
  const FILE_TYPES = [
    { value: '', get label() { return m.search_filetype_any(); } },
    { value: 'Audio', get label() { return m.library_type_audio(); } },
    { value: 'Video', get label() { return m.library_type_video(); } },
    { value: 'Image', get label() { return m.library_type_image(); } },
    { value: 'Pro', get label() { return m.search_filetype_program(); } },
    { value: 'Doc', get label() { return m.library_type_document(); } },
    { value: 'Arc', get label() { return m.library_type_archive(); } },
    { value: 'Iso', get label() { return m.search_filetype_cd_image(); } },
    { value: 'EmuleCollection', get label() { return m.search_filetype_collection(); } },
  ];

  const SIZE_UNITS = [
    { value: 1, label: 'B' },
    { value: 1024, label: 'KB' },
    { value: 1024 * 1024, label: 'MB' },
    { value: 1024 * 1024 * 1024, label: 'GB' },
  ];

  let filterType = $state('');
  // The four numeric filters are bound to `<input type="number">`, which Svelte
  // coerces to `number` (or `null` when the box is empty) — declaring them as
  // strings made every `!== ''` test true for a cleared field and made them
  // fail to round-trip through `localStorage`.
  let filterMinSize = $state<number | null>(null);
  let filterMinUnit = $state(1024 * 1024);
  let filterMaxSize = $state<number | null>(null);
  let filterMaxUnit = $state(1024 * 1024 * 1024);
  let filterExtension = $state('');
  let filterMinSources = $state<number | null>(null);
  // Client-side "complete sources" minimum. Unlike Min Sources (sent to the
  // remote node as a FT_SOURCES constraint), there is no standard eD2k search
  // tag for complete-source counts, so this filters the results we already
  // received (the count arrives on each hit as `file.complete_sources`).
  let filterMinComplete = $state<number | null>(null);
  let hideSpam = $state<boolean>(true);
  /** True when the hit is only from the shared library (not merged with KAD/Server/UDP/Notes). */
  function isLocalOnlySearchResult(r: SearchResult): boolean {
    const o = (r.result_origin || '').trim();
    if (!o) return r.peer_id === 'local';
    const parts = o.split(' · ').map((s) => s.trim()).filter(Boolean);
    if (parts.length === 0) return r.peer_id === 'local';
    return parts.every((p) => p === 'Local');
  }

  /**
   * Whether a (visible) result is effectively "already in the library" with
   * nothing to fetch. Pure-local rows are filtered out by
   * `isLocalOnlySearchResult`, but a row can carry a mixed origin like
   * `KAD · Local` when a file we share is also found on the network — those
   * rows DO have downloadable network sources. This mirrors the exact early
   * exit in `download()` so the in-library badge / disabled download button
   * only show when the action would genuinely be a no-op.
   */
  function isInLibraryOnly(r: SearchResult): boolean {
    if (!r.result_origin?.includes('Local')) return false;
    const net = (r.source_addresses ?? []).filter((a) => a && a !== 'local');
    return net.length === 0;
  }

  function displayName(result: SearchResult): string {
    return result.clean_name || result.file.name;
  }
  let spamProfile = $derived(
    ($appSettings?.spam_filter_profile as 'relaxed' | 'balanced' | 'aggressive' | undefined)
      ?? 'balanced',
  );
  let showSpamHelp = $state(false);
  let contextMenu: { x: number; y: number; result: SearchResult } | null = $state(null);
  let notesRequestId = $state(0);

  // Text filter (eMule-style: space-separated AND tokens, "-" prefix = NOT)
  type FilterColumn = 'name' | 'size' | 'type' | 'sources' | 'origin' | 'hash' | 'all';
  let filterColumn: FilterColumn = $state('all');
  let filterTextInput = $state('');
  let filterText = $state('');
  let filterDebounceTimer: ReturnType<typeof setTimeout> | null = null;
  let showAdvancedFilters = $state(false);

  const FILTER_COLUMNS: { value: FilterColumn; readonly label: string }[] = [
    { value: 'name', get label() { return m.search_col_name(); } },
    { value: 'type', get label() { return m.search_col_type(); } },
    { value: 'size', get label() { return m.search_col_size(); } },
    { value: 'sources', get label() { return m.search_col_sources(); } },
    { value: 'origin', get label() { return m.search_col_source(); } },
    { value: 'hash', get label() { return m.search_col_hash(); } },
    { value: 'all', get label() { return m.search_col_all_fields(); } },
  ];

  // Optional, user-toggleable media-metadata columns (eMule FT_MEDIA_*). Length
  // and bitrate are shown by default (the two classic eMule media columns); the
  // rest — plus the complete-source count — are available from the Columns menu.
  type MediaColumn = 'length' | 'bitrate' | 'codec' | 'artist' | 'album' | 'title' | 'complete';
  const MEDIA_COLUMNS: { key: MediaColumn; readonly label: string }[] = [
    { key: 'length', get label() { return m.search_col_length(); } },
    { key: 'bitrate', get label() { return m.search_col_bitrate(); } },
    { key: 'codec', get label() { return m.search_col_codec(); } },
    { key: 'artist', get label() { return m.search_col_artist(); } },
    { key: 'album', get label() { return m.search_col_album(); } },
    { key: 'title', get label() { return m.search_col_title(); } },
    { key: 'complete', get label() { return m.search_col_complete_sources(); } },
  ];
  const DEFAULT_COLUMN_VIS: Record<MediaColumn, boolean> = {
    length: true, bitrate: true, codec: true,
    artist: false, album: false, title: false, complete: false,
  };
  let columnVis = $state<Record<MediaColumn, boolean>>({ ...DEFAULT_COLUMN_VIS });
  let showColumnMenu = $state(false);

  function toggleColumn(key: MediaColumn) {
    // Reassign (rather than mutate in place) so the persistence $effect, which
    // tracks `columnVis` by reference, re-runs and saves the change.
    columnVis = { ...columnVis, [key]: !columnVis[key] };
  }

  let destroyed = false;
  const miscTimers = new Set<ReturnType<typeof setTimeout>>();
  function safeTimeout(fn: () => void, ms: number) {
    const id = setTimeout(() => { miscTimers.delete(id); fn(); }, ms);
    miscTimers.add(id);
  }

  onDestroy(() => {
    destroyed = true;
    if (filterDebounceTimer) { clearTimeout(filterDebounceTimer); filterDebounceTimer = null; }
    if (historyFetchTimer) { clearTimeout(historyFetchTimer); historyFetchTimer = null; }
    if (resultsSyncTimer !== null) { clearTimeout(resultsSyncTimer); resultsSyncTimer = null; }
    // Leave searchTimeouts alone: tabs/`isSearching` persist in the layout-
    // scoped store, and grace/watchdog callbacks only patch that store. Clearing
    // them here used to strand spinners when search-complete was missed.
    // For the same reason this prunes `searchInvokeSettled` rather than
    // clearing it: an id whose fallback is still armed still needs its flag,
    // or a late getSettings() could re-arm the cancel watchdog against a
    // background tab's live search.
    for (const id of [...searchInvokeSettled]) forgetSettledRequest(id);
    for (const id of miscTimers) clearTimeout(id);
  });

  function onFilterTextInput() {
    if (filterDebounceTimer) clearTimeout(filterDebounceTimer);
    filterDebounceTimer = setTimeout(() => {
      if (destroyed) return;
      filterText = filterTextInput;
    }, 400);
  }

  function clearFilterText() {
    filterTextInput = '';
    filterText = '';
    if (filterDebounceTimer) clearTimeout(filterDebounceTimer);
  }

  /** Format a media length (seconds) as H:MM:SS or M:SS, eMule-style. */
  function formatMediaLength(secs: number): string {
    if (!secs || secs <= 0) return '\u2014';
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = Math.floor(secs % 60);
    const pad = (n: number) => n.toString().padStart(2, '0');
    return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${m}:${pad(s)}`;
  }

  function getColumnText(result: SearchResult, column: FilterColumn): string {
    const name = displayName(result);
    switch (column) {
      case 'name': return name;
      case 'size': return formatSize(result.file.size);
      case 'type': return `${resultTypeLabel(result)} ${result.file_type || result.file.extension || ''}`.trim();
      case 'sources': return String(result.availability);
      case 'origin': return `${originLabel(result.result_origin || '')} ${result.result_origin || ''}`.trim();
      case 'hash': return result.file.hash;
      case 'all':
        return [
          name,
          formatSize(result.file.size),
          resultTypeLabel(result),
          result.file_type || result.file.extension || '',
          String(result.availability),
          originLabel(result.result_origin || ''),
          result.result_origin || '',
          result.file.hash,
        ].join(' ');
    }
  }

  // One reused collator instead of an implicit per-comparison one from
  // `String.prototype.localeCompare`, which allocates on every call during a
  // sort over thousands of rows. Default options, so ordering is unchanged.
  const sortCollator = new Intl.Collator();

  // Parsed once per filter-text change rather than once per result row:
  // `isFilteredByText` runs inside `filteredResults`, which re-derives on every
  // streamed batch, so the split and its regex were being re-run per row.
  let filterTokens = $derived.by(() => {
    const t = filterText.trim();
    if (!t) return [] as string[];
    return t.split(/\s+/).filter((s) => s !== '' && s !== '-');
  });

  function isFilteredByText(result: SearchResult): boolean {
    const tokens = filterTokens;
    if (tokens.length === 0) return false;

    // Sources column: numeric equality (and optional >= with leading `>`),
    // not substring-on-number which made "1" match 10/12/21 (SF11).
    if (filterColumn === 'sources') {
      for (const token of tokens) {
        const isNot = token.startsWith('-');
        const raw = (isNot ? token.slice(1) : token).trim();
        if (!raw) continue;
        let found = false;
        if (raw.startsWith('>=')) {
          const n = Number.parseInt(raw.slice(2), 10);
          found = Number.isFinite(n) && result.availability >= n;
        } else if (raw.startsWith('>')) {
          const n = Number.parseInt(raw.slice(1), 10);
          found = Number.isFinite(n) && result.availability > n;
        } else {
          const n = Number.parseInt(raw, 10);
          found = Number.isFinite(n) && result.availability === n;
        }
        if (isNot === found) return true;
      }
      return false;
    }

    const target = getColumnText(result, filterColumn).toLowerCase();

    for (const token of tokens) {
      const isNot = token.startsWith('-');
      const term = (isNot ? token.slice(1) : token).toLowerCase();
      if (!term) continue;

      const found = target.includes(term);
      if (isNot === found) return true;
    }

    return false;
  }

  type SortField = 'name' | 'size' | 'type' | 'sources' | 'origin'
    | 'length' | 'bitrate' | 'codec' | 'artist' | 'album' | 'title' | 'complete';
  type SortDir = 'asc' | 'desc';
  let sortField: SortField = $state('sources');
  let sortDir: SortDir = $state('desc');

  // ---- Persistence: filters, sort, advanced open state, search method/type ----
  // Stored under a versioned key so a future shape change can be migrated or
  // discarded safely by bumping the suffix.
  const PREFS_KEY = 'search-prefs-v1';
  const VALID_SEARCH_METHODS = new Set<SearchMethod>(['global', 'kad', 'server', 'ember']);
  const VALID_FILTER_COLUMNS = new Set<FilterColumn>([
    'name', 'size', 'type', 'sources', 'origin', 'hash', 'all',
  ]);
  const VALID_SORT_FIELDS = new Set<SortField>([
    'name', 'size', 'type', 'sources', 'origin',
    'length', 'bitrate', 'codec', 'artist', 'album', 'title', 'complete',
  ]);
  const VALID_SIZE_UNITS = new Set<number>(SIZE_UNITS.map((u) => u.value));
  const VALID_FILE_TYPES = new Set<string>(FILE_TYPES.map((t) => t.value));
  // Must be reactive: the persistence $effect below early-returns on this, and
  // a plain `let` would leave that run with zero tracked dependencies, so the
  // effect would never fire again and preferences would never be written.
  let prefsRestored = $state(false);

  function loadPersistedPrefs() {
    try {
      const raw = localStorage.getItem(PREFS_KEY);
      if (!raw) return;
      const p = JSON.parse(raw);
      if (!p || typeof p !== 'object') return;
      if (typeof p.searchMethod === 'string' && VALID_SEARCH_METHODS.has(p.searchMethod as SearchMethod)) {
        searchMethod = p.searchMethod as SearchMethod;
      }
      if (typeof p.searchFileType === 'string' && VALID_FILE_TYPES.has(p.searchFileType)) {
        searchFileType = p.searchFileType;
      }
      if (typeof p.filterType === 'string' && VALID_FILE_TYPES.has(p.filterType)) {
        // Program is not a client display filter (matches backend / handleSearch).
        filterType = p.filterType === 'Pro' ? '' : p.filterType;
      }
      if (typeof p.filterColumn === 'string' && VALID_FILTER_COLUMNS.has(p.filterColumn as FilterColumn)) {
        filterColumn = p.filterColumn as FilterColumn;
      }
      if (typeof p.filterExtension === 'string' && p.filterExtension.length <= 16) {
        filterExtension = p.filterExtension;
      }
      if (typeof p.filterMinSize === 'number' && Number.isFinite(p.filterMinSize)) {
        filterMinSize = p.filterMinSize;
      }
      if (typeof p.filterMaxSize === 'number' && Number.isFinite(p.filterMaxSize)) {
        filterMaxSize = p.filterMaxSize;
      }
      if (typeof p.filterMinUnit === 'number' && VALID_SIZE_UNITS.has(p.filterMinUnit)) {
        filterMinUnit = p.filterMinUnit;
      }
      if (typeof p.filterMaxUnit === 'number' && VALID_SIZE_UNITS.has(p.filterMaxUnit)) {
        filterMaxUnit = p.filterMaxUnit;
      }
      if (typeof p.filterMinSources === 'number' && Number.isFinite(p.filterMinSources)) {
        filterMinSources = p.filterMinSources;
      }
      if (typeof p.filterMinComplete === 'number' && Number.isFinite(p.filterMinComplete)) {
        filterMinComplete = p.filterMinComplete;
      }
      if (p.columnVis && typeof p.columnVis === 'object') {
        const next = { ...columnVis };
        for (const c of MEDIA_COLUMNS) {
          if (typeof p.columnVis[c.key] === 'boolean') next[c.key] = p.columnVis[c.key];
        }
        columnVis = next;
      }
      if (typeof p.hideSpam === 'boolean') hideSpam = p.hideSpam;
      if (typeof p.showAdvancedFilters === 'boolean') showAdvancedFilters = p.showAdvancedFilters;
      if (typeof p.sortField === 'string' && VALID_SORT_FIELDS.has(p.sortField as SortField)) {
        sortField = p.sortField as SortField;
      }
      if (p.sortDir === 'asc' || p.sortDir === 'desc') {
        sortDir = p.sortDir;
      }
    } catch {
      try { localStorage.removeItem(PREFS_KEY); } catch { /* ignore */ }
    }
  }

  function persistPrefs() {
    try {
      localStorage.setItem(PREFS_KEY, JSON.stringify({
        searchMethod,
        searchFileType,
        filterType,
        filterColumn,
        filterExtension,
        filterMinSize,
        filterMaxSize,
        filterMinUnit,
        filterMaxUnit,
        filterMinSources,
        filterMinComplete,
        columnVis,
        hideSpam,
        showAdvancedFilters,
        sortField,
        sortDir,
      }));
    } catch { /* quota/serialization — not fatal */ }
  }

  $effect(() => {
    if (!prefsRestored) return;
    // Reactivity markers: touch every persisted field so the effect runs
    // whenever any of them changes.
    void searchMethod; void searchFileType;
    void filterType; void filterColumn; void filterExtension;
    void filterMinSize; void filterMaxSize; void filterMinUnit; void filterMaxUnit;
    void filterMinSources; void filterMinComplete; void columnVis;
    void hideSpam; void showAdvancedFilters;
    void sortField; void sortDir;
    persistPrefs();
  });

  function toggleSort(field: SortField) {
    if (sortField === field) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc';
    } else {
      sortField = field;
      const ascByDefault = field === 'name' || field === 'type' || field === 'origin'
        || field === 'codec' || field === 'artist' || field === 'album' || field === 'title';
      sortDir = ascByDefault ? 'asc' : 'desc';
    }
  }

  function sortIndicator(field: SortField): string {
    if (sortField !== field) return '';
    return sortDir === 'asc' ? ' \u25B2' : ' \u25BC';
  }

  function resultKey(result: SearchResult): string {
    if (result.file.hash) return result.file.hash;
    if (result.file.id?.startsWith('pending:')) return `nohash-id:${result.file.id}`;
    if (result.file.path) return `nohash-path:${result.file.path}`;
    return `nohash:${result.file.name}:${result.file.size}`;
  }

  function inferSearchTypeFromExtension(extension: string | null | undefined): string {
    // Keep in sync with `search::index::infer_file_type` (eMule ED2KFT_*).
    const ext = (extension ?? '').toLowerCase();
    if ([
      'aac', 'ac3', 'aif', 'aifc', 'aiff', 'amr', 'ape', 'au', 'aud', 'audio',
      'cda', 'dmf', 'dsm', 'dts', 'far', 'flac', 'it', 'm1a', 'm2a', 'm4a', 'mdl',
      'med', 'mid', 'midi', 'mka', 'mod', 'mp1', 'mp2', 'mp3', 'mpa', 'mpc',
      'mtm', 'ogg', 'opus', 'psm', 'ptm', 'ra', 'rmi', 's3m', 'snd', 'stm', 'umx',
      'wav', 'wma', 'xm',
    ].includes(ext)) return 'Audio';
    if ([
      '3g2', '3gp', '3gp2', '3gpp', 'amv', 'asf', 'avi', 'bik', 'divx', 'dvr-ms',
      'flc', 'fli', 'flic', 'flv', 'hdmov', 'ifo', 'm1v', 'm2t', 'm2ts', 'm2v',
      'm4b', 'm4v', 'mkv', 'mov', 'movie', 'mp1v', 'mp2v', 'mp4', 'mpe', 'mpeg',
      'mpg', 'mpv', 'mpv1', 'mpv2', 'ogm', 'pva', 'qt', 'ram', 'ratdvd', 'rm',
      'rmm', 'rmvb', 'rv', 'smil', 'smk', 'swf', 'tp', 'ts', 'vid', 'video',
      'vob', 'vp6', 'webm', 'wm', 'wmv', 'xvid',
    ].includes(ext)) return 'Video';
    if ([
      'bmp', 'emf', 'gif', 'ico', 'jfif', 'jpe', 'jpeg', 'jpg', 'pct', 'pcx', 'pic',
      'pict', 'png', 'psd', 'psp', 'svg', 'tga', 'tif', 'tiff', 'webp', 'wmf',
      'wmp', 'xif',
    ].includes(ext)) return 'Image';
    if ([
      'bat', 'cmd', 'com', 'exe', 'hta', 'js', 'jse', 'msc', 'vbe', 'vbs', 'wsf',
      'wsh', 'apk', 'app', 'deb', 'rpm', 'scr',
    ].includes(ext)) return 'Pro';
    if ([
      'chm', 'css', 'diz', 'doc', 'dot', 'hlp', 'htm', 'html', 'nfo', 'pdf', 'pps',
      'ppt', 'ps', 'rtf', 'text', 'txt', 'wri', 'xls', 'xml', 'docx', 'xlsx',
      'pptx', 'odt', 'ods', 'odp', 'epub', 'djvu', 'lit', 'mobi', 'azw',
    ].includes(ext)) return 'Doc';
    if ([
      '7z', 'ace', 'alz', 'arc', 'arj', 'bz2', 'cab', 'cbr', 'cbz', 'gz', 'hqx',
      'lha', 'lzh', 'msi', 'pak', 'par', 'par2', 'rar', 'sit', 'sitx', 'tar',
      'tbz2', 'tgz', 'xpi', 'xz', 'z', 'zip',
    ].includes(ext)) return 'Arc';
    if ([
      'bin', 'bwa', 'bwi', 'bws', 'bwt', 'ccd', 'cue', 'dmg', 'img', 'iso', 'mdf',
      'mds', 'nrg', 'sub', 'toast',
    ].includes(ext)) return 'Iso';
    if (ext === 'emulecollection') return 'EmuleCollection';
    return '';
  }

  function resultType(result: SearchResult): string {
    return result.file_type || inferSearchTypeFromExtension(result.file.extension);
  }

  function resultTypeLabel(result: SearchResult): string {
    switch (resultType(result)) {
      case 'Audio': return m.library_type_audio();
      case 'Video': return m.library_type_video();
      case 'Image': return m.library_type_image();
      case 'Pro': return m.search_filetype_program();
      case 'Doc': return m.library_type_document();
      case 'Arc': return m.library_type_archive();
      case 'Iso': return m.search_filetype_cd_image();
      case 'EmuleCollection': return m.search_filetype_collection();
      default: return resultType(result);
    }
  }

  function originLabel(origin: string): string {
    if (!origin.trim()) return '';
    return origin.split(' · ').map((token) => {
      switch (token) {
        case 'Local': return m.search_origin_local();
        case 'KAD': return m.search_origin_kad();
        case 'Server': return m.search_origin_server();
        case 'UDP': return m.search_origin_udp();
        case 'Notes': return m.search_origin_notes();
        case 'Ember': return m.search_origin_ember();
        default: return token;
      }
    }).join(' · ');
  }

  function searchPhaseLabel(phase: string): string | null {
    switch (phase) {
      case 'Lookup': return m.search_phase_lookup();
      case 'Fetch': return m.search_phase_fetch();
      default: return null;
    }
  }

  function spamProfileLabel(profile: string): string {
    switch (profile) {
      case 'aggressive': return m.settings_spam_profile_aggressive();
      case 'relaxed': return m.settings_spam_profile_relaxed();
      default: return m.settings_spam_profile_balanced();
    }
  }

  let searchTimeoutSecs = $state(120);
  let emberEnabled = $derived(!!$appSettings?.ember_native_enabled);
  let emberContacts = $state(0);
  let emberJoinTimedOut = $state(false);
  let emberJoinActiveSince = $state<number | null>(null);
  let emberDiagnosticsStale = $state(false);
  let emberSearchUsable = $derived(emberEnabled && emberContacts > 0);
  let searchSubmitBlocked = $derived(
    (searchMethod === 'ember' && !emberSearchUsable)
      || (searchMethod === 'global' && !kadUpLive && !serverUpLive && !emberSearchUsable),
  );

  function recomputeEmberJoinState() {
    if (!emberEnabled) {
      emberJoinActiveSince = null;
      emberJoinTimedOut = false;
      emberContacts = 0;
      return;
    }
    if (emberContacts > 0) {
      emberJoinActiveSince = null;
      emberJoinTimedOut = false;
      return;
    }
    if (emberJoinActiveSince === null) {
      emberJoinActiveSince = Date.now();
      emberJoinTimedOut = false;
    } else if (Date.now() - emberJoinActiveSince >= EMBER_JOIN_TIMEOUT_MS) {
      emberJoinTimedOut = true;
    }
  }

  $effect(() => {
    // Re-arm joining UX when Ember is toggled on (mirrors /ember).
    void emberEnabled;
    void emberContacts;
    void emberDiagnosticsStale;
    recomputeEmberJoinState();
  });

  onMount(() => {
    loadPersistedPrefs();
    prefsRestored = true;
    getSettings()
      .then((s) => {
        searchTimeoutSecs = s.search_timeout_secs;
      })
      .catch(() => {});

    // Poll Ember DHT contact count while Ember is enabled so the readiness
    // strip can show "joining" vs "ready" without navigating to /ember.
    let emberPoll: ReturnType<typeof setInterval> | undefined;
    let joinPoll: ReturnType<typeof setInterval> | undefined;
    const refreshEmber = () => {
      if (!$appSettings?.ember_native_enabled) {
        emberContacts = 0;
        return;
      }
      getEmberDiagnostics()
        .then((d) => {
          emberContacts = d.ember_dht_verified_contacts ?? 0;
          emberDiagnosticsStale = false;
        })
        .catch((e) => {
          emberDiagnosticsStale = true;
          console.error('Failed to poll Ember DHT readiness:', e);
        });
    };
    refreshEmber();
    emberPoll = setInterval(refreshEmber, 3000);
    joinPoll = setInterval(() => recomputeEmberJoinState(), 1000);

    let unlistenHistory: (() => void) | undefined;
    let historyListenMounted = true;
    listen('download-history-cleared', () => {
      downloadHistoryMap = {};
      historyFetchedHashes.clear();
      historyPendingHashes.clear();
      historyHashGen.clear();
      // Re-queue visible hashes — clearing the cache alone does not re-run the
      // searchResultsList effect, so badges would stay blank until results change.
      const hashes = searchResultsList.map((r) => r.file.hash);
      if (hashes.length > 0) queueHistoryFetch(hashes);
    }).then((u) => {
      if (historyListenMounted) unlistenHistory = u; else u();
    }).catch(() => {});
    return () => {
      historyListenMounted = false;
      unlistenHistory?.();
      if (emberPoll) clearInterval(emberPoll);
      if (joinPoll) clearInterval(joinPoll);
    };
  });
  let spamThreshold = $derived(spamProfile === 'aggressive' ? 45 : spamProfile === 'relaxed' ? 80 : 60);

  function currentSearchQuery(): string {
    return activeTab?.query ?? '';
  }

  function explanationFromResult(result: SearchResult): SpamExplanation | null {
    if (!result.spam_reasons?.length) return null;
    return {
      score: result.spam_rating ?? 0,
      threshold: spamThreshold,
      profile: spamProfile,
      is_spam: !!result.is_spam,
      reasons: result.spam_reasons,
    };
  }

  function rowIsCleanOfSpam(result: SearchResult): boolean {
    return !result.is_spam && (result.spam_rating ?? 0) === 0 && !(result.spam_reasons?.length);
  }

  function spamExplainFor(result: SearchResult): SpamExplanation | undefined {
    const stored = explanationFromResult(result);
    if (stored) return stored;
    // After a filter reset, rows come back with empty reasons. Don't revive
    // a pre-reset tooltip from the IPC cache.
    if (rowIsCleanOfSpam(result)) return undefined;
    return spamExplainCache[resultKey(result)];
  }

  function explainOpts(result: SearchResult) {
    return {
      serverIp: result.origin_server_ip ?? null,
      rating: result.rating ?? null,
      resultOrigin: result.result_origin ?? null,
    };
  }

  let selectedSpam = $derived.by(() => {
    if (!selectedResult) return undefined;
    return spamExplainFor(selectedResult);
  });

  function hasSearchFilters(filters: import('$lib/api/search').SearchFilters | undefined, fileType?: string): boolean {
    return !!(
      fileType ||
      filters?.fileType ||
      filters?.fileExtension ||
      filters?.minSize !== undefined ||
      filters?.maxSize !== undefined ||
      filters?.minAvailability !== undefined
    );
  }

  const DL_STATUS_PRIORITY: Record<string, number> = {
    active: 6, verifying: 5, completing: 5, hashing: 5,
    queued: 4, searching: 4, paused: 3, stopped: 2, completed: 1, failed: 0,
  };

  function buildDownloadsByHash(list: readonly Transfer[]): Map<string, Transfer> {
    const map = new Map<string, Transfer>();
    for (const t of list) {
      if (t.direction === 'download' && t.file_hash) {
        const existing = map.get(t.file_hash);
        if (!existing || (DL_STATUS_PRIORITY[t.status] ?? 0) > (DL_STATUS_PRIORITY[existing.status] ?? 0)) {
          map.set(t.file_hash, t);
        }
      }
    }
    return map;
  }

  // Maps each downloaded file's hash -> its most-relevant transfer so result
  // rows can show a live download badge. Rebuilding is cheap, but it fans out
  // to every visible row, so throttle rebuilds to ~2.5x/sec (leading edge plus
  // one coalesced trailing rebuild) instead of re-deriving on every 4–10 Hz
  // progress tick.
  let downloadsByHash = $state<Map<string, Transfer>>(buildDownloadsByHash(get(transfers)));
  let dlMapLastBuilt = 0;
  let dlMapTimer: ReturnType<typeof setTimeout> | null = null;
  const DL_MAP_MIN_INTERVAL_MS = 400;

  $effect(() => {
    void $transfers; // track the store
    const now = Date.now();
    const elapsed = now - dlMapLastBuilt;
    if (elapsed >= DL_MAP_MIN_INTERVAL_MS) {
      dlMapLastBuilt = now;
      downloadsByHash = buildDownloadsByHash($transfers);
    } else if (dlMapTimer === null) {
      dlMapTimer = setTimeout(() => {
        dlMapTimer = null;
        dlMapLastBuilt = Date.now();
        downloadsByHash = buildDownloadsByHash(get(transfers));
      }, DL_MAP_MIN_INTERVAL_MS - elapsed);
    }
  });

  onDestroy(() => {
    if (dlMapTimer !== null) {
      clearTimeout(dlMapTimer);
      dlMapTimer = null;
    }
  });

  function getDownloadTransfer(result: SearchResult): Transfer | undefined {
    return downloadsByHash.get(result.file.hash);
  }

  /** Statuses that mean a download is still in flight and should block a new
   * start_download from Search. Terminal failed/completed do not block retry. */
  const BLOCKING_DOWNLOAD_STATUSES = new Set([
    'searching', 'queued', 'active', 'paused', 'stopped',
    'verifying', 'completing', 'hashing', 'insufficient', 'noneneeded',
  ]);

  function getBlockingDownloadTransfer(result: SearchResult): Transfer | undefined {
    const t = getDownloadTransfer(result);
    if (!t) return undefined;
    return BLOCKING_DOWNLOAD_STATUSES.has(t.status) ? t : undefined;
  }

  function dlBadgeLabel(t: Transfer): string {
    switch (t.status) {
      case 'searching': return m.search_dl_searching();
      case 'queued': return m.transfer_status_queued();
      case 'active': return `${Math.max(0, Math.min(100, Math.round(t.progress || 0)))}%`;
      case 'paused': return m.transfer_status_paused();
      case 'stopped': return m.transfer_status_stopped();
      case 'verifying': return m.transfer_status_verifying();
      case 'completing': return m.transfer_status_completing();
      case 'completed': return m.search_dl_downloaded();
      case 'failed': return m.transfer_status_failed();
      case 'hashing': return m.transfer_status_hashing();
      case 'insufficient': return m.transfer_status_insufficient();
      case 'noneneeded': return m.transfer_status_noneneeded();
      default: return m.common_unknown();
    }
  }

  function dlBadgeClass(t: Transfer): string {
    switch (t.status) {
      case 'completed': return 'dl-badge-success';
      case 'active': return 'dl-badge-active';
      case 'verifying':
      case 'completing':
      case 'hashing': return 'dl-badge-progress';
      case 'paused':
      case 'stopped': return 'dl-badge-warning';
      case 'failed':
      case 'insufficient':
      case 'noneneeded': return 'dl-badge-danger';
      default: return 'dl-badge-neutral';
    }
  }

  function dlRowClass(t: Transfer | undefined): string {
    if (!t) return '';
    switch (t.status) {
      case 'completed': return 'row-dl-completed';
      case 'active':
      case 'verifying':
      case 'completing': return 'row-dl-active';
      case 'failed': return 'row-dl-failed';
      default: return 'row-dl-queued';
    }
  }

  let selectedDlTransfer = $derived.by(() =>
    selectedResult ? downloadsByHash.get(selectedResult.file.hash) : undefined
  );

  // Filter, sort and the spam tally all in one walk of the list. `spamHidden`
  // used to be its own `.filter().length` over the same array, which meant a
  // second full pass riding the same invalidation as this one.
  let filterPass = $derived.by(() => {
    // Single-pass filter: the previous implementation chained up to 8
    // `.filter()` calls, each allocating a fresh array. On a busy search
    // this re-runs several times a second, so a result set of several
    // thousand rows meant we allocated tens of thousands of short-lived
    // intermediate entries per second just to get to the sort. Collapsing
    // the predicates and pre-parsing the filter inputs once keeps the hot
    // path allocation-light and cuts the re-derive cost roughly
    // proportionally to the number of active filters.
    const ext = filterExtension.trim().toLowerCase().replace(/^\./, '');
    const hasExt = ext.length > 0;
    const minParsed = filterMinSize !== null ? filterMinSize * filterMinUnit : NaN;
    const minBytes = Number.isFinite(minParsed) && minParsed > 0 ? minParsed : 0;
    const maxParsed = filterMaxSize !== null ? filterMaxSize * filterMaxUnit : NaN;
    const maxBytes = Number.isFinite(maxParsed) && maxParsed > 0 ? maxParsed : 0;
    const minSrcParsed = filterMinSources !== null ? Math.trunc(filterMinSources) : NaN;
    const minSrc = Number.isFinite(minSrcParsed) && minSrcParsed > 0 ? minSrcParsed : 0;
    const minCompleteParsed = filterMinComplete !== null ? Math.trunc(filterMinComplete) : NaN;
    const minComplete = Number.isFinite(minCompleteParsed) && minCompleteParsed > 0 ? minCompleteParsed : 0;
    const hasType = !!filterType;
    const spamHidden = hideSpam;

    const out: SearchResult[] = [];
    let spamCount = 0;
    for (const r of visibleResults) {
      if (r.is_spam) spamCount++;
      if (spamHidden && r.is_spam) continue;
      if (isLocalOnlySearchResult(r)) continue;
      if (hasType && resultType(r) !== filterType) continue;
      if (hasExt && (r.file.extension ?? '').toLowerCase() !== ext) continue;
      if (minBytes > 0 && r.file.size < minBytes) continue;
      if (maxBytes > 0 && r.file.size > maxBytes) continue;
      if (minSrc > 0 && r.availability < minSrc) continue;
      if (minComplete > 0 && (r.file.complete_sources ?? 0) < minComplete) continue;
      if (isFilteredByText(r)) continue;
      out.push(r);
    }

    out.sort((a, b) => {
      let cmp = 0;
      switch (sortField) {
        case 'name':
          cmp = sortCollator.compare(a.clean_name || a.file.name, b.clean_name || b.file.name);
          break;
        case 'size':
          cmp = a.file.size - b.file.size;
          break;
        case 'type':
          cmp = sortCollator.compare(resultType(a), resultType(b));
          break;
        case 'sources':
          cmp = a.availability - b.availability;
          break;
        case 'origin':
          cmp = sortCollator.compare(a.result_origin || '', b.result_origin || '');
          break;
        case 'length':
          cmp = (a.media?.duration ?? 0) - (b.media?.duration ?? 0);
          break;
        case 'bitrate':
          cmp = (a.media?.bitrate ?? 0) - (b.media?.bitrate ?? 0);
          break;
        case 'complete':
          cmp = (a.file.complete_sources ?? 0) - (b.file.complete_sources ?? 0);
          break;
        case 'codec':
          cmp = sortCollator.compare(a.media?.codec ?? '', b.media?.codec ?? '');
          break;
        case 'artist':
          cmp = sortCollator.compare(a.media?.artist ?? '', b.media?.artist ?? '');
          break;
        case 'album':
          cmp = sortCollator.compare(a.media?.album ?? '', b.media?.album ?? '');
          break;
        case 'title':
          cmp = sortCollator.compare(a.media?.title ?? '', b.media?.title ?? '');
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return { rows: out, spamCount };
  });

  let filteredResults: SearchResult[] = $derived(filterPass.rows);
  let spamHiddenCount = $derived(filterPass.spamCount);

  // O(1) instead of two more full scans of `filteredResults`. The effect below
  // reconciles `checkedKeys` down to the visible set on every change, and
  // every write to it (`toggleCheck`, `toggleCheckAll`) only ever adds keys
  // taken from `filteredResults` — so the set is a subset of what's on screen
  // and its size alone answers both questions. This is the same invariant the
  // existing `checkedCount` toolbar counter already depends on.
  let allFilteredChecked = $derived(
    filteredResults.length > 0 && checkedCount === filteredResults.length
  );
  let someFilteredChecked = $derived(checkedCount > 0);
  let selectAllCheckbox: HTMLInputElement | undefined = $state(undefined);
  $effect(() => {
    if (selectAllCheckbox) {
      selectAllCheckbox.indeterminate = someFilteredChecked && !allFilteredChecked;
    }
  });
  // Keep the checked set confined to currently-visible results. A row can
  // be checked and then hidden by a filter change; without this the bulk
  // toolbar would count it ("N selected") while `downloadChecked` — which
  // only iterates `filteredResults` — would silently skip it, so the count
  // overstated what actually downloads. Reconciling to the visible set
  // (as the transfers page does for its selection) keeps `checkedCount`
  // and the bulk action in agreement. `untrack` so writing `checkedKeys`
  // here doesn't retrigger this effect.
  $effect(() => {
    const rows = filteredResults;
    untrack(() => {
      // Nothing ticked means nothing to reconcile, and that is the state the
      // page is in for all but a few seconds of its life — worth skipping the
      // whole-list key scan for. (Matches the old behaviour exactly: with an
      // empty set the loop below found nothing to drop either.)
      if (checkedKeys.size === 0) return;
      const visible = new Set(rows.map((r) => resultKey(r)));
      let changed = false;
      const next = new Set<string>();
      for (const k of checkedKeys) {
        if (visible.has(k)) next.add(k);
        else changed = true;
      }
      if (changed) {
        checkedKeys = next;
        if (lastCheckedKey && !visible.has(lastCheckedKey)) lastCheckedKey = null;
      }
    });
  });

  function clearSearchTimeoutForRequest(requestId: number) {
    const t = searchTimeouts.get(requestId);
    if (t) {
      clearTimeout(t);
      searchTimeouts.delete(requestId);
    }
  }

  /** Drop a request's settled flag once nothing can re-arm a timer for it.
   *  Both the cancel watchdog and the completion fallback live in
   *  `searchTimeouts`, so an id with no entry left there has neither, and
   *  `getSettings`'s own `searchTimeouts.has` guard already covers it.
   *  Without this the set gained an entry per search for the page's life. */
  function forgetSettledRequest(requestId: number) {
    if (!searchTimeouts.has(requestId)) searchInvokeSettled.delete(requestId);
  }

  // Grace period after the backend confirms a search finished (the
  // `search_files` invoke resolved) during which we still expect the
  // `search-complete` event to flip `isSearching` off. If that event is
  // ever dropped on the IPC bridge the spinner would spin forever, so this
  // fallback clears it — but only when no retry phase is still running
  // (the retry path owns the spinner until its own completion).
  // Kad-only: short grace (oneshot ≈ search end). Global/server: TCP/UDP can
  // still stream for ~90s+ after the invoke returns.
  const SEARCH_COMPLETE_GRACE_KAD_MS = 5000;
  const SEARCH_COMPLETE_GRACE_ED2K_MS = 120_000;

  function armSearchCompletionFallback(requestId: number, method: SearchMethod) {
    clearSearchTimeoutForRequest(requestId);
    const graceMs =
      method === 'kad' ? SEARCH_COMPLETE_GRACE_KAD_MS : SEARCH_COMPLETE_GRACE_ED2K_MS;
    searchTimeouts.set(
      requestId,
      setTimeout(() => {
        searchTimeouts.delete(requestId);
        forgetSettledRequest(requestId);
        patchSearchTabByRequestId(requestId, (tab) => {
          if (!tab.isSearching) return tab;
          return { ...tab, isSearching: false, progress: null };
        });
      }, graceMs),
    );
  }

  function shortenTabLabel(s: string, max = 28): string {
    const t = s.trim() || '—';
    return t.length <= max ? t : `${t.slice(0, max - 1)}…`;
  }

  function selectSearchTab(tabId: string) {
    setActiveSearchTab(tabId);
    const t = get(searchTabs).find((x) => x.id === tabId);
    if (t) barQuery = t.query;
    selectedResultKey = null;
    notes = [];
    notesRequestId += 1;
    loadingNotes = false;
    spamExplainLoading = false;
    spamExplainError = null;
    clearChecked();
    closeContextMenu();
  }

  /**
   * Arrow-key navigation across search tabs, matching WAI-ARIA tablist
   * guidance: Left/Right move, Home/End jump to ends, and focus follows
   * selection so the selected tab is always the one activated.
   */
  function onTabKeydown(e: KeyboardEvent, tabId: string) {
    const tabs = get(searchTabs);
    if (tabs.length === 0) return;
    const idx = tabs.findIndex((t) => t.id === tabId);
    if (idx === -1) return;
    let target = -1;
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      target = (idx + 1) % tabs.length;
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      target = (idx - 1 + tabs.length) % tabs.length;
    } else if (e.key === 'Home') {
      target = 0;
    } else if (e.key === 'End') {
      target = tabs.length - 1;
    } else {
      return;
    }
    e.preventDefault();
    const nextTab = tabs[target];
    if (!nextTab) return;
    selectSearchTab(nextTab.id);
    requestAnimationFrame(() => {
      const el = document.querySelector<HTMLButtonElement>(
        `[data-search-tab-id="${nextTab.id}"]`,
      );
      el?.focus();
    });
  }

  function requestCloseSearchTab(tab: SearchTab) {
    // Only confirm when closing would lose work: an in-flight search or
    // accumulated results. A closed, empty tab is always one click to drop.
    const hasResults = tab.results.length > 0;
    if (!tab.isSearching && !hasResults) {
      void performCloseSearchTab(tab);
      return;
    }
    pendingConfirm = { kind: 'close-tab', tab };
    confirmTitle = tab.isSearching ? m.search_confirm_stop_close() : m.search_confirm_close_tab();
    const preview = tab.query.length > 60 ? `${tab.query.slice(0, 59)}…` : tab.query;
    confirmMessage = tab.isSearching
      ? m.search_confirm_stop_message({ preview })
      : (tab.results.length === 1
          ? m.search_confirm_close_message_one({ preview })
          : m.search_confirm_close_message_other({ preview, count: tab.results.length }));
    confirmOpen = true;
  }

  async function performCloseSearchTab(tab: SearchTab) {
    clearSearchTimeoutForRequest(tab.requestId);
    await closeSearchTab(tab.id);
    selectedResultKey = null;
    notes = [];
    notesRequestId += 1;
    loadingNotes = false;
    spamExplainLoading = false;
    spamExplainError = null;
    clearChecked();
    closeContextMenu();
    // The closed tab's result hashes are no longer referenced; drop their
    // history bookkeeping so it doesn't accumulate across the session.
    pruneHistoryToVisible();
    const next = get(activeSearchTabId);
    if (next) {
      const nt = get(searchTabs).find((x) => x.id === next);
      if (nt) barQuery = nt.query;
    }
  }

  async function handleSearch(query: string) {
    // Clamp the query length before it reaches IPC: ed2k search keywords are
    // short, and an unbounded string is a needless payload/edge-case vector.
    const q = query.trim().slice(0, MAX_SEARCH_QUERY_LEN);
    const method = searchMethod;
    // eMule/backend: Program clears the local type filter so Arc/Iso hits
    // from a Pro-wire search remain visible. Keep Arc/Iso as client filters.
    filterType = searchFileType === 'Pro' ? '' : searchFileType;
    const parsedMinSize = filterMinSize !== null ? filterMinSize * filterMinUnit : undefined;
    const parsedMaxSize = filterMaxSize !== null ? filterMaxSize * filterMaxUnit : undefined;
    const parsedMinAvail = filterMinSources !== null ? Math.trunc(filterMinSources) : undefined;
    // Reject NaN *and* Infinity (e.g. "1e400") and negatives — `Number.isFinite`
    // excludes both, unlike the previous `!isNaN` which let Infinity through.
    const searchFilterSnapshot: import('$lib/api/search').SearchFilters = {
      fileExtension: filterExtension.trim() || undefined,
      minSize: parsedMinSize !== undefined && Number.isFinite(parsedMinSize) && parsedMinSize >= 0 ? parsedMinSize : undefined,
      maxSize: parsedMaxSize !== undefined && Number.isFinite(parsedMaxSize) && parsedMaxSize >= 0 ? parsedMaxSize : undefined,
      minAvailability: parsedMinAvail !== undefined && Number.isFinite(parsedMinAvail) && parsedMinAvail >= 0 ? parsedMinAvail : undefined,
    };
    if (!q && !hasSearchFilters(searchFilterSnapshot, searchFileType || undefined)) return;
    // Gate by the selected search method — KAD-only needs KAD, server-only
    // needs the eD2K server, Ember-only needs Ember enabled, global needs
    // any of KAD / server / Ember.
    const kadUp = $networkStats.status === 'connected';
    const serverUp = $serverStatus === 'connected';
    const emberJoining = emberEnabled && emberContacts === 0 && !emberJoinTimedOut;
    const emberReady = emberEnabled && emberContacts > 0;
    const emberNoPeers = emberEnabled && emberContacts === 0 && emberJoinTimedOut;
    const methodAllowed =
      method === 'kad' ? kadUp :
      method === 'server' ? serverUp :
      method === 'ember' ? emberReady :
      kadUp || serverUp || emberReady;
    if (!methodAllowed) {
      // Joining / timed out with zero Ember contacts: keep the muted hint
      // only when Ember is the method that would have been used. KAD-only
      // and server-only still raise the disconnected dialog.
      const emberIsTheOnlyCandidate =
        method === 'ember' || (method === 'global' && !kadUp && !serverUp);
      if (emberIsTheOnlyCandidate && (emberJoining || emberNoPeers)) {
        return;
      }
      networkAlertOpen = true;
      return;
    }
    const { requestId } = openSearchTab(q, method, searchFileType || undefined, searchFilterSnapshot);
    selectedResultKey = null;
    notes = [];
    clearChecked();
    closeContextMenu();
    let timeoutSec = searchTimeoutSecs;
    const searchPromise = searchFiles(q, method, requestId, searchFileType || undefined, searchFilterSnapshot);

    // Arm the watchdog once and expose a re-arm helper. getSettings() runs in
    // parallel with the search so a slow settings fetch can never block (and
    // therefore never race against) the search result path. If the search
    // settles first the watchdog is cleared by the success/error branch below
    // and the settings promise becomes a no-op.
    const armTimeout = (secs: number) => {
      clearSearchTimeoutForRequest(requestId);
      searchTimeouts.set(
        requestId,
        setTimeout(async () => {
          searchTimeouts.delete(requestId);
          try { await cancelSearch(requestId); } catch { /* best effort */ }
          // Same discard protocol as Stop: rotate the id so the cancel
          // oneshot cannot merge into this tab, keep streamed rows, and
          // only show a timeout error when the tab is still empty.
          searchInvokeSettled.add(requestId);
          clearPendingSearchResults(requestId);
          patchSearchTabByRequestId(requestId, (tab) => {
            if (!tab.isSearching) return tab;
            return {
              ...tab,
              requestId: newSearchNonce(),
              isSearching: false,
              progress: null,
              error: tab.results.length > 0 ? null : m.search_timeout_error({ secs }),
            };
          });
          forgetSettledRequest(requestId);
        }, secs * 1000),
      );
    };
    armTimeout(timeoutSec);

    getSettings()
      .then((s) => {
        if (searchInvokeSettled.has(requestId)) return;
        if (!searchTimeouts.has(requestId)) return; // search already finished
        if (s.search_timeout_secs !== timeoutSec) {
          timeoutSec = s.search_timeout_secs;
          searchTimeoutSecs = timeoutSec;
          armTimeout(timeoutSec);
        }
        // spamProfile tracks $appSettings reactively
      })
      .catch(() => {
        /* use cached timeout already set */
      });

    try {
      const results = await searchPromise;
      // Search succeeded — cancel the long timeout watchdog so it doesn't
      // fire later and call cancelSearch() against a request the backend has
      // already closed, then arm a short completion fallback so a dropped
      // `search-complete` event can't leave the spinner stuck forever.
      searchInvokeSettled.add(requestId);
      clearSearchTimeoutForRequest(requestId);
      if (!get(searchTabs).some((t) => t.requestId === requestId)) {
        return;
      }
      if (results && results.length > 0) {
        appendSearchResults(requestId, results);
      }
      armSearchCompletionFallback(requestId, method);
    } catch (e: unknown) {
      searchInvokeSettled.add(requestId);
      clearSearchTimeoutForRequest(requestId);
      if (!get(searchTabs).some((t) => t.requestId === requestId)) return;
      const msg = translateError(e, m.search_failed());
      console.error('Search failed:', e);
      patchSearchTabByRequestId(requestId, (tab) => ({
        ...tab,
        isSearching: false,
        progress: null,
        error: msg,
      }));
      forgetSettledRequest(requestId);
    }
  }

  // `tabId` defaults to the active tab (toolbar Stop button), but a search
  // running in a background tab previously had no way to be stopped without
  // switching to it first — the tab strip's per-tab stop control below
  // passes its own tab's id explicitly.
  async function stopSearch(tabId?: string) {
    const t = tabId != null ? get(searchTabs).find((tab) => tab.id === tabId) ?? null : activeTab;
    if (!t?.isSearching) return;
    const stoppedId = t.requestId;
    clearSearchTimeoutForRequest(stoppedId);
    try {
      await cancelSearch(stoppedId);
    } catch (e) {
      console.error('Failed to cancel search:', e);
      // The backend `try_send`s the cancel, so a full command channel drops it.
      // Since we rotate the requestId below regardless, a silently-failed cancel
      // means the search keeps running server-side while every result it finds
      // is discarded — the user should know the stop didn't reach the network.
      addToast('warning', m.search_stop_failed());
    }
    // Same discard protocol as `performClearResults`: the backend answers a
    // cancel by resolving the pending `search_files` oneshot with everything it
    // collected so far, so without rotating the id that payload merges into the
    // tab the user just stopped. Results already shown are kept — this is Stop,
    // not Clear.
    searchInvokeSettled.add(stoppedId);
    clearPendingSearchResults(stoppedId);
    patchSearchTabByRequestId(stoppedId, (tab) => ({
      ...tab,
      requestId: newSearchNonce(),
      isSearching: false,
      progress: null,
    }));
    forgetSettledRequest(stoppedId);
  }

  function dismissTabError() {
    const id = get(activeSearchTabId);
    if (!id) return;
    searchTabs.update((tabs) => tabs.map((tab) => (tab.id === id ? { ...tab, error: null } : tab)));
  }

  async function showFileDetails(result: SearchResult) {
    selectedResultKey = resultKey(result);
    loadingNotes = true;
    spamExplainLoading = true;
    spamExplainError = null;
    notes = [];
    notesError = null;
    noteRating = 0;
    noteComment = '';
    publishMessage = '';
    const requestId = ++notesRequestId;
    const fileHash = result.file.hash;
    const key = resultKey(result);
    const query = currentSearchQuery();

    // Load notes and spam explanation independently so one slow request
    // does not block the other from rendering in the details panel.
    void (async () => {
      try {
        const loadedNotes = await findNotes(result.file.hash, result.file.size);
        if (!selectedResult || selectedResult.file.hash !== fileHash || requestId !== notesRequestId) return;
        notes = loadedNotes;
      } catch (e: unknown) {
        console.error('Failed to load notes:', e);
        // Otherwise a timed-out KAD lookup is indistinguishable from a file
        // that genuinely has no notes.
        if (requestId === notesRequestId && selectedResult?.file.hash === fileHash) {
          notesError = translateError(e, m.search_failed_load_notes());
        }
      } finally {
        if (requestId === notesRequestId && selectedResult?.file.hash === fileHash) {
          loadingNotes = false;
        }
      }
    })();

    void (async () => {
      try {
        const cached = explanationFromResult(result)
          ?? (rowIsCleanOfSpam(result) ? undefined : spamExplainCache[key]);
        if (cached) {
          setSpamCache(key, cached);
          return;
        }
        const explain = await explainSpamResult(
          result.file.hash,
          result.file.name,
          result.file.size,
          result.source_addresses,
          query,
          explainOpts(result),
        );
        if (!selectedResult || selectedResult.file.hash !== fileHash || requestId !== notesRequestId) return;
        setSpamCache(key, explain);
      } catch (e: unknown) {
        if (requestId === notesRequestId && selectedResult?.file.hash === fileHash) {
          spamExplainError = translateError(e, m.search_failed_evaluate_spam());
        }
      } finally {
        if (requestId === notesRequestId && selectedResult?.file.hash === fileHash) {
          spamExplainLoading = false;
        }
      }
    })();
  }

  async function ensureSpamExplanation(result: SearchResult): Promise<void> {
    const key = resultKey(result);
    const stored = explanationFromResult(result);
    if (stored) {
      setSpamCache(key, stored);
      return;
    }
    if (rowIsCleanOfSpam(result)) {
      delete spamExplainCache[key];
      return;
    }
    if (spamExplainCache[key] || spamExplainPending[key]) return;
    spamExplainPending[key] = true;
    delete spamExplainErrors[key];
    try {
      const explain = await explainSpamResult(
        result.file.hash,
        result.file.name,
        result.file.size,
        result.source_addresses,
        currentSearchQuery(),
        explainOpts(result),
      );
      setSpamCache(key, explain);
    } catch (e: unknown) {
      spamExplainErrors[key] = translateError(e, m.search_failed_explain_spam());
    } finally {
      spamExplainPending[key] = false;
    }
  }

  function openSpamTooltip(result: SearchResult) {
    const key = resultKey(result);
    spamTooltipKey = key;
    void ensureSpamExplanation(result);
  }

  function closeSpamTooltip() {
    spamTooltipKey = null;
  }

  let publishingNote = $state(false);
  async function handlePublishNote() {
    if (!selectedResult || publishingNote) return;
    publishingNote = true;
    publishMessage = '';
    // The rating input is a free-form number field; browsers can submit
    // out-of-range or fractional values (and an empty field yields NaN).
    // Clamp to the backend's 0..5 integer contract before publishing.
    const rating = Math.max(0, Math.min(5, Math.round(Number(noteRating) || 0)));
    try {
      publishMessage = await publishNote(
        selectedResult.file.hash,
        rating,
        noteComment,
        selectedResult.file.name,
        selectedResult.file.size,
      );
      publishSuccess = true;
      noteComment = '';
      noteRating = 0;
      safeTimeout(() => publishMessage = '', 3000);
    } catch (e: unknown) {
      publishMessage = translateError(e, m.search_publish_failed());
      publishSuccess = false;
      safeTimeout(() => publishMessage = '', 5000);
    } finally {
      publishingNote = false;
    }
  }

  let downloadPending: Record<string, boolean> = $state({});

  /**
   * Pick the first syntactically valid address from the candidate list.
   * Returns `{ ip: '', port: 0 }` when nothing parses — the backend then
   * performs full KAD/server source discovery on its own. Previously we
   * passed `addresses[0]` blindly, which could pin the transfer's first
   * source to a bad peer when the list was unordered.
   */
  function pickInitialSource(addresses: string[]): { ip: string; port: number } {
    for (const addr of addresses) {
      if (!addr) continue;
      const { ip, port } = parseAddress(addr);
      if (ip && port > 0 && ip !== '0.0.0.0') {
        return { ip, port };
      }
    }
    return { ip: '', port: 0 };
  }

  function parseAddress(addr: string): { ip: string; port: number } {
    if (!addr) return { ip: '', port: 0 };
    const bracketEnd = addr.lastIndexOf(']');
    if (bracketEnd >= 0) {
      const ip = addr.slice(0, bracketEnd + 1).replace(/^\[/, '').replace(/\]$/, '');
      const rest = addr.slice(bracketEnd + 1);
      const port = rest.startsWith(':') ? parseInt(rest.slice(1), 10) || 0 : 0;
      return { ip, port };
    }
    // Count colons to distinguish IPv6 from IPv4:port
    const colonCount = (addr.match(/:/g) || []).length;
    if (colonCount > 1) {
      // Unbracketed IPv6 — treat entire string as IP, no port
      return { ip: addr, port: 0 };
    }
    const lastColon = addr.lastIndexOf(':');
    if (lastColon > 0) {
      return { ip: addr.slice(0, lastColon), port: parseInt(addr.slice(lastColon + 1), 10) || 0 };
    }
    return { ip: addr, port: 0 };
  }

  async function download(result: SearchResult) {
    const key = resultKey(result);
    if (downloadPending[key]) return;
    // The row's download button disables itself once `getDownloadTransfer`
    // finds a match (see its "mirrors `download()`'s early-exit checks"
    // comment below), but double-click and the context-menu "Download" item
    // both call this directly without checking first. Without this, either
    // path fires a redundant `startDownload` for a file that's already an
    // active transfer — harmless server-side (`already_queued: true`), but
    // it's an extra IPC round-trip and toast the disabled button exists
    // specifically to prevent.
    if (getBlockingDownloadTransfer(result)) {
      addToast('info', m.search_action_already_downloading_title());
      return;
    }

    const networkAddresses = (result.source_addresses ?? []).filter(
      (a) => a && a !== 'local'
    );

    if (!result.file.hash?.trim()) {
      addToast('error', m.error_transfers_invalid_file_hash());
      return;
    }

    if (networkAddresses.length === 0 && result.result_origin?.includes('Local')) {
      addToast('info', m.search_already_in_library());
      return;
    }

    // Empty `source_addresses` is fine when we have a hash: KAD/server
    // results often report availability without embedding peer IPs. The
    // backend starts with `{ ip: '', port: 0 }` and runs full source
    // discovery. Only local-only hits (handled above) should short-circuit.

    downloadPending[key] = true;
    try {
      const { ip: peerIp, port: peerPort } = pickInitialSource(networkAddresses);
      // Pass every other valid address from the search hit as extras
      // so the multi-source manager can attempt them in parallel
      // instead of waiting for the backend's KAD / server source
      // discovery to find them again. The backend re-validates and
      // dedups against the primary anyway, but we can save it the
      // round-trip by stripping the exact primary string here.
      const primaryAddr = peerIp && peerPort > 0 ? `${peerIp}:${peerPort}` : '';
      const extraSources = primaryAddr
        ? networkAddresses.filter((addr) => addr !== primaryAddr)
        : networkAddresses.slice();
      const res = await startDownload(
        result.file.hash,
        displayName(result),
        result.file.size,
        peerIp,
        peerPort,
        extraSources,
        result.file.ember_file_hash,
        result.file.aich_hash,
      );
      addToast('success', res.already_queued ? m.search_already_in_queue() : m.search_download_queued());
    } catch (e: unknown) {
      console.error('Download failed:', e);
      const msg = translateError(e, m.browse_download_failed());
      addToast('error', msg);
    } finally {
      downloadPending[key] = false;
    }
  }

  function clearFilters() {
    filterType = '';
    filterMinSize = null;
    filterMaxSize = null;
    filterExtension = '';
    filterMinSources = null;
    filterMinComplete = null;
    filterColumn = 'all';
    hideSpam = false;
    clearFilterText();
  }

  function showContextMenu(e: MouseEvent, result: SearchResult) {
    e.preventDefault();
    const margin = 8;
    const x = Math.max(margin, Math.min(e.clientX, window.innerWidth - 200 - margin));
    const y = Math.max(margin, Math.min(e.clientY, window.innerHeight - 150 - margin));
    contextMenu = { x, y, result };
  }

  function closeContextMenu() {
    contextMenu = null;
  }

  function clearSpamExplainForResult(result: SearchResult) {
    const key = resultKey(result);
    delete spamExplainCache[key];
    delete spamExplainErrors[key];
    spamExplainPending[key] = false;
  }

  async function handleMarkSpam(result: SearchResult) {
    const prevSpam = result.is_spam;
    const prevRating = result.spam_rating ?? 0;
    const prevReasons = result.spam_reasons?.slice() ?? [];
    const hash = result.file.hash;
    const gen = (spamToggleGen.get(hash) ?? 0) + 1;
    spamToggleGen.set(hash, gen);
    // Close the menu first so the dismiss paints before filter/sort work.
    // Persist in the background; waiting on IPC (incl. disk) used to freeze the UI.
    contextMenu = null;
    await new Promise<void>((r) => requestAnimationFrame(() => r()));
    patchSpamFlagByHash(hash, true, spamThreshold, ['Manually marked as spam']);
    clearSpamExplainForResult(result);
    try {
      await markSpam(
        hash,
        result.file.name,
        result.file.size,
        result.source_addresses,
        currentSearchQuery(),
        result.origin_server_ip,
      );
      // A newer mark/unmark superseded this request — leave its optimistic state.
      if (spamToggleGen.get(hash) !== gen) return;
    } catch (e) {
      console.error('Failed to mark spam:', e);
      if (spamToggleGen.get(hash) === gen) {
        patchSpamFlagByHash(hash, prevSpam, prevRating, prevReasons);
        addToast('error', m.search_failed_mark_spam());
      }
    }
  }

  async function handleMarkNotSpam(result: SearchResult) {
    const prevSpam = result.is_spam;
    const prevRating = result.spam_rating ?? 0;
    const prevReasons = result.spam_reasons?.slice() ?? [];
    const hash = result.file.hash;
    const gen = (spamToggleGen.get(hash) ?? 0) + 1;
    spamToggleGen.set(hash, gen);
    contextMenu = null;
    await new Promise<void>((r) => requestAnimationFrame(() => r()));
    patchSpamFlagByHash(hash, false, 0, ['Manually marked as not spam']);
    clearSpamExplainForResult(result);
    try {
      await markNotSpam(hash);
      if (spamToggleGen.get(hash) !== gen) return;
    } catch (e) {
      console.error('Failed to unmark spam:', e);
      if (spamToggleGen.get(hash) === gen) {
        patchSpamFlagByHash(hash, prevSpam, prevRating, prevReasons);
        addToast('error', m.search_failed_unmark_spam());
      }
    }
  }

  /** Per-row delete from download history. Complements the batch-clear
   *  buttons in Settings > Downloads: useful when a user wants a single
   *  completed/cancelled row to stop being badged on re-searches (e.g.
   *  they deleted the downloaded file and want to fetch it again).
   *
   *  After a successful remove, drop the hash from `downloadHistoryMap`
   *  so the row's class bindings (`history-completed-row` /
   *  `history-cancelled-row`) and the badge text update immediately —
   *  avoiding a page reload or a full `getDownloadHistory` re-poll.
   */
  async function handleRemoveFromHistory(result: SearchResult) {
    const hash = result.file.hash;
    try {
      await removeDownloadHistoryEntry(hash);
      delete downloadHistoryMap[hash];
      // Drop the cache marks so a later re-download of this file is allowed to
      // re-fetch and re-badge (otherwise the hash would stay permanently in
      // `historyFetchedHashes` and never refresh).
      invalidateHistory(hash);
      completedHandled.delete(hash);
      addToast('success', m.search_removed_from_history());
    } catch (e) {
      console.error('Failed to remove from history:', e);
      addToast('error', m.search_failed_remove_history());
    }
    contextMenu = null;
  }

  function historyStatusLabel(status: string | undefined): string {
    if (status === 'completed') return m.search_history_downloaded();
    if (status === 'cancelled') return m.search_history_cancelled();
    return status ?? '';
  }

  function requestClearResults() {
    const tab = activeTab;
    if (!tab || tab.results.length === 0) return;
    pendingConfirm = { kind: 'clear-results' };
    confirmTitle = m.search_confirm_clear_title();
    confirmMessage = tab.results.length === 1
      ? m.search_confirm_clear_message_one()
      : m.search_confirm_clear_message_other({ count: tab.results.length });
    confirmOpen = true;
  }

  // Bound the per-hash download-history bookkeeping to hashes still referenced
  // by an open tab. Without this, `downloadHistoryMap`, `historyFetchedHashes`,
  // `historyPendingHashes` and `historyHashGen` grow monotonically for the
  // page's lifetime (every unique result hash is added and never evicted).
  function pruneHistoryToVisible() {
    const live = new Set<string>();
    for (const t of get(searchTabs)) {
      for (const r of t.results) {
        const h = r?.file?.hash;
        if (h) live.add(h);
      }
    }
    const pruned: Record<string, string> = {};
    for (const [h, v] of Object.entries(downloadHistoryMap)) {
      if (live.has(h)) pruned[h] = v;
    }
    downloadHistoryMap = pruned;
    for (const h of [...historyFetchedHashes]) if (!live.has(h)) historyFetchedHashes.delete(h);
    for (const h of [...historyPendingHashes]) if (!live.has(h)) historyPendingHashes.delete(h);
    for (const h of [...historyHashGen.keys()]) if (!live.has(h)) historyHashGen.delete(h);
  }

  function performClearResults() {
    const tabId = get(activeSearchTabId);
    if (!tabId) return;
    const tab = get(searchTabs).find((t) => t.id === tabId);
    const oldRequestId = tab?.requestId;
    if (tab?.isSearching && oldRequestId != null) {
      clearSearchTimeoutForRequest(oldRequestId);
      searchInvokeSettled.add(oldRequestId);
      void cancelSearch(oldRequestId).catch(() => { /* best effort */ });
    }
    // Rotate requestId and drop buffered stream merges so late oneshot /
    // search-results / flush cannot refill the cleared tab (SF9).
    const discardedId = oldRequestId;
    const freshId = newSearchNonce();
    if (discardedId != null) {
      clearPendingSearchResults(discardedId);
      searchInvokeSettled.add(discardedId);
    }
    searchTabs.update((tabs) =>
      tabs.map((t) =>
        t.id === tabId
          ? {
              ...t,
              requestId: freshId,
              results: [],
              error: null,
              isSearching: false,
              progress: null,
            }
          : t,
      ),
    );
    selectedResultKey = null;
    notes = [];
    spamExplainLoading = false;
    spamExplainError = null;
    downloadPending = {};
    spamExplainPending = {};
    spamExplainErrors = {};
    spamExplainCache = {};
    spamTooltipKey = null;
    clearChecked();
    pruneHistoryToVisible();
    if (discardedId != null) forgetSettledRequest(discardedId);
  }

  function handleConfirm() {
    const action = pendingConfirm;
    pendingConfirm = null;
    if (!action) return;
    if (action.kind === 'clear-results') {
      performClearResults();
    } else if (action.kind === 'close-tab') {
      void performCloseSearchTab(action.tab);
    } else if (action.kind === 'copy-all-links') {
      void copyLinksFor(action.results);
    }
  }

  function handleConfirmCancel() {
    pendingConfirm = null;
  }

  function toggleCheck(key: string, index: number, shiftKey: boolean) {
    const next = new Set(checkedKeys);
    const lastIdx = lastCheckedKey
      ? filteredResults.findIndex(r => resultKey(r) === lastCheckedKey)
      : -1;
    if (shiftKey && lastIdx >= 0 && lastIdx !== index) {
      const lo = Math.min(lastIdx, index);
      const hi = Math.max(lastIdx, index);
      for (let i = lo; i <= hi; i++) {
        const r = filteredResults[i];
        if (r) next.add(resultKey(r));
      }
    } else {
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
    }
    checkedKeys = next;
    lastCheckedKey = key;
  }

  function toggleCheckAll() {
    if (allFilteredChecked) {
      const filtered = new Set(filteredResults.map((r) => resultKey(r)));
      const next = new Set(checkedKeys);
      for (const k of filtered) next.delete(k);
      checkedKeys = next;
    } else {
      const next = new Set(checkedKeys);
      for (const r of filteredResults) next.add(resultKey(r));
      checkedKeys = next;
    }
  }

  function clearChecked() {
    checkedKeys = new Set();
    lastCheckedKey = null;
  }

  // --- eD2K links ---
  // Copying links is how a search result gets shared or handed to another
  // client, so it works on one row, on the ticked rows, and on the whole
  // filtered list — the same three scopes the library offers.

  /** Above this many links, ask first: some apps take a long time to paste
   *  a list this size. Mirrors the library's threshold. */
  const COPY_ALL_LINKS_CONFIRM_AT = 5_000;
  let copyingLinks = $state(false);

  /** Results that can actually produce a link, deduplicated by hash. A hit
   *  still waiting on its hash has nothing to copy. */
  function linkableResults(results: SearchResult[]): SearchResult[] {
    const seen = new Set<string>();
    const out: SearchResult[] = [];
    for (const r of results) {
      const h = r.file.hash?.trim();
      if (!h || seen.has(h)) continue;
      seen.add(h);
      out.push(r);
    }
    return out;
  }

  async function copyResultLink(result: SearchResult) {
    if (!result.file.hash?.trim()) {
      addToast('error', m.error_transfers_invalid_file_hash());
      return;
    }
    try {
      const link = await formatEd2kLink(
        displayName(result),
        result.file.size,
        result.file.hash,
        result.file.ember_file_hash,
      );
      if (!(await copyToClipboard(link))) {
        addToast('error', m.search_copy_failed());
        return;
      }
      addToast('success', m.search_copied_link_one());
    } catch (e: unknown) {
      addToast('error', translateError(e, m.search_copy_failed()));
    }
  }

  async function copyLinksFor(results: SearchResult[]) {
    if (copyingLinks) return;
    const targets = linkableResults(results);
    if (targets.length === 0) {
      addToast('warning', m.search_copy_none());
      return;
    }
    copyingLinks = true;
    try {
      const text = await formatEd2kLinks(
        targets.map((r) => ({
          name: displayName(r),
          size: r.file.size,
          hash: r.file.hash,
          emberFileHash: r.file.ember_file_hash || undefined,
        })),
      );
      if (!(await copyToClipboard(text))) {
        addToast('error', m.search_copy_failed());
        return;
      }
      addToast('success', targets.length === 1
        ? m.search_copied_link_one()
        : m.search_copied_links_other({ count: targets.length }));
    } catch (e: unknown) {
      addToast('error', translateError(e, m.search_copy_failed()));
    } finally {
      copyingLinks = false;
    }
  }

  function copyCheckedLinks() {
    void copyLinksFor(filteredResults.filter((r) => checkedKeys.has(resultKey(r))));
  }

  function requestCopyAllLinks() {
    const targets = linkableResults(filteredResults);
    if (targets.length === 0) {
      addToast('warning', m.search_copy_none());
      return;
    }
    if (targets.length < COPY_ALL_LINKS_CONFIRM_AT) {
      void copyLinksFor(targets);
      return;
    }
    pendingConfirm = { kind: 'copy-all-links', results: targets };
    confirmTitle = m.search_copy_all_confirm_title();
    confirmMessage = m.search_copy_all_confirm({ count: targets.length.toLocaleString() });
    confirmOpen = true;
  }

  async function downloadChecked() {
    if (bulkDownloadPending || checkedKeys.size === 0) return;
    bulkDownloadPending = true;
    bulkDownloadMessage = '';
    bulkDownloadHasFailures = false;
    const toDownload = filteredResults.filter((r) => checkedKeys.has(resultKey(r)));

    let queued = 0;
    let failed = 0;
    let skippedLocal = 0;
    let alreadyQueued = 0;
    const failures: string[] = [];

    // Fan out with bounded concurrency so the backend doesn't get hammered
    // with hundreds of simultaneous start_download calls on a big selection.
    const CONCURRENCY = 6;
    let cursor = 0;
    async function worker() {
      while (true) {
        const idx = cursor++;
        if (idx >= toDownload.length) return;
        const result = toDownload[idx];
        const networkAddrs = (result.source_addresses ?? []).filter((a) => a && a !== 'local');
        if (!result.file.hash?.trim()) {
          failed++;
          failures.push(`${displayName(result)}: ${m.error_transfers_invalid_file_hash()}`);
          continue;
        }
        if (networkAddrs.length === 0 && isInLibraryOnly(result)) {
          skippedLocal++;
          continue;
        }
        if (getBlockingDownloadTransfer(result)) {
          alreadyQueued++;
          continue;
        }
        // Same as single-row download: a hash without embedded addresses
        // still queues; the backend discovers sources.
        try {
          const { ip: peerIp, port: peerPort } = pickInitialSource(networkAddrs);
          // Same bulk-seed treatment as the single-row download path
          // — pass the rest of the search hit's addresses so the
          // multi-source manager can fan out in parallel.
          const primaryAddr = peerIp && peerPort > 0 ? `${peerIp}:${peerPort}` : '';
          const extraSources = primaryAddr
            ? networkAddrs.filter((addr) => addr !== primaryAddr)
            : networkAddrs.slice();
          const res = await startDownload(
            result.file.hash,
            displayName(result),
            result.file.size,
            peerIp,
            peerPort,
            extraSources,
            result.file.ember_file_hash,
            result.file.aich_hash,
          );
          if (res.already_queued) {
            alreadyQueued++;
          } else {
            queued++;
          }
        } catch (e) {
          failed++;
          const msg = translateError(e, m.search_bulk_download_failed());
          failures.push(`${displayName(result)}: ${msg}`);
        }
      }
    }

    try {
      const workers: Promise<void>[] = [];
      for (let i = 0; i < Math.min(CONCURRENCY, toDownload.length); i++) {
        workers.push(worker());
      }
      await Promise.all(workers);
    } finally {
      bulkDownloadPending = false;
    }

    const parts: string[] = [];
    if (queued > 0) parts.push(m.search_bulk_queued({ count: queued }));
    if (alreadyQueued > 0) parts.push(`${alreadyQueued}× ${m.search_already_in_queue()}`);
    if (skippedLocal > 0) parts.push(m.search_bulk_already_in_library({ count: skippedLocal }));
    if (failed > 0) parts.push(m.search_bulk_failed({ count: failed }));
    bulkDownloadMessage = parts.join(', ');
    bulkDownloadHasFailures = failed > 0;
    safeTimeout(() => {
      bulkDownloadMessage = '';
      bulkDownloadHasFailures = false;
    }, 3000);

    if (queued > 0 && failed === 0) {
      const base = queued === 1 ? m.search_bulk_queued_one() : m.search_bulk_queued_other({ count: queued });
      addToast('success', skippedLocal > 0 ? m.search_bulk_queued_with_local({ base, local: skippedLocal }) : base);
    } else if (queued === 0 && alreadyQueued > 0 && failed === 0) {
      addToast('info', m.search_already_in_queue());
    } else if (failed > 0) {
      const head = failures.slice(0, 3).join(' · ');
      const more = failures.length > 3 ? m.search_bulk_more({ count: failures.length - 3 }) : '';
      addToast('error', m.search_bulk_failed_summary({
        failed,
        queued_part: queued > 0 ? m.search_bulk_failed_queued_suffix({ count: queued }) : '',
        head: head ? `: ${head}${more}` : '',
      }));
    } else if (skippedLocal > 0) {
      addToast('info', m.search_bulk_already_in_library({ count: skippedLocal }));
    }
  }

  let hasActiveFilters = $derived(
    filterType !== '' ||
    filterMinSize !== null ||
    filterMaxSize !== null ||
    filterExtension !== '' ||
    filterMinSources !== null ||
    filterMinComplete !== null ||
    filterText !== ''
  );

  // The visible result count and the raw search count can differ for
  // two reasons that aren't covered by `hasActiveFilters`: the spam
  // filter (`hideSpam`) and local-only entries that the pipeline always
  // drops. When they differ, the "(filtered from N)" suffix should show
  // even if no explicit filter chip is set, so the user understands why
  // the table isn't showing the headline number.
  // Both sides come from `visibleResults`, not the live store list: mixing a
  // throttled count with an unthrottled one makes "showing X of Y" briefly
  // disagree with the rows actually on screen (and X - Y go negative).
  let resultsHidden = $derived(visibleResults.length - filteredResults.length);

  let advancedFilterCount = $derived(
    (filterColumn !== 'all' && filterText !== '' ? 1 : 0) +
    (filterMinSize !== null ? 1 : 0) +
    (filterMaxSize !== null ? 1 : 0) +
    (filterExtension !== '' ? 1 : 0) +
    (filterMinSources !== null ? 1 : 0) +
    (filterMinComplete !== null ? 1 : 0)
  );

</script>

<svelte:document onkeydown={(e) => {
  if (e.key === 'Escape') {
    if (showColumnMenu) {
      showColumnMenu = false;
      e.preventDefault();
      e.stopPropagation();
    } else if (contextMenu) {
      closeContextMenu();
      e.preventDefault();
      e.stopPropagation();
    } else if (
      e.target instanceof HTMLInputElement ||
      e.target instanceof HTMLSelectElement
    ) {
      const id = e.target.id;
      if (id === 'filter-text' && filterTextInput) {
        clearFilterText();
        e.preventDefault();
        e.stopPropagation();
      } else if (id.startsWith('filter-') || e.target.closest('.filter-bar')) {
        e.preventDefault();
        e.stopPropagation();
      }
    } else if (selectedResultKey) {
      selectedResultKey = null;
      e.preventDefault();
      e.stopPropagation();
    }
    return;
  }
  // Ctrl+C copies the ticked results' links, or the whole filtered list when
  // nothing is ticked. Skipped while text is selected or focus is in a field,
  // so the normal copy still works in the query box.
  if ((e.ctrlKey || e.metaKey) && (e.key === 'c' || e.key === 'C')) {
    const target = e.target as HTMLElement | null;
    if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)) return;
    if (confirmOpen || !(window.getSelection()?.isCollapsed ?? true)) return;
    if (filteredResults.length === 0) return;
    e.preventDefault();
    if (checkedCount > 0) copyCheckedLinks();
    else requestCopyAllLinks();
  }
}} />

<div class="page-header">
  <h2>{m.search_title()}</h2>
</div>

<div class="search-area">
  <SearchBar
    bind:value={barQuery}
    placeholder={m.search_query_placeholder()}
    onsubmit={handleSearch}
    recentKey="search-recent-queries-v1"
    historyEnabled={$appSettings?.save_search_history ?? true}
  />
  <select class="type-select" bind:value={searchMethod} title={m.search_method_title()}>
    <option value="global">{m.search_method_global()}</option>
    <option value="kad">{m.search_method_kad_only()}</option>
    <option value="server">{m.search_method_server_only()}</option>
    {#if emberEnabled}
      <option value="ember">{m.search_method_ember_only()}</option>
    {/if}
  </select>
  <select class="type-select" bind:value={searchFileType} title={m.search_filter_by_filetype()}>
    {#each FILE_TYPES as ft}
      <option value={ft.value}>{ft.label}</option>
    {/each}
  </select>
  {#if activeTab?.isSearching}
    <button class="stop-btn" type="button" onclick={() => stopSearch()}>
      <svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor" aria-hidden="true">
        <rect x="3.5" y="3.5" width="9" height="9" rx="2"/>
      </svg>
      {m.common_stop()}
    </button>
  {:else}
    <button onclick={() => handleSearch(barQuery)} disabled={searchSubmitBlocked}>{m.search_title()}</button>
  {/if}
</div>
<p class="search-syntax-hint">{m.search_query_syntax_hint()}</p>

{#if $searchTabs.length > 0}
  <div class="search-tabs" role="tablist" aria-label={m.search_sessions_aria()}>
    {#each $searchTabs as tab (tab.id)}
      <div class="search-tab" class:active={tab.id === $activeSearchTabId} title={tab.query}>
        <button
          type="button"
          class="search-tab-select"
          data-search-tab-id={tab.id}
          onclick={() => selectSearchTab(tab.id)}
          onkeydown={(e) => onTabKeydown(e, tab.id)}
          role="tab"
          aria-selected={tab.id === $activeSearchTabId}
          tabindex={tab.id === $activeSearchTabId ? 0 : -1}
        >
          <span class="search-tab-label">{shortenTabLabel(tab.query)}</span>
          <span class="search-tab-meta" aria-label={tab.isSearching ? m.search_in_progress_aria() : m.search_results_aria({ count: tab.results.length })}>
            {#if tab.isSearching}
              {m.search_searching_label()}
            {:else}
              {tab.results.length}
            {/if}
          </span>
          {#if tab.isSearching}
            <span class="search-tab-spinner" aria-hidden="true"></span>
          {/if}
        </button>
        <div class="search-tab-actions">
          {#if tab.isSearching}
            <!-- Lets a search running in a background tab be stopped without
                 switching to it first — the toolbar Stop button only ever
                 acts on `activeTab`. -->
            <button
              type="button"
              class="search-tab-action search-tab-stop"
              onclick={() => stopSearch(tab.id)}
              title={m.search_stop_tab()}
              aria-label={m.search_stop_tab_aria()}
            >
              <svg viewBox="0 0 16 16" width="11" height="11" fill="currentColor" aria-hidden="true">
                <rect x="4" y="4" width="8" height="8" rx="1.75"/>
              </svg>
            </button>
          {/if}
          <button
            type="button"
            class="search-tab-action search-tab-close"
            onclick={() => requestCloseSearchTab(tab)}
            title={m.search_close_tab()}
            aria-label={m.search_close_tab_aria()}
          >
            <svg viewBox="0 0 16 16" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true">
              <path d="M4.25 4.25l7.5 7.5M11.75 4.25l-7.5 7.5"/>
            </svg>
          </button>
        </div>
      </div>
    {/each}
  </div>
{/if}

<div class="filter-bar">
  <div class="filter-primary-row">
    <div class="filter-group filter-text-group">
      <label for="filter-text">{m.search_filter_results()}</label>
      <div class="filter-text-wrap">
        <input
          id="filter-text"
          type="text"
          placeholder={m.search_filter_text_placeholder()}
          bind:value={filterTextInput}
          oninput={onFilterTextInput}
          class="filter-text-input"
        />
        {#if filterTextInput}
          <button type="button" class="filter-text-clear" onclick={clearFilterText} title={m.search_clear_filter_text()} aria-label={m.search_clear_filter_text()}>
            <svg viewBox="0 0 14 14" width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
              <line x1="3.5" y1="3.5" x2="10.5" y2="10.5"/>
              <line x1="10.5" y1="3.5" x2="3.5" y2="10.5"/>
            </svg>
          </button>
        {/if}
      </div>
    </div>

    <div class="filter-group">
      <label for="filter-type">{m.search_col_type()}</label>
      <select id="filter-type" bind:value={filterType}>
        {#each FILE_TYPES as ft}
          <option value={ft.value}>{ft.label}</option>
        {/each}
      </select>
    </div>

    <button class="ghost advanced-toggle" onclick={() => (showAdvancedFilters = !showAdvancedFilters)}>
      {showAdvancedFilters ? m.search_hide_advanced() : (advancedFilterCount > 0 ? m.search_advanced_filters_count({ count: advancedFilterCount }) : m.search_advanced_filters())}
    </button>

    {#if hasActiveFilters}
      <button class="ghost clear-filters" onclick={clearFilters}>{m.library_clear_filters()}</button>
    {/if}
  </div>

  {#if showAdvancedFilters}
    <div class="filter-advanced-row">
      <div class="filter-toggles" role="group" aria-label={m.search_visibility_filters_aria()}>
        <label class="filter-toggle">
          <input type="checkbox" bind:checked={hideSpam} />
          <span>{m.search_hide_spam()}</span>
          {#if spamHiddenCount > 0}
            <span class="filter-count">({spamHiddenCount})</span>
          {/if}
          <span class="filter-help-wrap">
            <button
              type="button"
              class="filter-help-icon"
              aria-label={m.search_explain_spam_hiding()}
              onmouseenter={() => (showSpamHelp = true)}
              onmouseleave={() => (showSpamHelp = false)}
              onfocus={() => (showSpamHelp = true)}
              onblur={() => (showSpamHelp = false)}
              onclick={() => (showSpamHelp = !showSpamHelp)}
            >
              <svg viewBox="0 0 16 16" width="11" height="11" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="8" cy="8" r="6.25"/>
                <path d="M6.25 6.25c0-1 .75-1.75 1.75-1.75s1.75.75 1.75 1.75c0 1-1.75 1.25-1.75 2.75"/>
                <circle cx="8" cy="11.5" r="0.55" fill="currentColor" stroke="none"/>
              </svg>
            </button>
            {#if showSpamHelp}
              <div class="filter-help-popover" role="tooltip">
                {#if hideSpam && spamHiddenCount > 0}
                  {m.search_spam_hidden_count({ count: spamHiddenCount })}
                {:else}
                  {m.search_spam_hidden_none()}
                {/if}
                <br />
                {m.search_spam_help_prefix()}
                <strong>{spamThreshold}</strong> {m.search_spam_help_in()} <strong>{spamProfileLabel(spamProfile)}</strong> {m.search_spam_help_suffix()}
              </div>
            {/if}
          </span>
        </label>
      </div>

      <div class="filter-group">
        <label for="filter-column">{m.search_filter_column()}</label>
        <select id="filter-column" bind:value={filterColumn} class="column-select" aria-label={m.search_filter_column()}>
          {#each FILTER_COLUMNS as col}
            <option value={col.value}>{col.label}</option>
          {/each}
        </select>
      </div>

      <div class="filter-group">
        <label for="filter-min-size">{m.search_min_size()}</label>
        <div class="size-input">
          <input
            id="filter-min-size"
            type="number"
            min="0"
            step="any"
            placeholder="—"
            bind:value={filterMinSize}
          />
          <select bind:value={filterMinUnit}>
            {#each SIZE_UNITS as u}
              <option value={u.value}>{u.label}</option>
            {/each}
          </select>
        </div>
      </div>

      <div class="filter-group">
        <label for="filter-max-size">{m.search_max_size()}</label>
        <div class="size-input">
          <input
            id="filter-max-size"
            type="number"
            min="0"
            step="any"
            placeholder="—"
            bind:value={filterMaxSize}
          />
          <select bind:value={filterMaxUnit}>
            {#each SIZE_UNITS as u}
              <option value={u.value}>{u.label}</option>
            {/each}
          </select>
        </div>
      </div>

      <div class="filter-group">
        <label for="filter-ext">{m.search_extension()}</label>
        <input
          id="filter-ext"
          type="text"
          placeholder={m.search_ext_placeholder()}
          bind:value={filterExtension}
          class="ext-input"
        />
      </div>

      <div class="filter-group">
        <label for="filter-sources">{m.search_min_sources()}</label>
        <input
          id="filter-sources"
          type="number"
          min="1"
          step="1"
          placeholder="—"
          bind:value={filterMinSources}
          class="sources-input"
        />
      </div>

      <div class="filter-group">
        <label for="filter-complete">{m.search_min_complete_sources()}</label>
        <input
          id="filter-complete"
          type="number"
          min="1"
          step="1"
          placeholder="—"
          bind:value={filterMinComplete}
          class="sources-input"
        />
      </div>
    </div>
  {/if}

  <p class="filter-help">{m.search_filter_help_prefix()} <code>-</code> {m.search_filter_help_suffix()}</p>
</div>

<div class="page-content">
  {#if (searchMethod === 'kad' && $networkStats.status !== 'connected')
    || (searchMethod === 'server' && $serverStatus !== 'connected')
    || (searchMethod === 'ember' && (!emberEnabled || (emberContacts === 0 && !emberJoinTimedOut)))
    || (searchMethod === 'global'
      && $networkStats.status !== 'connected'
      && $serverStatus !== 'connected'
      && emberEnabled
      && (emberContacts === 0 ? !emberJoinTimedOut : true))}
    <div class="search-readiness-hint" role="status">
      {searchNetworkHint(searchMethod)}
    </div>
  {:else if (searchMethod === 'ember' || (searchMethod === 'global' && !kadUpLive && !serverUpLive))
    && emberEnabled && emberContacts === 0 && emberJoinTimedOut}
    <div class="search-readiness-hint search-readiness-muted" role="status">
      {m.search_network_ember_no_peers_hint()}
    </div>
  {:else if searchMethod === 'global'
    && $networkStats.status !== 'connected'
    && $serverStatus !== 'connected'
    && !emberEnabled}
    <div class="search-readiness-hint" role="status">
      {m.search_network_disconnected_hint()}
    </div>
  {:else if $networkStats.degraded && $networkStats.degraded_reason}
    <div class="search-readiness-hint search-readiness-muted" role="status">
      {m.search_network_degraded_hint({ reason: degradedReasonText($networkStats.degraded_reason) })}
    </div>
  {/if}
  {#if activeTab?.error}
    <div class="search-error-banner">
      <span>{m.search_failed_with({ error: activeTab.error })}</span>
      <button class="ghost" onclick={dismissTabError}>{m.common_dismiss()}</button>
    </div>
  {/if}
  {#if $searchTabs.length === 0}
    <div class="empty-state">
      <div class="icon" aria-hidden="true">
        <svg viewBox="0 0 48 48" width="48" height="48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="20" cy="20" r="13"/>
          <line x1="30" y1="30" x2="41" y2="41"/>
        </svg>
      </div>
      <p>{m.search_empty_title()}</p>
      <p class="hint">{m.search_empty_hint()}</p>
    </div>
  {:else if activeTab?.isSearching && visibleResults.length === 0}
    <div class="empty-state">
      <div class="spinner lg"></div>
      <p>{m.search_searching_network()}</p>
      {#if activeTab.progress}
        {@const phase = searchPhaseLabel(activeTab.progress.phase)}
        <p class="search-detail">
          {m.search_contacted_nodes({ count: activeTab.progress.nodes_contacted })}
          {#if activeTab.progress.results_so_far > 0}
            &middot; {m.search_results_so_far({ count: activeTab.progress.results_so_far })}
          {/if}
          {#if phase}
            &middot; {phase}
          {/if}
        </p>
      {/if}
    </div>
  {:else if visibleResults.length === 0 && !activeTab?.isSearching}
    <div class="empty-state">
      <div class="icon" aria-hidden="true">
        <svg viewBox="0 0 48 48" width="48" height="48" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="20" cy="20" r="13"/>
          <line x1="30" y1="30" x2="41" y2="41"/>
        </svg>
      </div>
      <p>{m.search_no_results()}</p>
      <p class="hint">{m.search_no_results_hint()}</p>
    </div>
  {:else}
    <div class="results-info">
      <span>
        {#if activeTab?.isSearching}
          <span class="searching-indicator">{m.search_searching_indicator()}</span>
        {/if}
        {#if filteredResults.length > 0}
          {filteredResults.length === 1 ? m.search_showing_one() : m.search_showing_other({ count: filteredResults.length })}{#if resultsHidden > 0} {m.search_filtered_from({ total: visibleResults.length })}{/if}
        {:else if visibleResults.length > 0}
          {visibleResults.length === 1 ? m.search_zero_of_one({ what: hasActiveFilters ? m.search_filters_word() : m.search_visibility_rules_word() }) : m.search_zero_of_other({ count: visibleResults.length, what: hasActiveFilters ? m.search_filters_word() : m.search_visibility_rules_word() })}
        {:else}
          {m.search_zero_results()}
        {/if}
      </span>
      <div class="results-info-actions">
        <details class="column-menu" bind:open={showColumnMenu}>
          <summary class="column-menu-summary" title={m.search_columns_aria()} aria-haspopup="true">
            <svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
              <rect x="2" y="2.5" width="12" height="11" rx="1.5"/>
              <line x1="6.5" y1="2.5" x2="6.5" y2="13.5"/>
              <line x1="10.5" y1="2.5" x2="10.5" y2="13.5"/>
            </svg>
            {m.search_columns_button()}
          </summary>
          <div class="column-menu-panel" role="group" aria-label={m.search_columns_aria()}>
            {#each MEDIA_COLUMNS as col}
              <label class="column-menu-item">
                <input type="checkbox" checked={columnVis[col.key]} onchange={() => toggleColumn(col.key)} />
                <span>{col.label}</span>
              </label>
            {/each}
          </div>
        </details>
        <button
          class="ghost copy-links-btn"
          disabled={copyingLinks || filteredResults.length === 0}
          title={m.search_copy_all_links_title()}
          onclick={requestCopyAllLinks}
        >{m.search_copy_all_links()}</button>
        <button class="ghost clear-results-btn" onclick={requestClearResults}>{m.search_clear_results()}</button>
      </div>
    </div>
    {#if checkedCount > 0}
      <div class="bulk-actions" role="toolbar" aria-label={m.search_bulk_actions_aria()}>
        <span class="bulk-count">{m.search_bulk_selected({ count: checkedCount })}</span>
        <button class="bulk-download-btn" onclick={downloadChecked} disabled={bulkDownloadPending}>
          {bulkDownloadPending ? m.search_downloading_ellipsis() : (checkedCount === 1 ? m.search_bulk_download_one() : m.search_bulk_download_other({ count: checkedCount }))}
        </button>
        <button class="ghost bulk-copy-btn" onclick={copyCheckedLinks} disabled={copyingLinks} title={m.search_bulk_copy_links_title()}>
          {checkedCount === 1 ? m.search_bulk_copy_link_one() : m.search_bulk_copy_links_other({ count: checkedCount })}
        </button>
        <button class="ghost bulk-clear-btn" onclick={clearChecked} title={m.search_clear_selection_title()}>{m.search_clear_selection()}</button>
        {#if bulkDownloadMessage}
          <span class={bulkDownloadHasFailures ? 'error-msg' : 'success-msg'}>{bulkDownloadMessage}</span>
        {/if}
      </div>
    {/if}
    <table class="search-results-table">
      <thead>
        <tr>
          <th class="col-check">
            <input
              type="checkbox"
              bind:this={selectAllCheckbox}
              checked={allFilteredChecked}
              onchange={toggleCheckAll}
              aria-label={m.search_select_all_results()}
              title={m.search_select_all_results()}
            />
          </th>
          <th class="sortable col-name" role="columnheader" aria-sort={sortField === 'name' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('name')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('name'))}>
            {m.search_col_name()}{sortIndicator('name')}
          </th>
          <th class="sortable col-size" role="columnheader" aria-sort={sortField === 'size' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('size')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('size'))}>
            {m.search_col_size()}{sortIndicator('size')}
          </th>
          <th class="sortable col-type" role="columnheader" aria-sort={sortField === 'type' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('type')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('type'))}>
            {m.search_col_type()}{sortIndicator('type')}
          </th>
          <th class="sortable col-origin" role="columnheader" aria-sort={sortField === 'origin' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('origin')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('origin'))}>
            {m.search_col_source()}{sortIndicator('origin')}
          </th>
          <th class="sortable col-sources" role="columnheader" aria-sort={sortField === 'sources' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('sources')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('sources'))}>
            {m.search_col_sources()}{sortIndicator('sources')}
          </th>
          {#if columnVis.complete}
            <th class="sortable col-complete" role="columnheader" aria-sort={sortField === 'complete' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('complete')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('complete'))}>
              {m.search_col_complete_sources()}{sortIndicator('complete')}
            </th>
          {/if}
          {#if columnVis.length}
            <th class="sortable col-length" role="columnheader" aria-sort={sortField === 'length' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('length')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('length'))}>
              {m.search_col_length()}{sortIndicator('length')}
            </th>
          {/if}
          {#if columnVis.bitrate}
            <th class="sortable col-bitrate" role="columnheader" aria-sort={sortField === 'bitrate' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('bitrate')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('bitrate'))}>
              {m.search_col_bitrate()}{sortIndicator('bitrate')}
            </th>
          {/if}
          {#if columnVis.codec}
            <th class="sortable col-codec" role="columnheader" aria-sort={sortField === 'codec' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('codec')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('codec'))}>
              {m.search_col_codec()}{sortIndicator('codec')}
            </th>
          {/if}
          {#if columnVis.artist}
            <th class="sortable col-artist" role="columnheader" aria-sort={sortField === 'artist' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('artist')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('artist'))}>
              {m.search_col_artist()}{sortIndicator('artist')}
            </th>
          {/if}
          {#if columnVis.album}
            <th class="sortable col-album" role="columnheader" aria-sort={sortField === 'album' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('album')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('album'))}>
              {m.search_col_album()}{sortIndicator('album')}
            </th>
          {/if}
          {#if columnVis.title}
            <th class="sortable col-title" role="columnheader" aria-sort={sortField === 'title' ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'} tabindex="0" onclick={() => toggleSort('title')} onkeydown={(e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), toggleSort('title'))}>
              {m.search_col_title()}{sortIndicator('title')}
            </th>
          {/if}
          <th class="col-history">{m.search_th_history()}</th>
          <th class="col-action" aria-label={m.search_th_actions_aria()}></th>
        </tr>
      </thead>
      <tbody title={m.search_double_click_hint()}>
        {#each filteredResults as result, idx (resultKey(result))}
          {@const rKey = resultKey(result)}
          {@const dlTransfer = getDownloadTransfer(result)}
          {@const blockingDl = getBlockingDownloadTransfer(result)}
          {@const originText = originLabel(result.result_origin || '')}
          {@const spamExplain = spamExplainFor(result)}
          <tr
            class="{dlRowClass(dlTransfer)}"
            class:spam-row={result.is_spam}
            class:row-checked={checkedKeys.has(rKey)}
            class:in-library-row={isInLibraryOnly(result)}
            class:history-completed-row={!isInLibraryOnly(result) && downloadHistoryMap[result.file.hash] === 'completed'}
            class:history-cancelled-row={!isInLibraryOnly(result) && downloadHistoryMap[result.file.hash] === 'cancelled'}
            oncontextmenu={(e) => showContextMenu(e, result)}
            ondblclick={() => { if (!blockingDl) download(result); }}
          >
            <td class="col-check">
              <input
                type="checkbox"
                checked={checkedKeys.has(rKey)}
                onclick={(e) => { e.stopPropagation(); toggleCheck(rKey, idx, e.shiftKey); }}
                aria-label={m.search_select_result({ name: displayName(result) })}
              />
            </td>
            <td class="col-name" title={displayName(result)}>
              <div class="name-cell-wrap">
                <button class="ghost link-btn" onclick={() => showFileDetails(result)}><bdi dir="auto">{displayName(result)}</bdi></button>
                {#if dlTransfer}
                  <span class="dl-status-badge {dlBadgeClass(dlTransfer)}" title="{dlBadgeLabel(dlTransfer)}: {dlTransfer.file_name}">
                    {dlBadgeLabel(dlTransfer)}
                  </span>
                {/if}
                {#if result.is_spam}
                  <div class="spam-flag-wrap">
                    <button
                      class="spam-flag-btn"
                      type="button"
                      aria-label={m.search_show_spam_reason()}
                      onclick={() => openSpamTooltip(result)}
                      onfocus={() => openSpamTooltip(result)}
                      onmouseenter={() => openSpamTooltip(result)}
                      onmouseleave={closeSpamTooltip}
                      onblur={closeSpamTooltip}
                    >
                      {m.search_spam_label()}
                    </button>
                    {#if spamTooltipKey === resultKey(result)}
                      <div class="spam-tooltip" role="tooltip">
                        {#if spamExplainPending[resultKey(result)]}
                          <div class="spam-tooltip-title">{m.search_spam_evaluating()}</div>
                        {:else if spamExplainErrors[resultKey(result)]}
                          <div class="spam-tooltip-title">{spamExplainErrors[resultKey(result)]}</div>
                        {:else if spamExplain}
                          <div class="spam-tooltip-title">
                            {m.search_spam_score({ score: spamExplain.score, threshold: spamExplain.threshold, profile: spamExplain.profile })}
                          </div>
                          <ul>
                            {#each spamExplain.reasons.slice(0, 4) as reason}
                              <li>{reason}</li>
                            {/each}
                          </ul>
                        {/if}
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            </td>
            <td class="col-size">{formatSize(result.file.size)}</td>
            <td class="col-type">{resultTypeLabel(result) || result.file.extension || '\u2014'}</td>
            <td class="col-origin" title={originText}>{originText || '\u2014'}</td>
            <td class="col-sources">
              <span class="source-count" class:high-sources={result.availability >= 10}>
                {result.availability}
              </span>
            </td>
            {#if columnVis.complete}
              <td class="col-complete">{result.file.complete_sources ? result.file.complete_sources : '\u2014'}</td>
            {/if}
            {#if columnVis.length}
              <td class="col-length">{result.media?.duration ? formatMediaLength(result.media.duration) : '\u2014'}</td>
            {/if}
            {#if columnVis.bitrate}
              <td class="col-bitrate">{result.media?.bitrate ? m.search_bitrate_value({ kbps: result.media.bitrate }) : '\u2014'}</td>
            {/if}
            {#if columnVis.codec}
              <td class="col-codec" title={result.media?.codec || ''}>{result.media?.codec || '\u2014'}</td>
            {/if}
            {#if columnVis.artist}
              <td class="col-artist" title={result.media?.artist || ''}>{result.media?.artist || '\u2014'}</td>
            {/if}
            {#if columnVis.album}
              <td class="col-album" title={result.media?.album || ''}>{result.media?.album || '\u2014'}</td>
            {/if}
            {#if columnVis.title}
              <td class="col-title" title={result.media?.title || ''}>{result.media?.title || '\u2014'}</td>
            {/if}
            <td class="col-history">
              {#if isInLibraryOnly(result)}
                <span class="history-badge in-library" title={m.search_history_in_library_title()}>{m.search_history_in_library()}</span>
              {:else if downloadHistoryMap[result.file.hash] === 'completed'}
                <span class="history-badge history-completed" title={m.search_history_downloaded_title()}>{m.search_history_downloaded()}</span>
              {:else if downloadHistoryMap[result.file.hash] === 'cancelled'}
                <span class="history-badge history-cancelled" title={m.search_history_cancelled_title()}>{m.search_history_cancelled()}</span>
              {/if}
            </td>
            <td class="col-action">
              <!-- Visible per-row download trigger so the primary
                   action isn't only discoverable via double-click or
                   the right-click menu. Disabled-state mirrors the
                   `download()` function's early-exit checks so the
                   button is faithful to what the action would do. -->
              {#if isInLibraryOnly(result)}
                <button
                  class="row-dl-btn"
                  type="button"
                  disabled
                  title={m.search_action_already_in_library_title()}
                  aria-label={m.search_action_already_in_library_aria({ name: displayName(result) })}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <polyline points="3,8 7,12 13,4"/>
                  </svg>
                </button>
              {:else if blockingDl}
                <button
                  class="row-dl-btn"
                  type="button"
                  disabled
                  title={m.search_action_already_downloading_title()}
                  aria-label={m.search_action_already_downloading_aria({ name: displayName(result) })}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <circle cx="8" cy="8" r="6.5"/>
                    <line x1="8" y1="4.5" x2="8" y2="9"/>
                    <line x1="8" y1="9" x2="11" y2="11"/>
                  </svg>
                </button>
              {:else}
                <button
                  class="row-dl-btn row-dl-btn-active"
                  type="button"
                  onclick={(e) => { e.stopPropagation(); download(result); }}
                  disabled={downloadPending[rKey]}
                  title={m.search_action_download_title()}
                  aria-label={m.search_action_download_aria({ name: displayName(result) })}
                >
                  {#if downloadPending[rKey]}
                    <span class="row-dl-spinner" aria-hidden="true"></span>
                  {:else}
                    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                      <line x1="8" y1="2.5" x2="8" y2="11"/>
                      <polyline points="4.5,7.5 8,11 11.5,7.5"/>
                      <line x1="3" y1="13.5" x2="13" y2="13.5"/>
                    </svg>
                  {/if}
                </button>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if filteredResults.length === 0 && visibleResults.length > 0}
      <div class="empty-state">
        <p>{m.search_no_results_filters()}</p>
        <button class="ghost" onclick={clearFilters}>{m.library_clear_filters()}</button>
      </div>
    {/if}

    {#if contextMenu}
      <button
        type="button"
        class="context-menu-backdrop"
        aria-label={m.search_close_context_menu()}
        onclick={closeContextMenu}
        oncontextmenu={(e) => { e.preventDefault(); closeContextMenu(); }}
      ></button>
      <div class="context-menu" role="menu" style="left: {contextMenu.x}px; top: {contextMenu.y}px;">
        <button role="menuitem" onclick={() => { if (contextMenu) handleMarkSpam(contextMenu.result); }}>{m.search_mark_spam()}</button>
        <button role="menuitem" onclick={() => { if (contextMenu) handleMarkNotSpam(contextMenu.result); }}>{m.search_mark_not_spam()}</button>
        <button
          role="menuitem"
          disabled={isInLibraryOnly(contextMenu.result) || !!getBlockingDownloadTransfer(contextMenu.result)}
          title={isInLibraryOnly(contextMenu.result)
            ? m.search_action_already_in_library_title()
            : getBlockingDownloadTransfer(contextMenu.result) ? m.search_action_already_downloading_title() : undefined}
          onclick={() => { if (contextMenu) download(contextMenu.result); closeContextMenu(); }}
        >{m.search_ctx_download()}</button>
        {#if checkedCount > 1}
          <button role="menuitem" onclick={() => { downloadChecked(); closeContextMenu(); }}>{m.search_ctx_download_selected({ count: checkedCount })}</button>
        {/if}
        <button role="menuitem" onclick={() => { if (contextMenu) void copyResultLink(contextMenu.result); closeContextMenu(); }}>{m.search_ctx_copy_link()}</button>
        {#if checkedCount > 1}
          <button role="menuitem" onclick={() => { copyCheckedLinks(); closeContextMenu(); }}>{m.search_ctx_copy_selected_links({ count: checkedCount })}</button>
        {/if}
        <button role="menuitem" onclick={() => { if (contextMenu) showFileDetails(contextMenu.result); closeContextMenu(); }}>{m.search_ctx_details()}</button>
        {#if downloadHistoryMap[contextMenu.result.file.hash]}
          <button
            role="menuitem"
            onclick={() => { if (contextMenu) handleRemoveFromHistory(contextMenu.result); }}
            title={m.search_remove_from_history_title({ status: historyStatusLabel(downloadHistoryMap[contextMenu.result.file.hash]) })}
          >
            {m.search_remove_from_history({ status: historyStatusLabel(downloadHistoryMap[contextMenu.result.file.hash]) })}
          </button>
        {/if}
      </div>
    {/if}
    {#if selectedResult}
      <div class="file-details-panel scroll-shadows">
        <div class="panel-header">
          <h3>{m.search_file_details()}</h3>
          <button type="button" class="panel-close" title={m.search_close_details_aria()} aria-label={m.search_close_details_aria()} onclick={() => { selectedResultKey = null; notesRequestId += 1; loadingNotes = false; spamExplainLoading = false; spamExplainError = null; }}>
            <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
              <line x1="3.5" y1="3.5" x2="10.5" y2="10.5"/>
              <line x1="10.5" y1="3.5" x2="3.5" y2="10.5"/>
            </svg>
          </button>
        </div>
        <div class="panel-body">
          <div class="detail-row"><strong>{m.search_detail_name()}</strong> <bdi dir="auto">{displayName(selectedResult)}</bdi></div>
          <div class="detail-row"><strong>{m.search_detail_size()}</strong> {formatSize(selectedResult.file.size)}</div>
          <div class="detail-row"><strong>{m.search_detail_hash()}</strong> <code>{selectedResult.file.hash}</code></div>
          <div class="detail-row"><strong>{m.search_detail_sources()}</strong> {selectedResult.availability}</div>
          {#if selectedResult.media}
            {#if selectedResult.media.duration}
              <div class="detail-row"><strong>{m.search_detail_duration()}</strong> {formatMediaLength(selectedResult.media.duration)}</div>
            {/if}
            {#if selectedResult.media.bitrate}
              <div class="detail-row"><strong>{m.search_detail_bitrate()}</strong> {m.search_bitrate_value({ kbps: selectedResult.media.bitrate })}</div>
            {/if}
            {#if selectedResult.media.codec}
              <div class="detail-row"><strong>{m.search_detail_codec()}</strong> <bdi dir="auto">{selectedResult.media.codec}</bdi></div>
            {/if}
            {#if selectedResult.media.artist}
              <div class="detail-row"><strong>{m.search_detail_artist()}</strong> <bdi dir="auto">{selectedResult.media.artist}</bdi></div>
            {/if}
            {#if selectedResult.media.album}
              <div class="detail-row"><strong>{m.search_detail_album()}</strong> <bdi dir="auto">{selectedResult.media.album}</bdi></div>
            {/if}
            {#if selectedResult.media.title}
              <div class="detail-row"><strong>{m.search_detail_title()}</strong> <bdi dir="auto">{selectedResult.media.title}</bdi></div>
            {/if}
          {/if}
          <div class="detail-row">
            <strong>{m.search_detail_spam_score()}</strong>
            {#if spamExplainLoading}
              {m.search_evaluating()}
            {:else if selectedSpam}
              {selectedSpam.score}/{selectedSpam.threshold}
              {#if selectedSpam.is_spam}
                <span class="spam-chip">{m.search_spam_flagged({ profile: selectedSpam.profile })}</span>
              {:else}
                <span class="ham-chip">{m.search_spam_not_flagged({ profile: selectedSpam.profile })}</span>
              {/if}
            {:else}
              {selectedResult.spam_rating}
            {/if}
          </div>
          {#if spamExplainError}
            <div class="detail-row"><span class="error-msg">{spamExplainError}</span></div>
          {:else if selectedSpam}
            <div class="detail-row">
              <strong>{m.search_spam_signals()}</strong>
              <ul class="spam-reasons">
                {#each selectedSpam.reasons as reason}
                  <li>{reason}</li>
                {/each}
              </ul>
            </div>
          {/if}
          {#if selectedResult.result_origin}
            <div class="detail-row"><strong>{m.search_hit_origin()}</strong> {originLabel(selectedResult.result_origin)}</div>
          {/if}
          {#if selectedDlTransfer}
            <div class="detail-section-dl">
              <h4>{m.search_download_status()}</h4>
              <div class="detail-row">
                <strong>{m.search_status_label()}</strong>
                <span class="dl-status-badge {dlBadgeClass(selectedDlTransfer)}">{dlBadgeLabel(selectedDlTransfer)}</span>
              </div>
              {#if selectedDlTransfer.status === 'active' || selectedDlTransfer.progress > 0}
                <div class="detail-row"><strong>{m.search_progress_label()}</strong> {m.search_progress_value({ percent: selectedDlTransfer.progress.toFixed(1), transferred: formatSize(selectedDlTransfer.transferred), total: formatSize(selectedDlTransfer.total_size) })}</div>
              {/if}
              {#if selectedDlTransfer.status === 'active' || selectedDlTransfer.speed > 0}
                <div class="detail-row"><strong>{m.search_speed_label()}</strong> {selectedDlTransfer.speed > 0 ? formatSpeed(selectedDlTransfer.speed) : '—'}</div>
              {/if}
              {#if selectedDlTransfer.sources > 0}
                <div class="detail-row"><strong>{m.search_sources_label()}</strong> {m.search_sources_value({ active: selectedDlTransfer.active_sources || 0, total: selectedDlTransfer.sources })}</div>
              {/if}
              {#if selectedDlTransfer.failure_reason}
                <div class="detail-row"><strong>{m.search_error_label()}</strong> <span class="error-msg">{selectedDlTransfer.failure_reason}</span></div>
              {/if}
            </div>
          {/if}

          <h4>{m.search_notes_comments()}</h4>
          {#if loadingNotes}
            <p class="hint">{m.search_loading_notes()}</p>
          {:else if notesError}
            <p class="error-msg">{notesError}</p>
          {:else if notes.length === 0}
            <p class="hint">{m.search_no_notes()}</p>
          {:else}
            <div class="notes-list">
              {#each notes as note (note)}
                <div class="note-item">
                  <span class="note-peer"><bdi dir="auto">{note.peer_name || m.search_note_anonymous()}</bdi></span>
                  {#if note.rating}
                    {@const r = Math.round(Math.max(0, Math.min(5, note.rating ?? 0)))}
                    <span class="note-rating">{'★'.repeat(r)}{'☆'.repeat(5 - r)}</span>
                  {/if}
                  {#if note.comment}
                    <span class="note-comment"><bdi dir="auto">{note.comment}</bdi></span>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
          
          <div class="publish-note">
            <h4>{m.search_add_note()}</h4>
            <div class="note-form">
              <label for="note-rating">{m.search_rating_label()}</label>
              <input id="note-rating" type="number" min="0" max="5" bind:value={noteRating} />
              <label for="note-comment">{m.search_comment_label()}</label>
              <input id="note-comment" type="text" maxlength="4096" bind:value={noteComment} placeholder={m.search_comment_placeholder()} />
              <button onclick={handlePublishNote} disabled={publishingNote}>{publishingNote ? m.search_publishing() : m.search_publish_note()}</button>
              {#if publishMessage}
                <span class={publishSuccess ? 'success-msg' : 'error-msg'}>{publishMessage}</span>
              {/if}
            </div>
          </div>
        </div>
      </div>
    {/if}
  {/if}
</div>

<ConfirmDialog
  bind:open={confirmOpen}
  title={confirmTitle}
  message={confirmMessage}
  confirmLabel={pendingConfirm?.kind === 'close-tab'
    ? m.search_confirm_close_tab_btn()
    : pendingConfirm?.kind === 'copy-all-links'
      ? m.search_copy_all_confirm_btn()
      : m.search_confirm_clear_btn()}
  cancelLabel={m.search_confirm_keep()}
  danger={pendingConfirm?.kind !== 'copy-all-links'}
  onconfirm={handleConfirm}
  oncancel={handleConfirmCancel}
/>

<ConfirmDialog
  bind:open={networkAlertOpen}
  alert
  title={m.search_no_network_title()}
  message={searchNetworkAlertMessage(searchMethod)}
  confirmLabel={m.common_ok()}
/>

<style>
  .search-area {
    display: flex;
    gap: 12px;
    padding: 14px 20px 12px;
    align-items: stretch;
    background: var(--bg-secondary);
    flex-wrap: wrap;
  }

  .search-area :global(.search-bar-wrap) {
    flex: 1 1 420px;
    min-width: 260px;
  }

  .type-select {
    padding: 7px 28px 7px 10px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background-color: var(--bg-surface);
    color: var(--text-secondary);
    flex-shrink: 0;
    cursor: pointer;
  }

  .type-select:focus {
    border-color: var(--accent);
    outline: none;
  }

  .search-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    padding: 8px 20px 10px;
    align-items: center;
    border-bottom: 1px solid var(--border);
    overflow-x: auto;
    background: linear-gradient(to bottom, color-mix(in srgb, var(--bg-secondary) 88%, transparent), transparent);
  }

  .search-tab {
    display: flex;
    align-items: stretch;
    max-width: min(240px, 100%);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-surface);
    overflow: hidden;
    flex-shrink: 0;
    box-shadow: var(--shadow-sm);
    transition: transform 0.12s ease, box-shadow 0.15s ease, border-color 0.15s ease, background-color 0.15s ease;
  }

  .search-tab:hover {
    transform: translateY(-1px);
    border-color: var(--border-light);
    box-shadow: var(--shadow-md);
    background: var(--bg-secondary);
  }

  .search-tab.active {
    border-color: var(--accent);
    background: var(--bg-secondary);
    box-shadow: 0 0 0 1px color-mix(in srgb, var(--accent) 30%, transparent), var(--shadow-md);
  }

  .search-tab-select {
    display: flex;
    align-items: center;
    gap: 6px;
    flex: 1;
    min-width: 0;
    padding: 7px 6px 7px 11px;
    border: none;
    background: transparent;
    color: var(--text-primary);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    text-align: left;
  }

  .search-tab-select:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
    border-radius: 0;
  }

  .search-tab-select:hover {
    background: var(--bg-hover);
  }

  .search-tab.active .search-tab-select {
    font-weight: 600;
  }

  .search-tab-label {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .search-tab-meta {
    font-size: 11px;
    color: var(--text-muted);
    background: color-mix(in srgb, var(--bg-hover) 78%, var(--bg-secondary));
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    padding: 1px 7px;
    line-height: 1.3;
    flex-shrink: 0;
  }

  .search-tab.active .search-tab-meta {
    color: var(--text-accent);
    border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    background: color-mix(in srgb, var(--accent-dim) 58%, transparent);
  }

  .search-tab-spinner {
    width: 11px;
    height: 11px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    flex-shrink: 0;
    animation: search-tab-spin 0.7s linear infinite;
  }

  @keyframes search-tab-spin {
    to {
      transform: rotate(360deg);
    }
  }

  .search-tab-actions {
    display: flex;
    align-items: center;
    gap: 2px;
    padding: 4px 5px 4px 4px;
    border-left: 1px solid var(--border);
    flex-shrink: 0;
    background: color-mix(in srgb, var(--bg-tertiary) 35%, transparent);
  }

  .search-tab.active .search-tab-actions {
    background: color-mix(in srgb, var(--accent-dim) 28%, transparent);
  }

  .search-tab-action {
    width: 24px;
    height: 24px;
    padding: 0;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-secondary);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    flex-shrink: 0;
    transition:
      color 0.14s ease,
      background-color 0.14s ease,
      transform 0.1s ease;
  }

  .search-tab-action:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }

  .search-tab-action:active {
    transform: scale(0.94);
  }

  .search-tab-stop {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .search-tab-stop:hover,
  .search-tab-stop:focus-visible {
    color: var(--on-danger);
    background: var(--danger);
    outline-color: var(--danger);
  }

  .search-tab-close:hover,
  .search-tab-close:focus-visible {
    color: #ffffff;
    background: var(--danger);
    outline-color: var(--danger);
  }

  @media (max-width: 760px) {
    .search-tabs {
      gap: 6px;
      padding: 8px 12px 10px;
    }

    .search-tab {
      max-width: min(200px, 100%);
    }
  }

  .filter-bar {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 20px 14px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(to bottom, var(--bg-secondary), color-mix(in srgb, var(--bg-secondary) 70%, var(--bg-primary)));
  }

  .filter-primary-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px 12px;
    align-items: flex-end;
  }

  .filter-advanced-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px 12px;
    align-items: flex-end;
    border-top: 1px dashed var(--border);
    padding-top: 10px;
  }

  .filter-text-group {
    min-width: 260px;
    max-width: 620px;
    flex: 1 1 360px;
  }

  .filter-text-wrap {
    display: flex;
    align-items: center;
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    overflow: hidden;
    background: var(--bg-surface);
    transition: border-color 0.15s;
    min-height: 34px;
  }

  .filter-text-wrap:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-halo);
  }

  .column-select {
    background-color: var(--bg-input);
    font-size: 12px;
    padding: 6px 28px 6px 8px;
    min-width: 110px;
    color: var(--text-secondary);
  }

  .filter-text-input {
    flex: 1;
    border: none;
    outline: none;
    box-shadow: none;
    font-size: 13px;
    padding: 5px 8px;
    background: transparent;
    color: var(--text-primary);
    min-width: 0;
  }

  .filter-text-input::placeholder {
    color: var(--text-muted);
  }

  .filter-text-clear {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 22px;
    height: 22px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--text-secondary);
    cursor: pointer;
    line-height: 1;
    flex-shrink: 0;
  }

  .filter-text-clear:hover {
    color: var(--text-primary);
    background: var(--bg-hover);
  }

  .filter-group {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .filter-group label {
    font-size: 11px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }

  .filter-group select,
  .filter-group input {
    font-size: 13px;
    padding: 6px 8px;
    min-width: 0;
  }

  .filter-group select {
    min-width: 100px;
    padding-right: 28px;
  }

  .size-input {
    display: flex;
    gap: 4px;
  }

  .size-input input {
    width: 72px;
  }

  .size-input select {
    min-width: 72px;
  }

  .ext-input {
    width: 80px;
  }

  .sources-input {
    width: 64px;
  }

  .clear-filters {
    font-size: 12px;
    padding: 6px 12px;
  }

  .advanced-toggle {
    font-size: 12px;
    padding: 6px 12px;
  }

  .filter-help {
    margin-top: 4px;
    font-size: 11px;
    color: var(--text-muted);
  }

  .filter-help code {
    font-family: var(--font-mono);
    font-size: 10px;
    background: var(--bg-hover);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0 4px;
  }

  .search-syntax-hint {
    margin: 0;
    padding: 0 20px 12px;
    font-size: 11px;
    color: var(--text-muted);
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
  }

  .results-info {
    padding: 10px 20px;
    font-size: 12px;
    color: var(--text-secondary);
    border-bottom: 1px solid var(--border);
    background: var(--bg-secondary);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .clear-results-btn {
    font-size: 12px;
    padding: 4px 10px;
  }

  .results-info-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .column-menu {
    position: relative;
  }

  .column-menu-summary {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    padding: 4px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--bg-surface);
    color: var(--text-secondary);
    cursor: pointer;
    list-style: none;
    user-select: none;
  }

  .column-menu-summary::-webkit-details-marker {
    display: none;
  }

  .column-menu-summary:hover {
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .column-menu[open] .column-menu-summary {
    border-color: var(--accent);
    color: var(--text-primary);
  }

  .column-menu-panel {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    z-index: 9999;
    min-width: 180px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: var(--shadow-md);
    padding: 6px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .column-menu-item {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 6px 8px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    color: var(--text-primary);
    cursor: pointer;
  }

  .column-menu-item:hover {
    background: var(--bg-hover);
  }

  .column-menu-item input[type="checkbox"] {
    margin: 0;
    cursor: pointer;
  }

  .bulk-actions {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 20px;
    background: color-mix(in srgb, var(--accent-dim) 30%, var(--bg-secondary));
    border-bottom: 1px solid color-mix(in srgb, var(--accent) 40%, var(--border));
  }

  .bulk-count {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-accent);
  }

  .bulk-download-btn {
    padding: 5px 14px;
    font-size: 12px;
    font-weight: 600;
    border: none;
    border-radius: var(--radius-md);
    background: var(--accent);
    color: var(--on-accent);
    cursor: pointer;
    transition: opacity 0.15s;
  }

  .bulk-download-btn:hover:not(:disabled) {
    opacity: 0.88;
  }

  .bulk-download-btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  .bulk-clear-btn,
  .bulk-copy-btn {
    font-size: 12px;
    padding: 5px 10px;
  }

  .copy-links-btn {
    font-size: 12px;
    padding: 4px 10px;
  }

  .copy-links-btn:disabled,
  .bulk-copy-btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
  }

  :global(tr.row-checked td) {
    background: color-mix(in srgb, var(--accent-dim) 25%, transparent) !important;
  }

  .col-check {
    width: 32px;
    text-align: center;
    padding-left: 6px !important;
    padding-right: 2px !important;
  }

  .col-check input[type="checkbox"] {
    margin: 0;
    cursor: pointer;
  }

  .col-name {
    width: 42%;
    max-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .col-size {
    width: 10%;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }

  .col-type {
    width: 9%;
  }

  .col-origin {
    width: 12%;
    max-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .col-sources {
    width: 7%;
    text-align: center;
    font-variant-numeric: tabular-nums;
  }

  .col-history {
    width: 10%;
    text-align: center;
  }

  .col-action {
    width: 36px;
    text-align: center;
    padding: 0 4px;
  }

  .col-complete {
    width: 7%;
    text-align: center;
    font-variant-numeric: tabular-nums;
  }

  .col-length,
  .col-bitrate {
    width: 8%;
    text-align: right;
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }

  .col-codec {
    width: 7%;
  }

  .col-artist,
  .col-album,
  .col-title {
    width: 11%;
    max-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 12px;
    color: var(--text-secondary);
  }

  .row-dl-btn {
    width: 26px;
    height: 26px;
    padding: 0;
    border: 1px solid transparent;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-muted);
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    transition: background var(--transition-fast), color var(--transition-fast), border-color var(--transition-fast);
  }
  .row-dl-btn :global(svg) {
    width: 14px;
    height: 14px;
  }
  .row-dl-btn-active {
    color: var(--accent);
  }
  .row-dl-btn-active:hover {
    background: color-mix(in srgb, var(--accent) 18%, transparent);
    border-color: color-mix(in srgb, var(--accent) 32%, transparent);
    color: var(--accent);
  }
  .row-dl-btn:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -1px;
  }
  .row-dl-btn:disabled {
    cursor: default;
    opacity: 0.6;
  }
  .row-dl-spinner {
    width: 12px;
    height: 12px;
    border: 2px solid color-mix(in srgb, var(--accent) 30%, transparent);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: row-dl-spin 0.7s linear infinite;
  }
  @keyframes row-dl-spin { to { transform: rotate(360deg); } }
  @media (prefers-reduced-motion: reduce) {
    .row-dl-spinner { animation: none; }
  }

  .history-badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: var(--radius-sm);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.02em;
  }

  .in-library {
    background: color-mix(in srgb, var(--accent) 20%, transparent);
    color: var(--accent);
  }

  .history-completed {
    background: color-mix(in srgb, var(--success) 20%, transparent);
    color: var(--success);
  }

  .history-cancelled {
    background: color-mix(in srgb, var(--warning) 20%, transparent);
    color: var(--warning);
  }

  :global(tr.in-library-row:not(.row-checked):not(:hover) td) {
    color: var(--accent);
  }

  :global(tr.history-cancelled-row:not(.row-checked):not(:hover) td) {
    color: var(--warning);
  }

  .search-results-table th {
    padding: 6px 10px;
    font-size: 12px;
  }

  .search-results-table td {
    padding: 4px 10px;
    font-size: 12px;
    line-height: 1.2;
  }

  .search-results-table tbody tr {
    height: 30px;
    /*
     * Chromium-native virtualization: skips layout/paint for rows that are
     * offscreen, using the intrinsic-size hint to reserve scroll space.
     * Tauri ships with WebView2 (Chromium) on Windows, so this is always
     * available in the app; other engines gracefully fall back to normal
     * rendering. This gives large result sets (thousands of rows) a huge
     * scroll-perf win without fragile manual row windowing.
     */
    content-visibility: auto;
    contain-intrinsic-size: auto 30px;
  }

  th.sortable {
    cursor: pointer;
    user-select: none;
  }

  th.sortable:hover {
    color: var(--text-primary);
  }

  table {
    table-layout: fixed;
  }

  thead th {
    position: sticky;
    top: 0;
    z-index: 2;
    background: var(--bg-secondary);
  }

  tbody tr:nth-child(even) td {
    background: color-mix(in srgb, var(--bg-secondary) 82%, var(--bg-primary));
  }

  .source-count {
    display: inline-block;
    min-width: 22px;
    text-align: center;
    padding: 1px 5px;
    border-radius: var(--radius-pill);
    font-size: 11px;
    font-weight: 600;
    background: var(--bg-hover);
  }

  .source-count.high-sources {
    background: var(--accent-dim);
    color: var(--text-accent);
  }

  .stop-btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: var(--danger);
    color: var(--on-danger);
    border: none;
    border-radius: var(--radius-md);
    padding: 8px 16px 8px 14px;
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
    box-shadow: 0 1px 0 color-mix(in srgb, #000 12%, transparent);
    transition: background-color 0.15s ease, transform 0.1s ease, box-shadow 0.15s ease;
  }

  .stop-btn:hover {
    background: var(--danger-hover);
  }

  .stop-btn:active {
    transform: translateY(1px);
    box-shadow: none;
  }

  .stop-btn:focus-visible {
    outline: 2px solid var(--danger);
    outline-offset: 2px;
  }

  .searching-indicator {
    color: var(--accent);
    font-weight: 600;
    margin-right: 8px;
  }

  @keyframes pulse-opacity {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .searching-indicator {
    animation: pulse-opacity 1.5s ease-in-out infinite;
  }

  .hint, .search-detail {
    font-size: 13px;
    color: var(--text-muted);
  }

  .error-msg {
    color: var(--danger);
    font-size: 11px;
    margin-left: 8px;
  }

  .success-msg {
    color: var(--success);
    font-size: 11px;
    margin-left: 8px;
  }

  .search-readiness-hint {
    padding: 9px 20px;
    font-size: 12px;
    color: var(--badge-warning-text);
    background: color-mix(in srgb, var(--warning) 9%, var(--bg-secondary));
    border-bottom: 1px solid color-mix(in srgb, var(--warning) 36%, var(--border));
  }

  .search-readiness-muted {
    color: var(--text-secondary);
  }

  .search-error-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    font-size: 13px;
  }

  .file-details-panel {
    border-top: 1px solid var(--border);
    background: var(--bg-secondary);
    max-height: 320px;
    overflow-y: auto;
  }

  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--bg-surface);
  }

  .panel-header h3 {
    margin: 0;
    font-size: 14px;
  }

  .panel-close {
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
  }

  .panel-close:hover {
    color: var(--danger);
    border-color: color-mix(in srgb, var(--danger) 35%, var(--border));
    background: color-mix(in srgb, var(--danger) 12%, transparent);
  }

  .panel-body {
    padding: 14px 20px;
  }

  .detail-row {
    font-size: 13px;
    margin-bottom: 6px;
  }

  .detail-row code {
    font-family: var(--font-mono);
    font-size: 12px;
    color: var(--text-muted);
  }

  .detail-section-dl {
    margin-top: 8px;
    padding-top: 6px;
    border-top: 1px solid var(--border);
  }

  .detail-section-dl h4 {
    margin: 0 0 6px;
  }

  .spam-chip,
  .ham-chip {
    display: inline-flex;
    align-items: center;
    margin-left: 8px;
    padding: 1px 8px;
    border-radius: var(--radius-pill);
    font-size: 11px;
    font-weight: 600;
  }

  .spam-chip {
    background: color-mix(in srgb, var(--danger) 16%, transparent);
    color: var(--danger);
  }

  .ham-chip {
    background: color-mix(in srgb, var(--success) 16%, transparent);
    color: var(--success);
  }

  .spam-reasons {
    margin: 6px 0 0 16px;
    display: grid;
    gap: 4px;
    color: var(--text-secondary);
  }

  .notes-list {
    margin: 8px 0;
  }

  .note-item {
    padding: 6px 0;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
    /* Peer-supplied and up to 4096 chars; without this an unbroken run turns
       the details panel into a horizontal scroller. */
    overflow-wrap: anywhere;
  }

  .publish-note {
    margin-top: 12px;
  }

  .publish-note h4 {
    font-size: 13px;
    margin-bottom: 8px;
  }

  .note-form {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }

  .note-form label {
    font-size: 12px;
    color: var(--text-muted);
  }

  .note-form input[type="number"] {
    width: 60px;
  }

  .note-form input[type="text"] {
    flex: 1;
    min-width: 200px;
  }

  .link-btn {
    text-align: left;
    font-size: inherit;
    color: var(--text-primary);
    padding: 0;
    text-decoration: none;
    line-height: 1.15;
    background: transparent;
    cursor: pointer;
  }

  .name-cell-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
  }

  .name-cell-wrap .link-btn {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .spam-flag-wrap {
    position: relative;
    flex-shrink: 0;
    display: inline-flex;
    align-items: center;
  }

  .spam-flag-btn {
    padding: 1px 7px;
    border-radius: var(--radius-pill);
    border: 1px solid color-mix(in srgb, var(--danger) 55%, var(--border));
    background: color-mix(in srgb, var(--danger) 15%, transparent);
    color: var(--danger);
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.02em;
    line-height: 1.5;
  }

  .spam-flag-btn:hover {
    background: color-mix(in srgb, var(--danger) 22%, transparent);
  }

  .spam-tooltip {
    position: absolute;
    top: calc(100% + 6px);
    right: 0;
    z-index: 9999;
    width: min(360px, 70vw);
    padding: 8px 10px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    box-shadow: var(--shadow-md);
    color: var(--text-secondary);
    font-size: 11px;
    line-height: 1.35;
  }

  .spam-tooltip-title {
    color: var(--text-primary);
    font-weight: 600;
    margin-bottom: 5px;
  }

  .spam-tooltip ul {
    margin: 0;
    padding-left: 14px;
    display: grid;
    gap: 3px;
  }

  .link-btn:hover {
    color: var(--text-primary);
    text-decoration: none;
    background: transparent;
  }

  .filter-toggles {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    padding-top: 2px;
  }

  .filter-toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-pill);
    background: var(--bg-surface);
    padding: 5px 10px;
    cursor: pointer;
    user-select: none;
    transition: border-color 0.15s ease, background-color 0.15s ease, color 0.15s ease;
  }

  .filter-toggle:hover {
    border-color: var(--border-light);
    background: var(--bg-hover);
    color: var(--text-primary);
  }

  .filter-toggle:has(input:checked) {
    border-color: color-mix(in srgb, var(--accent) 50%, var(--border));
    background: color-mix(in srgb, var(--accent-dim) 38%, transparent);
    color: var(--text-primary);
  }

  .filter-toggle input[type="checkbox"] {
    margin: 0;
  }

  .filter-count {
    font-size: 11px;
    color: var(--text-muted);
  }

  .filter-help-wrap {
    position: relative;
    display: inline-flex;
    align-items: center;
  }

  .filter-help-icon {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    font-size: 10px;
    font-weight: 700;
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-muted);
    cursor: help;
  }

  .filter-help-icon:hover {
    color: var(--text-primary);
    border-color: var(--border-light);
  }

  .filter-help-popover {
    position: absolute;
    top: calc(100% + 8px);
    right: 0;
    width: min(320px, 72vw);
    z-index: 9999;
    padding: 8px 10px;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-secondary);
    font-size: 11px;
    line-height: 1.35;
    box-shadow: var(--shadow-md);
  }

  /* Spam rows stay faded enough to de-prioritize but don't strike out
     the filename (line-through hurts readability and was the only
     non-color signal — we already have a "Spam" badge in the name
     cell). A left-border accent in the warning hue carries the row's
     status without painting the whole cell. */
  :global(tr.spam-row td) {
    color: var(--text-muted);
  }
  :global(tr.spam-row td:first-child) {
    box-shadow: inset 3px 0 0 0 var(--warning);
  }

  .dl-status-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: var(--radius-sm);
    font-size: 11px;
    font-weight: 500;
    white-space: nowrap;
    line-height: 1.3;
  }
  .dl-badge-success {
    background: color-mix(in srgb, var(--success) 18%, transparent);
    color: var(--success);
  }
  .dl-badge-active {
    background: color-mix(in srgb, var(--accent) 18%, transparent);
    color: var(--accent);
  }
  .dl-badge-progress {
    background: color-mix(in srgb, var(--accent) 12%, transparent);
    color: var(--accent);
  }
  .dl-badge-warning {
    background: color-mix(in srgb, var(--warning) 18%, transparent);
    color: var(--warning);
  }
  .dl-badge-danger {
    background: color-mix(in srgb, var(--danger) 18%, transparent);
    color: var(--danger);
  }
  .dl-badge-neutral {
    background: color-mix(in srgb, var(--text-secondary) 12%, transparent);
    color: var(--text-secondary);
  }

  .row-dl-completed {
    background: color-mix(in srgb, var(--success) 5%, transparent) !important;
  }
  .row-dl-active {
    background: color-mix(in srgb, var(--accent) 5%, transparent) !important;
  }
  .row-dl-queued {
    background: color-mix(in srgb, var(--text-secondary) 4%, transparent) !important;
  }
  .row-dl-failed {
    background: color-mix(in srgb, var(--danger) 5%, transparent) !important;
  }

  .context-menu-backdrop {
    position: fixed;
    inset: 0;
    z-index: 9998;
    padding: 0;
    margin: 0;
    border: none;
    background: transparent;
    cursor: default;
  }
  .context-menu {
    position: fixed;
    z-index: 9999;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 4px;
    min-width: 160px;
    box-shadow: var(--shadow-md);
    transform-origin: top left;
    animation: context-menu-pop 0.12s ease;
  }
  @keyframes context-menu-pop {
    from { opacity: 0; transform: scale(0.97); }
    to { opacity: 1; transform: scale(1); }
  }
  .context-menu button {
    display: block;
    width: 100%;
    padding: 6px 12px;
    background: none;
    border: none;
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 0.85rem;
    text-align: left;
    cursor: pointer;
  }
  .context-menu button:hover {
    background: var(--bg-hover);
  }
  .context-menu button:disabled {
    opacity: 0.5;
    cursor: default;
  }
  .context-menu button:disabled:hover {
    background: none;
  }

  @media (max-width: 1200px) {
    .search-area {
      padding: 10px 14px 8px;
      gap: 8px;
    }

    .filter-text-group {
      min-width: 0;
      max-width: none;
      flex: 1 1 100%;
    }

    .filter-primary-row,
    .filter-advanced-row {
      gap: 8px 10px;
    }
  }

  @media (max-width: 980px) {
    .filter-text-group {
      max-width: none;
    }

    .size-input input,
    .size-input select,
    .ext-input,
    .sources-input {
      width: 100%;
      min-width: 0;
    }

    .size-input {
      display: grid;
      grid-template-columns: 1fr 90px;
    }

    .filter-primary-row,
    .filter-advanced-row {
      align-items: stretch;
    }

    .filter-group {
      flex: 1 1 140px;
      min-width: 0;
    }

    .results-info {
      flex-direction: column;
      align-items: flex-start;
      gap: 8px;
    }

    .file-details-panel {
      max-height: min(280px, 36vh);
    }
  }
</style>
