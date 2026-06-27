<script lang="ts">
  import SearchBar from '$lib/components/SearchBar.svelte';
  import { searchFiles, cancelSearch, parseEd2kLink, findNotes, publishNote, markSpam, markNotSpam, explainSpamResult, getDownloadHistory, removeDownloadHistoryEntry, type SearchMethod } from '$lib/api/search';
  import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
  import { getSettings } from '$lib/api/settings';
  import { startDownload } from '$lib/api/transfers';
  import { transfers } from '$lib/stores/transfers';
  import type { Transfer } from '$lib/types';
  import {
    activeSearchTabId,
    closeSearchTab,
    mergeSearchResults,
    newSearchNonce,
    openSearchTab,
    patchSearchTabByRequestId,
    attachRetryRequestId,
    clearRetryRequestId,
    searchTabs,
    setActiveSearchTab,
    type SearchTab,
  } from '$lib/stores/search';
  import { networkStats, serverStatus } from '$lib/stores/network';
  import { onDestroy, onMount, untrack } from 'svelte';
  import { get } from 'svelte/store';
  import type { SearchResult, SpamExplanation } from '$lib/types';
  import { formatSize, formatSpeed } from '$lib/utils';
  import { addToast } from '$lib/stores/toast';
  import * as m from '$lib/paraglide/messages';
  import { translateError, degradedReasonText } from '$lib/i18n';

  const searchTimeouts = new Map<number, ReturnType<typeof setTimeout>>();

  let searchMethod: SearchMethod = $state('global');
  let searchFileType: string = $state('');

  let ed2kInput = $state('');
  let ed2kError = $state('');
  let ed2kSuccess = $state('');
  let barQuery = $state('');

  let activeTab = $derived.by(() => {
    const id = $activeSearchTabId;
    if (!id) return null;
    return $searchTabs.find((t) => t.id === id) ?? null;
  });

  let searchResultsList = $derived(activeTab?.results ?? []);

  let downloadHistoryMap = $state<Record<string, string>>({});
  let historyFetchedHashes = new Set<string>();
  let historyPendingHashes = new Set<string>();
  let historyFetchTimer: ReturnType<typeof setTimeout> | null = null;
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

  async function flushHistoryFetch() {
    historyFetchTimer = null;
    if (historyPendingHashes.size === 0) return;
    const batch = [...historyPendingHashes];
    historyPendingHashes.clear();
    const myGen = ++historyFetchGen;
    for (const h of batch) historyHashGen.set(h, myGen);
    try {
      const result = await getDownloadHistory(batch);
      if (destroyed) return;
      // Per-hash freshness check: only apply keys for which our gen
      // is still the most recent dispatch.
      const fresh: Record<string, string> = {};
      for (const [h, status] of Object.entries(result)) {
        if (historyHashGen.get(h) === myGen) {
          fresh[h] = status;
        }
      }
      if (Object.keys(fresh).length > 0) {
        downloadHistoryMap = { ...downloadHistoryMap, ...fresh };
      }
    } catch (e) {
      console.error('Failed to fetch download history:', e);
      // Failed batch — forget the "already fetched" mark so they retry next cycle.
      for (const h of batch) {
        historyFetchedHashes.delete(h);
        // Clear our gen claim too so a future batch can re-attempt
        // without the stale-gen filter rejecting its results.
        if (historyHashGen.get(h) === myGen) historyHashGen.delete(h);
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
    // Coalesce high-frequency streaming updates into a single batched fetch.
    if (historyFetchTimer) return;
    historyFetchTimer = setTimeout(flushHistoryFetch, 250);
  }

  $effect(() => {
    // Touch the list length so the effect re-runs as streaming batches arrive,
    // but do the diffing inside queueHistoryFetch to avoid re-sending known
    // hashes. The actual invoke is debounced.
    const hashes = searchResultsList.map(r => r.file.hash);
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

  // React to downloads finishing while results are on screen: drop the stale
  // "already fetched" mark for the completed file and re-queue, so its
  // completed/cancelled badge appears without a reload. A `completedHandled`
  // guard keeps this from re-firing on every transfers-store tick.
  const completedHandled = new Set<string>();
  // Bound the dedupe set so a very long session with thousands of completed
  // downloads can't grow it without limit. Sets preserve insertion order, so
  // dropping the oldest entry evicts the least-recently-completed hash.
  const COMPLETED_HANDLED_CAP = 2000;
  $effect(() => {
    const list = $transfers;
    if (destroyed) return;
    for (const t of list) {
      if (t.direction !== 'download' || t.status !== 'completed' || !t.file_hash) continue;
      if (completedHandled.has(t.file_hash)) continue;
      completedHandled.add(t.file_hash);
      if (completedHandled.size > COMPLETED_HANDLED_CAP) {
        const oldest = completedHandled.values().next().value;
        if (oldest !== undefined) completedHandled.delete(oldest);
      }
      invalidateHistory(t.file_hash);
      queueHistoryFetch([t.file_hash]);
    }
  });

  // Destructive-action confirmation state. Shared by "Clear Results" and
  // "Close Tab". Skip confirmation for empty / non-destructive cases.
  type ConfirmAction =
    | { kind: 'clear-results' }
    | { kind: 'close-tab'; tab: SearchTab };
  let pendingConfirm: ConfirmAction | null = $state(null);
  let confirmOpen = $state(false);
  let confirmTitle = $state('');
  let confirmMessage = $state('');

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
  let selectedSpam = $derived.by(() =>
    selectedResult ? spamExplainCache[resultKey(selectedResult)] : undefined
  );
  let notes: SearchResult[] = $state([]);
  let loadingNotes = $state(false);
  let noteRating = $state(0);
  let noteComment = $state('');
  let publishMessage = $state('');
  let publishSuccess = $state(true);
  let spamExplainLoading = $state(false);
  let spamExplainError: string | null = $state(null);
  let spamExplainPending = $state<Record<string, boolean>>({});
  let spamExplainErrors = $state<Record<string, string>>({});
  let spamTooltipKey = $state<string | null>(null);
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
  let filterMinSize = $state('');
  let filterMinUnit = $state(1024 * 1024);
  let filterMaxSize = $state('');
  let filterMaxUnit = $state(1024 * 1024 * 1024);
  let filterExtension = $state('');
  let filterMinSources = $state('');
  // Client-side "complete sources" minimum. Unlike Min Sources (sent to the
  // remote node as a FT_SOURCES constraint), there is no standard eD2k search
  // tag for complete-source counts, so this filters the results we already
  // received (the count arrives on each hit as `file.complete_sources`).
  let filterMinComplete = $state('');
  let hideSpam = $state(true);
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
  let spamProfile = $state<'relaxed' | 'balanced' | 'aggressive'>('balanced');
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
    for (const t of searchTimeouts.values()) clearTimeout(t);
    searchTimeouts.clear();
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
    const displayName = result.clean_name || result.file.name;
    switch (column) {
      case 'name': return displayName;
      case 'size': return formatSize(result.file.size);
      case 'type': return result.file_type || result.file.extension || '';
      case 'sources': return String(result.availability);
      case 'origin': return result.result_origin || '';
      case 'hash': return result.file.hash;
      case 'all':
        return [
          displayName,
          formatSize(result.file.size),
          result.file_type || result.file.extension || '',
          String(result.availability),
          result.result_origin || '',
          result.file.hash,
        ].join(' ');
    }
  }

  function isFilteredByText(result: SearchResult): boolean {
    if (!filterText.trim()) return false;

    const tokens = filterText.trim().split(/\s+/).filter(t => t !== '' && t !== '-');
    if (tokens.length === 0) return false;

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
  const VALID_SEARCH_METHODS = new Set<SearchMethod>(['global', 'kad', 'server']);
  const VALID_FILTER_COLUMNS = new Set<FilterColumn>([
    'name', 'size', 'type', 'sources', 'origin', 'hash', 'all',
  ]);
  const VALID_SORT_FIELDS = new Set<SortField>([
    'name', 'size', 'type', 'sources', 'origin',
    'length', 'bitrate', 'codec', 'artist', 'album', 'title', 'complete',
  ]);
  const VALID_SIZE_UNITS = new Set<number>(SIZE_UNITS.map((u) => u.value));
  const VALID_FILE_TYPES = new Set<string>(FILE_TYPES.map((t) => t.value));
  let prefsRestored = false;

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
        filterType = p.filterType;
      }
      if (typeof p.filterColumn === 'string' && VALID_FILTER_COLUMNS.has(p.filterColumn as FilterColumn)) {
        filterColumn = p.filterColumn as FilterColumn;
      }
      if (typeof p.filterExtension === 'string' && p.filterExtension.length <= 16) {
        filterExtension = p.filterExtension;
      }
      if (typeof p.filterMinSize === 'string' && p.filterMinSize.length <= 24) {
        filterMinSize = p.filterMinSize;
      }
      if (typeof p.filterMaxSize === 'string' && p.filterMaxSize.length <= 24) {
        filterMaxSize = p.filterMaxSize;
      }
      if (typeof p.filterMinUnit === 'number' && VALID_SIZE_UNITS.has(p.filterMinUnit)) {
        filterMinUnit = p.filterMinUnit;
      }
      if (typeof p.filterMaxUnit === 'number' && VALID_SIZE_UNITS.has(p.filterMaxUnit)) {
        filterMaxUnit = p.filterMaxUnit;
      }
      if (typeof p.filterMinSources === 'string' && p.filterMinSources.length <= 8) {
        filterMinSources = p.filterMinSources;
      }
      if (typeof p.filterMinComplete === 'string' && p.filterMinComplete.length <= 8) {
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
    return `nohash:${result.result_origin}:${result.file.name}:${result.file.size}`;
  }

  function inferSearchTypeFromExtension(extension: string | null | undefined): string {
    const ext = (extension ?? '').toLowerCase();
    if (['mp3', 'ogg', 'wav', 'flac', 'aac', 'm4a', 'wma', 'opus'].includes(ext)) return 'Audio';
    if (['avi', 'mkv', 'mp4', 'wmv', 'mov', 'mpeg', 'mpg', 'webm', 'flv'].includes(ext)) return 'Video';
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp'].includes(ext)) return 'Image';
    if (['exe', 'msi', 'apk', 'app', 'deb', 'rpm', 'scr'].includes(ext)) return 'Pro';
    if (['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return 'Doc';
    if (['zip', 'rar', '7z', 'tar', 'gz', 'ace'].includes(ext)) return 'Arc';
    if (['iso', 'bin', 'cue', 'mdf', 'nrg', 'img'].includes(ext)) return 'Iso';
    return '';
  }

  function resultType(result: SearchResult): string {
    return result.file_type || inferSearchTypeFromExtension(result.file.extension);
  }

  let searchTimeoutSecs = $state(120);

  onMount(() => {
    loadPersistedPrefs();
    prefsRestored = true;
    getSettings()
      .then((s) => {
        searchTimeoutSecs = s.search_timeout_secs;
        spamProfile = s.spam_filter_profile ?? 'balanced';
      })
      .catch(() => {});
  });
  let spamHiddenCount = $derived(searchResultsList.filter(r => r.is_spam).length);
  let spamThreshold = $derived(spamProfile === 'aggressive' ? 45 : spamProfile === 'relaxed' ? 80 : 60);

  let serverHintDismissedTabs = $state(new Set<string>());
  let serverRetryPending = $state(false);

  function hasServerOrigin(r: SearchResult): boolean {
    return (r.result_origin || '').includes('Server');
  }

  let serverNoResultsHint = $derived.by(() => {
    if (!activeTab || activeTab.isSearching) return null;
    if (serverHintDismissedTabs.has(activeTab.id)) return null;
    const method = activeTab.method;
    if (method !== 'global' && method !== 'server') return null;
    if (searchResultsList.some(hasServerOrigin)) return null;
    const srvConnected = $serverStatus === 'connected';
    if (method === 'server') {
      if (!srvConnected) return m.search_hint_not_connected();
      return searchResultsList.length === 0
        ? m.search_hint_server_empty_only()
        : m.search_hint_server_empty_mixed();
    }
    if (searchResultsList.length > 0 && srvConnected) {
      return m.search_hint_server_empty_global();
    }
    return null;
  });

  let serverRetryAllowed = $derived(
    !!serverNoResultsHint && $serverStatus === 'connected' && !serverRetryPending
  );

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

  async function retryServerSearch() {
    if (!activeTab || serverRetryPending || $serverStatus !== 'connected') return;
    const tabQuery = activeTab.query;
    const tabId = activeTab.id;
    if (!tabQuery.trim() && !hasSearchFilters(activeTab.filters, activeTab.fileType || undefined)) return;
    serverRetryPending = true;
    // Keep the tab's canonical requestId unchanged so late streaming events
    // for the original search still land in the correct tab. The retry runs
    // under its own nonce; we attach it as the tab's secondary request id so
    // search-results / search-progress / search-complete events for the retry
    // merge into this tab live, and the backend's cancel path still works if
    // the user closes the tab mid-retry.
    const retryRequestId = newSearchNonce();
    attachRetryRequestId(tabId, retryRequestId);
    let retryTimeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const results = await Promise.race([
        searchFiles(tabQuery, 'server', retryRequestId, activeTab.fileType || undefined, activeTab.filters),
        new Promise<never>((_, reject) => {
          retryTimeout = setTimeout(() => reject(new Error(m.search_retry_timeout())), 60_000);
        }),
      ]);
      // Bail out if the user stopped this retry or closed the tab while the
      // invoke was in flight: the backend resolves `search_files` with
      // partial results on cancel (it sends on the oneshot rather than
      // rejecting), so without this guard a stopped/closed retry would still
      // merge rows and flash a "server returned N" toast. `stopSearch()` and
      // `closeSearchTab()` both detach the retry id, so a mismatch (or a
      // missing tab) means this result is stale.
      const liveTab = get(searchTabs).find((t) => t.id === tabId);
      if (!liveTab || liveTab.retryRequestId !== retryRequestId) {
        return;
      }
      if (results && results.length > 0) {
        searchTabs.update((tabs) => tabs.map((t) => (
          t.id === tabId
            ? { ...t, results: mergeSearchResults(t.results, results) }
            : t
        )));
        addToast('success', results.length === 1 ? m.search_server_returned_one() : m.search_server_returned_other({ count: results.length }));
      } else {
        addToast('info', m.search_server_no_results_retry());
      }
    } catch (e: unknown) {
      // Suppress the error toast too when the retry was stopped/closed
      // mid-flight (e.g. cancel surfaced as a rejected invoke).
      const liveTab = get(searchTabs).find((t) => t.id === tabId);
      if (!liveTab || liveTab.retryRequestId !== retryRequestId) {
        return;
      }
      const msg = translateError(e, m.search_retry_failed());
      addToast('error', msg);
    } finally {
      // Clear the watchdog so the loser timer doesn't keep running (and can't
      // fire a late rejection) after the search resolves first.
      if (retryTimeout) clearTimeout(retryTimeout);
      clearRetryRequestId(tabId);
      serverRetryPending = false;
    }
  }

  const DL_STATUS_PRIORITY: Record<string, number> = {
    active: 6, verifying: 5, completing: 5, hashing: 5,
    queued: 4, searching: 4, paused: 3, stopped: 2, completed: 1, failed: 0,
  };

  let downloadsByHash = $derived.by(() => {
    const map = new Map<string, Transfer>();
    for (const t of $transfers) {
      if (t.direction === 'download' && t.file_hash) {
        const existing = map.get(t.file_hash);
        if (!existing || (DL_STATUS_PRIORITY[t.status] ?? 0) > (DL_STATUS_PRIORITY[existing.status] ?? 0)) {
          map.set(t.file_hash, t);
        }
      }
    }
    return map;
  });

  function getDownloadTransfer(result: SearchResult): Transfer | undefined {
    return downloadsByHash.get(result.file.hash);
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
      default: return t.status;
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

  let filteredResults: SearchResult[] = $derived.by(() => {
    // Single-pass filter: the previous implementation chained up to 8
    // `.filter()` calls, each allocating a fresh array. On a busy search
    // the store ships new `searchResultsList` snapshots dozens of times
    // a second, so a result set of several thousand rows meant we
    // allocated tens of thousands of short-lived intermediate entries
    // per second just to get to the sort. Collapsing the predicates and
    // pre-parsing the filter inputs once keeps the hot path allocation-
    // light and cuts the re-derive cost roughly proportionally to the
    // number of active filters.
    const ext = filterExtension.trim().toLowerCase().replace(/^\./, '');
    const hasExt = ext.length > 0;
    const minParsed = filterMinSize !== '' ? parseFloat(filterMinSize) * filterMinUnit : NaN;
    const minBytes = Number.isFinite(minParsed) && minParsed > 0 ? minParsed : 0;
    const maxParsed = filterMaxSize !== '' ? parseFloat(filterMaxSize) * filterMaxUnit : NaN;
    const maxBytes = Number.isFinite(maxParsed) && maxParsed > 0 ? maxParsed : 0;
    const minSrcParsed = filterMinSources !== '' ? parseInt(filterMinSources, 10) : NaN;
    const minSrc = Number.isFinite(minSrcParsed) && minSrcParsed > 0 ? minSrcParsed : 0;
    const minCompleteParsed = filterMinComplete !== '' ? parseInt(filterMinComplete, 10) : NaN;
    const minComplete = Number.isFinite(minCompleteParsed) && minCompleteParsed > 0 ? minCompleteParsed : 0;
    const hasType = !!filterType;
    const spamHidden = hideSpam;

    const out: SearchResult[] = [];
    for (const r of searchResultsList) {
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
          cmp = (a.clean_name || a.file.name).localeCompare(b.clean_name || b.file.name);
          break;
        case 'size':
          cmp = a.file.size - b.file.size;
          break;
        case 'type':
          cmp = resultType(a).localeCompare(resultType(b));
          break;
        case 'sources':
          cmp = a.availability - b.availability;
          break;
        case 'origin':
          cmp = (a.result_origin || '').localeCompare(b.result_origin || '');
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
          cmp = (a.media?.codec ?? '').localeCompare(b.media?.codec ?? '');
          break;
        case 'artist':
          cmp = (a.media?.artist ?? '').localeCompare(b.media?.artist ?? '');
          break;
        case 'album':
          cmp = (a.media?.album ?? '').localeCompare(b.media?.album ?? '');
          break;
        case 'title':
          cmp = (a.media?.title ?? '').localeCompare(b.media?.title ?? '');
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return out;
  });

  let allFilteredChecked = $derived(
    filteredResults.length > 0 && filteredResults.every((r) => checkedKeys.has(resultKey(r)))
  );
  let someFilteredChecked = $derived(
    filteredResults.some((r) => checkedKeys.has(resultKey(r)))
  );
  // Keep the checked set confined to currently-visible results. A row can
  // be checked and then hidden by a filter change; without this the bulk
  // toolbar would count it ("N selected") while `downloadChecked` — which
  // only iterates `filteredResults` — would silently skip it, so the count
  // overstated what actually downloads. Reconciling to the visible set
  // (as the transfers page does for its selection) keeps `checkedCount`
  // and the bulk action in agreement. `untrack` so writing `checkedKeys`
  // here doesn't retrigger this effect.
  $effect(() => {
    const visible = new Set(filteredResults.map((r) => resultKey(r)));
    untrack(() => {
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

  // Grace period after the backend confirms a search finished (the
  // `search_files` invoke resolved) during which we still expect the
  // `search-complete` event to flip `isSearching` off. If that event is
  // ever dropped on the IPC bridge the spinner would spin forever, so this
  // fallback clears it — but only when no retry phase is still running
  // (the retry path owns the spinner until its own completion).
  const SEARCH_COMPLETE_GRACE_MS = 5000;

  function armSearchCompletionFallback(requestId: number) {
    clearSearchTimeoutForRequest(requestId);
    searchTimeouts.set(
      requestId,
      setTimeout(() => {
        searchTimeouts.delete(requestId);
        patchSearchTabByRequestId(requestId, (tab) => {
          if (!tab.isSearching || tab.retryRequestId != null) return tab;
          return { ...tab, isSearching: false, progress: null };
        });
      }, SEARCH_COMPLETE_GRACE_MS),
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
    const q = query.trim();
    const method = searchMethod;
    filterType = searchFileType;
    const parsedMinSize = filterMinSize !== '' ? parseFloat(filterMinSize) * filterMinUnit : undefined;
    const parsedMaxSize = filterMaxSize !== '' ? parseFloat(filterMaxSize) * filterMaxUnit : undefined;
    const parsedMinAvail = filterMinSources !== '' ? parseInt(filterMinSources, 10) : undefined;
    const searchFilterSnapshot: import('$lib/api/search').SearchFilters = {
      fileExtension: filterExtension.trim() || undefined,
      minSize: parsedMinSize !== undefined && !isNaN(parsedMinSize) ? parsedMinSize : undefined,
      maxSize: parsedMaxSize !== undefined && !isNaN(parsedMaxSize) ? parsedMaxSize : undefined,
      minAvailability: parsedMinAvail !== undefined && !isNaN(parsedMinAvail) ? parsedMinAvail : undefined,
    };
    if (!q && !hasSearchFilters(searchFilterSnapshot, searchFileType || undefined)) return;
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
          patchSearchTabByRequestId(requestId, (tab) => {
            if (!tab.isSearching) return tab;
            return {
              ...tab,
              isSearching: false,
              progress: null,
              error: m.search_timeout_error({ secs }),
            };
          });
        }, secs * 1000),
      );
    };
    armTimeout(timeoutSec);

    getSettings()
      .then((s) => {
        if (!searchTimeouts.has(requestId)) return; // search already finished
        if (s.search_timeout_secs !== timeoutSec) {
          timeoutSec = s.search_timeout_secs;
          searchTimeoutSecs = timeoutSec;
          armTimeout(timeoutSec);
        }
        spamProfile = s.spam_filter_profile ?? 'balanced';
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
      clearSearchTimeoutForRequest(requestId);
      if (!get(searchTabs).some((t) => t.requestId === requestId)) {
        return;
      }
      if (results && results.length > 0) {
        patchSearchTabByRequestId(requestId, (tab) => ({
          ...tab,
          results: mergeSearchResults(tab.results, results),
        }));
      }
      armSearchCompletionFallback(requestId);
    } catch (e: unknown) {
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
    }
  }

  async function stopSearch() {
    const t = activeTab;
    if (!t) return;
    // Nothing to stop if neither the primary search nor a server retry
    // is in flight.
    if (!t.isSearching && t.retryRequestId == null) return;
    const retryRequestId = t.retryRequestId;
    // Detach the retry routing and clear the page-local "retrying" flag
    // synchronously, BEFORE awaiting the cancel round-trips. The in-flight
    // `retryServerSearch()` promise guards on the tab still carrying its
    // retry id, so clearing it here ensures a stopped retry can't merge late
    // results or flash a toast once `search_files` resolves on cancel.
    if (retryRequestId != null) {
      clearRetryRequestId(t.id);
      serverRetryPending = false;
    }
    if (t.isSearching) {
      clearSearchTimeoutForRequest(t.requestId);
      try {
        await cancelSearch(t.requestId);
      } catch (e) {
        console.error('Failed to cancel search:', e);
      }
    }
    // The server-retry leg can still be running after the primary
    // search completed (isSearching === false); cancel it too so Stop
    // actually stops all backend work for this tab.
    if (retryRequestId != null) {
      try {
        await cancelSearch(retryRequestId);
      } catch (e) {
        console.error('Failed to cancel server retry:', e);
      }
    }
    patchSearchTabByRequestId(t.requestId, (tab) => ({
      ...tab,
      isSearching: false,
      progress: null,
    }));
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
    noteRating = 0;
    noteComment = '';
    publishMessage = '';
    const requestId = ++notesRequestId;
    const fileHash = result.file.hash;
    const key = resultKey(result);
    const keywords = (activeTab?.query ?? '').split(/\s+/).filter((w) => w.length > 0);

    // Load notes and spam explanation independently so one slow request
    // does not block the other from rendering in the details panel.
    void (async () => {
      try {
        const loadedNotes = await findNotes(result.file.hash, result.file.size);
        if (!selectedResult || selectedResult.file.hash !== fileHash || requestId !== notesRequestId) return;
        notes = loadedNotes;
      } catch (e: unknown) {
        console.error('Failed to load notes:', e);
      } finally {
        if (requestId === notesRequestId && selectedResult?.file.hash === fileHash) {
          loadingNotes = false;
        }
      }
    })();

    void (async () => {
      try {
        const cached = spamExplainCache[key];
        if (cached) return;
        const explain = await explainSpamResult(
          result.file.hash,
          result.file.name,
          result.file.size,
          result.source_addresses,
          keywords,
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

  function currentSearchKeywords(): string[] {
    return (activeTab?.query ?? '').split(/\s+/).filter((w) => w.length > 0);
  }

  async function ensureSpamExplanation(result: SearchResult): Promise<void> {
    const key = resultKey(result);
    if (spamExplainCache[key] || spamExplainPending[key]) return;
    spamExplainPending[key] = true;
    delete spamExplainErrors[key];
    try {
      const explain = await explainSpamResult(
        result.file.hash,
        result.file.name,
        result.file.size,
        result.source_addresses,
        currentSearchKeywords(),
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
    try {
      publishMessage = await publishNote(
        selectedResult.file.hash,
        noteRating,
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

    const networkAddresses = (result.source_addresses ?? []).filter(
      (a) => a && a !== 'local'
    );

    if (networkAddresses.length === 0 && result.result_origin?.includes('Local')) {
      addToast('info', m.search_already_in_library());
      return;
    }

    if (networkAddresses.length === 0 && !result.file.hash) {
      addToast('error', m.search_no_sources());
      return;
    }

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
        result.file.name,
        result.file.size,
        peerIp,
        peerPort,
        extraSources
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

  async function handleEd2kLink() {
    const link = ed2kInput.trim();
    if (!link) return;
    ed2kError = '';
    ed2kSuccess = '';
    try {
      const info = await parseEd2kLink(link);
      const res = await startDownload(info.hash, info.name, info.size, '', 0);
      ed2kSuccess = res.already_queued ? m.search_already_queued_name({ name: info.name }) : m.search_queued_name({ name: info.name });
      ed2kInput = '';
      safeTimeout(() => (ed2kSuccess = ''), 5000);
    } catch (e: unknown) {
      ed2kError = translateError(e, m.search_invalid_ed2k());
      safeTimeout(() => (ed2kError = ''), 5000);
    }
  }

  function clearFilters() {
    filterType = '';
    filterMinSize = '';
    filterMaxSize = '';
    filterExtension = '';
    filterMinSources = '';
    filterMinComplete = '';
    filterColumn = 'all';
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

  async function handleMarkSpam(result: SearchResult) {
    const keywords = (activeTab?.query ?? '').split(/\s+/).filter(w => w.length > 0);
    try {
      await markSpam(result.file.hash, result.file.name, result.file.size, result.source_addresses, keywords);
      searchTabs.update((tabs) =>
        tabs.map((t) => ({
          ...t,
          results: t.results.map((r) =>
            r.file.hash === result.file.hash ? { ...r, is_spam: true, spam_rating: spamThreshold } : r
          ),
        }))
      );
      const key = resultKey(result);
      delete spamExplainCache[key];
      delete spamExplainErrors[key];
      spamExplainPending[key] = false;
    } catch (e) {
      console.error('Failed to mark spam:', e);
      addToast('error', m.search_failed_mark_spam());
    }
    contextMenu = null;
  }

  async function handleMarkNotSpam(result: SearchResult) {
    try {
      await markNotSpam(result.file.hash);
      searchTabs.update((tabs) =>
        tabs.map((t) => ({
          ...t,
          results: t.results.map((r) =>
            r.file.hash === result.file.hash ? { ...r, is_spam: false, spam_rating: 0 } : r
          ),
        }))
      );
      const key = resultKey(result);
      delete spamExplainCache[key];
      delete spamExplainErrors[key];
      spamExplainPending[key] = false;
    } catch (e) {
      console.error('Failed to unmark spam:', e);
      addToast('error', m.search_failed_unmark_spam());
    }
    contextMenu = null;
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
      downloadHistoryMap = Object.fromEntries(
        Object.entries(downloadHistoryMap).filter(([k]) => k !== hash),
      );
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
    searchTabs.update((tabs) => tabs.map((t) => (t.id === tabId ? { ...t, results: [], error: null } : t)));
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
  }

  function handleConfirm() {
    const action = pendingConfirm;
    pendingConfirm = null;
    if (!action) return;
    if (action.kind === 'clear-results') {
      performClearResults();
    } else if (action.kind === 'close-tab') {
      void performCloseSearchTab(action.tab);
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

  async function downloadChecked() {
    if (bulkDownloadPending || checkedKeys.size === 0) return;
    bulkDownloadPending = true;
    bulkDownloadMessage = '';
    bulkDownloadHasFailures = false;
    const toDownload = filteredResults.filter((r) => checkedKeys.has(resultKey(r)));

    let queued = 0;
    let failed = 0;
    let skippedLocal = 0;
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
        if (networkAddrs.length === 0 && result.result_origin?.includes('Local')) {
          skippedLocal++;
          continue;
        }
        if (networkAddrs.length === 0 && !result.file.hash) {
          failed++;
          failures.push(m.search_bulk_no_sources({ name: result.file.name }));
          continue;
        }
        try {
          const { ip: peerIp, port: peerPort } = pickInitialSource(networkAddrs);
          // Same bulk-seed treatment as the single-row download path
          // — pass the rest of the search hit's addresses so the
          // multi-source manager can fan out in parallel.
          const primaryAddr = peerIp && peerPort > 0 ? `${peerIp}:${peerPort}` : '';
          const extraSources = primaryAddr
            ? networkAddrs.filter((addr) => addr !== primaryAddr)
            : networkAddrs.slice();
          await startDownload(
            result.file.hash,
            result.file.name,
            result.file.size,
            peerIp,
            peerPort,
            extraSources
          );
          queued++;
        } catch (e) {
          failed++;
          const msg = translateError(e, m.search_bulk_download_failed());
          failures.push(`${result.file.name}: ${msg}`);
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
    filterMinSize !== '' ||
    filterMaxSize !== '' ||
    filterExtension !== '' ||
    filterMinSources !== '' ||
    filterMinComplete !== '' ||
    filterText !== ''
  );

  // The visible result count and the raw search count can differ for
  // two reasons that aren't covered by `hasActiveFilters`: the spam
  // filter (`hideSpam`) and local-only entries that the pipeline always
  // drops. When they differ, the "(filtered from N)" suffix should show
  // even if no explicit filter chip is set, so the user understands why
  // the table isn't showing the headline number.
  let resultsHidden = $derived(searchResultsList.length - filteredResults.length);

  let advancedFilterCount = $derived(
    (filterColumn !== 'all' && filterText !== '' ? 1 : 0) +
    (filterMinSize !== '' ? 1 : 0) +
    (filterMaxSize !== '' ? 1 : 0) +
    (filterExtension !== '' ? 1 : 0) +
    (filterMinSources !== '' ? 1 : 0) +
    (filterMinComplete !== '' ? 1 : 0)
  );

</script>

<svelte:document onkeydown={(e) => {
  if (e.key === 'Escape') {
    if (contextMenu) { closeContextMenu(); e.preventDefault(); }
    else if (selectedResultKey) { selectedResultKey = null; e.preventDefault(); }
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
  />
  <select class="type-select" bind:value={searchMethod} title={m.search_method_title()}>
    <option value="global">{m.search_method_global()}</option>
    <option value="kad">{m.search_method_kad_only()}</option>
    <option value="server">{m.search_method_server_only()}</option>
  </select>
  <select class="type-select" bind:value={searchFileType} title={m.search_filter_by_filetype()}>
    {#each FILE_TYPES as ft}
      <option value={ft.value}>{ft.label}</option>
    {/each}
  </select>
  {#if activeTab?.isSearching || activeTab?.retryRequestId != null}
    <!-- Also show Stop while a server retry is in flight (isSearching is
         false then, but retryRequestId is set) so the user can cancel it;
         stopSearch already cancels the retry leg. -->
    <button class="stop-btn" onclick={stopSearch}>{m.common_stop()}</button>
  {:else}
    <button onclick={() => handleSearch(barQuery)}>{m.search_title()}</button>
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
        <button
          type="button"
          class="search-tab-close"
          onclick={() => requestCloseSearchTab(tab)}
          title={m.search_close_tab()}
          aria-label={m.search_close_tab_aria()}
        >
          <svg viewBox="0 0 14 14" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
            <line x1="3.5" y1="3.5" x2="10.5" y2="10.5"/>
            <line x1="10.5" y1="3.5" x2="3.5" y2="10.5"/>
          </svg>
        </button>
      </div>
    {/each}
  </div>
{/if}

<div class="ed2k-bar">
  <input
    type="text"
    placeholder={m.search_ed2k_placeholder()}
    bind:value={ed2kInput}
    onkeydown={(e) => { if (e.key === 'Enter') handleEd2kLink(); }}
    aria-label={m.search_ed2k_aria()}
  />
  <button onclick={handleEd2kLink} disabled={!ed2kInput.trim()}>{m.search_add_link()}</button>
  {#if ed2kSuccess}
    <span class="ed2k-success">{ed2kSuccess}</span>
  {/if}
  {#if ed2kError}
    <span class="ed2k-error">{ed2kError}</span>
  {/if}
</div>

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
          <button class="filter-text-clear" onclick={clearFilterText} title={m.search_clear_filter_text()} aria-label={m.search_clear_filter_text()}>
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
              {#if spamHiddenCount > 0}
                {m.search_spam_hidden_count({ count: spamHiddenCount })}
              {:else}
                {m.search_spam_hidden_none()}
              {/if}
              <br />
              {m.search_spam_help_prefix()}
              <strong>{spamThreshold}</strong> {m.search_spam_help_in()} <strong>{spamProfile}</strong> {m.search_spam_help_suffix()}
            </div>
          {/if}
        </span>
      </label>
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
  {#if $networkStats.status === 'disconnected'}
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
  {#if serverNoResultsHint}
    <div class="server-hint-banner" role="status">
      <span>{serverNoResultsHint}</span>
      <div class="server-hint-actions">
        {#if serverRetryAllowed}
          <button class="server-retry-btn" onclick={retryServerSearch}>{m.search_retry_server()}</button>
        {:else if serverRetryPending}
          <button class="server-retry-btn" disabled>{m.search_retrying()}</button>
        {/if}
        <button class="ghost" onclick={() => { if (activeTab?.id) { const next = new Set(serverHintDismissedTabs); next.add(activeTab.id); serverHintDismissedTabs = next; } }}>{m.common_dismiss()}</button>
      </div>
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
  {:else if activeTab?.isSearching && searchResultsList.length === 0}
    <div class="empty-state">
      <p>{m.search_searching_network()}</p>
      {#if activeTab.progress}
        <p class="search-detail">
          {m.search_contacted_nodes({ count: activeTab.progress.nodes_contacted })}
          {#if activeTab.progress.results_so_far > 0}
            &middot; {m.search_results_so_far({ count: activeTab.progress.results_so_far })}
          {/if}
          &middot; {activeTab.progress.phase}
        </p>
      {/if}
    </div>
  {:else if searchResultsList.length === 0 && !activeTab?.isSearching}
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
          {filteredResults.length === 1 ? m.search_showing_one() : m.search_showing_other({ count: filteredResults.length })}{#if resultsHidden > 0} {m.search_filtered_from({ total: searchResultsList.length })}{/if}
        {:else if searchResultsList.length > 0}
          {searchResultsList.length === 1 ? m.search_zero_of_one({ what: hasActiveFilters ? m.search_filters_word() : m.search_visibility_rules_word() }) : m.search_zero_of_other({ count: searchResultsList.length, what: hasActiveFilters ? m.search_filters_word() : m.search_visibility_rules_word() })}
        {:else}
          {m.search_zero_results()}
        {/if}
      </span>
      <div class="results-info-actions">
        <details class="column-menu" bind:open={showColumnMenu}>
          <summary class="column-menu-summary" title={m.search_columns_aria()}>
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
        <button class="ghost clear-results-btn" onclick={requestClearResults}>{m.search_clear_results()}</button>
      </div>
    </div>
    {#if checkedCount > 0}
      <div class="bulk-actions" role="toolbar" aria-label={m.search_bulk_actions_aria()}>
        <span class="bulk-count">{m.search_bulk_selected({ count: checkedCount })}</span>
        <button class="bulk-download-btn" onclick={downloadChecked} disabled={bulkDownloadPending}>
          {bulkDownloadPending ? m.search_downloading_ellipsis() : (checkedCount === 1 ? m.search_bulk_download_one() : m.search_bulk_download_other({ count: checkedCount }))}
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
              checked={allFilteredChecked}
              indeterminate={someFilteredChecked && !allFilteredChecked}
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
          <tr
            class="{dlRowClass(dlTransfer)}"
            class:spam-row={result.is_spam}
            class:row-checked={checkedKeys.has(rKey)}
            class:in-library-row={result.result_origin?.includes('Local')}
            class:history-completed-row={!result.result_origin?.includes('Local') && downloadHistoryMap[result.file.hash] === 'completed'}
            class:history-cancelled-row={!result.result_origin?.includes('Local') && downloadHistoryMap[result.file.hash] === 'cancelled'}
            oncontextmenu={(e) => showContextMenu(e, result)}
            ondblclick={() => download(result)}
          >
            <td class="col-check">
              <input
                type="checkbox"
                checked={checkedKeys.has(rKey)}
                onclick={(e) => { e.stopPropagation(); toggleCheck(rKey, idx, e.shiftKey); }}
                aria-label={m.search_select_result({ name: result.clean_name || result.file.name })}
              />
            </td>
            <td class="col-name" title={result.file.name}>
              <div class="name-cell-wrap">
                <button class="ghost link-btn" onclick={() => showFileDetails(result)}>{result.clean_name || result.file.name}</button>
                {#if dlTransfer}
                  <span class="dl-status-badge {dlBadgeClass(dlTransfer)}" title="{dlTransfer.status}: {dlTransfer.file_name}">
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
                        {:else if spamExplainCache[resultKey(result)]}
                          <div class="spam-tooltip-title">
                            {m.search_spam_score({ score: spamExplainCache[resultKey(result)].score, threshold: spamExplainCache[resultKey(result)].threshold, profile: spamExplainCache[resultKey(result)].profile })}
                          </div>
                          <ul>
                            {#each spamExplainCache[resultKey(result)].reasons.slice(0, 4) as reason}
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
            <td class="col-type">{resultType(result) || result.file.extension || '\u2014'}</td>
            <td class="col-origin" title={result.result_origin || ''}>{result.result_origin || '\u2014'}</td>
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
                  aria-label={m.search_action_already_in_library_aria({ name: result.clean_name || result.file.name })}
                >
                  <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <polyline points="3,8 7,12 13,4"/>
                  </svg>
                </button>
              {:else if dlTransfer}
                <button
                  class="row-dl-btn"
                  type="button"
                  disabled
                  title={m.search_action_already_downloading_title()}
                  aria-label={m.search_action_already_downloading_aria({ name: result.clean_name || result.file.name })}
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
                  aria-label={m.search_action_download_aria({ name: result.clean_name || result.file.name })}
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
    {#if filteredResults.length === 0 && searchResultsList.length > 0}
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
        {#if contextMenu.result.is_spam}
          <button role="menuitem" onclick={() => { if (contextMenu) handleMarkNotSpam(contextMenu.result); }}>{m.search_mark_not_spam()}</button>
        {:else}
          <button role="menuitem" onclick={() => { if (contextMenu) handleMarkSpam(contextMenu.result); }}>{m.search_mark_spam()}</button>
        {/if}
        <button role="menuitem" onclick={() => { if (contextMenu) download(contextMenu.result); closeContextMenu(); }}>{m.search_ctx_download()}</button>
        {#if checkedCount > 1}
          <button role="menuitem" onclick={() => { downloadChecked(); closeContextMenu(); }}>{m.search_ctx_download_selected({ count: checkedCount })}</button>
        {/if}
        <button role="menuitem" onclick={() => { if (contextMenu) showFileDetails(contextMenu.result); closeContextMenu(); }}>{m.search_ctx_details()}</button>
        {#if downloadHistoryMap[contextMenu.result.file.hash]}
          <button
            role="menuitem"
            onclick={() => { if (contextMenu) handleRemoveFromHistory(contextMenu.result); }}
            title={m.search_remove_from_history_title({ status: downloadHistoryMap[contextMenu.result.file.hash] })}
          >
            {m.search_remove_from_history({ status: downloadHistoryMap[contextMenu.result.file.hash] })}
          </button>
        {/if}
      </div>
    {/if}
    {#if selectedResult}
      <div class="file-details-panel scroll-shadows">
        <div class="panel-header">
          <h3>{m.search_file_details()}</h3>
          <button class="ghost panel-close" aria-label={m.search_close_details_aria()} onclick={() => { selectedResultKey = null; notesRequestId += 1; loadingNotes = false; spamExplainLoading = false; spamExplainError = null; }}>
            <svg viewBox="0 0 14 14" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
              <line x1="3.5" y1="3.5" x2="10.5" y2="10.5"/>
              <line x1="10.5" y1="3.5" x2="3.5" y2="10.5"/>
            </svg>
          </button>
        </div>
        <div class="panel-body">
          <div class="detail-row"><strong>{m.search_detail_name()}</strong> {selectedResult.file.name}</div>
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
              <div class="detail-row"><strong>{m.search_detail_codec()}</strong> {selectedResult.media.codec}</div>
            {/if}
            {#if selectedResult.media.artist}
              <div class="detail-row"><strong>{m.search_detail_artist()}</strong> {selectedResult.media.artist}</div>
            {/if}
            {#if selectedResult.media.album}
              <div class="detail-row"><strong>{m.search_detail_album()}</strong> {selectedResult.media.album}</div>
            {/if}
            {#if selectedResult.media.title}
              <div class="detail-row"><strong>{m.search_detail_title()}</strong> {selectedResult.media.title}</div>
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
            <div class="detail-row"><strong>{m.search_hit_origin()}</strong> {selectedResult.result_origin}</div>
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
          {:else if notes.length === 0}
            <p class="hint">{m.search_no_notes()}</p>
          {:else}
            <div class="notes-list">
              {#each notes as note}
                <div class="note-item">
                  <span class="note-peer">{note.peer_name || m.search_note_anonymous()}</span>
                  {#if note.rating}
                    {@const r = Math.round(Math.max(0, Math.min(5, note.rating ?? 0)))}
                    <span class="note-rating">{'★'.repeat(r)}{'☆'.repeat(5 - r)}</span>
                  {/if}
                  {#if note.comment}
                    <span class="note-comment">{note.comment}</span>
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
              <input id="note-comment" type="text" bind:value={noteComment} placeholder={m.search_comment_placeholder()} />
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
  confirmLabel={pendingConfirm?.kind === 'close-tab' ? m.search_confirm_close_tab_btn() : m.search_confirm_clear_btn()}
  cancelLabel={m.search_confirm_keep()}
  danger={true}
  onconfirm={handleConfirm}
  oncancel={handleConfirmCancel}
/>

<style>
  .search-area {
    display: flex;
    gap: 12px;
    padding: 14px 20px 12px;
    align-items: stretch;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }

  .search-area :global(.search-bar-wrap) {
    flex: 1 1 420px;
    min-width: 260px;
  }

  .type-select {
    padding: 7px 10px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    background: var(--bg-surface);
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
    border-radius: 999px;
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

  .search-tab-close {
    width: 30px;
    padding: 0;
    border: none;
    border-left: 1px solid var(--border);
    background: transparent;
    color: var(--text-muted);
    font-size: 17px;
    line-height: 1;
    cursor: pointer;
    transition: color 0.15s ease, background-color 0.15s ease, opacity 0.12s ease;
    opacity: 0.55;
  }

  .search-tab:hover .search-tab-close,
  .search-tab.active .search-tab-close {
    opacity: 1;
  }

  .search-tab-close:focus-visible {
    outline: 2px solid var(--accent);
    outline-offset: -2px;
  }

  .search-tab-close:hover {
    color: var(--danger, #e74c3c);
    background: var(--bg-hover);
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

  .ed2k-bar {
    display: flex;
    gap: 8px;
    padding: 10px 20px 12px;
    align-items: center;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }

  .ed2k-bar input {
    flex: 1 1 380px;
    min-width: 260px;
    font-family: var(--font-mono);
    font-size: 12px;
    padding: 5px 8px;
  }

  .ed2k-success {
    color: var(--success, #2ecc71);
    font-size: 12px;
    white-space: nowrap;
  }

  .ed2k-error {
    color: var(--danger, #e74c3c);
    font-size: 12px;
    white-space: nowrap;
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
    border-radius: var(--radius-md);
    overflow: hidden;
    background: var(--bg-surface);
    transition: border-color 0.15s;
    min-height: 34px;
  }

  .filter-text-wrap:focus-within {
    border-color: var(--accent);
  }

  .column-select {
    background: var(--bg-input);
    font-size: 12px;
    padding: 6px 8px;
    min-width: 110px;
    color: var(--text-secondary);
  }

  .filter-text-input {
    flex: 1;
    border: none;
    outline: none;
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
    border: none;
    background: none;
    color: var(--text-muted);
    cursor: pointer;
    padding: 4px 8px;
    font-size: 12px;
    line-height: 1;
    flex-shrink: 0;
    border-radius: 0;
  }

  .filter-text-clear:hover {
    color: var(--text-primary);
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
  }

  .size-input {
    display: flex;
    gap: 4px;
  }

  .size-input input {
    width: 72px;
  }

  .size-input select {
    min-width: 56px;
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
    border-radius: 4px;
    padding: 0 4px;
  }

  .search-syntax-hint {
    margin: 6px 2px 0;
    font-size: 11px;
    color: var(--text-muted);
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
    z-index: 50;
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
    color: #fff;
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

  :global([data-theme="dark"]) .bulk-download-btn {
    background: var(--accent-dim);
    color: var(--text-primary);
  }

  .bulk-clear-btn {
    font-size: 12px;
    padding: 5px 10px;
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
    border-radius: var(--radius-sm, 3px);
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.02em;
  }

  .in-library {
    background: color-mix(in srgb, var(--accent, #3b82f6) 20%, transparent);
    color: var(--accent, #3b82f6);
  }

  .history-completed {
    background: color-mix(in srgb, var(--success, #22c55e) 20%, transparent);
    color: var(--success, #22c55e);
  }

  .history-cancelled {
    background: color-mix(in srgb, var(--warning, #f59e0b) 20%, transparent);
    color: var(--warning, #f59e0b);
  }

  :global(tr.in-library-row:not(.row-checked):not(:hover) td) {
    color: var(--accent, #3b82f6);
  }

  :global(tr.history-cancelled-row:not(.row-checked):not(:hover) td) {
    color: var(--warning, #f59e0b);
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
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
    background: var(--bg-hover);
  }

  .source-count.high-sources {
    background: var(--accent-dim);
    color: var(--text-accent);
  }

  .stop-btn {
    background: var(--danger, #e74c3c);
    color: #fff;
    border: none;
    border-radius: var(--radius-md);
    padding: 8px 18px;
    font-weight: 600;
    cursor: pointer;
    flex-shrink: 0;
  }

  .stop-btn:hover {
    opacity: 0.85;
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
    color: var(--success, #2ecc71);
    font-size: 11px;
    margin-left: 8px;
  }

  .search-readiness-hint {
    padding: 9px 20px;
    font-size: 12px;
    color: var(--warning, #c9a227);
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    border-left: 3px solid var(--warning, #c9a227);
  }

  .search-readiness-muted {
    color: var(--text-secondary);
  }

  .search-error-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--danger, #e74c3c);
    border-left: 3px solid var(--danger, #e74c3c);
    color: var(--danger, #e74c3c);
    font-size: 13px;
  }

  .server-hint-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 8px 20px;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--warning, #f39c12);
    border-left: 3px solid var(--warning, #f39c12);
    color: var(--text-secondary, #aaa);
    font-size: 12px;
    line-height: 1.4;
  }

  .server-hint-actions {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-shrink: 0;
  }

  .server-retry-btn {
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid var(--warning, #f39c12);
    border-radius: var(--radius-md);
    background: color-mix(in srgb, var(--warning, #f39c12) 15%, transparent);
    color: var(--warning, #f39c12);
    cursor: pointer;
    transition: background 0.15s, opacity 0.15s;
    white-space: nowrap;
  }

  .server-retry-btn:hover:not(:disabled) {
    background: color-mix(in srgb, var(--warning, #f39c12) 25%, transparent);
  }

  .server-retry-btn:disabled {
    opacity: 0.55;
    cursor: not-allowed;
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
    border-radius: 999px;
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
    border-radius: 999px;
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
    z-index: 30;
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
    border-radius: 999px;
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
    z-index: 35;
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
  :global(tr.spam-row) {
    opacity: 0.7;
  }
  :global(tr.spam-row td:first-child) {
    box-shadow: inset 3px 0 0 0 var(--warning);
  }

  .dl-status-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 500;
    white-space: nowrap;
    line-height: 1.3;
  }
  .dl-badge-success {
    background: color-mix(in srgb, var(--success, #2ecc71) 18%, transparent);
    color: var(--success, #2ecc71);
  }
  .dl-badge-active {
    background: color-mix(in srgb, var(--accent, #3498db) 18%, transparent);
    color: var(--accent, #3498db);
  }
  .dl-badge-progress {
    background: color-mix(in srgb, var(--accent, #3498db) 12%, transparent);
    color: var(--accent, #3498db);
  }
  .dl-badge-warning {
    background: color-mix(in srgb, var(--warning, #f39c12) 18%, transparent);
    color: var(--warning, #f39c12);
  }
  .dl-badge-danger {
    background: color-mix(in srgb, var(--danger, #e74c3c) 18%, transparent);
    color: var(--danger, #e74c3c);
  }
  .dl-badge-neutral {
    background: color-mix(in srgb, var(--text-secondary, #aaa) 12%, transparent);
    color: var(--text-secondary, #aaa);
  }

  .row-dl-completed {
    background: color-mix(in srgb, var(--success, #2ecc71) 5%, transparent) !important;
  }
  .row-dl-active {
    background: color-mix(in srgb, var(--accent, #3498db) 5%, transparent) !important;
  }
  .row-dl-queued {
    background: color-mix(in srgb, var(--text-secondary, #aaa) 4%, transparent) !important;
  }
  .row-dl-failed {
    background: color-mix(in srgb, var(--danger, #e74c3c) 5%, transparent) !important;
  }

  .context-menu-backdrop {
    position: fixed;
    inset: 0;
    z-index: 999;
    padding: 0;
    margin: 0;
    border: none;
    background: transparent;
    cursor: default;
  }
  .context-menu {
    position: fixed;
    z-index: 1000;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 4px 0;
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
    padding: 6px 14px;
    background: none;
    border: none;
    color: var(--text-primary);
    font-size: 0.85rem;
    text-align: left;
    cursor: pointer;
  }
  .context-menu button:hover {
    background: var(--bg-hover);
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

    .results-info {
      flex-direction: column;
      align-items: flex-start;
      gap: 8px;
    }
  }
</style>
