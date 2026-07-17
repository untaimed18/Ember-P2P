import { get, writable } from 'svelte/store';
import { listen } from '@tauri-apps/api/event';
import type { SearchResult } from '$lib/types';
import type { UnlistenFn } from '@tauri-apps/api/event';
import type { SearchMethod, SearchFilters } from '$lib/api/search';
import { cancelSearch } from '$lib/api/search';
import { dev } from '$app/environment';

export type SearchTab = {
  id: string;
  requestId: number;
  query: string;
  method: SearchMethod;
  fileType?: string;
  filters?: SearchFilters;
  results: SearchResult[];
  isSearching: boolean;
  progress: { nodes_contacted: number; results_so_far: number; phase: string } | null;
  error: string | null;
};

export const searchTabs = writable<SearchTab[]>([]);
export const activeSearchTabId = writable<string | null>(null);

let initialized = false;
let unlisteners: UnlistenFn[] = [];
let searchNonce = 0;
// Bumped by `cleanupSearchStore`; see the matching comment in
// `stores/network.ts` for why `initSearchStore` needs to re-check this
// after its async listener registration before adopting the results.
let storeEpoch = 0;

export function newSearchNonce(): number {
  searchNonce += 1;
  return searchNonce;
}

export function currentSearchNonce(): number {
  return searchNonce;
}

function newTabId(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `t-${Date.now()}-${Math.random().toString(36).slice(2, 11)}`;
}

function resultKey(result: SearchResult): string {
  if (result.file.hash) return result.file.hash;
  if (result.file.id?.startsWith('pending:')) return `nohash-id:${result.file.id}`;
  if (result.file.path) return `nohash-path:${result.file.path}`;
  return `nohash:${result.file.name}:${result.file.size}`;
}

function combineOrigin(a: string, b: string): string {
  if (!b || a === b) return a || b;
  if (!a) return b;
  const parts = [...a.split(' · '), ...b.split(' · ')]
    .map((s) => s.trim())
    .filter(Boolean);
  return [...new Set(parts)].sort().join(' · ');
}

/** Per-hash user spam overrides. Honored by mergeResult so stream merges
 * cannot undo an explicit Mark spam / Mark not spam. Cleared on store cleanup. */
const spamUserOverrides = new Map<string, { isSpam: boolean; spamRating: number }>();

function mergeResult(existing: SearchResult, incoming: SearchResult): SearchResult {
  const mergedAddresses = Array.from(new Set([...(existing.source_addresses || []), ...(incoming.source_addresses || [])]));
  // Backend ed2k resights emit absolute noted availability; take max so we do
  // not double-sum. Cross-server summing happens in Rust before the emit.
  // Kad / mixed origins also use max (matches merge.rs).
  const availability = Math.max(
    existing.availability || 0,
    incoming.availability || 0,
    mergedAddresses.length,
  );
  const existingMedia = existing.media || {};
  const incomingMedia = incoming.media || {};
  const media = {
    duration: existingMedia.duration ?? incomingMedia.duration,
    bitrate: existingMedia.bitrate ?? incomingMedia.bitrate,
    codec: existingMedia.codec || incomingMedia.codec,
    artist: existingMedia.artist || incomingMedia.artist,
    album: existingMedia.album || incomingMedia.album,
    title: existingMedia.title || incomingMedia.title,
  };
  const hasMedia = Object.values(media).some((v) => v != null && v !== '');
  const existingName = existing.file.name || '';
  const incomingName = incoming.file.name || '';
  const preferredName =
    incomingName.length > existingName.length ? incomingName : existingName || incomingName;
  const hash = incoming.file.hash || existing.file.hash || '';
  const override = hash ? spamUserOverrides.get(hash) : undefined;
  const spam_rating = override
    ? override.spamRating
    : Math.max(existing.spam_rating ?? 0, incoming.spam_rating ?? 0);
  const is_spam = override
    ? override.isSpam
    // Search channels can disagree or report partial spam evaluation. Treat a
    // positive classification and the highest observed score conservatively;
    // a later unflagged hit must not erase an earlier warning for the same file
    // unless the user explicitly unmarked it (override above).
    : existing.is_spam || incoming.is_spam;
  return {
    ...existing,
    ...incoming,
    file: {
      ...existing.file,
      ...incoming.file,
      name: preferredName,
      size: incoming.file.size ?? existing.file.size,
      hash: incoming.file.hash || existing.file.hash,
      extension: incoming.file.extension || existing.file.extension,
      aich_hash: incoming.file.aich_hash || existing.file.aich_hash,
      complete_sources: Math.max(existing.file.complete_sources || 0, incoming.file.complete_sources || 0),
    },
    peer_id: existing.peer_id || incoming.peer_id,
    peer_name: existing.peer_name || incoming.peer_name,
    availability,
    file_type: incoming.file_type || existing.file_type,
    source_addresses: mergedAddresses,
    rating: incoming.rating ?? existing.rating,
    comment: incoming.comment ?? existing.comment,
    media: hasMedia ? media : existing.media || incoming.media,
    spam_rating,
    is_spam,
    clean_name: incoming.clean_name || existing.clean_name,
    result_origin: combineOrigin(existing.result_origin || '', incoming.result_origin || ''),
  };
}

export function mergeSearchResults(existing: SearchResult[], incoming: SearchResult[]): SearchResult[] {
  const merged = new Map<string, SearchResult>();
  for (const result of existing) {
    merged.set(resultKey(result), result);
  }
  for (const result of incoming) {
    const key = resultKey(result);
    const current = merged.get(key);
    merged.set(key, current ? mergeResult(current, result) : result);
  }
  return [...merged.values()];
}

function updateTabByRequestId(
  tabs: SearchTab[],
  requestId: number,
  fn: (tab: SearchTab) => SearchTab,
): SearchTab[] {
  const i = tabs.findIndex((t) => t.requestId === requestId);
  if (i === -1) return tabs;
  const next = [...tabs];
  next[i] = fn(next[i]);
  return next;
}

/** Update a tab by network request id (for invoke completion / errors). */
export function patchSearchTabByRequestId(requestId: number, fn: (tab: SearchTab) => SearchTab) {
  searchTabs.update((tabs) => updateTabByRequestId(tabs, requestId, fn));
}

/**
 * Patch `is_spam` / `spam_rating` for a file hash across all tabs.
 * Only reallocates tabs/results that actually contain a match.
 * Records a user override so later stream merges cannot undo the choice.
 */
export function patchSpamFlagByHash(fileHash: string, isSpam: boolean, spamRating: number) {
  if (!fileHash) return;
  spamUserOverrides.set(fileHash, { isSpam, spamRating });
  searchTabs.update((tabs) => {
    let anyChanged = false;
    const next = tabs.map((tab) => {
      const idx = tab.results.findIndex((r) => r.file.hash === fileHash);
      if (idx === -1) return tab;
      const current = tab.results[idx];
      if (current.is_spam === isSpam && current.spam_rating === spamRating) return tab;
      anyChanged = true;
      const results = tab.results.slice();
      results[idx] = { ...current, is_spam: isSpam, spam_rating: spamRating };
      return { ...tab, results };
    });
    return anyChanged ? next : tabs;
  });
}

/** Start a new search tab and select it. Returns tab id and request id for invoke/searchFiles. */
export function openSearchTab(query: string, method: SearchMethod, fileType?: string, filters?: SearchFilters): { tabId: string; requestId: number } {
  const requestId = newSearchNonce();
  const id = newTabId();
  const tab: SearchTab = {
    id,
    requestId,
    query,
    method,
    fileType,
    filters,
    results: [],
    isSearching: true,
    progress: null,
    error: null,
  };
  searchTabs.update((tabs) => [...tabs, tab]);
  activeSearchTabId.set(id);
  return { tabId: id, requestId };
}

export function setActiveSearchTab(tabId: string | null) {
  activeSearchTabId.set(tabId);
}

export async function closeSearchTab(tabId: string): Promise<void> {
  const tabs = get(searchTabs);
  const idx = tabs.findIndex((t) => t.id === tabId);
  if (idx === -1) return;
  const tab = tabs[idx];
  if (tab.isSearching) {
    try {
      await cancelSearch(tab.requestId);
    } catch {
      /* best effort */
    }
  }
  const currentTabs = get(searchTabs);
  const currentIdx = currentTabs.findIndex((t) => t.id === tabId);
  if (currentIdx === -1) return;
  const remaining = currentTabs.filter((t) => t.id !== tabId);
  searchTabs.set(remaining);
  const active = get(activeSearchTabId);
  if (active === tabId) {
    const newIdx = Math.max(0, currentIdx - 1);
    activeSearchTabId.set(remaining[newIdx]?.id ?? remaining[0]?.id ?? null);
  }
}

// search-results coalescing buffer + flush scheduling. Hoisted to module
// scope (rather than living inside initSearchStore) so cleanupSearchStore can
// cancel a scheduled flush — otherwise a stale rAF/timeout could merge a
// buffered batch into the tabs we just cleared on teardown/re-init.
const pendingByRequest = new Map<number, SearchResult[]>();
let flushScheduled = false;
let flushRaf: number | null = null;
let flushTimeout: ReturnType<typeof setTimeout> | null = null;

function validRequestId(raw: unknown): number | null {
  return typeof raw === 'number' && Number.isSafeInteger(raw) && raw > 0 ? raw : null;
}

function validCount(raw: unknown): number {
  return typeof raw === 'number' && Number.isFinite(raw) ? Math.max(0, Math.floor(raw)) : 0;
}

function flushSearchResults() {
  flushScheduled = false;
  flushRaf = null;
  flushTimeout = null;
  if (pendingByRequest.size === 0) return;
  // Snapshot-and-clear the buffer up front rather than iterating the live
  // `pendingByRequest` reference and clearing it afterward. Both currently
  // execute back-to-back with no `await` between them, so nothing can slip
  // a new batch in between today — but aliasing instead of snapshotting
  // means any future change that adds an await (or a re-entrant caller)
  // would start silently dropping results. Matches the snapshot pattern
  // `flushProgress` already uses in `stores/transfers.ts`.
  const batch = new Map(pendingByRequest);
  pendingByRequest.clear();
  searchTabs.update((tabs) => {
    let next = tabs;
    for (const [requestId, incoming] of batch) {
      next = updateTabByRequestId(next, requestId, (t) => ({
        ...t,
        results: mergeSearchResults(t.results, incoming),
      }));
    }
    return next;
  });
}

function scheduleFlush() {
  if (flushScheduled) return;
  flushScheduled = true;
  if (typeof requestAnimationFrame === 'function' && typeof document !== 'undefined' && document.visibilityState === 'visible') {
    flushRaf = requestAnimationFrame(flushSearchResults);
  } else {
    // Hidden tab or non-DOM host (SSR / tests): fall back to a macrotask so we
    // still coalesce but don't hang the burst waiting for a visibilitychange
    // that might never come.
    flushTimeout = setTimeout(flushSearchResults, 32);
  }
}

export async function initSearchStore() {
  if (initialized) return;

  initialized = true;
  const myEpoch = storeEpoch;
  const registered: UnlistenFn[] = [];
  try {
    // `search-results` events are coalesced per request id across one
    // animation frame via the module-level `pendingByRequest`/`scheduleFlush`
    // (see above). A global-phase KAD/server search streams dozens of small
    // batches back-to-back; buffering folds them into one merge per tab per
    // frame instead of an O(N·B) rebuild per event.
    registered.push(await listen<{ request_id: number; results: SearchResult[] }>('search-results', (event) => {
      const requestId = validRequestId(event.payload?.request_id);
      if (requestId === null) return;
      const incoming = event.payload.results;
      if (!Array.isArray(incoming)) return;
      if (dev) {
        const origins = new Set(incoming.map((r) => r.result_origin).filter(Boolean));
        if (origins.size > 0) {
          console.debug(`[search-results] req=${requestId} count=${incoming.length} origins=${[...origins].join(', ')}`);
        }
      }
      const existing = pendingByRequest.get(requestId);
      if (existing) {
        // In-place concat beats recreating the array — the buffer is
        // internal, and we clear it at flush time.
        for (const r of incoming) existing.push(r);
      } else {
        pendingByRequest.set(requestId, incoming.slice());
      }
      scheduleFlush();
    }));
    registered.push(await listen<{ request_id: number }>('search-complete', (event) => {
      const requestId = validRequestId(event.payload?.request_id);
      if (requestId === null) return;
      // Flush any buffered `search-results` for this request synchronously
      // before flipping `isSearching` off — otherwise the spinner could
      // disappear while the last batch of results is still queued for the
      // next animation frame, and the UI would briefly show "done with
      // N results" where N is missing the final chunk.
      if (pendingByRequest.has(requestId)) {
        flushSearchResults();
      }
      searchTabs.update((tabs) =>
        updateTabByRequestId(tabs, requestId, (t) => ({
          ...t,
          isSearching: false,
          progress: null,
        })),
      );
    }));
    registered.push(await listen<{ request_id: number; nodes_contacted: number; results_so_far: number; phase: string }>(
      'search-progress',
      (event) => {
        const requestId = validRequestId(event.payload?.request_id);
        if (requestId === null) return;
        searchTabs.update((tabs) =>
          updateTabByRequestId(tabs, requestId, (t) => {
            if (!t.isSearching) return t;
            return {
              ...t,
              progress: {
                nodes_contacted: validCount(event.payload?.nodes_contacted),
                results_so_far: validCount(event.payload?.results_so_far),
                phase: typeof event.payload?.phase === 'string' ? event.payload.phase : '',
              },
            };
          }),
        );
      },
    ));
  } catch (e) {
    for (const u of registered) u();
    initialized = false;
    console.error('Failed to initialize search store listeners:', e);
    throw e;
  }
  if (myEpoch !== storeEpoch) {
    // `cleanupSearchStore` ran while we were still registering (dev HMR
    // remount / rapid re-init). Unlisten what we just added rather than
    // adopting orphaned listeners into an already-torn-down store.
    for (const u of registered) u();
    return;
  }
  unlisteners.push(...registered);
}

export function cleanupSearchStore() {
  storeEpoch++;
  for (const unlisten of unlisteners) unlisten();
  unlisteners = [];
  initialized = false;
  // Cancel any scheduled result flush so a stale rAF/timeout can't merge a
  // buffered batch into the freshly-cleared tabs after teardown/re-init.
  if (flushRaf !== null && typeof cancelAnimationFrame === 'function') cancelAnimationFrame(flushRaf);
  if (flushTimeout !== null) clearTimeout(flushTimeout);
  flushRaf = null;
  flushTimeout = null;
  flushScheduled = false;
  pendingByRequest.clear();
  spamUserOverrides.clear();
  searchTabs.set([]);
  activeSearchTabId.set(null);
}
