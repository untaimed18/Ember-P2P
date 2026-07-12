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
  /**
   * When a retry is in flight (e.g. retryServerSearch), this is the
   * secondary request id used by the backend for the retry. Events
   * with either `requestId` OR `retryRequestId` are routed into this
   * tab, so live progress/results during a retry are not dropped.
   * Cleared when the retry completes.
   */
  retryRequestId: number | null;
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

function mergeResult(existing: SearchResult, incoming: SearchResult): SearchResult {
  const mergedAddresses = Array.from(new Set([...(existing.source_addresses || []), ...(incoming.source_addresses || [])]));
  const combinedAvailability = Math.max(existing.availability || 0, incoming.availability || 0);
  return {
    ...existing,
    ...incoming,
    file: {
      ...existing.file,
      ...incoming.file,
      name: incoming.file.name || existing.file.name,
      size: incoming.file.size ?? existing.file.size,
      hash: incoming.file.hash || existing.file.hash,
      extension: incoming.file.extension || existing.file.extension,
      aich_hash: incoming.file.aich_hash || existing.file.aich_hash,
      complete_sources: Math.max(existing.file.complete_sources || 0, incoming.file.complete_sources || 0),
    },
    peer_id: existing.peer_id || incoming.peer_id,
    peer_name: existing.peer_name || incoming.peer_name,
    availability: Math.max(combinedAvailability, mergedAddresses.length),
    file_type: incoming.file_type || existing.file_type,
    source_addresses: mergedAddresses,
    rating: incoming.rating ?? existing.rating,
    comment: incoming.comment ?? existing.comment,
    // Search channels can disagree or report partial spam evaluation. Treat a
    // positive classification and the highest observed score conservatively;
    // a later unflagged hit must not erase an earlier warning for the same file.
    spam_rating: Math.max(existing.spam_rating ?? 0, incoming.spam_rating ?? 0),
    is_spam: existing.is_spam || incoming.is_spam,
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
  const i = tabs.findIndex((t) => t.requestId === requestId || t.retryRequestId === requestId);
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
 * Attach a secondary request id (e.g. from a retry) to an existing tab so
 * incoming search-result/progress/complete events for that id merge into it.
 */
export function attachRetryRequestId(tabId: string, retryRequestId: number) {
  searchTabs.update((tabs) => {
    const i = tabs.findIndex((t) => t.id === tabId);
    if (i === -1) return tabs;
    const next = [...tabs];
    next[i] = { ...next[i], retryRequestId };
    return next;
  });
}

/** Clear retry routing when the retry completes or is cancelled. */
export function clearRetryRequestId(tabId: string) {
  searchTabs.update((tabs) => {
    const i = tabs.findIndex((t) => t.id === tabId);
    if (i === -1 || tabs[i].retryRequestId == null) return tabs;
    const next = [...tabs];
    // The retry is always the last search phase (it's user-triggered only
    // after the primary search has already finished and reported no/low
    // results), so its completion ends all searching for the tab. Also clear
    // `isSearching`/`progress` here: if the primary's `search-complete` event
    // was ever lost, the completion fallback refuses to fire while a retry is
    // attached, which would otherwise leave the spinner stuck on forever.
    next[i] = { ...next[i], retryRequestId: null, isSearching: false, progress: null };
    return next;
  });
}

/** Start a new search tab and select it. Returns tab id and request id for invoke/searchFiles. */
export function openSearchTab(query: string, method: SearchMethod, fileType?: string, filters?: SearchFilters): { tabId: string; requestId: number } {
  const requestId = newSearchNonce();
  const id = newTabId();
  const tab: SearchTab = {
    id,
    requestId,
    retryRequestId: null,
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
  // The server-retry leg often runs AFTER the primary search has
  // finished (so `isSearching` is already false). Cancel it
  // independently of `isSearching`, otherwise closing the tab would
  // leave the backend retry running and its completion handlers firing
  // against a tab that no longer exists.
  if (tab.retryRequestId != null) {
    try {
      await cancelSearch(tab.retryRequestId);
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
        updateTabByRequestId(tabs, requestId, (t) => {
          const isRetry = t.retryRequestId === requestId;
          const isPrimary = t.requestId === requestId;
          // Only flip isSearching off once both primary and any in-flight
          // retry have finished, so the spinner doesn't disappear between
          // the two phases of a retry-server search.
          const stillRetrying = t.retryRequestId != null && !isRetry;
          const stillPrimary = !isPrimary && t.isSearching;
          const done = !(stillRetrying || stillPrimary);
          return {
            ...t,
            retryRequestId: isRetry ? null : t.retryRequestId,
            isSearching: done ? false : t.isSearching,
            progress: done ? null : t.progress,
          };
        }),
      );
    }));
    registered.push(await listen<{ request_id: number; nodes_contacted: number; results_so_far: number; phase: string }>(
      'search-progress',
      (event) => {
        const requestId = validRequestId(event.payload?.request_id);
        if (requestId === null) return;
        searchTabs.update((tabs) =>
          updateTabByRequestId(tabs, requestId, (t) => {
            // A server retry runs with `isSearching === false` (only
            // `retryRequestId` is set), so it must still accept progress —
            // otherwise retry progress is silently dropped on the floor even
            // though the retry is genuinely in flight and results/complete
            // events for it merge normally.
            if (!t.isSearching && t.retryRequestId !== requestId) return t;
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
  searchTabs.set([]);
  activeSearchTabId.set(null);
}
