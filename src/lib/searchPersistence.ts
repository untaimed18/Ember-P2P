/**
 * What a search tab keeps across a reload of the webview.
 *
 * A reload takes the whole module graph with it, and nothing replays a search:
 * the backend streams results and keeps no copy once the request finishes. So a
 * stray reload — and the webview offers one from its own context menu on most
 * of the app — threw away everything the user had searched for, with no way
 * back but running the search again.
 *
 * Its own module rather than a private helper in `stores/search.ts` for the
 * reason `searchOverflow.ts` gives: the store imports `$app/environment`, so a
 * test process cannot load it, and a rule with no test drifts. This one is
 * pure — the storage reads and writes stay in the store.
 */
import type { SearchTab } from '$lib/stores/search';
import type { SearchResult } from '$lib/types';

/** `sessionStorage`, not `localStorage`: a search is something you are in the
 *  middle of, not a preference. It should survive the accident that ends the
 *  page and not outlive the window. */
export const SEARCH_STORAGE_KEY = 'ember.searchTabs.v1';

/** Tabs kept, oldest dropped first. */
export const PERSIST_MAX_TABS = 8;

/**
 * Rows kept per tab. Well past a screenful, and far enough below the 15 000 a
 * tab may hold to keep the payload inside a session-storage quota — restoring
 * the first several hundred rows beats restoring nothing because the write was
 * refused.
 */
export const PERSIST_MAX_RESULTS = 500;

/** Successively smaller row budgets. An over-quota write stores nothing at all,
 *  so retrying smaller is strictly better than failing outright. */
export const PERSIST_RETRY_LIMITS = [PERSIST_MAX_RESULTS, 100, 25];

/**
 * The `requestId` a restored tab carries instead of the one it had.
 *
 * This matters more than it looks. `requestId` is a frontend counter
 * (`newSearchNonce`) that restarts at 1 on every page load, while tabs restored
 * from storage still held ids from before the reload — so the first search
 * after a restore would be handed an id a restored tab already had, and
 * `updateTabByRequestId` matches on exactly that. The new search's results
 * would have streamed into the old tab while the new one sat empty.
 *
 * Zero is unmatchable rather than merely unlikely: `newSearchNonce` only ever
 * returns positive integers, and `validRequestId` rejects anything `<= 0`
 * arriving on an event. A restored tab has no live request, and this is how it
 * says so — the same admission as `isSearching: false`.
 */
export const RESTORED_REQUEST_ID = 0;

export type PersistedSearch = {
  tabs: SearchTab[];
  activeId: string | null;
};

/**
 * Whether a stored row can be used at all.
 *
 * `parsePersistedSearch` checked the tab's shape but never the rows inside it,
 * and every consumer reaches straight through `result.file` — `resultKey` does,
 * and it runs both in `mergeIntoTab`'s index rebuild and in the keyed `{#each}`
 * that renders the table. So one row missing `file`, from hand-edited storage or
 * a `SearchResult` shape change shipped without bumping `SEARCH_STORAGE_KEY`,
 * threw a `TypeError` that took the whole search page down — instead of
 * restoring nothing, which is what this module promises.
 */
function usableRow(row: unknown): row is SearchResult {
  return !!row && typeof row === 'object' && typeof (row as SearchResult).file === 'object'
    && !!(row as SearchResult).file;
}

/** Strip a tab to what is worth storing, and to what survives being stored. */
export function forPersist(tab: SearchTab, limit = PERSIST_MAX_RESULTS): SearchTab {
  return {
    ...tab,
    results: (Array.isArray(tab.results) ? tab.results : []).filter(usableRow).slice(0, limit),
    // A `Map` does not survive JSON, and `mergeIntoTab` rebuilds it from its
    // length check whenever it is missing.
    resultIndex: undefined,
    // The request this tab was streaming is unreachable now: its id belonged to
    // a listener that no longer exists, so no further event will ever arrive
    // for it. Restoring it as still-searching would leave a spinner running
    // against nothing.
    isSearching: false,
    progress: null,
    // And the id itself has to go, or the next search will collide with it.
    // See `RESTORED_REQUEST_ID`.
    requestId: RESTORED_REQUEST_ID,
  };
}

export function buildPersistPayload(
  tabs: SearchTab[],
  activeId: string | null,
  limit = PERSIST_MAX_RESULTS,
): PersistedSearch {
  return {
    tabs: tabs.slice(-PERSIST_MAX_TABS).map((t) => forPersist(t, limit)),
    activeId,
  };
}

/**
 * Read back what was stored.
 *
 * Defensive throughout, as `chatTabs` is: hand-edited or stale-schema storage
 * must not be able to stop the store from hydrating. Anything unrecognisable
 * yields an empty restore rather than an exception.
 */
export function parsePersistedSearch(raw: string | null): PersistedSearch {
  if (!raw) return { tabs: [], activeId: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { tabs: [], activeId: null };
  }
  if (!parsed || typeof parsed !== 'object') return { tabs: [], activeId: null };
  const obj = parsed as { tabs?: unknown; activeId?: unknown };
  const tabs = (Array.isArray(obj.tabs) ? obj.tabs : [])
    .filter(
      (t): t is SearchTab =>
        !!t &&
        typeof t === 'object' &&
        typeof (t as SearchTab).id === 'string' &&
        typeof (t as SearchTab).query === 'string' &&
        Array.isArray((t as SearchTab).results),
    )
    .map((t) => forPersist(t))
    .slice(-PERSIST_MAX_TABS);
  const activeRaw = typeof obj.activeId === 'string' ? obj.activeId : null;
  const activeId =
    activeRaw && tabs.some((t) => t.id === activeRaw) ? activeRaw : tabs[0]?.id ?? null;
  return { tabs, activeId };
}
