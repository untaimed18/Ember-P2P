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
import { shedWeakestRows } from '$lib/searchOverflow';
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
 * (`newSearchNonce`) that used to restart at 1 on every page load, while tabs
 * restored from storage still held ids from before the reload — so the first
 * search after a restore was handed an id a restored tab already had, and
 * `updateTabByRequestId` matches on exactly that. The new search's results
 * streamed into the old tab while the new one sat empty. The counter now
 * starts from the clock, but a restored tab still has no live request.
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

/**
 * The rows worth carrying across a reload, when they don't all fit.
 *
 * Taking the first `limit` kept whichever rows happened to arrive first, which
 * is packet order — so a big search came back with a few hundred arbitrary
 * hits and the well-sourced ones the user was actually looking at were as
 * likely as not among the ones dropped. `shedWeakestRows` is the rule the tab
 * itself uses when it overflows, so a restore now keeps what an overflowing
 * tab would have kept: the best-sourced rows of each network, spam last.
 *
 * Only when they don't all fit, which is the part that matters for what this
 * costs: the shed is three O(n log n) passes, and this runs on the
 * `visibilitychange`→hidden handler — every time the user switches apps — across
 * up to `PERSIST_MAX_TABS` tabs of up to `MAX_TAB_RESULTS` rows each. A tab
 * already inside the budget is stored as-is, the way the plain `.slice()` this
 * replaced was.
 *
 * `filter` has already copied, so the in-place shed cannot touch the live tab.
 * `shed` is how many usable rows the limit left out.
 */
function rowsWorthStoring(raw: unknown, limit: number): { rows: SearchResult[]; shed: number } {
  const rows = (Array.isArray(raw) ? raw : []).filter(usableRow);
  const usable = rows.length;
  if (usable > limit) shedWeakestRows(rows, limit);
  return { rows, shed: usable - rows.length };
}

/** A stored tab's `shed`, which nothing else checks before it is added to. */
function storedShed(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : 0;
}

/** Strip a tab to what is worth storing, and to what survives being stored. */
export function forPersist(tab: SearchTab, limit = PERSIST_MAX_RESULTS): SearchTab {
  const { rows, shed } = rowsWorthStoring(tab.results, limit);
  return {
    ...tab,
    results: rows,
    // Rows storage leaves out are as gone after a restore as those the cap shed.
    shed: storedShed(tab.shed) + shed,
    // A `Map` does not survive JSON, and `mergeIntoTab` rebuilds it from its
    // length check whenever it is missing.
    resultIndex: undefined,
    // Nor does a `Set`; and a restored tab has no stream left to tell repeats in.
    shedKeys: undefined,
    // The request this tab was streaming is unreachable now: its id belonged to
    // a listener that no longer exists, so no further event will ever arrive
    // for it. Restoring it as still-searching would leave a spinner running
    // against nothing.
    isSearching: false,
    progress: null,
    // The network forgets the search across a restart, so there is nothing
    // left for Search More to continue.
    canSearchMore: undefined,
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
 * Re-trim a payload that has already been built, for the next-smaller limit in
 * `PERSIST_RETRY_LIMITS`.
 *
 * The retry used to call `buildPersistPayload` again, which re-ran the
 * `usableRow` filter and `shedWeakestRows` over every tab's *live* row array —
 * up to `MAX_TAB_RESULTS` rows apiece — once per limit, so a quota failure cost
 * three full passes over everything the user had searched for. The rows here
 * have already been through both, so re-shedding them is a sort over at most
 * `PERSIST_MAX_RESULTS`.
 *
 * It reaches the same answer as re-shedding from the live tab would. The shed
 * ranks rows within each origin class and keeps the strongest, and what this is
 * handed is precisely the strongest `PERSIST_MAX_RESULTS` under that same
 * ranking — so the strongest 100 of them are the strongest 100 of the tab.
 */
export function trimPersistPayload(payload: PersistedSearch, limit: number): PersistedSearch {
  return {
    activeId: payload.activeId,
    tabs: payload.tabs.map((tab) => {
      if (tab.results.length <= limit) return tab;
      // Copied rather than shed in place: the caller still holds the payload
      // this came from, and the attempt that failed may not be the last one.
      const results = tab.results.slice();
      shedWeakestRows(results, limit);
      return { ...tab, results, shed: storedShed(tab.shed) + tab.results.length - results.length };
    }),
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
