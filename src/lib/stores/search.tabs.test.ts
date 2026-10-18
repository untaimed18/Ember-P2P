import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { SearchResult } from '$lib/types';

vi.mock('@tauri-apps/api/core', () => ({ invoke: async () => [] }));
let emit: ((event: { payload: unknown }) => void) | null = null;
vi.mock('@tauri-apps/api/event', () => ({
  listen: async (name: string, handler: (event: { payload: unknown }) => void) => {
    if (name === 'search-results') emit = handler;
    return () => {};
  },
}));
vi.mock('$app/environment', () => ({ dev: false, browser: false }));

const {
  MAX_SEARCH_TABS,
  appendSearchResults,
  flushPendingSearchResults,
  initSearchStore,
  openSearchTab,
  patchSearchTabByRequestId,
  patchSpamFlagByHash,
  searchTabs,
} = await import('$lib/stores/search');

function row(hash: string, size = 100, origin = 'KAD'): SearchResult {
  return {
    file: { hash, size, name: `${hash}.avi`, extension: 'avi' } as SearchResult['file'],
    peer_id: '',
    peer_name: '',
    availability: 1,
    file_type: 'Video',
    source_addresses: [],
    spam_rating: 0,
    is_spam: false,
    clean_name: `${hash}.avi`,
    result_origin: origin,
  };
}

/** Open a tab and finish it, with `rows` results. */
function finishedTab(query: string, rows: number) {
  const opened = openSearchTab(query, 'global');
  appendSearchResults(opened.requestId, Array.from({ length: rows }, (_, i) => row(`${query}-${i}`)));
  patchSearchTabByRequestId(opened.requestId, (t) => ({ ...t, isSearching: false }));
  return opened;
}

function notifications(run: () => void): number {
  let count = 0;
  const unsubscribe = searchTabs.subscribe(() => count++);
  count = 0;
  run();
  unsubscribe();
  return count;
}

function tabRows(requestId: number): SearchResult[] {
  return get(searchTabs).find((t) => t.requestId === requestId)?.results ?? [];
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(1_000_000);
  searchTabs.set([]);
});

afterEach(() => {
  vi.useRealTimers();
});

describe('opening a tab past the limit', () => {
  it('closes the oldest finished tab that found nothing before any with results', () => {
    finishedTab('first', 3);
    finishedTab('empty', 0);
    for (let i = 2; i < MAX_SEARCH_TABS; i++) finishedTab(`tab${i}`, 1);
    vi.advanceTimersByTime(60_000);

    const { evicted } = openSearchTab('newest', 'global');

    expect(evicted.map((t) => t.query)).toEqual(['empty']);
    const queries = get(searchTabs).map((t) => t.query);
    expect(queries).toHaveLength(MAX_SEARCH_TABS);
    expect(queries[0]).toBe('first');
    expect(queries.at(-1)).toBe('newest');
  });

  it('does not take a search started moments ago for one that found nothing', () => {
    for (let i = 0; i < MAX_SEARCH_TABS - 1; i++) finishedTab(`tab${i}`, 1);
    vi.advanceTimersByTime(60_000);
    // Still searching when the next one starts, which stops it.
    openSearchTab('just started', 'global');

    const { evicted } = openSearchTab('newest', 'global');

    expect(evicted.map((t) => t.query)).toEqual(['tab0']);
    expect(get(searchTabs).map((t) => t.query)).toContain('just started');
  });

  it('closes the oldest when every tab has results', () => {
    for (let i = 0; i < MAX_SEARCH_TABS; i++) finishedTab(`tab${i}`, 1);

    const { evicted } = openSearchTab('newest', 'global');

    expect(evicted.map((t) => t.query)).toEqual(['tab0']);
    expect(get(searchTabs)[0].query).toBe('tab1');
  });

  it('closes nothing under the limit', () => {
    finishedTab('only', 0);
    expect(openSearchTab('second', 'global').evicted).toEqual([]);
  });
});

describe('searching a tab again', () => {
  it('puts the new search in its place and closes nothing, even at the limit', () => {
    for (let i = 0; i < MAX_SEARCH_TABS; i++) finishedTab(`tab${i}`, i === 0 ? 0 : 1);
    vi.advanceTimersByTime(60_000);
    const target = get(searchTabs)[5];

    const { tabId, evicted } = openSearchTab(target.query, 'global', undefined, undefined, undefined, target.id);

    expect(evicted).toEqual([]);
    const tabs = get(searchTabs);
    expect(tabs).toHaveLength(MAX_SEARCH_TABS);
    expect(tabs[5].id).toBe(tabId);
    expect(tabs.some((t) => t.id === target.id)).toBe(false);
    expect(tabs[0].query).toBe('tab0');
  });

  it('opens on the end when the tab to replace is gone', () => {
    finishedTab('a', 1);
    const { tabId } = openSearchTab('b', 'global', undefined, undefined, undefined, 'no-such-tab');
    expect(get(searchTabs).at(-1)?.id).toBe(tabId);
  });
});

describe('updates for a request no tab owns', () => {
  it('do not notify subscribers', () => {
    finishedTab('alive', 1);
    expect(notifications(() => appendSearchResults(999_999, [row('late')]))).toBe(0);
    expect(notifications(() => patchSearchTabByRequestId(999_999, (t) => ({ ...t, error: 'x' })))).toBe(0);
  });

  it('do not notify when a buffered batch flushes after its request moved on', async () => {
    await initSearchStore();
    const { requestId } = openSearchTab('stream', 'global');
    emit?.({ payload: { request_id: requestId, results: [row('buffered')] } });
    // Stop rotates the tab's id, leaving the batch buffered under the old one.
    patchSearchTabByRequestId(requestId, (t) => ({ ...t, isSearching: false, requestId: requestId + 1_000 }));

    expect(notifications(() => flushPendingSearchResults(requestId))).toBe(0);
  });

  it('do not notify when the patch leaves the tab as it was', () => {
    const { requestId } = finishedTab('same', 1);
    expect(notifications(() => patchSearchTabByRequestId(requestId, (t) => t))).toBe(0);
  });

  it('still notify for the tab that owns the request', () => {
    const { requestId } = openSearchTab('live', 'global');
    expect(notifications(() => appendSearchResults(requestId, [row('hit')]))).toBe(1);
  });
});

describe('rows claiming another size for a hash', () => {
  it('are left alone by a spam mark on the hash', () => {
    const { requestId } = openSearchTab('movie', 'global');
    appendSearchResults(requestId, [row('aa', 700, 'Server'), row('aa', 9_999, 'KAD')]);

    patchSpamFlagByHash('aa', true, 100, ['manual']);

    const rows = tabRows(requestId);
    expect(rows.find((r) => !r.size_variant)?.is_spam).toBe(true);
    expect(rows.find((r) => r.size_variant)?.is_spam).toBe(false);
  });

  it('are not mistaken for the file once its own row is gone', () => {
    const { requestId } = openSearchTab('movie', 'global');
    appendSearchResults(requestId, [row('bb', 700, 'Server'), row('bb', 9_999, 'KAD')]);
    patchSearchTabByRequestId(requestId, (t) => ({
      ...t,
      results: t.results.filter((r) => r.size_variant),
      resultIndex: undefined,
    }));

    patchSpamFlagByHash('bb', true, 100, ['manual']);

    expect(tabRows(requestId).map((r) => r.is_spam)).toEqual([false]);
  });

  it('take a plain row of the same size instead of listing it twice', () => {
    const { requestId } = openSearchTab('movie', 'global');
    appendSearchResults(requestId, [row('cc', 700, 'Server'), row('cc', 9_999, 'KAD')]);
    patchSearchTabByRequestId(requestId, (t) => ({
      ...t,
      results: t.results.filter((r) => r.size_variant),
      resultIndex: undefined,
    }));

    appendSearchResults(requestId, [row('cc', 9_999, 'Ember')]);

    const rows = tabRows(requestId);
    expect(rows).toHaveLength(1);
    expect(rows[0].result_origin).toBe('Ember · KAD');
  });
});
