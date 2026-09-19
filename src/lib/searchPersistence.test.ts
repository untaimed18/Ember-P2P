import { describe, expect, it } from 'vitest';
import {
  PERSIST_MAX_RESULTS,
  PERSIST_MAX_TABS,
  RESTORED_REQUEST_ID,
  buildPersistPayload,
  forPersist,
  parsePersistedSearch,
} from './searchPersistence';
import type { SearchTab } from '$lib/stores/search';
import type { SearchResult } from '$lib/types';

function result(name: string): SearchResult {
  return {
    file: {
      id: name,
      name,
      path: '',
      size: 1,
      hash: name,
      aich_hash: '',
      ember_file_hash: '',
      extension: 'bin',
      complete_sources: 0,
    },
    availability: 1,
    clean_name: name,
    file_type: '',
    rating: null,
    media: null,
    comment: null,
    source_addresses: [],
    is_spam: false,
    result_origin: 'Server',
    origin_server_ip: null,
    spam_reasons: [],
    spam_reason_details: [],
  } as unknown as SearchResult;
}

function tab(id: string, resultCount = 1): SearchTab {
  return {
    id,
    requestId: 7,
    query: `q-${id}`,
    method: 'global',
    results: Array.from({ length: resultCount }, (_, i) => result(`${id}-${i}`)),
    resultIndex: new Map([['a', 0]]),
    isSearching: true,
    progress: { nodes_contacted: 3, results_so_far: 9, phase: 'searching' },
    error: null,
  } as unknown as SearchTab;
}

describe('forPersist', () => {
  it('lands a restored tab in a settled state', () => {
    // The request it was streaming is gone with the page, so nothing will ever
    // arrive to end a spinner left running.
    const stripped = forPersist(tab('a'));

    expect(stripped.isSearching).toBe(false);
    expect(stripped.progress).toBeNull();
  });

  it('gives up the request id so the next search cannot collide with it', () => {
    // `newSearchNonce` restarts at 1 on every page load, so a restored tab that
    // kept its old id would capture the first search made after the restore —
    // `updateTabByRequestId` matches on exactly this field.
    const stripped = forPersist(tab('a'));

    expect(stripped.requestId).toBe(RESTORED_REQUEST_ID);
    // Whatever the sentinel is, it must be something a live request can never
    // be: the nonce counts up from 1 and `validRequestId` rejects `<= 0`.
    expect(RESTORED_REQUEST_ID).toBeLessThan(1);
  });

  it('drops the result index, which JSON cannot carry', () => {
    const stripped = forPersist(tab('a'));

    expect(stripped.resultIndex).toBeUndefined();
    expect(JSON.parse(JSON.stringify(stripped)).resultIndex).toBeUndefined();
  });

  it('keeps the query and results that make a tab worth restoring', () => {
    const stripped = forPersist(tab('a', 3));

    expect(stripped.query).toBe('q-a');
    expect(stripped.results).toHaveLength(3);
  });

  it('caps the rows it stores', () => {
    const stripped = forPersist(tab('a', PERSIST_MAX_RESULTS + 250));

    expect(stripped.results).toHaveLength(PERSIST_MAX_RESULTS);
  });
});

describe('buildPersistPayload', () => {
  it('round-trips through JSON', () => {
    const payload = buildPersistPayload([tab('a', 2), tab('b', 1)], 'b');
    const restored = parsePersistedSearch(JSON.stringify(payload));

    expect(restored.tabs.map((t) => t.id)).toEqual(['a', 'b']);
    expect(restored.activeId).toBe('b');
    expect(restored.tabs[0].results).toHaveLength(2);
  });

  it('keeps the newest tabs when there are too many', () => {
    const tabs = Array.from({ length: PERSIST_MAX_TABS + 3 }, (_, i) => tab(`t${i}`));
    const payload = buildPersistPayload(tabs, null);

    expect(payload.tabs).toHaveLength(PERSIST_MAX_TABS);
    expect(payload.tabs.at(-1)?.id).toBe(`t${PERSIST_MAX_TABS + 2}`);
  });

  it('honours a smaller row budget for a retry after a refused write', () => {
    const payload = buildPersistPayload([tab('a', 400)], 'a', 25);

    expect(payload.tabs[0].results).toHaveLength(25);
  });
});

describe('parsePersistedSearch', () => {
  it('restores nothing rather than throwing on unusable storage', () => {
    // Hand-edited or stale-schema storage must not stop the store hydrating.
    for (const raw of [null, '', 'not json', '{', '[]', 'null', '"a string"', '42']) {
      expect(parsePersistedSearch(raw)).toEqual({ tabs: [], activeId: null });
    }
  });

  it('drops entries that do not look like tabs, keeping the ones that do', () => {
    const raw = JSON.stringify({
      tabs: [
        { id: 'good', query: 'q', results: [], isSearching: false, progress: null },
        { id: 'no-query', results: [] },
        { query: 'no-id', results: [] },
        { id: 'no-results', query: 'q' },
        null,
        'nonsense',
      ],
      activeId: 'good',
    });

    const restored = parsePersistedSearch(raw);

    expect(restored.tabs.map((t) => t.id)).toEqual(['good']);
    expect(restored.activeId).toBe('good');
  });

  it('falls back to the first tab when the stored active id is gone', () => {
    const raw = JSON.stringify({
      tabs: [{ id: 'a', query: 'q', results: [] }],
      activeId: 'closed-tab',
    });

    expect(parsePersistedSearch(raw).activeId).toBe('a');
  });

  it('reports no active tab when nothing was restored', () => {
    const raw = JSON.stringify({ tabs: [], activeId: 'a' });

    expect(parsePersistedSearch(raw)).toEqual({ tabs: [], activeId: null });
  });

  it('settles a tab that was stored mid-search', () => {
    // Belt and braces: the writer already settles these, but storage written by
    // an older build could carry a live-looking tab.
    const raw = JSON.stringify({
      tabs: [
        {
          id: 'a',
          query: 'q',
          results: [],
          isSearching: true,
          progress: { nodes_contacted: 1, results_so_far: 2, phase: 'searching' },
        },
      ],
      activeId: 'a',
    });

    const restored = parsePersistedSearch(raw);

    expect(restored.tabs[0].isSearching).toBe(false);
    expect(restored.tabs[0].progress).toBeNull();
  });
});
