import { describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { SearchResult } from '$lib/types';

vi.mock('@tauri-apps/api/core', () => ({ invoke: async () => [] }));
vi.mock('@tauri-apps/api/event', () => ({ listen: async () => () => {} }));
vi.mock('$app/environment', () => ({ dev: false, browser: false }));

const { appendSearchResults, openSearchTab, searchTabs } = await import('$lib/stores/search');

function row(hash: string, size: number, origin = 'KAD', name = 'movie.avi'): SearchResult {
  return {
    file: { hash, size, name, extension: 'avi' } as SearchResult['file'],
    peer_id: '',
    peer_name: '',
    availability: 1,
    file_type: 'Video',
    source_addresses: [],
    spam_rating: 0,
    is_spam: false,
    clean_name: name,
    result_origin: origin,
  };
}

function tabRows(requestId: number): SearchResult[] {
  return get(searchTabs).find((t) => t.requestId === requestId)?.results ?? [];
}

describe('merging rows for one hash', () => {
  it('keeps a row claiming another size apart instead of folding it in', () => {
    const { requestId } = openSearchTab('movie', 'global');
    appendSearchResults(requestId, [row('aa', 700, 'Server')]);
    appendSearchResults(requestId, [row('aa', 9_999, 'KAD')]);
    appendSearchResults(requestId, [row('aa', 700, 'UDP'), row('aa', 9_999, 'Ember')]);

    const rows = tabRows(requestId);
    expect(rows).toHaveLength(2);
    const real = rows.find((r) => r.file.size === 700)!;
    expect(real.size_variant).toBeUndefined();
    expect(real.result_origin).toBe('Server · UDP');
    const other = rows.find((r) => r.file.size === 9_999)!;
    expect(other.size_variant).toBe(true);
    expect(other.result_origin).toBe('Ember · KAD');
  });

  it('merges a row of unknown size into the sized one', () => {
    const { requestId } = openSearchTab('clip', 'global');
    appendSearchResults(requestId, [row('bb', 0, 'KAD')]);
    appendSearchResults(requestId, [row('bb', 500, 'Server')]);
    appendSearchResults(requestId, [row('bb', 0, 'Ember')]);

    const rows = tabRows(requestId);
    expect(rows).toHaveLength(1);
    expect(rows[0].file.size).toBe(500);
    expect(rows[0].size_variant).toBeUndefined();
  });
});
