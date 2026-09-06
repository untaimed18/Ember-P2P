import { describe, expect, it } from 'vitest';
import { shedWeakestRows } from './searchOverflow';
import type { SearchResult } from '$lib/types';

/**
 * Overflow eviction used to sort the whole tab by `availability`, which is a
 * swarm estimate on an eD2K or KAD row and a count of confirmed publishers on an
 * Ember one. The two are not the same measurement and Ember's is always the
 * smaller, so every Ember row sorted below every ordinary one and a tab that
 * overflowed lost them all — the only rows no other network could have found.
 */
function row(hash: string, availability: number, origin: string): SearchResult {
  return {
    file: {
      id: hash,
      name: `${hash}.bin`,
      path: '',
      size: 1024,
      hash,
      aich_hash: '',
      ember_file_hash: '',
      extension: 'bin',
      modified_at: 0,
      priority: 'normal',
      requests: 0,
      accepted: 0,
      bytes_transferred: 0,
      alltime_requests: 0,
      alltime_accepted: 0,
      alltime_transferred: 0,
      complete_sources: 0,
      folder: '',
      shared: false,
      friends_only: false,
      shared_kad: false,
      shared_ed2k: false,
      shared_ember: false,
    },
    peer_id: '',
    peer_name: '',
    availability,
    file_type: 'Pro',
    source_addresses: [],
    spam_rating: 0,
    is_spam: false,
    clean_name: '',
    result_origin: origin,
  } as unknown as SearchResult;
}

describe('shedWeakestRows', () => {
  it('keeps the Ember rows a single numeric sort would have dropped first', () => {
    // Every KAD row claims a bigger swarm than any Ember row has publishers,
    // which is the ordinary case rather than a contrived one.
    const rows = [
      ...Array.from({ length: 40 }, (_, i) => row(`kad${i}`, 50 + i, 'KAD')),
      ...Array.from({ length: 5 }, (_, i) => row(`ember${i}`, 1 + i, 'Ember')),
    ];

    shedWeakestRows(rows, 20);

    expect(rows).toHaveLength(20);
    expect(rows.filter((r) => r.result_origin === 'Ember')).toHaveLength(5);
  });

  it('still sheds the weakest of each class', () => {
    const rows = [
      row('kad-strong', 90, 'KAD'),
      row('kad-weak', 1, 'KAD'),
      row('ember-strong', 4, 'Ember'),
      row('ember-weak', 1, 'Ember'),
    ];

    shedWeakestRows(rows, 2);

    expect(rows.map((r) => r.file.hash).sort()).toEqual(['ember-strong', 'kad-strong']);
  });

  it('leaves a tab that fits completely alone', () => {
    const rows = [row('a', 1, 'KAD'), row('b', 2, 'Ember')];
    shedWeakestRows(rows, 10);
    expect(rows.map((r) => r.file.hash)).toEqual(['a', 'b']);
  });

  it('treats a mixed origin as Ember, since the publisher count is in the number', () => {
    const rows = [
      ...Array.from({ length: 10 }, (_, i) => row(`kad${i}`, 30 + i, 'KAD')),
      row('mixed', 2, 'Ember · KAD'),
    ];

    shedWeakestRows(rows, 5);

    expect(rows.some((r) => r.file.hash === 'mixed')).toBe(true);
  });
});
