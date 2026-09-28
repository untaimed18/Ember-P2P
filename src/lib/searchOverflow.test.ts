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
function row(hash: string, availability: number, origin: string, isSpam = false): SearchResult {
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
    spam_rating: isSpam ? 80 : 0,
    is_spam: isSpam,
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

  it('sheds spam before any unflagged row, whatever the spam claims', () => {
    // The inflated count is the polluter's own claim, and "Hide spam" means
    // the rows it would have evicted are the only ones on screen.
    const rows = [
      row('spam-loud', 900, 'KAD', true),
      row('spam-louder', 800, 'KAD', true),
      row('honest-quiet', 1, 'KAD'),
      row('honest-silent', 0, 'KAD'),
    ];

    shedWeakestRows(rows, 2);

    expect(rows.map((r) => r.file.hash).sort()).toEqual(['honest-quiet', 'honest-silent']);
  });

  it('still ranks spam against spam by availability once only spam is left', () => {
    const rows = [
      row('spam-weak', 2, 'KAD', true),
      row('spam-strong', 40, 'KAD', true),
      row('honest', 5, 'KAD'),
    ];

    shedWeakestRows(rows, 2);

    expect(rows.map((r) => r.file.hash)).toEqual(['honest', 'spam-strong']);
  });

  it('sheds a flagged row near the top of its class before a clean row lower in another', () => {
    // Ranked only by position within each class, the Ember spam row sat at
    // position 5 and beat every clean KAD row from position 6 down.
    const rows = [
      ...Array.from({ length: 5 }, (_, i) => row(`ember${i}`, 10 - i, 'Ember')),
      row('ember-spam', 1, 'Ember', true),
      ...Array.from({ length: 12 }, (_, i) => row(`kad${i}`, 100 - i, 'KAD')),
    ];

    shedWeakestRows(rows, 17);

    expect(rows).toHaveLength(17);
    expect(rows.some((r) => r.is_spam)).toBe(false);
  });

  it('interleaves flagged rows across classes once only spam is left to keep', () => {
    const rows = [
      row('honest', 5, 'KAD'),
      ...Array.from({ length: 3 }, (_, i) => row(`kad-spam${i}`, 50 - i, 'KAD', true)),
      ...Array.from({ length: 3 }, (_, i) => row(`ember-spam${i}`, 3 - i, 'Ember', true)),
    ];

    shedWeakestRows(rows, 3);

    expect(rows.map((r) => r.file.hash)).toEqual(['honest', 'kad-spam0', 'ember-spam0']);
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
