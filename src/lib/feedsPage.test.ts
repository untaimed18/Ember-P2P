import { describe, expect, it } from 'vitest';
import {
  AUTO_MIB_MAX,
  capMib,
  concernsFollowed,
  draftOf,
  keepUnchanged,
  onDisk,
  pickFollowed,
  runEach,
  sameDraft,
  withLiveProgress,
  type FeedDraft,
} from './feedsPage';

describe('withLiveProgress', () => {
  const row = (id: string | null, done = 0, speed = 0) => ({
    ed2k: id ?? 'none',
    size: 1000,
    progress: done / 10,
    transfer: id ? { id, done, speed, sources: 3 } : null,
  });

  it('takes in the figures for rows downloading, and only theirs', () => {
    const items = [row('a', 100, 5), row('b', 200, 5), row(null)];
    const next = withLiveProgress(items, new Map([['a', { done: 400, speed: 9 }]]));
    expect(next).not.toBe(items);
    expect(next[0]).toMatchObject({ progress: 40, transfer: { id: 'a', done: 400, speed: 9, sources: 3 } });
    expect(next[1]).toBe(items[1]);
    expect(next[2]).toBe(items[2]);
  });

  it('keeps the same rows when nothing changes, so nothing redraws', () => {
    const items = [row('a', 100, 5)];
    expect(withLiveProgress(items, new Map([['a', { done: 100, speed: 5 }]]))).toBe(items);
    expect(withLiveProgress(items, new Map([['other', { done: 900, speed: 1 }]]))).toBe(items);
    expect(withLiveProgress(items, new Map())).toBe(items);
  });

  it('never shows more than the file or less than nothing', () => {
    const [over] = withLiveProgress([row('a')], new Map([['a', { done: 5000, speed: 1 }]]));
    expect(over).toMatchObject({ progress: 100, transfer: { done: 1000 } });
    const [under] = withLiveProgress([row('a', 10)], new Map([['a', { done: -1, speed: 0 }]]));
    expect(under).toMatchObject({ progress: 0, transfer: { done: 0 } });
  });
});

describe('keepUnchanged', () => {
  const row = (ed2k: string, done = 0, note = '') => ({
    ed2k,
    note,
    status: done > 0 ? 'downloading' : 'none',
    transfer: done > 0 ? { id: `t-${ed2k}`, done, speed: 5 } : null,
  });

  it('keeps the rows that read the same, and takes the ones that changed', () => {
    const prev = [row('a', 100), row('b'), row('c', 0, 'live')];
    const next = [row('a', 200), row('b'), row('c', 0, 'studio')];
    const merged = keepUnchanged(prev, next);
    expect(merged).toEqual(next);
    expect(merged[0]).toBe(next[0]);
    expect(merged[1]).toBe(prev[1]);
    expect(merged[2]).toBe(next[2]);
  });

  it('sees a change inside the download', () => {
    const prev = [row('a', 100)];
    const next = [{ ...row('a', 100), transfer: { id: 't-a', done: 100, speed: 9 } }];
    expect(keepUnchanged(prev, next)[0]).toBe(next[0]);
  });

  it('gives back the same list when nothing changed, so nothing redraws', () => {
    const prev = [row('a', 100), row('b')];
    expect(keepUnchanged(prev, [row('a', 100), row('b')])).toBe(prev);
  });

  it('follows the new order, and rows that came or went', () => {
    const prev = [row('a'), row('b'), row('c')];
    const moved = keepUnchanged(prev, [row('b'), row('a'), row('c')]);
    expect(moved).not.toBe(prev);
    expect(moved).toEqual([prev[1], prev[0], prev[2]]);
    expect(moved[0]).toBe(prev[1]);
    const added = keepUnchanged(prev, [row('a'), row('b'), row('c'), row('d')]);
    expect(added.map((r) => r.ed2k)).toEqual(['a', 'b', 'c', 'd']);
    expect(added[2]).toBe(prev[2]);
    const removed = keepUnchanged(prev, [row('a'), row('c')]);
    expect(removed).toEqual([prev[0], prev[2]]);
    expect(removed[1]).toBe(prev[2]);
  });
});

describe('capMib', () => {
  it('saves an emptied, negative or fractional field as a whole number from 0', () => {
    expect(capMib(null)).toBe(0);
    expect(capMib(undefined)).toBe(0);
    expect(capMib(Number.NaN)).toBe(0);
    expect(capMib(-5)).toBe(0);
    expect(capMib(12.9)).toBe(12);
  });

  it('keeps no more than the backend does', () => {
    expect(capMib(AUTO_MIB_MAX)).toBe(AUTO_MIB_MAX);
    expect(capMib(AUTO_MIB_MAX + 1)).toBe(AUTO_MIB_MAX);
    expect(capMib(1e300)).toBe(AUTO_MIB_MAX);
    expect(capMib(Number.POSITIVE_INFINITY)).toBe(AUTO_MIB_MAX);
  });
});

describe('sameDraft', () => {
  const base: FeedDraft = {
    title: 'Mixes',
    description: 'Weekly',
    items: [
      { ed2k: 'AA', note: '' },
      { ed2k: 'bb', note: 'live' },
    ],
  };

  it('is clean after an edit that was undone', () => {
    expect(sameDraft({ ...base, title: 'Mixes', items: base.items.map((i) => ({ ...i })) }, base)).toBe(true);
  });

  it('ignores the case of a hash', () => {
    expect(sameDraft({ ...base, items: [{ ed2k: 'aa', note: '' }, { ed2k: 'BB', note: 'live' }] }, base)).toBe(true);
  });

  it('sees a changed title, description or note', () => {
    expect(sameDraft({ ...base, title: 'Mixes!' }, base)).toBe(false);
    expect(sameDraft({ ...base, description: '' }, base)).toBe(false);
    expect(sameDraft({ ...base, items: [base.items[0], { ed2k: 'bb', note: 'studio' }] }, base)).toBe(false);
  });

  it('sees files added, removed or reordered', () => {
    expect(sameDraft({ ...base, items: [...base.items, { ed2k: 'cc', note: '' }] }, base)).toBe(false);
    expect(sameDraft({ ...base, items: [base.items[0]] }, base)).toBe(false);
    expect(sameDraft({ ...base, items: [base.items[1], base.items[0]] }, base)).toBe(false);
  });
});

describe('draftOf', () => {
  it('keeps what a save stores and nothing else', () => {
    const feed = {
      salt: 's',
      title: 'Mixes',
      description: 'Weekly',
      items: [{ ed2k: 'aa', name: 'a.flac', size: 3, aich: '', blake3: 'b', note: 'live' }],
    };
    expect(draftOf(feed)).toEqual({ title: 'Mixes', description: 'Weekly', items: [{ ed2k: 'aa', note: 'live' }] });
  });

  it('is a copy, so an edit to the editor leaves it as saved', () => {
    const items = [{ ed2k: 'aa', note: '' }];
    const saved = draftOf({ title: 'T', description: '', items });
    items[0].note = 'typed after';
    expect(saved.items[0].note).toBe('');
  });
});

describe('concernsFollowed', () => {
  const feed = { publisher: 'pub', salt: 'salt' };

  it('matches an event naming the feed, or naming none', () => {
    expect(concernsFollowed({ publisher: 'pub', salt: 'salt' }, feed)).toBe(true);
    expect(concernsFollowed({}, feed)).toBe(true);
    expect(concernsFollowed(null, feed)).toBe(true);
  });

  it('ignores other followed feeds and the user’s own', () => {
    expect(concernsFollowed({ publisher: 'other', salt: 'salt' }, feed)).toBe(false);
    expect(concernsFollowed({ publisher: 'pub', salt: 'other' }, feed)).toBe(false);
    expect(concernsFollowed({ salt: 'salt' }, feed)).toBe(false);
  });
});

describe('pickFollowed', () => {
  const feed = (salt: string, unread = 0) => ({ publisher: 'pub', salt, unread });
  const feeds = [feed('a'), feed('b', 2), feed('c', 5)];

  it('opens the one last opened while it is still followed', () => {
    expect(pickFollowed(feeds, 'pub/c')?.salt).toBe('c');
    expect(pickFollowed(feeds, 'pub/a')?.salt).toBe('a');
  });

  it('else the first with something new, else the first', () => {
    expect(pickFollowed(feeds, 'pub/gone')?.salt).toBe('b');
    expect(pickFollowed(feeds, null)?.salt).toBe('b');
    expect(pickFollowed([feed('a'), feed('b')], null)?.salt).toBe('a');
  });

  it('opens nothing when nothing is followed', () => {
    expect(pickFollowed([], 'pub/a')).toBeUndefined();
  });
});

describe('onDisk', () => {
  it('is true only for a file downloaded and kept', () => {
    expect(onDisk('done')).toBe(true);
    expect(onDisk('in_library')).toBe(true);
    for (const status of ['none', 'queued', 'downloading', 'paused', 'failed', 'missing', 'cancelled', 'elsewhere'] as const) {
      expect(onDisk(status)).toBe(false);
    }
  });
});

describe('runEach', () => {
  it('runs every item, no more than the limit at once', async () => {
    let running = 0;
    let most = 0;
    const seen: number[] = [];
    const errors = await runEach([1, 2, 3, 4, 5], 2, async (n) => {
      running++;
      most = Math.max(most, running);
      await new Promise((resolve) => setTimeout(resolve, 1));
      seen.push(n);
      running--;
    });
    expect(errors).toEqual([]);
    expect(seen.sort()).toEqual([1, 2, 3, 4, 5]);
    expect(most).toBe(2);
  });

  it('goes on past a failure, and gives back what failed in order', async () => {
    const seen: number[] = [];
    const errors = await runEach([1, 2, 3, 4], 3, async (n) => {
      seen.push(n);
      if (n % 2 === 0) throw new Error(`no ${n}`);
    });
    expect(seen.sort()).toEqual([1, 2, 3, 4]);
    expect(errors.map((e) => (e as Error).message)).toEqual(['no 2', 'no 4']);
  });

  it('runs nothing for nothing', async () => {
    expect(await runEach([], 4, async () => {})).toEqual([]);
  });
});
