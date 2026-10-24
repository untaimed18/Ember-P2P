import { describe, expect, it } from 'vitest';
import { AUTO_MIB_MAX, capMib, concernsFollowed, draftOf, sameDraft, type FeedDraft } from './feedsPage';

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
