import { describe, expect, it } from 'vitest';
import { distinctLinks, searchWatchdogSecs, wireNumericFilters, type Ed2kLinkInfo } from './search';
import { MAX_MIN_SOURCES } from '$lib/searchQuery';

const link = (hash: string, name = 'file.bin'): Ed2kLinkInfo => ({ name, size: 1000, hash });

describe('distinctLinks', () => {
  it('counts the same file pasted more than once as one link, the first kept', () => {
    const a = 'a'.repeat(32);
    const b = 'b'.repeat(32);
    const links = [link(a, 'first.bin'), link(b), link(a, 'second.bin'), link(a)];
    expect(distinctLinks(links)).toEqual([link(a, 'first.bin'), link(b)]);
  });

  it('keeps a batch without repeats as it is', () => {
    const links = [link('1'.repeat(32)), link('2'.repeat(32))];
    expect(distinctLinks(links)).toEqual(links);
  });
});

describe('searchWatchdogSecs', () => {
  it('outwaits the backend, which never gives up before KAD finishes', () => {
    expect(searchWatchdogSecs(30)).toBe(80);
    expect(searchWatchdogSecs(120)).toBe(125);
  });
});

describe('wireNumericFilters', () => {
  it('sends only values the command can deserialize', () => {
    expect(wireNumericFilters({ minSize: 1.5, maxSize: 1e30, minAvailability: 1e12 })).toEqual({
      minSize: 2,
      maxSize: Number.MAX_SAFE_INTEGER,
      minAvailability: MAX_MIN_SOURCES,
    });
  });

  it('sends no constraint for what is absent or meaningless', () => {
    expect(wireNumericFilters(undefined)).toEqual({ minSize: null, maxSize: null, minAvailability: null });
    expect(wireNumericFilters({ minSize: -1, minAvailability: 0 })).toEqual({
      minSize: null,
      maxSize: null,
      minAvailability: null,
    });
  });
});
