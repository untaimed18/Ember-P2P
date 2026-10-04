import { describe, expect, it } from 'vitest';
import { distinctLinks, type Ed2kLinkInfo } from './search';

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
