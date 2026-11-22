import { describe, expect, it } from 'vitest';
import { feedLinksIn } from './feedLinks';

const body = (c: string) => c.repeat(77);

describe('feedLinksIn', () => {
  it('finds each feed link once, in either form, as Ember writes it', () => {
    const a = body('a');
    const b = body('b');
    const text = `try ember-feed:${a} or https://www.emberp2p.org/feed/${b.toUpperCase()}, and ember-feed:${a} again`;
    expect(feedLinksIn(text)).toEqual([`ember-feed:${a}`, `ember-feed:${b}`]);
  });

  it('takes only a whole link', () => {
    expect(feedLinksIn(`ember-feed:${'a'.repeat(76)}`)).toEqual([]);
    expect(feedLinksIn(`ember-feed:${'a'.repeat(78)}`)).toEqual([]);
    expect(feedLinksIn(`http://emberp2p.org/feed/${body('a')}`)).toEqual([]);
    expect(feedLinksIn('no links here')).toEqual([]);
  });

  it('draws at most three cards', () => {
    const text = ['a', 'b', 'c', 'd'].map((c) => `ember-feed:${body(c)}`).join(' ');
    expect(feedLinksIn(text)).toHaveLength(3);
  });
});
