import { describe, expect, it } from 'vitest';
import { LIKELY_SPAM_SCORE, LONG_LISTED_SECS, listingNameKey, listingSpamScores } from './channelListingSpam';

const listing = (channel_id: string, name: string, member_count: number | null = 2) => ({
  channel_id,
  name,
  member_count,
});

const flagged = (rows: (ReturnType<typeof listing> & { friends_present?: number | null })[]) => {
  const scores = listingSpamScores(rows);
  return rows.filter((row) => (scores.get(row.channel_id) ?? 0) >= LIKELY_SPAM_SCORE).map((row) => row.channel_id);
};

describe('listingSpamScores', () => {
  it('leaves ordinary room names alone, in any script', () => {
    expect(
      flagged([
        listing('a', 'Music'),
        listing('b', 'Rust beginners'),
        listing('c', 'Café & chat'),
        listing('d', '日本語の部屋'),
        listing('e', 'Новости'),
        listing('f', 'NASA'),
        listing('g', 'New room', 0),
      ]),
    ).toEqual([]);
  });

  it('folds a name that carries a link', () => {
    expect(
      flagged([
        listing('a', 'Free coins at www.example.com'),
        listing('b', 'join t.me/somewhere'),
        listing('c', 'cheap-stuff.xyz deals'),
        listing('d', 'https://x.example'),
      ]),
    ).toEqual(['a', 'b', 'c', 'd']);
  });

  it('needs two weaker signs together', () => {
    expect(flagged([listing('a', 'FREEEEEE')])).toEqual([]);
    expect(flagged([listing('a', 'FREEEEEE STUFF')])).toEqual([]);
    expect(flagged([listing('a', 'FREEEEEE STUFF', 0)])).toEqual(['a']);
    expect(flagged([listing('a', '$$$ !!! ***', 0)])).toEqual([]);
    expect(flagged([listing('a', '$$$$$ !!! ***', 0)])).toEqual(['a']);
  });

  it('folds a flood of copies but keeps the one people are in', () => {
    const rows = [
      listing('real', 'Music', 12),
      listing('copy1', 'music', 0),
      listing('copy2', 'M U S I C', 0),
      listing('copy3', 'Music!', 0),
    ];
    expect(flagged(rows)).toEqual(['copy1', 'copy2', 'copy3']);
    // Two of a name is ordinary.
    expect(flagged([listing('a', 'Music', 0), listing('b', 'music', 0)])).toEqual([]);
  });

  it('does not fold copies on a count it could not read', () => {
    const rows = [listing('a', 'Lobby', null), listing('b', 'lobby', null), listing('c', 'LOBBY', null)];
    expect(flagged(rows)).toEqual([]);
  });

  it('never folds a room a friend is in', () => {
    const rows = [
      { ...listing('ad', 'Free coins at www.example.com', 3), friends_present: 1 },
      { ...listing('copy', 'FREEEEEE STUFF', 0), friends_present: 0 },
    ];
    expect(flagged(rows)).toEqual(['copy']);
  });

  it('lets a long-listed room outlive one quirk, never a link', () => {
    const now = 2_000_000_000;
    const old = now - LONG_LISTED_SECS;
    const scores = listingSpamScores(
      [
        { ...listing('shouty', 'FREEEEEE STUFF', 0), listed_since: old },
        { ...listing('fresh', 'FREEEEEE STUFF', 0), listed_since: now - 3600 },
        { ...listing('linked', 'www.example.com', 4), listed_since: old },
      ],
      now,
    );
    expect(scores.get('shouty')).toBeLessThan(LIKELY_SPAM_SCORE);
    expect(scores.get('fresh')).toBeGreaterThanOrEqual(LIKELY_SPAM_SCORE);
    expect(scores.get('linked')).toBeGreaterThanOrEqual(LIKELY_SPAM_SCORE);
  });

  it('reads names the way a person would', () => {
    expect(listingNameKey('  Ｍusic! ')).toBe('music');
    expect(listingNameKey('M-U-S-I-C')).toBe('music');
    expect(listingNameKey('!!!')).toBe('');
  });
});
