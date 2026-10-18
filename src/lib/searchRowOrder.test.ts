import { describe, expect, it } from 'vitest';
import { holdRowOrder, rowRanks } from './searchRowOrder';

type Row = { key: string; sources: number };
const keyOf = (r: Row) => r.key;
const bySourcesDesc = (a: Row, b: Row) => b.sources - a.sources;
const row = (key: string, sources: number): Row => ({ key, sources });
const keys = (rows: Row[]) => rows.map((r) => r.key);

describe('holdRowOrder', () => {
  it('keeps rows where they were when their values change', () => {
    // A re-sight raises a row's source count mid-stream; sorted, it would jump
    // above the row the pointer is on.
    const ranks = rowRanks([row('a', 9), row('b', 5), row('c', 1)], keyOf);
    const rows = [row('c', 50), row('a', 9), row('b', 5)];

    holdRowOrder(rows, ranks, keyOf, bySourcesDesc);

    expect(keys(rows)).toEqual(['a', 'b', 'c']);
  });

  it('puts results that arrived during the hold below the rows already shown', () => {
    const ranks = rowRanks([row('a', 9), row('b', 5)], keyOf);
    const rows = [row('new-low', 1), row('a', 9), row('new-high', 99), row('b', 5)];

    holdRowOrder(rows, ranks, keyOf, bySourcesDesc);

    expect(keys(rows)).toEqual(['a', 'b', 'new-high', 'new-low']);
  });

  it('keeps a newly arrived row in place on the next pass too', () => {
    const ranks = rowRanks([row('a', 9)], keyOf);
    const first = [row('a', 9), row('x', 3)];
    holdRowOrder(first, ranks, keyOf, bySourcesDesc);

    const second = [row('y', 7), row('x', 3), row('a', 9)];
    holdRowOrder(second, ranks, keyOf, bySourcesDesc);

    expect(keys(second)).toEqual(['a', 'x', 'y']);
  });

  it('closes the gap a filtered-out row leaves, and returns it to its place', () => {
    const ranks = rowRanks([row('a', 3), row('b', 2), row('c', 1)], keyOf);
    const without = [row('c', 1), row('a', 3)];
    holdRowOrder(without, ranks, keyOf, bySourcesDesc);
    expect(keys(without)).toEqual(['a', 'c']);

    const back = [row('c', 1), row('b', 2), row('a', 3)];
    holdRowOrder(back, ranks, keyOf, bySourcesDesc);
    expect(keys(back)).toEqual(['a', 'b', 'c']);
  });
});
