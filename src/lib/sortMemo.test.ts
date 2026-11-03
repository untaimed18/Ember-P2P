import { describe, expect, it, vi } from 'vitest';
import { createSortMemo, sortWithMemo } from './sortMemo';

interface Row {
  id: string;
  name: string;
  speed: number;
}

const byName = (a: Row, b: Row) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id);
const idOf = (r: Row) => r.id;
const nameKey = (r: Row) => r.name;

describe('sortWithMemo', () => {
  it('sorts the first time and returns a new array', () => {
    const memo = createSortMemo();
    const rows = [
      { id: 'b', name: 'beta', speed: 1 },
      { id: 'a', name: 'alpha', speed: 2 },
    ];
    const sorted = sortWithMemo(rows, byName, memo, 'name:asc', idOf, nameKey);
    expect(sorted.map(idOf)).toEqual(['a', 'b']);
    expect(rows.map(idOf)).toEqual(['b', 'a']);
  });

  it('reuses the order without comparing when only other figures change, with the new row objects', () => {
    const memo = createSortMemo();
    sortWithMemo(
      [{ id: 'b', name: 'beta', speed: 1 }, { id: 'a', name: 'alpha', speed: 2 }],
      byName, memo, 'name:asc', idOf, nameKey,
    );
    const compare = vi.fn(byName);
    const next = [{ id: 'b', name: 'beta', speed: 9 }, { id: 'a', name: 'alpha', speed: 8 }];
    const sorted = sortWithMemo(next, compare, memo, 'name:asc', idOf, nameKey);
    expect(compare).not.toHaveBeenCalled();
    expect(sorted.map(idOf)).toEqual(['a', 'b']);
    expect(sorted[0]).toBe(next[1]);
    expect(sorted[1]).toBe(next[0]);
  });

  it('sorts again when a key, the set of rows, or the token changes', () => {
    const memo = createSortMemo();
    const first = [{ id: 'a', name: 'alpha', speed: 0 }, { id: 'b', name: 'beta', speed: 0 }];
    sortWithMemo(first, byName, memo, 'name:asc', idOf, nameKey);

    const renamed = [{ id: 'a', name: 'zeta', speed: 0 }, { id: 'b', name: 'beta', speed: 0 }];
    expect(sortWithMemo(renamed, byName, memo, 'name:asc', idOf, nameKey).map(idOf)).toEqual(['b', 'a']);

    const swapped = [{ id: 'a', name: 'zeta', speed: 0 }, { id: 'c', name: 'beta', speed: 0 }];
    expect(sortWithMemo(swapped, byName, memo, 'name:asc', idOf, nameKey).map(idOf)).toEqual(['c', 'a']);

    const grown = [...swapped, { id: 'd', name: 'alpha', speed: 0 }];
    expect(sortWithMemo(grown, byName, memo, 'name:asc', idOf, nameKey).map(idOf)).toEqual(['d', 'c', 'a']);

    const desc = (a: Row, b: Row) => -byName(a, b);
    expect(sortWithMemo(grown, desc, memo, 'name:desc', idOf, nameKey).map(idOf)).toEqual(['a', 'c', 'd']);
  });

  it('always sorts on live keys', () => {
    const memo = createSortMemo();
    const bySpeed = vi.fn((a: Row, b: Row) => a.speed - b.speed);
    const rows = [{ id: 'a', name: 'a', speed: 2 }, { id: 'b', name: 'b', speed: 1 }];
    expect(sortWithMemo(rows, bySpeed, memo, 'speed:asc', idOf, null).map(idOf)).toEqual(['b', 'a']);
    sortWithMemo(rows, bySpeed, memo, 'speed:asc', idOf, null);
    expect(bySpeed.mock.calls.length).toBeGreaterThan(1);
    expect(memo.order).toEqual([]);
  });

  it('does not reuse an order when ids repeat', () => {
    const memo = createSortMemo();
    const rows = [{ id: 'a', name: 'b', speed: 0 }, { id: 'a', name: 'b', speed: 0 }];
    sortWithMemo(rows, byName, memo, 'name:asc', idOf, nameKey);
    expect(sortWithMemo(rows, byName, memo, 'name:asc', idOf, nameKey)).toHaveLength(2);
  });
});
