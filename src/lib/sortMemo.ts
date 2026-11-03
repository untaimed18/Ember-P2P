/**
 * Sorting a list that is replaced many times a second without re-sorting it
 * when its order cannot have changed.
 *
 * The transfer store hands out a new array on every progress flush, and most
 * flushes change only figures the chosen sort ignores. When every row's sort
 * key is what it was last time, the last order still holds and only the row
 * objects need swapping in.
 */

export interface SortMemo {
  /** Sort field and direction the order was computed for. */
  token: string;
  /** Row ids in sorted order. */
  order: string[];
  /** Each row's sort key when the order was computed. */
  keys: Map<string, string | number>;
}

export function createSortMemo(): SortMemo {
  return { token: '', order: [], keys: new Map() };
}

/**
 * `rows` sorted by `compare`, reusing `memo`'s order when `token` and every
 * row's `orderKey` are unchanged. `orderKey` must cover everything `compare`
 * reads, tie-breaks included; pass `null` for a sort on figures that move with
 * every update, which always sorts and clears the memo.
 *
 * Mutates `memo`. Never mutates `rows`.
 */
export function sortWithMemo<T>(
  rows: readonly T[],
  compare: (a: T, b: T) => number,
  memo: SortMemo,
  token: string,
  idOf: (row: T) => string,
  orderKey: ((row: T) => string | number) | null,
): T[] {
  if (orderKey === null) {
    memo.token = '';
    memo.order = [];
    memo.keys = new Map();
    return [...rows].sort(compare);
  }
  if (memo.token === token && memo.keys.size === rows.length) {
    const byId = new Map<string, T>();
    let unchanged = true;
    for (const row of rows) {
      const id = idOf(row);
      if (memo.keys.get(id) !== orderKey(row)) {
        unchanged = false;
        break;
      }
      byId.set(id, row);
    }
    if (unchanged && byId.size === rows.length) {
      return memo.order.map((id) => byId.get(id) as T);
    }
  }
  const sorted = [...rows].sort(compare);
  memo.token = token;
  memo.order = sorted.map(idOf);
  memo.keys = new Map(sorted.map((row) => [idOf(row), orderKey(row)]));
  return sorted;
}
