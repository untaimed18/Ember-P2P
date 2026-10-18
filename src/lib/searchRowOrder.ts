/**
 * Keeping search results where they are while the user is aiming at one.
 *
 * Results stream in and re-sort several times a second, so a row moves under
 * the pointer between the two clicks of a double-click — which downloads — or
 * while its context menu is open. Holding the order is a pure rule over the
 * already-filtered rows, so it lives here with tests rather than in the page.
 */

/** Each row's position, by key, in the order given. */
export function rowRanks<T>(rows: readonly T[], keyOf: (row: T) => string): Map<string, number> {
  const ranks = new Map<string, number>();
  rows.forEach((row, i) => ranks.set(keyOf(row), i));
  return ranks;
}

/**
 * Put `rows` back in the order `ranks` holds.
 *
 * Rows `ranks` knows keep their relative order. Rows it does not — results that
 * arrived since the hold began — go after all of them, ordered by `compare`
 * among themselves, and are added to `ranks` so the next pass leaves them where
 * they landed too. A row that has left `rows` keeps its rank, so one that comes
 * back (a filter toggled off and on) returns to its place.
 *
 * Mutates `rows` and `ranks`.
 */
export function holdRowOrder<T>(
  rows: T[],
  ranks: Map<string, number>,
  keyOf: (row: T) => string,
  compare: (a: T, b: T) => number,
): void {
  const known: { row: T; rank: number }[] = [];
  const fresh: T[] = [];
  for (const row of rows) {
    const rank = ranks.get(keyOf(row));
    if (rank === undefined) fresh.push(row);
    else known.push({ row, rank });
  }
  known.sort((a, b) => a.rank - b.rank);
  fresh.sort(compare);
  let i = 0;
  for (const k of known) rows[i++] = k.row;
  for (const row of fresh) {
    ranks.set(keyOf(row), ranks.size);
    rows[i++] = row;
  }
}
