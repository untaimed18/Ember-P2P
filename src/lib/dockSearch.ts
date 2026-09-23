/**
 * How the chat dock's switcher decides what a query matches.
 *
 * Its own module, with tests, for the reason `dockWidth.ts` gives: the rule is
 * small, but it decides which conversation "type two letters, press Enter"
 * opens, and a rule that is wrong shows up as the wrong chat rather than as an
 * error.
 */

/** Below this a run of hex digits is far more likely to be part of a name —
 *  "de", "cafe", "bead" — than someone pasting an ID. */
const ID_QUERY_MIN = 8;
const ID_QUERY_RE = /^[0-9a-f]+$/;

/** Lowercase with accents stripped, so "jose" finds "José". */
export function foldForSearch(text: string): string {
  return text.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
}

/** The query as rows are compared against it. */
export function searchNeedle(query: string): string {
  return foldForSearch(query.trim());
}

export type SwitcherMatch = 'name' | 'id' | null;

/**
 * Whether a row answers the needle, and how.
 *
 * The ID is matched by prefix only, and only once the needle could be one: a
 * substring test against 32 hex characters matched almost any short query
 * made of the letters a–f, so "de" offered half the friend list. An unnamed
 * friend is still findable by the hex fragment their name shows.
 */
export function switcherMatch(
  row: { name: string; hash: string },
  needle: string,
): SwitcherMatch {
  if (!needle) return 'name';
  if (foldForSearch(row.name).includes(needle)) return 'name';
  if (needle.length >= ID_QUERY_MIN && ID_QUERY_RE.test(needle)
    && row.hash.toLowerCase().startsWith(needle)) {
    return 'id';
  }
  return null;
}

/** The rows that match, name matches ahead of ID matches, each group in the
 *  order it arrived — the caller's order already means something. */
export function filterSwitcherRows<T extends { name: string; hash: string }>(
  rows: T[],
  needle: string,
): T[] {
  const byName: T[] = [];
  const byId: T[] = [];
  for (const row of rows) {
    const match = switcherMatch(row, needle);
    if (match === 'name') byName.push(row);
    else if (match === 'id') byId.push(row);
  }
  return [...byName, ...byId];
}

/**
 * The row Enter takes when nothing is highlighted.
 *
 * The first name match anywhere rather than simply the first row: the list
 * shows open conversations above friends, and an ID match up there is a
 * weaker answer than a friend whose name is what was typed.
 */
export function defaultSwitcherRow<T extends { name: string; hash: string }>(
  rows: T[],
  needle: string,
): T | undefined {
  return rows.find((row) => switcherMatch(row, needle) === 'name') ?? rows[0];
}
