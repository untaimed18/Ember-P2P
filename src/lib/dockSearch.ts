/**
 * How the chat dock's switcher decides what a query matches.
 *
 * Its own module, with tests, for the reason `dockWidth.ts` gives: the rule is
 * small, but it decides which conversation "type two letters, press Enter"
 * opens, and a rule that is wrong shows up as the wrong chat rather than as an
 * error.
 */
import { splitHighlights, type HighlightPart } from '$lib/highlight';

/** Below this a run of hex digits is far more likely to be part of a name —
 *  "de", "cafe", "bead" — than someone pasting an ID. */
const ID_QUERY_MIN = 8;
const ID_QUERY_RE = /^[0-9a-f]+$/;

/**
 * Lowercase with accents stripped, so "jose" finds "José".
 *
 * Only the combining diacriticals block (U+0300–U+036F) goes: every other mark
 * is part of the letter — Japanese dakuten, Indic and Thai vowel signs — and
 * stripping it turns one word into another. NFC afterwards puts back what NFD
 * took apart and nothing was stripped from.
 */
export function foldForSearch(text: string): string {
  return text.normalize('NFD').replace(/[\u0300-\u036f]/g, '').normalize('NFC').toLowerCase();
}

/**
 * `splitHighlights` matched the way `foldForSearch` matches, so a filter of
 * "jose" marks the "José" it found. Falls back to the plain case-insensitive
 * split when folding changes the text's length, since the folded positions
 * would then point at the wrong characters of the original.
 */
export function splitFoldedHighlights(text: string, terms: readonly string[]): HighlightPart[] {
  const folded = foldForSearch(text);
  if (folded.length !== text.length) return splitHighlights(text, terms);
  const parts = splitHighlights(folded, terms.map(foldForSearch));
  let at = 0;
  return parts.map((part) => {
    const original = text.slice(at, at + part.text.length);
    at += part.text.length;
    return { text: original, mark: part.mark };
  });
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
