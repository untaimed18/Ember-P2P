/** A run of text, and whether it matched a highlighted term. */
export type HighlightPart = { text: string; mark: boolean };

const OPERATORS = new Set(['AND', 'OR', 'NOT']);

/**
 * The words a query or result filter asks to find, lower-cased: quoted
 * phrases whole, the eD2K operators dropped, and nothing that was excluded
 * (`-word`, `-"a phrase"`, `NOT word`) — marking those would point at the very
 * thing the user asked to leave out.
 */
export function highlightTerms(...queries: string[]): string[] {
  const terms = new Set<string>();
  for (const query of queries) {
    let negateNext = false;
    for (const match of query.matchAll(/(-?)"([^"]*)"|(\S+)/g)) {
      const [, dash, phrase, word] = match;
      if (phrase !== undefined) {
        if (!dash && !negateNext) addTerm(terms, phrase);
        negateNext = false;
        continue;
      }
      if (word === 'NOT') {
        negateNext = true;
        continue;
      }
      if (OPERATORS.has(word)) continue;
      const bare = word.replace(/^\(+|\)+$/g, '');
      if (!bare.startsWith('-') && !negateNext) addTerm(terms, bare);
      negateNext = false;
    }
  }
  return [...terms];
}

function addTerm(terms: Set<string>, raw: string) {
  const term = raw.trim().toLowerCase();
  if (term.length >= 2) terms.add(term);
}

/** `text` split into marked and unmarked runs for every case-insensitive
 *  occurrence of `terms`. */
export function splitHighlights(text: string, terms: readonly string[]): HighlightPart[] {
  if (terms.length === 0 || !text) return [{ text, mark: false }];
  const lower = text.toLowerCase();
  // Lower-casing that changes the length (a few non-Latin letters) would put
  // the indexes on the wrong characters of the original.
  if (lower.length !== text.length) return [{ text, mark: false }];
  const ranges: [number, number][] = [];
  for (const term of terms) {
    for (let at = lower.indexOf(term); at !== -1; at = lower.indexOf(term, at + term.length)) {
      ranges.push([at, at + term.length]);
    }
  }
  if (ranges.length === 0) return [{ text, mark: false }];
  ranges.sort((a, b) => a[0] - b[0]);
  const parts: HighlightPart[] = [];
  let cursor = 0;
  let open: [number, number] | null = null;
  const flush = () => {
    if (!open) return;
    if (open[0] > cursor) parts.push({ text: text.slice(cursor, open[0]), mark: false });
    parts.push({ text: text.slice(open[0], open[1]), mark: true });
    cursor = open[1];
    open = null;
  };
  for (const [start, end] of ranges) {
    if (open && start <= open[1]) {
      open[1] = Math.max(open[1], end);
    } else {
      flush();
      open = [start, end];
    }
  }
  flush();
  if (cursor < text.length) parts.push({ text: text.slice(cursor), mark: false });
  return parts;
}
