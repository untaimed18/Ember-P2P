/**
 * What a search tab drops when it overflows.
 *
 * Its own module rather than a private helper in `stores/search.ts` for the
 * reason `searchQuery.ts` gives: the store imports `$app/environment`, so a test
 * process cannot load it, and a rule with no test drifts. This one is pure.
 */
import type { SearchResult } from '$lib/types';

/**
 * Trim an overflowing tab down to `keep` rows, shedding the weakest.
 *
 * "Weakest" is `availability` — the merged source count, so the rows dropped are
 * the ones no peer claims to have and a user can least act on — except that a
 * row flagged as spam ranks below every unflagged one whatever it claims.
 * Availability on a spam row is the one number a polluter controls and the one
 * it inflates, so ranking on it alone let fake hits evict the honest rows
 * underneath them, and the tab shed rows the user could see to keep rows
 * "Hide spam" hides. eMule discounts the same number for the same reason:
 * `CSearchList::AddResultCount` credits a spam result with at most 5 sources
 * however many it claims. But it is ranked
 * *within each origin class* rather than across the whole list, because an Ember
 * publisher count and an eD2K swarm estimate are not the same measurement. A
 * single numeric sort put every Ember row below every ordinary one: Ember counts
 * the distinct signed publishers of a record, which is a handful, while a KAD or
 * server row carries a swarm figure in the tens or hundreds. Overflow therefore
 * discarded the Ember rows first and completely — the rows least like the rest of
 * the list, and on a young overlay the only ones no other network could have
 * found.
 *
 * Ranking by position within a class sheds the weakest of each instead. Ember is
 * a small minority of any result set big enough to overflow, so in practice it
 * survives whole and the cost is a few of the ordinary rows it displaces.
 *
 * Mutates `results` in place, because the caller has just built it.
 */
export function shedWeakestRows(results: SearchResult[], keep: number): void {
  if (results.length <= keep) return;
  // Strongest first: unflagged ahead of flagged, then by claimed sources.
  // Availability still orders the flagged rows among themselves, so if a tab
  // is so polluted that only spam is left to keep, the least implausible of it
  // survives.
  const strongerFirst = (a: SearchResult, b: SearchResult) =>
    (a.is_spam ? 1 : 0) - (b.is_spam ? 1 : 0) || (b.availability || 0) - (a.availability || 0);
  const isEmber = (r: SearchResult) => (r.result_origin || '').includes('Ember');
  // Indices rather than sorting the objects twice. `sort` is stable, so equal
  // strength keeps the earlier-seen hit inside each class.
  const rank = new Map<number, number>();
  for (const wantEmber of [true, false]) {
    const members: number[] = [];
    for (let i = 0; i < results.length; i++) {
      if (isEmber(results[i]) === wantEmber) members.push(i);
    }
    members.sort((a, b) => strongerFirst(results[a], results[b]));
    members.forEach((idx, position) => rank.set(idx, position));
  }
  const ordered = results
    .map((row, i) => ({ row, rank: rank.get(i) ?? 0 }))
    .sort((a, b) => a.rank - b.rank || strongerFirst(a.row, b.row));
  for (let i = 0; i < keep; i++) results[i] = ordered[i].row;
  results.length = keep;
}
