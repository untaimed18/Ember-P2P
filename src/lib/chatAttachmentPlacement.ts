/**
 * Where chat attachments sit among the messages of a transcript.
 *
 * Its own module, with tests, because the rule has edges that are easy to get
 * wrong in a component: a file and a message in the same second, and history
 * that has not been loaded yet. Attachments are placed at draw time rather than
 * merged into the message rows, which carry run grouping, day separators and a
 * cache keyed on message ids an attachment does not have.
 */

export interface PlacementRow {
  id: number;
  /** Unix seconds; 0 means unknown. */
  timestamp: number;
}

export interface Placement<A> {
  /** Attachments to draw immediately before the row with this id. */
  before: Map<number, A[]>;
  /** Attachments newer than every row, drawn after the last one. */
  after: A[];
  /** How many attachments are shown at all. */
  count: number;
}

/**
 * Place each attachment before the first row strictly newer than it, or after
 * the last row.
 *
 * "Strictly newer", so a file sent in the same second as a message lands after
 * it — the message was almost always typed first, and the alternative puts a
 * reply's attachment above the line that introduced it.
 *
 * While `hasMoreHistory`, a file older than the oldest loaded row belongs with
 * history that is not on screen yet and is held back until "Load older" brings
 * it in; otherwise every old file would pile up at the top of a transcript that
 * starts yesterday. Rows with no timestamp are passed over, so an undated row
 * can neither swallow nor strand a file.
 */
export function placeAttachments<A extends { created_at: number }>(
  rows: readonly PlacementRow[],
  attachments: readonly A[],
  hasMoreHistory: boolean,
): Placement<A> {
  const before = new Map<number, A[]>();
  const after: A[] = [];
  if (attachments.length === 0) return { before, after, count: 0 };

  const dated = rows.filter((r) => r.timestamp > 0);
  const oldest = dated.length > 0 ? dated[0].timestamp : 0;
  const shown = attachments
    .filter((a) => !(hasMoreHistory && oldest > 0 && a.created_at < oldest))
    .slice()
    .sort((a, b) => a.created_at - b.created_at);

  let i = 0;
  for (const a of shown) {
    while (i < dated.length && dated[i].timestamp <= a.created_at) i++;
    if (i < dated.length) {
      const id = dated[i].id;
      const bucket = before.get(id);
      if (bucket) bucket.push(a);
      else before.set(id, [a]);
    } else {
      after.push(a);
    }
  }
  return { before, after, count: shown.length };
}
