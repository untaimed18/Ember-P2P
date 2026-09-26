/**
 * Which rows of one section of a windowed table to render, for a section that
 * shares its scroll container with other content and may have one row
 * expanded into a block of detail rows.
 *
 * The Transfers downloads table is two such sections — in-progress rows, then
 * the Completed/Failed ones — under a single header, and the in-progress row
 * whose sources are open is followed by a variable number of child rows. So
 * unlike `rowWindow.ts` the rows are not all one height: exactly one of them
 * carries `expandedExtra` pixels below it. The caller measures (row height,
 * the expanded block, where the section starts); this owns the arithmetic.
 */

import { DEFAULT_ROW_OVERSCAN } from '$lib/rowWindow';

export type SegmentWindow = {
  /** First row index to render. */
  start: number;
  /** One past the last row index to render. */
  end: number;
  /** Height standing in for rows `[0, start)`. */
  topPad: number;
  /** Height standing in for rows `[end, total)`. */
  bottomPad: number;
};

export type SegmentWindowInput = {
  total: number;
  /** Offset of row 0's top from the top of the scrollport; negative once it
   *  has scrolled past. */
  bodyTop: number;
  viewportHeight: number;
  rowHeight: number;
  /** Row followed by the detail block, or -1. */
  expandedIndex?: number;
  /** Height of that block, not counting the row itself. */
  expandedExtra?: number;
  overscan?: number;
  /** Sections this short are rendered whole. */
  minRows?: number;
};

function sanitize(input: SegmentWindowInput) {
  const total = Number.isFinite(input.total) ? Math.max(0, Math.trunc(input.total)) : 0;
  const rowHeight =
    Number.isFinite(input.rowHeight) && input.rowHeight > 0 ? input.rowHeight : 1;
  const e = input.expandedIndex ?? -1;
  const expandedIndex = Number.isInteger(e) && e >= 0 && e < total ? e : -1;
  const x = input.expandedExtra ?? 0;
  const expandedExtra = expandedIndex >= 0 && Number.isFinite(x) && x > 0 ? x : 0;
  return { total, rowHeight, expandedIndex, expandedExtra };
}

/** Top of row `index` measured from the top of the section. */
export function segmentRowOffset(
  index: number,
  rowHeight: number,
  expandedIndex = -1,
  expandedExtra = 0,
): number {
  const extra = expandedIndex >= 0 && index > expandedIndex ? expandedExtra : 0;
  return index * rowHeight + extra;
}

export function computeSegmentWindow(input: SegmentWindowInput): SegmentWindow {
  const { total, rowHeight: h, expandedIndex: e, expandedExtra: x } = sanitize(input);
  const height = segmentRowOffset(total, h, e, x);
  const minRows = input.minRows ?? 0;
  if (total === 0) return { start: 0, end: 0, topPad: 0, bottomPad: 0 };
  if (total <= minRows) return { start: 0, end: total, topPad: 0, bottomPad: 0 };

  const bodyTop = Number.isFinite(input.bodyTop) ? input.bodyTop : 0;
  const viewport = Number.isFinite(input.viewportHeight) ? Math.max(0, input.viewportHeight) : 0;
  const pad = Number.isFinite(input.overscan ?? DEFAULT_ROW_OVERSCAN)
    ? Math.max(0, Math.trunc(input.overscan ?? DEFAULT_ROW_OVERSCAN))
    : 0;

  // Pixel offsets within the section of the viewport's top and bottom edges.
  const fromY = Math.max(0, -bodyTop);
  const toY = viewport - bodyTop;
  const blockStart = e >= 0 ? (e + 1) * h : Infinity;
  const indexAt = (y: number) => {
    if (y < blockStart) return Math.floor(y / h);
    if (y < blockStart + x) return e;
    return Math.floor((y - x) / h);
  };

  let start: number;
  let end: number;
  if (toY <= 0 && bodyTop > 0) {
    // Entirely below the viewport: only the overscan at its top edge.
    start = 0;
    end = Math.min(total, pad);
  } else if (fromY >= height) {
    // Entirely above it: only the overscan at its bottom edge.
    start = Math.max(0, total - pad);
    end = total;
  } else {
    const first = Math.min(total - 1, indexAt(fromY));
    const last = Math.min(total - 1, indexAt(Math.max(fromY, toY - 1e-6)));
    start = Math.max(0, first - pad);
    end = Math.min(total, Math.max(start + 1, last + 1 + pad));
  }
  const topPad = segmentRowOffset(start, h, e, x);
  const bottomPad = Math.max(0, height - segmentRowOffset(end, h, e, x));
  return { start, end, topPad, bottomPad };
}
