/**
 * Which slice of a long list a windowed table actually renders.
 *
 * Its own module, with tests, for the reason `searchOverflow.ts` gives: the
 * arithmetic is small but every term of it is a chance to render the wrong
 * rows — and a windowing bug shows up as blank space or a row that will not
 * scroll into view, not as an exception. The caller owns the measuring (it is
 * the only side that can read the DOM); this owns the rule.
 */

/** Rows to keep mounted beyond each edge of the viewport, so a scroll of a
 *  frame or two is already rendered when it lands. */
export const DEFAULT_ROW_OVERSCAN = 8;

export type RowWindow = {
  /** First row index to render. */
  start: number;
  /** One past the last row index to render. */
  end: number;
};

export type RowWindowInput = {
  /** Rows in the whole list, not in the window. */
  total: number;
  /**
   * Offset of row 0 from the top of the scrollport, in pixels.
   *
   * Measured rather than assumed because the table is not the only thing in
   * its scroll container — banners, the results bar and the bulk toolbar sit
   * above it and scroll with it. Positive while the first row is still below
   * the top edge, negative once it has scrolled past.
   */
  bodyTop: number;
  /** Visible height of the scrollport. */
  viewportHeight: number;
  /** Height of one row. Measured from a rendered row, so it tracks font size
   *  and zoom rather than trusting a constant. */
  rowHeight: number;
  overscan?: number;
};

/**
 * Total, because the inputs come from the DOM: a container that has not been
 * laid out yet reports zero, a detached one can report anything, and none of
 * those may produce a window that renders nothing forever — the row height is
 * measured from a rendered row, so a window that is empty when it should not
 * be cannot correct itself.
 */
export function computeRowWindow({
  total,
  bodyTop,
  viewportHeight,
  rowHeight,
  overscan = DEFAULT_ROW_OVERSCAN,
}: RowWindowInput): RowWindow {
  if (!Number.isFinite(total) || total <= 0) return { start: 0, end: 0 };
  const height = Number.isFinite(rowHeight) && rowHeight > 0 ? rowHeight : 1;
  const above = Number.isFinite(bodyTop) ? Math.max(0, -bodyTop) : 0;
  const visible = Number.isFinite(viewportHeight) ? Math.max(0, viewportHeight) : 0;
  const pad = Number.isFinite(overscan) ? Math.max(0, Math.trunc(overscan)) : 0;

  const firstVisible = Math.floor(above / height);
  const fits = Math.ceil(visible / height);
  // `start` is clamped to the last row that exists, not to `total`, and `end` to
  // at least one row past it. A stale scroll position — the list shrank under
  // the user, which "Hide spam" does on every mark — otherwise asked for a slice
  // beginning at or past the end: `{ total: 12, bodyTop: -3400 }` returned
  // `{ start: 12, end: 12 }`, which renders no rows at all behind a spacer as
  // tall as the list used to be. Nothing here recovers from that on its own, and
  // the caller cannot either: the row height is measured from a rendered row, and
  // the only event that would re-run this is a scroll the user has no reason to
  // make. Whether it healed came down to whether the browser happened to clamp
  // `scrollTop` and fire a scroll event for it.
  const start = Math.max(0, Math.min(firstVisible - pad, total - 1));
  const end = Math.min(total, Math.max(start + 1, firstVisible + fits + pad));
  return { start, end };
}
