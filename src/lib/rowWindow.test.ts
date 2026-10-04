import { describe, expect, it } from 'vitest';
import { adoptRowHeight, computeRowWindow } from './rowWindow';

/** The search table's real numbers: 34px rows in a 680px scrollport. */
const base = { total: 15_000, bodyTop: 0, viewportHeight: 680, rowHeight: 34, overscan: 8 };

describe('computeRowWindow', () => {
  it('renders the first screenful plus overscan at the top', () => {
    // 680 / 34 = 20 rows fit; nothing has scrolled past, so there is no
    // overscan to add above.
    expect(computeRowWindow(base)).toEqual({ start: 0, end: 28 });
  });

  it('follows the rows that have scrolled past the top edge', () => {
    // 100 rows above the fold: 3400px of them.
    const window = computeRowWindow({ ...base, bodyTop: -3400 });

    expect(window).toEqual({ start: 92, end: 128 });
  });

  it('keeps the table unrendered while it is still below the fold', () => {
    // The table starts 200px down the scrollport, so row 0 is the first one
    // visible however far the content above it pushes it.
    expect(computeRowWindow({ ...base, bodyTop: 200 })).toEqual({ start: 0, end: 28 });
  });

  it('renders a bounded slice however long the list is', () => {
    const window = computeRowWindow({ ...base, total: 1_000_000, bodyTop: -340_000 });

    expect(window.end - window.start).toBeLessThan(50);
  });

  it('stops at the end of a list that shrank under the scroll position', () => {
    // What "Hide spam" does on every mark: the rows go away while the
    // scrollport stays where it was.
    const window = computeRowWindow({ ...base, total: 12, bodyTop: -3400 });

    expect(window.end).toBeLessThanOrEqual(12);
    // Non-empty, not merely ordered. `{ start: 12, end: 12 }` satisfied both
    // `start <= end` and `end <= 12`, and that is exactly the window this used
    // to return — twelve rows behind a 408px spacer, with nothing that would
    // re-measure until the user scrolled.
    expect(window.end).toBeGreaterThan(window.start);
    expect(window.start).toBeLessThan(12);
    // And the whole of what is left, not the last row alone: `{ start: 11,
    // end: 12 }` was one row behind the same spacer.
    expect(window).toEqual({ start: 0, end: 12 });
  });

  it('anchors a stale scroll past the end of a long list to its last screenful', () => {
    // 200 rows left, scrolled as though there were 500: the last 20 that fit,
    // plus overscan above them.
    const window = computeRowWindow({ ...base, total: 200, bodyTop: -500 * 34 });

    expect(window).toEqual({ start: 172, end: 200 });
  });

  it('renders nothing for an empty list', () => {
    expect(computeRowWindow({ ...base, total: 0 })).toEqual({ start: 0, end: 0 });
  });

  it('still renders rows before the container has been laid out', () => {
    // A zero viewport must not settle on an empty window: the row height is
    // measured from a rendered row, so an empty window cannot correct itself.
    const window = computeRowWindow({ ...base, viewportHeight: 0 });

    expect(window.end).toBeGreaterThan(0);
  });

  it('keeps the spacer height when a window is only a fraction of a pixel off', () => {
    // Two slices a scrollbar drag can land on: one a little over 34, one a
    // little under. Chasing either of them is the freeze.
    let height = 34;
    for (let n = 0; n < 8; n++) height = adoptRowHeight(height, n % 2 === 0 ? 34.4 : 33.7);
    expect(height).toBe(34);
  });

  it('follows a row height that actually changed', () => {
    // Zoom, or the first real measure after the 34px guess.
    expect(adoptRowHeight(34, 36)).toBe(36);
    expect(adoptRowHeight(34, 33)).toBe(33);
  });

  it('ignores a measurement the DOM should not have produced', () => {
    expect(adoptRowHeight(34, 0)).toBe(34);
    expect(adoptRowHeight(34, Number.NaN)).toBe(34);
    expect(adoptRowHeight(Number.NaN, 36)).toBe(36);
    expect(adoptRowHeight(Number.NaN, Number.NaN)).toBe(1);
  });

  it('survives measurements the DOM should never produce', () => {
    for (const rowHeight of [0, -34, Number.NaN, Number.POSITIVE_INFINITY]) {
      const window = computeRowWindow({ ...base, rowHeight });
      expect(window.start).toBeGreaterThanOrEqual(0);
      // A non-empty list always renders something, which is the promise the
      // module doc makes: an empty window cannot correct itself, because the row
      // height it would need is measured from a rendered row.
      expect(window.end).toBeGreaterThan(window.start);
      expect(window.end).toBeLessThanOrEqual(base.total);
    }
    expect(computeRowWindow({ ...base, bodyTop: Number.NaN }).start).toBe(0);
  });
});
