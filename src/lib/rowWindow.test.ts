import { describe, expect, it } from 'vitest';
import { computeRowWindow } from './rowWindow';

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

    expect(window.start).toBeLessThanOrEqual(window.end);
    expect(window.end).toBeLessThanOrEqual(12);
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

  it('survives measurements the DOM should never produce', () => {
    for (const rowHeight of [0, -34, Number.NaN, Number.POSITIVE_INFINITY]) {
      const window = computeRowWindow({ ...base, rowHeight });
      expect(window.start).toBeGreaterThanOrEqual(0);
      expect(window.end).toBeGreaterThanOrEqual(window.start);
      expect(window.end).toBeLessThanOrEqual(base.total);
    }
    expect(computeRowWindow({ ...base, bodyTop: Number.NaN }).start).toBe(0);
  });
});
