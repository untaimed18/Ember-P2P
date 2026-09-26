import { describe, expect, it } from 'vitest';
import { computeSegmentWindow, segmentRowOffset } from './segmentWindow';

const base = { rowHeight: 20, viewportHeight: 200, overscan: 2 };

/** Pads plus the rendered rows' own heights must always equal the section's
 *  height, or the scrollbar jumps as the window moves. */
function renderedHeight(
  w: { start: number; end: number; topPad: number; bottomPad: number },
  h: number,
  e = -1,
  x = 0,
) {
  const rows = (w.end - w.start) * h + (e >= w.start && e < w.end ? x : 0);
  return w.topPad + rows + w.bottomPad;
}

describe('computeSegmentWindow', () => {
  it('renders a short section whole', () => {
    expect(computeSegmentWindow({ ...base, total: 5, bodyTop: 0, minRows: 10 })).toEqual({
      start: 0,
      end: 5,
      topPad: 0,
      bottomPad: 0,
    });
  });

  it('renders the visible slice plus overscan', () => {
    const w = computeSegmentWindow({ ...base, total: 1000, bodyTop: -400 });
    // Rows 20..29 are on screen.
    expect(w.start).toBe(18);
    expect(w.end).toBe(32);
    expect(w.topPad).toBe(18 * 20);
    expect(renderedHeight(w, 20)).toBe(1000 * 20);
  });

  it('accounts for an expanded row above the window', () => {
    const w = computeSegmentWindow({
      ...base,
      total: 1000,
      bodyTop: -(400 + 300),
      expandedIndex: 3,
      expandedExtra: 300,
    });
    expect(w.start).toBe(18);
    expect(w.topPad).toBe(18 * 20 + 300);
    expect(renderedHeight(w, 20, 3, 300)).toBe(1000 * 20 + 300);
  });

  it('keeps the expanded row rendered while its block is on screen', () => {
    // Scrolled into the middle of row 3's 300px block.
    const w = computeSegmentWindow({
      ...base,
      total: 1000,
      bodyTop: -(4 * 20 + 150),
      expandedIndex: 3,
      expandedExtra: 300,
    });
    expect(w.start).toBeLessThanOrEqual(3);
    expect(w.end).toBeGreaterThan(3);
    expect(renderedHeight(w, 20, 3, 300)).toBe(1000 * 20 + 300);
  });

  it('renders only overscan for a section below or above the viewport', () => {
    const below = computeSegmentWindow({ ...base, total: 500, bodyTop: 250 });
    expect(below).toEqual({ start: 0, end: 2, topPad: 0, bottomPad: 498 * 20 });
    const above = computeSegmentWindow({ ...base, total: 500, bodyTop: -20_000 });
    expect(above.start).toBe(498);
    expect(above.end).toBe(500);
    expect(renderedHeight(above, 20)).toBe(500 * 20);
  });

  it('never renders nothing for a section that is on screen', () => {
    const w = computeSegmentWindow({ total: 50, bodyTop: 0, viewportHeight: 0, rowHeight: 0, overscan: 0 });
    expect(w.end - w.start).toBeGreaterThan(0);
  });
});

describe('segmentRowOffset', () => {
  it('shifts rows after the expanded one by its block', () => {
    expect(segmentRowOffset(3, 20, 3, 100)).toBe(60);
    expect(segmentRowOffset(4, 20, 3, 100)).toBe(180);
    expect(segmentRowOffset(4, 20)).toBe(80);
  });
});
