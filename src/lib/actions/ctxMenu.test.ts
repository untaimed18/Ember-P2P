import { describe, expect, it } from 'vitest';
import { resolveMenuPlacement, resolveSubmenuPlacement } from './ctxMenu';

/** A 1280x800 window, the size these menus are usually opened in. */
const view = { width: 1280, height: 800 };

describe('resolveMenuPlacement', () => {
  it('opens down-right of the pointer when there is room', () => {
    const at = resolveMenuPlacement({ x: 400, y: 300 }, { width: 220, height: 260 }, view);
    expect(at).toEqual({ left: 400, top: 300, maxHeight: null });
  });

  it('flips above the pointer instead of running off the bottom', () => {
    // The bug this guards: a menu opened 60px from the bottom edge used to be
    // placed at the pointer and lose everything below the fold.
    const at = resolveMenuPlacement({ x: 400, y: 740 }, { width: 220, height: 260 }, view);
    expect(at.top).toBe(480);
    expect(at.top + 260).toBeLessThanOrEqual(view.height);
    expect(at.maxHeight).toBeNull();
  });

  it('flips left instead of running off the right edge', () => {
    const at = resolveMenuPlacement({ x: 1200, y: 300 }, { width: 220, height: 260 }, view);
    expect(at.left).toBe(980);
    expect(at.left + 220).toBeLessThanOrEqual(view.width);
  });

  it('flips on both axes at once in the bottom-right corner', () => {
    const at = resolveMenuPlacement({ x: 1270, y: 790 }, { width: 220, height: 260 }, view);
    expect(at).toEqual({ left: 1050, top: 530, maxHeight: null });
  });

  it('keeps the margin when neither side has room', () => {
    const narrow = { width: 200, height: 800 };
    const at = resolveMenuPlacement({ x: 150, y: 300 }, { width: 220, height: 260 }, narrow);
    expect(at.left).toBe(8);
  });

  it('scrolls a menu taller than the viewport rather than cropping it', () => {
    const at = resolveMenuPlacement({ x: 400, y: 300 }, { width: 220, height: 900 }, view);
    expect(at.maxHeight).toBe(784);
    expect(at.top).toBe(8);
  });

  it('never places a panel above or left of the margin', () => {
    for (const y of [0, 5, 400, 799, 2000]) {
      for (const x of [0, 5, 640, 1279, 4000]) {
        const at = resolveMenuPlacement({ x, y }, { width: 220, height: 260 }, view);
        expect(at.left).toBeGreaterThanOrEqual(8);
        expect(at.top).toBeGreaterThanOrEqual(8);
      }
    }
  });
});

describe('resolveSubmenuPlacement', () => {
  /** Anchor row of a menu opened at (x, y); rows are ~26px tall, panels ~210 wide. */
  function row(x: number, y: number) {
    return { left: x, right: x + 210, top: y, bottom: y + 26 };
  }

  it('unfolds down-right from a menu in the middle of the screen', () => {
    const at = resolveSubmenuPlacement(row(400, 300), { width: 170, height: 190 }, view);
    expect(at).toEqual({ flipLeft: false, flipUp: false, maxHeight: null });
  });

  it('unfolds to the left when the right side cannot hold it', () => {
    const at = resolveSubmenuPlacement(row(1000, 300), { width: 170, height: 190 }, view);
    expect(at.flipLeft).toBe(true);
  });

  it('rises from the item when there is no room below', () => {
    const at = resolveSubmenuPlacement(row(400, 700), { width: 170, height: 190 }, view);
    expect(at.flipUp).toBe(true);
    expect(at.maxHeight).toBeNull();
  });

  it('scrolls when neither direction can show it whole', () => {
    const short = { width: 1280, height: 220 };
    const at = resolveSubmenuPlacement(row(400, 120), { width: 170, height: 190 }, short);
    expect(at.maxHeight).not.toBeNull();
    expect(at.maxHeight!).toBeLessThan(190);
  });

  it('prefers the default side on a tie rather than flipping unpredictably', () => {
    // Equal room on both sides: stay down-right.
    const anchor = { left: 400, right: 880, top: 300, bottom: 508 };
    const centered = { width: 1288, height: 816 };
    const at = resolveSubmenuPlacement(anchor, { width: 500, height: 500 }, centered);
    expect(at.flipLeft).toBe(false);
    expect(at.flipUp).toBe(false);
  });
});
