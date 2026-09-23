import { describe, expect, it } from 'vitest';
import {
  clampDockWidth,
  maxDockWidth,
  preferredDockWidth,
  DOCK_WIDTH_CAP,
  DOCK_WIDTH_DEFAULT,
  DOCK_WIDTH_MIN,
} from './dockWidth';

describe('maxDockWidth', () => {
  it('leaves something of the page beside the dock', () => {
    expect(maxDockWidth(1000)).toBe(900);
    expect(maxDockWidth(800)).toBe(720);
  });

  it('stops a side panel becoming the page on a wide monitor', () => {
    expect(maxDockWidth(3840)).toBe(DOCK_WIDTH_CAP);
  });

  // The floor wins over the share, or the range inverts and the clamp below
  // starts returning widths under the minimum.
  it('never reports a bound below the floor', () => {
    expect(maxDockWidth(200)).toBe(DOCK_WIDTH_MIN);
    expect(maxDockWidth(0)).toBe(DOCK_WIDTH_CAP);
    expect(maxDockWidth(Number.NaN)).toBe(DOCK_WIDTH_CAP);
  });
});

describe('clampDockWidth', () => {
  it('takes a width that already fits', () => {
    expect(clampDockWidth(560, 1600)).toBe(560);
  });

  it('holds both ends of a drag', () => {
    expect(clampDockWidth(40, 1600)).toBe(DOCK_WIDTH_MIN);
    expect(clampDockWidth(5000, 1600)).toBe(DOCK_WIDTH_CAP);
  });

  // The case that has no way back: a width stored on a wide monitor, reopened
  // on a narrow one, would cover the app with the handle off-screen.
  it('brings a width stored on a wider screen back into view', () => {
    expect(clampDockWidth(880, 700)).toBe(630);
  });

  it('falls back to the default when the stored value is unreadable', () => {
    expect(clampDockWidth(Number.NaN, 1600)).toBe(DOCK_WIDTH_DEFAULT);
    // ...and still respects a window too narrow to hold even that.
    expect(clampDockWidth(Number.NaN, 400)).toBe(360);
  });

  it('rounds, so a fractional pointer position cannot accumulate', () => {
    expect(clampDockWidth(560.4, 1600)).toBe(560);
    expect(clampDockWidth(560.6, 1600)).toBe(561);
  });

  it('never returns a width the panel cannot be used at', () => {
    for (const viewport of [0, 100, 320, 640, 1280, 2560]) {
      for (const asked of [-100, 0, 321, 900, 10_000]) {
        const width = clampDockWidth(asked, viewport);
        expect(width).toBeGreaterThanOrEqual(DOCK_WIDTH_MIN);
        expect(width).toBeLessThanOrEqual(DOCK_WIDTH_CAP);
      }
    }
  });
});

describe('preferredDockWidth', () => {
  // The window only limits what is drawn. A preference clamped on read would
  // be written back narrower the next time anything saved it.
  it('keeps a stored width the current window cannot show', () => {
    expect(preferredDockWidth('800')).toBe(800);
    expect(clampDockWidth(preferredDockWidth('800'), 700)).toBe(630);
    expect(clampDockWidth(preferredDockWidth('800'), 1600)).toBe(800);
  });

  it('still holds the absolute bounds', () => {
    expect(preferredDockWidth('10')).toBe(DOCK_WIDTH_MIN);
    expect(preferredDockWidth('5000')).toBe(DOCK_WIDTH_CAP);
  });

  it('falls back to the default for nothing or garbage', () => {
    expect(preferredDockWidth(null)).toBe(DOCK_WIDTH_DEFAULT);
    expect(preferredDockWidth('')).toBe(DOCK_WIDTH_DEFAULT);
    expect(preferredDockWidth('wide')).toBe(DOCK_WIDTH_DEFAULT);
  });
});
