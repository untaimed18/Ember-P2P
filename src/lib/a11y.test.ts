import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { inertDuringOutro, swallowKeyboardContextMenu } from './a11y';

describe('inertDuringOutro', () => {
  it('makes the dialog that is fading out inert', () => {
    const dialog = { inert: false } as HTMLElement;
    inertDuringOutro({ currentTarget: dialog } as unknown as Event);
    expect(dialog.inert).toBe(true);
  });
});

/** Unit tests run without a DOM; an `EventTarget` stands in for `window`. */
let win: EventTarget;

function fireContextMenu(): boolean {
  const event = new Event('contextmenu', { cancelable: true });
  win.dispatchEvent(event);
  return event.defaultPrevented;
}

describe('swallowKeyboardContextMenu', () => {
  beforeEach(() => {
    win = new EventTarget();
    vi.stubGlobal('window', win);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('cancels the one contextmenu that follows the key, and no other', () => {
    swallowKeyboardContextMenu();
    expect(fireContextMenu()).toBe(true);
    expect(fireContextMenu()).toBe(false);
  });

  it('lapses when no contextmenu comes', () => {
    vi.useFakeTimers();
    swallowKeyboardContextMenu(1000);
    vi.advanceTimersByTime(1000);
    expect(fireContextMenu()).toBe(false);
  });
});
