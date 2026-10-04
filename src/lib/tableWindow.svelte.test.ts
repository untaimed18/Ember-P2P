import { afterEach, describe, expect, it } from 'vitest';
import { flushSync } from 'svelte';
import { TableWindow } from './tableWindow.svelte';

/** A scroller and table body standing in for the DOM: the body's top is
 *  `-scrollTop` from the scroller's, and every row is `rowHeight` tall. */
function fakeTable(rowHeight: number, viewportHeight: number) {
  const listeners = new Set<() => void>();
  const state = { scrollTop: 0 };
  const scroller = {
    clientHeight: viewportHeight,
    getBoundingClientRect: () => ({ top: 0 }),
    addEventListener: (_: string, fn: () => void) => listeners.add(fn),
    removeEventListener: (_: string, fn: () => void) => listeners.delete(fn),
  } as unknown as HTMLElement;
  const body = {
    isConnected: true,
    getBoundingClientRect: () => ({ top: -state.scrollTop }),
    querySelectorAll: () => [0, 1].map((i) => ({
      getBoundingClientRect: () => ({ top: i * rowHeight, bottom: (i + 1) * rowHeight }),
    })),
  } as unknown as HTMLTableSectionElement;
  return {
    scroller,
    body,
    scrollTo(top: number) {
      state.scrollTop = top;
      for (const fn of listeners) fn();
    },
    listenerCount: () => listeners.size,
  };
}

let cleanups: (() => void)[] = [];
afterEach(() => {
  for (const cleanup of cleanups) cleanup();
  cleanups = [];
});

function mount(total: () => number): TableWindow {
  let win: TableWindow | undefined;
  cleanups.push($effect.root(() => {
    win = new TableWindow(total, { minRows: 50, rowHeight: 20, rowSelector: 'tr' });
  }));
  flushSync();
  if (!win) throw new Error('the effect root did not run');
  return win;
}

describe('TableWindow', () => {
  it('renders a short list whole', () => {
    const win = mount(() => 40);
    expect(win.active).toBe(false);
    expect([win.start, win.end, win.topPad, win.bottomPad]).toEqual([0, 40, 0, 0]);
  });

  it('shows the first rows until the table is mounted', () => {
    const win = mount(() => 1000);
    expect([win.start, win.end]).toEqual([0, 50]);
  });

  it('follows the scroll of a long list, with spacers for the rest', () => {
    let total = $state(1000);
    const win = mount(() => total);
    const table = fakeTable(20, 200);
    win.scroller = table.scroller;
    win.body = table.body;
    flushSync();
    expect(table.listenerCount()).toBe(1);
    expect([win.start, win.end]).toEqual([0, 18]);

    table.scrollTo(4000);
    flushSync();
    expect([win.start, win.end]).toEqual([192, 218]);
    expect(win.topPad).toBe(192 * 20);
    expect(win.bottomPad).toBe((1000 - 218) * 20);
    expect(win.slice(Array.from({ length: 1000 }, (_, i) => i))[0]).toBe(192);

    // The list shrinks under a stale scroll position: its end stays in view.
    total = 100;
    flushSync();
    expect(win.end).toBe(100);
    expect(win.start).toBeLessThan(100);
  });

  it('settles when rows differ by a fraction of a pixel', () => {
    // Known peers with a nickname, or queued peers without a flag, can sit
    // half a pixel off the rest at 200% scaling. Here rows from 190 on are a
    // pixel taller: 4000px down, a 20px height puts row 192 first and a 21px
    // one row 182, so remeasuring after each window could swap between the
    // two for good.
    const heightOf = (i: number) => (i >= 190 ? 21 : 20);
    const state = { scrollTop: 0 };
    const listeners = new Set<() => void>();
    const scroller = {
      clientHeight: 200,
      getBoundingClientRect: () => ({ top: 0 }),
      addEventListener: (_: string, fn: () => void) => listeners.add(fn),
      removeEventListener: (_: string, fn: () => void) => listeners.delete(fn),
    } as unknown as HTMLElement;
    let win: TableWindow | undefined;
    const rendered = () => {
      const top = -state.scrollTop + (win?.topPad ?? 0);
      let y = top;
      return Array.from({ length: (win?.end ?? 0) - (win?.start ?? 0) }, (_, k) => {
        const height = heightOf((win?.start ?? 0) + k);
        const rect = { top: y, bottom: y + height, height };
        y += height;
        return { getBoundingClientRect: () => rect };
      });
    };
    const body = {
      isConnected: true,
      getBoundingClientRect: () => ({ top: -state.scrollTop }),
      querySelectorAll: () => rendered(),
    } as unknown as HTMLTableSectionElement;
    win = mount(() => 1000);
    win.scroller = scroller;
    win.body = body;
    flushSync();

    const scrollTo = (top: number) => {
      state.scrollTop = top;
      for (const fn of listeners) fn();
      flushSync();
    };
    expect(() => {
      for (let i = 0; i < 4; i++) scrollTo(4000);
    }).not.toThrow();
    const settled = [win.start, win.end];
    scrollTo(4000);
    expect([win.start, win.end]).toEqual(settled);
    expect(win.start).toBeLessThanOrEqual(4000 / 21);
    expect(win.end).toBeGreaterThan(4200 / 21);
  });

  it('scrolls a row outside the window into view and renders it at once', () => {
    const win = mount(() => 1000);
    const table = fakeTable(20, 200);
    let scrollTop = 0;
    Object.defineProperty(table.scroller, 'scrollTop', {
      get: () => scrollTop,
      set: (top: number) => {
        scrollTop = top;
        table.scrollTo(top);
      },
    });
    win.scroller = table.scroller;
    win.body = table.body;
    flushSync();

    win.reveal(500, 30);
    expect(scrollTop).toBe(501 * 20 - 200);
    expect(win.start).toBeLessThanOrEqual(500);
    expect(win.end).toBeGreaterThan(500);

    win.reveal(400, 30);
    expect(scrollTop).toBe(400 * 20 - 30);
    expect(win.start).toBeLessThanOrEqual(400);
    expect(win.end).toBeGreaterThan(400);

    win.reveal(401, 30);
    expect(scrollTop).toBe(400 * 20 - 30);
  });

  it('stops listening once its owner is gone', () => {
    const win = mount(() => 1000);
    const table = fakeTable(20, 200);
    win.scroller = table.scroller;
    win.body = table.body;
    flushSync();
    expect(table.listenerCount()).toBe(1);
    for (const cleanup of cleanups) cleanup();
    cleanups = [];
    expect(table.listenerCount()).toBe(0);
  });
});
