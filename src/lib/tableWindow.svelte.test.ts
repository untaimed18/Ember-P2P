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
    querySelector: () => ({ getBoundingClientRect: () => ({ height: rowHeight }) }),
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
