import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { hoverSubmenus, SUBMENU_INTENT_MS } from './hoverSubmenus';

type Sub = 'priority' | 'category';

function setup() {
  let openSub: Sub | null = null;
  const subs = hoverSubmenus<Sub>(
    () => openSub,
    (which) => {
      openSub = which;
    },
  );
  return { subs, current: () => openSub };
}

describe('hoverSubmenus', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('opens a submenu as soon as the pointer reaches its item', () => {
    const { subs, current } = setup();
    subs.enter('priority');
    expect(current()).toBe('priority');
  });

  it('waits before closing, so the pointer can cross into the submenu', () => {
    const { subs, current } = setup();
    subs.enter('priority');
    subs.leave();
    vi.advanceTimersByTime(SUBMENU_INTENT_MS - 1);
    expect(current()).toBe('priority');
    // Reaching the submenu re-enters the element that holds it.
    subs.enter('priority');
    vi.advanceTimersByTime(SUBMENU_INTENT_MS * 2);
    expect(current()).toBe('priority');

    subs.leave();
    vi.advanceTimersByTime(SUBMENU_INTENT_MS);
    expect(current()).toBeNull();
  });

  it('switches to another item only if the pointer stays on it', () => {
    const { subs, current } = setup();
    subs.enter('priority');
    subs.enter('category');
    expect(current()).toBe('priority');
    subs.enter('priority');
    vi.advanceTimersByTime(SUBMENU_INTENT_MS);
    expect(current(), 'brushing past did not switch').toBe('priority');

    subs.enter('category');
    vi.advanceTimersByTime(SUBMENU_INTENT_MS);
    expect(current()).toBe('category');
  });

  it('opens on click without dismissing the menu, and leaves submenu items alone', () => {
    const { subs, current } = setup();
    // Stand-ins for the clicked element: `closest` answers whether it sits
    // inside a `.ctx-submenu`.
    const clickOn = (insideSubmenu: boolean) => ({
      target: { closest: (selector: string) => (selector === '.ctx-submenu' && insideSubmenu ? {} : null) },
      stopPropagation: vi.fn(),
    }) as unknown as MouseEvent;

    const onItem = clickOn(false);
    subs.click(onItem, 'category');
    expect(current()).toBe('category');
    expect(onItem.stopPropagation).toHaveBeenCalled();

    const onChoice = clickOn(true);
    subs.click(onChoice, 'priority');
    expect(current()).toBe('category');
    expect(onChoice.stopPropagation).not.toHaveBeenCalled();
  });

  it('cancel drops a pending close as the menu goes away', () => {
    const { subs, current } = setup();
    subs.enter('priority');
    subs.leave();
    subs.cancel();
    vi.advanceTimersByTime(SUBMENU_INTENT_MS * 2);
    expect(current()).toBe('priority');
  });
});
