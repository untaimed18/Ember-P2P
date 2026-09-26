import type { Action } from 'svelte/action';

/**
 * Where ←/→/Home/End move focus in a row of `count` controls, or null for keys
 * the row leaves alone. Arrows wrap, and follow the reading direction.
 */
export function toolbarMove(index: number, key: string, count: number, rtl = false): number | null {
  if (count <= 0) return null;
  const forward = rtl ? 'ArrowLeft' : 'ArrowRight';
  const back = rtl ? 'ArrowRight' : 'ArrowLeft';
  switch (key) {
    case forward:
      return index >= count - 1 ? 0 : index + 1;
    case back:
      return index <= 0 ? count - 1 : index - 1;
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    default:
      return null;
  }
}

/**
 * One tab stop for a row of buttons, with the arrow keys moving along it: the
 * ARIA toolbar pattern, for a node with `role="toolbar"`.
 *
 * Read from the DOM rather than handed a list, because the buttons come and go
 * with what a line allows at the moment (Reply, Pin, Edit, a busy Remove). The
 * one last focused keeps the tab stop while it is there and enabled; otherwise
 * the first does, so the row is never left without one.
 */
export const rovingToolbar: Action<HTMLElement> = (node) => {
  let current: HTMLButtonElement | null = null;

  const buttons = () => Array.from(node.querySelectorAll<HTMLButtonElement>('button'));
  const enabled = () => buttons().filter((b) => !b.disabled);

  const sync = () => {
    const usable = enabled();
    if (!current || !usable.includes(current)) current = usable[0] ?? null;
    for (const b of buttons()) {
      const tabIndex = b === current ? 0 : -1;
      if (b.tabIndex !== tabIndex) b.tabIndex = tabIndex;
    }
  };

  const onFocusIn = (e: FocusEvent) => {
    const target = e.target;
    if (target instanceof HTMLButtonElement && node.contains(target)) {
      current = target;
      sync();
    }
  };

  const onKeyDown = (e: KeyboardEvent) => {
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const usable = enabled();
    const at = current ? usable.indexOf(current) : -1;
    const rtl = getComputedStyle(node).direction === 'rtl';
    const next = toolbarMove(Math.max(0, at), e.key, usable.length, rtl);
    if (next === null) return;
    e.preventDefault();
    usable[next]?.focus();
  };

  // `disabled` as well as the children: a button that disables while holding
  // the tab stop would otherwise leave the row with none.
  const observer = new MutationObserver(sync);
  observer.observe(node, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled'] });
  node.addEventListener('focusin', onFocusIn);
  node.addEventListener('keydown', onKeyDown);
  sync();

  return {
    destroy() {
      observer.disconnect();
      node.removeEventListener('focusin', onFocusIn);
      node.removeEventListener('keydown', onKeyDown);
    },
  };
};
