import type { Action } from 'svelte/action';

// Viewport-aware placement for right-click context menus.
//
// Every menu used to be clamped against a guessed panel size at open time
// (`Math.min(e.clientY, window.innerHeight - 300 - margin)`), with a different
// guess per menu. Any item added to a menu — or a longer translation, or a
// header — made the guess too small and the bottom of the panel fell off the
// screen, silently and only near an edge. The actions below measure the panel
// that actually rendered, so the size can never drift out of sync with the
// markup, and hand the numbers to the pure helpers above them (which is where
// the geometry is unit-tested).

const MARGIN = 8;

export interface CtxMenuAnchor {
  /** Pointer position the menu should open from, in client coordinates. */
  x: number;
  y: number;
}

export interface Box {
  width: number;
  height: number;
}

export interface MenuPlacement {
  left: number;
  top: number;
  /** Set only when the panel cannot fit on screen at its natural height. */
  maxHeight: number | null;
}

/**
 * Places a panel at a pointer position: down-right of the pointer, flipped to
 * the opposite side when there is no room, clamped to the margin as a last
 * resort. A panel taller than the viewport gets a `maxHeight` to scroll in,
 * since no placement can make it fit.
 */
export function resolveMenuPlacement(
  anchor: CtxMenuAnchor,
  menu: Box,
  view: Box,
  margin = MARGIN,
): MenuPlacement {
  let left = anchor.x;
  if (left + menu.width > view.width - margin) left = anchor.x - menu.width;
  left = Math.min(Math.max(margin, left), Math.max(margin, view.width - menu.width - margin));

  const fits = view.height - margin * 2;
  const maxHeight = menu.height > fits ? fits : null;
  const height = maxHeight ?? menu.height;

  let top = anchor.y;
  if (top + height > view.height - margin) top = anchor.y - height;
  top = Math.min(Math.max(margin, top), Math.max(margin, view.height - height - margin));

  return { left, top, maxHeight };
}

export interface SubmenuAnchorRect {
  top: number;
  bottom: number;
  left: number;
  right: number;
}

export interface SubmenuPlacement {
  flipLeft: boolean;
  flipUp: boolean;
  maxHeight: number | null;
}

/**
 * Picks the side a submenu unfolds towards. It hangs down-right of its parent
 * item by default and flips only when the other side has strictly more room,
 * so a menu in the middle of the screen always unfolds the same predictable
 * way. Scrolls when neither side can show it whole.
 */
export function resolveSubmenuPlacement(
  anchor: SubmenuAnchorRect,
  menu: Box,
  view: Box,
  margin = MARGIN,
): SubmenuPlacement {
  // `left: 100%` puts the panel just past the anchor's right edge; the flipped
  // rule mirrors it to just before the left edge.
  const roomRight = view.width - margin - anchor.right;
  const roomLeft = anchor.left - margin;
  const flipLeft = menu.width > roomRight && roomLeft > roomRight;

  // Vertically the panel hangs from the anchor's top edge, or rises from its
  // bottom edge when flipped up.
  const roomDown = view.height - margin - anchor.top;
  const roomUp = anchor.bottom - margin;
  const flipUp = menu.height > roomDown && roomUp > roomDown;

  const room = flipUp ? roomUp : roomDown;
  return { flipLeft, flipUp, maxHeight: menu.height > room ? Math.max(0, room) : null };
}

/**
 * Positions a `position: fixed` menu panel at a pointer location, keeping it
 * on screen. The action owns `left`/`top`, so the element must not also set
 * them inline.
 */
export const ctxMenuPosition: Action<HTMLElement, CtxMenuAnchor> = (node, anchor) => {
  let current = anchor;

  function place(next: CtxMenuAnchor) {
    current = next;

    // Measure at the natural size: a max-height left behind by an earlier
    // placement would otherwise read as the panel's real height and let the
    // menu keep shrinking each time it reopens near an edge.
    node.style.maxHeight = '';
    node.style.overflowY = '';

    // offsetWidth/offsetHeight are untransformed layout sizes.
    // getBoundingClientRect() would report the entrance scale animation
    // mid-flight and place the menu a few px off.
    const placement = resolveMenuPlacement(
      next,
      { width: node.offsetWidth, height: node.offsetHeight },
      { width: window.innerWidth, height: window.innerHeight },
    );

    if (placement.maxHeight !== null) {
      node.style.maxHeight = `${placement.maxHeight}px`;
      node.style.overflowY = 'auto';
    }
    node.style.left = `${placement.left}px`;
    node.style.top = `${placement.top}px`;
  }

  const reflow = () => place(current);
  place(anchor);
  window.addEventListener('resize', reflow);

  return {
    update: place,
    destroy() {
      window.removeEventListener('resize', reflow);
    },
  };
};

/**
 * Flips a submenu towards whichever side has room, via the
 * `.ctx-submenu-left` / `.ctx-submenu-up` rules in app.css. Apply to the
 * submenu panel itself; its parent element is the anchor.
 */
export const ctxSubmenuPlacement: Action<HTMLElement> = (node) => {
  function place() {
    node.classList.remove('ctx-submenu-left', 'ctx-submenu-up');
    node.style.maxHeight = '';
    node.style.overflowY = '';

    const anchor = node.parentElement?.getBoundingClientRect();
    if (!anchor) return;
    const placement = resolveSubmenuPlacement(
      anchor,
      { width: node.offsetWidth, height: node.offsetHeight },
      { width: window.innerWidth, height: window.innerHeight },
    );

    node.classList.toggle('ctx-submenu-left', placement.flipLeft);
    node.classList.toggle('ctx-submenu-up', placement.flipUp);
    if (placement.maxHeight !== null) {
      node.style.maxHeight = `${placement.maxHeight}px`;
      node.style.overflowY = 'auto';
    }
  }

  place();
  window.addEventListener('resize', place);

  return {
    destroy() {
      window.removeEventListener('resize', place);
    },
  };
};
