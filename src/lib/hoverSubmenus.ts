/**
 * Hover intent for context-menu submenus, shared so every menu opens them the
 * same way: on hover, on click, and from the keyboard.
 *
 * The path from a parent item to its submenu crosses the gap beside the item
 * and often clips a neighbouring item, or the list underneath when the menu
 * sits near an edge. Closing on the first `mouseleave` snapped the submenu
 * shut on the way to it, so leaving waits a moment, reaching the submenu (a
 * descendant of the element carrying the handlers, so it never leaves it)
 * cancels that, and brushing past another parent item only switches to it if
 * the pointer stays there.
 */

/** How long a submenu waits before closing, or before another replaces it. */
export const SUBMENU_INTENT_MS = 300;

export interface HoverSubmenus<T extends string> {
  /** Open `which` now, or close every submenu with `null`. */
  open(which: T | null): void;
  /** The pointer entered the element holding `which`'s item and submenu. */
  enter(which: T): void;
  /** The pointer left it. */
  leave(): void;
  /** A click on the parent item opens its submenu. Without stopping it here
   *  the click reached the handler that dismisses the whole menu. Clicks on
   *  the submenu's own items are left alone: they run their action. */
  click(e: Pick<MouseEvent, 'target' | 'stopPropagation'>, which: T): void;
  /** Drop a pending open or close, as the menu itself closes. */
  cancel(): void;
}

/**
 * `current` reads which submenu is open; `apply` opens one (or none) — it
 * should close every other, since only one is open at a time.
 */
export function hoverSubmenus<T extends string>(
  current: () => T | null,
  apply: (which: T | null) => void,
): HoverSubmenus<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const open = (which: T | null) => {
    clearTimeout(timer);
    apply(which);
  };
  return {
    open,
    enter(which) {
      clearTimeout(timer);
      const now = current();
      if (now === null || now === which) open(which);
      else timer = setTimeout(() => open(which), SUBMENU_INTENT_MS);
    },
    leave() {
      clearTimeout(timer);
      timer = setTimeout(() => open(null), SUBMENU_INTENT_MS);
    },
    click(e, which) {
      const target = e.target as { closest?: (selector: string) => unknown } | null;
      if (typeof target?.closest === 'function' && target.closest('.ctx-submenu')) return;
      e.stopPropagation();
      open(which);
    },
    cancel() {
      clearTimeout(timer);
    },
  };
}
