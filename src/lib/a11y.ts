// Shared accessibility helpers for modal dialogs.

/**
 * Make every element *outside* the modal overlay's ancestor chain `inert`, so
 * assistive tech and Tab focus can't reach background content while a modal is
 * open. Returns a cleanup that restores only the attributes this call added.
 *
 * Why the ancestor walk instead of "inert every `document.body` child except
 * the overlay's container": dialogs in this app are frequently rendered *inside*
 * the page tree (a `ConfirmDialog` mounted within `.app-shell`, or About/Shortcut
 * dialogs nested inside the sidebar). The naive body-children approach skipped
 * whichever child *contained* the overlay (i.e. `.app-shell`), so nothing behind
 * the dialog ever actually became inert. Walking up from the overlay to `<body>`
 * and inerting each level's *siblings* makes the background inert without moving
 * the node out of its Svelte-managed parent (which would break transitions).
 */
// Per-element count of how many open modals have inerted each element. Lets
// stacked/overlapping modals share the same background siblings without one
// modal's cleanup un-inerting siblings another modal still needs: `inert` is
// only set when the count goes 0 → 1 and only removed when it falls back to 0.
const inertRefCounts = new WeakMap<Element, number>();

export function inertBackground(overlay: Element | null | undefined): () => void {
  if (!overlay || typeof document === 'undefined') return () => {};
  const managed: Element[] = [];
  let node: Element = overlay;
  while (node.parentElement) {
    const parent = node.parentElement;
    for (const sibling of Array.from(parent.children)) {
      if (sibling === node) continue;
      const count = inertRefCounts.get(sibling) ?? 0;
      // Leave a pre-existing `inert` we didn't set (count 0 + attribute
      // already present) untouched so we never clear someone else's inert.
      if (count === 0 && sibling.hasAttribute('inert')) continue;
      if (count === 0) sibling.setAttribute('inert', '');
      inertRefCounts.set(sibling, count + 1);
      managed.push(sibling);
    }
    if (parent === document.body) break;
    node = parent;
  }
  return () => {
    for (const el of managed) {
      const next = (inertRefCounts.get(el) ?? 1) - 1;
      if (next <= 0) {
        inertRefCounts.delete(el);
        el.removeAttribute('inert');
      } else {
        inertRefCounts.set(el, next);
      }
    }
  };
}

/**
 * Standard modal Tab focus-trap. Call from a `keydown` handler; wraps focus
 * between the first and last focusable descendant of `container` so Tab /
 * Shift+Tab cycle within the dialog instead of escaping to the background.
 */
export function trapTabKey(e: KeyboardEvent, container: HTMLElement | null | undefined): void {
  if (e.key !== 'Tab' || !container || typeof document === 'undefined') return;
  const focusable = container.querySelectorAll<HTMLElement>(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  );
  if (focusable.length === 0) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}
