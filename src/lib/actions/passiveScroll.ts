import type { Action } from 'svelte/action';

/** Scroll listener with `{ passive: true }` so the browser can scroll without waiting on the handler. */
export const passiveScroll: Action<HTMLElement, (e: Event) => void> = (node, handler) => {
  let h = handler;
  const listener = (e: Event) => h(e);
  node.addEventListener('scroll', listener, { passive: true });
  return {
    update(newHandler) {
      h = newHandler;
    },
    destroy() {
      node.removeEventListener('scroll', listener);
    },
  };
};
