import type { Action } from 'svelte/action';

/**
 * Moves an element to the end of `<body>` for as long as it is mounted.
 *
 * For `position: fixed` popovers inside panels that scroll, clip, or slide in
 * with a transform: any of those turns "fixed" into "relative to that panel"
 * or cuts the popover off at the panel's edge. Apply it to an element whose
 * parent Svelte keeps in place (not the root of an `{#if}` block) — Svelte
 * removes a block by walking its own DOM siblings, and a root that has moved
 * elsewhere would send that walk through `<body>`.
 *
 * Once moved, the node is outside the app's root, so Svelte's delegated
 * handlers (`onkeydown`, `onclick`…) on it run from Svelte's listener on
 * `document`. A handler that has to stop an event before other `document`
 * listeners see it — Escape, say — must be added natively on the node.
 */
export const portal: Action<HTMLElement> = (node) => {
  node.ownerDocument.body.appendChild(node);
  return {
    destroy() {
      node.remove();
    },
  };
};
