/**
 * How wide the chat dock is allowed to be.
 *
 * Its own module, with tests, for the reason `rowWindow.ts` gives: the
 * arithmetic is small but every term of it decides whether the panel is
 * usable, and a clamp that is wrong shows up as a dock that cannot be dragged
 * back rather than as an exception. The caller owns the measuring — it is the
 * only side that can read the window — and this owns the rule.
 */

/** Below this the tab strip cannot hold two readable tabs beside its two
 *  controls, so allowing it would only produce a panel nobody can use. */
export const DOCK_WIDTH_MIN = 320;
export const DOCK_WIDTH_DEFAULT = 420;
/** Past this a side panel stops being one and starts being the page. */
export const DOCK_WIDTH_CAP = 900;
/** Share of the window the dock may take, so there is always something left
 *  of whatever it is docked beside. */
const DOCK_WIDTH_VIEWPORT_SHARE = 0.9;

/**
 * The widest the dock may be in a window this size.
 *
 * Total, because the input comes from the DOM: a window reporting zero (or
 * anything else nonsensical) must still yield a bound the clamp can use, and
 * one that came back below the floor would otherwise invert the range and let
 * `clampDockWidth` return something under the minimum.
 */
export function maxDockWidth(viewportWidth: number): number {
  if (!Number.isFinite(viewportWidth) || viewportWidth <= 0) return DOCK_WIDTH_CAP;
  const share = Math.round(viewportWidth * DOCK_WIDTH_VIEWPORT_SHARE);
  return Math.max(DOCK_WIDTH_MIN, Math.min(DOCK_WIDTH_CAP, share));
}

/**
 * A width to actually apply, given what was asked for and the window it has
 * to fit in.
 *
 * A stored width from a wider monitor, a drag past either end, and a window
 * narrowed under the dock all arrive here, and none of them may produce a
 * panel that cannot be dragged back.
 */
export function clampDockWidth(px: number, viewportWidth: number): number {
  const max = maxDockWidth(viewportWidth);
  if (!Number.isFinite(px)) return Math.min(max, DOCK_WIDTH_DEFAULT);
  return Math.min(max, Math.max(DOCK_WIDTH_MIN, Math.round(px)));
}
