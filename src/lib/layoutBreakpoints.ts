/** Shared layout breakpoints (CSS px). Keep in sync with `--bp-*` in `app.css`.
 *  CSS `@media` cannot read custom properties, so pages hardcode the same
 *  values; JS `matchMedia` callers should import from here. */
export const BP_LG = 1200;
export const BP_MD = 980;
export const BP_SM = 760;

export const MQ_MAX_LG = `(max-width: ${BP_LG}px)`;
