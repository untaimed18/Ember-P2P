import { readable } from 'svelte/store';

const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Unix seconds, refreshed once a minute while anything subscribes, so a
 *  relative time ("5 minutes ago") does not freeze at its first render. */
export const minuteClock = readable(nowSeconds(), (set) => {
  set(nowSeconds());
  const timer = setInterval(() => set(nowSeconds()), 60_000);
  return () => clearInterval(timer);
});
