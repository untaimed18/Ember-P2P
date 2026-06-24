import { writable } from 'svelte/store';
import { browser } from '$app/environment';

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'ember-theme';

export function getInitialTheme(): Theme {
  if (browser) {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
  }
  return 'light';
}

export const theme = writable<Theme>(getInitialTheme());

function applyThemeToDOM(t: Theme) {
  if (!browser) return;
  document.documentElement.setAttribute('data-theme', t);
}

export function applyTheme(t: Theme) {
  applyThemeToDOM(t);
  if (browser) localStorage.setItem(STORAGE_KEY, t);
}

let themeCleanup: (() => void) | null = null;

export function initTheme() {
  const t = getInitialTheme();
  applyThemeToDOM(t);
  theme.set(t);
  // Important: do NOT persist `t` here. The OS-tracking branch in the
  // matchMedia handler below uses "is `STORAGE_KEY` unset?" as the
  // signal for "user has not made an explicit choice yet" — if we
  // wrote the resolved theme back to localStorage on every init,
  // every user would look like they had explicitly chosen the
  // OS-derived value, and OS dark/light flips after launch would
  // never propagate. `applyTheme()` (called from settings) is the
  // single point that records an explicit choice.
  // `getInitialTheme()` already validates whatever's in storage and
  // safely falls through to the OS preference if it's garbage, so
  // there's nothing to "self-heal" by writing it back.

  if (browser) {
    if (themeCleanup) themeCleanup();
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => {
      const userChose = localStorage.getItem(STORAGE_KEY);
      if (!userChose) {
        const next: Theme = e.matches ? 'dark' : 'light';
        applyThemeToDOM(next);
        theme.set(next);
      }
    };
    mq.addEventListener('change', handler);
    themeCleanup = () => mq.removeEventListener('change', handler);
  }
}

export function cleanupTheme() {
  if (themeCleanup) {
    themeCleanup();
    themeCleanup = null;
  }
}
