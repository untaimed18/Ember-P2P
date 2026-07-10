import { writable } from 'svelte/store';
import { browser } from '$app/environment';
import { getCurrentWindow } from '@tauri-apps/api/window';

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

function applyThemeToNativeWindow(t: Theme) {
  // The browser-only Vite preview does not expose Tauri's IPC bridge.
  // Guard it so theme development outside the desktop shell remains usable.
  if (!browser || !('__TAURI_INTERNALS__' in window)) return;
  void getCurrentWindow().setTheme(t).catch((error) => {
    console.warn('Failed to apply native window theme:', error);
  });
}

function applyResolvedTheme(t: Theme) {
  applyThemeToDOM(t);
  applyThemeToNativeWindow(t);
}

export function applyTheme(t: Theme) {
  applyResolvedTheme(t);
  if (browser) localStorage.setItem(STORAGE_KEY, t);
}

export function toggleTheme() {
  theme.update((current) => {
    const next: Theme = current === 'light' ? 'dark' : 'light';
    applyTheme(next);
    return next;
  });
}

let themeCleanup: (() => void) | null = null;

export function initTheme() {
  const t = getInitialTheme();
  applyResolvedTheme(t);
  theme.set(t);
  // Important: do NOT persist `t` here. The OS-tracking branch in the
  // matchMedia handler below uses "is `STORAGE_KEY` unset?" as the
  // signal for "user has not made an explicit choice yet" — if we
  // wrote the resolved theme back to localStorage on every init,
  // every user would look like they had explicitly chosen the
  // OS-derived value, and OS dark/light flips after launch would
  // never propagate. `applyTheme()` (called from `toggleTheme()` and
  // settings) is the single point that records an explicit choice.
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
        applyResolvedTheme(next);
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
