import { writable } from 'svelte/store';
import { browser } from '$app/environment';
import { getCurrentWindow } from '@tauri-apps/api/window';

export type Theme = 'light' | 'dark';

// Keep in lockstep with `static/theme-boot.js`, which reads this key
// before first paint so dark-mode users do not flash the light canvas.
const STORAGE_KEY = 'ember-theme';

// Storage access can throw (SecurityError when storage is disabled), and this
// module is evaluated while the layout loads, so every touch is guarded.
function readStoredTheme(): string | null {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeStoredTheme(t: Theme): void {
  try {
    localStorage.setItem(STORAGE_KEY, t);
  } catch {
    // The theme still applies for this session.
  }
}

function clearStoredTheme(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Following the OS still applies for this session.
  }
}

function storedThemeIsExplicit(): boolean {
  const stored = readStoredTheme();
  return stored === 'light' || stored === 'dark';
}

function prefersDark(): boolean {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  } catch {
    return false;
  }
}

export function getInitialTheme(): Theme {
  if (browser) {
    const stored = readStoredTheme();
    if (stored === 'light' || stored === 'dark') return stored;
    if (prefersDark()) return 'dark';
  }
  return 'light';
}

export const theme = writable<Theme>(getInitialTheme());

/** True until the user picks Light or Dark; the OS decides meanwhile. */
export const themeFollowsSystem = writable<boolean>(browser ? !storedThemeIsExplicit() : true);

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
  if (browser) writeStoredTheme(t);
  themeFollowsSystem.set(false);
}

/** Drop the explicit choice, so the theme tracks the OS again. */
export function followSystemTheme() {
  const t: Theme = browser && prefersDark() ? 'dark' : 'light';
  if (browser) clearStoredTheme();
  applyResolvedTheme(t);
  theme.set(t);
  themeFollowsSystem.set(true);
}

let themeCleanup: (() => void) | null = null;

export function initTheme() {
  const t = getInitialTheme();
  applyResolvedTheme(t);
  theme.set(t);
  if (browser) themeFollowsSystem.set(!storedThemeIsExplicit());
  // Important: do NOT persist `t` here. The OS-tracking branch in the
  // matchMedia handler below uses "is `STORAGE_KEY` unset?" as the
  // signal for "user has not made an explicit choice yet" — if we
  // wrote the resolved theme back to localStorage on every init,
  // every user would look like they had explicitly chosen the
  // OS-derived value, and OS dark/light flips after launch would
  // never propagate. `applyTheme()` (called from settings) is the single
  // point that records an explicit choice.
  // `getInitialTheme()` already validates whatever's in storage and
  // safely falls through to the OS preference if it's garbage, so
  // there's nothing to "self-heal" by writing it back.

  if (browser) {
    if (themeCleanup) themeCleanup();
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => {
      if (!storedThemeIsExplicit()) {
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
