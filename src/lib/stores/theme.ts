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

/** The explicit choice made this session, so it holds even where storage
 *  refuses to keep it; `undefined` until one is made either way. */
let sessionChoice: Theme | null | undefined;

function explicitTheme(): Theme | null {
  if (sessionChoice !== undefined) return sessionChoice;
  const stored = readStoredTheme();
  return stored === 'light' || stored === 'dark' ? stored : null;
}

function prefersDark(): boolean {
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches;
  } catch {
    return false;
  }
}

function hasTauri(): boolean {
  // The browser-only Vite preview does not expose Tauri's IPC bridge.
  // Guard it so theme development outside the desktop shell remains usable.
  return browser && '__TAURI_INTERNALS__' in window;
}

export function getInitialTheme(): Theme {
  if (browser) {
    const explicit = explicitTheme();
    if (explicit) return explicit;
    if (prefersDark()) return 'dark';
  }
  return 'light';
}

export const theme = writable<Theme>(getInitialTheme());

/** True until the user picks Light or Dark; the OS decides meanwhile. */
export const themeFollowsSystem = writable<boolean>(browser ? explicitTheme() === null : true);

function applyThemeToDOM(t: Theme) {
  if (!browser) return;
  document.documentElement.setAttribute('data-theme', t);
}

/**
 * `null` follows the OS. That has to reach the window, not only the page: on
 * Windows a window theme is handed on to WebView2 as its color scheme, so a
 * window pinned to the theme the OS had last would also pin
 * `prefers-color-scheme`, and the next OS change would never be seen.
 */
function applyThemeToNativeWindow(t: Theme | null) {
  if (!hasTauri()) return;
  void getCurrentWindow().setTheme(t).catch((error) => {
    console.warn('Failed to apply native window theme:', error);
  });
}

function showSystemTheme(t: Theme) {
  applyThemeToDOM(t);
  theme.set(t);
}

/** The OS theme as the window reports it, where the media query may lag. */
async function resolveSystemTheme(): Promise<void> {
  if (!hasTauri()) return;
  try {
    const t = await getCurrentWindow().theme();
    if (t && explicitTheme() === null) showSystemTheme(t);
  } catch {
    // The media query's answer stands.
  }
}

export function applyTheme(t: Theme) {
  sessionChoice = t;
  applyThemeToDOM(t);
  applyThemeToNativeWindow(t);
  if (browser) writeStoredTheme(t);
  themeFollowsSystem.set(false);
}

/** Drop the explicit choice, so the theme tracks the OS again. */
export function followSystemTheme() {
  sessionChoice = null;
  if (browser) clearStoredTheme();
  applyThemeToNativeWindow(null);
  showSystemTheme(browser && prefersDark() ? 'dark' : 'light');
  themeFollowsSystem.set(true);
  void resolveSystemTheme();
}

let themeCleanup: (() => void) | null = null;

export function initTheme() {
  const t = getInitialTheme();
  const following = explicitTheme() === null;
  applyThemeToDOM(t);
  applyThemeToNativeWindow(following ? null : t);
  theme.set(t);
  if (browser) themeFollowsSystem.set(following);
  // Important: do NOT persist `t` here. "Is `STORAGE_KEY` unset?" is the
  // signal for "user has not made an explicit choice yet" — if we wrote the
  // resolved theme back to localStorage on every init, every user would look
  // like they had explicitly chosen the OS-derived value, and OS dark/light
  // flips after launch would never propagate. `applyTheme()` (called from
  // settings) is the single point that records an explicit choice.

  if (browser) {
    if (themeCleanup) themeCleanup();
    if (following) void resolveSystemTheme();
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => {
      if (explicitTheme() === null) showSystemTheme(e.matches ? 'dark' : 'light');
    };
    mq.addEventListener('change', handler);
    // The window's own theme event as well: it reports the OS change even
    // where the webview's media query is slow to.
    let unlistenNative: (() => void) | null = null;
    let live = true;
    if (hasTauri()) {
      getCurrentWindow()
        .onThemeChanged(({ payload }) => {
          if (explicitTheme() === null) showSystemTheme(payload);
        })
        .then((fn) => { if (live) unlistenNative = fn; else fn(); })
        .catch((error) => console.warn('Failed to watch the OS theme:', error));
    }
    themeCleanup = () => {
      live = false;
      mq.removeEventListener('change', handler);
      unlistenNative?.();
    };
  }
}

export function cleanupTheme() {
  if (themeCleanup) {
    themeCleanup();
    themeCleanup = null;
  }
}
