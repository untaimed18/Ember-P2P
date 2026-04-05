import { writable } from 'svelte/store';
import { browser } from '$app/environment';

export type Theme = 'light' | 'dark';

const STORAGE_KEY = 'ember-theme';

function getInitialTheme(): Theme {
  if (browser) {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === 'light' || stored === 'dark') return stored;
    if (window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
  }
  return 'light';
}

export const theme = writable<Theme>(getInitialTheme());

export function applyTheme(t: Theme) {
  if (!browser) return;
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem(STORAGE_KEY, t);
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
  applyTheme(t);
  theme.set(t);

  if (browser) {
    if (themeCleanup) themeCleanup();
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e: MediaQueryListEvent) => {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (!stored) {
        const next: Theme = e.matches ? 'dark' : 'light';
        applyTheme(next);
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
