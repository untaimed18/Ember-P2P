/*
 * `@tauri-apps/api/window` for the browser build: the page is the one main
 * window, the size the browser gives it.
 */

import type { UnlistenFn } from './event';

type Theme = 'light' | 'dark';

function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

class PageWindow {
  readonly label = 'main';

  async isVisible(): Promise<boolean> {
    return document.visibilityState === 'visible';
  }

  async isMinimized(): Promise<boolean> {
    return false;
  }

  async isMaximized(): Promise<boolean> {
    return false;
  }

  async scaleFactor(): Promise<number> {
    return window.devicePixelRatio || 1;
  }

  async outerPosition(): Promise<{ x: number; y: number }> {
    return { x: window.screenX, y: window.screenY };
  }

  async innerSize(): Promise<{ width: number; height: number }> {
    return { width: window.innerWidth, height: window.innerHeight };
  }

  async onMoved(_handler: () => void): Promise<UnlistenFn> {
    return () => {};
  }

  async onResized(handler: () => void): Promise<UnlistenFn> {
    window.addEventListener('resize', handler);
    return () => window.removeEventListener('resize', handler);
  }

  async theme(): Promise<Theme> {
    return systemTheme();
  }

  async setTheme(_theme: Theme | null): Promise<void> {}

  async onThemeChanged(handler: (event: { payload: Theme }) => void): Promise<UnlistenFn> {
    const query = window.matchMedia('(prefers-color-scheme: dark)');
    const listener = (e: MediaQueryListEvent) => handler({ payload: e.matches ? 'dark' : 'light' });
    query.addEventListener('change', listener);
    return () => query.removeEventListener('change', listener);
  }
}

const page = new PageWindow();

export function getCurrentWindow(): PageWindow {
  return page;
}
