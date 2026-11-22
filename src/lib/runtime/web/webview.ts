/*
 * `@tauri-apps/api/webview` for the browser build. A browser hands a page no
 * paths for files dropped on it, so a drop never reaches Ember's folders.
 */

import type { UnlistenFn } from './event';

export function getCurrentWebview() {
  return {
    async onDragDropEvent(_handler: (event: { payload: { type: string; paths?: string[] } }) => void): Promise<UnlistenFn> {
      return () => {};
    },
  };
}
