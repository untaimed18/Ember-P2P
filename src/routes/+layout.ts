// Tauri doesn't have a Node.js server to do proper SSR
// so we use adapter-static with a fallback to index.html to put the site in SPA mode
// See: https://svelte.dev/docs/kit/single-page-apps
// See: https://v2.tauri.app/start/frontend/sveltekit/ for more info
import { browser } from '$app/environment';
import { takePendingRestoredPrefs } from '$lib/api/backup';
import { applyRestoredPrefs } from '$lib/backupPrefs';
import { isChatWindow } from '$lib/windowRole';

export const ssr = false;

/**
 * Put back the window preferences a restore applied at this launch carried.
 *
 * Here rather than in the layout because the stores, the theme and the locale
 * have already read `localStorage` by the time anything mounts, and the
 * layout's `onMount` consumes one-shot startup notices a reload would lose.
 * Nothing has mounted while this runs, so reloading costs nothing.
 */
export async function load() {
  if (!browser || isChatWindow()) return;
  let prefs: Record<string, string> | null = null;
  try {
    prefs = await takePendingRestoredPrefs();
  } catch (e) {
    console.error('Failed to take the restored preferences:', e);
    return;
  }
  let changed = false;
  try {
    changed = !!prefs && applyRestoredPrefs(prefs, localStorage);
  } catch (e) {
    console.error('Failed to apply the restored preferences:', e);
  }
  if (!changed) return;
  location.reload();
  // Never settles, so the layout cannot mount on the values being replaced.
  await new Promise<never>(() => {});
}
