// Tauri doesn't have a Node.js server to do proper SSR
// so we use adapter-static with a fallback to index.html to put the site in SPA mode
// See: https://svelte.dev/docs/kit/single-page-apps
// See: https://v2.tauri.app/start/frontend/sveltekit/ for more info
import { browser } from '$app/environment';
import { takePendingRestoredPrefs } from '$lib/api/backup';
import { applyRestoredPrefs } from '$lib/backupPrefs';
import { isChatWindow } from '$lib/windowRole';
import { isServer } from '$lib/runtime';
import { markSignedIn, readSession, type ServerSession } from '$lib/runtime/web/session';

export const ssr = false;

/** emberd served this page a moment ago, so a failed check is most likely it
 *  restarting: asked again for a few seconds before the page gives up. */
async function readSessionPatiently(): Promise<ServerSession> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await readSession();
    } catch (error) {
      if (attempt >= 5) throw error;
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  }
}

/**
 * Put back the window preferences a restore applied at this launch carried.
 *
 * Here rather than in the layout because the stores, the theme and the locale
 * have already read `localStorage` by the time anything mounts, and the
 * layout's `onMount` consumes one-shot startup notices a reload would lose.
 * Nothing has mounted while this runs, so reloading costs nothing.
 */
export async function load(): Promise<{ serverLogin?: ServerSession } | undefined> {
  if (!browser || isChatWindow()) return;
  if (isServer) {
    // Signed out, the page is the login and nothing else: every command
    // would be refused.
    const session = await readSessionPatiently();
    if (!session.authenticated) return { serverLogin: session };
    markSignedIn();
  }
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
