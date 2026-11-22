/*
 * `@tauri-apps/plugin-process` for the browser build. `relaunch` restarts
 * `emberd` (which saves everything first and starts again in place), waits
 * for it to answer, and reloads the page.
 */

import * as m from '$lib/paraglide/messages';
import { REQUEST_HEADER } from './session';

const POLL_MS = 1_000;
/** Long enough for a clean stop, which can take most of a minute. */
const GIVE_UP_MS = 180_000;

async function healthy(): Promise<boolean> {
  try {
    const response = await fetch('/api/health', { cache: 'no-store' });
    return response.ok;
  } catch {
    return false;
  }
}

export async function relaunch(): Promise<void> {
  const response = await fetch('/api/restart', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { [REQUEST_HEADER]: '1' },
  });
  if (!response.ok) throw new Error(m.web_runtime_bad_status({ status: response.status }));
  const started = Date.now();
  // First the old process going away, then the new one answering.
  let down = false;
  while (Date.now() - started < GIVE_UP_MS) {
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
    const up = await healthy();
    if (!up) down = true;
    else if (down || Date.now() - started > 10_000) {
      location.reload();
      return;
    }
  }
  throw new Error(m.web_runtime_restart_lost());
}

export async function exit(_code?: number): Promise<void> {}
