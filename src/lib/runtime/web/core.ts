/*
 * `@tauri-apps/api/core` for the browser build: what `emberd` serves to a web
 * browser. `invoke` posts the same command and arguments to the server, which
 * runs the same command the desktop app's IPC would.
 */

import { loggedOut, REQUEST_HEADER } from './session';

export type InvokeArgs = Record<string, unknown>;

export async function invoke<T>(cmd: string, args?: InvokeArgs): Promise<T> {
  const response = await fetch(`/api/invoke/${encodeURIComponent(cmd)}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', [REQUEST_HEADER]: '1' },
    body: JSON.stringify(args ?? {}),
  });
  if (response.status === 401) {
    loggedOut();
  }
  let body: { ok?: unknown; error?: unknown };
  try {
    body = await response.json();
  } catch {
    throw `emberd answered ${response.status} without a reply`;
  }
  if ('error' in body) throw body.error;
  return body.ok as T;
}

/** Only the desktop updater streams over a channel, and `emberd` has none. */
export class Channel<T> {
  onmessage: (message: T) => void = () => {};
}

/** A library file for the browser's player, served with the same checks as
 *  the desktop's `ember-media` protocol. */
export function convertFileSrc(path: string, _protocol?: string): string {
  return `/api/media/${encodeURIComponent(path)}`;
}
