/*
 * `@tauri-apps/api/event` for the browser build. The backend's events come
 * over one WebSocket to `emberd` (`/api/events`), in the shape Tauri hands
 * listeners; `emit` stays within this page, as the frontend only ever emits
 * to its own windows.
 */

import { writable } from 'svelte/store';
import { loggedOut, onSignedIn, readSession } from './session';

export interface Event<T> {
  event: string;
  id: number;
  payload: T;
}

export type EventCallback<T> = (event: Event<T>) => void;
export type UnlistenFn = () => void;

/** The close code `emberd` uses for a page that fell behind its events, and
 *  the one for a session that ended. */
const CLOSE_BEHIND = 4000;
const CLOSE_LOGGED_OUT = 4001;
/** A restart or an upgrade takes seconds, and a session check costs the
 *  server nothing, so the page is back soon after emberd is. */
const MAX_RETRY_MS = 5_000;

/** Whether the event stream is up. False only once it has been up and dropped:
 *  the layout says so while it is reconnecting. */
export const eventsConnected = writable(true);

const handlers = new Map<string, Set<EventCallback<unknown>>>();
let socket: WebSocket | null = null;
let opened = false;
let lost = false;
let retryMs = 1_000;
let nextId = 1;

function dispatch(event: string, payload: unknown) {
  const listeners = handlers.get(event);
  if (!listeners) return;
  const message = { event, id: nextId++, payload };
  for (const listener of [...listeners]) {
    try {
      listener(message);
    } catch (error) {
      console.error(`Listener for ${event} failed:`, error);
    }
  }
}

function connect() {
  if (socket || typeof window === 'undefined') return;
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  const ws = new WebSocket(`${scheme}://${location.host}/api/events`);
  socket = ws;
  ws.onopen = () => {
    retryMs = 1_000;
    if (lost) {
      // Events sent while the stream was down are gone; the page reads its
      // state afresh rather than show what it missed.
      location.reload();
      return;
    }
    opened = true;
    eventsConnected.set(true);
  };
  ws.onmessage = (message) => {
    try {
      const data = JSON.parse(String(message.data)) as { event: string; payload: unknown };
      dispatch(data.event, data.payload);
    } catch (error) {
      console.warn('Unreadable event from emberd:', error);
    }
  };
  ws.onclose = (close) => {
    socket = null;
    if (close.code === CLOSE_LOGGED_OUT) {
      loggedOut();
      return;
    }
    if (opened || close.code === CLOSE_BEHIND) {
      lost = true;
      eventsConnected.set(false);
    }
    setTimeout(retry, retryMs);
    retryMs = Math.min(retryMs * 2, MAX_RETRY_MS);
  };
}

/** A session that ended while the stream was down refuses the upgrade with
 *  no close code to say so: ask before trying again. */
function retry() {
  readSession()
    .then((session) => {
      if (session.authenticated) connect();
      else loggedOut();
    })
    .catch(() => {
      setTimeout(retry, retryMs);
      retryMs = Math.min(retryMs * 2, MAX_RETRY_MS);
    });
}

export async function listen<T>(event: string, handler: EventCallback<T>): Promise<UnlistenFn> {
  onSignedIn(connect);
  let listeners = handlers.get(event);
  if (!listeners) {
    listeners = new Set();
    handlers.set(event, listeners);
  }
  const callback = handler as EventCallback<unknown>;
  listeners.add(callback);
  return () => {
    listeners?.delete(callback);
  };
}

export async function once<T>(event: string, handler: EventCallback<T>): Promise<UnlistenFn> {
  const unlisten = await listen<T>(event, (message) => {
    unlisten();
    handler(message);
  });
  return unlisten;
}

/** To the listeners on this page, as Tauri's reaches the app's own windows. */
export async function emit(event: string, payload?: unknown): Promise<void> {
  dispatch(event, payload);
}
