/*
 * The web interface's login: whether this browser is signed in to `emberd`,
 * and the calls that sign it in and out.
 */

/** The header `emberd` requires on every request that changes something, so
 *  a form on another site cannot make one. */
export const REQUEST_HEADER = 'x-ember-request';

export interface ServerSession {
  authenticated: boolean;
  /** No password is set yet: the first visit chooses one, with the code
   *  `emberd` printed to its log. */
  setup_required: boolean;
  /** Reached over plain HTTP from another computer. */
  unencrypted: boolean;
  min_password_chars: number;
  version: string;
}

export async function readSession(): Promise<ServerSession> {
  const response = await fetch('/api/session', { credentials: 'same-origin', cache: 'no-store' });
  if (!response.ok) throw new Error(`emberd answered ${response.status}`);
  return response.json();
}

/** What a refused login says: the coded error the backend sends. */
async function post(path: string, body: unknown): Promise<void> {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json', [REQUEST_HEADER]: '1' },
    body: JSON.stringify(body),
  });
  if (response.ok) return;
  let error: unknown = `emberd answered ${response.status}`;
  try {
    const reply = await response.json();
    if (reply && 'error' in reply) error = reply.error;
  } catch {
    // The status is all there is.
  }
  throw error;
}

export function logIn(password: string): Promise<void> {
  return post('/api/login', { password });
}

export function setUp(code: string, password: string): Promise<void> {
  return post('/api/setup', { code, password });
}

export function changePassword(current: string, next: string): Promise<void> {
  return post('/api/password', { current, new: next });
}

export async function logOut(): Promise<void> {
  await post('/api/logout', {});
  location.reload();
}

let signedIn = false;
let reloading = false;
const whenSignedIn: Array<() => void> = [];

/** The layout found this browser signed in: requests may now count on it, and
 *  the event stream may open. */
export function markSignedIn(): void {
  if (signedIn) return;
  signedIn = true;
  for (const run of whenSignedIn.splice(0)) run();
}

/** Run `run` once signed in (now, if already). */
export function onSignedIn(run: () => void): void {
  if (signedIn) run();
  else whenSignedIn.push(run);
}

/** The session ended (logged out elsewhere, the password changed, or it
 *  expired): the page goes back to the login. Before the page knew it was
 *  signed in a refusal is expected, and reloading would only loop. */
export function loggedOut(): void {
  if (!signedIn || reloading) return;
  reloading = true;
  location.reload();
}
