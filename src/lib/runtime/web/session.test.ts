import { afterEach, describe, expect, it, vi } from 'vitest';

describe('the web interface sign-in', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('reloads for an ended session only once the page knew it was signed in', async () => {
    const reload = vi.fn();
    vi.stubGlobal('location', { reload });
    const session = await import('./session');

    // The sign-in page is refused everything, and reloading it would loop.
    session.loggedOut();
    expect(reload).not.toHaveBeenCalled();

    const ran: string[] = [];
    session.onSignedIn(() => ran.push('waiting'));
    expect(ran).toEqual([]);
    session.markSignedIn();
    session.onSignedIn(() => ran.push('after'));
    expect(ran).toEqual(['waiting', 'after']);

    session.loggedOut();
    session.loggedOut();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('hands back the coded error emberd refused with', async () => {
    const coded = '{"__coded":true,"code":"server_wrong_password","message":"That is not the password"}';
    const fetch = vi.fn(async () => new Response(JSON.stringify({ error: coded }), { status: 401 }));
    vi.stubGlobal('fetch', fetch);
    const session = await import('./session');
    await expect(session.logIn('nope')).rejects.toBe(coded);
    const [, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect((init.headers as Record<string, string>)[session.REQUEST_HEADER]).toBe('1');
  });
});
