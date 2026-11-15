import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { REQUEST_HEADER } from './session';
import { pickAndUpload, uploadFile } from './files';

/** The hidden `<input type="file">` the picker stands in with. */
class FakeInput {
  type = '';
  accept = '';
  hidden = false;
  files: File[] | null = null;
  removed = false;
  clicked = false;
  private listeners = new Map<string, () => void>();
  addEventListener(name: string, listener: () => void) {
    this.listeners.set(name, listener);
  }
  click() {
    this.clicked = true;
  }
  remove() {
    this.removed = true;
  }
  fire(name: string) {
    this.listeners.get(name)?.();
  }
}

let input: FakeInput;

beforeEach(() => {
  input = new FakeInput();
  vi.stubGlobal('document', {
    createElement: vi.fn(() => input),
    body: { appendChild: vi.fn() },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function answering(status: number, body: unknown) {
  const fetch = vi.fn(async () => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status }));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('a file sent from the browser', () => {
  it('goes to emberd under its own name, and the id it is kept under comes back', async () => {
    const fetch = answering(200, { ok: '0123456789abcdef0123456789abcdef' });
    const picked = pickAndUpload('.p2p,.dat');
    expect(input.clicked && input.hidden && input.type === 'file').toBe(true);
    expect(input.accept).toBe('.p2p,.dat');
    input.files = [new File(['ranges'], 'my list #2.p2p')];
    input.fire('change');
    await expect(picked).resolves.toBe('0123456789abcdef0123456789abcdef');
    expect(input.removed).toBe(true);
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe(`/api/upload?name=${encodeURIComponent('my list #2.p2p')}`);
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('same-origin');
    expect((init.headers as Record<string, string>)[REQUEST_HEADER]).toBe('1');
  });

  it('is nothing when the picker is closed or nothing is chosen', async () => {
    const fetch = answering(200, { ok: 'unused' });
    const cancelled = pickAndUpload();
    input.fire('cancel');
    await expect(cancelled).resolves.toBeNull();
    expect(input.removed).toBe(true);

    input = new FakeInput();
    const empty = pickAndUpload();
    input.fire('change');
    await expect(empty).resolves.toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects with the coded error emberd refused it with', async () => {
    const coded = '{"__coded":true,"code":"server_upload_too_large","message":"too large"}';
    answering(413, { error: coded });
    const picked = pickAndUpload();
    input.files = [new File(['x'], 'big.zip')];
    input.fire('change');
    await expect(picked).rejects.toBe(coded);
  });

  it('says what emberd answered when the answer is not its own', async () => {
    answering(502, '<html>Bad gateway</html>');
    await expect(uploadFile('/api/upload?name=x', new File(['x'], 'x'))).rejects.toBe('emberd answered 502');
  });
});
