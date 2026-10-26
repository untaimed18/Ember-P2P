import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { Transfer } from '$lib/types';

const handlers = new Map<string, (event: { payload: unknown }) => void>();

vi.mock('@tauri-apps/api/event', () => ({
  listen: async (name: string, handler: (event: { payload: unknown }) => void) => {
    handlers.set(name, handler);
    return () => handlers.delete(name);
  },
}));

function row(id: string): Transfer {
  return {
    id,
    file_name: `${id}.bin`,
    file_hash: id.padStart(32, '0'),
    peer_id: '',
    peer_name: '',
    direction: 'download',
    status: 'active',
    progress: 10,
    speed: 100,
    total_size: 1000,
    transferred: 100,
    completed_size: 100,
    started_at: 1,
    priority: 'normal',
    sources: 1,
    active_sources: 0,
    queued_sources: 0,
    health: 'healthy',
    category: '',
    wait_time: 0,
    upload_time: 0,
    a4af_sources: 0,
    max_sources: 0,
    preview_priority: false,
    preview_ready: false,
    ember_sources: 0,
  };
}

/** What the mocked backend answers. A poll reads it when it is sent, and its
 *  answer waits for `hold` when one is set: a poll still in flight. */
const backend = {
  rows: [row('a')],
  restored: true,
  resumable: [] as string[],
  hold: null as Promise<void> | null,
};

vi.mock('$lib/api/transfers', () => ({
  getTransfersSince: async () => {
    const answer = {
      epoch: 1,
      revision: 1,
      full: true,
      transfers: backend.rows.map((t) => ({ ...t })),
      removed: [],
      restored: backend.restored,
      resumable_failed: [...backend.resumable],
    };
    if (backend.hold) await backend.hold;
    return answer;
  },
}));

vi.mock('$lib/api/system', () => ({
  getRuntimeStatus: async () => ({}),
}));

/** Just enough `document` for the store: visibility and its listeners. */
const fakeDocument = {
  visibilityState: 'visible' as 'visible' | 'hidden',
  listeners: new Set<() => void>(),
  addEventListener(_: string, fn: () => void) {
    this.listeners.add(fn);
  },
  removeEventListener(_: string, fn: () => void) {
    this.listeners.delete(fn);
  },
  hide() {
    this.visibilityState = 'hidden';
    for (const fn of this.listeners) fn();
  },
};

const store = await import('./transfers');

function emitSources(active: number) {
  handlers.get('transfer-sources')?.({
    payload: { id: 'a', sources: 9, active_sources: active, queued_sources: 0 },
  });
}

function activeSources(): number | undefined {
  return get(store.transfers).find((t) => t.id === 'a')?.active_sources;
}

describe('transfer event flushing while the window is hidden', () => {
  beforeEach(async () => {
    fakeDocument.visibilityState = 'visible';
    vi.stubGlobal('document', fakeDocument);
    // A frame that is never delivered — what a hidden window does to one.
    vi.stubGlobal('requestAnimationFrame', () => 1);
    vi.stubGlobal('cancelAnimationFrame', () => {});
    await store.initTransferStore();
    vi.useFakeTimers();
  });

  afterEach(() => {
    store.cleanupTransferStore();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('starts from the backend snapshot', () => {
    expect(activeSources()).toBe(0);
  });

  it('says the list is loaded once that snapshot is in, and not after a reset', () => {
    expect(get(store.transfersLoaded)).toBe(true);
    store.cleanupTransferStore();
    expect(get(store.transfersLoaded)).toBe(false);
  });

  it('flushes on a backstop timer when the requested frame never comes', () => {
    emitSources(4);
    expect(activeSources()).toBe(0);
    vi.advanceTimersByTime(1_000);
    expect(activeSources()).toBe(4);
  });

  it('flushes at once when the window hides with a frame pending', () => {
    emitSources(3);
    fakeDocument.hide();
    expect(activeSources()).toBe(3);
  });

  it('keeps flushing, at a slower cadence, while hidden', () => {
    fakeDocument.hide();
    emitSources(2);
    vi.advanceTimersByTime(100);
    expect(activeSources()).toBe(0);
    vi.advanceTimersByTime(500);
    expect(activeSources()).toBe(2);
  });
});

describe('the transfers poll', () => {
  const category = () => get(store.transfers).find((t) => t.id === 'a')?.category;

  beforeEach(() => {
    fakeDocument.visibilityState = 'visible';
    vi.stubGlobal('document', fakeDocument);
    vi.stubGlobal('requestAnimationFrame', () => 1);
    vi.stubGlobal('cancelAnimationFrame', () => {});
    backend.rows = [row('a')];
    backend.restored = true;
    backend.resumable = [];
    backend.hold = null;
    vi.useFakeTimers();
  });

  afterEach(() => {
    store.cleanupTransferStore();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('calls the list loaded only once the last session is restored', async () => {
    backend.restored = false;
    await store.initTransferStore();
    expect(get(store.transfers)).toHaveLength(1);
    expect(get(store.transfersLoaded)).toBe(false);

    backend.restored = true;
    const stop = store.startTransferPoll();
    await vi.advanceTimersByTimeAsync(0);
    expect(get(store.transfersLoaded)).toBe(true);
    stop();
  });

  it('keeps a category set while a poll was in flight, and takes the next one', async () => {
    await store.initTransferStore();
    let release = () => {};
    backend.hold = new Promise<void>((resolve) => (release = resolve));
    const stop = store.startTransferPoll();

    vi.setSystemTime(Date.now() + 1);
    backend.rows = [{ ...row('a'), category: 'Video' }];
    store.setLocalCategory(new Set(['a']), 'Video');
    backend.hold = null;
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(category()).toBe('Video');

    backend.rows = [{ ...row('a'), category: 'Audio' }];
    await vi.advanceTimersByTimeAsync(3_000);
    expect(category()).toBe('Audio');
    stop();
  });

  it('takes a resumed failed download out of Failed, whatever a poll in flight says', async () => {
    const status = () => get(store.transfers).find((t) => t.id === 'a')?.status;
    backend.rows = [{ ...row('a'), status: 'failed', failure_code: 'local_read_failed' }];
    backend.resumable = ['a'];
    await store.initTransferStore();
    expect(status()).toBe('failed');
    expect(get(store.resumableFailedDownloads).has('a')).toBe(true);

    let release = () => {};
    backend.hold = new Promise<void>((resolve) => (release = resolve));
    const stop = store.startTransferPoll();
    vi.setSystemTime(Date.now() + 1);
    handlers.get('transfer-started')?.({ payload: { ...row('a'), status: 'searching' } });
    expect(status()).toBe('searching');

    backend.hold = null;
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(status()).toBe('searching');

    backend.rows = [{ ...row('a'), status: 'searching' }];
    backend.resumable = [];
    await vi.advanceTimersByTimeAsync(3_000);
    expect(status()).toBe('searching');
    expect(get(store.resumableFailedDownloads).size).toBe(0);

    backend.rows = [{ ...row('a'), status: 'failed' }];
    await vi.advanceTimersByTimeAsync(3_000);
    expect(status(), 'failing again later is not held off').toBe('failed');
    stop();
  });
});

describe('progress for a download with no row here', () => {
  let frames: FrameRequestCallback[] = [];
  const runFrame = () => {
    const due = frames;
    frames = [];
    for (const frame of due) frame(0);
  };
  const progress = (id: string, downloaded: number) =>
    handlers.get('transfer-progress')?.({
      payload: { id, downloaded, completed_size: downloaded, total: 1000, progress: downloaded / 10, speed: 1 },
    });

  beforeEach(async () => {
    fakeDocument.visibilityState = 'visible';
    vi.stubGlobal('document', fakeDocument);
    frames = [];
    backend.rows = [row('a')];
    backend.hold = null;
    // Before the frame stubs: fake timers replace `requestAnimationFrame` too.
    vi.useFakeTimers();
    vi.stubGlobal('requestAnimationFrame', (frame: FrameRequestCallback) => frames.push(frame));
    vi.stubGlobal('cancelAnimationFrame', () => {});
    await store.initTransferStore();
    // Whatever the start queued, settled before the counting starts.
    runFrame();
    vi.advanceTimersByTime(1_000);
    frames = [];
  });

  afterEach(() => {
    store.cleanupTransferStore();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  /** A feed's download is never listed here. Its progress used to ask for a
   *  frame from every frame it was flushed in, for as long as it downloaded,
   *  which kept the window rendering flat out and its timers starved. */
  it('is looked at again on a timer, not on every frame', () => {
    progress('feed', 100);
    expect(frames).toHaveLength(1);
    runFrame();
    for (let i = 0; i < 30; i++) runFrame();
    expect(frames, 'no frame asked for while it waits').toHaveLength(0);
    vi.advanceTimersByTime(500);
    expect(frames).toHaveLength(1);
  });

  it('still reaches a row that arrives after it', () => {
    progress('b', 400);
    runFrame();
    handlers.get('transfer-started')?.({ payload: { ...row('b'), progress: 0, transferred: 0, completed_size: 0 } });
    vi.advanceTimersByTime(500);
    runFrame();
    expect(get(store.transfers).find((t) => t.id === 'b')?.completed_size).toBe(400);
  });
});
