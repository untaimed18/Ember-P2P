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
});
