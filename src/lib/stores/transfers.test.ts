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

vi.mock('$lib/api/transfers', () => ({
  getTransfersSince: async () => ({
    epoch: 1,
    revision: 1,
    full: true,
    transfers: [row('a')],
    removed: [],
  }),
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
