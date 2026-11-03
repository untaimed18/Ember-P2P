import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import type { Transfer } from '$lib/types';

vi.mock('@tauri-apps/api/event', () => ({
  listen: async () => () => {},
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

/** A poll reads `rows` when it is sent, and its answer waits for `hold`. */
const backend = {
  rows: [row('a')],
  hold: null as Promise<void> | null,
  calls: 0,
};

vi.mock('$lib/api/transfers', () => ({
  getTransfersSince: async () => {
    backend.calls += 1;
    const answer = {
      epoch: 1,
      revision: 1,
      full: true,
      transfers: backend.rows.map((t) => ({ ...t })),
      removed: [],
      restored: true,
      resumable_failed: [],
    };
    if (backend.hold) await backend.hold;
    return answer;
  },
}));

vi.mock('$lib/api/system', () => ({
  getRuntimeStatus: async () => ({}),
}));

const fakeDocument = {
  visibilityState: 'visible' as 'visible' | 'hidden',
  addEventListener() {},
  removeEventListener() {},
};

const store = await import('./transfers');

describe('renaming a download', () => {
  const name = () => get(store.transfers).find((t) => t.id === 'a')?.file_name;

  beforeEach(() => {
    vi.stubGlobal('document', fakeDocument);
    vi.stubGlobal('requestAnimationFrame', () => 1);
    vi.stubGlobal('cancelAnimationFrame', () => {});
    backend.rows = [row('a')];
    backend.hold = null;
    vi.useFakeTimers();
  });

  afterEach(() => {
    store.cleanupTransferStore();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('keeps the new name over a poll already in flight, and takes the next one', async () => {
    await store.initTransferStore();
    let release = () => {};
    backend.hold = new Promise<void>((resolve) => (release = resolve));
    const calls = backend.calls;
    const stop = store.startTransferPoll();
    expect(backend.calls).toBe(calls + 1);

    vi.setSystemTime(Date.now() + 1);
    backend.rows = [{ ...row('a'), file_name: 'renamed.bin' }];
    store.setLocalFileName('a', 'renamed.bin');
    backend.hold = null;
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(name()).toBe('renamed.bin');

    backend.rows = [{ ...row('a'), file_name: 'other.bin' }];
    await vi.advanceTimersByTimeAsync(3_000);
    expect(name()).toBe('other.bin');
    stop();
  });
});
