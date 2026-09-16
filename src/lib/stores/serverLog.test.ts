import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get } from 'svelte/store';
import { appendServerLog, clearServerLog, hydrateServerLog, serverLog } from './serverLog';
import type { ServerLogLine } from '$lib/types';

function line(seq: number, at: number, message: string): ServerLogLine {
  return { seq, at, message };
}

const messages = () => get(serverLog).map((e) => e.message);

beforeEach(() => {
  clearServerLog();
});

describe('hydrateServerLog', () => {
  it('restores history the store never saw', () => {
    // What a reload looks like: the store starts empty while the backend still
    // holds everything that happened before it.
    hydrateServerLog([
      line(1, 1_000, 'connecting'),
      line(2, 2_000, 'connected'),
      line(3, 3_000, 'welcome'),
    ]);

    expect(messages()).toEqual(['connecting', 'connected', 'welcome']);
  });

  it('does not duplicate a line the live listener already recorded', () => {
    // The replay is requested after the listener is registered, so anything
    // emitted in between arrives twice. `seq` is what tells them apart.
    appendServerLog('connected', line(2, 2_000, 'connected'));

    hydrateServerLog([line(1, 1_000, 'connecting'), line(2, 2_000, 'connected')]);

    expect(messages()).toEqual(['connecting', 'connected']);
  });

  it('keeps two genuinely repeated messages, rather than reading them as one', () => {
    // Identical text in the same millisecond is not a duplicate if the backend
    // gave it two sequence numbers — servers really do repeat MOTD lines.
    hydrateServerLog([line(1, 1_000, 'motd'), line(2, 1_000, 'motd')]);

    expect(messages()).toEqual(['motd', 'motd']);
  });

  it('orders replayed lines against ones the page wrote itself', () => {
    // The Servers page logs its own progress messages, which carry no sequence
    // number at all. Ordering is by timestamp so the two kinds interleave,
    // rather than the seq-less one being pinned to either end.
    vi.useFakeTimers();
    vi.setSystemTime(2_500);
    appendServerLog('disconnecting');
    vi.useRealTimers();

    hydrateServerLog([line(1, 1_000, 'connecting'), line(2, 3_000, 'connected')]);

    expect(messages()).toEqual(['connecting', 'disconnecting', 'connected']);
    expect(get(serverLog)[1].seq).toBeUndefined();
  });

  it('gives every entry a distinct key', () => {
    // `id` is the `{#each}` key; a collision makes Svelte drop rows.
    appendServerLog('live', line(9, 9_000, 'live'));
    hydrateServerLog([line(1, 1_000, 'a'), line(2, 2_000, 'b')]);

    const ids = get(serverLog).map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('holds no more than the cap, dropping the oldest', () => {
    const history = Array.from({ length: 250 }, (_, i) => line(i + 1, i + 1, `line ${i}`));

    hydrateServerLog(history);

    const held = messages();
    expect(held).toHaveLength(200);
    expect(held[0]).toBe('line 50');
    expect(held[held.length - 1]).toBe('line 249');
  });

  it('leaves the store alone when the backend has nothing to replay', () => {
    appendServerLog('live', line(1, 1_000, 'live'));

    hydrateServerLog([]);

    expect(messages()).toEqual(['live']);
  });
});

describe('appendServerLog', () => {
  it('stamps arrival time for lines the page writes itself', () => {
    const before = Date.now();
    appendServerLog('connecting to server');
    const entry = get(serverLog)[0];

    expect(entry.seq).toBeUndefined();
    expect(entry.at).toBeGreaterThanOrEqual(before);
  });

  it('prefers the backend timestamp over arrival time', () => {
    // So a replayed line reads as the time it happened, not the time it was
    // read back.
    appendServerLog('connected', line(4, 1_234, 'connected'));

    expect(get(serverLog)[0]).toMatchObject({ at: 1_234, seq: 4 });
  });

  it('ignores an empty message', () => {
    appendServerLog('');

    expect(get(serverLog)).toHaveLength(0);
  });
});
