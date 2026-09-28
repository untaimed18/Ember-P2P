import { describe, expect, it } from 'vitest';
import type { Transfer } from '$lib/types';
import {
  PendingRowOps,
  applyHealthEvent,
  applyRowPatches,
  applySnapshotDelta,
  applySourcesEvent,
  applySpeedDecay,
  applyStatusEvent,
  keepIdentity,
  reconcileRows,
  shallowEqualRow,
  type ReconcileOptions,
  type RowEventContext,
  type SnapshotState,
  type SourcesEventPayload,
  type StatusEventPayload,
} from './transferRows';

function row(id: string, patch: Partial<Transfer> = {}): Transfer {
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
    sources: 2,
    active_sources: 1,
    queued_sources: 1,
    health: 'healthy',
    category: '',
    wait_time: 0,
    upload_time: 0,
    a4af_sources: 0,
    max_sources: 0,
    preview_priority: false,
    preview_ready: false,
    ember_sources: 0,
    ...patch,
  };
}

function ctx(now = 1_000): RowEventContext {
  return {
    now,
    reversibleStateEnteredAt: new Map(),
    reversibleStateLeftAt: new Map(),
    sourceCountsUpdatedAt: new Map(),
  };
}

describe('shallowEqualRow / keepIdentity', () => {
  it('treats an undefined key as an absent one', () => {
    const a = row('a');
    expect(shallowEqualRow(a, { ...a, health_reason: undefined })).toBe(true);
    expect(shallowEqualRow(a, { ...a, health_reason: 'x' })).toBe(false);
    expect(shallowEqualRow({ ...a, health_reason: 'x' }, a)).toBe(false);
  });

  it('keeps the previous object when the values match', () => {
    const a = row('a');
    expect(keepIdentity(a, { ...a })).toBe(a);
    const moved = { ...a, speed: 5 };
    expect(keepIdentity(a, moved)).toBe(moved);
  });
});

describe('applyRowPatches', () => {
  it('returns the same list when no patch changes a value', () => {
    const list = [row('a'), row('b')];
    const out = applyRowPatches(list, [
      ['a', (t) => ({ ...t })],
      ['missing', () => null],
      ['b', (t) => applySpeedDecay(t, t.speed)],
    ]);
    expect(out).toBe(list);
  });

  it('replaces only the changed rows and keeps the rest by identity', () => {
    const list = [row('a'), row('b'), row('c')];
    const out = applyRowPatches(list, [['b', (t) => ({ ...t, speed: 0 })]]);
    expect(out).not.toBe(list);
    expect(out[0]).toBe(list[0]);
    expect(out[2]).toBe(list[2]);
    expect(out[1].speed).toBe(0);
    expect(list[1].speed).toBe(100);
  });

  it('applies patches in arrival order, including across a removal', () => {
    const list = [row('a'), row('b'), row('c')];
    const out = applyRowPatches(list, [
      ['b', (t) => ({ ...t, speed: 1 })],
      ['a', () => null],
      ['c', (t) => ({ ...t, speed: 2 })],
      ['b', (t) => ({ ...t, speed: t.speed + 10 })],
    ]);
    expect(out.map((t) => [t.id, t.speed])).toEqual([
      ['b', 11],
      ['c', 2],
    ]);
  });

  it('batches a status event after a health event in the order they arrived', () => {
    const list = [row('a', { status: 'searching', health: 'degraded', health_reason: 'x' })];
    const c = ctx();
    const out = applyRowPatches(list, [
      ['a', (t) => applyHealthEvent(t, { id: 'a', health: 'stalled', health_reason: 'y' })],
      ['a', (t) => applyStatusEvent(t, { id: 'a', status: 'active' }, c)],
    ]);
    // Entering `active` clears runtime health, as the backend does.
    expect(out[0].status).toBe('active');
    expect(out[0].health).toBe('healthy');
    expect(out[0].health_reason).toBeUndefined();
  });
});

describe('row event reducers', () => {
  it('records when a row enters and leaves a reversible state', () => {
    const c = ctx(500);
    const paused = applyStatusEvent(row('a'), { id: 'a', status: 'paused' }, c);
    expect(paused.status).toBe('paused');
    expect(paused.speed).toBe(0);
    expect(c.reversibleStateEnteredAt.get('a')).toBe(500);

    const later = { ...c, now: 900 };
    const resumed = applyStatusEvent(paused, { id: 'a', status: 'searching' }, later);
    expect(resumed.status).toBe('searching');
    expect(c.reversibleStateLeftAt.get('a')).toBe(900);
    expect(c.reversibleStateEnteredAt.has('a')).toBe(false);
  });

  it('never downgrades a terminal row', () => {
    const done = row('a', { status: 'completed' });
    expect(applyStatusEvent(done, { id: 'a', status: 'active' }, ctx()).status).toBe('completed');
  });

  it('leaves frozen rows alone on speed decay', () => {
    const paused = row('a', { status: 'paused', speed: 7 });
    expect(applySpeedDecay(paused, 0)).toBe(paused);
    expect(applySpeedDecay(row('b'), 0).speed).toBe(0);
  });

  it('keeps fresh live source counts over a 0/0 discovery refresh', () => {
    const c = ctx(10_000);
    c.sourceCountsUpdatedAt.set('a', 9_000);
    const out = applySourcesEvent(row('a'), { id: 'a', sources: 5, active_sources: 0, queued_sources: 0 }, c);
    expect(out.sources).toBe(5);
    expect(out.active_sources).toBe(1);
    expect(out.queued_sources).toBe(1);
  });
});

describe('applySnapshotDelta', () => {
  function fresh(): SnapshotState<Transfer> {
    return { epoch: null, revision: 0, rows: new Map() };
  }

  it('replaces on a full snapshot and merges a delta', () => {
    const state = fresh();
    expect(
      applySnapshotDelta(state, { epoch: 7, revision: 3, full: true, transfers: [row('a'), row('b')], removed: [] }),
    ).toBeNull();
    expect([...state.rows.keys()]).toEqual(['a', 'b']);

    const changed = applySnapshotDelta(state, {
      epoch: 7,
      revision: 4,
      full: false,
      transfers: [row('b', { speed: 1 }), row('c')],
      removed: ['a'],
    });
    expect(changed).toEqual(new Set(['a', 'b', 'c']));
    expect([...state.rows.keys()]).toEqual(['b', 'c']);
    expect(state.rows.get('b')?.speed).toBe(1);
    expect(state.revision).toBe(4);
  });

  it('ignores an answer older than the one already applied', () => {
    const state = fresh();
    applySnapshotDelta(state, { epoch: 7, revision: 5, full: true, transfers: [row('a')], removed: [] });
    expect(
      applySnapshotDelta(state, { epoch: 7, revision: 4, full: false, transfers: [row('z')], removed: ['a'] }),
    ).toBeUndefined();
    expect([...state.rows.keys()]).toEqual(['a']);
  });

  it('re-adds a row removed and restored within one delta', () => {
    const state = fresh();
    applySnapshotDelta(state, { epoch: 1, revision: 1, full: true, transfers: [row('a')], removed: [] });
    applySnapshotDelta(state, { epoch: 1, revision: 3, full: false, transfers: [row('a', { speed: 9 })], removed: ['a'] });
    expect(state.rows.get('a')?.speed).toBe(9);
  });

  it('refuses a delta from another epoch but takes its full snapshot', () => {
    const state = fresh();
    applySnapshotDelta(state, { epoch: 1, revision: 9, full: true, transfers: [row('a')], removed: [] });
    expect(
      applySnapshotDelta(state, { epoch: 2, revision: 10, full: false, transfers: [], removed: ['a'] }),
    ).toBeUndefined();
    expect(
      applySnapshotDelta(state, { epoch: 2, revision: 1, full: true, transfers: [row('b')], removed: [] }),
    ).toBeNull();
    expect(state.epoch).toBe(2);
    expect([...state.rows.keys()]).toEqual(['b']);
  });
});

describe('reconcileRows', () => {
  function options(over: Partial<ReconcileOptions<Transfer>> = {}): ReconcileOptions<Transfer> {
    return {
      changed: null,
      needsMerge: () => false,
      merge: (api, current) => ({ ...current, ...api }),
      fresh: (api) => api,
      suppressed: () => false,
      keepMissing: () => false,
      ...over,
    };
  }

  it('returns the same list when the backend matches every row', () => {
    const current = [row('a'), row('b')];
    const api = new Map(current.map((t) => [t.id, { ...t }]));
    expect(reconcileRows(current, api, options())).toBe(current);
  });

  it('keeps unchanged rows by identity and their order', () => {
    const current = [row('b'), row('a'), row('c')];
    const api = new Map([
      ['a', row('a', { speed: 1 })],
      ['b', row('b')],
      ['c', row('c')],
      ['d', row('d')],
    ]);
    const out = reconcileRows(current, api, options({ changed: new Set(['a', 'd']) }));
    expect(out.map((t) => t.id)).toEqual(['b', 'a', 'c', 'd']);
    expect(out[0]).toBe(current[0]);
    expect(out[2]).toBe(current[2]);
    expect(out[1].speed).toBe(1);
  });

  it('only merges rows the backend changed or something else rewrote', () => {
    const current = [row('a', { speed: 50 }), row('b', { speed: 50 })];
    const api = new Map([
      ['a', row('a')],
      ['b', row('b')],
    ]);
    const merged: string[] = [];
    const out = reconcileRows(
      current,
      api,
      options({
        changed: new Set(),
        needsMerge: (t) => t.id === 'b',
        merge: (apiRow, cur) => {
          merged.push(cur.id);
          return { ...cur, speed: apiRow.speed };
        },
      }),
    );
    expect(merged).toEqual(['b']);
    expect(out[0]).toBe(current[0]);
    expect(out[1].speed).toBe(100);
  });

  it('drops suppressed rows, never re-adds them, and asks about missing ones', () => {
    const current = [row('gone'), row('zombie'), row('kept')];
    const api = new Map([
      ['kept', row('kept')],
      ['gone', row('gone')],
      ['cancelled', row('cancelled')],
    ]);
    const out = reconcileRows(
      current,
      api,
      options({
        suppressed: (id) => id === 'gone' || id === 'cancelled',
        keepMissing: (t) => t.id === 'zombie',
      }),
    );
    expect(out.map((t) => t.id)).toEqual(['zombie', 'kept']);
  });
});

describe('PendingRowOps', () => {
  type Ev =
    | { kind: 'status'; p: StatusEventPayload; at: number }
    | { kind: 'health'; p: StatusEventPayload }
    | { kind: 'speed'; id: string; speed: number }
    | { kind: 'sources'; p: SourcesEventPayload; at: number };

  function side(seed: Map<string, number>) {
    const maps = {
      reversibleStateEnteredAt: new Map<string, number>(),
      reversibleStateLeftAt: new Map<string, number>(),
      sourceCountsUpdatedAt: new Map(seed),
    };
    return { maps, at: (now: number): RowEventContext => ({ now, ...maps }) };
  }

  /** Apply `events` one at a time and through the queue, and return both. */
  function both(start: Transfer[], events: Ev[], seed = new Map<string, number>()) {
    const seq = side(seed);
    let expected = start;
    for (const e of events) {
      const patch = (t: Transfer): Transfer => {
        switch (e.kind) {
          case 'status': return applyStatusEvent(t, e.p, seq.at(e.at));
          case 'health': return applyHealthEvent(t, e.p);
          case 'speed': return applySpeedDecay(t, e.speed);
          case 'sources': return applySourcesEvent(t, e.p, seq.at(e.at));
        }
      };
      const id = e.kind === 'speed' ? e.id : e.p.id;
      expected = applyRowPatches(expected, [[id, patch]]);
    }
    const queued = side(seed);
    const ops = new PendingRowOps();
    for (const e of events) {
      if (e.kind === 'status') ops.status(e.p.id, (t) => applyStatusEvent(t, e.p, queued.at(e.at)));
      else if (e.kind === 'health') ops.health(e.p);
      else if (e.kind === 'speed') ops.speed(e.id, e.speed);
      else ops.sources(e.p, e.at);
    }
    const size = ops.size;
    const actual = applyRowPatches(start, ops.drain(queued.at));
    return { expected, actual, size, seqMaps: seq.maps, queuedMaps: queued.maps, ops };
  }

  const src = (active: number, queued: number, sources = 9): SourcesEventPayload => ({
    id: 'a',
    sources,
    active_sources: active,
    queued_sources: queued,
  });

  it('stays bounded by the rows it has events for, however long it waits', () => {
    const ops = new PendingRowOps();
    for (let i = 0; i < 10_000; i++) {
      const id = `t${i % 3}`;
      ops.sources({ id, sources: i, active_sources: i % 2, queued_sources: 0 }, i);
      ops.speed(id, i);
      ops.health({ id, health: i % 2 ? 'degraded' : 'healthy' });
    }
    expect(ops.size).toBe(9);
    expect(ops.drain(() => side(new Map()).at(0)).length).toBe(9);
    expect(ops.size).toBe(0);
  });

  it('folds source events without changing what they do', () => {
    const start = [row('a', { active_sources: 1, queued_sources: 1 })];
    // A live report, then idle refreshes inside the grace window: the live
    // counts survive them.
    const inGrace = both(start, [
      { kind: 'sources', p: src(3, 1), at: 1_000 },
      { kind: 'sources', p: src(0, 0, 4), at: 2_000 },
      { kind: 'sources', p: src(0, 0, 5), at: 3_000 },
    ]);
    expect(inGrace.size).toBe(1);
    expect(inGrace.actual).toEqual(inGrace.expected);
    expect(inGrace.actual[0].active_sources).toBe(3);
    expect(inGrace.queuedMaps.sourceCountsUpdatedAt).toEqual(inGrace.seqMaps.sourceCountsUpdatedAt);

    // The last idle one lands after the window: counts drop to zero.
    const late = both(start, [
      { kind: 'sources', p: src(3, 1), at: 1_000 },
      { kind: 'sources', p: src(0, 0), at: 2_000 },
      { kind: 'sources', p: src(0, 0), at: 1_000 + 7_000 },
    ]);
    expect(late.actual).toEqual(late.expected);
    expect(late.actual[0].active_sources).toBe(0);

    // Only idle reports, against counts the row already had.
    const idleOnly = both(
      start,
      [
        { kind: 'sources', p: src(0, 0), at: 2_000 },
        { kind: 'sources', p: src(0, 0), at: 4_000 },
      ],
      new Map([['a', 1_000]]),
    );
    expect(idleOnly.actual).toEqual(idleOnly.expected);
  });

  it('folds health events without losing an earlier failure field', () => {
    const r = both(
      [row('a')],
      [
        { kind: 'health', p: { id: 'a', health: 'degraded', health_reason: 'slow', failure_code: 'x' } },
        { kind: 'health', p: { id: 'a', failure_kind: 'transient' } },
        { kind: 'health', p: { id: 'a', health: 'healthy' } },
        { kind: 'speed', id: 'a', speed: 3 },
        { kind: 'speed', id: 'a', speed: 0 },
      ],
    );
    expect(r.size).toBe(2);
    expect(r.actual).toEqual(r.expected);
    expect(r.actual[0].failure_code).toBe('x');
    expect(r.actual[0].failure_kind).toBe('transient');
    expect(r.actual[0].health_reason).toBeUndefined();
  });

  it('does not fold across a status event for the same row', () => {
    // `active` resets health; the stalled report after it must survive.
    const health = both(
      [row('a', { status: 'searching' })],
      [
        { kind: 'health', p: { id: 'a', health: 'degraded', health_reason: 'x' } },
        { kind: 'status', p: { id: 'a', status: 'active' }, at: 1 },
        { kind: 'health', p: { id: 'a', health: 'stalled', health_reason: 'y' } },
      ],
    );
    expect(health.size).toBe(3);
    expect(health.actual).toEqual(health.expected);
    expect(health.actual[0].health).toBe('stalled');

    // A completed row ignores decay, so the rate from before it must stand.
    const speed = both(
      [row('a')],
      [
        { kind: 'speed', id: 'a', speed: 5 },
        { kind: 'status', p: { id: 'a', status: 'completed' }, at: 2 },
        { kind: 'speed', id: 'a', speed: 0 },
      ],
    );
    expect(speed.actual).toEqual(speed.expected);
    expect(speed.actual[0].speed).toBe(5);
  });
});

describe('reconcileRows after a failed cancel', () => {
  it('merges a row put back as the same object once it is no longer suppressed', () => {
    const reconciled = new WeakSet<Transfer>();
    const stale = row('a', { status: 'active', progress: 10 });
    reconciled.add(stale);
    const resurfaced = new Set<string>();
    const base = {
      needsMerge: (t: Transfer) => !reconciled.has(t),
      merge: (api: Transfer, cur: Transfer) => ({ ...cur, ...api }),
      fresh: (api: Transfer) => api,
      keepMissing: () => false,
      resurfaced,
    };

    // The cancel is in flight: the row is tombstoned and gone from the list,
    // and the poll that carries the backend's pause is consumed without it.
    const api = new Map([['a', row('a', { status: 'paused', progress: 40 })]]);
    const during = reconcileRows<Transfer>([], api, {
      ...base,
      changed: new Set(['a']),
      suppressed: () => true,
    });
    expect(during).toEqual([]);

    // The cancel failed and the page restored the object it had. The next
    // delta has nothing for `a`.
    const restored = [stale];
    const after = reconcileRows(restored, api, {
      ...base,
      changed: new Set(),
      suppressed: () => false,
    });
    expect(after[0].status).toBe('paused');
    expect(after[0].progress).toBe(40);
    expect(resurfaced.size).toBe(0);
  });

  it('forgets a skipped id the backend no longer has', () => {
    const resurfaced = new Set(['gone']);
    reconcileRows([], new Map<string, Transfer>(), {
      changed: new Set(),
      needsMerge: () => false,
      merge: (api) => api,
      fresh: (api) => api,
      suppressed: () => false,
      keepMissing: () => false,
      resurfaced,
    });
    expect(resurfaced.size).toBe(0);
  });
});