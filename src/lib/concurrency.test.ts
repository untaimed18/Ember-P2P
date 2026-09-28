import { describe, expect, it } from 'vitest';
import { mapSettledWithLimit } from './concurrency';

function deferred<T = void>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

describe('mapSettledWithLimit', () => {
  it('returns nothing for no items without calling fn', async () => {
    let calls = 0;
    const results = await mapSettledWithLimit([], 4, async () => { calls++; });
    expect(results).toEqual([]);
    expect(calls).toBe(0);
  });

  it('never runs more than `limit` calls at once', async () => {
    const gates = Array.from({ length: 10 }, () => deferred());
    let inFlight = 0;
    let peak = 0;
    const run = mapSettledWithLimit(gates, 4, async (gate) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await gate.promise;
      inFlight--;
    });
    await flush();
    expect(inFlight).toBe(4);
    for (const gate of gates) {
      gate.resolve();
      await flush();
      expect(inFlight).toBeLessThanOrEqual(4);
    }
    await run;
    expect(peak).toBe(4);
    expect(inFlight).toBe(0);
  });

  it('keeps input order and settles every item despite failures', async () => {
    const results = await mapSettledWithLimit([1, 2, 3, 4, 5], 2, async (n) => {
      await new Promise((resolve) => setTimeout(resolve, (5 - n) * 2));
      if (n % 2 === 0) throw new Error(`bad ${n}`);
      return n * 10;
    });
    expect(results.map((r) => r.status)).toEqual([
      'fulfilled', 'rejected', 'fulfilled', 'rejected', 'fulfilled',
    ]);
    expect(results[0]).toEqual({ status: 'fulfilled', value: 10 });
    expect((results[1] as PromiseRejectedResult).reason).toEqual(new Error('bad 2'));
    expect(results[4]).toEqual({ status: 'fulfilled', value: 50 });
  });

  it('reports a synchronous throw as that item’s rejection', async () => {
    const results = await mapSettledWithLimit(['a', 'b'], 1, (s) => {
      if (s === 'a') throw new Error('sync');
      return Promise.resolve(s);
    });
    expect(results[0].status).toBe('rejected');
    expect(results[1]).toEqual({ status: 'fulfilled', value: 'b' });
  });

  it('treats a nonsensical limit as serial', async () => {
    let inFlight = 0;
    let peak = 0;
    const work = async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await flush();
      inFlight--;
    };
    await mapSettledWithLimit([1, 2, 3], 0, work);
    expect(peak).toBe(1);
    peak = 0;
    await mapSettledWithLimit([1, 2, 3], Number.NaN, work);
    expect(peak).toBe(1);
  });
});
