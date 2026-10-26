import { describe, expect, it } from 'vitest';
import { EarlyRoomDeliveries, stepSlowModeAnnouncer, type SlowModeAnnouncer } from './conversationState';

describe('EarlyRoomDeliveries', () => {
  it('applies a report that beat the send to the row it names, once', () => {
    const early = new EarlyRoomDeliveries();
    expect(early.hold(7, 'failed', true)).toBe(true);
    const row = { id: 7, delivery: 'delivered', message: 'hi' };
    expect(early.apply(row)).toEqual({ ...row, delivery: 'failed' });
    expect(early.apply(row)).toBe(row);
    expect(early.size).toBe(0);
  });

  it('keeps nothing when no send is waiting to add the row', () => {
    const early = new EarlyRoomDeliveries();
    expect(early.hold(7, 'queued', false)).toBe(false);
    expect(early.size).toBe(0);
  });

  it('leaves other rows alone and forgets everything on a switch', () => {
    const early = new EarlyRoomDeliveries();
    early.hold(1, 'queued', true);
    const other = { id: 2, delivery: 'delivered' };
    expect(early.apply(other)).toBe(other);
    early.clear();
    expect(early.apply({ id: 1, delivery: 'delivered' }).delivery).toBe('delivered');
  });
});

describe('stepSlowModeAnnouncer', () => {
  const run = (steps: [string, boolean][]) => {
    let state: SlowModeAnnouncer = { key: 'room-a', waiting: false };
    return steps.map(([key, waiting]) => {
      const { next, say } = stepSlowModeAnnouncer(state, key, waiting);
      state = next;
      return say;
    });
  };

  it('speaks only the start and the end of a wait', () => {
    expect(
      run([
        ['room-a', true],
        ['room-a', true],
        ['room-a', true],
        ['room-a', false],
        ['room-a', false],
      ]),
    ).toEqual(['started', null, null, 'ready', null]);
  });

  it('does not call a wait over because the conversation changed', () => {
    expect(
      run([
        ['room-a', true],
        ['room-b', false],
        ['room-b', false],
        ['room-b', true],
      ]),
    ).toEqual(['started', 'clear', null, 'started']);
  });

  it('clears on a switch even into a room already waiting, then follows it', () => {
    expect(run([['room-b', true], ['room-b', true], ['room-b', false]])).toEqual(['clear', 'started', 'ready']);
  });
});
