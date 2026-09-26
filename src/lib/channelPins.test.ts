import { describe, expect, it } from 'vitest';
import {
  clampPinIndex,
  nextPinIndex,
  pinAction,
  pinIndexAfterChange,
  resolvePins,
} from './channelPins';
import type { ChannelPinInfo } from './api/channels';
import type { QuotableMessage } from './channelReply';

const A = 'a'.repeat(32);
const B = 'b'.repeat(32);
const C = 'c'.repeat(32);

function lookup(msgId: string, id: number, excerpt: string): ChannelPinInfo {
  return { msg_id: msgId, message: { id, sender_pubkey: 'pk', excerpt }, deleted: false };
}

describe('resolvePins', () => {
  it('lists the newest pin first', () => {
    const pins = resolvePins([A, B], [lookup(A, 1, 'first'), lookup(B, 2, 'second')], new Map(), new Set());
    expect(pins.map((p) => p.msgId)).toEqual([B, A]);
    expect(pins[0]).toEqual({ kind: 'message', msgId: B, id: 2, senderPubkey: 'pk', text: 'second' });
  });

  it('prefers the loaded copy, which live edits patch', () => {
    const loaded = new Map<string, QuotableMessage>([
      [A, { id: 1, sender_pubkey: 'pk2', message: 'edited' }],
    ]);
    const [pin] = resolvePins([A], [lookup(A, 1, 'original')], loaded, new Set());
    expect(pin).toMatchObject({ kind: 'message', text: 'edited', senderPubkey: 'pk2' });
  });

  it('ignores a loaded live bubble without a stored row', () => {
    const loaded = new Map<string, QuotableMessage>([[A, { id: -3, message: 'live' }]]);
    const [pin] = resolvePins([A], [lookup(A, 9, 'stored')], loaded, new Set());
    expect(pin).toMatchObject({ kind: 'message', id: 9, text: 'stored' });
  });

  it('marks a pin not held here as missing rather than hiding it', () => {
    const pins = resolvePins([A, B], [lookup(A, 1, 'held')], new Map(), new Set());
    expect(pins[0]).toEqual({ kind: 'missing', msgId: B });
    expect(pins).toHaveLength(2);
  });

  it('drops a pin removed from this device, by the backend or in this session', () => {
    const deleted: ChannelPinInfo = { msg_id: B, message: null, deleted: true };
    const pins = resolvePins([A, B, C], [lookup(A, 1, 'a'), deleted, lookup(C, 3, 'c')], new Map(), new Set([C]));
    expect(pins.map((p) => p.msgId)).toEqual([A]);
  });

  it('follows the pin list even when the lookups lag it', () => {
    expect(resolvePins([], [lookup(A, 1, 'stale')], new Map(), new Set())).toEqual([]);
  });
});

describe('pin index', () => {
  it('cycles and wraps', () => {
    expect(nextPinIndex(0, 3)).toBe(1);
    expect(nextPinIndex(2, 3)).toBe(0);
    expect(nextPinIndex(0, 1)).toBe(0);
    expect(nextPinIndex(0, 0)).toBe(0);
  });

  it('clamps into a list that shrank', () => {
    expect(clampPinIndex(2, 1)).toBe(0);
    expect(clampPinIndex(1, 3)).toBe(1);
    expect(clampPinIndex(-1, 3)).toBe(0);
    expect(clampPinIndex(4, 0)).toBe(0);
  });
});

describe('pinIndexAfterChange', () => {
  it('keeps the reader where they were when the list is the same', () => {
    expect(pinIndexAfterChange([A, B, C], [A, B, C], 2)).toBe(2);
  });

  it('shows a new pin first', () => {
    expect(pinIndexAfterChange([A, B], [A, B, C], 1)).toBe(0);
    expect(pinIndexAfterChange([A, B], [B, C], 1)).toBe(0);
  });

  it('clamps when a pin is taken away under the reader', () => {
    expect(pinIndexAfterChange([A, B, C], [A, B], 2)).toBe(1);
    expect(pinIndexAfterChange([A, B, C], [B, C], 1)).toBe(1);
    expect(pinIndexAfterChange([A], [], 0)).toBe(0);
  });

  it('starts at the first pin in a room just opened', () => {
    expect(pinIndexAfterChange([], [A, B], 1)).toBe(0);
  });
});

describe('pinAction', () => {
  it('offers unpin for a pinned line, pin under the cap, and nothing at it', () => {
    expect(pinAction(A, [A], 3)).toBe('unpin');
    expect(pinAction(B, [A], 3)).toBe('pin');
    expect(pinAction(C, [A, B, 'd'.repeat(32)], 3)).toBe('full');
    expect(pinAction(A, [A, B, C], 3)).toBe('unpin');
  });
});
