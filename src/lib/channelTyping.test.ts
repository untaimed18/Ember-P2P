import { describe, expect, it } from 'vitest';
import {
  dropTypist,
  nextTypistExpiry,
  noteTypist,
  outgoingTypingAction,
  pruneTypists,
  shouldAnnounceTyping,
  typingLineSegments,
  visibleTypists,
  ROOM_TYPING_ANNOUNCE_GAP_MS,
  ROOM_TYPING_EXPIRE_MS,
  ROOM_TYPING_REFRESH_MS,
  type Typists,
} from './channelTyping';

const ADA = 'aa'.repeat(32);
const BO = 'bb'.repeat(32);
const CY = 'cc'.repeat(32);

const messages = {
  one: (name: string) => `${name} is typing…`,
  two: (first: string, second: string) => `${first} and ${second} are typing…`,
  several: () => 'Several people are typing…',
};

describe('typing expiry bookkeeping', () => {
  it('lapses an indicator a fixed time after its last signal', () => {
    let typists: Typists = new Map();
    typists = noteTypist(typists, ADA, 1000);
    expect(visibleTypists(typists, 1000)).toEqual([ADA]);
    expect(visibleTypists(typists, 1000 + ROOM_TYPING_EXPIRE_MS - 1)).toEqual([ADA]);
    expect(visibleTypists(typists, 1000 + ROOM_TYPING_EXPIRE_MS)).toEqual([]);
    expect(nextTypistExpiry(typists)).toBe(1000 + ROOM_TYPING_EXPIRE_MS);
  });

  it('keeps a refreshed indicator up and in its place', () => {
    let typists: Typists = new Map();
    typists = noteTypist(typists, ADA, 0);
    typists = noteTypist(typists, BO, 1000);
    typists = noteTypist(typists, ADA, 4000);
    // Past Bo's lapse, and Ada's original one, but inside her refreshed one.
    expect(visibleTypists(typists, 1000 + ROOM_TYPING_EXPIRE_MS)).toEqual([ADA]);
    expect(visibleTypists(typists, 2000)).toEqual([ADA, BO]);
  });

  it('keys members case-insensitively', () => {
    const typists = noteTypist(new Map(), ADA.toUpperCase(), 0);
    expect(visibleTypists(typists, 0)).toEqual([ADA]);
    expect(dropTypist(typists, ADA).size).toBe(0);
  });

  it('prunes only what lapsed, and hands back the same map when nothing did', () => {
    let typists: Typists = new Map();
    typists = noteTypist(typists, ADA, 0);
    typists = noteTypist(typists, BO, 3000);
    expect(pruneTypists(typists, 100)).toBe(typists);
    const pruned = pruneTypists(typists, ROOM_TYPING_EXPIRE_MS);
    expect([...pruned.keys()]).toEqual([BO]);
    expect(nextTypistExpiry(pruned)).toBe(3000 + ROOM_TYPING_EXPIRE_MS);
    expect(nextTypistExpiry(new Map())).toBeNull();
  });

  it('drops an author whose message arrived, and nothing else', () => {
    let typists: Typists = new Map();
    typists = noteTypist(typists, ADA, 0);
    typists = noteTypist(typists, BO, 0);
    expect(visibleTypists(dropTypist(typists, ADA), 0)).toEqual([BO]);
    expect(dropTypist(typists, CY)).toBe(typists);
  });

  it('never names an ignored member', () => {
    let typists: Typists = new Map();
    typists = noteTypist(typists, ADA, 0);
    typists = noteTypist(typists, BO, 0);
    expect(visibleTypists(typists, 0, [BO.toUpperCase()])).toEqual([ADA]);
  });
});

describe('outgoingTypingAction', () => {
  const base = { hasText: true, allowed: true, lastSentOn: false, lastSentAt: 0, now: 10_000 };

  it('starts on the first keystroke and refreshes at most once per window', () => {
    expect(outgoingTypingAction(base)).toBe('start');
    const sent = { ...base, lastSentOn: true, lastSentAt: 10_000 };
    expect(outgoingTypingAction({ ...sent, now: 10_000 + ROOM_TYPING_REFRESH_MS - 1 })).toBeNull();
    expect(outgoingTypingAction({ ...sent, now: 10_000 + ROOM_TYPING_REFRESH_MS })).toBe('start');
  });

  it('stops only an indicator it raised', () => {
    expect(outgoingTypingAction({ ...base, hasText: false, lastSentOn: true })).toBe('stop');
    expect(outgoingTypingAction({ ...base, hasText: false })).toBeNull();
  });

  it('sends nothing but a stop while typing is not allowed', () => {
    expect(outgoingTypingAction({ ...base, allowed: false })).toBeNull();
    expect(outgoingTypingAction({ ...base, allowed: false, lastSentOn: true })).toBe('stop');
  });
});

describe('typingLineSegments', () => {
  it('names one or two people and collapses more', () => {
    expect(typingLineSegments([], messages)).toEqual([]);
    expect(typingLineSegments(['Ada'], messages)).toEqual([
      { kind: 'name', text: 'Ada' },
      { kind: 'text', text: ' is typing…' },
    ]);
    expect(typingLineSegments(['Ada', 'Bo'], messages)).toEqual([
      { kind: 'name', text: 'Ada' },
      { kind: 'text', text: ' and ' },
      { kind: 'name', text: 'Bo' },
      { kind: 'text', text: ' are typing…' },
    ]);
    expect(typingLineSegments(['Ada', 'Bo', 'Cy'], messages)).toEqual([
      { kind: 'text', text: 'Several people are typing…' },
    ]);
  });

  it('follows a translation that puts the names in another order', () => {
    const reordered = { ...messages, two: (first: string, second: string) => `${second}、${first}が入力中…` };
    expect(typingLineSegments(['Ada', 'Bo'], reordered)).toEqual([
      { kind: 'name', text: 'Bo' },
      { kind: 'text', text: '、' },
      { kind: 'name', text: 'Ada' },
      { kind: 'text', text: 'が入力中…' },
    ]);
  });

  it('keeps a name whole rather than reading it as part of the sentence', () => {
    const tricky = 'אדה \uE001';
    expect(typingLineSegments([tricky], messages)).toEqual([
      { kind: 'name', text: tricky },
      { kind: 'text', text: ' is typing…' },
    ]);
  });
});

describe('shouldAnnounceTyping', () => {
  const gap = ROOM_TYPING_ANNOUNCE_GAP_MS;

  it('speaks when the room goes from nobody typing to somebody', () => {
    expect(shouldAnnounceTyping({ active: true, wasActive: false, lastAnnouncedAt: -Infinity, now: 0 })).toBe(true);
  });

  it('stays quiet while the line only changes who is named', () => {
    expect(shouldAnnounceTyping({ active: true, wasActive: true, lastAnnouncedAt: -Infinity, now: 0 })).toBe(false);
    expect(shouldAnnounceTyping({ active: false, wasActive: true, lastAnnouncedAt: 0, now: 1 })).toBe(false);
  });

  it('waits out the gap before speaking again', () => {
    const at = 1_000_000;
    expect(shouldAnnounceTyping({ active: true, wasActive: false, lastAnnouncedAt: at, now: at + gap - 1 })).toBe(false);
    expect(shouldAnnounceTyping({ active: true, wasActive: false, lastAnnouncedAt: at, now: at + gap })).toBe(true);
  });
});
