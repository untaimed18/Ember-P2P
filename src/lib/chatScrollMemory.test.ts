import { afterEach, describe, expect, it } from 'vitest';
import {
  firstRowBelow,
  forgetAllScroll,
  recalledScroll,
  rememberScroll,
  SCROLL_MEMORY_LIMIT,
} from './chatScrollMemory';

afterEach(() => forgetAllScroll());

describe('rememberScroll', () => {
  it('keeps a spot per conversation and forgets it on null', () => {
    rememberScroll('ch:a', { id: 10, offset: -4 });
    rememberScroll('friend', { id: 3, offset: 12 });
    expect(recalledScroll('ch:a')).toEqual({ id: 10, offset: -4 });
    expect(recalledScroll('friend')).toEqual({ id: 3, offset: 12 });
    rememberScroll('ch:a', null);
    expect(recalledScroll('ch:a')).toBeUndefined();
    expect(recalledScroll('friend')).toEqual({ id: 3, offset: 12 });
  });

  it('drops the conversation left longest ago once full', () => {
    for (let i = 0; i < SCROLL_MEMORY_LIMIT; i++) rememberScroll(`k${i}`, { id: i + 1, offset: 0 });
    // Touched again, so it is now the newest rather than the oldest.
    rememberScroll('k0', { id: 99, offset: 0 });
    rememberScroll('extra', { id: 1, offset: 0 });
    expect(recalledScroll('k0')).toEqual({ id: 99, offset: 0 });
    expect(recalledScroll('k1')).toBeUndefined();
    expect(recalledScroll('extra')).toBeDefined();
  });
});

describe('firstRowBelow', () => {
  const bottoms = [10, 30, 50, 70];
  const at = (i: number) => bottoms[i];

  it('finds the first row reaching past the top edge', () => {
    expect(firstRowBelow(at, bottoms.length, 0)).toBe(0);
    expect(firstRowBelow(at, bottoms.length, 10)).toBe(1);
    expect(firstRowBelow(at, bottoms.length, 45)).toBe(2);
  });

  it('says so when every row is above', () => {
    expect(firstRowBelow(at, bottoms.length, 70)).toBe(4);
    expect(firstRowBelow(at, 0, 0)).toBe(0);
  });
});
