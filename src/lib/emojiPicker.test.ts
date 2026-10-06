import { describe, expect, it } from 'vitest';
import {
  EMOJI_CATEGORIES,
  insertAtSelection,
  loadRecentEmoji,
  noteRecentEmoji,
  RECENT_EMOJI_LIMIT,
} from './emojiPicker';

function memoryStorage(seed: Record<string, string> = {}) {
  const data = new Map(Object.entries(seed));
  return {
    data,
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => void data.set(key, value),
  };
}

describe('emoji set', () => {
  it('offers each glyph once, so the grid can key on it', () => {
    const all = EMOJI_CATEGORIES.flatMap((category) => category.emoji);
    expect(new Set(all).size).toBe(all.length);
    for (const category of EMOJI_CATEGORIES) {
      expect(category.emoji.length).toBeGreaterThan(0);
      expect(category.emoji).toContain(category.icon);
    }
  });
});

describe('recent emoji', () => {
  it('puts the latest pick first, once, up to the limit', () => {
    const storage = memoryStorage();
    noteRecentEmoji('😀', storage);
    noteRecentEmoji('👍', storage);
    expect(noteRecentEmoji('😀', storage)).toEqual(['😀', '👍']);
    const many = EMOJI_CATEGORIES[0].emoji.slice(0, RECENT_EMOJI_LIMIT + 4);
    for (const e of many) noteRecentEmoji(e, storage);
    expect(loadRecentEmoji(storage)).toHaveLength(RECENT_EMOJI_LIMIT);
    expect(loadRecentEmoji(storage)[0]).toBe(many[many.length - 1]);
  });

  it('keeps only glyphs the picker draws', () => {
    const storage = memoryStorage({ 'ember.emoji.recent.v1': JSON.stringify(['👍', '<b>', 7, '👍']) });
    expect(loadRecentEmoji(storage)).toEqual(['👍']);
    expect(loadRecentEmoji(memoryStorage({ 'ember.emoji.recent.v1': '{' }))).toEqual([]);
    expect(loadRecentEmoji(null)).toEqual([]);
  });
});

describe('insertAtSelection', () => {
  it('goes in at the caret, or over the selection', () => {
    expect(insertAtSelection('hi there', 2, 2, '👋', 100)).toEqual({ text: 'hi👋 there', caret: 4 });
    expect(insertAtSelection('hi there', 3, 8, '🎉', 100)).toEqual({ text: 'hi 🎉', caret: 5 });
  });

  it('clamps a stale caret to the text it is given', () => {
    expect(insertAtSelection('ab', 9, 12, '✅', 100)).toEqual({ text: 'ab✅', caret: 3 });
  });

  it('refuses to pass the length limit', () => {
    expect(insertAtSelection('abc', 3, 3, '😀', 4)).toBeNull();
    expect(insertAtSelection('abc', 0, 3, '😀', 4)).toEqual({ text: '😀', caret: 2 });
  });
});
