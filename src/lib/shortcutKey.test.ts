import { describe, expect, it } from 'vitest';
import { isShortcutLetter } from './shortcutKey';

const key = (key: string, code: string, altKey = false, keyCode = 0) => ({ key, code, keyCode, altKey });

describe('isShortcutLetter', () => {
  it('matches the letter on a Latin layout, either case', () => {
    expect(isShortcutLetter(key('v', 'KeyV'), 'v')).toBe(true);
    expect(isShortcutLetter(key('V', 'KeyV'), 'v')).toBe(true);
    expect(isShortcutLetter(key('c', 'KeyC'), 'v')).toBe(false);
  });

  it('falls back to the physical key when the layout types another script', () => {
    expect(isShortcutLetter(key('м', 'KeyV'), 'v')).toBe(true);
    expect(isShortcutLetter(key('М', 'KeyV'), 'v')).toBe(true);
    expect(isShortcutLetter(key('с', 'KeyC'), 'v')).toBe(false);
    // Greek, Hebrew, Arabic.
    expect(isShortcutLetter(key('ψ', 'KeyC'), 'c')).toBe(true);
    expect(isShortcutLetter(key('ה', 'KeyV'), 'v')).toBe(true);
    expect(isShortcutLetter(key('ر', 'KeyV'), 'v')).toBe(true);
  });

  it('falls back for keys that type a vowel sign or more than one letter', () => {
    // Thai puts a combining vowel on B; Devanagari InScript puts them on A, S
    // and D; Arabic's B key types lam-alef, two letters.
    expect(isShortcutLetter(key('\u0E34', 'KeyB'), 'b')).toBe(true);
    expect(isShortcutLetter(key('\u094B', 'KeyA'), 'a')).toBe(true);
    expect(isShortcutLetter(key('\u0644\u0627', 'KeyB'), 'b')).toBe(true);
  });

  it('goes by the physical key while an IME holds the key', () => {
    expect(isShortcutLetter(key('Process', 'KeyV', false, 229), 'v')).toBe(true);
  });

  it('trusts a Latin letter over where the key sits', () => {
    // AZERTY: the key labelled A sits where QWERTY has Q, and the reverse.
    expect(isShortcutLetter(key('a', 'KeyQ'), 'a')).toBe(true);
    expect(isShortcutLetter(key('q', 'KeyA'), 'a')).toBe(false);
    // Dvorak: W is where QWERTY has the comma.
    expect(isShortcutLetter(key('w', 'Comma', false, 87), 'w')).toBe(true);
  });

  it('does not read punctuation on a letter key as that letter', () => {
    // Dvorak's comma is where QWERTY has W, AZERTY's where it has M.
    expect(isShortcutLetter(key(',', 'KeyW', false, 188), 'w')).toBe(false);
    expect(isShortcutLetter(key('<', 'KeyW', false, 188), 'w')).toBe(false);
    expect(isShortcutLetter(key(',', 'KeyM', false, 188), 'm')).toBe(false);
  });

  it('takes punctuation on a non-Latin layout as the letter its key code names', () => {
    // Hebrew types an apostrophe on W but still reports VK_W, as Windows
    // shortcuts read it.
    expect(isShortcutLetter(key("'", 'KeyW', false, 87), 'w')).toBe(true);
  });

  it('does not read AltGr text as a shortcut', () => {
    expect(isShortcutLetter(key('ł', 'KeyK', true), 'k')).toBe(false);
    expect(isShortcutLetter(key('@', 'KeyQ', true), 'q')).toBe(false);
  });

  it('never matches a non-letter key', () => {
    expect(isShortcutLetter(key('Enter', 'Enter'), 'v')).toBe(false);
    expect(isShortcutLetter(key('/', 'Slash'), 'v')).toBe(false);
  });
});
