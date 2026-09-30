import { describe, expect, it } from 'vitest';
import { isShortcutLetter } from './shortcutKey';

const key = (key: string, code: string, altKey = false) => ({ key, code, altKey });

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
  });

  it('trusts a Latin letter over where the key sits', () => {
    // AZERTY: the key labelled A sits where QWERTY has Q, and the reverse.
    expect(isShortcutLetter(key('a', 'KeyQ'), 'a')).toBe(true);
    expect(isShortcutLetter(key('q', 'KeyA'), 'a')).toBe(false);
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
