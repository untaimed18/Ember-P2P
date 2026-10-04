/**
 * Whether a keydown is the letter `letter` (a–z) for a Ctrl/Cmd shortcut,
 * whatever the keyboard layout.
 *
 * `e.key` is what the layout types: Cyrillic on a Russian layout, so Ctrl+V
 * arrives as `м`. Only then does the physical key decide, as native shortcuts
 * do. A layout that types a Latin letter is taken at its word, so AZERTY's
 * Ctrl+A is still the key labelled A and not the one where QWERTY keeps it.
 * Never with Alt held: Windows reports AltGr as Ctrl+Alt, and AltGr+K typing
 * `ł` is text, not Ctrl+K.
 *
 * Punctuation on a letter's key is punctuation where a Latin layout puts it
 * there: Dvorak's `,` sits where QWERTY has W, and Ctrl+, is not Ctrl+W.
 * Hebrew types `'` on that key too but reports it with W's key code, which is
 * what native shortcuts go by, so for punctuation that code decides.
 */
export function isShortcutLetter(
  e: Pick<KeyboardEvent, 'key' | 'code' | 'keyCode' | 'altKey'>,
  letter: string,
): boolean {
  const wanted = letter.toLowerCase();
  if (/^[a-z]$/i.test(e.key)) return e.key.toLowerCase() === wanted;
  if (e.altKey || e.code !== `Key${wanted.toUpperCase()}`) return false;
  if (/^[\p{P}\p{S}\p{N}\p{Z}]$/u.test(e.key)) return e.keyCode === wanted.toUpperCase().charCodeAt(0);
  return true;
}
