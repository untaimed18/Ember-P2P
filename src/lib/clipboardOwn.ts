// What Ember last put on the clipboard. "Copy link" in Ember is no reason to
// offer the link back the next time the window gains focus.
//
// Kept in localStorage so a copy made in the popped-out chat window counts in
// the main one too; both share it. Only a fingerprint is stored, never the
// text: a copied chat message has no business being written to disk.

const STORAGE_KEY = 'ember-own-clipboard';

let own: string | null = null;

function fingerprint(text: string): string {
  // FNV-1a, 32-bit: enough to tell "the text Ember copied" from anything else.
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${text.length}:${hash.toString(16)}`;
}

export function noteOwnClipboardText(text: string): void {
  own = fingerprint(text.trim());
  try {
    localStorage.setItem(STORAGE_KEY, own);
  } catch {
    // This window still knows.
  }
}

export function isOwnClipboardText(text: string): boolean {
  let stored: string | null = null;
  try {
    stored = localStorage.getItem(STORAGE_KEY);
  } catch {
    // Fall back to this window's own record.
  }
  const latest = stored ?? own;
  return latest !== null && fingerprint(text.trim()) === latest;
}
