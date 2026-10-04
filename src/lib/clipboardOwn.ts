// What Ember last put on the clipboard. "Copy link" in Ember is no reason to
// offer the link back the next time the window gains focus.

let own: string | null = null;

export function noteOwnClipboardText(text: string): void {
  own = text.trim();
}

export function isOwnClipboardText(text: string): boolean {
  return own !== null && text.trim() === own;
}
