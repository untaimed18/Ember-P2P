/** Platform helpers for keyboard-shortcut chrome (tooltips, ARIA, cheat-sheet). */

export function isApplePlatform(): boolean {
  return typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/.test(navigator.platform);
}

/** Visible modifier: ⌘ on Apple, Ctrl elsewhere. */
export function shortcutModSymbol(): string {
  return isApplePlatform() ? '\u2318' : 'Ctrl';
}

/** `aria-keyshortcuts` token: Meta on Apple, Control elsewhere. */
export function shortcutModAria(): string {
  return isApplePlatform() ? 'Meta' : 'Control';
}
