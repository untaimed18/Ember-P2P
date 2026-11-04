/** Platform helpers for keyboard-shortcut chrome (tooltips, ARIA, cheat-sheet). */
import * as m from '$lib/paraglide/messages';

export function isApplePlatform(): boolean {
  return typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/.test(navigator.platform);
}

/** Visible modifier: ⌘ on Apple, Ctrl (as the active locale names it) elsewhere. */
export function shortcutModSymbol(): string {
  return isApplePlatform() ? '\u2318' : m.shortcuts_key_ctrl();
}

/** `aria-keyshortcuts` token: Meta on Apple, Control elsewhere. */
export function shortcutModAria(): string {
  return isApplePlatform() ? 'Meta' : 'Control';
}
