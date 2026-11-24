/** Platform helpers for keyboard-shortcut chrome (tooltips, ARIA, cheat-sheet). */
import * as m from '$lib/paraglide/messages';
import { isServer } from '$lib/runtime';

/** Whether deleted files go to the Recycle Bin, as Windows calls it, rather
 *  than the Trash. emberd's files are on its server, which runs Linux,
 *  whatever the browser looking at them runs. */
export function binIsRecycleBin(): boolean {
  return !isServer && typeof navigator !== 'undefined' && /Windows/.test(navigator.userAgent);
}

export function isApplePlatform(): boolean {
  return typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/.test(navigator.platform);
}

/** Visible modifier: ⌘ on Apple, Ctrl (as the active locale names it) elsewhere. */
export function shortcutModSymbol(): string {
  return isApplePlatform() ? '\u2318' : m.shortcuts_key_ctrl();
}

/** Visible Alt key: ⌥ (Option) on Apple, Alt (as the active locale names it) elsewhere. */
export function shortcutAltSymbol(): string {
  return isApplePlatform() ? '\u2325' : m.shortcuts_key_alt();
}

/** `aria-keyshortcuts` token: Meta on Apple, Control elsewhere. */
export function shortcutModAria(): string {
  return isApplePlatform() ? 'Meta' : 'Control';
}
