import * as m from '$lib/paraglide/messages';

export type NavItem = {
  href: string;
  /** Function returning the localized label. We keep `label` as a
   *  thunk (rather than a pre-resolved string) so the array can
   *  remain a top-level `const` while still picking up locale
   *  changes — Paraglide message functions read the current
   *  locale on each call. */
  label: () => string;
  id: string;
  /** Legacy URLs that should highlight this item (and short-circuit
   *  re-navigation) until the route-level redirect fires. The KAD
   *  view used to live at `/kad-network`; we keep the alias so the
   *  sidebar doesn't flicker between "no item active" and "KAD
   *  active" on the brief detour through the redirect stub. */
  aliases?: string[];
};

/**
 * Primary sidebar navigation, in display order.
 *
 * Shared with the keyboard cheat-sheet rather than duplicated, because the
 * Alt+N shortcut for an entry is just its position here. The two lists were
 * once maintained separately and silently drifted: inserting Ember in the
 * middle shifted three shortcuts without the cheat-sheet noticing, so it
 * advertised the wrong key for each of them.
 */
export const navItems: NavItem[] = [
  { href: '/ember', label: () => m.nav_ember_network(), id: 'ember' },
  { href: '/', label: () => m.nav_kad_network(), id: 'kad', aliases: ['/kad-network'] },
  { href: '/servers', label: () => m.nav_ed2k_servers(), id: 'servers' },
  { href: '/search', label: () => m.nav_search(), id: 'search' },
  { href: '/transfers', label: () => m.nav_transfers(), id: 'transfers' },
  { href: '/library', label: () => m.nav_library(), id: 'library' },
  { href: '/friends', label: () => m.nav_friends(), id: 'friends' },
  { href: '/channels', label: () => m.nav_channels(), id: 'channels' },
  { href: '/statistics', label: () => m.nav_statistics(), id: 'statistics' },
  { href: '/security', label: () => m.nav_security(), id: 'security' },
  { href: '/settings', label: () => m.nav_settings(), id: 'settings' },
];

/**
 * How many entries get an Alt+N shortcut. Alt+1..9 map to the first nine
 * items; Alt+0 maps to the tenth (Security, today). Anything past that is
 * click-only — worth remembering when reordering, and the reason this says
 * "today": inserting Channels moved which page the tenth slot lands on.
 */
export const NAV_SHORTCUT_LIMIT = 10;

/** Digit shown in "Alt+N" for the item at `index` (0-based). */
export function navShortcutDigit(index: number): string | null {
  if (index < 0 || index >= NAV_SHORTCUT_LIMIT) return null;
  return index === 9 ? '0' : String(index + 1);
}

/** 0-based nav index for a pressed digit key, or null if it isn't a nav shortcut. */
export function navIndexFromDigitKey(key: string): number | null {
  if (key === '0') return 9;
  if (key.length === 1 && key >= '1' && key <= '9') return Number(key) - 1;
  return null;
}

/**
 * Resolve a sidebar Alt+N shortcut from a keydown event. Prefer the physical
 * top-row `Digit*` code so Option/Alt still works on Apple layouts where
 * `e.key` becomes a symbol (º, ¡, ™, …). Numpad is ignored: Windows Alt+Numpad
 * is character entry.
 */
export function navIndexFromShortcutEvent(e: KeyboardEvent): number | null {
  // Windows Alt+Numpad is character entry (Alt+0169 → ©). Do not treat
  // Numpad digits as sidebar shortcuts even though `e.key` is still "1"/"0".
  if (e.code.startsWith('Numpad')) return null;
  if (e.code.startsWith('Digit') && e.code.length === 6) {
    return navIndexFromDigitKey(e.code.slice(5));
  }
  return navIndexFromDigitKey(e.key);
}
