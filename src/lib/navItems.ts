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
 * How many entries get an Alt+N shortcut. Single digits only, so anything
 * past the ninth entry is reachable by click alone — worth remembering when
 * reordering, since the last item silently loses its shortcut.
 */
export const NAV_SHORTCUT_LIMIT = 9;
