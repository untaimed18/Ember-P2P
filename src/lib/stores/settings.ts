import { writable } from 'svelte/store';
import { getSettings } from '$lib/api/settings';
import { setHiddenToastAreas, type ToastArea } from '$lib/stores/toast';
import type { AppSettings } from '$lib/types';

/**
 * Process-wide cache of the persisted {@link AppSettings}, so feature code
 * that lives outside the Settings page (the friends store's online-notification
 * toast, the chat dock's "chat disabled" state, …) can read user preferences
 * reactively without each doing its own `getSettings()` round-trip.
 *
 * `null` until the first load completes; consumers treat that as "unknown" and
 * fall back to conservative defaults. Kept fresh by:
 *  - {@link loadAppSettings} on app boot (called from the layout), and
 *  - {@link setAppSettings} after the Settings page persists a change,
 * so a toggle flipped at runtime takes effect immediately, not just next launch.
 */
export const appSettings = writable<AppSettings | null>(null);
let settingsEpoch = 0;

const TOAST_AREA_SETTINGS: Record<ToastArea, keyof AppSettings> = {
  downloads: 'popups_downloads',
  search: 'popups_search',
  library: 'popups_library',
  friends: 'popups_friends',
  channels: 'popups_channels',
  feeds: 'popups_feeds',
  network: 'popups_network',
};

/** The areas `settings` turns off. Unknown settings show everything. */
export function hiddenToastAreas(settings: AppSettings | null): ToastArea[] {
  if (!settings) return [];
  return (Object.keys(TOAST_AREA_SETTINGS) as ToastArea[]).filter(
    (area) => settings[TOAST_AREA_SETTINGS[area]] === false,
  );
}

/** Keep the toast store's hidden areas in step with the settings, for as long
 *  as the returned unsubscribe is not called. Each window calls it once. */
export function syncToastAreasWithSettings(): () => void {
  return appSettings.subscribe((settings) => setHiddenToastAreas(hiddenToastAreas(settings)));
}

function keepNewestSettings(current: AppSettings | null, incoming: AppSettings): AppSettings {
  return current && incoming.settings_revision < current.settings_revision
    ? current
    : incoming;
}

export async function loadAppSettings(): Promise<void> {
  const epoch = settingsEpoch;
  try {
    const settings = await getSettings();
    if (epoch === settingsEpoch) {
      appSettings.update((current) => keepNewestSettings(current, settings));
    }
  } catch {
    // Backend not ready yet — consumers fall back to defaults until a later
    // load (or a Settings save) populates the cache.
  }
}

/** Mirror a just-persisted settings object into the cache. Call after a
 *  successful `updateSettings` so the cache never lags the on-disk value. */
export function setAppSettings(settings: AppSettings): void {
  // Any explicit write is newer than a load that started before it, even when
  // the load's IPC response arrives afterward.
  settingsEpoch++;
  // Settings revisions are monotonic. A delayed getSettings() or an older
  // caller snapshot must never roll runtime consumers back to stale values.
  appSettings.update((current) => keepNewestSettings(current, settings));
}

export function clearAppSettings(): void {
  settingsEpoch++;
  appSettings.set(null);
}
