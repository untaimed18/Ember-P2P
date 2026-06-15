import { writable } from 'svelte/store';
import { getSettings } from '$lib/api/settings';
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

export async function loadAppSettings(): Promise<void> {
  try {
    appSettings.set(await getSettings());
  } catch {
    // Backend not ready yet — consumers fall back to defaults until a later
    // load (or a Settings save) populates the cache.
  }
}

/** Mirror a just-persisted settings object into the cache. Call after a
 *  successful `updateSettings` so the cache never lags the on-disk value. */
export function setAppSettings(settings: AppSettings): void {
  appSettings.set(settings);
}

export function clearAppSettings(): void {
  appSettings.set(null);
}
