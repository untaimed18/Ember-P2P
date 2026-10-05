/**
 * Preferences the app window keeps in `localStorage` rather than in the data
 * directory, which a profile backup carries alongside its files.
 *
 * Only choices worth carrying to another machine: language, theme, the room
 * lists, ignored people, search history and options, and which columns each
 * list shows. Left out on purpose: sizes and positions (column widths, split
 * and sidebar widths, the chat window's bounds), state that changes with every
 * click (sort orders, filters, collapsed sections, open chat and search tabs),
 * and the dismissed-update record, which must not silence an update notice on
 * a different install.
 *
 * Keep in step with `WEBVIEW_PREF_KEYS` in `src-tauri/src/commands/backup.rs`,
 * which refuses anything else on export and drops it on restore.
 */
export const BACKED_UP_STORAGE_KEYS = [
  // Paraglide's `localStorageKey`.
  'PARAGLIDE_LOCALE',
  'ember-theme',
  'ember.channels.notify.v1',
  'ember.channels.favourites.v1',
  'ember.channels.hidden.v1',
  'ember.channels.ignored.v1',
  'ember.channels.carried.v1',
  'search-recent-queries-v1',
  'search-prefs-v1',
  'transfers-advanced-cols',
  'transfers-column-hidden-DownloadListCtrl',
  'transfers-column-hidden-UploadListCtrlV3',
  'transfers-column-hidden-QueueListCtrlV2',
  'transfers-column-hidden-KnownClientsCtrlV2',
  'transfers-column-hidden-DownloadClientsCtrl',
  'transfers-column-order-DownloadListCtrl',
  'transfers-column-order-UploadListCtrl',
  'transfers-column-order-QueueListCtrlV3',
  'transfers-column-order-KnownClientsCtrlV2',
  'transfers-column-order-DownloadClientsCtrl',
  'library-col-hidden',
  'library-col-order',
  'kad-search-col-hidden',
] as const;

export const SEARCH_HISTORY_STORAGE_KEY = 'search-recent-queries-v1';

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/**
 * The backed-up keys that are set, for a new backup. Search history goes in
 * only when saving it is known to be on: `undefined` (settings not loaded yet)
 * leaves it out, as turning saving off is a privacy choice.
 *
 * Null without storage rather than an empty snapshot: a restore reads a key
 * missing from the snapshot as unset and clears it, so an empty one would wipe
 * the restoring machine's preferences instead of leaving them alone.
 */
export function collectBackupPrefs(
  storage: StorageLike | null,
  options: { searchHistory: boolean | undefined },
): Record<string, string> | null {
  if (!storage) return null;
  const prefs: Record<string, string> = {};
  for (const key of BACKED_UP_STORAGE_KEYS) {
    if (key === SEARCH_HISTORY_STORAGE_KEY && options.searchHistory !== true) continue;
    try {
      const value = storage.getItem(key);
      if (value !== null) prefs[key] = value;
    } catch {
      // Storage disabled: the backup simply carries less.
    }
  }
  return prefs;
}

/**
 * Write a restored backup's preferences. The snapshot is the whole state of
 * the backed-up keys when the backup was made, so a key it does not carry is
 * cleared rather than left as this machine had it. Nothing outside
 * {@link BACKED_UP_STORAGE_KEYS} is ever written, whatever the snapshot holds.
 *
 * Returns whether anything changed, which is when the window has to reload:
 * the stores read these keys once, as they load.
 */
export function applyRestoredPrefs(snapshot: unknown, storage: StorageLike): boolean {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return false;
  const values = snapshot as Record<string, unknown>;
  let changed = false;
  for (const key of BACKED_UP_STORAGE_KEYS) {
    const value = Object.prototype.hasOwnProperty.call(values, key) ? values[key] : undefined;
    try {
      if (typeof value === 'string') {
        if (storage.getItem(key) === value) continue;
        storage.setItem(key, value);
        changed = true;
      } else if (storage.getItem(key) !== null) {
        storage.removeItem(key);
        changed = true;
      }
    } catch {
      // Quota or disabled storage: that preference keeps this machine's value.
    }
  }
  return changed;
}
