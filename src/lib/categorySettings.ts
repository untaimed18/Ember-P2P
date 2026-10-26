// The download categories and their folders, as the Categories dialog edits
// them. Shared by every page that opens the dialog, so a category made or
// removed from the Library is handled exactly as one from Transfers.
import { get } from 'svelte/store';
import * as m from '$lib/paraglide/messages';
import { getSettings, updateSettings } from '$lib/api/settings';
import { setTransfersCategory } from '$lib/api/transfers';
import { setAppSettings } from '$lib/stores/settings';
import { setLocalCategory, transfers } from '$lib/stores/transfers';
import { BUILTIN_DOWNLOAD_CATEGORIES, downloadCategoryLabel } from '$lib/downloadCategories';
import { normalizeCategoryFolder } from '$lib/categoryFolders';
import type { Transfer } from '$lib/types';

/** Edits the categories and their folders as the backend holds them now,
 *  not as the calling page last saw them. */
async function saveCategorySettings(
  edit: (categories: string[], folders: Record<string, string>) => {
    categories: string[];
    folders: Record<string, string>;
  },
): Promise<{ before: string[]; saved: string[] }> {
  const current = await getSettings();
  const before = current.download_categories ?? [];
  const next = edit(before, current.download_category_folders ?? {});
  const result = await updateSettings({
    ...current,
    download_categories: next.categories,
    download_category_folders: next.folders,
  });
  setAppSettings(result.settings);
  return { before, saved: result.settings.download_categories ?? [] };
}

function saveUserCategories(edit: (current: string[]) => string[]) {
  return saveCategorySettings((categories, folders) => ({ categories: edit(categories), folders }));
}

/** Where a category's downloads finish; `null` is Downloads itself. */
export async function setCategoryFolder(category: string, folder: string | null): Promise<void> {
  await saveCategorySettings((categories, folders) => {
    const next = { ...folders };
    if (folder) next[category] = folder;
    else delete next[category];
    return { categories, folders: next };
  });
}

/** Make a user category, with a folder named after it when `ownFolder`.
 *
 *  Returns the name as the backend kept it, which may be trimmed or cut. A
 *  folder that could not be saved is handed back rather than thrown, so the
 *  caller can finish with the category before reporting it. */
export async function addUserCategory(
  name: string,
  ownFolder: boolean,
): Promise<{ kept: string; folderError: unknown }> {
  const { before, saved } = await saveUserCategories((current) => [...current, name]);
  // None when the backend cleaned the name into one that already exists.
  const kept = saved.find((cat) => !before.includes(cat));
  if (!kept) throw new Error(m.transfers_categories_exists());
  let folderError: unknown = null;
  const folder = ownFolder ? normalizeCategoryFolder(kept) : null;
  if (folder) {
    try {
      await setCategoryFolder(kept, folder);
    } catch (e: unknown) {
      folderError = e;
    }
  }
  return { kept, folderError };
}

/** Delete a user category. Its downloads lose it first, and their files stay
 *  where they are: taking away a category is not a request to move anything. */
export async function removeUserCategory(name: string): Promise<void> {
  const ids = get(transfers)
    .filter((t) => t.direction === 'download' && t.category === name)
    .map((t) => t.id);
  if (ids.length > 0) {
    const changes = await setTransfersCategory(ids, '', false);
    // The backend sends no event for this; show what it accepted right away.
    if (changes.changed.length > 0) setLocalCategory(new Set(changes.changed), '');
    if (changes.error) throw changes.error;
  }
  await saveUserCategories((current) => current.filter((cat) => cat !== name));
}

/** Whether `name` is already a category, built-in or the user's, by value or
 *  by the name shown for it. */
export function isCategoryTaken(name: string, userCategories: readonly string[]): boolean {
  const folded = name.toLocaleLowerCase();
  return ['None', ...BUILTIN_DOWNLOAD_CATEGORIES].some(
    (cat) => cat.toLocaleLowerCase() === folded || downloadCategoryLabel(cat).toLocaleLowerCase() === folded,
  ) || userCategories.some((cat) => cat.toLocaleLowerCase() === folded);
}

/** Downloads in each category, by category value. */
export function countDownloadCategories(list: readonly Transfer[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const t of list) {
    if (t.direction === 'download' && t.category) counts[t.category] = (counts[t.category] ?? 0) + 1;
  }
  return counts;
}
