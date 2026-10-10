/**
 * A download category's folder inside Downloads, cleaned exactly as the
 * backend cleans it (`storage::category_folders::normalize_folder`), so the
 * Categories dialog can show the folder a download will really land in
 * before anything is saved.
 */

/** Most folder levels below Downloads. */
export const CATEGORY_FOLDER_MAX_DEPTH = 3;
/** Longest folder name at each level, in characters. */
export const CATEGORY_FOLDER_MAX_CHARS = 64;

// What `sanitize_filename` turns into `_`: characters Windows refuses in a
// name, control characters, and the invisible and bidi formatters
// `is_invisible_or_bidi_control` lists.
const UNSAFE_CHAR =
  /[\\/:*?"<>|\p{Cc}\u061C\u180E\u200B-\u200F\u202A-\u202E\u2028\u2029\u2060-\u2064\u2066-\u2069\uFEFF\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;

const RESERVED_DEVICE = /^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$/;

/** Windows' DOS device test, as `is_reserved_windows_device_name` applies it. */
function isReservedDeviceName(name: string): boolean {
  const stem = name.split('.')[0]
    .replace(/\u00B9/g, '1')
    .replace(/\u00B2/g, '2')
    .replace(/\u00B3/g, '3')
    .toUpperCase()
    .replace(/[. ]+$/, '');
  return RESERVED_DEVICE.test(stem);
}

/** `sanitize_filename`'s cap, in UTF-8 bytes: the limit Linux puts on one name. */
const MAX_NAME_BYTES = 255;
const utf8 = new TextEncoder();

function sanitizeSegment(segment: string): string {
  let safe = segment.replace(UNSAFE_CHAR, '_');
  if (utf8.encode(safe).length > MAX_NAME_BYTES) {
    const chars = Array.from(safe);
    while (utf8.encode(chars.join('')).length > MAX_NAME_BYTES) chars.pop();
    safe = chars.join('').replace(/[. ]+$/, '');
  }
  return isReservedDeviceName(safe) ? `_${safe}` : safe;
}

/** The folder's names, outermost first; none means Downloads itself. */
export function categoryFolderSegments(value: string): string[] {
  const out: string[] = [];
  for (const raw of value.split(/[\\/]/)) {
    if (out.length === CATEGORY_FOLDER_MAX_DEPTH) break;
    const segment = raw.trim();
    if (!segment || segment === '.' || segment === '..') continue;
    const cut = Array.from(segment).slice(0, CATEGORY_FOLDER_MAX_CHARS).join('');
    const trimmed = cut.replace(/[. ]+$/, '');
    if (trimmed) out.push(sanitizeSegment(trimmed));
  }
  return out;
}

/** The folder as it will be saved, `/`-separated, or `null` for Downloads itself. */
export function normalizeCategoryFolder(value: string): string | null {
  const segments = categoryFolderSegments(value);
  return segments.length > 0 ? segments.join('/') : null;
}

/** `path`'s folders, outermost first, without Windows' extended-length prefix
 *  (`\\?\C:\…`), which a finished download is recorded with. */
function pathSegments(path: string): string[] {
  return path
    .replace(/^[\\/]{2}\?[\\/]UNC[\\/]/i, '\\\\')
    .replace(/^[\\/]{2}\?[\\/]/, '')
    .split(/[\\/]/)
    .filter(Boolean);
}

function sameSegments(a: string[], b: string[], caseInsensitive: boolean): boolean {
  if (a.length !== b.length) return false;
  return a.every((segment, i) =>
    caseInsensitive ? segment.toLowerCase() === b[i].toLowerCase() : segment === b[i],
  );
}

/**
 * The folders below `<downloadFolder>/Downloads` that the file at `filePath`
 * is in, outermost first — `[]` directly in Downloads — or `null` when it is
 * not inside that Downloads at all, or deeper than a category folder can be,
 * which are the files a category cannot move.
 */
export function downloadsSubdirOf(
  filePath: string,
  downloadFolder: string,
  caseInsensitive: boolean,
): string[] | null {
  if (!downloadFolder) return null;
  const downloads = [...pathSegments(downloadFolder), 'Downloads'];
  const dirs = pathSegments(filePath);
  dirs.pop();
  if (dirs.length < downloads.length) return null;
  if (!sameSegments(dirs.slice(0, downloads.length), downloads, caseInsensitive)) return null;
  const below = dirs.slice(downloads.length);
  return below.length <= CATEGORY_FOLDER_MAX_DEPTH ? below : null;
}

/** The folders below Downloads that `category` files its downloads in: `[]`
 *  for one with no folder, which is Downloads itself. */
export function categorySubdir(category: string, folders: Record<string, string>): string[] {
  const folder = folders[category];
  return folder ? categoryFolderSegments(folder) : [];
}

/** The categories whose folder is `subdir`. None for `[]`: Downloads itself is
 *  where every category without a folder goes, so it is no one's folder. */
export function categoriesWithFolder(
  subdir: string[],
  folders: Record<string, string>,
  caseInsensitive: boolean,
): string[] {
  if (subdir.length === 0) return [];
  return Object.keys(folders).filter((category) =>
    sameSegments(categorySubdir(category, folders), subdir, caseInsensitive),
  );
}

/** Whether `a` and `b` name the same place below Downloads. */
export function sameCategorySubdir(a: string[], b: string[], caseInsensitive: boolean): boolean {
  return sameSegments(a, b, caseInsensitive);
}

/** Where a category files its downloads, as shown: `Downloads/<folder>`. */
export function categoryDestinationLabel(subdir: string[]): string {
  return ['Downloads', ...subdir].join('/');
}
