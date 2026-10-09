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

function sanitizeSegment(segment: string): string {
  const safe = segment.replace(UNSAFE_CHAR, '_');
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
