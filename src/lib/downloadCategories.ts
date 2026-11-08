import * as m from '$lib/paraglide/messages';

/** The categories every download can take besides the user's own; `None` is
 *  the absence of one. Stored by these values, shown translated. */
export const BUILTIN_DOWNLOAD_CATEGORIES = ['Audio', 'Video', 'Image', 'Archive', 'Document', 'Program'] as const;

/** The Transfers filter for downloads with no category. Not a category value:
 *  the backend drops control characters from the user's category names, so
 *  none can be this. */
export const UNCATEGORIZED_FILTER = '\u0000uncategorized';

/** Whether a download has no category. `None` is how the Category menu names
 *  the absence of one, and a row saved with it as its value has none either. */
export function isUncategorized(category: string | null | undefined): boolean {
  return !category || category === 'None';
}

/** Whether a download with `category` is in the Transfers filter `filter`, a
 *  category value or [`UNCATEGORIZED_FILTER`]. */
export function inCategoryFilter(category: string | null | undefined, filter: string): boolean {
  return filter === UNCATEGORIZED_FILTER ? isUncategorized(category) : category === filter;
}

/** A category's name as shown: built-in values are translated, the user's own
 *  are shown as they typed them. */
export function downloadCategoryLabel(category: string): string {
  switch (category) {
    case 'None': return m.transfers_cat_none();
    case 'Audio': return m.transfers_cat_audio();
    case 'Video': return m.transfers_cat_video();
    case 'Image': return m.transfers_cat_image();
    case 'Archive': return m.transfers_cat_archive();
    case 'Document': return m.transfers_cat_document();
    case 'Program': return m.transfers_cat_program();
    default: return category;
  }
}
