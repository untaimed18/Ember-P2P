import * as m from '$lib/paraglide/messages';

/** The categories every download can take besides the user's own; `None` is
 *  the absence of one. Stored by these values, shown translated. */
export const BUILTIN_DOWNLOAD_CATEGORIES = ['Audio', 'Video', 'Image', 'Archive', 'Document', 'Program'] as const;

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
