import * as m from '$lib/paraglide/messages';

/**
 * The file-type categories a user can filter by: the Library's type filter and
 * the category bar in Browse Friend both read from here, so a file lands in the
 * same bucket in either place.
 *
 * Option values are stable English keys, never translated: the Library
 * persists the selected value, and a translated key would stop matching as
 * soon as the locale changed. Use {@link fileTypeFilterLabel} for display.
 */
export const FILE_TYPE_FILTERS = ['All', 'Audio', 'Video', 'Image', 'Archive', 'Document', 'Program', 'CD/DVD', 'Collection'] as const;
export type FileTypeFilter = (typeof FILE_TYPE_FILTERS)[number];
export type FileTypeKey = Exclude<FileTypeFilter, 'All'>;

const AUDIO_EXTS: ReadonlySet<string> = new Set([
  'aac','ac3','aif','aifc','aiff','amr','ape','au','aud','audio','cda',
  'dmf','dsm','dts','far','flac','it','m1a','m2a','m4a','mdl','med',
  'mid','midi','mka','mod','mp1','mp2','mp3','mpa','mpc','mtm','ogg',
  'opus','psm','ptm','ra','rmi','s3m','snd','stm','umx','wav','wma','xm',
]);
const VIDEO_EXTS: ReadonlySet<string> = new Set([
  '3g2','3gp','3gp2','3gpp','amv','asf','avi','bik','divx','dvr-ms',
  'flc','fli','flic','flv','hdmov','ifo','m1v','m2t','m2ts','m2v',
  'm4b','m4v','mkv','mov','movie','mp1v','mp2v','mp4','mpe','mpeg',
  'mpg','mpv','mpv1','mpv2','ogm','pva','qt','ram','ratdvd','rm',
  'rmm','rmvb','rv','smil','smk','swf','tp','ts','vid','video','vob',
  'vp6','webm','wm','wmv','xvid',
]);
const IMAGE_EXTS: ReadonlySet<string> = new Set([
  'bmp','emf','gif','ico','jfif','jpe','jpeg','jpg','pct','pcx','pic',
  'pict','png','psd','psp','svg','tga','tif','tiff','webp','wmf','wmp','xif',
]);
const ARCHIVE_EXTS: ReadonlySet<string> = new Set([
  '7z','ace','alz','arc','arj','bz2','cab','cbr','cbz','gz','hqx',
  'lha','lzh','msi','pak','par','par2','rar','sit','sitx','tar',
  'tbz2','tgz','xpi','xz','z','zip',
]);
const DOCUMENT_EXTS: ReadonlySet<string> = new Set([
  'chm','css','diz','doc','docx','dot','djvu','epub','hlp','htm',
  'html','lit','mobi','azw','nfo','ods','odt','odp','pdf','pps',
  'ppt','pptx','ps','rtf','text','txt','wri','xls','xlsx','xml',
]);
/** Same set as `search::index::infer_file_type`'s Program arm (eMule
 *  ED2KFT_PROGRAM, plus apk/deb/rpm/scr/app). */
const PROGRAM_EXTS: ReadonlySet<string> = new Set([
  'apk','app','bat','cmd','com','deb','exe','hta','js','jse','msc',
  'rpm','scr','vbe','vbs','wsf','wsh',
]);
const CD_DVD_EXTS: ReadonlySet<string> = new Set([
  'bin','bwa','bwi','bws','bwt','ccd','cue','dmg','img','iso',
  'mdf','mds','nrg','sub','toast',
]);
/** Same extension as `search::index::infer_file_type`'s Collection arm. A
 *  `.txt` link list stays a Document. */
const COLLECTION_EXTS: ReadonlySet<string> = new Set(['emulecollection']);

/** Extension of the last path segment, without the dot; `''` for none, a
 *  dotfile (`.nfo`) or a trailing dot. Accepts `/` and `\` separators. */
export function extensionFromPath(path: string): string {
  const base = path.replace(/^.*[/\\]/, '');
  const dot = base.lastIndexOf('.');
  if (dot <= 0 || dot === base.length - 1) return '';
  return base.slice(dot + 1);
}

/** Category for an extension (no dot, any case); `''` when it fits none, which
 *  only the `All` filter matches. */
export function fileTypeKey(ext: string): FileTypeKey | '' {
  const lower = ext.toLowerCase();
  if (AUDIO_EXTS.has(lower)) return 'Audio';
  if (VIDEO_EXTS.has(lower)) return 'Video';
  if (IMAGE_EXTS.has(lower)) return 'Image';
  if (ARCHIVE_EXTS.has(lower)) return 'Archive';
  if (DOCUMENT_EXTS.has(lower)) return 'Document';
  if (PROGRAM_EXTS.has(lower)) return 'Program';
  if (CD_DVD_EXTS.has(lower)) return 'CD/DVD';
  if (COLLECTION_EXTS.has(lower)) return 'Collection';
  return '';
}

export function fileTypeFilterLabel(filter: FileTypeFilter): string {
  switch (filter) {
    case 'All': return m.library_all_types();
    case 'Audio': return m.library_type_audio();
    case 'Video': return m.library_type_video();
    case 'Image': return m.library_type_image();
    case 'Archive': return m.library_type_archive();
    case 'Document': return m.library_type_document();
    case 'Program': return m.library_type_program();
    case 'CD/DVD': return m.library_type_cd_dvd();
    case 'Collection': return m.library_type_collection();
  }
}
