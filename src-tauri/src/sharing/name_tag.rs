//! The `[Ember-P2P]` tag at the start of a file's name: added or removed in
//! bulk from the Library, and, when the user asks for it, put on every
//! download as it completes and on files new to a shared folder.

use std::sync::atomic::{AtomicBool, Ordering};

/// The tag itself. Followed by a space when added.
pub const EMBER_NAME_TAG: &str = "[Ember-P2P]";

/// Whether downloads are saved under a tagged name as they complete. Read by
/// the completion paths, which run without the settings in hand; kept
/// current by `apply_network_settings`, as the category folders are.
static TAG_COMPLETED_DOWNLOADS: AtomicBool = AtomicBool::new(false);

pub fn set_tag_completed_downloads(on: bool) {
    TAG_COMPLETED_DOWNLOADS.store(on, Ordering::Relaxed);
}

/// Whether `name` already starts with the tag, in any capitals.
pub fn has_tag(name: &str) -> bool {
    name.get(..EMBER_NAME_TAG.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(EMBER_NAME_TAG))
}

/// `name` with the tag added (`add`) or taken off, or `None` when there is
/// nothing to do: already tagged, or not tagged to begin with.
pub fn tagged_name(name: &str, add: bool) -> Option<String> {
    match (add, has_tag(name)) {
        (true, false) => Some(format!("{EMBER_NAME_TAG} {name}")),
        (false, true) => {
            let rest = name[EMBER_NAME_TAG.len()..].trim_start();
            (!rest.is_empty()).then(|| rest.to_string())
        }
        _ => None,
    }
}

/// Extensions never renamed on their own when a shared folder gains them:
/// code, libraries, shortcuts and configuration, which other programs find
/// by name. A folder an app runs from stops working when they move. The
/// Library's own Add [Ember-P2P] still renames them, since that is asked for
/// file by file.
const NEVER_AUTO_TAG_EXTENSIONS: &[&str] = &[
    "app", "asar", "bash", "bat", "cfg", "cmd", "com", "conf", "config", "cpl", "db", "desktop",
    "dll", "drv", "dylib", "exe", "inf", "ini", "jar", "js", "json", "lnk", "msi", "msp", "msu",
    "ocx", "pak", "plist", "ps1", "psm1", "py", "reg", "scr", "sh", "so", "sqlite", "sys", "toml",
    "url", "vbs", "wsf", "xml", "yaml", "yml",
];

/// Whether a file may be renamed without being asked for by name: not hidden,
/// and not one of [`NEVER_AUTO_TAG_EXTENSIONS`]. A file new to a shared
/// folder has to pass [`may_auto_tag_new_shared_file`] as well.
pub fn may_auto_tag(name: &str) -> bool {
    if name.starts_with('.') {
        return false;
    }
    let extension = std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default();
    !NEVER_AUTO_TAG_EXTENSIONS
        .iter()
        .any(|denied| denied.eq_ignore_ascii_case(extension))
}

/// The Library's file types whose files are renamed on their own when new to
/// a shared folder: media, archives, disc images and documents, which people
/// share as files. Programs and everything untyped are left alone.
const AUTO_TAG_FILE_TYPES: &[&str] = &["Audio", "Video", "Image", "Arc", "Iso", "Doc"];

/// Extensions of those types that programs, sites and release tools still
/// load by name (`requirements.txt`, `file_id.diz`, `index.html`, TypeScript's
/// `.ts`, a game's `.pak` and `.bin`, a cue sheet's tracks), so they are not
/// renamed on their own either.
const NEVER_AUTO_TAG_TYPED_EXTENSIONS: &[&str] = &[
    "bin", "cab", "chm", "css", "cue", "diz", "dot", "hlp", "htm", "html", "ico", "ifo", "msi",
    "nfo", "pak", "ram", "smil", "sub", "svg", "swf", "text", "ts", "txt", "xml", "xpi",
];

/// Whether a file new to a shared folder may be tagged without being asked
/// for by name: [`may_auto_tag`], its extension is one of
/// [`AUTO_TAG_FILE_TYPES`] and not [`NEVER_AUTO_TAG_TYPED_EXTENSIONS`], and it
/// is not one volume of a split archive. A file with no extension never is.
/// Where the file sits, and what sits beside it, is checked separately.
pub fn may_auto_tag_new_shared_file(name: &str) -> bool {
    if !may_auto_tag(name) || is_archive_volume(name) {
        return false;
    }
    let Some(extension) = std::path::Path::new(name).extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let file_type = crate::search::index::infer_file_type(extension);
    AUTO_TAG_FILE_TYPES.contains(&file_type.as_str())
        && !NEVER_AUTO_TAG_TYPED_EXTENSIONS
            .iter()
            .any(|denied| denied.eq_ignore_ascii_case(extension))
}

/// Whether `name` is one volume of an archive split into several, which the
/// archiver finds by name from the first: `x.r00`, `x.z01`, `x.7z.001`,
/// `x.part1.rar`.
fn is_archive_volume(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let path = std::path::Path::new(&lower);
    let Some(extension) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let numbered = match extension.as_bytes() {
        [letter, tens, units] if letter.is_ascii_alphabetic() => {
            tens.is_ascii_digit() && units.is_ascii_digit()
        }
        digits @ [_, _, _] => digits.iter().all(u8::is_ascii_digit),
        _ => false,
    };
    numbered
        || (extension == "rar"
            && path
                .file_stem()
                .and_then(|stem| std::path::Path::new(stem).extension())
                .and_then(|e| e.to_str())
                .and_then(|part| part.strip_prefix("part"))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())))
}

/// Folders of a disc copied whole, whose menus, playlists and certificates
/// find the files inside by name: a DVD's `VIDEO_TS` and `AUDIO_TS`, a
/// Blu-ray's `BDMV` and `CERTIFICATE`.
const DISC_STRUCTURE_FOLDERS: &[&str] = &["VIDEO_TS", "AUDIO_TS", "BDMV", "CERTIFICATE"];

/// Whether a folder named `name` is one of [`DISC_STRUCTURE_FOLDERS`], in any
/// capitals. Nothing under one is renamed on its own.
pub fn is_disc_structure_folder(name: &str) -> bool {
    DISC_STRUCTURE_FOLDERS
        .iter()
        .any(|folder| folder.eq_ignore_ascii_case(name))
}

/// Extensions of files that find another by its name with at most a short tag
/// added: subtitles (`Movie.en.srt` for `Movie.mkv`), cue sheets, and the
/// control files of disc images.
const COMPANION_EXTENSIONS: &[&str] = &[
    "ass", "bup", "ccd", "cue", "idx", "ifo", "mds", "smi", "srt", "ssa", "sub", "sup", "toc", "vtt",
];

/// The most dotted parts, and the longest part, of a tag between a file's
/// name and its companion's: `en`, `forced.en`, `cd1`, a language or a disc.
const COMPANION_TAG_PARTS: usize = 3;
const COMPANION_TAG_PART_LEN: usize = 8;

fn is_companion_type(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, extension)| COMPANION_EXTENSIONS.contains(&extension))
}

/// Whether `between` reads as a short tag such as a language: a few short
/// dotted parts, none empty.
fn is_short_tag(between: &str) -> bool {
    between.split('.').count() <= COMPANION_TAG_PARTS
        && between
            .split('.')
            .all(|part| !part.is_empty() && part.len() <= COMPANION_TAG_PART_LEN)
}

/// The file names in one folder, for asking whether a file there has
/// companions: files that find it by name, or that it finds by name, such as
/// a film's subtitles, an album's cue sheet, the other volumes of an archive,
/// or a disc image's control file. A file with companions is not renamed on
/// its own, since renaming it breaks them. Only files: a subfolder finds
/// nothing by name.
pub struct FolderNames {
    /// Every name, lowercased, sorted.
    names: Vec<String>,
    /// Every name up to its last dot, lowercased, and whether a name with
    /// that stem is of [`COMPANION_EXTENSIONS`].
    stems: std::collections::HashMap<String, bool>,
}

impl FolderNames {
    pub fn new(names: impl IntoIterator<Item = String>) -> Self {
        let mut names: Vec<String> = names.into_iter().map(|name| name.to_lowercase()).collect();
        names.sort_unstable();
        names.dedup();
        let mut stems = std::collections::HashMap::new();
        for name in &names {
            if let Some(dot) = name.rfind('.') {
                *stems.entry(name[..dot].to_string()).or_insert(false) |= is_companion_type(name);
            }
        }
        Self { names, stems }
    }

    /// Whether `name` and another name here pair up, in any capitals: one is
    /// the other's name up to its last dot, then a dot, then either just
    /// another extension (`Movie.srt`, `Movie.jpg` beside `Movie.mkv`, `x.r00`
    /// beside `x.rar`, `Album.cue` beside `Album.flac`), or a short tag and an
    /// extension where one of the two is of [`COMPANION_EXTENSIONS`]
    /// (`Movie.en.srt` beside `Movie.mkv`).
    ///
    /// Names that only begin alike are not companions: `Show.S01E01.mkv` and
    /// `Show.S01E02.mkv` are two episodes, each renamed on its own, and so is
    /// `Show.Name.S01E01.mkv` beside `Show.Name.nfo` or `Show.Name.jpg`.
    pub fn has_companion(&self, name: &str) -> bool {
        let name = name.to_lowercase();
        let Some(last_dot) = name.rfind('.') else {
            return false;
        };
        let companion = is_companion_type(&name);
        let prefix = &name[..=last_dot];
        let start = self.names.partition_point(|other| other.as_str() < prefix);
        let finds_others = self.names[start..]
            .iter()
            .take_while(|other| other.starts_with(prefix))
            .filter(|other| **other != name)
            .any(|other| {
                let their_dot = other.rfind('.').unwrap_or(last_dot);
                their_dot == last_dot
                    || ((companion || is_companion_type(other)) && is_short_tag(&other[prefix.len()..their_dot]))
            });
        finds_others
            || name.match_indices('.').any(|(at, _)| {
                at > 0
                    && at < last_dot
                    && self.stems.get(&name[..at]).is_some_and(|their_companion| {
                        (companion || *their_companion) && is_short_tag(&name[at + 1..last_dot])
                    })
            })
    }
}

/// The name a completing download is saved under: tagged when the user asked
/// for that, unless the tag would take it past a file name's 255 bytes, in
/// which case it keeps the name it has rather than be cut short.
pub fn completed_download_name(name: &str) -> String {
    completed_download_name_when(name, TAG_COMPLETED_DOWNLOADS.load(Ordering::Relaxed))
}

fn completed_download_name_when(name: &str, tag: bool) -> String {
    match tagged_name(name, true) {
        Some(tagged) if tag && tagged.len() <= 255 => tagged,
        _ => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tag_goes_on_the_front_once_and_comes_off_cleanly() {
        assert_eq!(tagged_name("Linux.zip", true).as_deref(), Some("[Ember-P2P] Linux.zip"));
        assert_eq!(tagged_name("[Ember-P2P] Linux.zip", true), None, "never twice");
        assert_eq!(tagged_name("[ember-p2p]Linux.zip", true), None, "any capitals");

        assert_eq!(tagged_name("[Ember-P2P] Linux.zip", false).as_deref(), Some("Linux.zip"));
        assert_eq!(tagged_name("[EMBER-P2P]Linux.zip", false).as_deref(), Some("Linux.zip"));
        assert_eq!(tagged_name("Linux.zip", false), None, "nothing to take off");
        assert_eq!(tagged_name("[Ember-P2P]", false), None, "no name would be left");
        assert_eq!(tagged_name("Ünïcode.zip", false), None, "a short multibyte head is not a tag");
    }

    #[test]
    fn program_and_hidden_files_are_never_tagged_on_their_own() {
        assert!(may_auto_tag("Linux.zip"));
        assert!(may_auto_tag("Holiday.MKV"));
        assert!(!may_auto_tag("game.exe"));
        assert!(!may_auto_tag("engine.DLL"));
        assert!(!may_auto_tag("settings.ini"));
        assert!(!may_auto_tag("Start.lnk"));
        assert!(!may_auto_tag(".hidden.zip"));
    }

    #[test]
    fn only_media_archives_and_documents_new_to_a_share_are_tagged() {
        for shared in [
            "Holiday.MKV", "Song.flac", "Photo.jpg", "Linux.zip", "Backup.7z", "src.tar.gz",
            "Ubuntu.iso", "Book.epub", "Paper.pdf", "Comic.cbz", "Notes.docx",
        ] {
            assert!(may_auto_tag_new_shared_file(shared), "{shared}");
        }
        for left in [
            // A git object, and other names with no extension.
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            "Makefile",
            // Program files and build output nothing classifies.
            "module.pyc", "addon.node", "app.wasm", "bundle.js.map", "game.exe", "engine.dll",
            "resume.dat", "settings.ini",
            // Typed, but loaded by name.
            "requirements.txt", "file_id.diz", "index.html", "main.ts", "data.pak", "track.cue",
            "game.bin", "setup.msi",
            ".hidden.mkv",
        ] {
            assert!(!may_auto_tag_new_shared_file(left), "{left}");
        }
    }

    #[test]
    fn untyped_names_pass_the_first_check_and_only_the_first() {
        assert!(!may_auto_tag("setup.exe"));
        assert!(!may_auto_tag("run.bat"));
        assert!(may_auto_tag("Show.S01E01.mkv"));
        assert!(may_auto_tag("readme"));
        assert!(!may_auto_tag_new_shared_file("readme"), "a file new to a share needs a type");
    }

    #[test]
    fn split_archive_volumes_are_never_tagged_on_their_own() {
        for volume in [
            "x.part1.rar", "x.PART01.RAR", "x.r00", "x.R17", "x.s00", "x.z01", "x.7z.001", "x.zip.002",
        ] {
            assert!(!may_auto_tag_new_shared_file(volume), "{volume}");
        }
        for whole in ["x.rar", "x.zip", "x.7z", "Song.mp3", "Clip.3gp", "Party.rar"] {
            assert!(may_auto_tag_new_shared_file(whole), "{whole}");
        }
    }

    #[test]
    fn disc_structure_folders_are_known_in_any_capitals() {
        for folder in ["VIDEO_TS", "audio_ts", "BDMV", "Certificate"] {
            assert!(is_disc_structure_folder(folder), "{folder}");
        }
        assert!(!is_disc_structure_folder("Videos"));
        assert!(!is_disc_structure_folder("STREAM"), "only below BDMV, which is checked for itself");
    }

    #[test]
    fn files_with_companions_are_known_by_their_names() {
        let folder = FolderNames::new(
            [
                "Movie.mkv", "Movie.en.srt", "Album.FLAC", "album.cue", "x.rar", "x.r00", "y.zip",
                "y.z01", "Disc.img", "Disc.ccd", "Disc.sub", "Show.S01E01.mkv", "Show.S01E02.mkv",
                "Holiday.mkv", "Holiday Photos.jpg", "Notes",
            ]
            .map(String::from),
        );
        for paired in [
            "Movie.mkv", "Movie.en.srt", "Album.flac", "ALBUM.CUE", "x.rar", "x.r00", "y.zip", "Disc.img",
            "Disc.ccd",
        ] {
            assert!(folder.has_companion(paired), "{paired}");
        }
        for alone in ["Show.S01E01.mkv", "Show.S01E02.mkv", "Holiday.mkv", "Holiday Photos.jpg", "Notes"] {
            assert!(!folder.has_companion(alone), "{alone}");
        }
    }

    #[test]
    fn a_shows_own_extras_do_not_hold_back_its_episodes() {
        let folder = FolderNames::new(
            [
                "Show.Name.S01E01.mkv", "Show.Name.S01E02.mkv", "Show.Name.nfo", "Show.Name.jpg",
                "Show.S01E03.mkv", "Show.nfo", "Show.Name.S01E02.en.srt",
            ]
            .map(String::from),
        );
        for episode in ["Show.Name.S01E01.mkv", "Show.S01E03.mkv"] {
            assert!(!folder.has_companion(episode), "{episode}");
        }
        assert!(folder.has_companion("Show.Name.S01E02.mkv"), "its subtitles");
        assert!(folder.has_companion("Show.Name.S01E02.en.srt"));
    }

    #[test]
    fn a_companion_pairs_by_its_stem_or_a_short_tag_after_it() {
        for (file, beside) in [
            ("Movie.mkv", "Movie.en.srt"),
            ("Movie.mkv", "Movie.forced.en.srt"),
            ("Movie.mkv", "Movie.srt"),
            ("Album.flac", "Album.cue"),
            ("Album.flac", "Album.flac.cue"),
            ("x.rar", "x.r00"),
            ("Disc.img", "Disc.ccd"),
            ("Disc.mdf", "Disc.mds"),
        ] {
            let folder = FolderNames::new([file, beside].map(String::from));
            assert!(folder.has_companion(file), "{file} beside {beside}");
            assert!(folder.has_companion(beside), "{beside} beside {file}");
        }
        for (file, beside) in [
            ("Movie.mkv", "Movie.Directors.Cut.Extras.Feature.srt"),
            ("Movie.mkv", "Movie.Commentary.mkv"),
            ("Show.S01E01.mkv", "Show.S01"),
            ("Concert.flac", "Concert.Encore.flac"),
        ] {
            let folder = FolderNames::new([file, beside].map(String::from));
            assert!(!folder.has_companion(file), "{file} beside {beside}");
        }
    }

    #[test]
    fn completed_downloads_are_tagged_only_when_asked_and_never_cut_short() {
        assert_eq!(completed_download_name_when("Linux.zip", false), "Linux.zip");
        assert_eq!(completed_download_name_when("Linux.zip", true), "[Ember-P2P] Linux.zip");
        assert_eq!(
            completed_download_name_when("[Ember-P2P] Linux.zip", true),
            "[Ember-P2P] Linux.zip"
        );
        let long = format!("{}.zip", "a".repeat(250));
        assert_eq!(completed_download_name_when(&long, true), long, "past 255 bytes it keeps its name");
    }
}
