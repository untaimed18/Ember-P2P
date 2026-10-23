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

/// Whether a file new to a shared folder may be tagged without being asked
/// for by name: not hidden, and not one of [`NEVER_AUTO_TAG_EXTENSIONS`].
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
