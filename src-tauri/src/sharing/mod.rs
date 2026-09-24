pub mod disk;
pub mod indexer;
pub mod manager;
pub mod watcher;

/// Directory basenames that must not be shared as roots and must be skipped
/// during recursive indexing under an allowed parent. Without the indexer
/// skip, sharing e.g. a home folder would still walk into `.ssh` / `.gnupg`
/// / `AppData` and expose secrets. Matched case-insensitively.
///
/// The dot-directories below are the standard per-user credential stores of
/// widely installed tooling (`~/.aws/credentials`, `~/.kube/config`,
/// `~/.docker/config.json`, browser profiles with saved logins). Sharing a home
/// folder is allowed, so without these entries those files are hashed and
/// published to eD2K, KAD and the Ember DHT as ordinary fetchable content.
pub const SENSITIVE_DIR_NAMES: &[&str] = &[
    "windows",
    "program files",
    "program files (x86)",
    "programdata",
    "appdata",
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".docker",
    ".config",
    ".password-store",
    ".mozilla",
    ".thunderbird",
    "etc",
    "usr",
    "bin",
    "sbin",
    "var",
    "root",
    "tmp",
    "temp",
    "proc",
    "sys",
    "dev",
    // Volume housekeeping Windows keeps at the top of every drive. Only
    // reachable by walking a shared drive root, which is now allowed.
    "$recycle.bin",
    "recycler",
    "system volume information",
    "$windows.~bt",
    "$windows.~ws",
    "$sysreset",
];

/// True when `name` is a sensitive directory basename (ASCII case-insensitive).
pub fn is_sensitive_dir_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_DIR_NAMES.contains(&lower.as_str())
}

/// What sharing `path` would mean if it is a whole volume (`T:\`, `\\nas\share\`, `/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveRootShare {
    /// Not a volume root, so the ordinary folder checks decide.
    NotARoot,
    /// A dedicated data volume. Sharable whole once the user confirms, which is
    /// how eMule users with a drive per archive have always shared.
    NeedsConfirmation,
    /// The volume the OS or the user's profile lives on: sharing it would offer
    /// the system and every personal file on it.
    Refused,
}

pub fn is_volume_root(path: &std::path::Path) -> bool {
    path.parent().is_none()
        || !path
            .components()
            .any(|c| matches!(c, std::path::Component::Normal(_)))
}

/// Classify a canonical path as a shareable volume root or not.
pub fn drive_root_share(path: &std::path::Path) -> DriveRootShare {
    drive_root_share_against(path, &protected_volumes())
}

fn drive_root_share_against(
    path: &std::path::Path,
    protected: &[std::path::PathBuf],
) -> DriveRootShare {
    use std::path::{Component, Prefix};
    let prefix = match path.components().next() {
        Some(Component::Prefix(prefix)) => Some(prefix.kind()),
        _ => None,
    };
    // `\\?\GLOBALROOT\…`, `\\?\Volume{…}\…` and `\\.\…` name a volume without
    // its drive letter, so nothing below could tell which one it is.
    if matches!(prefix, Some(Prefix::Verbatim(_) | Prefix::DeviceNS(_))) {
        return DriveRootShare::Refused;
    }
    if !is_volume_root(path) {
        return DriveRootShare::NotARoot;
    }
    let Some(volume) = volume_key(path) else {
        // `/`, or a root with no drive or share to name it.
        return DriveRootShare::Refused;
    };
    // A local drive under another name: `\\localhost\…`, or a drive's
    // administrative share such as `\\server\c$`.
    if let Some(Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share)) = prefix {
        let share = share.to_string_lossy().to_ascii_lowercase();
        let drive_admin_share = share == "admin$"
            || (share.len() == 2 && share.ends_with('$') && share.as_bytes()[0].is_ascii_alphabetic());
        if drive_admin_share || is_this_machine(&server.to_string_lossy()) {
            return DriveRootShare::Refused;
        }
    }
    if protected
        .iter()
        .any(|p| volume_key(p).as_deref() == Some(volume.as_str()))
    {
        DriveRootShare::Refused
    } else {
        DriveRootShare::NeedsConfirmation
    }
}

fn is_this_machine(server: &str) -> bool {
    let server = server.to_ascii_lowercase();
    matches!(server.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]")
        || std::env::var("COMPUTERNAME").is_ok_and(|name| name.eq_ignore_ascii_case(&server))
}

/// Volumes whose root is never shared: the system drive, and the drives holding
/// Windows, programs, the user profile and Ember's own data.
fn protected_volumes() -> Vec<std::path::PathBuf> {
    let mut volumes: Vec<std::path::PathBuf> = [
        "SystemDrive",
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "USERPROFILE",
        "HOME",
    ]
    .iter()
    .filter_map(std::env::var_os)
    .filter(|value| !value.is_empty())
    .map(std::path::PathBuf::from)
    .collect();
    volumes.push(crate::storage::paths::resolve_data_dir());
    volumes
}

/// `c:` for a drive letter, `\\server\share` for a UNC share, lowercased so
/// two spellings of one volume compare equal. `None` without a prefix, which
/// on Unix is every path.
pub(crate) fn volume_key(path: &std::path::Path) -> Option<String> {
    use std::path::{Component, Prefix};
    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return None;
    };
    match prefix.kind() {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
            Some(format!("{}:", (letter as char).to_ascii_lowercase()))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => Some(
            format!(
                r"\\{}\{}",
                server.to_string_lossy(),
                share.to_string_lossy()
            )
            .to_lowercase(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn a_folder_is_not_a_volume_root() {
        let path = if cfg!(windows) { r"D:\Archive" } else { "/mnt/archive" };
        assert_eq!(drive_root_share(Path::new(path)), DriveRootShare::NotARoot);
    }

    #[cfg(windows)]
    #[test]
    fn a_data_drive_needs_confirmation_and_the_system_drive_is_refused() {
        let protected = [PathBuf::from("C:"), PathBuf::from(r"C:\Users\someone")];
        assert_eq!(
            drive_root_share_against(Path::new(r"\\?\T:\"), &protected),
            DriveRootShare::NeedsConfirmation
        );
        assert_eq!(
            drive_root_share_against(Path::new(r"c:\"), &protected),
            DriveRootShare::Refused
        );
        let with_profile_on_t = [PathBuf::from(r"T:\Users\someone")];
        assert_eq!(
            drive_root_share_against(Path::new(r"T:\"), &with_profile_on_t),
            DriveRootShare::Refused
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_local_drive_by_another_name_is_refused() {
        for path in [
            r"\\localhost\d$\",
            r"\\?\UNC\127.0.0.1\Media\",
            r"\\nas\c$\",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Films",
            r"\\.\D:\",
        ] {
            assert_eq!(drive_root_share_against(Path::new(path), &[]), DriveRootShare::Refused, "{path}");
        }
        assert_eq!(
            drive_root_share_against(Path::new(r"\\nas\media$\"), &[]),
            DriveRootShare::NeedsConfirmation,
            "a named hidden share on another machine is an ordinary share"
        );
        assert_eq!(
            drive_root_share_against(Path::new(r"\\localhost\d$\Films"), &[]),
            DriveRootShare::NotARoot
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_unix_root_is_always_refused() {
        assert_eq!(
            drive_root_share_against(Path::new("/"), &[]),
            DriveRootShare::Refused
        );
    }
}
