//! Name the filesystem a path lives on by what is written on it.
//!
//! `st_dev` is not such a name on Linux. A USB drive's device number follows
//! the order the kernel found the drives in (`sdb1` one boot, `sdc1` the next)
//! and FUSE hands out a fresh one on every mount, so a folder identified by
//! `st_dev` looked like a different folder after every replug. The UUID or
//! serial on the filesystem itself is what survives that.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeId {
    /// The filesystem's UUID or serial, and the subtree of it the mount
    /// exposes (a btrfs subvolume, a bind-mounted directory).
    pub id: String,
    /// Inode numbers are stored on disk and survive a remount. False where the
    /// driver makes them up as it loads each inode: FAT, exFAT, and anything
    /// behind FUSE, whose driver we cannot see.
    pub persistent_inodes: bool,
}

/// The volume `path` is on, or `None` where that cannot be told: every
/// platform but Linux, and Linux without `/dev/disk/by-uuid` (containers,
/// systems without udev) or with a mount that is not backed by a device.
#[cfg(target_os = "linux")]
pub fn volume_of(path: &Path) -> Option<VolumeId> {
    let table = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mount = mountinfo::mount_containing(&table, path)?;
    let uuid = uuid_of_device(Path::new(&mount.source))?;
    Some(VolumeId {
        id: format!("{uuid}:{}", mount.root),
        persistent_inodes: mountinfo::has_persistent_inodes(&mount.fs_type),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn volume_of(_path: &Path) -> Option<VolumeId> {
    None
}

#[cfg(target_os = "linux")]
fn uuid_of_device(source: &Path) -> Option<String> {
    if !source.starts_with("/dev") {
        return None;
    }
    let device = source.canonicalize().ok()?;
    std::fs::read_dir("/dev/disk/by-uuid")
        .ok()?
        .flatten()
        .find(|entry| {
            entry
                .path()
                .canonicalize()
                .is_ok_and(|target| target == device)
        })
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
}

#[cfg(any(target_os = "linux", test))]
mod mountinfo {
    use std::path::Path;

    /// Filesystems whose inode numbers are stored on disk.
    const PERSISTENT_INODE_FILESYSTEMS: &[&str] = &[
        "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "jfs", "reiserfs", "zfs", "bcachefs",
        "nilfs2", "ntfs3", "ntfs", "hfsplus",
    ];

    pub(super) fn has_persistent_inodes(fs_type: &str) -> bool {
        PERSISTENT_INODE_FILESYSTEMS.contains(&fs_type)
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Mount {
        pub(super) root: String,
        pub(super) mount_point: String,
        pub(super) fs_type: String,
        pub(super) source: String,
    }

    /// The mount `path` is under: the deepest mount point containing it, and
    /// of several at the same point the last listed, which hides the others.
    pub(super) fn mount_containing(table: &str, path: &Path) -> Option<Mount> {
        let depth = |mount: &Mount| Path::new(&mount.mount_point).components().count();
        let mut best: Option<Mount> = None;
        for mount in table.lines().filter_map(parse_line) {
            if !path.starts_with(&mount.mount_point) {
                continue;
            }
            if best.as_ref().is_some_and(|best| depth(best) > depth(&mount)) {
                continue;
            }
            best = Some(mount);
        }
        best
    }

    /// One line of `/proc/self/mountinfo`:
    /// `id parent major:minor root mount-point options [optional...] - type source super-options`.
    fn parse_line(line: &str) -> Option<Mount> {
        let (mount_fields, fs_fields) = line.split_once(" - ")?;
        let mut mount_fields = mount_fields.split(' ');
        let root = unescape(mount_fields.nth(3)?);
        let mount_point = unescape(mount_fields.next()?);
        let mut fs_fields = fs_fields.split(' ');
        let fs_type = fs_fields.next()?.to_string();
        let source = unescape(fs_fields.next()?);
        Some(Mount {
            root,
            mount_point,
            fs_type,
            source,
        })
    }

    /// The kernel writes space, tab, newline and backslash as `\ooo`.
    fn unescape(field: &str) -> String {
        let bytes = field.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let octal = bytes
                .get(i + 1..i + 4)
                .filter(|digits| digits.iter().all(|d| (b'0'..=b'7').contains(d)))
                .and_then(|digits| u8::from_str_radix(std::str::from_utf8(digits).ok()?, 8).ok());
            match octal {
                Some(byte) if bytes[i] == b'\\' => {
                    out.push(byte);
                    i += 4;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const TABLE: &str = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
61 22 0:52 / /media/u/WD rw,nosuid shared:30 - vfat /dev/sdd1 rw
62 22 0:53 / /media/u/WD\\0404\\040TB rw,nosuid,nodev shared:31 - fuseblk /dev/sdb1 rw,user_id=0
63 22 8:33 / /media/u/VOLUME_8TB rw,nosuid,nodev shared:32 - ext4 /dev/sdc1 rw
64 63 8:49 / /media/u/VOLUME_8TB rw,nosuid,nodev shared:33 - exfat /dev/sde1 rw
65 22 0:40 /@home /home rw,relatime shared:34 - btrfs /dev/mapper/luks-1 rw
";

        #[test]
        fn a_mount_point_with_spaces_is_found_by_its_real_name() {
            let mount =
                mount_containing(TABLE, Path::new("/media/u/WD 4 TB/CONDIVISI")).expect("mount");
            assert_eq!(mount.mount_point, "/media/u/WD 4 TB");
            assert_eq!(mount.fs_type, "fuseblk");
            assert_eq!(mount.source, "/dev/sdb1");
        }

        #[test]
        fn a_sibling_whose_name_is_a_prefix_does_not_match() {
            let mount = mount_containing(TABLE, Path::new("/media/u/WDX/share")).expect("mount");
            assert_eq!(mount.mount_point, "/", "`/media/u/WD` is not a parent of `/media/u/WDX`");
        }

        #[test]
        fn the_last_mount_at_a_point_is_the_one_in_effect() {
            let mount =
                mount_containing(TABLE, Path::new("/media/u/VOLUME_8TB/CONDIVISI")).expect("mount");
            assert_eq!(mount.source, "/dev/sde1");
            assert!(!has_persistent_inodes(&mount.fs_type));
        }

        #[test]
        fn the_subtree_a_mount_exposes_is_kept() {
            let mount = mount_containing(TABLE, Path::new("/home/u/Downloads")).expect("mount");
            assert_eq!(mount.root, "/@home");
            assert!(has_persistent_inodes(&mount.fs_type));
        }

        #[test]
        fn escapes_are_decoded_and_stray_backslashes_kept() {
            assert_eq!(unescape("a\\040b\\011c\\134d"), "a b\tc\\d");
            assert_eq!(unescape("trailing\\04"), "trailing\\04");
            assert_eq!(unescape("not\\999octal"), "not\\999octal");
        }
    }
}
