//! Is the library on something that minds being asked for several files at
//! once?
//!
//! The hash pass reads every byte of every file it indexes. On a solid-state
//! disk one file at a time leaves the drive idle between CPU-bound stretches,
//! and running a few concurrently is close to free. On a spinning disk it is
//! the opposite: concurrent reads interleave into seeks, and the head spends
//! its time travelling rather than reading. The same change that makes an SSD
//! several times faster can make a 7200rpm drive slower than it was.
//!
//! So this answers the only question that matters — *is the seek cheap?* — and
//! the answer is deliberately three-valued. Unknown is treated exactly like
//! spinning: we widen only where we have been told it is safe, never where we
//! are guessing. That keeps the conservative behaviour for every platform and
//! every storage kind this cannot speak for: macOS, network shares, exotic
//! filesystems, containers.
//!
//! Two distinct questions, and conflating them has now caused a bug in each
//! direction:
//!
//! - *Which drive is this on?* — [`DeviceInfo::key`]. Asked so files on
//!   different drives can be read at the same time. The first version asked it
//!   once for the whole library and took the most cautious answer, so a library
//!   spread over four external drives ran one read at a time and left three
//!   spindles idle for a pass that takes days.
//! - *How fast can this drive answer?* — [`DeviceInfo::concurrency`]. Asked so
//!   one drive is not handed more work than it can take.
//!
//! The identity has to be the *physical* device, not the volume. Two drive
//! letters, or two Linux partitions, are routinely two slices of one spinning
//! disk — and treating those as separate drives would schedule exactly the
//! concurrent head travel this module exists to avoid. Where the physical
//! device cannot be determined, identity is `None` and the caller groups every
//! such path together, because paths we cannot tell apart must be assumed to
//! share a spindle.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Concurrent file hashes to run against one device known not to seek.
///
/// Four rather than "one per core": the pass is a mix of reading and hashing,
/// so the useful ceiling is set by the drive's queue depth long before the
/// CPU's core count, and every extra worker is another 1 MiB buffer and another
/// file held open. Bounded by `available_parallelism` below, so a dual-core
/// machine does not run four.
const SOLID_STATE_HASH_CONCURRENCY: usize = 4;

/// Ceiling on reads in flight across every device at once.
///
/// A library spread over a dozen drives should use them, but each worker holds
/// a 1 MiB buffer and an open file, and past this the gain is the drives'
/// rather than ours to give.
pub const MAX_TOTAL_HASH_CONCURRENCY: usize = 16;

/// A physical device the library lives on, and what it will tolerate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Identity of the underlying physical drive. Paths sharing this share a
    /// spindle and must share a read budget.
    pub key: String,
    /// Reads this device may serve at once. One unless it has positively
    /// reported that its reads do not seek.
    pub concurrency: usize,
}

/// Which physical device `path` lives on, and how hard it may be pushed.
///
/// `None` when that cannot be determined, which the caller must treat as "this
/// might be the same drive as any other unknown path, and it might seek".
/// Cached per volume: the queries are device round trips and their answers
/// cannot change for the life of the process.
pub fn describe_device(path: &Path) -> Option<DeviceInfo> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<DeviceInfo>>>> = OnceLock::new();
    let volume = volume_key(path)?;
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&volume)
        .cloned()
    {
        return cached;
    }
    let answer = query_device(&volume).map(|(key, seeks)| DeviceInfo {
        key,
        concurrency: concurrency_for(seeks),
    });
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(volume, answer.clone());
    answer
}

/// Reads in progress that the library scheduler did not start, per device.
///
/// A completing download verifies itself by reading the whole file, and that
/// read lands on a drive the library pass believes it has fully accounted for.
/// Recording it here lets the scheduler subtract it from that device's budget
/// rather than pile a read on top of it — on a mechanical drive, the difference
/// between one seek-free reader and two heads fighting.
///
/// Deliberately advisory and one-directional: nothing here blocks or delays the
/// transfer. A download the user is waiting on outranks a library scan, so the
/// scan yields to it and never the other way round.
static EXTERNAL_READS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn external_reads_map() -> &'static Mutex<HashMap<String, usize>> {
    EXTERNAL_READS.get_or_init(Default::default)
}

/// Record a read this module's scheduler does not own, until the guard drops.
#[must_use = "the read is only counted while the guard is alive"]
pub fn note_external_read(path: &Path) -> ExternalRead {
    let key = describe_device(path).map(|d| d.key);
    if let Some(key) = key.as_ref() {
        note_external_read_by_key(key);
    }
    ExternalRead { key }
}

/// Raise the count for an already-resolved device. Split out so a test can
/// stand in for a drive without owning one.
pub(crate) fn note_external_read_by_key(key: &str) {
    *external_reads_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(key.to_string())
        .or_insert(0) += 1;
}

pub(crate) fn release_external_read_by_key(key: &str) {
    let mut reads = external_reads_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if let Some(count) = reads.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            reads.remove(key);
        }
    }
}

/// How many reads someone else currently has running on this device.
pub fn external_reads(key: Option<&str>) -> usize {
    let Some(key) = key else {
        return 0;
    };
    external_reads_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(key)
        .copied()
        .unwrap_or(0)
}

/// Drop handle for [`note_external_read`].
pub struct ExternalRead {
    key: Option<String>,
}

impl Drop for ExternalRead {
    fn drop(&mut self) {
        if let Some(key) = self.key.as_ref() {
            release_external_read_by_key(key);
        }
    }
}

/// Reads to allow against a device whose seek behaviour is `seeks`.
///
/// `None` — could not find out — is treated exactly as `Some(true)`. That is
/// the rule the whole module enforces.
fn concurrency_for(seeks: Option<bool>) -> usize {
    if seeks != Some(false) {
        return 1;
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    SOLID_STATE_HASH_CONCURRENCY.min(cores).max(1)
}

/// The volume `path` sits on, as a key the platform query below understands.
/// Cheap and pure: the device round trip happens in `query_device`.
#[cfg(windows)]
fn volume_key(path: &Path) -> Option<String> {
    // `\\?\C:\dir\file` and `C:\dir\file` both reduce to `C:`; a UNC path has
    // no volume we can query this way and is left unknown on purpose — a
    // network share is exactly the case where guessing "fast" would be worst.
    let text = path.to_str()?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let mut chars = text.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() || chars.next() != Some(':') {
        return None;
    }
    Some(format!("{}:", letter.to_ascii_uppercase()))
}

/// `(physical device identity, does it seek)` for a volume.
///
/// The identity is the disk's number rather than the volume's letter, because
/// `C:` and `D:` are very often two partitions of one drive. Keying on the
/// letter would have told the caller they were independent and earned exactly
/// the concurrent head travel this module exists to prevent.
#[cfg(windows)]
fn query_device(volume: &str) -> Option<(String, Option<bool>)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceSeekPenaltyProperty, DEVICE_SEEK_PENALTY_DESCRIPTOR,
        IOCTL_STORAGE_GET_DEVICE_NUMBER, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_NUMBER,
        STORAGE_PROPERTY_QUERY,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // No access rights requested: these property queries need only a handle to
    // the volume, and asking for READ would require elevation.
    let wide: Vec<u16> = std::ffi::OsStr::new(&format!(r"\\.\{volume}"))
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return None;
    }

    let mut number = STORAGE_DEVICE_NUMBER {
        DeviceType: 0,
        DeviceNumber: 0,
        PartitionNumber: 0,
    };
    let mut returned: u32 = 0;
    let got_number = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            std::ptr::null(),
            0,
            std::ptr::addr_of_mut!(number) as *mut std::ffi::c_void,
            std::mem::size_of::<STORAGE_DEVICE_NUMBER>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };

    let mut descriptor = DEVICE_SEEK_PENALTY_DESCRIPTOR {
        Version: 0,
        Size: 0,
        IncursSeekPenalty: false,
    };
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceSeekPenaltyProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0; 1],
    };
    let mut penalty_returned: u32 = 0;
    let got_penalty = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            std::ptr::addr_of!(query) as *const std::ffi::c_void,
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            std::ptr::addr_of_mut!(descriptor) as *mut std::ffi::c_void,
            std::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            &mut penalty_returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };

    // Without the disk number we cannot say which drive this is, and a wrong
    // guess splits one spindle into two budgets. Unknown is the safe answer.
    if got_number == 0 || (returned as usize) < std::mem::size_of::<STORAGE_DEVICE_NUMBER>() {
        return None;
    }
    // Plenty of drivers — USB bridges especially — do not answer the seek
    // query. Unknown, not "no penalty". Note this does not cost the caller the
    // *identity*: four unanswering USB drives are still four drives, and still
    // get one read each.
    let seeks = (got_penalty != 0
        && (penalty_returned as usize) >= std::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>())
    .then_some(descriptor.IncursSeekPenalty);
    Some((format!("disk:{}", number.DeviceNumber), seeks))
}

#[cfg(target_os = "linux")]
fn volume_key(path: &Path) -> Option<String> {
    // The device backing this path, as `major:minor`, which is what
    // `/sys/dev/block` is indexed by. Resolved from the path itself rather than
    // by parsing mount tables, so bind mounts and containers answer correctly.
    use std::os::unix::fs::MetadataExt;
    // Walk up until something exists: the file may be mid-scan, but its parent
    // directory is on the same device.
    let mut probe = path;
    let meta = loop {
        match std::fs::metadata(probe) {
            Ok(meta) => break meta,
            Err(_) => probe = probe.parent()?,
        }
    };
    let dev = meta.dev();
    // `libc::major`/`minor` are not available without the crate; the encoding
    // is stable, so decode it here.
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfffu64);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xffu64);
    Some(format!("{major}:{minor}"))
}

/// `(physical device identity, does it seek)` for a `major:minor`.
///
/// Both answers come from the same sysfs node, and it is the *disk's* node, not
/// the partition's: `sda1` and `sda2` are one spindle, and keying on the
/// partition would let the caller read from both at once.
#[cfg(target_os = "linux")]
fn query_device(device: &str) -> Option<(String, Option<bool>)> {
    // `/sys/dev/block/<major>:<minor>` symlinks into the block device's sysfs
    // node; a partition's node sits inside its disk's.
    let base = std::path::PathBuf::from(format!("/sys/dev/block/{device}"));
    let resolved = std::fs::canonicalize(&base).ok()?;
    // A disk's node carries `queue/`; a partition's does not, and its parent is
    // the disk. Anything else — device-mapper and md volumes canonicalize under
    // `/sys/devices/virtual/block`, whose parent is not a disk at all — keeps
    // its own node, which is the honest answer for a virtual device that may
    // span several spindles.
    let disk = if resolved.join("queue").is_dir() {
        resolved
    } else {
        match resolved.parent() {
            Some(parent) if parent.join("queue").is_dir() => parent.to_path_buf(),
            _ => resolved,
        }
    };
    let key = disk.file_name()?.to_string_lossy().into_owned();
    let seeks = match std::fs::read_to_string(disk.join("queue/rotational")) {
        Ok(text) => match text.trim() {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        },
        Err(_) => None,
    };
    Some((format!("disk:{key}"), seeks))
}

/// Everywhere else — macOS most notably — neither question can be answered, so
/// the whole library counts as one unknown device and reads one file at a time.
/// Widening this means adding a real query for that platform (on macOS, an
/// IOKit walk to the physical disk), not relaxing the default: `st_dev` alone
/// would name the *partition*, which is exactly the mistake the Windows and
/// Linux paths above go out of their way to avoid.
#[cfg(not(any(windows, target_os = "linux")))]
fn volume_key(_path: &Path) -> Option<String> {
    None
}

#[cfg(not(any(windows, target_os = "linux")))]
fn query_device(_key: &str) -> Option<(String, Option<bool>)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule the whole module exists to enforce: widen only on a positive
    /// answer. A device that did not report its seek behaviour reads one file
    /// at a time, which is what every release before this did for everything.
    #[test]
    fn unknown_storage_is_treated_as_spinning() {
        assert_eq!(concurrency_for(None), 1);
        assert_eq!(concurrency_for(Some(true)), 1);
        // A path with no volume we can key on resolves to unknown on every
        // platform, so this exercises the fallback without mocking the device.
        assert_eq!(describe_device(Path::new("")), None);
    }

    /// Whatever this machine reports, the answer has to be usable: at least
    /// one, never more than the core count, never more than the ceiling.
    #[test]
    fn a_device_limit_stays_within_its_bounds() {
        let cores = std::thread::available_parallelism()
            .map(|c| c.get())
            .unwrap_or(1);
        for seeks in [None, Some(true), Some(false)] {
            let n = concurrency_for(seeks);
            assert!(n >= 1, "a device must always be readable one at a time");
            assert!(n <= SOLID_STATE_HASH_CONCURRENCY);
            assert!(n <= cores, "never more workers than cores");
        }
        if let Some(info) = describe_device(&std::env::temp_dir()) {
            assert!(info.concurrency >= 1 && info.concurrency <= MAX_TOTAL_HASH_CONCURRENCY);
            assert!(!info.key.is_empty(), "an identified device needs a name");
        }
    }

    /// Caching must not change either answer, only the cost of asking.
    #[test]
    fn repeated_queries_agree() {
        let temp = std::env::temp_dir();
        assert_eq!(describe_device(&temp), describe_device(&temp));
    }

    /// The identity must name the *physical* drive, never the volume. `C:` and
    /// `D:`, or `sda1` and `sda2`, are routinely one spinning disk; keying on
    /// the volume would tell the caller they were independent and schedule
    /// precisely the concurrent head travel this module exists to prevent.
    ///
    /// Checked through the spelling because the alternative — two partitions on
    /// one disk — is not something a unit test can conjure. A key that is just
    /// the volume back again would fail this.
    #[test]
    fn the_identity_names_a_disk_rather_than_a_volume() {
        let Some(info) = describe_device(&std::env::temp_dir()) else {
            // Unidentifiable storage is a legitimate answer on some machines,
            // and it is the safe one; nothing to check.
            return;
        };
        assert!(
            info.key.starts_with("disk:"),
            "expected a physical disk identity, got {:?}",
            info.key
        );
        let volume = volume_key(&std::env::temp_dir()).expect("a described device has a volume");
        assert_ne!(
            info.key,
            format!("disk:{volume}"),
            "the key must come from the disk, not be the volume wearing a prefix"
        );
    }

    /// Two paths on one drive must resolve to one identity, or the caller reads
    /// from both at once and the spinning-disk safeguard is defeated by the very
    /// change that was meant to respect it. Exercised through the real query, so
    /// it also pins that a volume's key is stable across paths within it.
    #[test]
    fn paths_on_one_volume_share_a_device() {
        let temp = std::env::temp_dir();
        let nested = temp.join("ember-device-key-probe");
        assert_eq!(
            describe_device(&temp).map(|d| d.key),
            describe_device(&nested).map(|d| d.key),
            "a directory and a path inside it are the same drive"
        );
    }
}
