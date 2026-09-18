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
//! spinning by [`hash_concurrency`]: we widen only where we have been told it
//! is safe, never where we are guessing. That keeps the conservative behaviour
//! for every platform and every storage kind this cannot speak for: macOS,
//! network shares, exotic filesystems, containers.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// Concurrent file hashes to run when the storage is known not to seek.
///
/// Four rather than "one per core": the pass is a mix of reading and hashing,
/// so the useful ceiling is set by the drive's queue depth long before the
/// CPU's core count, and every extra worker is another 1 MiB buffer and another
/// file held open. It is also bounded by `available_parallelism` below, so a
/// dual-core machine does not run four.
const SOLID_STATE_HASH_CONCURRENCY: usize = 4;

/// Whether reads from `path` incur a seek penalty — i.e. whether it lives on
/// something mechanical.
///
/// `None` means we could not find out, which callers must treat as "assume it
/// seeks". Results are cached per volume: the query is a device round trip and
/// the answer cannot change for the life of the process.
pub fn incurs_seek_penalty(path: &Path) -> Option<bool> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<bool>>>> = OnceLock::new();
    let key = volume_key(path)?;
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .copied()
    {
        return cached;
    }
    let answer = query_seek_penalty(&key);
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, answer);
    answer
}

/// How many files to hash at once for a library rooted at these paths.
///
/// One unless *every* path is on storage we have positively identified as
/// non-seeking. A library spread across an SSD and an external drive hashes at
/// the speed the external drive tolerates, because the alternative is making
/// the slower half slower still.
pub fn hash_concurrency(paths: &[impl AsRef<Path>]) -> usize {
    if paths.is_empty() {
        return 1;
    }
    let all_solid_state = paths
        .iter()
        .all(|p| incurs_seek_penalty(p.as_ref()) == Some(false));
    if !all_solid_state {
        return 1;
    }
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    SOLID_STATE_HASH_CONCURRENCY.min(cores).max(1)
}

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

#[cfg(windows)]
fn query_seek_penalty(volume: &str) -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Ioctl::{
        DEVICE_SEEK_PENALTY_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
        STORAGE_PROPERTY_QUERY, StorageDeviceSeekPenaltyProperty,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // No access rights requested: the property query needs only a handle to the
    // volume, and asking for READ would require elevation.
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

    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceSeekPenaltyProperty,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0; 1],
    };
    let mut descriptor = DEVICE_SEEK_PENALTY_DESCRIPTOR {
        Version: 0,
        Size: 0,
        IncursSeekPenalty: false,
    };
    let mut returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            std::ptr::addr_of!(query) as *const std::ffi::c_void,
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            std::ptr::addr_of_mut!(descriptor) as *mut std::ffi::c_void,
            std::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(handle) };

    if ok == 0 || (returned as usize) < std::mem::size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() {
        // Plenty of drivers — USB bridges especially — simply do not answer
        // this. Unknown, not "no penalty".
        return None;
    }
    Some(descriptor.IncursSeekPenalty)
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

#[cfg(target_os = "linux")]
fn query_seek_penalty(device: &str) -> Option<bool> {
    // `/sys/dev/block/<major>:<minor>` symlinks into the block device's sysfs
    // node. A partition's own directory has no `queue/`, so fall back to the
    // parent disk.
    let base = std::path::PathBuf::from(format!("/sys/dev/block/{device}"));
    let resolved = std::fs::canonicalize(&base).ok()?;
    // A partition's own node has no `queue/`; its parent disk does. Built
    // lazily — an eager `resolved.parent()?` in the list would abandon the
    // whole lookup for a device that happens to have no parent, before the
    // first candidate had been tried at all.
    let mut candidates = vec![resolved.join("queue/rotational")];
    if let Some(parent) = resolved.parent() {
        candidates.push(parent.join("queue/rotational"));
    }
    for candidate in candidates {
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            return match text.trim() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            };
        }
    }
    None
}

/// Everywhere else — macOS most notably — the answer is unknown, and
/// [`hash_concurrency`] therefore stays at one. Widening this means adding a
/// real query for that platform, not relaxing the default.
#[cfg(not(any(windows, target_os = "linux")))]
fn volume_key(_path: &Path) -> Option<String> {
    None
}

#[cfg(not(any(windows, target_os = "linux")))]
fn query_seek_penalty(_key: &str) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule the whole module exists to enforce: widen only on a positive
    /// answer. Anything we could not determine hashes one file at a time, which
    /// is what every release before this did for everyone.
    #[test]
    fn unknown_storage_is_treated_as_spinning() {
        // A path with no volume we can key on resolves to unknown on every
        // platform, so this exercises the fallback without mocking the device.
        let unknowable: &[&Path] = &[Path::new("")];
        assert_eq!(hash_concurrency(unknowable), 1);
        let none: &[&Path] = &[];
        assert_eq!(hash_concurrency(none), 1);
    }

    /// A library spread across two drives is only as parallel as its least
    /// tolerant member, so one unknown path holds the whole pass to one.
    #[test]
    fn a_single_unknown_path_holds_the_pass_to_one() {
        let temp = std::env::temp_dir();
        let mixed: Vec<&Path> = vec![temp.as_path(), Path::new("")];
        assert_eq!(hash_concurrency(&mixed), 1);
    }

    /// Whatever this machine reports, the answer has to be usable: at least
    /// one, never more than the core count, never more than the ceiling.
    #[test]
    fn concurrency_stays_within_its_bounds() {
        let temp = std::env::temp_dir();
        let n = hash_concurrency(std::slice::from_ref(&temp));
        assert!(n >= 1, "a pass must always run at least one hash");
        assert!(n <= SOLID_STATE_HASH_CONCURRENCY);
        let cores = std::thread::available_parallelism()
            .map(|c| c.get())
            .unwrap_or(1);
        assert!(n <= cores, "never more workers than cores");
    }

    /// Caching must not change the answer, only the cost of asking.
    #[test]
    fn repeated_queries_agree() {
        let temp = std::env::temp_dir();
        let first = incurs_seek_penalty(&temp);
        let second = incurs_seek_penalty(&temp);
        assert_eq!(first, second);
    }
}
