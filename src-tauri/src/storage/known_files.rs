use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{info, warn};

const MET_HEADER: u8 = 0x0E;
const MET_HEADER_I64TAGS: u8 = 0x0F;

const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_AICH_HASH: u8 = 0x27;
const FT_ATTRANSFERRED: u8 = 0x50;
const FT_ATTRANSFERREDHI: u8 = 0x51;
const FT_ATREQUESTED: u8 = 0x52;
const FT_ATACCEPTED: u8 = 0x53;
const FT_ULPRIORITY: u8 = 0x18;
const FT_KADLASTPUBLISHSRC: u8 = 0x23;
const FT_LASTSHARED: u8 = 0x24;

const TAG_STRING: u8 = 0x02;
const TAG_UINT32: u8 = 0x03;

#[derive(Debug, Clone)]
pub struct KnownFileRecord {
    pub file_hash: [u8; 16],
    pub part_hashes: Vec<[u8; 16]>,
    pub file_name: String,
    pub file_size: u64,
    pub file_path: String,
    pub aich_hash: String,
    pub modified_at: i64,
    pub all_time_transferred: u64,
    pub all_time_requested: u32,
    pub all_time_accepted: u32,
    pub upload_priority: u8,
    pub last_publish_src: u32,
    pub last_shared: u32,
}

pub struct KnownFileList {
    files: HashMap<[u8; 16], KnownFileRecord>,
    path_index: HashMap<String, [u8; 16]>,
    dirty: bool,
}

impl KnownFileList {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            path_index: HashMap::new(),
            dirty: false,
        }
    }

    pub fn load(path: &Path) -> Self {
        let mut list = Self::new();
        if !path.exists() {
            return list;
        }
        // known.met is app-managed, but a corrupt or maliciously-swapped file
        // shouldn't be slurped wholesale. 50k records (the parse cap) is only
        // a few MB, so this ceiling is very generous while still bounding the
        // worst-case allocation.
        const MAX_KNOWN_MET_BYTES: u64 = 256 * 1024 * 1024;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_KNOWN_MET_BYTES {
                warn!("known.met too large ({} bytes), refusing to load", meta.len());
                return list;
            }
        }
        match std::fs::read(path) {
            Ok(data) => {
                if let Err(e) = list.parse_known_met(&data) {
                    warn!("Failed to parse known.met: {e}");
                }
            }
            Err(e) => warn!("Failed to read known.met: {e}"),
        }
        list.load_path_index(&path.with_file_name("known_paths.dat"));
        list
    }

    fn parse_known_met(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.len() < 5 {
            return Ok(());
        }
        let mut cursor = Cursor::new(data);
        let version = cursor.read_u8()?;
        if version != MET_HEADER && version != MET_HEADER_I64TAGS {
            anyhow::bail!("Unknown known.met version: 0x{version:02X}");
        }
        let count = cursor.read_u32::<LittleEndian>()? as usize;

        // No artificial record cap here: `save()` writes the full `files.len()`
        // header, so a hard 50k parse cap silently dropped every file past the
        // 50,000th on restart for large libraries. Memory is already bounded
        // before we get here — the caller refuses files over MAX_KNOWN_MET_BYTES
        // (256 MiB), each record's part/tag counts are clamped, and the
        // consecutive-failure guard below stops a truncated/garbage tail (e.g. a
        // bogus huge `count`) after 3 failed reads.
        let mut consecutive_failures = 0u32;
        for _ in 0..count {
            match Self::read_record(&mut cursor, version) {
                Ok(record) => {
                    consecutive_failures = 0;
                    let hash = record.file_hash;
                    let path = record.file_path.clone();
                    self.files.insert(hash, record);
                    if !path.is_empty() {
                        self.path_index.insert(path, hash);
                    }
                }
                Err(e) => {
                    consecutive_failures += 1;
                    warn!("Skipping corrupt record in known.met: {e}");
                    if consecutive_failures >= 3 {
                        warn!("Too many consecutive failures, stopping known.met parse");
                        break;
                    }
                }
            }
        }

        info!("Loaded {} known files from known.met", self.files.len());
        Ok(())
    }

    fn read_record(cursor: &mut Cursor<&[u8]>, _version: u8) -> anyhow::Result<KnownFileRecord> {
        let modified_at = cursor.read_u32::<LittleEndian>()? as i64;

        let mut file_hash = [0u8; 16];
        cursor.read_exact(&mut file_hash)?;

        let part_count = cursor.read_u16::<LittleEndian>()? as usize;
        let clamped_parts = part_count.min(1000);
        let mut part_hashes = Vec::with_capacity(clamped_parts);
        for _ in 0..clamped_parts {
            let mut ph = [0u8; 16];
            cursor.read_exact(&mut ph)?;
            part_hashes.push(ph);
        }
        for _ in clamped_parts..part_count {
            let mut skip = [0u8; 16];
            cursor.read_exact(&mut skip)?;
        }

        let tag_count = cursor.read_u32::<LittleEndian>()? as usize;
        if tag_count > 5000 {
            anyhow::bail!("implausible tag count {tag_count} in known.met record");
        }

        let mut record = KnownFileRecord {
            file_hash,
            part_hashes,
            file_name: String::new(),
            file_size: 0,
            file_path: String::new(),
            aich_hash: String::new(),
            modified_at,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
        };

        for _ in 0..tag_count {
            let tag_type = cursor.read_u8()?;
            let name_id = if tag_type & 0x80 != 0 {
                cursor.read_u8()?
            } else {
                let name_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut name_buf = vec![0u8; name_len];
                cursor.read_exact(&mut name_buf)?;
                if name_len == 1 { name_buf[0] } else { 0 }
            };

            let real_type = if tag_type & 0x80 != 0 { tag_type & 0x7F } else { tag_type };
            match real_type {
                TAG_STRING => {
                    let slen = cursor.read_u16::<LittleEndian>()? as usize;
                    let clamped = slen.min(4096);
                    let mut sbuf = vec![0u8; clamped];
                    cursor.read_exact(&mut sbuf)?;
                    if slen > clamped {
                        let skip = (slen - clamped) as u64;
                        let new_pos = cursor.position() + skip;
                        if new_pos > cursor.get_ref().len() as u64 {
                            anyhow::bail!("string tag length {slen} exceeds data boundary");
                        }
                        cursor.set_position(new_pos);
                    }
                    let s = String::from_utf8_lossy(&sbuf).to_string();
                    match name_id {
                        FT_FILENAME => record.file_name = s,
                        FT_AICH_HASH => record.aich_hash = s,
                        _ => {}
                    }
                }
                TAG_UINT32 => {
                    let v = cursor.read_u32::<LittleEndian>()?;
                    match name_id {
                        FT_FILESIZE => record.file_size = v as u64,
                        FT_ATTRANSFERRED => {
                            record.all_time_transferred =
                                (record.all_time_transferred & 0xFFFF_FFFF_0000_0000) | v as u64;
                        }
                        FT_ATTRANSFERREDHI => {
                            record.all_time_transferred =
                                (record.all_time_transferred & 0x0000_0000_FFFF_FFFF) | ((v as u64) << 32);
                        }
                        FT_ATREQUESTED => record.all_time_requested = v,
                        FT_ATACCEPTED => record.all_time_accepted = v,
                        FT_ULPRIORITY => record.upload_priority = v as u8,
                        FT_KADLASTPUBLISHSRC => record.last_publish_src = v,
                        FT_LASTSHARED => record.last_shared = v,
                        _ => {}
                    }
                }
                0x08 => { cursor.read_u16::<LittleEndian>()?; }
                0x09 => { cursor.read_u8()?; }
                0x0B => {
                    let v = cursor.read_u64::<LittleEndian>()?;
                    if name_id == FT_FILESIZE {
                        record.file_size = v;
                    }
                }
                0x01 => {
                    let mut skip = [0u8; 16];
                    cursor.read_exact(&mut skip)?;
                }
                0x04 => { cursor.read_f32::<LittleEndian>()?; }
                0x05 => { cursor.read_u8()?; }
                0x07 => {
                    let blen = cursor.read_u32::<LittleEndian>()? as u64;
                    let new_pos = cursor.position().checked_add(blen)
                        .filter(|&p| p <= cursor.get_ref().len() as u64)
                        .ok_or_else(|| anyhow::anyhow!("blob tag length {blen} exceeds data"))?;
                    cursor.set_position(new_pos);
                }
                0x0A => {
                    let blen = cursor.read_u8()? as usize;
                    let mut skip = vec![0u8; blen];
                    cursor.read_exact(&mut skip)?;
                }
                t if (0x11..=0x20).contains(&t) => {
                    let len = (t - 0x11 + 1) as usize;
                    let mut sbuf = vec![0u8; len];
                    cursor.read_exact(&mut sbuf)?;
                    let s = String::from_utf8_lossy(&sbuf).to_string();
                    match name_id {
                        FT_FILENAME => record.file_name = s,
                        FT_AICH_HASH => record.aich_hash = s,
                        _ => {}
                    }
                }
                _ => {
                    anyhow::bail!(
                        "Unknown known.met tag type 0x{:02X} at position {}, cannot skip value",
                        real_type,
                        cursor.position(),
                    );
                }
            }
        }

        Ok(record)
    }

    /// Look up a known file by path, size, and mtime to skip re-hashing.
    pub fn find_by_path_and_meta(&self, path: &str, size: u64, mtime: i64) -> Option<&KnownFileRecord> {
        if let Some(hash) = self.path_index.get(path) {
            if let Some(record) = self.files.get(hash) {
                if record.file_size == size && record.modified_at == mtime {
                    return Some(record);
                }
            }
        }
        // Fallback: match by name + size + mtime (eMule's FindKnownFile approach).
        // The known.met format doesn't persist file paths, so after a restart
        // the path_index is empty and we must match by metadata instead.
        self.find_by_name_and_meta(
            std::path::Path::new(path)
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
                .as_ref(),
            size,
            mtime,
        )
    }

    /// eMule-compatible lookup: match by filename, size, and modified time.
    /// Used when file paths aren't available (e.g. after loading from known.met).
    ///
    /// Safety: when multiple stored records share the same (name, size, mtime)
    /// tuple we intentionally return `None` rather than pick an arbitrary one.
    /// Returning the wrong record here would attribute a file's hash/AICH to
    /// the wrong path on disk, causing uploads/downloads to serve corrupted
    /// data. The next indexer pass will rehash the file and re-establish a
    /// unique association via `path_index`.
    ///
    /// TODO: persist an inode/NtfsFileID discriminator alongside the record
    /// so ambiguous matches can be resolved without a rehash. Requires a
    /// known.met format-version bump (add a new tag).
    pub fn find_by_name_and_meta(&self, name: &str, size: u64, mtime: i64) -> Option<&KnownFileRecord> {
        let mut matches = self.files.values().filter(|r| {
            r.file_name == name && r.file_size == size && r.modified_at == mtime
        });
        let first = matches.next()?;
        if matches.next().is_some() {
            warn!(
                "known.met: ambiguous match for {name} ({size} bytes, mtime {mtime}); rehashing"
            );
            return None;
        }
        Some(first)
    }

    pub fn find_by_hash(&self, hash: &[u8; 16]) -> Option<&KnownFileRecord> {
        self.files.get(hash)
    }

    /// Companion to `find_by_hash` for callers that need to mutate a
    /// known-file record in-place (e.g. bumping cumulative counters).
    /// Kept on the public surface alongside the immutable accessor for
    /// API symmetry; V2 currently uses `add_or_update` for mutations,
    /// so this is allowed to be unused.
    #[allow(dead_code)]
    pub fn find_by_hash_mut(&mut self, hash: &[u8; 16]) -> Option<&mut KnownFileRecord> {
        self.files.get_mut(hash)
    }

    /// Manually flag the in-memory list as dirty so the next save will
    /// flush even when no `add_or_update` happened (used by callers
    /// that mutate a record via `find_by_hash_mut`).
    #[allow(dead_code)]
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Decide whether the on-disk known-file record matches what we just
    /// discovered for this file, or whether we need to refresh the
    /// record. Returns `true` if any of `file_path`, `modified_at`,
    /// `file_size`, `file_name`, or `aich_hash` (when the discovery
    /// supplies one) has drifted from the stored value.
    ///
    /// Used by the `SharedFilesChanged` handler to break the
    /// "permanent rehash loop" that fires whenever any external
    /// process (Defender, indexing, cloud sync, copy-with-mtime-
    /// preserved) touches a shared file's metadata: the next
    /// discovery's `find_by_path_and_meta` rejects the stale `mtime`,
    /// the rehash produces an identical hash, and without a refresh
    /// here the record's `modified_at` would stay stale forever and
    /// every subsequent reload would rehash the same files again.
    pub fn record_needs_refresh(
        &self,
        hash: &[u8; 16],
        discovered_path: &str,
        discovered_size: u64,
        discovered_mtime: i64,
        discovered_name: &str,
        discovered_aich: &str,
    ) -> bool {
        match self.files.get(hash) {
            None => true,
            Some(record) => {
                record.file_path != discovered_path
                    || record.modified_at != discovered_mtime
                    || record.file_size != discovered_size
                    || record.file_name != discovered_name
                    || (!discovered_aich.is_empty() && record.aich_hash != discovered_aich)
            }
        }
    }

    pub fn add_or_update(&mut self, record: KnownFileRecord) {
        let hash = record.file_hash;
        let new_path = record.file_path.clone();
        if !new_path.is_empty() {
            if let Some(&old_hash) = self.path_index.get(&new_path) {
                if old_hash != hash {
                    let other_refs = self.path_index.iter()
                        .any(|(p, h)| *h == old_hash && *p != new_path);
                    if !other_refs {
                        self.files.remove(&old_hash);
                    }
                }
            }
            // Remove stale path_index entry if this hash was previously at a different path
            if let Some(existing) = self.files.get(&hash) {
                let old_path = &existing.file_path;
                if !old_path.is_empty() && *old_path != new_path {
                    if self.path_index.get(old_path) == Some(&hash) {
                        self.path_index.remove(old_path);
                    }
                }
            }
            self.path_index.insert(new_path, hash);
        }
        self.files.insert(hash, record);
        self.dirty = true;
    }

    /// Increment all-time request/accept counters (eMule-style per-file upload interest).
    pub fn bump_share_interest(&mut self, hash: &[u8; 16], requested: u32, accepted: u32) {
        if requested == 0 && accepted == 0 {
            return;
        }
        if let Some(record) = self.files.get_mut(hash) {
            record.all_time_requested = record.all_time_requested.saturating_add(requested);
            record.all_time_accepted = record.all_time_accepted.saturating_add(accepted);
            self.dirty = true;
        }
    }

    /// Add payload bytes to all-time uploaded for this file.
    pub fn add_all_time_transferred(&mut self, hash: &[u8; 16], bytes: u64) {
        if bytes == 0 {
            return;
        }
        if let Some(record) = self.files.get_mut(hash) {
            record.all_time_transferred = record.all_time_transferred.saturating_add(bytes);
            self.dirty = true;
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn save(&mut self, path: &Path) -> anyhow::Result<()> {
        let needs_i64 = self.files.values().any(|r| r.file_size > u32::MAX as u64);
        let mut buf = Vec::new();
        buf.write_u8(if needs_i64 { MET_HEADER_I64TAGS } else { MET_HEADER })?;
        buf.write_u32::<LittleEndian>(self.files.len() as u32)?;

        for record in self.files.values() {
            buf.write_u32::<LittleEndian>((record.modified_at.max(0) as u64).min(u32::MAX as u64) as u32)?;

            buf.write_all(&record.file_hash)?;
            let part_count = record.part_hashes.len().min(u16::MAX as usize);
            buf.write_u16::<LittleEndian>(part_count as u16)?;
            for ph in &record.part_hashes {
                buf.write_all(ph)?;
            }

            let mut tags = Vec::new();
            let mut tag_count: u32 = 0;

            if !record.file_name.is_empty() {
                write_string_tag(&mut tags, FT_FILENAME, &record.file_name)?;
                tag_count += 1;
            }
            if record.file_size > u32::MAX as u64 {
                write_u64_tag(&mut tags, FT_FILESIZE, record.file_size)?;
            } else {
                write_u32_tag(&mut tags, FT_FILESIZE, record.file_size as u32)?;
            }
            tag_count += 1;

            if !record.aich_hash.is_empty() {
                write_string_tag(&mut tags, FT_AICH_HASH, &record.aich_hash)?;
                tag_count += 1;
            }
            if record.all_time_transferred > 0 {
                write_u32_tag(&mut tags, FT_ATTRANSFERRED, record.all_time_transferred as u32)?;
                tag_count += 1;
                let hi = (record.all_time_transferred >> 32) as u32;
                if hi > 0 {
                    write_u32_tag(&mut tags, FT_ATTRANSFERREDHI, hi)?;
                    tag_count += 1;
                }
            }
            if record.all_time_requested > 0 {
                write_u32_tag(&mut tags, FT_ATREQUESTED, record.all_time_requested)?;
                tag_count += 1;
            }
            if record.all_time_accepted > 0 {
                write_u32_tag(&mut tags, FT_ATACCEPTED, record.all_time_accepted)?;
                tag_count += 1;
            }
            if record.upload_priority > 0 {
                write_u32_tag(&mut tags, FT_ULPRIORITY, record.upload_priority as u32)?;
                tag_count += 1;
            }
            if record.last_publish_src > 0 {
                write_u32_tag(&mut tags, FT_KADLASTPUBLISHSRC, record.last_publish_src)?;
                tag_count += 1;
            }
            if record.last_shared > 0 {
                write_u32_tag(&mut tags, FT_LASTSHARED, record.last_shared)?;
                tag_count += 1;
            }

            buf.write_u32::<LittleEndian>(tag_count)?;
            buf.write_all(&tags)?;
        }

        crate::security::atomic_write(path, &buf, false)?;
        // Pair the companion path index to this specific known.met revision
        // by embedding known.met's current mtime. On load we only use the
        // cached path index when the mtime still matches — otherwise the
        // two files got out of sync (partial write, crash between writes)
        // and the stale index is silently discarded instead of producing
        // confusing name+size+mtime mismatches.
        //
        // Only clear `dirty` once BOTH known.met and its companion path
        // index are durable. Previously `dirty` was cleared right after
        // known.met, so a failed known_paths.dat write was never retried
        // until the next mutating change — leaving a stale/empty path index
        // after restart (files then matched by name only).
        let known_mtime_ns = mtime_ns(path).unwrap_or(0);
        match self.save_path_index(&path.with_file_name("known_paths.dat"), known_mtime_ns) {
            Ok(()) => {
                self.dirty = false;
            }
            Err(e) => {
                warn!("Failed to save known_paths.dat: {e}; keeping dirty flag set to retry next cycle");
                self.dirty = true;
            }
        }
        info!("Saved {} known files to known.met", self.files.len());
        Ok(())
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn all_records(&self) -> impl Iterator<Item = &KnownFileRecord> {
        self.files.values()
    }

    /// Load a companion path index so files can be matched by exact path
    /// after restart (the eMule known.met format only stores filenames).
    fn load_path_index(&mut self, path: &Path) {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => return,
        };
        if data.len() < 9 {
            return;
        }
        let mut cur = Cursor::new(&data[..]);
        let mut magic = [0u8; 4];
        if cur.read_exact(&mut magic).is_err() || &magic != b"NXPI" {
            return;
        }
        let version = match cur.read_u8() {
            Ok(v) => v,
            Err(_) => return,
        };
        // Version 2 adds a known.met mtime tag so we can detect pairs that
        // drifted apart (partial write / crash). Version 1 (no mtime) is
        // still accepted for backward compatibility with older installs.
        if version == 2 {
            let expected_mtime = match cur.read_u64::<LittleEndian>() {
                Ok(m) => m,
                Err(_) => return,
            };
            let actual_mtime = mtime_ns(&path.with_file_name("known.met")).unwrap_or(0);
            if expected_mtime != actual_mtime {
                warn!(
                    "known_paths.dat mtime tag does not match known.met (expected {expected_mtime}, got {actual_mtime}); discarding stale path index"
                );
                return;
            }
        } else if version != 1 {
            return;
        }
        let count = match cur.read_u32::<LittleEndian>() {
            Ok(c) => c as usize,
            Err(_) => return,
        };
        let mut loaded = 0usize;
        for _ in 0..count.min(100_000) {
            let path_len = match cur.read_u16::<LittleEndian>() {
                Ok(l) => l as usize,
                Err(_) => break,
            };
            if path_len > 32768 {
                break;
            }
            let mut pbuf = vec![0u8; path_len];
            if cur.read_exact(&mut pbuf).is_err() {
                break;
            }
            let mut hash = [0u8; 16];
            if cur.read_exact(&mut hash).is_err() {
                break;
            }
            if let Some(record) = self.files.get_mut(&hash) {
                let fp = String::from_utf8_lossy(&pbuf).to_string();
                if record.file_path.is_empty() {
                    record.file_path = fp.clone();
                }
                self.path_index.insert(fp, hash);
                loaded += 1;
            }
        }
        if loaded > 0 {
            info!("Loaded {loaded} path mappings from known_paths.dat");
        }
    }

    fn save_path_index(&self, path: &Path, known_mtime_ns: u64) -> anyhow::Result<()> {
        if self.path_index.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::with_capacity(17 + self.path_index.len() * 40);
        buf.write_all(b"NXPI")?;
        buf.write_u8(2)?;
        buf.write_u64::<LittleEndian>(known_mtime_ns)?;
        buf.write_u32::<LittleEndian>(self.path_index.len() as u32)?;
        for (file_path, hash) in &self.path_index {
            let pb = file_path.as_bytes();
            let len = pb.len().min(u16::MAX as usize);
            buf.write_u16::<LittleEndian>(len as u16)?;
            buf.write_all(&pb[..len])?;
            buf.write_all(hash)?;
        }
        crate::security::atomic_write(path, &buf, false)?;
        Ok(())
    }
}

/// Return the file's last-modification time in nanoseconds since the Unix
/// epoch, or None if the file doesn't exist or the filesystem doesn't
/// expose a modified timestamp.
fn mtime_ns(path: &Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let mtime = meta.modified().ok()?;
    mtime
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_nanos() as u64)
}

fn write_string_tag(buf: &mut Vec<u8>, name_id: u8, value: &str) -> anyhow::Result<()> {
    let max_len = 65535;
    let clamped = if value.len() <= max_len {
        value
    } else {
        let mut end = max_len;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    };
    buf.write_u8(TAG_STRING)?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_u16::<LittleEndian>(clamped.len() as u16)?;
    buf.write_all(clamped.as_bytes())?;
    Ok(())
}

fn write_u32_tag(buf: &mut Vec<u8>, name_id: u8, value: u32) -> anyhow::Result<()> {
    buf.write_u8(TAG_UINT32)?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_u32::<LittleEndian>(value)?;
    Ok(())
}

fn write_u64_tag(buf: &mut Vec<u8>, name_id: u8, value: u64) -> anyhow::Result<()> {
    buf.write_u8(0x0B)?; // TAGTYPE_UINT64
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_u64::<LittleEndian>(value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> KnownFileRecord {
        KnownFileRecord {
            file_hash: [0x42; 16],
            part_hashes: Vec::new(),
            file_name: "movie.mkv".to_string(),
            file_size: 1024 * 1024,
            file_path: "C:/Library/movie.mkv".to_string(),
            aich_hash: "aichaichaichaichaichaichaichaichaichaich".to_string(),
            modified_at: 1_700_000_000,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
        }
    }

    #[test]
    fn record_needs_refresh_returns_true_when_hash_unknown() {
        let kf = KnownFileList::new();
        assert!(kf.record_needs_refresh(
            &[0; 16],
            "C:/Library/movie.mkv",
            1024 * 1024,
            1_700_000_000,
            "movie.mkv",
            "",
        ));
    }

    #[test]
    fn record_needs_refresh_returns_false_when_everything_matches() {
        let mut kf = KnownFileList::new();
        let r = sample_record();
        let hash = r.file_hash;
        let path = r.file_path.clone();
        let aich = r.aich_hash.clone();
        kf.add_or_update(r);
        assert!(!kf.record_needs_refresh(
            &hash,
            &path,
            1024 * 1024,
            1_700_000_000,
            "movie.mkv",
            &aich,
        ));
    }

    /// Regression for the "permanent rehash loop" described above:
    /// when `mtime` drifts (the typical case — Defender / indexing /
    /// cloud sync touches the file), the helper must report a refresh
    /// is needed so the SharedFilesChanged handler updates the record.
    /// Before the helper existed, the handler skipped the update on
    /// hash-match and the file would re-hash on every reload forever.
    #[test]
    fn record_needs_refresh_on_mtime_drift() {
        let mut kf = KnownFileList::new();
        let r = sample_record();
        let hash = r.file_hash;
        let path = r.file_path.clone();
        let aich = r.aich_hash.clone();
        kf.add_or_update(r);
        assert!(
            kf.record_needs_refresh(
                &hash,
                &path,
                1024 * 1024,
                1_700_000_500, // <-- drifted
                "movie.mkv",
                &aich,
            ),
            "mtime drift must trigger a refresh — otherwise the next \
             discovery's find_by_path_and_meta will reject the stale \
             mtime, the rehash will produce an identical hash, and the \
             record will stay stale indefinitely (permanent rehash loop)",
        );
    }

    #[test]
    fn record_needs_refresh_on_path_change() {
        let mut kf = KnownFileList::new();
        let r = sample_record();
        let hash = r.file_hash;
        let aich = r.aich_hash.clone();
        kf.add_or_update(r);
        // Same hash, different path — file was moved/renamed.
        assert!(kf.record_needs_refresh(
            &hash,
            "C:/Library/Subfolder/movie.mkv",
            1024 * 1024,
            1_700_000_000,
            "movie.mkv",
            &aich,
        ));
    }

    #[test]
    fn record_needs_refresh_ignores_empty_aich_in_discovery() {
        // If discovery doesn't supply an AICH (e.g. the file hasn't
        // been AICH-hashed yet on this pass), don't flag a refresh
        // just because the stored record has one. Otherwise we'd
        // wipe a known AICH every time the watcher fires before AICH
        // has caught up.
        let mut kf = KnownFileList::new();
        let r = sample_record();
        let hash = r.file_hash;
        let path = r.file_path.clone();
        kf.add_or_update(r);
        assert!(!kf.record_needs_refresh(
            &hash,
            &path,
            1024 * 1024,
            1_700_000_000,
            "movie.mkv",
            "", // <-- discovery hasn't computed AICH yet
        ));
    }
}
