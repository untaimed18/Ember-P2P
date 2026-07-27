use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{info, warn};

use crate::search::index::normalize_path_key;

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
const FT_KADLASTPUBLISHSRC: u8 = 0x21;
const FT_LASTSHARED: u8 = 0x24;
// Older Ember builds accidentally wrote the source-publish timestamp with
// eMule's `FT_DL_ACTIVE_TIME` id. Read it for migration, but write the real
// eMule tag above.
const FT_KADLASTPUBLISHSRC_LEGACY_EMBER: u8 = 0x23;
// Ember-only tag (not part of the eMule known.met format): presence with a
// nonzero value means the user explicitly unshared this file while leaving
// it in place under a shared folder. Chosen well outside every FT_* id used
// above so it can never collide with a real eMule tag. Absent (the common
// case) means shared, which keeps old known.met files backward compatible.
const FT_EMBER_UNSHARED: u8 = 0xE0;
// Ember-only tag: last known KAD/source-manager complete-source ("Peers")
// count, refreshed roughly every 60s while connected. Persisted purely so
// the Library UI shows the last-known figure immediately at startup instead
// of resetting to 0 until the next sync — it's a point-in-time gauge, not a
// cumulative counter, so a fresh sync always simply overwrites it.
const FT_EMBER_SOURCES: u8 = 0xE1;
// Ember-only tag: streaming BLAKE3 of file contents (hex). Empty when unknown
// (legacy known.met / not yet hashed). Discovery still keys off eD2K MD4.
const FT_EMBER_FILE_HASH: u8 = 0xE2;
// Ember-only tag: presence with a nonzero value means the user restricted an
// otherwise-shared file to mutual friends. Absent (the common case, and every
// known.met written before this field existed) means the file is public,
// which keeps older catalogs behaving exactly as they did.
//
// 0xE3 rather than 0xE2: this branch already spends 0xE2 on the content hash
// above. See the note in the friends-only commit about keeping the two
// branches on the same id before either ships.
const FT_EMBER_FRIENDS_ONLY: u8 = 0xE3;

const TAG_STRING: u8 = 0x02;
const TAG_UINT32: u8 = 0x03;
const AICH_BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
// Settings accepts up to 512 shared folders and discovery accepts up to
// 100,000 files per folder. Keep the companion path-index ceiling aligned
// with that supported scale instead of silently retaining only the first
// folder's worth of mappings.
const MAX_KNOWN_PATH_MAPPINGS: usize = 512 * 100_000;

#[derive(Debug, Clone)]
pub struct KnownFileRecord {
    pub file_hash: [u8; 16],
    pub part_hashes: Vec<[u8; 16]>,
    pub file_name: String,
    pub file_size: u64,
    pub file_path: String,
    pub aich_hash: String,
    /// Streaming BLAKE3 of file contents (hex). Empty when unknown.
    pub ember_file_hash: String,
    pub modified_at: i64,
    pub all_time_transferred: u64,
    pub all_time_requested: u32,
    pub all_time_accepted: u32,
    pub upload_priority: u8,
    pub last_publish_src: u32,
    pub last_shared: u32,
    /// Whether the user still wants this file offered to the network. Mirrors
    /// `FileInfo::shared` so an explicit per-file "Unshare" (as opposed to
    /// removing the file from a shared folder entirely) survives a restart.
    /// Defaults to `true` so records from before this field existed keep
    /// behaving exactly as they did (nothing was ever persisted as unshared).
    pub is_shared: bool,
    /// Whether an otherwise-shared file is restricted to mutual friends.
    /// Mirrors `FileInfo::friends_only`. Defaults to `false` so records from
    /// before this field existed keep behaving as public shares.
    pub friends_only: bool,
    /// Last known complete-source ("Peers") count, refreshed roughly every
    /// 60s by the source-count sync while connected. See `FT_EMBER_SOURCES`.
    pub complete_sources: u32,
}

/// Per-physical-path metadata for a content-level known.met record. known.met
/// has one entry per ED2K hash, but a Library can contain several copies of
/// that content with different names and mtimes. Keeping this separately
/// avoids making every non-canonical copy rehash on the next startup.
#[derive(Debug, Clone)]
struct KnownPathEntry {
    hash: [u8; 16],
    path: String,
    size: u64,
    modified_at: i64,
}

#[derive(Clone)]
pub struct KnownFileList {
    files: HashMap<[u8; 16], KnownFileRecord>,
    path_index: HashMap<String, KnownPathEntry>,
    dirty: bool,
    dirty_generation: u64,
}

impl KnownFileList {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            path_index: HashMap::new(),
            dirty: false,
            dirty_generation: 0,
        }
    }

    /// Merge records from a freshly loaded catalog. Existing in-memory
    /// entries win on hash collision so a concurrent share-scan that ran
    /// before disk load finished is not clobbered by stale known.met data.
    pub fn absorb_missing_from(&mut self, other: Self) {
        for (hash, record) in other.files {
            if let std::collections::hash_map::Entry::Vacant(e) = self.files.entry(hash) {
                if !record.file_path.is_empty() {
                    self.path_index.insert(
                        normalize_path_key(&record.file_path),
                        KnownPathEntry {
                            hash,
                            path: record.file_path.clone(),
                            size: record.file_size,
                            modified_at: record.modified_at,
                        },
                    );
                }
                e.insert(record);
            }
        }
        // Path index entries for hashes we already had stay as-is; disk-only
        // path mappings for absorbed hashes are already inserted above.
        for (path_key, entry) in other.path_index {
            if self.files.contains_key(&entry.hash) && !self.path_index.contains_key(&path_key) {
                self.path_index.insert(path_key, entry);
            }
        }
    }

    /// Strict loader used by security-policy and share-intent startup. Missing
    /// is a valid empty first-run catalog; read/size/parse failures are
    /// returned so callers can fail closed instead of treating corruption as
    /// an authoritative empty share policy.
    pub fn load_checked(path: &Path) -> anyhow::Result<Self> {
        let mut list = Self::new();
        // known.met is app-managed, but a corrupt or maliciously-swapped file
        // shouldn't be slurped wholesale. This ceiling bounds the worst-case
        // allocation while allowing millions of ordinary records.
        const MAX_KNOWN_MET_BYTES: u64 = 256 * 1024 * 1024;
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(list),
            Err(error) => return Err(error.into()),
        };
        if meta.len() > MAX_KNOWN_MET_BYTES {
            anyhow::bail!(
                "known.met too large ({} bytes, max {MAX_KNOWN_MET_BYTES})",
                meta.len()
            );
        }
        let data = std::fs::read(path)?;
        list.parse_known_met(&data)?;
        list.load_path_index(&path.with_file_name("known_paths.dat"));
        Ok(list)
    }

    /// Compatibility loader for non-policy callers. Errors still quarantine
    /// the damaged catalog, but the independent share-intent store is notified
    /// before an empty in-memory list is returned.
    pub fn load(path: &Path) -> Self {
        match Self::load_checked(path) {
            Ok(list) => {
                if !path.exists() {
                    if let Err(error) = crate::storage::share_intent::note_catalog_missing() {
                        tracing::debug!("Could not record missing known.met state: {error}");
                        crate::storage::share_intent::force_unshared_all();
                    }
                }
                list
            }
            Err(e) => {
                if path.exists() {
                    let backup = path.with_extension(format!(
                        "met.{}.corrupt",
                        chrono::Utc::now().format("%Y%m%d%H%M%S")
                    ));
                    if let Err(backup_error) = std::fs::copy(path, &backup) {
                        warn!("Failed to preserve corrupt known.met: {backup_error}");
                    } else {
                        crate::security::restrict_file_permissions(&backup);
                    }
                    warn!(
                        "Failed to load known.met: {e}; fail-closed share intent enabled (backup: {})",
                        backup.display()
                    );
                } else {
                    warn!("Failed to load known.met: {e}; fail-closed share intent enabled");
                }
                if let Err(intent_error) = crate::storage::share_intent::enter_fail_closed() {
                    warn!("Failed to persist fail-closed share intent: {intent_error}");
                    crate::storage::share_intent::force_unshared_all();
                }
                Self::new()
            }
        }
    }

    fn parse_known_met(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.len() < 5 {
            anyhow::bail!("known.met is truncated");
        }
        let mut cursor = Cursor::new(data);
        let version = cursor.read_u8()?;
        if version != MET_HEADER && version != MET_HEADER_I64TAGS {
            anyhow::bail!("Unknown known.met version: 0x{version:02X}");
        }
        let count = cursor.read_u32::<LittleEndian>()? as usize;

        // Every record has at least mtime + hash + part-count + tag-count.
        // Reject an impossible declared count up front so a truncated file (or
        // corrupt count) reaches `load()`'s quarantine/reset path rather than
        // becoming a valid-looking, permanently shrunken catalog on next save.
        const MIN_RECORD_BYTES: usize = 4 + 16 + 2 + 4;
        let remaining = data.len().saturating_sub(cursor.position() as usize);
        if count > remaining / MIN_RECORD_BYTES {
            anyhow::bail!(
                "known.met declares {count} records but at most {} minimum-size records fit",
                remaining / MIN_RECORD_BYTES
            );
        }

        // No artificial record cap here: `save()` writes the full `files.len()`
        // header, so a hard parse cap would silently drop the tail on restart.
        // A mid-record parse failure has no framing marker to resync from, so we
        // bail and let the caller quarantine known.met rather than keep a prefix
        // that the next dirty save would permanently truncate.
        for record_index in 0..count {
            let record = match Self::read_record(&mut cursor, version) {
                Ok(record) => record,
                Err(e) => {
                    // Quarantine: a mid-file parse error means the on-disk
                    // known.met is corrupt. Returning Ok with a prefix would
                    // let the next dirty save permanently drop the unread tail.
                    anyhow::bail!(
                        "failed to parse known.met record {} of {count}: {e} (loaded {} records before failure)",
                        record_index + 1,
                        self.files.len()
                    );
                }
            };
            let hash = record.file_hash;
            let path = record.file_path.clone();
            self.files.insert(hash, record);
            if !path.is_empty() {
                // Normalize the key so Windows path-casing differences
                // between sessions still hit on lookup (the record keeps
                // the original-case `file_path`).
                self.path_index.insert(
                    normalize_path_key(&path),
                    KnownPathEntry {
                        hash,
                        path,
                        size: self
                            .files
                            .get(&hash)
                            .map(|record| record.file_size)
                            .unwrap_or_default(),
                        modified_at: self
                            .files
                            .get(&hash)
                            .map(|record| record.modified_at)
                            .unwrap_or_default(),
                    },
                );
            }
        }

        // Only after successfully reading all declared records: trailing bytes
        // mean the file is malformed beyond a clean prefix truncate.
        let consumed = cursor.position() as usize;
        if consumed != data.len() {
            anyhow::bail!(
                "known.met has {} trailing bytes after its declared {count} records",
                data.len() - consumed
            );
        }

        info!("Loaded {} known files from known.met", self.files.len());
        Ok(())
    }

    fn read_record(cursor: &mut Cursor<&[u8]>, _version: u8) -> anyhow::Result<KnownFileRecord> {
        let modified_at = cursor.read_u32::<LittleEndian>()? as i64;

        let mut file_hash = [0u8; 16];
        cursor.read_exact(&mut file_hash)?;

        // Part-hash count is a u16 on disk (max 65535 ≈ 608 GiB at PARTSIZE),
        // matching eMule's known.met layout and our own writer, which persists
        // up to u16::MAX hashes. Read the full set: an earlier 1000-hash clamp
        // silently dropped trailing part hashes for files larger than ~9.06 GiB
        // on reload, desyncing the in-memory hashset from what was saved.
        let part_count = cursor.read_u16::<LittleEndian>()? as usize;
        let pos = cursor.position() as usize;
        let remaining = cursor.get_ref().len().saturating_sub(pos);
        let max_parts_from_remaining = remaining / 16;
        if part_count > max_parts_from_remaining {
            anyhow::bail!(
                "known.met record claims {part_count} part hashes but only {max_parts_from_remaining} fit in remaining input"
            );
        }
        let mut part_hashes = Vec::with_capacity(part_count);
        for _ in 0..part_count {
            let mut ph = [0u8; 16];
            cursor.read_exact(&mut ph)?;
            part_hashes.push(ph);
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
            ember_file_hash: String::new(),
            modified_at,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
            is_shared: true,
            friends_only: false,
            complete_sources: 0,
        };

        for _ in 0..tag_count {
            let tag_type = cursor.read_u8()?;
            let name_id = if tag_type & 0x80 != 0 {
                cursor.read_u8()?
            } else {
                let name_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut name_buf = vec![0u8; name_len];
                cursor.read_exact(&mut name_buf)?;
                if name_len == 1 {
                    name_buf[0]
                } else {
                    0
                }
            };

            let real_type = if tag_type & 0x80 != 0 {
                tag_type & 0x7F
            } else {
                tag_type
            };
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
                        FT_AICH_HASH => record.aich_hash = normalize_aich_hash(&s),
                        FT_EMBER_FILE_HASH => record.ember_file_hash = s,
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
                            record.all_time_transferred = (record.all_time_transferred
                                & 0x0000_0000_FFFF_FFFF)
                                | ((v as u64) << 32);
                        }
                        FT_ATREQUESTED => record.all_time_requested = v,
                        FT_ATACCEPTED => record.all_time_accepted = v,
                        FT_ULPRIORITY => record.upload_priority = v as u8,
                        FT_KADLASTPUBLISHSRC | FT_KADLASTPUBLISHSRC_LEGACY_EMBER => {
                            record.last_publish_src = v;
                        }
                        FT_LASTSHARED => record.last_shared = v,
                        FT_EMBER_UNSHARED => record.is_shared = v == 0,
                        FT_EMBER_FRIENDS_ONLY => record.friends_only = v != 0,
                        FT_EMBER_SOURCES => record.complete_sources = v,
                        _ => {}
                    }
                }
                0x08 => {
                    cursor.read_u16::<LittleEndian>()?;
                }
                0x09 => {
                    cursor.read_u8()?;
                }
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
                0x04 => {
                    cursor.read_f32::<LittleEndian>()?;
                }
                0x05 => {
                    cursor.read_u8()?;
                }
                0x07 => {
                    let blen = cursor.read_u32::<LittleEndian>()? as u64;
                    let new_pos = cursor
                        .position()
                        .checked_add(blen)
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
                        FT_AICH_HASH => record.aich_hash = normalize_aich_hash(&s),
                        FT_EMBER_FILE_HASH => record.ember_file_hash = s,
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
    pub fn find_by_path_and_meta(
        &self,
        path: &str,
        size: u64,
        mtime: i64,
    ) -> Option<&KnownFileRecord> {
        if let Some(entry) = self.path_index.get(&normalize_path_key(path)) {
            if let Some(record) = self.files.get(&entry.hash) {
                if entry.size == size && entry.modified_at == mtime {
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
    pub fn find_by_name_and_meta(
        &self,
        name: &str,
        size: u64,
        mtime: i64,
    ) -> Option<&KnownFileRecord> {
        let mut matches = self
            .files
            .values()
            .filter(|r| r.file_name == name && r.file_size == size && r.modified_at == mtime);
        let first = matches.next()?;
        if matches.next().is_some() {
            warn!("known.met: ambiguous match for {name} ({size} bytes, mtime {mtime}); rehashing");
            return None;
        }
        Some(first)
    }

    pub fn find_by_hash(&self, hash: &[u8; 16]) -> Option<&KnownFileRecord> {
        self.files.get(hash)
    }

    /// Companion to `find_by_hash` for callers that need to mutate a
    /// known-file record in-place (e.g. bumping cumulative counters).
    pub fn find_by_hash_mut(&mut self, hash: &[u8; 16]) -> Option<&mut KnownFileRecord> {
        self.files.get_mut(hash)
    }

    /// Manually flag the in-memory list as dirty so the next save will
    /// flush even when no `add_or_update` happened (used by callers
    /// that mutate a record via `find_by_hash_mut`).
    pub fn mark_dirty(&mut self) {
        self.touch_dirty();
    }

    fn touch_dirty(&mut self) {
        self.dirty = true;
        self.dirty_generation = self.dirty_generation.saturating_add(1);
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
        _discovered_name: &str,
        discovered_aich: &str,
    ) -> bool {
        if let Some(entry) = self.path_index.get(&normalize_path_key(discovered_path)) {
            return entry.hash != *hash
                || entry.size != discovered_size
                || entry.modified_at != discovered_mtime
                || (!discovered_aich.is_empty()
                    && self
                        .files
                        .get(hash)
                        .is_none_or(|record| record.aich_hash != discovered_aich));
        }
        match self.files.get(hash) {
            None => true,
            // A new physical path for existing content must be persisted
            // independently. Do not compare it to the content record's
            // canonical name/mtime: those belong to another copy.
            Some(_) => true,
        }
    }

    pub fn add_or_update(&mut self, record: KnownFileRecord) {
        let hash = record.file_hash;
        let new_path = record.file_path.clone();
        if !new_path.is_empty() {
            // `path_index` keys are normalized (case-folded on Windows); compare
            // and mutate via the normalized form throughout so a re-share with
            // different path casing updates the same entry instead of
            // accumulating a stale duplicate.
            let new_key = normalize_path_key(&new_path);
            if let Some(old_entry) = self.path_index.get(&new_key) {
                let old_hash = old_entry.hash;
                if old_hash != hash {
                    let other_refs = self
                        .path_index
                        .iter()
                        .any(|(p, entry)| entry.hash == old_hash && *p != new_key);
                    if !other_refs {
                        self.files.remove(&old_hash);
                    }
                }
            }
            self.path_index.insert(
                new_key,
                KnownPathEntry {
                    hash,
                    path: new_path,
                    size: record.file_size,
                    modified_at: record.modified_at,
                },
            );
        }
        if let Some(existing) = self.files.get_mut(&hash) {
            // Counters are content-wide, but path/name/mtime belong to one
            // canonical copy. Keep that canonical metadata when another
            // duplicate is reconciled and update fields that are genuinely
            // content-wide or newly available.
            existing.part_hashes = record.part_hashes;
            if !record.aich_hash.is_empty() {
                existing.aich_hash = record.aich_hash;
            }
            existing.upload_priority = record.upload_priority;
            existing.is_shared = record.is_shared;
            existing.friends_only = record.friends_only;
            existing.complete_sources = record.complete_sources;
            existing.last_publish_src = record.last_publish_src;
            existing.last_shared = record.last_shared;
            if existing.file_path.is_empty()
                || normalize_path_key(&existing.file_path) == normalize_path_key(&record.file_path)
            {
                existing.file_name = record.file_name;
                existing.file_size = record.file_size;
                existing.file_path = record.file_path;
                existing.modified_at = record.modified_at;
            }
        } else {
            self.files.insert(hash, record);
        }
        self.touch_dirty();
    }

    /// Increment all-time request/accept counters (eMule-style per-file upload interest).
    pub fn bump_share_interest(&mut self, hash: &[u8; 16], requested: u32, accepted: u32) -> bool {
        if requested == 0 && accepted == 0 {
            return true;
        }
        if let Some(record) = self.files.get_mut(hash) {
            record.all_time_requested = record.all_time_requested.saturating_add(requested);
            record.all_time_accepted = record.all_time_accepted.saturating_add(accepted);
            self.touch_dirty();
            true
        } else {
            false
        }
    }

    /// Add payload bytes to all-time uploaded for this file.
    pub fn add_all_time_transferred(&mut self, hash: &[u8; 16], bytes: u64) -> bool {
        if bytes == 0 {
            return true;
        }
        if let Some(record) = self.files.get_mut(hash) {
            record.all_time_transferred = record.all_time_transferred.saturating_add(bytes);
            self.touch_dirty();
            true
        } else {
            false
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn dirty_generation(&self) -> u64 {
        self.dirty_generation
    }

    /// Mark a background snapshot save as durable if no newer mutation happened.
    pub fn mark_saved_if_generation(&mut self, generation: u64) {
        if self.dirty_generation == generation {
            self.dirty = false;
        }
    }

    /// Keep the next timer save eligible after a failed background write.
    pub fn mark_save_failed(&mut self) {
        self.dirty = true;
    }

    pub fn save(&mut self, path: &Path) -> anyhow::Result<()> {
        let needs_i64 = self.files.values().any(|r| r.file_size > u32::MAX as u64);
        let mut buf = Vec::new();
        buf.write_u8(if needs_i64 {
            MET_HEADER_I64TAGS
        } else {
            MET_HEADER
        })?;
        buf.write_u32::<LittleEndian>(self.files.len() as u32)?;

        for record in self.files.values() {
            buf.write_u32::<LittleEndian>(
                (record.modified_at.max(0) as u64).min(u32::MAX as u64) as u32
            )?;

            buf.write_all(&record.file_hash)?;
            let part_count = record.part_hashes.len();
            if part_count > u16::MAX as usize {
                anyhow::bail!(
                    "known.met cannot encode {} part hashes for {} (max {})",
                    part_count,
                    record.file_path,
                    u16::MAX
                );
            }
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
                let wire_aich = aich_hex_to_base32(&record.aich_hash)
                    .unwrap_or_else(|| record.aich_hash.clone());
                write_string_tag(&mut tags, FT_AICH_HASH, &wire_aich)?;
                tag_count += 1;
            }
            if !record.ember_file_hash.is_empty() {
                write_string_tag(&mut tags, FT_EMBER_FILE_HASH, &record.ember_file_hash)?;
                tag_count += 1;
            }
            if record.all_time_transferred > 0 {
                write_u32_tag(
                    &mut tags,
                    FT_ATTRANSFERRED,
                    record.all_time_transferred as u32,
                )?;
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
            if !record.is_shared {
                write_u32_tag(&mut tags, FT_EMBER_UNSHARED, 1)?;
                tag_count += 1;
            }
            if record.friends_only {
                write_u32_tag(&mut tags, FT_EMBER_FRIENDS_ONLY, 1)?;
                tag_count += 1;
            }
            if record.complete_sources > 0 {
                write_u32_tag(&mut tags, FT_EMBER_SOURCES, record.complete_sources)?;
                tag_count += 1;
            }

            buf.write_u32::<LittleEndian>(tag_count)?;
            buf.write_all(&tags)?;
        }

        crate::security::atomic_write(path, &buf, true)?;
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
        if let Ok(store) = crate::storage::share_intent::global() {
            store.mark_catalog_seen()?;
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

    /// Clear cached AICH root hashes for multi-part files (size > PARTSIZE).
    ///
    /// Multi-part AICH roots computed before the SHAHashSet part-boundary fix
    /// (`hash.rs` / `aich.rs`) are wrong: AICH blocks straddled ed2k PART
    /// boundaries, so the stored root doesn't match what eMule computes for the
    /// same file. Recovery data served on demand (`OP_AICHANSWER`) is already
    /// recomputed correctly, but the *stored* root is what we advertise
    /// (`OP_AICHFILEHASHANS`, KAD/search results, ed2k `h=` links), so a peer
    /// that recorded our stale root then rejects our (correct) recovery data.
    /// Clearing forces a one-time recompute via the normal hash path; the ed2k
    /// hash is unchanged, only the AICH root is restored. Single-part files
    /// never cross a part boundary, so their roots were always correct and are
    /// left untouched.
    ///
    /// Returns the number of records whose AICH root was cleared.
    pub fn clear_stale_multipart_aich(&mut self) -> usize {
        let mut cleared = 0usize;
        for record in self.files.values_mut() {
            if record.file_size > crate::network::ed2k::hash::PARTSIZE
                && !record.aich_hash.is_empty()
            {
                record.aich_hash.clear();
                cleared += 1;
            }
        }
        if cleared > 0 {
            self.touch_dirty();
        }
        cleared
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
        // drifted apart (partial write / crash). Version 3 additionally
        // stores path-local size/mtime, allowing multiple physical copies of
        // one hash to skip rehashing independently. Version 1 (no mtime) is
        // still accepted for backward compatibility with older installs.
        if version == 2 || version == 3 {
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
        if count > MAX_KNOWN_PATH_MAPPINGS {
            warn!(
                "known_paths.dat declares {count} mappings (max supported {MAX_KNOWN_PATH_MAPPINGS}); discarding path index"
            );
            return;
        }
        // A v1/v2 mapping needs at least a u16 length plus a 16-byte hash;
        // v3 appends path-local size and mtime.
        // This also rejects a corrupt huge count without iterating it.
        let remaining = data.len().saturating_sub(cur.position() as usize);
        let min_mapping_bytes = if version == 3 { 34 } else { 18 };
        if count > remaining / min_mapping_bytes {
            warn!(
                "known_paths.dat is truncated: declares {count} mappings but at most {} fit",
                remaining / min_mapping_bytes
            );
            return;
        }

        // Parse into a temporary collection first. A truncated/corrupt tail
        // must discard this rebuildable cache wholesale, not leave a silently
        // shortened path index that looks successfully loaded.
        let mut mappings = Vec::with_capacity(count.min(self.files.len()));
        for mapping_index in 0..count {
            let path_len = match cur.read_u16::<LittleEndian>() {
                Ok(l) => l as usize,
                Err(e) => {
                    warn!(
                        "known_paths.dat mapping {} of {count} has no path length: {e}; discarding path index",
                        mapping_index + 1
                    );
                    return;
                }
            };
            if path_len > 32768 {
                warn!(
                    "known_paths.dat mapping {} of {count} has implausible path length {path_len}; discarding path index",
                    mapping_index + 1
                );
                return;
            }
            let mut pbuf = vec![0u8; path_len];
            if let Err(e) = cur.read_exact(&mut pbuf) {
                warn!(
                    "known_paths.dat mapping {} of {count} has a truncated path: {e}; discarding path index",
                    mapping_index + 1
                );
                return;
            }
            let mut hash = [0u8; 16];
            if let Err(e) = cur.read_exact(&mut hash) {
                warn!(
                    "known_paths.dat mapping {} of {count} has a truncated hash: {e}; discarding path index",
                    mapping_index + 1
                );
                return;
            }
            let (size, modified_at) = if version == 3 {
                let size = match cur.read_u64::<LittleEndian>() {
                    Ok(value) => value,
                    Err(e) => {
                        warn!(
                            "known_paths.dat mapping {} of {count} has no size: {e}; discarding path index",
                            mapping_index + 1
                        );
                        return;
                    }
                };
                let modified_at = match cur.read_i64::<LittleEndian>() {
                    Ok(value) => value,
                    Err(e) => {
                        warn!(
                            "known_paths.dat mapping {} of {count} has no mtime: {e}; discarding path index",
                            mapping_index + 1
                        );
                        return;
                    }
                };
                (size, modified_at)
            } else {
                self.files
                    .get(&hash)
                    .map(|record| (record.file_size, record.modified_at))
                    .unwrap_or((0, 0))
            };
            let fp = match String::from_utf8(pbuf) {
                Ok(path) => path,
                Err(e) => {
                    warn!(
                        "known_paths.dat mapping {} of {count} is not UTF-8: {e}; discarding path index",
                        mapping_index + 1
                    );
                    return;
                }
            };
            if !fp.is_empty() && self.files.contains_key(&hash) {
                mappings.push(KnownPathEntry {
                    hash,
                    path: fp,
                    size,
                    modified_at,
                });
            }
        }
        if cur.position() as usize != data.len() {
            warn!(
                "known_paths.dat has {} trailing bytes after its declared {count} mappings; discarding path index",
                data.len() - cur.position() as usize
            );
            return;
        }

        let mut loaded = 0usize;
        for entry in mappings {
            if let Some(record) = self.files.get_mut(&entry.hash) {
                if record.file_path.is_empty() {
                    record.file_path = entry.path.clone();
                }
                self.path_index
                    .insert(normalize_path_key(&entry.path), entry);
                loaded += 1;
            }
        }
        if loaded > 0 {
            info!("Loaded {loaded} path mappings from known_paths.dat");
        }
    }

    fn save_path_index(&self, path: &Path, known_mtime_ns: u64) -> anyhow::Result<()> {
        if self.path_index.is_empty() {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            return Ok(());
        }
        let mut buf = Vec::with_capacity(17 + self.path_index.len() * 56);
        buf.write_all(b"NXPI")?;
        buf.write_u8(3)?;
        buf.write_u64::<LittleEndian>(known_mtime_ns)?;
        buf.write_u32::<LittleEndian>(self.path_index.len() as u32)?;
        for (norm_key, entry) in &self.path_index {
            // Persist the original-case physical path and its own metadata,
            // not the content record's canonical path/mtime.
            let file_path = if entry.path.is_empty() {
                norm_key.as_str()
            } else {
                entry.path.as_str()
            };
            let pb = file_path.as_bytes();
            let len = pb.len().min(u16::MAX as usize);
            buf.write_u16::<LittleEndian>(len as u16)?;
            buf.write_all(&pb[..len])?;
            buf.write_all(&entry.hash)?;
            buf.write_u64::<LittleEndian>(entry.size)?;
            buf.write_i64::<LittleEndian>(entry.modified_at)?;
        }
        crate::security::atomic_write(path, &buf, true)?;
        Ok(())
    }
}

/// One-time migration (guarded by a marker file) that invalidates AICH root
/// hashes computed before the multi-part SHAHashSet part-boundary fix. See
/// [`KnownFileList::clear_stale_multipart_aich`] for why only multi-part roots
/// are affected.
///
/// MUST run before any `known.met` consumer loads the file (the shared-file
/// index, the indexer/hashing task, and the network task) so they all pick up
/// the cleared roots — the invalidated files are then recomputed via the
/// normal startup hashing pass (which yields the same ed2k hash and the
/// corrected AICH root, preserved into `known.met` by the `SharedFilesChanged`
/// reconcile with existing counters intact).
pub fn migrate_aich_v2(data_dir: &Path) {
    let marker = data_dir.join(".aich_root_v2_migrated");
    if marker.exists() {
        return;
    }

    let known_met = data_dir.join("known.met");
    if known_met.exists() {
        let mut list = KnownFileList::load(&known_met);
        let cleared = list.clear_stale_multipart_aich();
        if cleared > 0 {
            if let Err(e) = list.save(&known_met) {
                // Don't write the marker: a failed save means the stale roots
                // are still on disk, so we must retry on the next startup.
                warn!(
                    "AICH v2 migration: failed to rewrite known.met ({e}); will retry next startup"
                );
                return;
            }
            info!(
                "AICH v2 migration: invalidated {cleared} stale multi-part AICH root(s); \
                 they will be recomputed on this startup's hashing pass"
            );
        }
    }

    // Drop the download-completion AICH cache wholesale: it's keyed by ed2k
    // hash with no size field, so we can't single out multi-part entries, and
    // it's a rebuildable cache (repopulated on download completion and from the
    // corrected known.met via the shared index), so clearing it can't lose
    // authoritative data — it only prevents a stale root being served from it.
    let aich_cache = data_dir.join("aich_cache.dat");
    if aich_cache.exists() {
        if let Err(e) = std::fs::remove_file(&aich_cache) {
            warn!("AICH v2 migration: failed to remove aich_cache.dat ({e})");
        }
    }

    if let Err(e) = crate::security::atomic_write(&marker, b"1", true) {
        warn!("AICH v2 migration: failed to write marker ({e}); migration may repeat next startup");
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

fn normalize_aich_hash(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() == 40 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return trimmed.to_ascii_lowercase();
    }
    aich_base32_to_hex(trimmed).unwrap_or_else(|| trimmed.to_string())
}

fn aich_hex_to_base32(hex_value: &str) -> Option<String> {
    let bytes = hex::decode(hex_value).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut out = String::with_capacity(32);
    let mut buffer: u32 = 0;
    let mut bits = 0u8;
    for byte in bytes {
        buffer = (buffer << 8) | byte as u32;
        bits += 8;
        while bits >= 5 {
            let idx = ((buffer >> (bits - 5)) & 0x1F) as usize;
            out.push(AICH_BASE32_ALPHABET[idx] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1F) as usize;
        out.push(AICH_BASE32_ALPHABET[idx] as char);
    }
    Some(out)
}

fn aich_base32_to_hex(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(20);
    let mut buffer: u32 = 0;
    let mut bits = 0u8;
    for ch in value.bytes().filter(|b| *b != b'=') {
        let up = ch.to_ascii_uppercase();
        let val = match up {
            b'A'..=b'Z' => up - b'A',
            b'2'..=b'7' => up - b'2' + 26,
            _ => return None,
        } as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bytes.push(((buffer >> (bits - 8)) & 0xFF) as u8);
            bits -= 8;
        }
    }
    if bytes.len() == 20 {
        Some(hex::encode(bytes))
    } else {
        None
    }
}

/// Encode a UI priority label into the byte stored as
/// `KnownFileRecord::upload_priority` (and shipped as the `FT_ULPRIORITY`
/// known-file tag). Order matches eMule's priority enum: 0=verylow, 1=low,
/// 2=normal, 3=high, 4=release, 5=auto. Unknown labels fall back to `normal`
/// so a malformed UI value never silently promotes a file to the highest tier.
pub fn priority_str_to_u8(priority: &str) -> u8 {
    match priority {
        "verylow" => 0,
        "low" => 1,
        "normal" => 2,
        "high" => 3,
        "release" => 4,
        "auto" => 5,
        _ => 2,
    }
}

/// Inverse of [`priority_str_to_u8`], used to restore a file's priority
/// label from its persisted `known.met` record when the file is
/// rediscovered (app restart, folder reload). Out-of-range bytes (never
/// written by this app, but a foreign/corrupt file could contain anything)
/// fall back to `normal` for the same reason the encoder does.
pub fn priority_u8_to_str(priority: u8) -> &'static str {
    match priority {
        0 => "verylow",
        1 => "low",
        3 => "high",
        4 => "release",
        5 => "auto",
        _ => "normal",
    }
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
            ember_file_hash: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                .to_string(),
            modified_at: 1_700_000_000,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
            is_shared: true,
            friends_only: false,
            complete_sources: 0,
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
    fn duplicate_paths_keep_independent_metadata() {
        let mut kf = KnownFileList::new();
        let first = sample_record();
        let hash = first.file_hash;
        kf.add_or_update(first);

        let mut second = sample_record();
        second.file_path = "C:/Library/renamed-copy.mkv".to_string();
        second.file_name = "renamed-copy.mkv".to_string();
        second.modified_at = 1_700_000_123;
        kf.add_or_update(second);

        assert!(kf
            .find_by_path_and_meta("C:/Library/movie.mkv", 1024 * 1024, 1_700_000_000)
            .is_some());
        assert!(kf
            .find_by_path_and_meta("C:/Library/renamed-copy.mkv", 1024 * 1024, 1_700_000_123)
            .is_some());
        assert!(!kf.record_needs_refresh(
            &hash,
            "C:/Library/renamed-copy.mkv",
            1024 * 1024,
            1_700_000_123,
            "renamed-copy.mkv",
            "",
        ));
    }

    #[test]
    fn clear_stale_multipart_aich_only_clears_multipart_files() {
        use crate::network::ed2k::hash::PARTSIZE;
        let mut kf = KnownFileList::new();

        // Single-part file (size == PARTSIZE ⇒ exactly one part, no part
        // boundary): its AICH root was always correct and must be kept.
        let mut single = sample_record();
        single.file_hash = [0x01; 16];
        single.file_path = "C:/Library/single.bin".to_string();
        single.file_name = "single.bin".to_string();
        single.file_size = PARTSIZE;
        single.aich_hash = "a".repeat(40);
        kf.add_or_update(single);

        // Multi-part file (size > PARTSIZE): stale root must be cleared.
        let mut multi = sample_record();
        multi.file_hash = [0x02; 16];
        multi.file_path = "C:/Library/multi.bin".to_string();
        multi.file_name = "multi.bin".to_string();
        multi.file_size = PARTSIZE + 1;
        multi.aich_hash = "b".repeat(40);
        kf.add_or_update(multi);

        let cleared = kf.clear_stale_multipart_aich();
        assert_eq!(cleared, 1, "only the multi-part file should be cleared");
        assert!(
            !kf.find_by_hash(&[0x01; 16]).unwrap().aich_hash.is_empty(),
            "single-part AICH root must be preserved"
        );
        assert!(
            kf.find_by_hash(&[0x02; 16]).unwrap().aich_hash.is_empty(),
            "multi-part AICH root must be cleared for recompute"
        );

        // Idempotent: a second pass finds nothing left to clear.
        assert_eq!(kf.clear_stale_multipart_aich(), 0);
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

    /// A record with no unshare tag ever written (the common case, and every
    /// known.met written before this field existed) must load as shared.
    #[test]
    fn is_shared_defaults_true_when_tag_absent() {
        let mut kf = KnownFileList::new();
        let r = sample_record();
        let hash = r.file_hash;
        kf.add_or_update(r);
        assert!(kf.find_by_hash(&hash).unwrap().is_shared);
    }

    /// Regression for the "Unshare survives a restart" fix: an explicitly
    /// unshared file's `is_shared = false` must round-trip through an actual
    /// save + load of known.met, not just stay correct in memory.
    #[test]
    fn is_shared_false_roundtrips_through_save_and_load() {
        let mut kf = KnownFileList::new();
        let mut r = sample_record();
        r.is_shared = false;
        let hash = r.file_hash;
        kf.add_or_update(r);

        let path = std::env::temp_dir().join(format!(
            "ember_known_met_shared_roundtrip_{}_{}.met",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        kf.save(&path).expect("save known.met");

        let loaded = KnownFileList::load(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_file_name("known_paths.dat"));

        assert!(
            !loaded.find_by_hash(&hash).unwrap().is_shared,
            "is_shared=false must survive a save/load round trip"
        );
    }

    /// Catalogs written before friends-only shares existed carry no tag, and
    /// must keep loading as public rather than silently restricting files.
    #[test]
    fn friends_only_defaults_false_when_tag_absent() {
        let mut kf = KnownFileList::new();
        let r = sample_record();
        let hash = r.file_hash;
        kf.add_or_update(r);
        assert!(!kf.find_by_hash(&hash).unwrap().friends_only);
    }

    /// A friends-only restriction is a privacy decision, so losing it on
    /// restart would silently republish the file to the open network.
    #[test]
    fn friends_only_roundtrips_through_save_and_load() {
        let mut kf = KnownFileList::new();
        let mut r = sample_record();
        r.friends_only = true;
        let hash = r.file_hash;
        kf.add_or_update(r);

        let path = std::env::temp_dir().join(format!(
            "ember_known_met_friends_only_roundtrip_{}_{}.met",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        kf.save(&path).expect("save known.met");

        let loaded = KnownFileList::load(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_file_name("known_paths.dat"));

        assert!(
            loaded.find_by_hash(&hash).unwrap().friends_only,
            "friends_only=true must survive a save/load round trip"
        );
    }

    /// A record with no source-count tag ever written (the common case, and
    /// every known.met written before this field existed) must load as 0,
    /// matching the pre-existing "unknown until synced" behavior.
    #[test]
    fn complete_sources_defaults_zero_when_tag_absent() {
        let mut kf = KnownFileList::new();
        let r = sample_record();
        let hash = r.file_hash;
        kf.add_or_update(r);
        assert_eq!(kf.find_by_hash(&hash).unwrap().complete_sources, 0);
    }

    /// Regression for "persist the Peers count": the last-known
    /// complete-source count must round-trip through an actual save + load
    /// of known.met so the Library UI doesn't show 0 immediately at startup.
    #[test]
    fn complete_sources_roundtrips_through_save_and_load() {
        let mut kf = KnownFileList::new();
        let mut r = sample_record();
        r.complete_sources = 7;
        let hash = r.file_hash;
        kf.add_or_update(r);

        let path = std::env::temp_dir().join(format!(
            "ember_known_met_sources_roundtrip_{}_{}.met",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        ));
        kf.save(&path).expect("save known.met");

        let loaded = KnownFileList::load(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_file_name("known_paths.dat"));

        assert_eq!(
            loaded.find_by_hash(&hash).unwrap().complete_sources,
            7,
            "complete_sources must survive a save/load round trip"
        );
    }

    #[test]
    fn priority_str_u8_roundtrip_covers_every_label() {
        for label in ["verylow", "low", "normal", "high", "release", "auto"] {
            let byte = priority_str_to_u8(label);
            assert_eq!(
                priority_u8_to_str(byte),
                label,
                "priority label {label} must survive an str->u8->str round trip"
            );
        }
    }
}
