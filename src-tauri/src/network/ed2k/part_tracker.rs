use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

use super::messages::PARTSIZE;

const OLD_PART_MET_MAGIC: u32 = 0x504D4554; // "PMET" - legacy format

/// eMule version bytes for .part.met files
const PARTFILE_VERSION: u8 = 0xE0;
const PARTFILE_VERSION_LARGEFILE: u8 = 0xE2;

/// eMule tag IDs for .part.met
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_GAPSTART: u8 = 0x09;
const FT_GAPEND: u8 = 0x0A;
const FT_TRANSFERRED: u8 = 0x08;
const FT_STATUS: u8 = 0x14;
/// Ember-private tag: per-part MD4 verified bitmap.
/// eMule ignores unknown tag IDs, so this is safe as a forward-compatible
/// extension. Encoded as a BLOB: first byte = byte count, then the raw
/// bitmap bytes (LSB-first per byte).
const FT_EMBER_VERIFIED_BITMAP: u8 = 0xEB;

/// eMule tag types
const TAGTYPE_UINT32: u8 = 0x03;
const TAGTYPE_UINT64: u8 = 0x0B;
const TAGTYPE_STRING: u8 = 0x02;
const TAGTYPE_BLOB: u8 = 0x07;

/// Hard cap on byte-gap list fragmentation. A hostile peer (or a long
/// adversarial session) can split the gap list into O(n) tiny intervals
/// by sending 1-byte chunks; every extra gap costs two tags in .part.met,
/// so unbounded fragmentation blows up the metadata file. When we exceed
/// this limit, small filled-between-two-gaps runs are re-invalidated to
/// merge neighbouring gaps (they'll be re-requested, cheap on the wire,
/// compared with an unusable .part.met).
const MAX_GAP_ENTRIES: usize = 8192;

/// Byte-level gap list matching eMule's CPartFile::m_gaplist.
/// Each gap is a (start, end_exclusive) byte range that has NOT been received.
/// A file with no gaps is complete.
#[derive(Debug, Clone)]
pub struct PartTracker {
    pub file_size: u64,
    pub part_count: usize,
    /// Byte-level gap list: missing ranges (start, end_exclusive).
    /// An empty list means the file is fully downloaded.
    gaps: Vec<(u64, u64)>,
    pub in_progress: Vec<bool>,
    met_path: PathBuf,
    file_hash: [u8; 16],
    file_name: String,
    /// MD4 hashes for each part (stored in .part.met for eMule compatibility)
    part_hashes: Vec<[u8; 16]>,
    /// Per-part MD4-verified flag. True only after the part's bytes fully
    /// arrived AND `part_hashes[i]` matched (or for a single-part file,
    /// after the file-level ed2k hash matched). Reset to false by
    /// `mark_incomplete`, `invalidate_range`, or any gap change that
    /// re-opens part bytes. Persisted via `FT_EMBER_VERIFIED_BITMAP` so a
    /// resume after restart does not re-mark bytes as safe-to-upload until
    /// the download verifies them again. `len() == part_count`.
    part_verified: Vec<bool>,
    /// Set when the final full-file ed2k hash passed; implies every part is
    /// verified even when `part_hashes` is empty (single-part files).
    /// Saved in `.part.met` only transiently — completion normally deletes
    /// the `.met` via `delete_met()` before the next process start.
    file_hash_verified: bool,
}

impl PartTracker {
    pub fn new(file_size: u64, part_file: &Path) -> Self {
        let part_count = if file_size == 0 {
            0
        } else {
            ((file_size + PARTSIZE - 1) / PARTSIZE) as usize
        };

        let met_path = part_file.with_extension("part.met");

        let mut tracker = PartTracker {
            file_size,
            part_count,
            gaps: if file_size > 0 {
                vec![(0, file_size)]
            } else {
                Vec::new()
            },
            in_progress: vec![false; part_count],
            met_path,
            file_hash: [0u8; 16],
            file_name: String::new(),
            part_hashes: Vec::new(),
            part_verified: vec![false; part_count],
            file_hash_verified: false,
        };

        tracker.load();
        tracker
    }

    /// Create a fresh tracker that ignores any existing `.part.met` on disk.
    /// Used when the `.part` data file is missing but a stale `.part.met` exists.
    pub fn new_empty(file_size: u64, part_file: &Path) -> Self {
        let part_count = if file_size == 0 {
            0
        } else {
            ((file_size + PARTSIZE - 1) / PARTSIZE) as usize
        };
        let met_path = part_file.with_extension("part.met");
        PartTracker {
            file_size,
            part_count,
            gaps: if file_size > 0 {
                vec![(0, file_size)]
            } else {
                Vec::new()
            },
            in_progress: vec![false; part_count],
            met_path,
            file_hash: [0u8; 16],
            file_name: String::new(),
            part_hashes: Vec::new(),
            part_verified: vec![false; part_count],
            file_hash_verified: false,
        }
    }

    pub fn set_file_hash(&mut self, hash: [u8; 16]) {
        self.file_hash = hash;
    }

    pub fn set_file_name(&mut self, name: &str) {
        self.file_name = name.to_string();
    }

    pub fn set_part_hashes(&mut self, hashes: Vec<[u8; 16]>) {
        self.part_hashes = hashes;
    }

    pub fn part_hashes(&self) -> &[[u8; 16]] {
        &self.part_hashes
    }

    /// Check if a part (9.28 MB chunk) is fully downloaded.
    pub fn is_part_complete(&self, part_idx: usize) -> bool {
        let (start, end) = self.part_range(part_idx);
        !self.gaps.iter().any(|&(gs, ge)| gs < end && ge > start)
    }

    /// Mark an entire part as complete (removes any gaps in the part's range).
    pub fn mark_complete(&mut self, part_idx: usize) {
        let (start, end) = self.part_range(part_idx);
        self.fill_range(start, end);
    }

    /// Mark an entire part as incomplete (adds a gap for the part's full range).
    pub fn mark_incomplete(&mut self, part_idx: usize) {
        let (start, end) = self.part_range(part_idx);
        self.add_gap(start, end);
        if part_idx < self.part_verified.len() {
            self.part_verified[part_idx] = false;
        }
    }

    /// Part has been fully received AND its MD4 hash was verified against
    /// the authoritative hashset (or for a single-part file, the whole-file
    /// ed2k hash passed — see `mark_file_hash_verified`). Callers that
    /// serve bytes to peers MUST gate on this, not on `is_part_complete`,
    /// to avoid re-uploading unverified (potentially corrupt) chunks.
    pub fn is_part_verified(&self, part_idx: usize) -> bool {
        part_idx < self.part_verified.len() && self.part_verified[part_idx]
    }

    /// Flip `part_verified[idx]` to `true`. Call this ONLY after the part's
    /// MD4 matched `part_hashes[idx]` (or after the whole-file hash passed,
    /// in which case `mark_file_hash_verified` is preferred for clarity).
    pub fn set_part_verified(&mut self, part_idx: usize) {
        if part_idx < self.part_verified.len() {
            self.part_verified[part_idx] = true;
        }
    }

    /// Return true iff every part overlapping `[start, end)` is both
    /// complete and verified — the gate the upload path uses before
    /// serving bytes back to peers.
    pub fn is_range_safe_to_serve(&self, start: u64, end: u64) -> bool {
        if start >= end || end > self.file_size || self.part_count == 0 {
            return false;
        }
        let first = (start / PARTSIZE) as usize;
        let last = ((end - 1) / PARTSIZE) as usize;
        for p in first..=last.min(self.part_count - 1) {
            if !self.is_part_complete(p) || !self.is_part_verified(p) {
                return false;
            }
        }
        true
    }

    /// Per-part verified bitmap (diagnostics / tests).
    #[allow(dead_code)]
    pub fn verified_parts(&self) -> Vec<bool> {
        self.part_verified.clone()
    }

    /// Cheap, in-memory mirror of [`super::preview::can_preview`] computed
    /// from live tracker state (no `.part.met` re-read). Lets the download
    /// worker publish preview-readiness onto the transfer control so the UI can
    /// grey out the Preview action until a preview would actually succeed.
    pub fn is_preview_ready(&self, file_name: &str, file_size: u64) -> bool {
        super::preview::can_preview(
            file_name,
            file_size,
            self.completed_bytes(),
            !self.part_hashes.is_empty(),
            &self.part_verified,
            PARTSIZE,
        )
    }

    /// Mark every part as verified because the whole-file ed2k hash matched.
    /// Used for < PARTSIZE single-part files (no hashset) and as a
    /// belt-and-braces check after final file verification on any file.
    pub fn mark_file_hash_verified(&mut self) {
        self.file_hash_verified = true;
        for flag in self.part_verified.iter_mut() {
            *flag = true;
        }
    }

    #[allow(dead_code)]
    pub fn file_hash_verified(&self) -> bool {
        self.file_hash_verified
    }

    /// Mark a byte range as not received (e.g. AICH-identified bad 180 KiB blocks inside a part).
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        self.add_gap(start, end);
        if start < end && end <= self.file_size && !self.part_verified.is_empty() {
            let first = (start / PARTSIZE) as usize;
            let last = ((end - 1) / PARTSIZE) as usize;
            for p in first..=last.min(self.part_count.saturating_sub(1)) {
                self.part_verified[p] = false;
            }
        }
    }

    /// How many bytes of `[start, end)` are still missing (overlap the gap
    /// list). Read-only mirror of the overlap math in `fill_range`. A return
    /// of 0 means every byte in the range is already on disk — writing it
    /// again would risk clobbering data in a part that another source may have
    /// already MD4-verified, so callers should skip the disk write.
    /// Return the sub-ranges of `[start, end)` that currently overlap gaps
    /// (i.e. bytes we do NOT yet have). Callers write only these sub-ranges
    /// from a received block so that bytes already present on disk —
    /// including bytes belonging to an adjacent part that is already
    /// complete and MD4-verified — are never clobbered by a later
    /// (possibly malicious) block that overlaps both a gap and good data.
    /// The trailing `fill_range(start, end)` is still idempotent over the
    /// non-gap portions, so gap accounting is unchanged.
    pub fn fillable_subranges(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        if start >= end {
            return Vec::new();
        }
        let mut out = Vec::new();
        for &(gs, ge) in &self.gaps {
            if ge <= start || gs >= end {
                continue;
            }
            let s = gs.max(start);
            let e = ge.min(end);
            if s < e {
                out.push((s, e));
            }
        }
        out
    }

    /// Record that bytes in [start, end) have been received.
    /// Returns the number of bytes that were actually newly filled (excluding
    /// overlap with already-filled regions).
    pub fn fill_range(&mut self, start: u64, end: u64) -> u64 {
        if start >= end {
            return 0;
        }
        let mut newly_filled: u64 = 0;
        let mut new_gaps = Vec::with_capacity(self.gaps.len());
        for &(gs, ge) in &self.gaps {
            if ge <= start || gs >= end {
                new_gaps.push((gs, ge));
            } else {
                let overlap_start = gs.max(start);
                let overlap_end = ge.min(end);
                newly_filled += overlap_end - overlap_start;
                if gs < start {
                    new_gaps.push((gs, start));
                }
                if ge > end {
                    new_gaps.push((end, ge));
                }
            }
        }
        self.gaps = new_gaps;
        // Bound gap-list fragmentation (defense-in-depth against hostile
        // peers that split the gap list with tiny fills). If we exceed
        // MAX_GAP_ENTRIES, find the smallest filled-between-two-gaps run
        // and re-invalidate it to merge its neighbours. Repeat until back
        // under the cap. The coalesced bytes will be re-requested and any
        // affected parts lose their `verified` flag, which is correct.
        while self.gaps.len() > MAX_GAP_ENTRIES {
            let Some(merge_idx) = self.find_smallest_coalesce_candidate() else {
                break;
            };
            let filled_start = self.gaps[merge_idx].1;
            let filled_end = self.gaps[merge_idx + 1].0;
            if filled_start >= filled_end {
                break;
            }
            self.invalidate_range(filled_start, filled_end);
        }
        newly_filled
    }

    /// Find the index `i` such that the filled span between `gaps[i]` and
    /// `gaps[i + 1]` is the smallest — re-invalidating that span merges
    /// two gaps into one with the smallest possible re-download cost.
    /// Returns `None` if there are fewer than two gaps (nothing to merge).
    fn find_smallest_coalesce_candidate(&self) -> Option<usize> {
        if self.gaps.len() < 2 {
            return None;
        }
        let mut best: Option<(usize, u64)> = None;
        for i in 0..self.gaps.len() - 1 {
            let gap_between = self.gaps[i + 1].0.saturating_sub(self.gaps[i].1);
            match best {
                None => best = Some((i, gap_between)),
                Some((_, cur)) if gap_between < cur => best = Some((i, gap_between)),
                _ => {}
            }
        }
        best.map(|(i, _)| i)
    }

    /// Add a gap (mark bytes in [start, end) as missing). Merges with adjacent gaps.
    fn add_gap(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut merged_start = start;
        let mut merged_end = end;
        let mut new_gaps = Vec::with_capacity(self.gaps.len() + 1);
        for &(gs, ge) in &self.gaps {
            if ge < merged_start || gs > merged_end {
                new_gaps.push((gs, ge));
            } else {
                merged_start = merged_start.min(gs);
                merged_end = merged_end.max(ge);
            }
        }
        new_gaps.push((merged_start, merged_end));
        new_gaps.sort_by_key(|&(s, _)| s);
        self.gaps = new_gaps;
    }

    pub fn all_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub fn completed_count(&self) -> usize {
        (0..self.part_count)
            .filter(|&i| self.is_part_complete(i))
            .count()
    }

    pub fn needed_parts(&self, available: &[bool]) -> Vec<usize> {
        (0..self.part_count)
            .filter(|&i| {
                !self.is_part_complete(i)
                    && (available.is_empty() || available.get(i).copied().unwrap_or(false))
            })
            .collect()
    }

    pub fn part_range(&self, part_idx: usize) -> (u64, u64) {
        let start = part_idx as u64 * PARTSIZE;
        let end = ((part_idx as u64 + 1) * PARTSIZE).min(self.file_size);
        (start, end)
    }

    /// Return byte ranges that are fully downloaded (inverse of gap list).
    pub fn filled_ranges(&self) -> Vec<(u64, u64)> {
        let mut filled = Vec::new();
        let mut pos: u64 = 0;
        for &(gs, ge) in &self.gaps {
            if gs > pos {
                filled.push((pos, gs));
            }
            pos = ge;
        }
        if pos < self.file_size {
            filled.push((pos, self.file_size));
        }
        filled
    }

    /// Total completed bytes.
    pub fn completed_bytes(&self) -> u64 {
        let gap_bytes: u64 = self.gaps.iter().map(|(s, e)| e - s).sum();
        self.file_size.saturating_sub(gap_bytes)
    }

    /// Return a boolean bitmap of completed parts (for OP_FILESTATUS compatibility).
    pub fn completed_parts(&self) -> Vec<bool> {
        (0..self.part_count)
            .map(|i| self.is_part_complete(i))
            .collect()
    }

    /// Parts that are BOTH gap-complete AND MD4-verified — i.e. the parts we
    /// are actually willing to serve. Any availability bitmap advertised to a
    /// peer must use this (not `completed_parts`), otherwise we advertise parts
    /// the serve gate (`is_range_safe_to_serve`) will then refuse, freezing the
    /// peer's download on a "dead" part it keeps re-requesting.
    pub fn serveable_parts(&self) -> Vec<bool> {
        (0..self.part_count)
            .map(|i| self.is_part_complete(i) && self.is_part_verified(i))
            .collect()
    }

    /// Return the raw gap list.
    pub fn gap_list(&self) -> &[(u64, u64)] {
        &self.gaps
    }

    /// Return a vector of remaining (gap) bytes per part, for use in
    /// nearest-to-completion part selection.
    pub fn part_gap_bytes_vec(&self) -> Vec<u64> {
        let mut result = vec![0u64; self.part_count];
        for &(gs, ge) in &self.gaps {
            let first_part = (gs / PARTSIZE) as usize;
            let last_part = (ge.saturating_sub(1) / PARTSIZE) as usize;
            for p in first_part..=last_part.min(self.part_count.saturating_sub(1)) {
                let (ps, pe) = self.part_range(p);
                let overlap_start = gs.max(ps);
                let overlap_end = ge.min(pe);
                if overlap_start < overlap_end {
                    result[p] += overlap_end - overlap_start;
                }
            }
        }
        result
    }

    pub fn save(&self) {
        tracing::trace!("Saving part tracker: {} gaps", self.gap_list().len());
        if let Err(e) = self.save_emule_format() {
            tracing::warn!("Failed to save part.met: {e}");
        }
    }

    /// Snapshot the small persistent state needed to write `.part.met`.
    /// Cheap clone of three short vectors; the produced `SaveSnapshot` is
    /// `Send` and can be passed to `tokio::task::spawn_blocking` so the
    /// caller can drop any `RwLock` guard *before* fsync — fixing the
    /// stall where reader/writer tasks blocked on the tracker lock during
    /// the periodic `.part.met` save.
    ///
    /// File-format byte-for-byte identical to `save_emule_format` so eMule
    /// resume metadata interop is preserved.
    pub fn snapshot_for_save(&self) -> SaveSnapshot {
        SaveSnapshot {
            met_path: self.met_path.clone(),
            file_size: self.file_size,
            file_hash: self.file_hash,
            file_name: self.file_name.clone(),
            part_hashes: self.part_hashes.clone(),
            gaps: self.gaps.clone(),
            part_verified: self.part_verified.clone(),
        }
    }

    /// Save in eMule-compatible .part.met format.
    fn save_emule_format(&self) -> anyhow::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(512);
        {
            let mut cur = std::io::Cursor::new(&mut buf);

            let use_large = self.file_size > 0xFFFF_FFFF;
            let version = if use_large {
                PARTFILE_VERSION_LARGEFILE
            } else {
                PARTFILE_VERSION
            };
            cur.write_u8(version)?;

            let date = chrono::Utc::now().timestamp().min(u32::MAX as i64) as u32;
            cur.write_u32::<LittleEndian>(date)?;

            cur.write_all(&self.file_hash)?;
            let part_hash_count = self.part_hashes.len();
            if part_hash_count > u16::MAX as usize {
                tracing::warn!(
                    "part.met: {} part hashes exceeds u16 limit, clamping to {}",
                    part_hash_count,
                    u16::MAX
                );
            }
            cur.write_u16::<LittleEndian>(part_hash_count.min(u16::MAX as usize) as u16)?;
            for ph in &self.part_hashes {
                cur.write_all(ph)?;
            }

            let tag_count_pos = 5 + 16 + 2 + self.part_hashes.len() * 16;
            cur.write_u32::<LittleEndian>(0)?;

            let mut tag_count: u32 = 0;

            if !self.file_name.is_empty() {
                write_string_tag(&mut cur, FT_FILENAME, &self.file_name)?;
                tag_count += 1;
            }

            if use_large {
                write_uint64_tag(&mut cur, FT_FILESIZE, self.file_size)?;
            } else {
                write_uint32_tag(&mut cur, FT_FILESIZE, self.file_size as u32)?;
            }
            tag_count += 1;

            let transferred = self.completed_bytes();
            if use_large {
                write_uint64_tag(&mut cur, FT_TRANSFERRED, transferred)?;
            } else {
                write_uint32_tag(&mut cur, FT_TRANSFERRED, transferred as u32)?;
            }
            tag_count += 1;

            // Gap list: eMule uses inclusive end (last missing byte), our gaps
            // use exclusive end (byte past last missing), so subtract 1 for wire format.
            for (i, &(gap_start, gap_end)) in self.gaps.iter().enumerate() {
                write_gap_tag(&mut cur, FT_GAPSTART, i, gap_start, use_large)?;
                write_gap_tag(&mut cur, FT_GAPEND, i, gap_end.saturating_sub(1), use_large)?;
                tag_count += 2;
            }

            // Ember-private: per-part verified bitmap. eMule-family clients
            // skip unknown tag IDs, so this extends the format without
            // breaking interop. Omitted when nothing is verified yet — saves
            // a tag on fresh downloads.
            if self.part_verified.iter().any(|&v| v) {
                let byte_count = (self.part_verified.len() + 7) / 8;
                let mut bitmap = vec![0u8; byte_count];
                for (i, &v) in self.part_verified.iter().enumerate() {
                    if v {
                        bitmap[i / 8] |= 1u8 << (i % 8);
                    }
                }
                write_blob_tag(&mut cur, FT_EMBER_VERIFIED_BITMAP, &bitmap)?;
                tag_count += 1;
            }

            cur.seek(SeekFrom::Start(tag_count_pos as u64))?;
            cur.write_u32::<LittleEndian>(tag_count)?;
        }

        crate::security::atomic_write(&self.met_path, &buf, false)?;
        Ok(())
    }

    fn load(&mut self) {
        if let Err(e) = self.load_inner() {
            if self.met_path.exists() {
                tracing::warn!(
                    "Failed to load part.met ({}), resetting progress: {e}",
                    self.met_path.display()
                );
            }
            self.gaps = if self.file_size > 0 {
                vec![(0, self.file_size)]
            } else {
                Vec::new()
            };
        }
        self.in_progress = vec![false; self.part_count];
    }

    fn load_inner(&mut self) -> anyhow::Result<()> {
        let data = std::fs::read(&self.met_path)?;
        if data.len() < 4 {
            anyhow::bail!("part.met too small");
        }

        let version = data[0];
        if version == PARTFILE_VERSION || version == PARTFILE_VERSION_LARGEFILE || version == 0xE1 {
            return self.load_emule_format(&data, version);
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic == OLD_PART_MET_MAGIC {
            return self.load_legacy(&data);
        }

        anyhow::bail!("unknown part.met format: 0x{:02X}", data[0]);
    }

    /// Load old "PMET" bitmap format and migrate.
    fn load_legacy(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let mut cursor = Cursor::new(data);
        cursor.set_position(4); // skip magic

        let stored_size = cursor.read_u64::<LittleEndian>()?;
        if stored_size != self.file_size {
            anyhow::bail!("file size mismatch in legacy part.met");
        }

        let stored_count = cursor.read_u32::<LittleEndian>()? as usize;
        if stored_count != self.part_count {
            anyhow::bail!("part count mismatch in legacy part.met");
        }

        let bitmap_bytes = (self.part_count + 7) / 8;
        let pos = cursor.position() as usize;
        if pos + bitmap_bytes > data.len() {
            anyhow::bail!("truncated bitmap in legacy part.met");
        }

        // Start with all gaps, then fill completed parts
        self.gaps = vec![(0, self.file_size)];
        for i in 0..self.part_count {
            if (data[pos + i / 8] >> (i % 8)) & 1 != 0 {
                let (start, end) = self.part_range(i);
                self.fill_range(start, end);
            }
        }

        tracing::info!(
            "Migrated legacy part.met ({} parts, {} completed), will save in eMule format",
            self.part_count,
            self.completed_count()
        );

        if let Err(e) = self.save_emule_format() {
            tracing::warn!("Failed to migrate part.met to eMule format: {e}");
        }

        Ok(())
    }

    /// Load eMule-format .part.met: version + date + hash + tags (with gap list).
    fn load_emule_format(&mut self, data: &[u8], version: u8) -> anyhow::Result<()> {
        let mut cursor = Cursor::new(data);
        cursor.set_position(1); // skip version byte

        let _date = cursor.read_u32::<LittleEndian>()?;

        let mut hash = [0u8; 16];
        cursor.read_exact(&mut hash)?;
        if self.file_hash == [0u8; 16] {
            self.file_hash = hash;
        }

        let part_hash_count = cursor.read_u16::<LittleEndian>()? as usize;
        if cursor.position() as usize + part_hash_count * 16 > data.len() {
            anyhow::bail!("truncated part hashes in part.met");
        }
        self.part_hashes = Vec::with_capacity(part_hash_count);
        for _ in 0..part_hash_count {
            let mut ph = [0u8; 16];
            cursor.read_exact(&mut ph)?;
            self.part_hashes.push(ph);
        }

        let raw_tag_count = cursor.read_u32::<LittleEndian>()?;
        const MAX_TAG_COUNT: u32 = 100_000;
        if raw_tag_count > MAX_TAG_COUNT {
            tracing::warn!(
                "part.met tag_count {} exceeds safety limit {}, clamping",
                raw_tag_count,
                MAX_TAG_COUNT
            );
        }
        let tag_count = raw_tag_count.min(MAX_TAG_COUNT);

        let use_large = version == PARTFILE_VERSION_LARGEFILE;
        let mut gap_starts: std::collections::HashMap<usize, u64> =
            std::collections::HashMap::new();
        let mut gap_ends: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
        let mut file_size_from_tags: Option<u64> = None;
        let mut verified_bitmap_bytes: Option<Vec<u8>> = None;
        let mut tags_parsed: u32 = 0;

        for _ in 0..tag_count {
            if cursor.position() as usize >= data.len() {
                break;
            }
            match read_emule_tag(&mut cursor, use_large) {
                Ok(tag) => {
                    tags_parsed += 1;
                    match tag {
                        MetTag::FileSize(s) => {
                            file_size_from_tags = Some(s);
                        }
                        MetTag::FileName(n) => {
                            self.file_name = n;
                        }
                        MetTag::GapStart(idx, val) => {
                            if let Some(prev) = gap_starts.insert(idx, val) {
                                tracing::warn!("part.met: duplicate gap start index {idx} (was {prev}, now {val})");
                            }
                        }
                        MetTag::GapEnd(idx, val) => {
                            if let Some(prev) = gap_ends.insert(idx, val) {
                                tracing::warn!("part.met: duplicate gap end index {idx} (was {prev}, now {val})");
                            }
                        }
                        MetTag::VerifiedBitmap(bytes) => {
                            verified_bitmap_bytes = Some(bytes);
                        }
                        MetTag::Unknown => {}
                    }
                }
                Err(e) => {
                    tracing::warn!("Error reading tag in part.met: {e}");
                    break;
                }
            }
        }

        if let Some(s) = file_size_from_tags {
            if s != self.file_size && self.file_size > 0 {
                tracing::warn!(
                    "File size mismatch: part.met says {} but expected {} — ignoring stored gaps",
                    s,
                    self.file_size
                );
                self.gaps = vec![(0, self.file_size)];
                return Ok(());
            }
        }

        // If the tag loop broke early (parse error / unknown type), the gap
        // picture may be incomplete.  With zero gap tags we'd falsely show a
        // fully-complete file; with a partial set we'd show *more* complete
        // than reality.  In either case, reset to "all incomplete".
        if tags_parsed < tag_count && self.file_size > 0 {
            tracing::warn!(
                "part.met parse truncated ({tags_parsed}/{tag_count} tags, {} gap starts found), \
                 assuming file is incomplete",
                gap_starts.len(),
            );
            self.gaps = vec![(0, self.file_size)];
            return Ok(());
        }

        // If all tags parsed but zero gap tags were found, the .part.met is
        // either for a genuinely complete file or is missing gap data.  Since
        // .part.met files only exist for incomplete downloads, treat this as
        // fully incomplete to be safe — the final hash will verify completeness.
        if gap_starts.is_empty() && self.file_size > 0 {
            tracing::warn!(
                "part.met has {} tags but no gap entries — assuming file is incomplete",
                tag_count,
            );
            self.gaps = vec![(0, self.file_size)];
            return Ok(());
        }

        // Build byte-level gap list from paired start/end tags
        self.gaps = Vec::new();
        for (&idx, &start) in &gap_starts {
            // eMule writes inclusive end; convert to our exclusive end by adding 1
            let inclusive_end = gap_ends.get(&idx).copied().unwrap_or_else(|| {
                tracing::warn!(
                    "Orphaned gap start at index {idx} (offset {start}), extending to file_size"
                );
                self.file_size.saturating_sub(1)
            });
            let end = inclusive_end.saturating_add(1).min(self.file_size);
            if start < end && end <= self.file_size {
                self.gaps.push((start, end));
            }
        }
        self.gaps.sort_by_key(|&(s, _)| s);

        // Merge overlapping gaps
        let mut merged = Vec::new();
        for &(s, e) in &self.gaps {
            if let Some(last) = merged.last_mut() {
                let (_, ref mut le): &mut (u64, u64) = last;
                if s <= *le {
                    *le = (*le).max(e);
                    continue;
                }
            }
            merged.push((s, e));
        }
        self.gaps = merged;

        // Restore Ember-private per-part verified bitmap. Any bit that
        // refers to a part that is currently incomplete is dropped — a part
        // can only be "verified" if it's also fully present. This prevents a
        // stale bitmap (e.g. .part hand-edited, .part.met survived a partial
        // rewrite) from letting us serve unverified bytes to uploads.
        if let Some(bytes) = verified_bitmap_bytes {
            self.part_verified = vec![false; self.part_count];
            for i in 0..self.part_count {
                let byte = bytes.get(i / 8).copied().unwrap_or(0);
                if byte & (1u8 << (i % 8)) != 0 && self.is_part_complete(i) {
                    self.part_verified[i] = true;
                }
            }
        }

        tracing::info!(
            "Loaded eMule part.met: {} parts, {} completed, {} verified, {} gaps ({} bytes remaining)",
            self.part_count,
            self.completed_count(),
            self.part_verified.iter().filter(|v| **v).count(),
            self.gaps.len(),
            self.file_size.saturating_sub(self.completed_bytes()),
        );

        Ok(())
    }

    pub fn remaining_count(&self) -> usize {
        self.part_count.saturating_sub(self.completed_count())
    }

    /// Sum of gap lengths: bytes still missing (same as `file_size - completed_bytes()` when consistent).
    pub fn remaining_gap_bytes(&self) -> u64 {
        self.gaps.iter().map(|&(s, e)| e.saturating_sub(s)).sum()
    }

    pub fn set_in_progress(&mut self, part_idx: usize, value: bool) {
        if part_idx < self.part_count {
            self.in_progress[part_idx] = value;
        }
    }

    pub fn delete_met(&self) {
        let _ = std::fs::remove_file(&self.met_path);
    }
}

/// Lock-free, owned snapshot of everything needed to rewrite `.part.met`.
/// Produced by `PartTracker::snapshot_for_save()` while holding the
/// tracker's lock; the actual disk write happens on a blocking thread
/// AFTER the lock is dropped.
pub struct SaveSnapshot {
    met_path: PathBuf,
    file_size: u64,
    file_hash: [u8; 16],
    file_name: String,
    part_hashes: Vec<[u8; 16]>,
    gaps: Vec<(u64, u64)>,
    part_verified: Vec<bool>,
}

impl SaveSnapshot {
    /// Synchronous fsync-anchored write. Call from `spawn_blocking`.
    /// Output bytes are byte-identical to `PartTracker::save_emule_format`
    /// so eMule clients can read our `.part.met` on resume.
    pub fn write_to_disk(&self) -> anyhow::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(512);
        {
            let mut cur = std::io::Cursor::new(&mut buf);

            let use_large = self.file_size > 0xFFFF_FFFF;
            let version = if use_large {
                PARTFILE_VERSION_LARGEFILE
            } else {
                PARTFILE_VERSION
            };
            cur.write_u8(version)?;

            let date = chrono::Utc::now().timestamp().min(u32::MAX as i64) as u32;
            cur.write_u32::<LittleEndian>(date)?;

            cur.write_all(&self.file_hash)?;
            let part_hash_count = self.part_hashes.len();
            if part_hash_count > u16::MAX as usize {
                tracing::warn!(
                    "part.met: {} part hashes exceeds u16 limit, clamping to {}",
                    part_hash_count,
                    u16::MAX
                );
            }
            cur.write_u16::<LittleEndian>(part_hash_count.min(u16::MAX as usize) as u16)?;
            for ph in &self.part_hashes {
                cur.write_all(ph)?;
            }

            let tag_count_pos = 5 + 16 + 2 + self.part_hashes.len() * 16;
            cur.write_u32::<LittleEndian>(0)?;

            let mut tag_count: u32 = 0;

            if !self.file_name.is_empty() {
                write_string_tag(&mut cur, FT_FILENAME, &self.file_name)?;
                tag_count += 1;
            }

            if use_large {
                write_uint64_tag(&mut cur, FT_FILESIZE, self.file_size)?;
            } else {
                write_uint32_tag(&mut cur, FT_FILESIZE, self.file_size as u32)?;
            }
            tag_count += 1;

            // Mirror PartTracker::completed_bytes() inline to keep this
            // snapshot self-contained.
            let gap_bytes: u64 = self.gaps.iter().map(|(s, e)| e - s).sum();
            let transferred = self.file_size.saturating_sub(gap_bytes);
            if use_large {
                write_uint64_tag(&mut cur, FT_TRANSFERRED, transferred)?;
            } else {
                write_uint32_tag(&mut cur, FT_TRANSFERRED, transferred as u32)?;
            }
            tag_count += 1;

            for (i, &(gap_start, gap_end)) in self.gaps.iter().enumerate() {
                write_gap_tag(&mut cur, FT_GAPSTART, i, gap_start, use_large)?;
                write_gap_tag(&mut cur, FT_GAPEND, i, gap_end.saturating_sub(1), use_large)?;
                tag_count += 2;
            }

            if self.part_verified.iter().any(|&v| v) {
                let byte_count = (self.part_verified.len() + 7) / 8;
                let mut bitmap = vec![0u8; byte_count];
                for (i, &v) in self.part_verified.iter().enumerate() {
                    if v {
                        bitmap[i / 8] |= 1u8 << (i % 8);
                    }
                }
                write_blob_tag(&mut cur, FT_EMBER_VERIFIED_BITMAP, &bitmap)?;
                tag_count += 1;
            }

            cur.seek(SeekFrom::Start(tag_count_pos as u64))?;
            cur.write_u32::<LittleEndian>(tag_count)?;
        }

        crate::security::atomic_write(&self.met_path, &buf, false)?;
        Ok(())
    }
}

/// Convenience: take a snapshot and persist it on a blocking task. The
/// caller MUST drop any tracker lock guard before awaiting this.
pub async fn save_snapshot_async(snap: SaveSnapshot) {
    if let Err(join_err) = tokio::task::spawn_blocking(move || {
        if let Err(e) = snap.write_to_disk() {
            tracing::warn!("Failed to save part.met (async): {e}");
        }
    })
    .await
    {
        tracing::warn!("part.met save task panicked: {join_err}");
    }
}

// --- eMule tag reading/writing helpers ---

enum MetTag {
    FileSize(u64),
    FileName(String),
    GapStart(usize, u64),
    GapEnd(usize, u64),
    /// Ember-private per-part verified bitmap (LSB-first per byte).
    VerifiedBitmap(Vec<u8>),
    Unknown,
}

fn read_emule_tag(cursor: &mut Cursor<&[u8]>, _use_large: bool) -> anyhow::Result<MetTag> {
    let raw_type = cursor.read_u8()?;

    // eMule new-style tags: bit 7 set means compact format (single-byte name, no length prefix)
    let (tag_type, name_buf) = if raw_type & 0x80 != 0 {
        let actual_type = raw_type & 0x7F;
        let name_id = cursor.read_u8()?;
        (actual_type, vec![name_id])
    } else {
        let name_len = cursor.read_u16::<LittleEndian>()? as usize;
        if name_len > 4096 {
            anyhow::bail!("part.met tag name too long: {name_len}");
        }
        let mut buf = vec![0u8; name_len];
        cursor.read_exact(&mut buf)?;
        (raw_type, buf)
    };
    let name_len = name_buf.len();

    let value: u64 = match tag_type {
        TAGTYPE_UINT32 => cursor.read_u32::<LittleEndian>()? as u64,
        TAGTYPE_UINT64 => cursor.read_u64::<LittleEndian>()?,
        0x09 => cursor.read_u8()? as u64,
        TAGTYPE_STRING => {
            let slen = cursor.read_u16::<LittleEndian>()? as usize;
            let mut sbuf = vec![0u8; slen];
            cursor.read_exact(&mut sbuf)?;
            let s = String::from_utf8_lossy(&sbuf).to_string();

            if name_len == 1 {
                match name_buf[0] {
                    FT_FILENAME => return Ok(MetTag::FileName(s)),
                    _ => return Ok(MetTag::Unknown),
                }
            }
            return Ok(MetTag::Unknown);
        }
        0x01 => {
            let mut hash = [0u8; 16];
            cursor.read_exact(&mut hash)?;
            return Ok(MetTag::Unknown);
        }
        0x07 => {
            let blen = cursor.read_u32::<LittleEndian>()? as u64;
            let start_pos = cursor.position();
            let new_pos = start_pos
                .checked_add(blen)
                .filter(|&p| p <= cursor.get_ref().len() as u64)
                .ok_or_else(|| anyhow::anyhow!("blob tag length exceeds data boundary"))?;
            // Recognize the Ember-private verified-bitmap blob tag here so
            // we can restore the verified set on resume. Cap the read size
            // to 1 MiB (enough for 8 million parts — far beyond any real file).
            if name_len == 1 && name_buf[0] == FT_EMBER_VERIFIED_BITMAP && blen <= 1_000_000 {
                let mut buf = vec![0u8; blen as usize];
                cursor.read_exact(&mut buf)?;
                return Ok(MetTag::VerifiedBitmap(buf));
            }
            cursor.set_position(new_pos);
            return Ok(MetTag::Unknown);
        }
        0x04 => {
            let _ = cursor.read_u32::<LittleEndian>()?;
            return Ok(MetTag::Unknown);
        }
        0x05 => cursor.read_u8()? as u64,
        0x06 => {
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let byte_count = (count + 7) / 8;
            let new_pos = cursor.position() + byte_count as u64;
            if new_pos > cursor.get_ref().len() as u64 {
                anyhow::bail!("BitSet tag overflows buffer");
            }
            cursor.set_position(new_pos);
            return Ok(MetTag::Unknown);
        }
        0x08 => cursor.read_u16::<LittleEndian>()? as u64,
        0x0A => {
            let blen = cursor.read_u8()? as u64;
            let new_pos = cursor.position() + blen;
            if new_pos > cursor.get_ref().len() as u64 {
                anyhow::bail!("BSOB tag overflows buffer");
            }
            cursor.set_position(new_pos);
            return Ok(MetTag::Unknown);
        }
        _ => {
            anyhow::bail!(
                "Unknown part.met tag type 0x{tag_type:02X}, cannot determine value size"
            );
        }
    };

    if name_len == 1 {
        match name_buf[0] {
            FT_FILESIZE => return Ok(MetTag::FileSize(value)),
            FT_STATUS | FT_TRANSFERRED => return Ok(MetTag::Unknown),
            _ => {}
        }
    }

    if name_len >= 2 {
        let tag_id = name_buf[0];
        if tag_id == FT_GAPSTART || tag_id == FT_GAPEND {
            let idx_str = String::from_utf8_lossy(&name_buf[1..]);
            if let Ok(idx) = idx_str.parse::<usize>() {
                if tag_id == FT_GAPSTART {
                    return Ok(MetTag::GapStart(idx, value));
                } else {
                    return Ok(MetTag::GapEnd(idx, value));
                }
            }
        }
    }

    Ok(MetTag::Unknown)
}

fn write_uint32_tag(w: &mut impl Write, tag_id: u8, value: u32) -> anyhow::Result<()> {
    w.write_u8(TAGTYPE_UINT32)?;
    w.write_u16::<LittleEndian>(1)?;
    w.write_u8(tag_id)?;
    w.write_u32::<LittleEndian>(value)?;
    Ok(())
}

fn write_uint64_tag(w: &mut impl Write, tag_id: u8, value: u64) -> anyhow::Result<()> {
    w.write_u8(TAGTYPE_UINT64)?;
    w.write_u16::<LittleEndian>(1)?;
    w.write_u8(tag_id)?;
    w.write_u64::<LittleEndian>(value)?;
    Ok(())
}

fn write_string_tag(w: &mut impl Write, tag_id: u8, value: &str) -> anyhow::Result<()> {
    w.write_u8(TAGTYPE_STRING)?;
    w.write_u16::<LittleEndian>(1)?;
    w.write_u8(tag_id)?;
    let bytes = value.as_bytes();
    let clamped = &bytes[..bytes.len().min(u16::MAX as usize)];
    w.write_u16::<LittleEndian>(clamped.len() as u16)?;
    w.write_all(clamped)?;
    Ok(())
}

/// eMule TAGTYPE_BLOB: u32 length + bytes (for the Ember-private verified bitmap tag).
fn write_blob_tag(w: &mut impl Write, tag_id: u8, data: &[u8]) -> anyhow::Result<()> {
    w.write_u8(TAGTYPE_BLOB)?;
    w.write_u16::<LittleEndian>(1)?;
    w.write_u8(tag_id)?;
    let len = u32::try_from(data.len())
        .map_err(|_| anyhow::anyhow!("blob tag payload too large ({} bytes)", data.len()))?;
    w.write_u32::<LittleEndian>(len)?;
    w.write_all(data)?;
    Ok(())
}

fn write_gap_tag(
    w: &mut impl Write,
    gap_type: u8,
    index: usize,
    value: u64,
    use_large: bool,
) -> anyhow::Result<()> {
    let idx_str = index.to_string();
    let name_len = 1 + idx_str.len();

    if use_large {
        w.write_u8(TAGTYPE_UINT64)?;
    } else {
        w.write_u8(TAGTYPE_UINT32)?;
    }
    w.write_u16::<LittleEndian>(name_len as u16)?;
    w.write_u8(gap_type)?;
    w.write_all(idx_str.as_bytes())?;

    if use_large {
        w.write_u64::<LittleEndian>(value)?;
    } else {
        // Don't silently truncate the gap offset. If the caller asked for the
        // 32-bit format but the value doesn't fit, that indicates a caller
        // bug (the file-size threshold for `use_large` was wrong) and
        // writing a truncated value would corrupt the resume metadata.
        let narrow = u32::try_from(value).map_err(|_| {
            anyhow::anyhow!(
                "gap offset {value} exceeds u32 range but use_large=false \
                 — refusing to truncate resume data (gap_type={gap_type}, index={index})"
            )
        })?;
        w.write_u32::<LittleEndian>(narrow)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_part_path(name: &str) -> PathBuf {
        let unique = format!(
            "ember-{}-{}-{name}.part",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }

    #[test]
    fn fill_range_tracks_completed_bytes() {
        let part_path = temp_part_path("fill");
        let mut tracker = PartTracker::new(100, &part_path);
        tracker.fill_range(0, 40);
        tracker.fill_range(60, 100);

        assert_eq!(tracker.completed_bytes(), 80);
        assert_eq!(tracker.gap_list(), &[(40, 60)]);

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    #[test]
    fn save_and_reload_preserves_gap_state() {
        let part_path = temp_part_path("reload");
        let mut tracker = PartTracker::new(100, &part_path);
        tracker.set_file_hash([0x44; 16]);
        tracker.set_file_name("example.bin");
        tracker.set_part_hashes(vec![[0x55; 16]]);
        tracker.fill_range(0, 25);
        tracker.fill_range(75, 100);
        tracker.save();

        let reloaded = PartTracker::new(100, &part_path);
        assert_eq!(reloaded.file_hash, [0x44; 16]);
        assert_eq!(reloaded.file_name, "example.bin");
        assert_eq!(reloaded.part_hashes(), &[[0x55; 16]]);
        assert_eq!(reloaded.gap_list(), &[(25, 75)]);

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    /// `OP_FILESTATUS` advertising must match the serve gate: every
    /// advertised part must pass `is_range_safe_to_serve` for the whole
    /// part. Previously the bitmap used `is_part_complete` alone, so a
    /// part that was fully received but not yet MD4-verified would be
    /// advertised as available, then every peer block request for it
    /// was silently rejected at the serve gate — producing the "upload
    /// appears frozen" UX. This test pins the invariant
    ///   advertise = (is_part_complete && is_part_verified)  => safe to serve
    /// for all the states a part tracker can be in mid-download.
    #[test]
    fn advertised_parts_are_always_safe_to_serve() {
        let part_path = temp_part_path("advertise-gate");
        // Three parts: part 0 = complete+verified, part 1 =
        // complete-but-unverified, part 2 = still has a gap.
        let file_size = PARTSIZE * 3;
        let mut tracker = PartTracker::new(file_size, &part_path);

        // Part 0: fill + mark verified.
        tracker.fill_range(0, PARTSIZE);
        tracker.set_part_verified(0);
        // Part 1: fill but do NOT verify.
        tracker.fill_range(PARTSIZE, 2 * PARTSIZE);
        // Part 2: only partially fill.
        tracker.fill_range(2 * PARTSIZE, 2 * PARTSIZE + 100);

        // Advertise predicate (what OP_FILESTATUS uses post-fix).
        let advertised = |p: usize| tracker.is_part_complete(p) && tracker.is_part_verified(p);
        assert!(advertised(0), "verified+complete part must advertise");
        assert!(
            !advertised(1),
            "complete-but-unverified part must NOT advertise"
        );
        assert!(!advertised(2), "incomplete part must NOT advertise");

        // Serve gate: every advertised part must be safe for its
        // entire byte range. This is what the invariant hinges on.
        for p in 0..3 {
            let (start, end) = tracker.part_range(p);
            if advertised(p) {
                assert!(
                    tracker.is_range_safe_to_serve(start, end),
                    "advertised part {p} must be safe to serve [{start}, {end})"
                );
            }
        }

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }
}
