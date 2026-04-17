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

/// eMule tag types
const TAGTYPE_UINT32: u8 = 0x03;
const TAGTYPE_UINT64: u8 = 0x0B;
const TAGTYPE_STRING: u8 = 0x02;

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
            gaps: if file_size > 0 { vec![(0, file_size)] } else { Vec::new() },
            in_progress: vec![false; part_count],
            met_path,
            file_hash: [0u8; 16],
            file_name: String::new(),
            part_hashes: Vec::new(),
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
            gaps: if file_size > 0 { vec![(0, file_size)] } else { Vec::new() },
            in_progress: vec![false; part_count],
            met_path,
            file_hash: [0u8; 16],
            file_name: String::new(),
            part_hashes: Vec::new(),
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
    }

    /// Mark a byte range as not received (e.g. AICH-identified bad 180 KiB blocks inside a part).
    pub fn invalidate_range(&mut self, start: u64, end: u64) {
        self.add_gap(start, end);
    }

    /// Record that bytes in [start, end) have been received.
    /// Returns the number of bytes that were actually newly filled (excluding
    /// overlap with already-filled regions).
    pub fn fill_range(&mut self, start: u64, end: u64) -> u64 {
        if start >= end { return 0; }
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
        newly_filled
    }

    /// Add a gap (mark bytes in [start, end) as missing). Merges with adjacent gaps.
    fn add_gap(&mut self, start: u64, end: u64) {
        if start >= end { return; }
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
        (0..self.part_count).filter(|&i| self.is_part_complete(i)).count()
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
        (0..self.part_count).map(|i| self.is_part_complete(i)).collect()
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

    /// Save in eMule-compatible .part.met format.
    fn save_emule_format(&self) -> anyhow::Result<()> {
        let mut buf: Vec<u8> = Vec::with_capacity(512);
        {
            let mut cur = std::io::Cursor::new(&mut buf);

            let use_large = self.file_size > 0xFFFF_FFFF;
            let version = if use_large { PARTFILE_VERSION_LARGEFILE } else { PARTFILE_VERSION };
            cur.write_u8(version)?;

            let date = chrono::Utc::now().timestamp().min(u32::MAX as i64) as u32;
            cur.write_u32::<LittleEndian>(date)?;

            cur.write_all(&self.file_hash)?;
            let part_hash_count = self.part_hashes.len();
            if part_hash_count > u16::MAX as usize {
                tracing::warn!(
                    "part.met: {} part hashes exceeds u16 limit, clamping to {}",
                    part_hash_count, u16::MAX
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
            self.gaps = if self.file_size > 0 { vec![(0, self.file_size)] } else { Vec::new() };
        }
        self.in_progress = vec![false; self.part_count];
    }

    fn load_inner(&mut self) -> anyhow::Result<()> {
        let data = std::fs::read(&self.met_path)?;
        if data.len() < 4 {
            anyhow::bail!("part.met too small");
        }

        let version = data[0];
        if version == PARTFILE_VERSION
            || version == PARTFILE_VERSION_LARGEFILE
            || version == 0xE1
        {
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
                raw_tag_count, MAX_TAG_COUNT
            );
        }
        let tag_count = raw_tag_count.min(MAX_TAG_COUNT);

        let use_large = version == PARTFILE_VERSION_LARGEFILE;
        let mut gap_starts: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
        let mut gap_ends: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
        let mut file_size_from_tags: Option<u64> = None;
        let mut tags_parsed: u32 = 0;

        for _ in 0..tag_count {
            if cursor.position() as usize >= data.len() {
                break;
            }
            match read_emule_tag(&mut cursor, use_large) {
                Ok(tag) => {
                    tags_parsed += 1;
                    match tag {
                        MetTag::FileSize(s) => { file_size_from_tags = Some(s); }
                        MetTag::FileName(n) => { self.file_name = n; }
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
                        MetTag::Unknown => {}
                    }
                },
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
                    s, self.file_size
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
                tracing::warn!("Orphaned gap start at index {idx} (offset {start}), extending to file_size");
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

        tracing::info!(
            "Loaded eMule part.met: {} parts, {} completed, {} gaps ({} bytes remaining)",
            self.part_count,
            self.completed_count(),
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
        self.gaps
            .iter()
            .map(|&(s, e)| e.saturating_sub(s))
            .sum()
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

// --- eMule tag reading/writing helpers ---

enum MetTag {
    FileSize(u64),
    FileName(String),
    GapStart(usize, u64),
    GapEnd(usize, u64),
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
            let new_pos = cursor.position().checked_add(blen)
                .filter(|&p| p <= cursor.get_ref().len() as u64)
                .ok_or_else(|| anyhow::anyhow!("blob tag length exceeds data boundary"))?;
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
            anyhow::bail!("Unknown part.met tag type 0x{tag_type:02X}, cannot determine value size");
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
        w.write_u32::<LittleEndian>(value as u32)?;
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
}
