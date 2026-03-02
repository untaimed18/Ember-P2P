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

#[derive(Debug, Clone)]
pub struct PartTracker {
    pub file_size: u64,
    pub part_count: usize,
    completed: Vec<bool>,
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
            completed: vec![false; part_count],
            in_progress: vec![false; part_count],
            met_path,
            file_hash: [0u8; 16],
            file_name: String::new(),
            part_hashes: Vec::new(),
        };

        tracker.load();
        tracker
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

    pub fn is_part_complete(&self, part_idx: usize) -> bool {
        self.completed.get(part_idx).copied().unwrap_or(false)
    }

    pub fn mark_complete(&mut self, part_idx: usize) {
        if part_idx < self.part_count {
            self.completed[part_idx] = true;
        }
    }

    pub fn mark_incomplete(&mut self, part_idx: usize) {
        if part_idx < self.part_count {
            self.completed[part_idx] = false;
        }
    }

    pub fn all_complete(&self) -> bool {
        self.completed.iter().all(|&c| c)
    }

    pub fn completed_count(&self) -> usize {
        self.completed.iter().filter(|&&c| c).count()
    }

    pub fn needed_parts(&self, available: &[bool]) -> Vec<usize> {
        (0..self.part_count)
            .filter(|&i| {
                !self.completed[i]
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
    /// Used for archive recovery which needs to know which bytes are available.
    pub fn filled_ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        let mut range_start: Option<u64> = None;

        for i in 0..self.part_count {
            let (ps, pe) = self.part_range(i);
            if self.completed[i] {
                if range_start.is_none() {
                    range_start = Some(ps);
                }
                if i + 1 >= self.part_count || !self.completed[i + 1] {
                    ranges.push((range_start.unwrap(), pe));
                    range_start = None;
                }
            }
        }

        ranges
    }

    pub fn save(&self) {
        if let Err(e) = self.save_emule_format() {
            tracing::warn!("Failed to save part.met: {e}");
        }
    }

    /// Save in eMule-compatible .part.met format.
    /// Format: version(1) + date(4) + hash(16) + tag_count(4) + tags...
    /// Gaps are stored as FT_GAPSTART/FT_GAPEND tag pairs.
    fn save_emule_format(&self) -> anyhow::Result<()> {
        let tmp_path = self.met_path.with_extension("met.tmp");
        let mut file = std::fs::File::create(&tmp_path)?;

        let use_large = self.file_size > 0xFFFF_FFFF;
        let version = if use_large { PARTFILE_VERSION_LARGEFILE } else { PARTFILE_VERSION };
        file.write_u8(version)?;

        let date = chrono::Utc::now().timestamp() as u32;
        file.write_u32::<LittleEndian>(date)?;

        file.write_all(&self.file_hash)?;
        file.write_u16::<LittleEndian>(self.part_hashes.len() as u16)?;
        for ph in &self.part_hashes {
            file.write_all(ph)?;
        }

        // Tag count placeholder (will seek back to fill)
        let tag_count_pos = 5 + 16 + 2; // version(1) + date(4) + hash(16) + part_hash_count(2)
        file.write_u32::<LittleEndian>(0)?;

        let mut tag_count: u32 = 0;

        // FT_FILENAME
        if !self.file_name.is_empty() {
            write_string_tag(&mut file, FT_FILENAME, &self.file_name)?;
            tag_count += 1;
        }

        // FT_FILESIZE
        if use_large {
            write_uint64_tag(&mut file, FT_FILESIZE, self.file_size)?;
        } else {
            write_uint32_tag(&mut file, FT_FILESIZE, self.file_size as u32)?;
        }
        tag_count += 1;

        // FT_TRANSFERRED
        let transferred = self.completed_bytes();
        if use_large {
            write_uint64_tag(&mut file, FT_TRANSFERRED, transferred)?;
        } else {
            write_uint32_tag(&mut file, FT_TRANSFERRED, transferred as u32)?;
        }
        tag_count += 1;

        // Gap list: convert completed bitmap to gap ranges
        let gaps = self.compute_gaps();
        for (i, (gap_start, gap_end)) in gaps.iter().enumerate() {
            write_gap_tag(&mut file, FT_GAPSTART, i, *gap_start, use_large)?;
            write_gap_tag(&mut file, FT_GAPEND, i, *gap_end, use_large)?;
            tag_count += 2;
        }

        // Seek back and write the actual tag count
        file.seek(SeekFrom::Start(tag_count_pos as u64))?;
        file.write_u32::<LittleEndian>(tag_count)?;

        file.seek(SeekFrom::End(0))?;
        file.flush()?;
        drop(file);
        std::fs::rename(&tmp_path, &self.met_path)?;
        Ok(())
    }

    /// Compute gap ranges (missing byte ranges) from the completed bitmap.
    /// Each gap is (start_offset, end_offset_exclusive) matching eMule's convention.
    fn compute_gaps(&self) -> Vec<(u64, u64)> {
        let mut gaps = Vec::new();
        let mut gap_start: Option<u64> = None;

        for i in 0..self.part_count {
            let (ps, pe) = self.part_range(i);
            if !self.completed[i] {
                if gap_start.is_none() {
                    gap_start = Some(ps);
                }
                // Extend gap to end of this part
                if i + 1 >= self.part_count || self.completed[i + 1] {
                    gaps.push((gap_start.unwrap(), pe));
                    gap_start = None;
                }
            }
        }

        gaps
    }

    /// Total completed bytes (sum of completed part sizes).
    fn completed_bytes(&self) -> u64 {
        (0..self.part_count)
            .filter(|&i| self.completed[i])
            .map(|i| {
                let (s, e) = self.part_range(i);
                e - s
            })
            .sum()
    }

    fn load(&mut self) {
        if let Err(e) = self.load_inner() {
            if self.met_path.exists() {
                tracing::warn!(
                    "Failed to load part.met ({}), resetting progress: {e}",
                    self.met_path.display()
                );
            }
            self.completed = vec![false; self.part_count];
        }
        self.in_progress = vec![false; self.part_count];
    }

    fn load_inner(&mut self) -> anyhow::Result<()> {
        let data = std::fs::read(&self.met_path)?;
        if data.len() < 4 {
            anyhow::bail!("part.met too small");
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        if magic == OLD_PART_MET_MAGIC {
            return self.load_legacy(&data);
        }

        let version = data[0];
        if version == PARTFILE_VERSION
            || version == PARTFILE_VERSION_LARGEFILE
            || version == 0xE1
        {
            return self.load_emule_format(&data, version);
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

        for i in 0..self.part_count {
            self.completed[i] = (data[pos + i / 8] >> (i % 8)) & 1 != 0;
        }

        tracing::info!(
            "Migrated legacy part.met ({} parts, {} completed), will save in eMule format",
            self.part_count,
            self.completed_count()
        );

        // Re-save in eMule format immediately
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

        // Read file hash (16 bytes)
        let mut hash = [0u8; 16];
        cursor.read_exact(&mut hash)?;
        if self.file_hash == [0u8; 16] {
            self.file_hash = hash;
        }

        let part_hash_count = cursor.read_u16::<LittleEndian>()? as usize;
        let skip_bytes = part_hash_count * 16;
        if cursor.position() as usize + skip_bytes > data.len() {
            anyhow::bail!("truncated part hashes in part.met");
        }
        self.part_hashes = Vec::with_capacity(part_hash_count);
        for _ in 0..part_hash_count {
            let mut ph = [0u8; 16];
            cursor.read_exact(&mut ph)?;
            self.part_hashes.push(ph);
        }

        // Tag count
        let tag_count = cursor.read_u32::<LittleEndian>()?;

        let use_large = version == PARTFILE_VERSION_LARGEFILE;
        let mut gaps: Vec<(usize, u64, bool)> = Vec::new(); // (index, value, is_start)
        let mut file_size_from_tags: Option<u64> = None;

        // Start with all parts complete; gaps will mark missing ranges
        self.completed = vec![true; self.part_count];

        for _ in 0..tag_count {
            if cursor.position() as usize >= data.len() {
                break;
            }
            match read_emule_tag(&mut cursor, use_large) {
                Ok(tag) => match tag {
                    MetTag::FileSize(s) => { file_size_from_tags = Some(s); }
                    MetTag::FileName(n) => { self.file_name = n; }
                    MetTag::GapStart(idx, val) => { gaps.push((idx, val, true)); }
                    MetTag::GapEnd(idx, val) => { gaps.push((idx, val, false)); }
                    MetTag::Unknown => {}
                },
                Err(e) => {
                    tracing::warn!("Error reading tag in part.met: {e}");
                    break;
                }
            }
        }

        // Verify file size if we got it from tags
        if let Some(s) = file_size_from_tags {
            if s != self.file_size && self.file_size > 0 {
                tracing::warn!(
                    "File size mismatch: part.met says {} but expected {}",
                    s, self.file_size
                );
            }
        }

        // Build gap map from paired start/end tags
        let mut gap_starts: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
        let mut gap_ends: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
        for (idx, val, is_start) in gaps {
            if is_start {
                gap_starts.insert(idx, val);
            } else {
                gap_ends.insert(idx, val);
            }
        }

        // Apply gaps: mark parts that overlap with any gap as incomplete
        for (&idx, &start) in &gap_starts {
            if let Some(&end) = gap_ends.get(&idx) {
                // end is exclusive (eMule stores gap.end + 1)
                for p in 0..self.part_count {
                    let (ps, pe) = self.part_range(p);
                    // Part overlaps gap if part_start < gap_end && part_end > gap_start
                    if ps < end && pe > start {
                        self.completed[p] = false;
                    }
                }
            }
        }

        tracing::info!(
            "Loaded eMule part.met: {} parts, {} completed, {} gaps",
            self.part_count,
            self.completed_count(),
            gap_starts.len()
        );

        Ok(())
    }

    pub fn remaining_count(&self) -> usize {
        self.part_count - self.completed_count()
    }

    pub fn set_in_progress(&mut self, part_idx: usize, value: bool) {
        if part_idx < self.part_count {
            self.in_progress[part_idx] = value;
        }
    }

    pub fn completed_parts(&self) -> &[bool] {
        &self.completed
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
    let tag_type = cursor.read_u8()?;
    let name_len = cursor.read_u16::<LittleEndian>()? as usize;

    let mut name_buf = vec![0u8; name_len];
    cursor.read_exact(&mut name_buf)?;

    // Read value based on type
    let value: u64 = match tag_type {
        TAGTYPE_UINT32 => cursor.read_u32::<LittleEndian>()? as u64,
        TAGTYPE_UINT64 | 0x09 => cursor.read_u64::<LittleEndian>()?,
        TAGTYPE_STRING => {
            let slen = cursor.read_u16::<LittleEndian>()? as usize;
            let mut sbuf = vec![0u8; slen];
            cursor.read_exact(&mut sbuf)?;
            let s = String::from_utf8_lossy(&sbuf).to_string();

            // Check if this is a known named tag
            if name_len == 1 {
                match name_buf[0] {
                    FT_FILENAME => return Ok(MetTag::FileName(s)),
                    _ => return Ok(MetTag::Unknown),
                }
            }
            return Ok(MetTag::Unknown);
        }
        0x01 => {
            // Hash (16 bytes)
            let mut hash = [0u8; 16];
            cursor.read_exact(&mut hash)?;
            return Ok(MetTag::Unknown);
        }
        0x07 => {
            // Blob
            let blen = cursor.read_u32::<LittleEndian>()? as usize;
            let pos = cursor.position();
            cursor.set_position(pos + blen as u64);
            return Ok(MetTag::Unknown);
        }
        0x04 => cursor.read_u8()? as u64,       // uint8
        0x05 => cursor.read_u16::<LittleEndian>()? as u64, // uint16
        0x06 => {
            // float32
            let _ = cursor.read_u32::<LittleEndian>()?;
            return Ok(MetTag::Unknown);
        }
        _ => {
            anyhow::bail!("unknown tag type 0x{:02X}", tag_type);
        }
    };

    if name_len == 1 {
        match name_buf[0] {
            FT_FILESIZE => return Ok(MetTag::FileSize(value)),
            FT_STATUS | FT_TRANSFERRED => return Ok(MetTag::Unknown),
            _ => {}
        }
    }

    // Gap tags have name format: [FT_GAPSTART|FT_GAPEND][index_as_ascii...]
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
    w.write_u16::<LittleEndian>(1)?; // name length
    w.write_u8(tag_id)?;
    w.write_u32::<LittleEndian>(value)?;
    Ok(())
}

fn write_uint64_tag(w: &mut impl Write, tag_id: u8, value: u64) -> anyhow::Result<()> {
    w.write_u8(TAGTYPE_UINT64)?;
    w.write_u16::<LittleEndian>(1)?; // name length
    w.write_u8(tag_id)?;
    w.write_u64::<LittleEndian>(value)?;
    Ok(())
}

fn write_string_tag(w: &mut impl Write, tag_id: u8, value: &str) -> anyhow::Result<()> {
    w.write_u8(TAGTYPE_STRING)?;
    w.write_u16::<LittleEndian>(1)?; // name length
    w.write_u8(tag_id)?;
    let bytes = value.as_bytes();
    w.write_u16::<LittleEndian>(bytes.len() as u16)?;
    w.write_all(bytes)?;
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
