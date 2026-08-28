use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};

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

static SAVE_PATH_GUARDS: OnceLock<
    parking_lot::Mutex<std::collections::HashMap<PathBuf, Arc<parking_lot::Mutex<()>>>>,
> = OnceLock::new();

fn save_path_guard(path: &Path) -> Arc<parking_lot::Mutex<()>> {
    let mut guards = SAVE_PATH_GUARDS
        .get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
        .lock();
    guards
        .entry(path.to_path_buf())
        .or_insert_with(|| Arc::new(parking_lot::Mutex::new(())))
        .clone()
}

/// Drop the per-path guard once its `.part.met` is deleted, or the map grows
/// by one entry per download for the process lifetime. Safe even with a
/// stale queued snapshot still holding the old Arc: the `save_generation`
/// bump in `delete_met` makes it bail before writing.
fn evict_save_path_guard(path: &Path) {
    if let Some(guards) = SAVE_PATH_GUARDS.get() {
        guards.lock().remove(path);
    }
}

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
    /// Per-part count of source workers currently pulling that part.
    ///
    /// A count, not a flag: the endgame fallback in `multi_source`
    /// deliberately re-selects with every part treated as free so a second
    /// source can pile onto a part already in flight. With a plain bool,
    /// whichever of the two tore down first cleared the *other* source's
    /// claim, `select_part` then handed the part to a third source, and the
    /// same bytes were pulled twice while a connection slot was wasted.
    /// Claims are registered exactly once per source via `InProgressGuard`,
    /// which also releases them on every task exit path, so the count
    /// returns to zero when nothing is transferring.
    in_progress_claims: Vec<u16>,
    /// Gap sub-ranges a source worker has taken out of circulation while it
    /// writes them to disk. Purely an exclusion set for the write path — the
    /// gap list itself is untouched until the write is committed. See
    /// `multi_source::WriteReservation` for why the tracker guard can no
    /// longer be held across `PartFileWriter::write`.
    write_reservations: Vec<(u64, u64)>,
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
    /// Invalidates queued snapshots when completion deletes `.part.met`.
    save_generation: Arc<AtomicU64>,
}

impl PartTracker {
    pub fn new(file_size: u64, part_file: &Path) -> Self {
        Self::new_with_identity(file_size, part_file, [0u8; 16])
    }

    /// Load a `.part.met` that is bound to an expected ed2k file hash.
    ///
    /// `.part.met` sidecars are named after the transfer, not the content, so
    /// a stale or hand-moved sidecar can describe a completely different file.
    /// Callers that know the hash they are downloading pass it here so
    /// `load_emule_format` can reject a mismatched sidecar; passing `[0u8; 16]`
    /// (via [`PartTracker::new`]) keeps the historical behaviour of adopting
    /// whatever hash the file carries, for callers that only want the gap list.
    /// The expected hash must be supplied at construction time because a later
    /// `set_file_hash` overwrites the stored value and hides the mismatch.
    pub fn new_with_identity(
        file_size: u64,
        part_file: &Path,
        expected_file_hash: [u8; 16],
    ) -> Self {
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
            in_progress_claims: vec![0; part_count],
            write_reservations: Vec::new(),
            met_path,
            file_hash: expected_file_hash,
            file_name: String::new(),
            part_hashes: Vec::new(),
            part_verified: vec![false; part_count],
            file_hash_verified: false,
            save_generation: Arc::new(AtomicU64::new(0)),
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
            in_progress_claims: vec![0; part_count],
            write_reservations: Vec::new(),
            met_path,
            file_hash: [0u8; 16],
            file_name: String::new(),
            part_hashes: Vec::new(),
            part_verified: vec![false; part_count],
            file_hash_verified: false,
            save_generation: Arc::new(AtomicU64::new(0)),
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

    /// Drop the stored hashset together with every per-part verified flag,
    /// leaving the gap list (and therefore the bytes already on disk) alone.
    ///
    /// Used when a hashset loaded from `.part.met` fails `verify_hashset`:
    /// nothing may stay "verified" on the strength of hashes we just rejected,
    /// and `part_hashes` has to be empty again for the normal
    /// `OP_HASHSETREQUEST` path to fetch a trustworthy set from a peer.
    pub fn clear_part_hashes_and_verified(&mut self) {
        self.part_hashes.clear();
        self.file_hash_verified = false;
        for flag in self.part_verified.iter_mut() {
            *flag = false;
        }
    }

    /// Index of the first gap that can overlap a range starting at `start`.
    ///
    /// The gap list is always kept sorted by start offset and free of overlaps
    /// (see `fill_range` / `add_gap` / the merge in `load_emule_format`), so
    /// gap ends are sorted too and every gap before this index ends at or
    /// before `start`. Callers scanning parts in ascending order can carry the
    /// returned index forward instead of re-searching, which is what keeps
    /// `completed_parts` linear.
    fn first_gap_reaching(&self, start: u64) -> usize {
        self.gaps.partition_point(|&(_, gap_end)| gap_end <= start)
    }

    /// Whether any gap overlaps `[start, end)`, given `from` is the index
    /// returned by [`Self::first_gap_reaching`] for `start`.
    fn gap_overlaps_from(&self, from: usize, end: u64) -> bool {
        self.gaps
            .get(from)
            .is_some_and(|&(gap_start, _)| gap_start < end)
    }

    /// Check if a part (9.28 MB chunk) is fully downloaded.
    pub fn is_part_complete(&self, part_idx: usize) -> bool {
        let (start, end) = self.part_range(part_idx);
        !self.gap_overlaps_from(self.first_gap_reaching(start), end)
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

    /// Drop verified/complete state for every part that extends past
    /// `readable_len` on disk. A truncated `.part` must not keep its
    /// `.part.met` verified bits — `set_len` would zero-fill the tail and
    /// `is_range_safe_to_serve` would then hand those zeros to peers.
    pub fn invalidate_unreadable(&mut self, readable_len: u64) {
        if readable_len < self.file_size {
            self.invalidate_range(readable_len, self.file_size);
            self.file_hash_verified = false;
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

    /// Total completed bytes.
    pub fn completed_bytes(&self) -> u64 {
        let gap_bytes: u64 = self.gaps.iter().map(|(s, e)| e - s).sum();
        self.file_size.saturating_sub(gap_bytes)
    }

    /// Bytes belonging to MD4-verified parts only.
    pub fn verified_bytes(&self) -> u64 {
        (0..self.part_count)
            .filter(|&i| self.is_part_verified(i))
            .map(|i| {
                let (ps, pe) = self.part_range(i);
                pe.saturating_sub(ps)
            })
            .sum()
    }

    /// Progress figure for UI / Progress events.
    ///
    /// Gap-fill alone can reach `file_size` before any part MD4 runs (no
    /// hashset yet). Cap just below 100% in that case so the bar does not
    /// claim completion until parts verify or the final whole-file hash runs.
    pub fn progress_bytes(&self) -> u64 {
        let filled = self.completed_bytes();
        if self.file_size == 0 {
            return 0;
        }
        if self.gaps.is_empty() && !self.part_verified.iter().all(|&v| v) {
            // Every byte is on disk here, so the figure must not fall back to
            // `verified_bytes()`: if the last part's bytes all land but the
            // source that would MD4 it disconnects first, that reported a drop
            // of about one part (~9.28 MB) and the bar visibly ran backwards.
            // Hold just short of complete instead — the final whole-file hash
            // (`mark_file_hash_verified`) releases it.
            return self.verified_bytes().max(self.file_size.saturating_sub(1));
        }
        filled.min(self.file_size)
    }

    /// Return a boolean bitmap of completed parts (for OP_FILESTATUS compatibility).
    pub fn completed_parts(&self) -> Vec<bool> {
        // One forward walk of the gap list rather than a per-part rescan from
        // the front: this is recomputed on every part completion, source
        // (re)start and pipeline extension while the shared tracker lock is
        // held, and a fragmented gap list (up to MAX_GAP_ENTRIES) against the
        // ~10,300 parts of a 100 GB file made that tens of millions of
        // comparisons per call. Part starts only increase, so a gap that ends
        // at or before the current part's start is irrelevant to every later
        // part as well and can be skipped permanently.
        let mut out = Vec::with_capacity(self.part_count);
        let mut gap_idx = 0usize;
        for part_idx in 0..self.part_count {
            let (start, end) = self.part_range(part_idx);
            while self
                .gaps
                .get(gap_idx)
                .is_some_and(|&(_, gap_end)| gap_end <= start)
            {
                gap_idx += 1;
            }
            out.push(!self.gap_overlaps_from(gap_idx, end));
        }
        out
    }

    /// Parts that are BOTH gap-complete AND MD4-verified — i.e. the parts we
    /// are actually willing to serve. Any availability bitmap advertised to a
    /// peer must use this (not `completed_parts`), otherwise we advertise parts
    /// the serve gate (`is_range_safe_to_serve`) will then refuse, freezing the
    /// peer's download on a "dead" part it keeps re-requesting.
    pub fn serveable_parts(&self) -> Vec<bool> {
        let mut parts = self.completed_parts();
        for (part_idx, serveable) in parts.iter_mut().enumerate() {
            *serveable &= self.is_part_verified(part_idx);
        }
        parts
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
            let last = last_part.min(self.part_count.saturating_sub(1));
            for (p, bytes) in result
                .iter_mut()
                .enumerate()
                .take(last + 1)
                .skip(first_part)
            {
                let (ps, pe) = self.part_range(p);
                let overlap_start = gs.max(ps);
                let overlap_end = ge.min(pe);
                if overlap_start < overlap_end {
                    *bytes += overlap_end - overlap_start;
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
        // Allocate a monotonically increasing sequence while the tracker is
        // locked. A delayed older writer checks this value before replacing
        // the file, so it cannot overwrite a newer snapshot that was taken
        // concurrently by another source worker.
        let generation = self
            .save_generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        SaveSnapshot {
            met_path: self.met_path.clone(),
            file_size: self.file_size,
            file_hash: self.file_hash,
            file_name: self.file_name.clone(),
            part_hashes: self.part_hashes.clone(),
            gaps: self.gaps.clone(),
            part_verified: self.part_verified.clone(),
            save_generation: self.save_generation.clone(),
            generation,
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
                anyhow::bail!(
                    "part.met: {} part hashes exceeds u16::MAX — refusing to write a mismatched count (file too large for classic part.met)",
                    part_hash_count
                );
            }
            cur.write_u16::<LittleEndian>(part_hash_count as u16)?;
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

    /// Fall back to "nothing downloaded yet". Used when a `.part.met` is
    /// rejected outright, because none of its resume data can be trusted once
    /// the file identity or hashset it describes fails to match the download.
    fn reset_to_incomplete(&mut self) {
        self.gaps = if self.file_size > 0 {
            vec![(0, self.file_size)]
        } else {
            Vec::new()
        };
    }

    fn load(&mut self) {
        if let Err(e) = self.load_inner() {
            if self.met_path.exists() {
                tracing::warn!(
                    "Failed to load part.met ({}), resetting progress: {e}",
                    self.met_path.display()
                );
            }
            self.reset_to_incomplete();
        }
        self.in_progress_claims = vec![0; self.part_count];
        self.write_reservations.clear();
        self.sync_to_on_disk_part_length();
    }

    /// If the `.part` file exists but is shorter than `file_size`, drop
    /// verified bits and re-open gaps for every part that extends past the
    /// readable byte count. Missing files are left to the resume reset
    /// path (tests also load `.part.met` without a data file).
    fn sync_to_on_disk_part_length(&mut self) {
        let part_path = match self.met_path.file_stem() {
            Some(stem) => self.met_path.with_file_name(stem),
            None => return,
        };
        let Ok(meta) = std::fs::metadata(&part_path) else {
            return;
        };
        self.invalidate_unreadable(meta.len());
    }

    fn load_inner(&mut self) -> anyhow::Result<()> {
        // A crash inside `atomic_write`'s Windows replace-fallback parks the only
        // copy under a fixed backup name and leaves nothing at `met_path`. `load`
        // reads that absence as "nothing downloaded yet" and `reset_to_incomplete`
        // restarts the download at 0%, after which the next save overwrites the
        // parked copy — so the loss is silent and permanent. Every other state
        // loader recovers first (`config.rs`, `identity.rs`, `known_files.rs`,
        // `share_intent.rs`, `database.rs`, `credits.rs`, `filesystem.rs`); this
        // one did not.
        crate::security::recover_interrupted_replace(&self.met_path);
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
        } else if hash != [0u8; 16] && hash != self.file_hash {
            // Never adopt another file's resume state. The caller's
            // `set_file_hash` would overwrite the stored hash, so without this
            // check a sidecar left behind by a different download is taken
            // wholesale — including its part hashes, which would then verify
            // every part of this file as corrupt.
            tracing::warn!(
                "File hash mismatch: part.met says {} but expected {} — ignoring stored gaps",
                hex::encode(hash),
                hex::encode(self.file_hash),
            );
            self.reset_to_incomplete();
            return Ok(());
        }

        let part_hash_count = cursor.read_u16::<LittleEndian>()? as usize;
        // A hashset that disagrees with the part count implied by the file size
        // cannot be indexed by part, so every part beyond the stored range
        // would silently stay unverifiable. Both counts are legitimate on
        // disk: the on-wire hashset (one MD4 per part) and the `known.met`
        // form, which appends the trailing `MD4("")` for sizes that are an
        // exact multiple of PARTSIZE. Zero means "hashset not fetched yet".
        if part_hash_count != 0
            && part_hash_count != super::messages::ed2k_part_count_for_size(self.file_size)
            && part_hash_count != super::hash::ed2k_known_met_part_hash_count(self.file_size)
        {
            tracing::warn!(
                "Part hash count mismatch: part.met says {} but expected {} for {} bytes — ignoring stored gaps",
                part_hash_count,
                super::messages::ed2k_part_count_for_size(self.file_size),
                self.file_size,
            );
            self.reset_to_incomplete();
            return Ok(());
        }
        if cursor.position() as usize + part_hash_count * 16 > data.len() {
            anyhow::bail!("truncated part hashes in part.met");
        }
        self.part_hashes = Vec::with_capacity(part_hash_count);
        for _ in 0..part_hash_count {
            let mut ph = [0u8; 16];
            cursor.read_exact(&mut ph)?;
            self.part_hashes.push(ph);
        }
        // Normalise the `known.met` form to the on-wire one by dropping the
        // trailing `MD4("")`. Everything downstream is checked by
        // `verify_hashset`, which requires exactly one MD4 per part and would
        // otherwise reject a perfectly good sidecar written by eMule for a
        // file that is an exact multiple of PARTSIZE — clearing every verified
        // flag with it. Truncating cannot weaken that check: the set still has
        // to reproduce the file hash afterwards.
        let wire_count = super::messages::ed2k_part_count_for_size(self.file_size);
        if self.part_hashes.len() > wire_count {
            self.part_hashes.truncate(wire_count);
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

        // If all tags parsed but zero gap tags were found, preserve it as a
        // complete-but-unverified candidate. This is the crash window after
        // the final bytes and metadata were written but before the completed
        // file was moved. The normal final whole-file verification runs before
        // completion, while the all-false verified bitmap keeps it unsafe to
        // advertise to uploads.
        if gap_starts.is_empty() && self.file_size > 0 {
            tracing::warn!(
                "part.met has {} tags but no gap entries — retaining complete candidate for final verification",
                tag_count,
            );
            self.gaps = Vec::new();
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
        //
        // We intentionally trust the verified bit for complete parts without
        // an immediate MD4 re-hash on load (same as eMule's part.met resume):
        // re-hashing every complete part at startup would stall large
        // resumes. Corruption is still caught when the download worker next
        // verifies a part, and `set_part_verified` only flips after a live
        // MD4 match. Upload serving further requires `is_part_complete` via
        // `is_range_safe_to_serve`. After restore, `load` also drops
        // verified/complete state for parts that extend past the on-disk
        // `.part` length so a truncated file cannot be served as verified.
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

    /// Whether any source worker currently claims `part_idx`. Production code
    /// wants the whole bitmap ([`Self::in_progress_flags`]) for the chunk
    /// selector; this is the single-part form used by tests.
    #[allow(dead_code)]
    pub fn is_in_progress(&self, part_idx: usize) -> bool {
        self.in_progress_claims
            .get(part_idx)
            .is_some_and(|&count| count > 0)
    }

    /// Per-part "somebody is pulling this" bitmap, for `ChunkSelector`.
    pub fn in_progress_flags(&self) -> Vec<bool> {
        self.in_progress_claims.iter().map(|&c| c > 0).collect()
    }

    /// How many parts have at least one outstanding claim (diagnostics).
    pub fn in_progress_part_count(&self) -> usize {
        self.in_progress_claims.iter().filter(|&&c| c > 0).count()
    }

    /// Register one source's claim on `part_idx`. Must be paired 1:1 with
    /// [`Self::release_in_progress`]; go through `multi_source`'s
    /// `InProgressGuard` so a task that exits via `?`/`bail!` or is dropped
    /// mid-await cannot leak a claim.
    pub fn claim_in_progress(&mut self, part_idx: usize) {
        if let Some(count) = self.in_progress_claims.get_mut(part_idx) {
            *count = count.saturating_add(1);
        }
    }

    /// Drop one source's claim on `part_idx`. Saturating: `overflow-checks`
    /// is on in release, so an unpaired release must not panic the worker.
    pub fn release_in_progress(&mut self, part_idx: usize) {
        if let Some(count) = self.in_progress_claims.get_mut(part_idx) {
            *count = count.saturating_sub(1);
        }
    }

    /// Take the gap sub-ranges of `[start, end)` out of circulation so the
    /// caller can write them to disk without holding the tracker guard.
    /// Sub-ranges another worker has already reserved are excluded, which is
    /// what preserves the "never write bytes another worker is writing"
    /// invariant that the long exclusive hold used to provide.
    ///
    /// Every returned sub-range MUST later be passed to
    /// [`Self::commit_write_reservation`] or
    /// [`Self::release_write_reservation`]: a reservation nobody hands back
    /// is a gap no worker is ever allowed to fill again.
    pub fn reserve_write_subranges(&mut self, start: u64, end: u64) -> Vec<(u64, u64)> {
        let candidates = self.fillable_subranges(start, end);
        if candidates.is_empty() {
            return Vec::new();
        }
        let mut blocked: Vec<(u64, u64)> = self
            .write_reservations
            .iter()
            .copied()
            .filter(|&(rs, re)| rs < end && re > start)
            .collect();
        blocked.sort_unstable();

        let mut granted: Vec<(u64, u64)> = Vec::with_capacity(candidates.len());
        for (cs, ce) in candidates {
            let mut cursor = cs;
            for &(rs, re) in &blocked {
                if re <= cursor || rs >= ce {
                    continue;
                }
                if rs > cursor {
                    granted.push((cursor, rs));
                }
                cursor = re;
                if cursor >= ce {
                    break;
                }
            }
            if cursor < ce {
                granted.push((cursor, ce));
            }
        }

        // Reservations live only for the duration of one `PartFileWriter`
        // round-trip and one worker only ever holds the sub-ranges of a
        // single received block, so this list stays tiny. The cap is
        // defence-in-depth: refusing to reserve past it just leaves those
        // bytes as gaps to be re-requested, which is always safe.
        const MAX_WRITE_RESERVATIONS: usize = 1024;
        let room = MAX_WRITE_RESERVATIONS.saturating_sub(self.write_reservations.len());
        granted.truncate(room);
        self.write_reservations.extend(granted.iter().copied());
        granted
    }

    /// Fold a written sub-range into the gap list and drop its reservation.
    /// Returns the bytes this actually transitioned from missing to present.
    pub fn commit_write_reservation(&mut self, start: u64, end: u64) -> u64 {
        self.release_write_reservation(start, end);
        self.fill_range(start, end)
    }

    /// Hand a reserved sub-range back unwritten, so it becomes selectable
    /// again. The range stays a gap, so the bytes are simply re-requested.
    pub fn release_write_reservation(&mut self, start: u64, end: u64) {
        if let Some(pos) = self
            .write_reservations
            .iter()
            .position(|&(s, e)| s == start && e == end)
        {
            self.write_reservations.swap_remove(pos);
        }
    }

    /// Currently reserved write sub-ranges (tests / diagnostics).
    #[allow(dead_code)]
    pub fn write_reservation_count(&self) -> usize {
        self.write_reservations.len()
    }

    pub fn delete_met(&self, allowed_roots: &[String]) {
        self.save_generation.fetch_add(1, Ordering::AcqRel);
        let path_guard = save_path_guard(&self.met_path);
        {
            let _guard = path_guard.lock();
            let _ =
                crate::security::filesystem::remove_approved_file(&self.met_path, allowed_roots);
        }
        evict_save_path_guard(&self.met_path);
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
    save_generation: Arc<AtomicU64>,
    generation: u64,
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
                anyhow::bail!(
                    "part.met: {} part hashes exceeds u16::MAX — refusing to write a mismatched count (file too large for classic part.met)",
                    part_hash_count
                );
            }
            cur.write_u16::<LittleEndian>(part_hash_count as u16)?;
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
        let path_guard = save_path_guard(&snap.met_path);
        let _write_guard = path_guard.lock();
        if snap.save_generation.load(Ordering::Acquire) != snap.generation {
            return;
        }
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
            // Verify the declared length fits in the remaining buffer before
            // allocating, so a truncated/corrupt `.part.met` can't make us
            // allocate for bytes that never arrive (mirrors the blob-tag
            // boundary check below).
            let pos = cursor.position() as usize;
            if pos
                .checked_add(slen)
                .is_none_or(|end| end > cursor.get_ref().len())
            {
                anyhow::bail!("part.met string tag length exceeds data boundary");
            }
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
    // Truncate at a UTF-8 char boundary, not an arbitrary byte offset —
    // see the sibling `write_string_tag` in `collection.rs` for why a raw
    // byte-slice cut can corrupt the tail of the value on reload.
    let max_len = u16::MAX as usize;
    let clamped = if value.len() <= max_len {
        value
    } else {
        let mut end = max_len;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    };
    let clamped = clamped.as_bytes();
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

    /// M5: the per-part claim is refcounted, not a flag. The endgame fallback
    /// in `multi_source` deliberately lets a second source pile onto a part
    /// already in flight, and with a bool whichever source tore down first
    /// cleared the other's claim — `select_part` then handed the part to a
    /// third source and the same bytes were pulled twice. Releases saturate
    /// because `overflow-checks` is on in release builds, so an unpaired
    /// release must not panic a source worker.
    #[test]
    fn in_progress_claims_are_refcounted_and_saturate() {
        let part_path = temp_part_path("claims");
        let mut tracker = PartTracker::new(PARTSIZE * 3, &part_path);
        assert!(!tracker.is_in_progress(1));

        tracker.claim_in_progress(1);
        tracker.claim_in_progress(1);
        assert!(tracker.is_in_progress(1));
        assert_eq!(tracker.in_progress_part_count(), 1);
        assert_eq!(tracker.in_progress_flags(), vec![false, true, false]);

        tracker.release_in_progress(1);
        assert!(
            tracker.is_in_progress(1),
            "one source is still pulling this part"
        );
        tracker.release_in_progress(1);
        assert!(!tracker.is_in_progress(1));

        tracker.release_in_progress(1);
        assert!(!tracker.is_in_progress(1));
        assert_eq!(tracker.in_progress_part_count(), 0);

        // Out-of-range indices are ignored rather than panicking.
        tracker.claim_in_progress(99);
        tracker.release_in_progress(99);
        assert!(!tracker.is_in_progress(99));

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    /// H1b: the write path reserves gap sub-ranges instead of holding the
    /// tracker guard across the disk write. A reserved range stays a gap
    /// (nothing is on disk yet) but must be invisible to every other worker's
    /// reservation, which is what still prevents two sources writing the same
    /// bytes.
    #[test]
    fn reserved_subranges_are_excluded_from_other_reservations() {
        let part_path = temp_part_path("reservations");
        let mut tracker = PartTracker::new(1000, &part_path);

        assert_eq!(tracker.reserve_write_subranges(100, 300), vec![(100, 300)]);
        assert_eq!(
            tracker.gap_list(),
            &[(0, 1000)],
            "reserving must not touch the gap list"
        );

        // An overlapping block may only take the un-reserved fringes...
        assert_eq!(
            tracker.reserve_write_subranges(0, 500),
            vec![(0, 100), (300, 500)]
        );
        // ...and one fully inside a reservation gets nothing at all.
        assert!(tracker.reserve_write_subranges(150, 250).is_empty());

        assert_eq!(tracker.commit_write_reservation(100, 300), 200);
        assert_eq!(tracker.gap_list(), &[(0, 100), (300, 1000)]);

        tracker.release_write_reservation(0, 100);
        tracker.release_write_reservation(300, 500);
        assert_eq!(tracker.write_reservation_count(), 0);
        // Released bytes never reached disk, so they stay reservable.
        assert_eq!(tracker.reserve_write_subranges(0, 100), vec![(0, 100)]);

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

    /// A crash inside `atomic_write`'s Windows replace-fallback leaves nothing
    /// at `.part.met` and the only copy parked under the fixed
    /// `.ember-replace-bak` name. Without a `recover_interrupted_replace` on the
    /// load path that absence reads as "first run": the tracker resets to 0%,
    /// and the next save overwrites the parked copy — silently discarding the
    /// progress and verified bitmap of a download that may be many GB in.
    #[test]
    fn load_recovers_a_part_met_parked_by_an_interrupted_replace() {
        let part_path = temp_part_path("interrupted-replace");
        let met_path = part_path.with_extension("part.met");

        let mut tracker = PartTracker::new(100, &part_path);
        tracker.set_file_hash([0x11; 16]);
        tracker.set_part_hashes(vec![[0x22; 16]]);
        tracker.fill_range(0, 70);
        tracker.save();
        assert_eq!(tracker.completed_bytes(), 70);

        // Reproduce the crash window: the destination has been moved aside and
        // the replacement never landed.
        let mut backup_name = met_path.file_name().unwrap().to_os_string();
        backup_name.push(".ember-replace-bak");
        let backup = met_path.with_file_name(backup_name);
        std::fs::rename(&met_path, &backup).unwrap();
        assert!(!met_path.exists());

        let recovered = PartTracker::new(100, &part_path);
        assert_eq!(
            recovered.completed_bytes(),
            70,
            "progress must be recovered from the parked .part.met, not reset to 0%"
        );
        assert_eq!(recovered.gap_list(), &[(70, 100)]);
        assert_eq!(recovered.file_hash, [0x11; 16]);
        assert!(met_path.exists(), "the parked copy should be restored in place");

        let _ = std::fs::remove_file(&met_path);
        let _ = std::fs::remove_file(&backup);
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

    /// The verified-part bitmap MUST survive the worker -> `.part.met` ->
    /// upload-handler round-trip. The download worker flips `set_part_verified`
    /// in memory and saves; the upload handler reads a *fresh* `PartTracker`
    /// from disk to decide what to advertise/serve. If the persisted bitmap
    /// didn't reload, every in-progress download would advertise zero
    /// serveable parts and partial-file seeding would silently never happen.
    #[test]
    fn verified_bitmap_survives_save_reload() {
        let part_path = temp_part_path("verified-roundtrip");
        let file_size = PARTSIZE * 3 + 123; // 4 parts: 3 full + a short tail
        let mut tracker = PartTracker::new(file_size, &part_path);
        tracker.set_file_hash([0x11; 16]);
        tracker.set_file_name("seed.bin");

        // Part 0: complete + verified. Part 1: complete but NOT verified.
        // Part 2: complete + verified. Part 3: left incomplete.
        tracker.fill_range(0, PARTSIZE);
        tracker.set_part_verified(0);
        tracker.fill_range(PARTSIZE, 2 * PARTSIZE);
        tracker.fill_range(2 * PARTSIZE, 3 * PARTSIZE);
        tracker.set_part_verified(2);
        tracker.save();

        let reloaded = PartTracker::new(file_size, &part_path);
        let serveable = reloaded.serveable_parts();
        assert_eq!(serveable.len(), 4);
        assert!(
            serveable[0],
            "verified+complete part 0 must reload as serveable"
        );
        assert!(
            !serveable[1],
            "complete-but-unverified part 1 must NOT be serveable after reload"
        );
        assert!(
            serveable[2],
            "verified+complete part 2 must reload as serveable"
        );
        assert!(!serveable[3], "incomplete part 3 must NOT be serveable");

        // Advertised (serveable) parts must stay within the serve gate.
        for (p, &is_serveable) in serveable.iter().enumerate().take(4) {
            let (s, e) = reloaded.part_range(p);
            if is_serveable {
                assert!(
                    reloaded.is_range_safe_to_serve(s, e),
                    "serveable part {p} must be safe to serve after reload"
                );
            }
        }

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    #[test]
    fn progress_bytes_caps_below_100_when_gaps_empty_but_unverified() {
        let part_path = temp_part_path("progress_cap");
        let file_size = PARTSIZE * 2;
        let mut tracker = PartTracker::new(file_size, &part_path);
        tracker.fill_range(0, file_size);
        assert!(tracker.all_complete());
        assert_eq!(tracker.completed_bytes(), file_size);
        assert_eq!(
            tracker.progress_bytes(),
            file_size.saturating_sub(1),
            "UI must not show 100% before any part MD4"
        );
        tracker.set_part_verified(0);
        tracker.set_part_verified(1);
        assert_eq!(tracker.progress_bytes(), file_size);
        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    /// All bytes on disk but only some parts MD4-verified (the source that
    /// would verify the last part disconnected first) must not rewind the
    /// bar to `verified_bytes()` — that dropped the reported figure by a
    /// whole part right at the end of the download.
    #[test]
    fn progress_bytes_does_not_regress_when_only_some_parts_verified() {
        let part_path = temp_part_path("progress_no_regress");
        let file_size = PARTSIZE * 3;
        let mut tracker = PartTracker::new(file_size, &part_path);
        tracker.fill_range(0, file_size);
        let all_filled = tracker.progress_bytes();
        tracker.set_part_verified(0);
        tracker.set_part_verified(1);
        assert_eq!(
            tracker.progress_bytes(),
            file_size.saturating_sub(1),
            "progress must hold just short of complete while part 2 awaits MD4"
        );
        assert!(
            tracker.progress_bytes() >= all_filled,
            "progress must never move backwards"
        );
        tracker.mark_file_hash_verified();
        assert_eq!(tracker.progress_bytes(), file_size);
        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    /// `completed_parts` / `serveable_parts` walk the sorted gap list with a
    /// single forward cursor instead of rescanning it per part. Pin the result
    /// against the naive per-part overlap scan across the shapes a cursor can
    /// get wrong: no gaps, one gap spanning every part, gaps landing exactly on
    /// part boundaries, single-byte gaps either side of a boundary, many small
    /// gaps inside one part, and a short final part.
    #[test]
    fn completed_parts_matches_naive_scan() {
        fn naive(tracker: &PartTracker) -> Vec<bool> {
            (0..tracker.part_count)
                .map(|i| {
                    let (start, end) = tracker.part_range(i);
                    !tracker
                        .gap_list()
                        .iter()
                        .any(|&(gs, ge)| gs < end && ge > start)
                })
                .collect()
        }

        let part_path = temp_part_path("completed-parts-scan");
        // Four full parts plus a 123-byte tail.
        let file_size = PARTSIZE * 4 + 123;
        let mut tracker = PartTracker::new(file_size, &part_path);
        assert_eq!(tracker.part_count, 5);

        assert_eq!(tracker.completed_parts(), naive(&tracker));
        assert!(tracker.completed_parts().iter().all(|&done| !done));

        tracker.fill_range(0, file_size);
        assert_eq!(tracker.completed_parts(), naive(&tracker));
        assert!(tracker.completed_parts().iter().all(|&done| done));

        tracker.mark_incomplete(1);
        tracker.mark_incomplete(3);
        assert_eq!(tracker.completed_parts(), naive(&tracker));
        assert_eq!(
            tracker.completed_parts(),
            vec![true, false, true, false, true]
        );

        // The one-byte gaps merge into their neighbour, so parts 0 and 2 lose
        // exactly one byte each — the cursor must not skip a gap that begins
        // where the previous part ended.
        tracker.invalidate_range(4 * PARTSIZE, file_size);
        tracker.invalidate_range(PARTSIZE - 1, PARTSIZE);
        tracker.invalidate_range(2 * PARTSIZE, 2 * PARTSIZE + 1);
        assert_eq!(tracker.completed_parts(), naive(&tracker));
        assert!(tracker.completed_parts().iter().all(|&done| !done));

        tracker.fill_range(0, file_size);
        for i in 0..64u64 {
            let at = 2 * PARTSIZE + i * 1024;
            tracker.invalidate_range(at, at + 16);
        }
        assert_eq!(tracker.gap_list().len(), 64);
        assert_eq!(tracker.completed_parts(), naive(&tracker));
        assert_eq!(
            tracker.completed_parts(),
            vec![true, true, false, true, true]
        );

        tracker.set_part_verified(0);
        tracker.set_part_verified(2);
        tracker.set_part_verified(4);
        let expected: Vec<bool> = naive(&tracker)
            .into_iter()
            .enumerate()
            .map(|(i, complete)| complete && tracker.is_part_verified(i))
            .collect();
        assert_eq!(tracker.serveable_parts(), expected);
        assert_eq!(
            tracker.serveable_parts(),
            vec![true, false, false, false, true]
        );

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    /// A `.part.met` belonging to a different file must not be adopted: its gap
    /// list would claim bytes this download never received and its part hashes
    /// would fail every part. The caller's `set_file_hash` overwrites the
    /// stored hash, so the expected hash has to be bound at load time.
    #[test]
    fn part_met_from_another_file_is_rejected() {
        let part_path = temp_part_path("identity");
        let file_size = PARTSIZE * 2 + 5;
        let mut tracker = PartTracker::new(file_size, &part_path);
        tracker.set_file_hash([0xAA; 16]);
        tracker.set_part_hashes(vec![[0x11; 16], [0x22; 16], [0x33; 16]]);
        tracker.fill_range(0, PARTSIZE);
        tracker.save();

        let same = PartTracker::new_with_identity(file_size, &part_path, [0xAA; 16]);
        assert_eq!(same.gap_list(), &[(PARTSIZE, file_size)]);
        assert_eq!(same.part_hashes().len(), 3);

        let other = PartTracker::new_with_identity(file_size, &part_path, [0xBB; 16]);
        assert_eq!(other.file_hash, [0xBB; 16]);
        assert_eq!(other.gap_list(), &[(0, file_size)]);
        assert!(other.part_hashes().is_empty());

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    /// A stored hashset whose length disagrees with the part count implied by
    /// the file size cannot be indexed by part, so the sidecar is rejected
    /// instead of leaving the parts past its end permanently unverifiable.
    #[test]
    fn part_met_with_wrong_hash_count_is_rejected() {
        let part_path = temp_part_path("hash-count");
        let file_size = PARTSIZE * 3;
        let mut tracker = PartTracker::new(file_size, &part_path);
        tracker.set_file_hash([0xCD; 16]);
        tracker.set_part_hashes(vec![[0x11; 16], [0x22; 16]]);
        tracker.fill_range(0, PARTSIZE);
        tracker.save();

        let reloaded = PartTracker::new_with_identity(file_size, &part_path, [0xCD; 16]);
        assert_eq!(reloaded.gap_list(), &[(0, file_size)]);
        assert!(reloaded.part_hashes().is_empty());

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }

    /// eMule stores one extra `MD4("")` for a file that is an exact multiple of
    /// PARTSIZE. That `known.met` form has to survive a load as the on-wire
    /// hashset, because `verify_hashset` accepts only one MD4 per part and the
    /// resume path clears every verified flag when it rejects a set.
    #[test]
    fn part_met_known_met_hash_count_is_normalised_to_the_wire_form() {
        let part_path = temp_part_path("known-met-sentinel");
        let file_size = PARTSIZE * 2;
        let wire_count = super::super::messages::ed2k_part_count_for_size(file_size);
        let known_met_count = super::super::hash::ed2k_known_met_part_hash_count(file_size);
        assert_eq!(
            known_met_count,
            wire_count + 1,
            "fixture must exercise the sentinel"
        );

        let mut tracker = PartTracker::new(file_size, &part_path);
        tracker.set_file_hash([0xEE; 16]);
        tracker.set_part_hashes(vec![[0x11; 16], [0x22; 16], [0x00; 16]]);
        tracker.fill_range(0, PARTSIZE);
        tracker.save();

        let reloaded = PartTracker::new_with_identity(file_size, &part_path, [0xEE; 16]);
        // Accepted, not reset: the gaps survive and the sentinel is gone.
        assert_eq!(reloaded.gap_list(), &[(PARTSIZE, file_size)]);
        assert_eq!(reloaded.part_hashes().len(), wire_count);
        assert_eq!(reloaded.part_hashes(), &[[0x11; 16], [0x22; 16]]);

        let _ = std::fs::remove_file(part_path.with_extension("part.met"));
    }
}
