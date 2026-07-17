use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use super::messages::EMBLOCKSIZE;

const BAN_CORRUPTION_RATIO: f64 = 0.32;

/// Minimum total bytes contributed by a single IP before its corruption
/// ratio is even considered for banning. The previous code would ban an
/// IP that contributed 1×EMBLOCKSIZE corrupt + 1×EMBLOCKSIZE clean (50% >
/// 32%), even though that's nowhere near a statistically reliable
/// signal. Three full eMule blocks (~540 KiB) is a small enough sample
/// that a deliberately corrupting peer trips it quickly, but big enough
/// to absorb a single bad block on a peer that's otherwise providing
/// valid data.
const MIN_BYTES_FOR_BAN_DECISION: u64 = 3 * EMBLOCKSIZE;

/// Cap on distinct files tracked at once. Each file's own block list is
/// already bounded by `MAX_BLOCKS_BEFORE_COMPACT`, but nothing previously
/// bounded the number of *files* — downloads that are paused/cancelled
/// (rather than completing or failing, the only two events that call
/// `remove_file`) never got cleaned up, so a long session with many
/// started-then-abandoned downloads could grow this map indefinitely.
const MAX_TRACKED_FILES: usize = 512;

#[derive(Debug, Clone)]
struct RecordedBlock {
    start: u64,
    end: u64,
    ip: Ipv4Addr,
    verified: bool,
    corrupt: bool,
}

impl RecordedBlock {
    fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

pub struct CorruptionBlackBox {
    records: HashMap<[u8; 16], Vec<RecordedBlock>>,
    /// Oldest-first insertion order of `records` keys, used to evict the
    /// longest-tracked file when `MAX_TRACKED_FILES` is exceeded.
    insertion_order: std::collections::VecDeque<[u8; 16]>,
}

impl CorruptionBlackBox {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            insertion_order: std::collections::VecDeque::new(),
        }
    }

    /// Records which IP sent a byte range. Overlapping regions from different
    /// IPs are split so only the latest writer owns each sub-range.
    pub fn record_data(&mut self, file_hash: [u8; 16], start: u64, end: u64, ip: Ipv4Addr) {
        if start >= end {
            return;
        }

        if !self.records.contains_key(&file_hash) {
            self.insertion_order.push_back(file_hash);
            if self.insertion_order.len() > MAX_TRACKED_FILES {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.records.remove(&oldest);
                }
            }
        }

        let blocks = self.records.entry(file_hash).or_default();

        let mut new_blocks: Vec<RecordedBlock> = Vec::new();

        for existing in blocks.drain(..) {
            if existing.verified || existing.corrupt {
                new_blocks.push(existing);
                continue;
            }

            let overlap_start = existing.start.max(start);
            let overlap_end = existing.end.min(end);

            if overlap_start >= overlap_end {
                new_blocks.push(existing);
                continue;
            }

            // The new write overwrites the overlapping portion. Keep non-overlapping
            // fragments of the existing block.
            if existing.start < overlap_start {
                new_blocks.push(RecordedBlock {
                    start: existing.start,
                    end: overlap_start,
                    ip: existing.ip,
                    verified: false,
                    corrupt: false,
                });
            }
            if existing.end > overlap_end {
                new_blocks.push(RecordedBlock {
                    start: overlap_end,
                    end: existing.end,
                    ip: existing.ip,
                    verified: false,
                    corrupt: false,
                });
            }
        }

        new_blocks.push(RecordedBlock {
            start,
            end,
            ip,
            verified: false,
            corrupt: false,
        });

        let entry = self.records.entry(file_hash).or_default();
        *entry = new_blocks;
        // Bound per-file growth. A long multi-source download with heavy
        // overlap can fragment the list into many small blocks. Once it
        // grows large, collapse the verified blocks (which are never split
        // again and only feed the per-IP byte denominator) into one
        // aggregate per IP — lossless for the ban ratio, bounded in size.
        const MAX_BLOCKS_BEFORE_COMPACT: usize = 4096;
        if entry.len() > MAX_BLOCKS_BEFORE_COMPACT {
            Self::compact(entry);
        }
    }

    /// Merge each IP's verified blocks into a single aggregate block,
    /// preserving total bytes. Verified blocks are skipped by
    /// `record_data`'s overlap splitting and can never be re-marked
    /// corrupt, so only their summed length matters (as the denominator
    /// in `corrupted_part`'s ratio). Corrupt and not-yet-verified blocks
    /// are preserved exactly.
    fn compact(blocks: &mut Vec<RecordedBlock>) {
        let mut verified_bytes: HashMap<Ipv4Addr, u64> = HashMap::new();
        let mut kept: Vec<RecordedBlock> = Vec::new();
        for b in blocks.drain(..) {
            if b.verified && !b.corrupt {
                *verified_bytes.entry(b.ip).or_default() += b.len();
            } else {
                kept.push(b);
            }
        }
        for (ip, bytes) in verified_bytes {
            if bytes > 0 {
                kept.push(RecordedBlock {
                    start: 0,
                    end: bytes,
                    ip,
                    verified: true,
                    corrupt: false,
                });
            }
        }
        *blocks = kept;
    }

    /// Marks all records overlapping [part_start, part_end) as verified (hash check passed).
    ///
    /// Splits any block that only *partially* overlaps the range so only
    /// the verified sub-range is marked — a block can span outside
    /// `[part_start, part_end)` when a source's write crossed a part
    /// boundary. Without splitting, bytes outside the actually-checked
    /// range were being marked verified too, which could hide corruption
    /// in whichever adjacent part those bytes actually belong to (their
    /// own MD4 check might never run if this over-broad marking excludes
    /// them from `corrupted_part_contributors`).
    pub fn verified_part(&mut self, file_hash: &[u8; 16], part_start: u64, part_end: u64) {
        if let Some(blocks) = self.records.get_mut(file_hash) {
            let mut result = Vec::with_capacity(blocks.len());
            for block in blocks.drain(..) {
                if block.verified
                    || block.corrupt
                    || block.start >= part_end
                    || block.end <= part_start
                {
                    result.push(block);
                    continue;
                }
                let overlap_start = block.start.max(part_start);
                let overlap_end = block.end.min(part_end);
                if block.start < overlap_start {
                    result.push(RecordedBlock {
                        start: block.start,
                        end: overlap_start,
                        ip: block.ip,
                        verified: false,
                        corrupt: false,
                    });
                }
                result.push(RecordedBlock {
                    start: overlap_start,
                    end: overlap_end,
                    ip: block.ip,
                    verified: true,
                    corrupt: false,
                });
                if block.end > overlap_end {
                    result.push(RecordedBlock {
                        start: overlap_end,
                        end: block.end,
                        ip: block.ip,
                        verified: false,
                        corrupt: false,
                    });
                }
            }
            *blocks = result;
        }
    }

    /// Returns the distinct IPs that contributed still-unverified data
    /// overlapping `[start, end)`, without mutating any records.
    ///
    /// A part-level MD4 mismatch tells us the aggregate bytes in the part
    /// are wrong, but not *which* contributor's bytes are the bad ones —
    /// AICH narrowing (when it succeeds) answers that at 180 KiB
    /// granularity, but a plain `corrupted_part` call only has part-level
    /// evidence. When more than one IP contributed to a failed part, a
    /// caller cannot reliably single out one of them as *the* culprit from
    /// this event alone: use this to detect that ambiguity before applying
    /// a per-connection penalty (e.g. a reputation strike) to whichever
    /// peer happened to be the one that completed/verified the part.
    pub fn corrupted_part_contributors(
        &self,
        file_hash: &[u8; 16],
        start: u64,
        end: u64,
    ) -> HashSet<Ipv4Addr> {
        let mut ips = HashSet::new();
        if let Some(blocks) = self.records.get(file_hash) {
            for block in blocks {
                if !block.verified && block.start < end && block.end > start {
                    ips.insert(block.ip);
                }
            }
        }
        ips
    }

    /// Evaluates corruption within [part_start, part_end). Returns a list of IPs
    /// that should be banned based on their corruption ratio across the entire file.
    ///
    /// When more than one IP contributed unverified bytes to the failed part,
    /// this is a no-op: we cannot attribute which contributor's bytes were bad
    /// from part-level MD4 alone, so marking every overlapping block corrupt
    /// would poison honest multi-source peers toward a false ban. AICH
    /// narrowing (or a later single-contributor failure) is required before
    /// corrupt bytes count toward the ban ratio.
    pub fn corrupted_part(
        &mut self,
        file_hash: &[u8; 16],
        part_start: u64,
        part_end: u64,
    ) -> Vec<Ipv4Addr> {
        let contributors = self.corrupted_part_contributors(file_hash, part_start, part_end);
        if contributors.len() != 1 {
            return Vec::new();
        }

        if let Some(blocks) = self.records.get_mut(file_hash) {
            for block in blocks.iter_mut() {
                if !block.verified && block.start < part_end && block.end > part_start {
                    block.corrupt = true;
                }
            }
        }

        let blocks = match self.records.get(file_hash) {
            Some(b) => b,
            None => return Vec::new(),
        };

        // Gather per-IP totals across ALL records for this file.
        let mut ip_total: HashMap<Ipv4Addr, u64> = HashMap::new();
        let mut ip_corrupt: HashMap<Ipv4Addr, u64> = HashMap::new();

        for block in blocks {
            let bytes = block.len();
            *ip_total.entry(block.ip).or_default() += bytes;
            if block.corrupt {
                *ip_corrupt.entry(block.ip).or_default() += bytes;
            }
        }

        let mut ban_list = Vec::new();
        for (ip, corrupt_bytes) in &ip_corrupt {
            if *corrupt_bytes < EMBLOCKSIZE {
                continue;
            }
            let total = ip_total.get(ip).copied().unwrap_or(1);
            // Require enough total volume from this IP for the ratio to
            // be statistically meaningful. Without this guard, an IP
            // that contributed exactly one EMBLOCKSIZE of corrupt data
            // (and nothing else) hits 100% ratio and gets banned on
            // first contact — even though the same bytes from a
            // disk-bit-flip-prone client would be re-fetched cleanly
            // from a different IP and cost us nothing.
            if total < MIN_BYTES_FOR_BAN_DECISION {
                continue;
            }
            let ratio = *corrupt_bytes as f64 / total as f64;
            if ratio >= BAN_CORRUPTION_RATIO {
                ban_list.push(*ip);
            }
        }

        ban_list
    }

    /// Removes all records for a file (e.g. when the download completes).
    pub fn remove_file(&mut self, file_hash: &[u8; 16]) {
        self.records.remove(file_hash);
        self.insertion_order.retain(|h| h != file_hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(id: u8) -> [u8; 16] {
        let mut h = [0u8; 16];
        h[0] = id;
        h
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn basic_record_and_verify() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(1);
        bb.record_data(h, 0, 1000, ip(1, 2, 3, 4));
        bb.verified_part(&h, 0, 1000);

        let blocks = bb.records.get(&h).unwrap();
        assert!(blocks.iter().all(|b| b.verified));
    }

    #[test]
    fn overlap_splits_existing() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(2);

        bb.record_data(h, 0, 1000, ip(1, 0, 0, 1));
        bb.record_data(h, 300, 700, ip(2, 0, 0, 2));

        let blocks = bb.records.get(&h).unwrap();
        // Should have 3 blocks: [0,300) from ip1, [300,700) from ip2, [700,1000) from ip1
        let ip1_blocks: Vec<_> = blocks.iter().filter(|b| b.ip == ip(1, 0, 0, 1)).collect();
        let ip2_blocks: Vec<_> = blocks.iter().filter(|b| b.ip == ip(2, 0, 0, 2)).collect();

        let ip1_bytes: u64 = ip1_blocks.iter().map(|b| b.len()).sum();
        let ip2_bytes: u64 = ip2_blocks.iter().map(|b| b.len()).sum();

        assert_eq!(ip1_bytes, 600);
        assert_eq!(ip2_bytes, 400);
    }

    #[test]
    fn corruption_bans_responsible_ip() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(3);

        // ip_bad sends 3*EMBLOCKSIZE of corrupt data — enough to exceed
        // MIN_BYTES_FOR_BAN_DECISION so the ratio test fires.
        let bad = ip(10, 0, 0, 1);
        bb.record_data(h, 0, MIN_BYTES_FOR_BAN_DECISION, bad);

        // ip_good sends a separate clean range
        let good = ip(10, 0, 0, 2);
        bb.record_data(
            h,
            MIN_BYTES_FOR_BAN_DECISION,
            MIN_BYTES_FOR_BAN_DECISION * 2,
            good,
        );

        let banned = bb.corrupted_part(&h, 0, MIN_BYTES_FOR_BAN_DECISION);
        assert!(banned.contains(&bad));
        assert!(!banned.contains(&good));
    }

    #[test]
    fn small_volume_ip_not_banned_even_at_100_percent_ratio() {
        // Regression: previously a peer that contributed a single bad
        // EMBLOCKSIZE (100% corrupt ratio) was banned on first contact.
        // The MIN_BYTES_FOR_BAN_DECISION guard now requires enough
        // sample size before the ratio test applies.
        let mut bb = CorruptionBlackBox::new();
        let h = hash(8);
        let suspect = ip(10, 0, 0, 9);
        bb.record_data(h, 0, EMBLOCKSIZE, suspect);
        let banned = bb.corrupted_part(&h, 0, EMBLOCKSIZE);
        assert!(banned.is_empty());
    }

    #[test]
    fn below_emblocksize_not_banned() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(4);
        let suspect = ip(10, 0, 0, 1);

        bb.record_data(h, 0, EMBLOCKSIZE - 1, suspect);
        let banned = bb.corrupted_part(&h, 0, EMBLOCKSIZE - 1);
        assert!(banned.is_empty());
    }

    #[test]
    fn verified_part_marks_blocks() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(5);

        bb.record_data(h, 0, 500, ip(1, 1, 1, 1));
        bb.record_data(h, 500, 1000, ip(2, 2, 2, 2));
        bb.verified_part(&h, 0, 500);

        let blocks = bb.records.get(&h).unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().any(|b| b.ip == ip(1, 1, 1, 1) && b.verified));
        assert!(blocks.iter().any(|b| b.ip == ip(2, 2, 2, 2) && !b.verified));
    }

    #[test]
    fn remove_file_clears_all() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(6);
        bb.record_data(h, 0, 1000, ip(1, 1, 1, 1));
        bb.remove_file(&h);
        assert!(bb.records.get(&h).is_none());
    }

    #[test]
    fn corrupted_part_contributors_reports_all_unverified_ips_in_range() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(9);
        let a = ip(10, 0, 0, 1);
        let b = ip(10, 0, 0, 2);

        // Two different peers contributed to the same part range.
        bb.record_data(h, 0, 500, a);
        bb.record_data(h, 500, 1000, b);

        let contributors = bb.corrupted_part_contributors(&h, 0, 1000);
        assert_eq!(contributors.len(), 2, "both peers overlap the range");
        assert!(contributors.contains(&a));
        assert!(contributors.contains(&b));
    }

    #[test]
    fn corrupted_part_contributors_excludes_already_verified_ips() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(10);
        let a = ip(10, 0, 0, 1);
        let b = ip(10, 0, 0, 2);

        bb.record_data(h, 0, 500, a);
        bb.record_data(h, 500, 1000, b);
        // `a`'s contribution to an earlier part already verified clean;
        // only `b`'s bytes remain unverified in this part.
        bb.verified_part(&h, 0, 500);

        let contributors = bb.corrupted_part_contributors(&h, 0, 1000);
        assert_eq!(
            contributors.len(),
            1,
            "a verified peer must not count as an ambiguous contributor"
        );
        assert!(contributors.contains(&b));
    }

    #[test]
    fn corrupted_part_contributors_is_a_single_ip_for_one_source_part() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(11);
        let solo = ip(10, 0, 0, 5);
        bb.record_data(h, 0, 1000, solo);

        let contributors = bb.corrupted_part_contributors(&h, 0, 1000);
        assert_eq!(contributors.len(), 1);
        assert!(contributors.contains(&solo));
    }

    #[test]
    fn multi_source_corrupt_part_does_not_ban_or_mark() {
        // Ambiguous multi-contributor part failures must not poison every
        // overlapping IP toward the corruption-ratio ban.
        let mut bb = CorruptionBlackBox::new();
        let h = hash(12);
        let a = ip(10, 0, 0, 1);
        let b = ip(10, 0, 0, 2);
        bb.record_data(h, 0, MIN_BYTES_FOR_BAN_DECISION, a);
        bb.record_data(
            h,
            MIN_BYTES_FOR_BAN_DECISION,
            MIN_BYTES_FOR_BAN_DECISION * 2,
            b,
        );
        let banned = bb.corrupted_part(&h, 0, MIN_BYTES_FOR_BAN_DECISION * 2);
        assert!(banned.is_empty());
        let blocks = bb.records.get(&h).unwrap();
        assert!(blocks.iter().all(|blk| !blk.corrupt));
    }

    #[test]
    fn tracked_file_count_is_capped_via_lru_eviction() {
        let mut bb = CorruptionBlackBox::new();
        let hash_n = |n: u16| {
            let mut h = [0u8; 16];
            h[0..2].copy_from_slice(&n.to_le_bytes());
            h
        };

        for n in 0..(MAX_TRACKED_FILES as u16 + 1) {
            bb.record_data(hash_n(n), 0, 100, ip(10, 0, 0, 1));
        }

        assert_eq!(
            bb.records.len(),
            MAX_TRACKED_FILES,
            "tracked file count must never exceed MAX_TRACKED_FILES"
        );
        assert!(
            bb.records.get(&hash_n(0)).is_none(),
            "oldest file must be evicted first"
        );
        assert!(
            bb.records.get(&hash_n(MAX_TRACKED_FILES as u16)).is_some(),
            "most recently added file must survive eviction"
        );
    }

    #[test]
    fn ratio_below_threshold_not_banned() {
        let mut bb = CorruptionBlackBox::new();
        let h = hash(7);
        let suspect = ip(10, 0, 0, 1);

        // 10 * EMBLOCKSIZE total, only EMBLOCKSIZE corrupt → 10% < 32%
        for i in 0..10 {
            bb.record_data(h, i * EMBLOCKSIZE, (i + 1) * EMBLOCKSIZE, suspect);
        }

        let banned = bb.corrupted_part(&h, 0, EMBLOCKSIZE);
        assert!(banned.is_empty());
    }
}
