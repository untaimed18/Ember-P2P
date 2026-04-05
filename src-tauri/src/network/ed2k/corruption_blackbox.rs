use std::collections::HashMap;
use std::net::Ipv4Addr;

use super::messages::EMBLOCKSIZE;

const BAN_CORRUPTION_RATIO: f64 = 0.32;

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
}

impl CorruptionBlackBox {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Records which IP sent a byte range. Overlapping regions from different
    /// IPs are split so only the latest writer owns each sub-range.
    pub fn record_data(&mut self, file_hash: [u8; 16], start: u64, end: u64, ip: Ipv4Addr) {
        if start >= end {
            return;
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

        *self.records.entry(file_hash).or_default() = new_blocks;
    }

    /// Marks all records overlapping [part_start, part_end) as verified (hash check passed).
    pub fn verified_part(&mut self, file_hash: &[u8; 16], part_start: u64, part_end: u64) {
        if let Some(blocks) = self.records.get_mut(file_hash) {
            for block in blocks.iter_mut() {
                if block.start < part_end && block.end > part_start {
                    block.verified = true;
                }
            }
        }
    }

    /// Evaluates corruption within [part_start, part_end). Returns a list of IPs
    /// that should be banned based on their corruption ratio across the entire file.
    pub fn corrupted_part(
        &mut self,
        file_hash: &[u8; 16],
        part_start: u64,
        part_end: u64,
    ) -> Vec<Ipv4Addr> {
        if let Some(blocks) = self.records.get_mut(file_hash) {
            for block in blocks.iter_mut() {
                if block.start < part_end && block.end > part_start {
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

        // ip_bad sends EMBLOCKSIZE bytes of data that will be flagged corrupt
        let bad = ip(10, 0, 0, 1);
        bb.record_data(h, 0, EMBLOCKSIZE, bad);

        // ip_good sends a separate range
        let good = ip(10, 0, 0, 2);
        bb.record_data(h, EMBLOCKSIZE, EMBLOCKSIZE * 2, good);

        let banned = bb.corrupted_part(&h, 0, EMBLOCKSIZE);
        assert!(banned.contains(&bad));
        assert!(!banned.contains(&good));
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
