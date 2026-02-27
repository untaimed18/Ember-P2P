use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::messages::PARTSIZE;

const PART_MET_MAGIC: u32 = 0x504D4554; // "PMET"

#[derive(Debug, Clone)]
pub struct PartTracker {
    pub file_size: u64,
    pub part_count: usize,
    completed: Vec<bool>,
    pub in_progress: Vec<bool>,
    met_path: PathBuf,
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
        };

        tracker.load();
        tracker
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

    /// Get all incomplete parts that the peer has available
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

    pub fn save(&self) {
        if let Err(e) = self.save_inner() {
            tracing::warn!("Failed to save part.met: {e}");
        }
    }

    fn save_inner(&self) -> anyhow::Result<()> {
        let mut file = std::fs::File::create(&self.met_path)?;
        file.write_all(&PART_MET_MAGIC.to_le_bytes())?;
        file.write_all(&(self.file_size).to_le_bytes())?;
        file.write_all(&(self.part_count as u32).to_le_bytes())?;

        let bitmap_bytes = (self.part_count + 7) / 8;
        let mut bitmap = vec![0u8; bitmap_bytes];
        for (i, &complete) in self.completed.iter().enumerate() {
            if complete {
                bitmap[i / 8] |= 1 << (i % 8);
            }
        }
        file.write_all(&bitmap)?;
        file.flush()?;
        Ok(())
    }

    fn load(&mut self) {
        if let Err(_) = self.load_inner() {
            self.completed = vec![false; self.part_count];
        }
        self.in_progress = vec![false; self.part_count];
    }

    fn load_inner(&mut self) -> anyhow::Result<()> {
        let mut file = std::fs::File::open(&self.met_path)?;
        let mut magic_buf = [0u8; 4];
        file.read_exact(&mut magic_buf)?;
        let magic = u32::from_le_bytes(magic_buf);
        if magic != PART_MET_MAGIC {
            anyhow::bail!("invalid part.met magic");
        }

        let mut size_buf = [0u8; 8];
        file.read_exact(&mut size_buf)?;
        let stored_size = u64::from_le_bytes(size_buf);
        if stored_size != self.file_size {
            anyhow::bail!("file size mismatch in part.met");
        }

        let mut count_buf = [0u8; 4];
        file.read_exact(&mut count_buf)?;
        let stored_count = u32::from_le_bytes(count_buf) as usize;
        if stored_count != self.part_count {
            anyhow::bail!("part count mismatch in part.met");
        }

        let bitmap_bytes = (self.part_count + 7) / 8;
        let mut bitmap = vec![0u8; bitmap_bytes];
        file.read_exact(&mut bitmap)?;

        for i in 0..self.part_count {
            self.completed[i] = (bitmap[i / 8] >> (i % 8)) & 1 != 0;
        }

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
