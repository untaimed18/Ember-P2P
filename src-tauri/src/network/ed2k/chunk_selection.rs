use super::multi_source::DownloadSource;

/// Rarest-first chunk selection matching eMule's CPartFile::GetNextRequestedBlock.
/// Categorizes parts into 4 rarity zones based on source frequency counts.
pub struct ChunkSelector {
    pub part_frequency: Vec<u16>,
    total_sources: u16,
}

impl ChunkSelector {
    pub fn new(part_count: usize) -> Self {
        Self {
            part_frequency: vec![0; part_count],
            total_sources: 0,
        }
    }

    /// Recalculate per-part frequency from all source availability maps.
    pub fn update_frequencies(&mut self, sources: &[DownloadSource]) {
        let part_count = self.part_frequency.len();
        self.part_frequency.fill(0);
        self.total_sources = sources.len() as u16;

        for source in sources {
            for (i, &has) in source.available_parts.iter().enumerate() {
                if i < part_count && has {
                    self.part_frequency[i] = self.part_frequency[i].saturating_add(1);
                }
            }
        }
    }

    /// Select the best part to download using eMule's 4-tier rarity zones.
    ///
    /// - Very rare: frequency < (sources+9)/10
    /// - Rare: frequency < 2*(sources+9)/10
    /// - Almost rare: frequency < 4*(sources+9)/10
    /// - Common: everything else
    ///
    /// Within each zone: prefer nearest-to-complete, then already-active chunks.
    pub fn select_part(
        &self,
        completed: &[bool],
        in_progress: &[bool],
        source_available: &[bool],
        active_parts: &[usize],
    ) -> Option<usize> {
        let s = self.total_sources as u32;
        let t1 = (s + 9) / 10;
        let t2 = 2 * t1;
        let t3 = 4 * t1;

        let mut candidates: Vec<(usize, u32)> = Vec::new();

        for i in 0..self.part_frequency.len() {
            if completed.get(i).copied().unwrap_or(true) {
                continue;
            }
            if in_progress.get(i).copied().unwrap_or(false) {
                continue;
            }
            if !source_available.get(i).copied().unwrap_or(true) {
                continue;
            }

            let freq = self.part_frequency[i] as u32;
            let zone = if freq < t1 {
                0 // very rare
            } else if freq < t2 {
                1 // rare
            } else if freq < t3 {
                2 // almost rare
            } else {
                3 // common
            };

            let active_bonus = if active_parts.contains(&i) { 0u32 } else { 1 };

            // Lower score = higher priority
            let score = zone * 1000 + active_bonus * 100 + freq;
            candidates.push((i, score));
        }

        candidates.sort_by_key(|&(_, score)| score);
        candidates.first().map(|&(idx, _)| idx)
    }
}
