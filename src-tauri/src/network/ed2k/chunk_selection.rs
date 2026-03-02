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
    /// Ties within the same zone and score are broken randomly to prevent
    /// all clients from herding onto the same chunk (eMule-style).
    ///
    /// When `preview_priority` is true (eMule's SetPreviewPrio), the first and
    /// last parts are returned before any rarity-based selection so that media
    /// files become previewable as quickly as possible.
    pub fn select_part(
        &self,
        completed: &[bool],
        in_progress: &[bool],
        source_available: &[bool],
        active_parts: &[usize],
        preview_priority: bool,
    ) -> Option<usize> {
        let part_count = self.part_frequency.len();

        if preview_priority && part_count > 0 {
            let last = part_count - 1;
            for &target in &[0, last] {
                if !completed.get(target).copied().unwrap_or(true)
                    && !in_progress.get(target).copied().unwrap_or(false)
                    && source_available.get(target).copied().unwrap_or(true)
                {
                    return Some(target);
                }
            }
        }

        let s = self.total_sources as u32;
        let t1 = (s + 9) / 10;
        let t2 = 2 * t1;
        let t3 = 4 * t1;

        let mut candidates: Vec<(usize, u32)> = Vec::new();

        for i in 0..part_count {
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

            let active_bonus = if active_parts.contains(&i) { 0u32 } else { 50 };

            // Lower score = higher priority
            let score = zone * 1000 + active_bonus + freq;
            candidates.push((i, score));
        }

        if candidates.is_empty() {
            return None;
        }

        // Sort by score, then randomize among ties (eMule-style anti-herding)
        candidates.sort_by_key(|&(_, score)| score);
        let best_score = candidates[0].1;
        let tie_count = candidates.iter().take_while(|&&(_, s)| s == best_score).count();
        if tie_count > 1 {
            let pick = (rand::random::<u32>() as usize) % tie_count;
            Some(candidates[pick].0)
        } else {
            Some(candidates[0].0)
        }
    }
}
