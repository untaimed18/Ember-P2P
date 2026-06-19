use super::messages::PARTSIZE;
use super::multi_source::DownloadSource;

/// Rarest-first chunk selection matching eMule's CPartFile::GetNextRequestedBlock.
/// Categorizes parts into 4 rarity zones based on source frequency counts.
pub struct ChunkSelector {
    pub part_frequency: Vec<u16>,
    pub total_sources: u16,
}

impl ChunkSelector {
    pub fn new(part_count: usize) -> Self {
        Self {
            part_frequency: vec![0; part_count],
            total_sources: 0,
        }
    }

    /// Recalculate per-part frequency from all source availability maps.
    ///
    /// `total_sources` counts only sources that already carry an availability
    /// map (non-empty `available_parts`). Server/KAD-discovered sources start
    /// with an empty map and are counted later, exactly once, when they learn
    /// their `FileStatus` on the wire (the `!had_preexisting_availability`
    /// branch in `multi_source`). Counting every source here as well would
    /// double-count those, inflating `total_sources` and skewing the
    /// rarest-first rarity zones toward "common".
    pub fn update_frequencies(&mut self, sources: &[DownloadSource]) {
        let part_count = self.part_frequency.len();
        self.part_frequency.fill(0);
        let mut counted = 0usize;

        for source in sources {
            if !source.available_parts.is_empty() {
                counted += 1;
            }
            for (i, &has) in source.available_parts.iter().enumerate() {
                if i < part_count && has {
                    self.part_frequency[i] = self.part_frequency[i].saturating_add(1);
                }
            }
        }
        self.total_sources = counted.min(u16::MAX as usize) as u16;
    }

    /// Remove a source's contribution from the frequency table.
    /// Called when a source disconnects or completes so that rarity data stays
    /// accurate for subsequent `select_part` calls.
    pub fn remove_source(&mut self, available_parts: &[bool]) {
        for (i, &has) in available_parts.iter().enumerate() {
            if i < self.part_frequency.len() && has && self.part_frequency[i] > 0 {
                self.part_frequency[i] -= 1;
            }
        }
        // Decrement total_sources to mirror the *counting* rule used by
        // `update_frequencies` and the wire-learned increment: a source is
        // counted iff it carries a non-empty availability map. The old guard
        // (decrement only when some part frequency actually dropped) leaked the
        // count whenever a counted source's map was non-empty but all-false —
        // i.e. a peer that advertised having none of the file's parts. That
        // inflated `total_sources` over a long session and skewed the
        // rarest-first rarity zones toward "common".
        if !available_parts.is_empty() {
            self.total_sources = self.total_sources.saturating_sub(1);
        }
    }

    /// Select the best part to download using eMule's 4-tier rarity zones.
    ///
    /// - Very rare: frequency < (sources+9)/10
    /// - Rare: frequency < 2*(sources+9)/10
    /// - Almost rare: frequency < 4*(sources+9)/10
    /// - Common: everything else
    ///
    /// Within each zone: prefer already-active chunks, then nearest-to-complete
    /// (parts with fewer remaining gap bytes), then lowest frequency.
    /// Ties within the same zone and score are broken randomly to prevent
    /// all clients from herding onto the same chunk (eMule-style).
    ///
    /// `part_remaining_gaps` provides per-part remaining bytes (from
    /// `PartTracker::part_gap_bytes_vec`). Pass an empty slice to skip the
    /// nearest-to-completion heuristic.
    ///
    /// When `preview_priority` is true (eMule's SetPreviewPrio), the first and
    /// last parts are returned before any rarity-based selection so that media
    /// files become previewable as quickly as possible.
    ///
    /// When `prefer_higher_availability` is true (endgame: few parts left), ties
    /// bias toward parts held by more sources to reduce duplicate work.
    pub fn select_part(
        &self,
        completed: &[bool],
        in_progress: &[bool],
        source_available: &[bool],
        active_parts: &[usize],
        part_remaining_gaps: &[u64],
        preview_priority: bool,
        prefer_higher_availability: bool,
    ) -> Option<usize> {
        let part_count = self.part_frequency.len();

        if preview_priority && part_count > 0 {
            let last = part_count - 1;
            for &target in &[0, last] {
                if !completed.get(target).copied().unwrap_or(false)
                    && !in_progress.get(target).copied().unwrap_or(false)
                    && source_available.get(target).copied().unwrap_or(false)
                {
                    return Some(target);
                }
            }
        }

        let s = self.total_sources as u32;
        // eMule: limit = max((source_count + 9) / 10, 3)
        let t1 = ((s + 9) / 10).max(3);
        let t2 = 2 * t1;
        let t3 = 4 * t1;

        let mut candidates: Vec<(usize, u32)> = Vec::new();

        for i in 0..part_count {
            if completed.get(i).copied().unwrap_or(false) {
                continue;
            }
            if in_progress.get(i).copied().unwrap_or(false) {
                continue;
            }
            if !source_available.get(i).copied().unwrap_or(false) {
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

            // Nearest-to-completion: 0 (nearly done) .. 100 (empty part).
            // Parts with partial progress are preferred within the same zone.
            let completion_score = if part_remaining_gaps.is_empty() {
                50
            } else {
                let remaining = part_remaining_gaps.get(i).copied().unwrap_or(PARTSIZE);
                ((remaining * 100) / PARTSIZE).min(100) as u32
            };

            // Lower score = higher priority
            let score = if prefer_higher_availability {
                let inv = (self.total_sources as u32).saturating_sub(freq);
                zone * 500 + active_bonus + completion_score / 2 + inv
            } else {
                zone * 1000 + active_bonus + completion_score + u32::from(freq)
            };
            candidates.push((i, score));
        }

        if candidates.is_empty() {
            return None;
        }

        // Sort by score, then randomize among ties (eMule-style anti-herding)
        candidates.sort_by_key(|&(_, score)| score);
        let best_score = candidates[0].1;
        let tie_count = candidates
            .iter()
            .take_while(|&&(_, s)| s == best_score)
            .count();
        if tie_count > 1 {
            use rand::Rng;
            let pick = rand::thread_rng().gen_range(0..tie_count);
            Some(candidates[pick].0)
        } else {
            Some(candidates[0].0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_priority_prefers_first_part() {
        let selector = ChunkSelector {
            part_frequency: vec![5, 1, 1],
            total_sources: 5,
        };

        let selected = selector.select_part(
            &[false, false, false],
            &[false, false, false],
            &[true, true, true],
            &[],
            &[],
            true,
            false,
        );

        assert_eq!(selected, Some(0));
    }

    #[test]
    fn rarest_first_prefers_lowest_frequency_part() {
        let selector = ChunkSelector {
            part_frequency: vec![4, 1, 3],
            total_sources: 4,
        };

        let selected = selector.select_part(
            &[false, false, false],
            &[false, false, false],
            &[true, true, true],
            &[],
            &[],
            false,
            false,
        );

        assert_eq!(selected, Some(1));
    }

    #[test]
    fn active_bonus_breaks_frequency_ties() {
        let selector = ChunkSelector {
            part_frequency: vec![2, 2, 2],
            total_sources: 3,
        };

        let selected = selector.select_part(
            &[false, false, false],
            &[false, false, false],
            &[true, true, true],
            &[2],
            &[],
            false,
            false,
        );

        assert_eq!(selected, Some(2));
    }

    #[test]
    fn nearest_to_completion_preferred_within_same_zone() {
        let selector = ChunkSelector {
            part_frequency: vec![2, 2, 2],
            total_sources: 3,
        };

        // Part 1 is 90% done (970K remaining), part 0 and 2 are empty
        let gaps = vec![PARTSIZE, 970_000, PARTSIZE];

        let selected = selector.select_part(
            &[false, false, false],
            &[false, false, false],
            &[true, true, true],
            &[],
            &gaps,
            false,
            false,
        );

        assert_eq!(selected, Some(1));
    }
}
