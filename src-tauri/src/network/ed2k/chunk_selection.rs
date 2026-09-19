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

    /// Add a source's contribution to the frequency table — the exact inverse
    /// of [`Self::remove_source`].
    ///
    /// Every dial that will `remove_source` on exit has to pair with one of
    /// these on entry. [`Self::update_frequencies`] covers only the sources
    /// present when the selector is built, and only for their *first* dial: a
    /// retry round re-dials a source whose previous task already removed its
    /// contribution, and an injected or adopted source was never counted at
    /// all. Unpaired, the table drains monotonically toward zero — at which
    /// point `select_part` scores every part in the "very rare" zone and
    /// rarest-first stops discriminating between parts entirely.
    pub fn add_source(&mut self, available_parts: &[bool]) {
        if available_parts.is_empty() {
            return;
        }
        for (i, &has) in available_parts.iter().enumerate() {
            if i < self.part_frequency.len() && has {
                self.part_frequency[i] = self.part_frequency[i].saturating_add(1);
            }
        }
        self.total_sources = self.total_sources.saturating_add(1);
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

        // Which parts preview wants first, if it is on at all.
        //
        // eMule's set also includes the second-to-last part when the tail is
        // shorter than a third of a part (`PartFile.cpp:4707-4711`), so the
        // player reaches enough of the container's trailing index to start.
        // That case is not reproduced here: it needs the file size, which this
        // selector does not carry, and the ranking fix below is what actually
        // mattered. Recorded rather than silently omitted.
        let is_preview_target = |i: usize| {
            preview_priority && part_count > 0 && (i == 0 || i == part_count - 1)
        };

        let s = self.total_sources as u32;
        // eMule: limit = max((source_count + 9) / 10, 3)
        let t1 = ((s + 9) / 10).max(3);
        let t2 = 2 * t1;
        let t3 = 4 * t1;

        // Lexicographic priority key, every term "lower is better":
        // `(zone, not_active, completion_score, rarity)`.
        //
        // These used to be summed into one scalar, which is NOT the order
        // documented above: `completion_score` (0..100) already outvoted the
        // 50-point active bonus, and once `total_sources` passed ~1000 the
        // in-zone `freq` term swamped both, drifting scheduling toward raw
        // rarity and leaving more partially-complete parts in flight on
        // popular files. A tuple comparison makes the tie-break genuinely
        // lexicographic and needs no weight normalisation.
        let mut candidates: Vec<(usize, (u32, u8, u32, u32))> = Vec::new();

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
            // Inclusive bounds, as eMule's are: it tests
            // `cur_chunk.frequency <= veryRareBound` and the same for the other
            // two zones (`PartFile.cpp:4816`, `:4829`, `:4838`). With strict
            // `<`, a part sitting exactly on a boundary was scored one zone
            // *less* rare than eMule would score it.
            // Preview is a band, not an override. It used to return the first
            // or last part immediately, before rarity was computed at all — so
            // with preview on, a part the swarm was starved of lost to one the
            // user might watch sooner, and stayed rare for longer.
            //
            // eMule ranks it below very-rare and above everything else: its
            // `else if` chain tests `frequency <= veryRareBound` first
            // (`PartFile.cpp:4816`) and only then `critPreview` (`:4824`), and
            // the base ranks say the same thing numerically — 3000/3001 for
            // very rare against 10000/20000 for preview. So preview sits
            // between zone 0 and zone 1, which is what this half-step does
            // while leaving the existing zone numbering alone.
            let zone = if freq <= t1 {
                0 // very rare — beats preview, as in eMule
            } else if is_preview_target(i) {
                1 // preview
            } else if freq <= t2 {
                2 // rare
            } else if freq <= t3 {
                3 // almost rare
            } else {
                4 // common
            };

            let not_active = u8::from(!active_parts.contains(&i));

            // Nearest-to-completion: 0 (nearly done) .. 100 (empty part).
            // Parts with partial progress are preferred within the same zone.
            let completion_score = if part_remaining_gaps.is_empty() {
                50
            } else {
                let remaining = part_remaining_gaps.get(i).copied().unwrap_or(PARTSIZE);
                ((remaining * 100) / PARTSIZE).min(100) as u32
            };

            // Final tie-break only. Normally the rarest part wins; in the
            // endgame the sense inverts, because piling onto a part many
            // sources hold finishes the file sooner than chasing the rare one.
            let rarity = if prefer_higher_availability {
                (self.total_sources as u32).saturating_sub(freq)
            } else {
                freq
            };
            candidates.push((i, (zone, not_active, completion_score, rarity)));
        }

        if candidates.is_empty() {
            return None;
        }

        // Sort by key, then randomize among ties (eMule-style anti-herding)
        candidates.sort_by_key(|&(_, key)| key);
        let best_key = candidates[0].1;
        let tie_count = candidates
            .iter()
            .take_while(|&&(_, k)| k == best_key)
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
        // Nothing here is very rare (t1 floors at 3, every part is at 10), so
        // preview is the highest band in play and takes the first part. The
        // last part is marked done so the only preview candidate left is 0 and
        // the random tie-break cannot pick the other one.
        let selector = ChunkSelector {
            part_frequency: vec![10, 10, 10],
            total_sources: 10,
        };

        let selected = selector.select_part(
            &[false, false, true],
            &[false, false, false],
            &[true, true, true],
            &[],
            &[],
            true,
            false,
        );

        assert_eq!(selected, Some(0));
    }

    /// Preview is a band, not an override. eMule tests
    /// `frequency <= veryRareBound` *before* `critPreview`
    /// (`PartFile.cpp:4816` against `:4824`) and ranks them 3000/3001 against
    /// 10000/20000, so a part the swarm is starved of always outranks one the
    /// user might watch sooner. Ember used to return the first or last part
    /// immediately, before rarity was computed at all, which left rare parts
    /// rare for longer on exactly the files most likely to have preview on.
    #[test]
    fn a_very_rare_part_outranks_a_preview_part() {
        // t1 = max((9 + 9) / 10, 3) = 3, so part 1 is very rare and parts 0
        // and 2 — the preview targets — are not.
        let selector = ChunkSelector {
            part_frequency: vec![9, 1, 9],
            total_sources: 9,
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

        assert_eq!(
            selected,
            Some(1),
            "the scarcest part must still win when preview priority is on"
        );
    }

    /// The shape that deadlocked a download at 0%: five parts, and every source
    /// holds only part 2, which one of them has claimed while sitting at a queue
    /// rank. A strict pass alone turns the rest away — and the callers reported
    /// that as "no needed parts", about peers demonstrably holding a part that was
    /// needed. Every caller now falls back to treating parts as free, so the pass
    /// modelled here is what has to succeed.
    #[test]
    fn a_claimed_part_is_still_offered_when_it_is_all_a_source_has() {
        let selector = ChunkSelector {
            part_frequency: vec![0, 0, 4, 0, 0],
            total_sources: 4,
        };
        let completed = [false; 5];
        let only_part_2 = [false, false, true, false, false];
        let claimed = [false, false, true, false, false];

        // Strict: the one part this source has is already claimed, so nothing.
        assert_eq!(
            selector.select_part(&completed, &claimed, &only_part_2, &[2], &[], false, false),
            None,
            "strict selection is expected to refuse — that is why callers retry"
        );

        // Relaxed, which is the retry every caller now performs.
        let free = [false; 5];
        assert_eq!(
            selector.select_part(&completed, &free, &only_part_2, &[2], &[], false, false),
            Some(2),
            "a source whose only part is claimed must still be given it, or a swarm \
             where every peer holds the same part can never start"
        );
    }

    /// Every dial removes its source's contribution when the task exits, so
    /// every dial has to add it back on entry. Without the pairing the table
    /// only ever drains: by the retry rounds `total_sources` is 0, every part
    /// lands in the "very rare" zone, and rarest-first stops discriminating.
    #[test]
    fn add_source_is_the_exact_inverse_of_remove_source() {
        let source = |available_parts: Vec<bool>| DownloadSource {
            peer_ip: "10.0.0.1".to_string(),
            peer_port: 4662,
            available_parts,
            peer_user_hash: None,
            peer_connect_options: None,
        };
        let sources = [
            source(vec![true, false, true]),
            source(vec![true, true, false]),
        ];

        let mut selector = ChunkSelector::new(3);
        selector.update_frequencies(&sources);
        let seeded = (selector.part_frequency.clone(), selector.total_sources);
        assert_eq!(seeded.1, 2);

        // A source's task exits, then a retry round re-dials it.
        selector.remove_source(&sources[0].available_parts);
        assert_ne!(
            (selector.part_frequency.clone(), selector.total_sources),
            seeded,
            "the removal has to actually change the table"
        );
        selector.add_source(&sources[0].available_parts);
        assert_eq!(
            (selector.part_frequency.clone(), selector.total_sources),
            seeded,
            "a re-dial must restore exactly what the previous exit removed"
        );

        // Repeated rounds must not drift the table either way.
        for _ in 0..8 {
            selector.remove_source(&sources[1].available_parts);
            selector.add_source(&sources[1].available_parts);
        }
        assert_eq!(
            (selector.part_frequency, selector.total_sources),
            seeded,
            "rarest-first must survive an arbitrary number of retry rounds"
        );
    }

    /// Adding twice and removing once leaves the table permanently inflated,
    /// which skews `select_part`'s rarity zones exactly as far the other way as
    /// an unpaired remove does. Each dial site must add once and remove once.
    #[test]
    fn a_doubled_add_is_not_undone_by_a_single_remove() {
        let avail = vec![true, false, true];
        let mut selector = ChunkSelector::new(3);

        selector.add_source(&avail);
        let balanced = (selector.part_frequency.clone(), selector.total_sources);

        selector.add_source(&avail);
        selector.remove_source(&avail);
        assert_eq!(
            (selector.part_frequency.clone(), selector.total_sources),
            balanced,
            "two adds against one remove must be visible as drift, not absorbed"
        );

        // And the drift is upward, not a wash.
        selector.add_source(&avail);
        assert_ne!(
            (selector.part_frequency, selector.total_sources),
            balanced
        );
    }

    /// An empty availability map means "this source has not answered yet", and
    /// `update_frequencies` does not count it — so neither side of the pair may.
    #[test]
    fn an_empty_availability_map_is_not_counted() {
        let mut selector = ChunkSelector::new(3);
        selector.add_source(&[]);
        assert_eq!(selector.total_sources, 0);
        assert_eq!(selector.part_frequency, vec![0, 0, 0]);
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

    /// L1: the documented order is active first, THEN nearest-to-complete.
    /// The old summed score gave the active chunk 50 points and completion up
    /// to 100, so a nearly-finished inactive part outvoted a part a source was
    /// already working on.
    #[test]
    fn active_chunk_outranks_a_nearer_to_complete_inactive_one() {
        let selector = ChunkSelector {
            part_frequency: vec![2, 2],
            total_sources: 3,
        };

        // Part 0 is active but empty; part 1 is 90% done with nobody on it.
        let gaps = vec![PARTSIZE, PARTSIZE / 10];

        let selected = selector.select_part(
            &[false, false],
            &[false, false],
            &[true, true],
            &[0],
            &gaps,
            false,
            false,
        );

        assert_eq!(selected, Some(0));
    }

    /// ...and frequency is only the last tie-break. With ~2000 sources the old
    /// summed score let the in-zone `freq` term (up to `t1 - 1`) swamp both the
    /// active bonus and the completion score, so scheduling drifted toward raw
    /// rarity and left more half-finished parts in flight.
    #[test]
    fn frequency_only_breaks_ties_among_otherwise_equal_candidates() {
        let popular = ChunkSelector {
            part_frequency: vec![199, 0],
            total_sources: 2000,
        };
        // Both parts land in the "very rare" zone (t1 = 200). Part 0 is nearly
        // done but held by 199 sources; part 1 is empty and held by none.
        let gaps = vec![PARTSIZE / 100, PARTSIZE];
        assert_eq!(
            popular.select_part(
                &[false, false],
                &[false, false],
                &[true, true],
                &[],
                &gaps,
                false,
                false,
            ),
            Some(0),
            "nearest-to-complete must outrank rarity"
        );

        // Same zone, none active, identical completion: now rarity decides.
        let tied = ChunkSelector {
            part_frequency: vec![7, 5, 9],
            total_sources: 2000,
        };
        let equal_gaps = vec![PARTSIZE, PARTSIZE, PARTSIZE];
        assert_eq!(
            tied.select_part(
                &[false, false, false],
                &[false, false, false],
                &[true, true, true],
                &[],
                &equal_gaps,
                false,
                false,
            ),
            Some(1),
        );
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
