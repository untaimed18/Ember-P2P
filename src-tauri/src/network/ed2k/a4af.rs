use std::collections::HashMap;
use std::net::SocketAddr;

/// Per-file cap on retained A4AF candidates.
const MAX_A4AF_ENTRIES_PER_FILE: usize = 500;

/// eMule PURGESOURCESWAPSTOP: minimum time between swaps for the same source (15 min).
/// Applied to peers that are actively transferring — keeps us protocol-compatible
/// with eMule's swap pacing and avoids hammering peers with re-asks.
const PURGE_SOURCE_SWAP_STOP_SECS: i64 = 15 * 60;

/// Shorter swap cooldown for sources whose currently-assigned file is
/// **starved** (zero active sources for it). Since the peer isn't actively
/// uploading to us anyway, the protocol-etiquette argument for the long
/// cooldown doesn't apply — we're just deciding which queue to wait in.
/// 2 minutes is well above any peer's queue-recalculation interval, so we
/// don't generate spurious re-ask traffic, but it's an order of magnitude
/// faster than the 15-minute default for when the user adds a new file
/// and wants peers to migrate over.
const STARVED_SWAP_STOP_SECS: i64 = 2 * 60;

/// A4AF (Asked For Another File) source management.
/// Tracks sources that are known to have files we want but are currently
/// assigned to a different download.
#[derive(Debug, Clone)]
pub struct A4AFEntry {
    pub peer_addr: SocketAddr,
    pub assigned_file_hash: [u8; 16],
    pub added_time: i64,
    /// Last time this source was swapped (eMule suspension timing)
    pub last_swap_time: i64,
    /// Queue rank on the assigned file (0 = unknown)
    pub queue_rank: u16,
    /// Whether we have needed parts from the assigned file (NNP = No Needed Parts)
    pub has_needed_parts: bool,
    /// Credit ratio for this peer (uploaded/downloaded ratio factor)
    pub credit_ratio: f64,
}

/// Candidates are keyed by peer address rather than held in a `Vec`, because
/// every mutating operation here is "find this one peer": the duplicate check
/// in [`A4AFManager::add_a4af_source`], the per-file probe in
/// [`A4AFManager::update_source_state`], and the removal in
/// [`A4AFManager::remove_source`]. As a `Vec` each of those was a linear scan
/// over up to [`MAX_A4AF_ENTRIES_PER_FILE`] entries, which the periodic NNP
/// sweep then paid once per (source × file) pair.
pub struct A4AFManager {
    a4af_sources: HashMap<[u8; 16], HashMap<SocketAddr, A4AFEntry>>,
}

#[derive(Debug, Clone)]
pub struct SwapAction {
    pub peer_addr: SocketAddr,
    pub from_file: [u8; 16],
    pub to_file: [u8; 16],
}

/// Extended file info for swap decisions, matching eMule's SwapToRightFile logic.
#[derive(Debug, Clone)]
pub struct FileSwapInfo {
    pub priority: u32,
    pub active_source_count: usize,
    pub has_needed_parts: bool,
}

impl A4AFManager {
    pub fn new() -> Self {
        Self {
            a4af_sources: HashMap::new(),
        }
    }

    /// Record `peer_addr` as a candidate for `file_hash` while it is currently
    /// working on `assigned_file_hash`.
    ///
    /// `has_needed_parts_on_assigned` is the peer's usefulness to the file it is
    /// already on, and it is the input [`evaluate_swap`] leans on hardest: a
    /// source that has nothing left to give its current file is the one eMule
    /// retasks first (`CPartFile::Process` hands every `DS_NONEEDEDPARTS` source
    /// to `SwapToAnotherFile`, `PartFile.cpp:2320-2324`). It is a parameter
    /// rather than a default because only the caller knows — the NNP sweep adds
    /// sources precisely *because* they have run dry, while a peer that merely
    /// asked us for a different file has not.
    pub fn add_a4af_source(
        &mut self,
        file_hash: [u8; 16],
        peer_addr: SocketAddr,
        assigned_file_hash: [u8; 16],
        has_needed_parts_on_assigned: bool,
    ) {
        let entries = self.a4af_sources.entry(file_hash).or_default();
        let full = entries.len() >= MAX_A4AF_ENTRIES_PER_FILE;
        if let std::collections::hash_map::Entry::Vacant(slot) = entries.entry(peer_addr) {
            if full {
                return;
            }
            slot.insert(A4AFEntry {
                peer_addr,
                assigned_file_hash,
                added_time: chrono::Utc::now().timestamp(),
                last_swap_time: 0,
                queue_rank: 0,
                has_needed_parts: has_needed_parts_on_assigned,
                credit_ratio: 1.0,
            });
        }
    }

    /// Offer every source in `dry_sources` to every file in `targets` other
    /// than the one that source is already assigned to.
    ///
    /// This is the periodic NNP sweep, and it is the only caller that runs at
    /// (targets × sources) scale, so it is a method rather than a loop over
    /// [`A4AFManager::add_a4af_source`] at the call site: the target's map is
    /// resolved once per target instead of once per pair, a target already at
    /// [`MAX_A4AF_ENTRIES_PER_FILE`] is abandoned rather than probed for every
    /// remaining source, and the clock is read once for the whole pass instead
    /// of once per insert.
    ///
    /// Callers should de-duplicate `dry_sources` by address first. A peer that
    /// has run dry on several files is still just one candidate per target,
    /// and feeding the raw per-file lists in multiplies the pass by the
    /// average number of files a peer appears on for no added coverage.
    pub fn offer_dry_sources(
        &mut self,
        targets: &[[u8; 16]],
        dry_sources: &[(SocketAddr, [u8; 16])],
    ) {
        if targets.is_empty() || dry_sources.is_empty() {
            return;
        }
        let now = chrono::Utc::now().timestamp();
        for target in targets {
            let entries = self.a4af_sources.entry(*target).or_default();
            if entries.len() >= MAX_A4AF_ENTRIES_PER_FILE {
                continue;
            }
            for (peer_addr, assigned_file_hash) in dry_sources {
                if assigned_file_hash == target {
                    continue;
                }
                if entries.len() >= MAX_A4AF_ENTRIES_PER_FILE {
                    break;
                }
                entries.entry(*peer_addr).or_insert(A4AFEntry {
                    peer_addr: *peer_addr,
                    assigned_file_hash: *assigned_file_hash,
                    added_time: now,
                    last_swap_time: 0,
                    queue_rank: 0,
                    // This sweep selects on `NoneNeededParts`, so by
                    // construction the peer has nothing left for the file it
                    // is on — which is the whole reason to retask it.
                    has_needed_parts: false,
                    credit_ratio: 1.0,
                });
            }
        }
        // `entry().or_default()` above materialises a map for every target,
        // including ones that gained nothing because each source was already
        // assigned to them.
        self.a4af_sources.retain(|_, v| !v.is_empty());
    }

    /// Update queue rank and NNP state for a peer on one specific file.
    ///
    /// `assigned_file_hash` scopes the update, because every field here is about
    /// the peer's relationship to *that* file: `queue_rank` is its position in
    /// that file's queue and `has_needed_parts` is whether it still has bytes
    /// that file wants. This used to walk every entry for the peer regardless of
    /// file, so a peer queued on one download overwrote its own record for a
    /// different download — including the "has run dry" flag that decides
    /// whether it gets retasked at all.
    pub fn update_source_state(
        &mut self,
        peer_addr: SocketAddr,
        assigned_file_hash: [u8; 16],
        queue_rank: u16,
        has_needed_parts: bool,
        credit_ratio: f64,
    ) {
        for entries in self.a4af_sources.values_mut() {
            if let Some(entry) = entries.get_mut(&peer_addr) {
                if entry.assigned_file_hash == assigned_file_hash {
                    entry.queue_rank = queue_rank;
                    entry.has_needed_parts = has_needed_parts;
                    entry.credit_ratio = credit_ratio;
                }
            }
        }
    }

    /// Sources registered as candidates for `file_hash` while working on another
    /// file — eMule's `GetSrcA4AFCount()`, the `+aa` term of the Sources column
    /// (`DownloadListCtrl.cpp:2005-2006`). It tells the user a file has reachable
    /// peers that a priority decision is currently spending elsewhere.
    pub fn a4af_count(&self, file_hash: &[u8; 16]) -> usize {
        self.a4af_sources
            .get(file_hash)
            .map(|entries| {
                entries
                    .values()
                    .filter(|e| e.assigned_file_hash != *file_hash)
                    .count()
            })
            .unwrap_or(0)
    }

    pub fn remove_source(&mut self, peer_addr: SocketAddr) {
        for entries in self.a4af_sources.values_mut() {
            entries.remove(&peer_addr);
        }
        self.a4af_sources.retain(|_, v| !v.is_empty());
    }

    /// Evaluate swap decisions matching eMule's SwapToRightFile logic:
    /// - Suspension timing: don't swap if swapped within PURGESOURCESWAPSTOP (15 min)
    /// - NNP awareness: aggressively swap away from files where we have no needed parts
    /// - Queue rank: peers with low rank (<=50) on current file are less likely to swap
    /// - Credit weighting: higher-credit peers are more valuable to keep
    /// - Source count: prefer files with fewer active sources
    pub fn process_swaps(&self, file_info: &HashMap<[u8; 16], FileSwapInfo>) -> Vec<SwapAction> {
        let mut swaps = Vec::new();
        let now = chrono::Utc::now().timestamp();

        for (target_hash, entries) in &self.a4af_sources {
            let target = match file_info.get(target_hash) {
                Some(p) => p,
                None => continue,
            };

            for entry in entries.values() {
                // Suspension: don't re-swap too quickly. Starved-target
                // override: when the file we want to swap *to* has zero
                // active sources, drop the cooldown to STARVED_SWAP_STOP_SECS
                // so a file the user just added can pull peers in
                // promptly. Still honours a cooldown to avoid re-ask spam.
                let cooldown_secs = if target.active_source_count == 0 {
                    STARVED_SWAP_STOP_SECS
                } else {
                    PURGE_SOURCE_SWAP_STOP_SECS
                };
                if entry.last_swap_time > 0 && now - entry.last_swap_time < cooldown_secs {
                    continue;
                }

                let assigned = match file_info.get(&entry.assigned_file_hash) {
                    Some(p) => p,
                    None => continue,
                };

                let should_swap = evaluate_swap(
                    target,
                    assigned,
                    entry.queue_rank,
                    entry.has_needed_parts,
                    entry.credit_ratio,
                );

                if should_swap {
                    swaps.push(SwapAction {
                        peer_addr: entry.peer_addr,
                        from_file: entry.assigned_file_hash,
                        to_file: *target_hash,
                    });
                }
            }
        }

        swaps
    }

    /// Mark a source as recently swapped (resets suspension timer).
    pub fn mark_swapped(&mut self, peer_addr: SocketAddr) {
        let now = chrono::Utc::now().timestamp();
        for entries in self.a4af_sources.values_mut() {
            if let Some(entry) = entries.get_mut(&peer_addr) {
                entry.last_swap_time = now;
            }
        }
    }

    /// Check if a source currently assigned to `current_file` is registered as
    /// an A4AF candidate for any other file (i.e., it may be swapped away).
    pub fn is_swap_candidate(&self, peer_addr: SocketAddr, current_file: &[u8; 16]) -> bool {
        for (target_hash, entries) in &self.a4af_sources {
            if target_hash == current_file {
                continue;
            }
            if entries
                .get(&peer_addr)
                .is_some_and(|e| e.assigned_file_hash == *current_file)
            {
                return true;
            }
        }
        false
    }

    pub fn cleanup_stale(&mut self, max_age_secs: i64) {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        for entries in self.a4af_sources.values_mut() {
            entries.retain(|_, e| e.added_time > cutoff);
        }
        self.a4af_sources.retain(|_, v| !v.is_empty());
    }
}

/// eMule-style swap evaluation matching SwapToRightFile logic.
/// `credit_ratio` > 1.0 means this peer has given us more than we've given them;
/// higher-credit peers are more valuable to keep on their current assignment.
fn evaluate_swap(
    target: &FileSwapInfo,
    assigned: &FileSwapInfo,
    queue_rank: u16,
    has_needed_parts_on_assigned: bool,
    credit_ratio: f64,
) -> bool {
    // NNP: aggressively swap away from files where we don't need anything
    if !has_needed_parts_on_assigned && target.has_needed_parts {
        return true;
    }

    // Don't swap away from a file where we have a good queue position
    if queue_rank > 0 && queue_rank <= 50 && has_needed_parts_on_assigned {
        return false;
    }

    // High-credit peers are less likely to be swapped: require the target to
    // have meaningfully fewer sources before swapping a valuable peer away.
    let source_advantage = assigned
        .active_source_count
        .saturating_sub(target.active_source_count + 1);
    if credit_ratio > 5.0 && source_advantage < 3 && has_needed_parts_on_assigned {
        return false;
    }

    // Higher priority target always wins
    if target.priority > assigned.priority {
        return true;
    }

    // Same priority: prefer the file with fewer sources
    if target.priority == assigned.priority && source_advantage > 0 {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const FILE_A: [u8; 16] = [0xAA; 16];
    const FILE_B: [u8; 16] = [0xBB; 16];

    fn peer(last_octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last_octet)), 4662)
    }

    fn downloading(priority: u32, active_sources: usize) -> FileSwapInfo {
        FileSwapInfo {
            priority,
            active_source_count: active_sources,
            has_needed_parts: true,
        }
    }

    /// The engine's whole job. A source that has run dry on file B, while file A
    /// still wants bytes, is the case eMule retasks on every `Process()` pass.
    ///
    /// This used to produce nothing at all, because the caller's file map was
    /// built only from *pending* downloads while candidates are harvested from
    /// *active* ones — `process_swaps` needs both the target and the assigned
    /// file present, and neither was. A map missing either side still silently
    /// yields no swaps, which is what the second half of this test pins.
    #[test]
    fn a_source_that_has_run_dry_is_retasked_to_a_file_that_still_wants_bytes() {
        let mut a4af = A4AFManager::new();
        a4af.add_a4af_source(FILE_A, peer(1), FILE_B, false);

        let mut files = HashMap::new();
        files.insert(FILE_A, downloading(7, 0));
        files.insert(FILE_B, downloading(7, 4));

        let swaps = a4af.process_swaps(&files);
        assert_eq!(swaps.len(), 1, "the dry source must be offered to file A");
        assert_eq!(swaps[0].peer_addr, peer(1));
        assert_eq!(swaps[0].from_file, FILE_B);
        assert_eq!(swaps[0].to_file, FILE_A);

        // Either side missing from the map disables the swap entirely — the
        // shape of the original bug.
        let only_target: HashMap<_, _> = [(FILE_A, downloading(7, 0))].into_iter().collect();
        assert!(a4af.process_swaps(&only_target).is_empty());
        let only_assigned: HashMap<_, _> = [(FILE_B, downloading(7, 4))].into_iter().collect();
        assert!(a4af.process_swaps(&only_assigned).is_empty());
    }

    /// A peer is usually a source for several of our files at once — that is why
    /// A4AF exists. Its queue position and "has run dry" flag are per file, so an
    /// update about one download must not rewrite its record for another.
    #[test]
    fn a_status_update_only_touches_the_file_it_describes() {
        let mut a4af = A4AFManager::new();
        // The same peer is a candidate for A while dry on B, and a candidate for
        // B while working on A.
        a4af.add_a4af_source(FILE_A, peer(1), FILE_B, false);
        a4af.add_a4af_source(FILE_B, peer(1), FILE_A, true);

        // News about file A: still useful there, good queue position.
        a4af.update_source_state(peer(1), FILE_A, 10, true, 1.0);

        let entry_b = a4af.a4af_sources[&FILE_A]
            .values()
            .find(|e| e.assigned_file_hash == FILE_B)
            .expect("the B-assigned entry survives");
        assert!(
            !entry_b.has_needed_parts,
            "an update about file A must not claim the peer still has parts for B"
        );
        assert_eq!(entry_b.queue_rank, 0, "nor overwrite B's queue position");

        let entry_a = a4af.a4af_sources[&FILE_B]
            .values()
            .find(|e| e.assigned_file_hash == FILE_A)
            .expect("the A-assigned entry is the one updated");
        assert_eq!(entry_a.queue_rank, 10);
    }

    /// `+aa` in the Sources column: peers held for this file while working on
    /// another. Every construction site set the transfer field to zero and
    /// nothing wrote it, so the segment never appeared.
    #[test]
    fn a4af_count_reports_candidates_held_for_a_file() {
        let mut a4af = A4AFManager::new();
        assert_eq!(a4af.a4af_count(&FILE_A), 0);

        a4af.add_a4af_source(FILE_A, peer(1), FILE_B, false);
        a4af.add_a4af_source(FILE_A, peer(2), FILE_B, false);
        assert_eq!(a4af.a4af_count(&FILE_A), 2);
        assert_eq!(a4af.a4af_count(&FILE_B), 0);

        // A duplicate peer is one candidate, not two.
        a4af.add_a4af_source(FILE_A, peer(1), FILE_B, false);
        assert_eq!(a4af.a4af_count(&FILE_A), 2);
    }

    /// The bulk sweep must agree with the one-at-a-time path: a dry source is
    /// offered to every file except the one it is already on, exactly once.
    #[test]
    fn offer_dry_sources_matches_per_call_adds_and_skips_the_assigned_file() {
        const FILE_C: [u8; 16] = [0xCC; 16];
        let mut bulk = A4AFManager::new();
        bulk.offer_dry_sources(
            &[FILE_A, FILE_B, FILE_C],
            &[(peer(1), FILE_B), (peer(2), FILE_C)],
        );

        let mut individual = A4AFManager::new();
        for (p, assigned) in [(peer(1), FILE_B), (peer(2), FILE_C)] {
            for target in [FILE_A, FILE_B, FILE_C] {
                if target != assigned {
                    individual.add_a4af_source(target, p, assigned, false);
                }
            }
        }

        for file in [FILE_A, FILE_B, FILE_C] {
            assert_eq!(
                bulk.a4af_count(&file),
                individual.a4af_count(&file),
                "bulk and per-call paths must agree for {}",
                hex::encode(file)
            );
        }
        assert_eq!(bulk.a4af_count(&FILE_A), 2, "both peers are dry elsewhere");
        assert_eq!(bulk.a4af_count(&FILE_B), 1, "peer 1 is already on B");
        assert_eq!(bulk.a4af_count(&FILE_C), 1, "peer 2 is already on C");

        // Re-running the sweep is idempotent rather than duplicating.
        bulk.offer_dry_sources(
            &[FILE_A, FILE_B, FILE_C],
            &[(peer(1), FILE_B), (peer(2), FILE_C)],
        );
        assert_eq!(bulk.a4af_count(&FILE_A), 2);
    }

    /// The per-file cap has to hold under the bulk path too, otherwise the
    /// sweep is an unbounded insert driven by remote source lists.
    #[test]
    fn offer_dry_sources_honours_the_per_file_cap() {
        let dry: Vec<(SocketAddr, [u8; 16])> = (0..(MAX_A4AF_ENTRIES_PER_FILE + 50))
            .map(|i| {
                let addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(10, (i >> 8) as u8, (i & 0xFF) as u8, 1)),
                    4662,
                );
                (addr, FILE_B)
            })
            .collect();

        let mut a4af = A4AFManager::new();
        a4af.offer_dry_sources(&[FILE_A], &dry);
        assert_eq!(a4af.a4af_count(&FILE_A), MAX_A4AF_ENTRIES_PER_FILE);
    }
}
