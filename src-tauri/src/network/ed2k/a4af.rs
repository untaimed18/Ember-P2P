use std::collections::HashMap;
use std::net::SocketAddr;

/// eMule PURGESOURCESWAPSTOP: minimum time between swaps for the same source (15 min)
const PURGE_SOURCE_SWAP_STOP_SECS: i64 = 15 * 60;

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

pub struct A4AFManager {
    a4af_sources: HashMap<[u8; 16], Vec<A4AFEntry>>,
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

    pub fn add_a4af_source(
        &mut self,
        file_hash: [u8; 16],
        peer_addr: SocketAddr,
        assigned_file_hash: [u8; 16],
    ) {
        let entries = self.a4af_sources.entry(file_hash).or_default();

        if entries.iter().any(|e| e.peer_addr == peer_addr) {
            return;
        }

        if entries.len() >= 500 {
            return;
        }

        entries.push(A4AFEntry {
            peer_addr,
            assigned_file_hash,
            added_time: chrono::Utc::now().timestamp(),
            last_swap_time: 0,
            queue_rank: 0,
            has_needed_parts: true,
            credit_ratio: 1.0,
        });
    }

    /// Update queue rank and NNP state for a peer (called from download loop).
    pub fn update_source_state(
        &mut self,
        peer_addr: SocketAddr,
        queue_rank: u16,
        has_needed_parts: bool,
        credit_ratio: f64,
    ) {
        for entries in self.a4af_sources.values_mut() {
            for entry in entries.iter_mut() {
                if entry.peer_addr == peer_addr {
                    entry.queue_rank = queue_rank;
                    entry.has_needed_parts = has_needed_parts;
                    entry.credit_ratio = credit_ratio;
                }
            }
        }
    }

    pub fn remove_source(&mut self, peer_addr: SocketAddr) {
        for entries in self.a4af_sources.values_mut() {
            entries.retain(|e| e.peer_addr != peer_addr);
        }
        self.a4af_sources.retain(|_, v| !v.is_empty());
    }

    /// Evaluate swap decisions matching eMule's SwapToRightFile logic:
    /// - Suspension timing: don't swap if swapped within PURGESOURCESWAPSTOP (15 min)
    /// - NNP awareness: aggressively swap away from files where we have no needed parts
    /// - Queue rank: peers with low rank (<=50) on current file are less likely to swap
    /// - Credit weighting: higher-credit peers are more valuable to keep
    /// - Source count: prefer files with fewer active sources
    pub fn process_swaps(
        &self,
        file_info: &HashMap<[u8; 16], FileSwapInfo>,
    ) -> Vec<SwapAction> {
        let mut swaps = Vec::new();
        let now = chrono::Utc::now().timestamp();

        for (target_hash, entries) in &self.a4af_sources {
            let target = match file_info.get(target_hash) {
                Some(p) => p,
                None => continue,
            };

            for entry in entries {
                // Suspension: don't re-swap too quickly
                if entry.last_swap_time > 0
                    && now - entry.last_swap_time < PURGE_SOURCE_SWAP_STOP_SECS
                {
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
            for entry in entries.iter_mut() {
                if entry.peer_addr == peer_addr {
                    entry.last_swap_time = now;
                }
            }
        }
    }

    /// Check if a source currently assigned to `current_file` is registered as
    /// an A4AF candidate for any other file (i.e., it may be swapped away).
    pub fn is_swap_candidate(&self, peer_addr: SocketAddr, current_file: &[u8; 16]) -> bool {
        for (target_hash, entries) in &self.a4af_sources {
            if target_hash == current_file { continue; }
            if entries.iter().any(|e| e.peer_addr == peer_addr && e.assigned_file_hash == *current_file) {
                return true;
            }
        }
        false
    }

    pub fn cleanup_stale(&mut self, max_age_secs: i64) {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        for entries in self.a4af_sources.values_mut() {
            entries.retain(|e| e.added_time > cutoff);
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
    let source_advantage = assigned.active_source_count.saturating_sub(target.active_source_count + 1);
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
