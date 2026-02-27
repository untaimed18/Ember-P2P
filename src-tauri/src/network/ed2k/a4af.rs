use std::collections::HashMap;
use std::net::SocketAddr;

/// A4AF (Asked For Another File) source management.
/// Tracks sources that are known to have files we want but are currently
/// assigned to a different download.
#[derive(Debug, Clone)]
pub struct A4AFEntry {
    pub peer_addr: SocketAddr,
    pub assigned_file_hash: [u8; 16],
    pub added_time: i64,
}

pub struct A4AFManager {
    /// file_hash -> list of A4AF entries (sources that have this file but are assigned elsewhere)
    a4af_sources: HashMap<[u8; 16], Vec<A4AFEntry>>,
}

#[derive(Debug, Clone)]
pub struct SwapAction {
    pub peer_addr: SocketAddr,
    pub from_file: [u8; 16],
    pub to_file: [u8; 16],
}

impl A4AFManager {
    pub fn new() -> Self {
        Self {
            a4af_sources: HashMap::new(),
        }
    }

    /// Register a source as A4AF for a file. The source has `file_hash` but is
    /// currently downloading `current_file`.
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

        entries.push(A4AFEntry {
            peer_addr,
            assigned_file_hash,
            added_time: chrono::Utc::now().timestamp(),
        });
    }

    pub fn remove_source(&mut self, peer_addr: SocketAddr) {
        for entries in self.a4af_sources.values_mut() {
            entries.retain(|e| e.peer_addr != peer_addr);
        }
        self.a4af_sources.retain(|_, v| !v.is_empty());
    }

    pub fn get_a4af_sources(&self, file_hash: &[u8; 16]) -> &[A4AFEntry] {
        self.a4af_sources
            .get(file_hash)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Evaluate swap decisions every 8 minutes.
    /// Returns list of sources that should be swapped to higher-priority files.
    ///
    /// `file_priorities` maps file_hash -> (priority, active_source_count)
    pub fn process_swaps(
        &self,
        file_priorities: &HashMap<[u8; 16], (u32, usize)>,
    ) -> Vec<SwapAction> {
        let mut swaps = Vec::new();

        for (target_hash, entries) in &self.a4af_sources {
            let (target_prio, target_sources) = match file_priorities.get(target_hash) {
                Some(p) => *p,
                None => continue,
            };

            for entry in entries {
                let (assigned_prio, assigned_sources) =
                    match file_priorities.get(&entry.assigned_file_hash) {
                        Some(p) => *p,
                        None => continue,
                    };

                // Swap if target has higher priority, or same priority but fewer sources
                let should_swap = target_prio > assigned_prio
                    || (target_prio == assigned_prio && target_sources < assigned_sources);

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

    pub fn cleanup_stale(&mut self, max_age_secs: i64) {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        for entries in self.a4af_sources.values_mut() {
            entries.retain(|e| e.added_time > cutoff);
        }
        self.a4af_sources.retain(|_, v| !v.is_empty());
    }
}
