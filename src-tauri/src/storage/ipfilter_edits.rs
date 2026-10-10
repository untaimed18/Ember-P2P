//! The user's own edits to the IP filter, kept apart from the list itself.
//!
//! A range added or removed on the Security page lives in `ipfilter.dat` like
//! every other, so installing a new list — a download, an import, or the daily
//! automatic update — used to take the user's edits with the old one. They are
//! recorded here as well and re-applied to each list that replaces it.
//!
//! Edits made before this file existed are not in it; they are lost on the
//! next new list as they always were.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::network::kad::ip_filter::IpFilter;

const EDITS_FILE: &str = "ipfilter_edits.json";

/// Ceiling on each list, so a runaway caller cannot grow the file without
/// bound. Far beyond what anyone edits by hand.
const MAX_EDITS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EditedRange {
    pub start: u32,
    pub end: u32,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpFilterEdits {
    /// Ranges the user added.
    #[serde(default)]
    pub added: Vec<EditedRange>,
    /// Ranges the user removed from a list: taken out again from each new one.
    #[serde(default)]
    pub removed: Vec<EditedRange>,
}

impl IpFilterEdits {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    fn same(range: &EditedRange, start: u32, end: u32) -> bool {
        range.start == start && range.end == end
    }

    /// The user added `start..=end`: a removal of the same range is undone.
    pub fn record_add(&mut self, start: u32, end: u32, description: String) {
        self.removed.retain(|r| !Self::same(r, start, end));
        if !self.added.iter().any(|r| Self::same(r, start, end)) && self.added.len() < MAX_EDITS {
            self.added.push(EditedRange { start, end, description });
        }
    }

    /// The user removed `start..=end`: one they had added is simply forgotten,
    /// one from the list is taken out of every new list too.
    pub fn record_remove(&mut self, start: u32, end: u32) {
        let before = self.added.len();
        self.added.retain(|r| !Self::same(r, start, end));
        if self.added.len() < before {
            return;
        }
        if !self.removed.iter().any(|r| Self::same(r, start, end)) && self.removed.len() < MAX_EDITS {
            self.removed.push(EditedRange { start, end, description: String::new() });
        }
    }

    /// Re-apply the edits to a freshly loaded list.
    pub fn apply(&self, filter: &mut IpFilter) {
        for range in &self.removed {
            filter.remove_range(
                &Ipv4Addr::from(range.start).to_string(),
                &Ipv4Addr::from(range.end).to_string(),
            );
        }
        for range in &self.added {
            filter.add_range(
                Ipv4Addr::from(range.start),
                Ipv4Addr::from(range.end),
                range.description.clone(),
            );
        }
    }
}

fn edits_path(data_dir: &Path) -> PathBuf {
    data_dir.join(EDITS_FILE)
}

/// The recorded edits; none when the file is missing or unreadable.
pub fn load(data_dir: &Path) -> IpFilterEdits {
    std::fs::read(edits_path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Serializes the read-modify-write in [`update`], which the network task
/// spawns once per edit.
static EDITS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Change the recorded edits and save them. Blocking.
pub fn update(data_dir: &Path, change: impl FnOnce(&mut IpFilterEdits)) {
    let _guard = EDITS_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut edits = load(data_dir);
    change(&mut edits);
    match serde_json::to_vec(&edits) {
        Ok(bytes) => {
            if let Err(error) = crate::security::atomic_write(&edits_path(data_dir), &bytes, false) {
                tracing::warn!("Could not save the IP filter edits: {error}");
            }
        }
        Err(error) => tracing::warn!("Could not save the IP filter edits: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removing_an_added_range_forgets_it_instead_of_recording_a_removal() {
        let mut edits = IpFilterEdits::default();
        edits.record_add(10, 20, "mine".into());
        edits.record_remove(10, 20);
        assert!(edits.is_empty());
    }

    #[test]
    fn adding_back_a_removed_range_undoes_the_removal() {
        let mut edits = IpFilterEdits::default();
        edits.record_remove(10, 20);
        assert_eq!(edits.removed.len(), 1);
        edits.record_add(10, 20, String::new());
        assert!(edits.removed.is_empty());
        assert_eq!(edits.added.len(), 1);
    }

    #[test]
    fn edits_are_reapplied_to_a_new_list() {
        let mut list = IpFilter::new(true, false);
        list.add_range(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 255), "list".into());
        let mut edits = IpFilterEdits::default();
        edits.record_remove(u32::from(Ipv4Addr::new(1, 0, 0, 0)), u32::from(Ipv4Addr::new(1, 0, 0, 255)));
        edits.record_add(
            u32::from(Ipv4Addr::new(9, 9, 9, 0)),
            u32::from(Ipv4Addr::new(9, 9, 9, 255)),
            "mine".into(),
        );
        edits.apply(&mut list);
        assert_eq!(list.range_count(), 1);
        let bytes = String::from_utf8(list.canonical_dat_bytes()).unwrap();
        assert!(bytes.contains("9.9.9.0"));
        assert!(!bytes.contains("1.0.0.0"));
    }
}
