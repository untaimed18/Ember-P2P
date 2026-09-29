//! Deletions in shared folders too big for one discovery page.
//!
//! A folder over the page cap is walked a page per reload, each page resuming
//! at the previous page's cursor. Every page after the first skips what came
//! before it, so none of them is a listing the index may remove missing rows
//! against, and a file deleted while events were not being watched (hashing
//! stopped, say) stayed offerable until "Remove missing". A cycle collects the
//! paths each page saw, and the page that finishes the folder removes the rows
//! that were indexed when the cycle began and that no page found.
//!
//! Rows indexed after the cycle began are left alone, however they arrived — a
//! download completing into the folder, a filesystem-event rescan: the walk
//! may already have passed their place in the order. Paths are held as 64-bit
//! fingerprints, since these folders run to hundreds of thousands of files. A
//! collision can only keep a row that should have gone, never remove one.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Mutex, OnceLock};

use crate::search::index::normalize_path_key;

/// What one reload page covered of one shared folder.
#[derive(Debug, Clone)]
pub struct PageFacts {
    /// The cursor the page started after; `None` for the folder's first page.
    pub cursor: Option<String>,
    /// Where the next page starts; `None` once the page reached the end.
    pub next: Option<String>,
    /// The page left entries in its stretch unvisited.
    pub frontier_trimmed: bool,
}

#[derive(Debug)]
struct Cycle {
    root: String,
    /// Cursor of the last page folded in (`None` for the first).
    at: Option<String>,
    next: Option<String>,
    indexed_at_start: HashSet<u64>,
    seen: HashSet<u64>,
}

#[derive(Debug, Default)]
pub struct PagedCycles {
    cycles: HashMap<String, Cycle>,
}

pub fn fingerprint(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    normalize_path_key(path).hash(&mut hasher);
    hasher.finish()
}

impl PagedCycles {
    /// Fold one page of `root` into its cycle. `indexed` lists the paths the
    /// index holds under `root`, and is only read when the page starts a
    /// cycle. Returns the fingerprints of the rows to remove when the page
    /// completes one.
    pub fn note_page<'a>(
        &mut self,
        root: &str,
        facts: &PageFacts,
        indexed: impl FnOnce() -> Vec<String>,
        page: impl Iterator<Item = &'a str>,
    ) -> Option<HashSet<u64>> {
        let key = normalize_path_key(root);
        if facts.cursor.is_none() {
            // A folder that fits one page is reconciled by the page itself; a
            // first page that skipped entries cannot anchor a cycle.
            if facts.next.is_none() || facts.frontier_trimmed {
                self.cycles.remove(&key);
                return None;
            }
            let cycle = Cycle {
                root: root.to_string(),
                at: None,
                next: facts.next.clone(),
                indexed_at_start: indexed().iter().map(|path| fingerprint(path)).collect(),
                seen: page.map(fingerprint).collect(),
            };
            self.cycles.insert(key, cycle);
            return None;
        }
        let cycle = self.cycles.get_mut(&key)?;
        let continues = facts.cursor == cycle.next;
        // A page whose cursor was not saved (cancelled while hashing) runs again.
        let repeats = cycle.at.is_some() && facts.cursor == cycle.at;
        if facts.frontier_trimmed || !(continues || repeats) {
            self.cycles.remove(&key);
            return None;
        }
        cycle.seen.extend(page.map(fingerprint));
        if continues {
            cycle.at = facts.cursor.clone();
            cycle.next = facts.next.clone();
        }
        if cycle.next.is_some() {
            return None;
        }
        let cycle = self.cycles.remove(&key)?;
        Some(cycle.indexed_at_start.difference(&cycle.seen).copied().collect())
    }

    /// Paths a scoped rescan found on disk, which count as seen by the cycle
    /// of the folder they are in: the page that walked their place may have
    /// run before they reappeared.
    pub fn note_found<'a>(&mut self, paths: impl Iterator<Item = &'a str>) {
        if self.cycles.is_empty() {
            return;
        }
        for path in paths {
            if let Some(cycle) = self
                .cycles
                .values_mut()
                .find(|cycle| crate::security::path_within_dir(path, &cycle.root))
            {
                cycle.seen.insert(fingerprint(path));
            }
        }
    }

    /// Drop the cycles of folders no longer shared.
    pub fn retain_roots(&mut self, roots: &[String]) {
        let keys: HashSet<String> = roots.iter().map(|root| normalize_path_key(root)).collect();
        self.cycles.retain(|key, _| keys.contains(key));
    }
}

/// The cycles of this session's reloads.
pub fn cycles() -> &'static Mutex<PagedCycles> {
    static CYCLES: OnceLock<Mutex<PagedCycles>> = OnceLock::new();
    CYCLES.get_or_init(Default::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(cursor: Option<&str>, next: Option<&str>) -> PageFacts {
        PageFacts {
            cursor: cursor.map(str::to_string),
            next: next.map(str::to_string),
            frontier_trimmed: false,
        }
    }

    fn paths(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| format!("/share/{name}")).collect()
    }

    #[test]
    fn a_finished_cycle_removes_what_no_page_found() {
        let mut cycles = PagedCycles::default();
        let indexed = paths(&["a", "b", "c", "d", "gone"]);
        let first = paths(&["a", "b"]);
        let second = paths(&["c", "d", "new"]);
        assert!(cycles
            .note_page("/share", &facts(None, Some("/share/b")), || indexed.clone(), first.iter().map(String::as_str))
            .is_none());
        let doomed = cycles
            .note_page("/share", &facts(Some("/share/b"), None), Vec::new, second.iter().map(String::as_str))
            .expect("the last page finishes the cycle");
        assert_eq!(doomed, HashSet::from([fingerprint("/share/gone")]));
    }

    #[test]
    fn rows_found_by_a_rescan_or_indexed_later_are_kept() {
        let mut cycles = PagedCycles::default();
        let indexed = paths(&["a", "back"]);
        let first = paths(&["a"]);
        cycles.note_page("/share", &facts(None, Some("/share/a")), || indexed.clone(), first.iter().map(String::as_str));
        // "back" was missing when its page ran, then a rescan found it again.
        cycles.note_found(["/share/back"].into_iter());
        let doomed = cycles
            .note_page("/share", &facts(Some("/share/a"), None), Vec::new, std::iter::empty())
            .unwrap();
        assert!(doomed.is_empty(), "{doomed:?}");
    }

    #[test]
    fn a_broken_sequence_or_a_trimmed_page_abandons_the_cycle() {
        let indexed = paths(&["a", "gone"]);
        let first = paths(&["a"]);
        let start = || {
            let mut cycles = PagedCycles::default();
            cycles.note_page("/share", &facts(None, Some("/share/a")), || indexed.clone(), first.iter().map(String::as_str));
            cycles
        };

        // A page from somewhere else in the order: the cycle missed a stretch.
        let mut cycles = start();
        assert!(cycles
            .note_page("/share", &facts(Some("/share/m"), None), Vec::new, std::iter::empty())
            .is_none());

        cycles = start();
        let trimmed = PageFacts { frontier_trimmed: true, ..facts(Some("/share/a"), None) };
        assert!(cycles.note_page("/share", &trimmed, Vec::new, std::iter::empty()).is_none());

        // A repeat of a page that already ran is fine, and the cycle goes on.
        cycles = start();
        let second = facts(Some("/share/a"), Some("/share/q"));
        assert!(cycles.note_page("/share", &second, Vec::new, std::iter::empty()).is_none());
        assert!(cycles.note_page("/share", &second, Vec::new, std::iter::empty()).is_none());
        let doomed = cycles
            .note_page("/share", &facts(Some("/share/q"), None), Vec::new, std::iter::empty())
            .unwrap();
        assert_eq!(doomed, HashSet::from([fingerprint("/share/gone")]));
    }

    #[test]
    fn a_folder_that_fits_one_page_needs_no_cycle() {
        let mut cycles = PagedCycles::default();
        assert!(cycles
            .note_page("/share", &facts(None, None), || paths(&["a"]), std::iter::empty())
            .is_none());
        assert!(cycles.cycles.is_empty());
    }
}
