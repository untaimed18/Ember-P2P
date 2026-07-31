use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tracing::{info, warn};

/// Text-format limits shared by the streaming loaders and their preflight
/// validator. Keeping one definition prevents a file from being accepted at
/// import time and then loading as an empty filter.
const MAX_TEXT_FILTER_LINE_BYTES: usize = 8 * 1024;
const MAX_TEXT_FILTER_LINES: usize = 5_000_000;

#[derive(Debug)]
struct IpRange {
    start: u32,
    end: u32,
    description: String,
    /// Atomic so [`IpFilter::is_blocked_readonly`] (and shared-snapshot
    /// collection) can attribute hits without `&mut self`.
    hits: AtomicU64,
}

impl Clone for IpRange {
    fn clone(&self) -> Self {
        Self {
            start: self.start,
            end: self.end,
            description: self.description.clone(),
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
        }
    }
}

impl IpRange {
    fn new(start: u32, end: u32, description: String) -> Self {
        Self {
            start,
            end,
            description,
            hits: AtomicU64::new(0),
        }
    }

    fn hit_count(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    fn add_hits(&self, n: u64) {
        if n > 0 {
            self.hits.fetch_add(n, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IpFilterEntry {
    pub start_ip: String,
    pub end_ip: String,
    pub description: String,
    pub hits: u64,
}

/// Lightweight shared IP filter for use in spawned tasks (upload handler).
/// Contains a sorted snapshot of blocked ranges and settings.
pub type SharedIpFilter = std::sync::Arc<std::sync::RwLock<IpFilterSnapshot>>;

pub struct IpFilterSnapshot {
    pub ranges: Vec<(u32, u32)>,
    /// Per-range hit counters parallel to [`Self::ranges`]. Hot-path blocks
    /// (upload / KAD / multi-source) only see this snapshot; without these,
    /// the Security page Hits column stayed at 0 while the header total grew.
    pub range_hits: Vec<AtomicU64>,
    pub enabled: bool,
    pub block_private: bool,
    /// False while a deferred/on-enable load of `ipfilter.dat` is still in
    /// flight. When `enabled && !ranges_ready`, [`Self::is_blocked`] fail-closes
    /// (treats every non-special IP as blocked) so peers cannot slip through
    /// an empty range list at startup.
    pub ranges_ready: bool,
    /// Hits from range-based (ipfilter.dat) matches (and fail-closed blocks
    /// while ranges are still loading).
    pub hit_counter: AtomicU64,
    /// Hits from always-blocked bogus IPs and (when `block_private`) LAN/CGNAT
    /// space. Kept separate from `hit_counter` so [`IpFilter::collect_shared_hits`]
    /// can attribute them to the right bucket in the stats UI rather than
    /// folding every upload-path block into the range total.
    pub special_hit_counter: AtomicU64,
}

impl std::fmt::Debug for IpFilterSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpFilterSnapshot")
            .field("ranges", &self.ranges.len())
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl IpFilterSnapshot {
    fn record_range_hit(&self, idx: usize) {
        if let Some(counter) = self.range_hits.get(idx) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        self.hit_counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        // Always-unroutable space is rejected regardless of any toggle.
        if crate::security::is_bogus_v4(ip) {
            self.special_hit_counter.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        // RFC1918 / link-local / CGNAT only when the user opted in.
        if self.block_private && crate::security::is_lan_or_cgnat_v4(ip) {
            self.special_hit_counter.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled && !self.ranges_ready {
            // Fail closed until ipfilter.dat has been applied (or confirmed
            // absent). Avoids a startup window where enabled+empty ranges
            // admit peers that the list would block.
            self.hit_counter.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled {
            let ip_u32 = u32::from(ip);
            if let Ok(idx) = self.ranges.binary_search_by(|&(start, end)| {
                if ip_u32 < start {
                    std::cmp::Ordering::Greater
                } else if ip_u32 > end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                self.record_range_hit(idx);
                return true;
            }
        }
        false
    }

    /// KAD UDP / routing-table admission while `ipfilter.dat` may still be
    /// loading. Unlike [`Self::is_blocked`], does **not** fail-closed when
    /// `!ranges_ready` — that window would blackhole bootstrap replies and
    /// reject every RT insert. Bogus/private rules still apply; once ranges
    /// are ready, range matches apply. After load, `evict_filtered_contacts`
    /// removes any contacts that should have been blocked.
    pub fn is_blocked_for_kad(&self, ip: Ipv4Addr) -> bool {
        if crate::security::is_bogus_v4(ip) {
            self.special_hit_counter.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.block_private && crate::security::is_lan_or_cgnat_v4(ip) {
            self.special_hit_counter.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled && self.ranges_ready {
            let ip_u32 = u32::from(ip);
            if let Ok(idx) = self.ranges.binary_search_by(|&(start, end)| {
                if ip_u32 < start {
                    std::cmp::Ordering::Greater
                } else if ip_u32 > end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                self.record_range_hit(idx);
                return true;
            }
        }
        false
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IpFilterStats {
    pub enabled: bool,
    pub block_private: bool,
    /// False while an enabled filter has not finished (or failed) loading
    /// ranges — peer paths fail-closed in that window.
    pub ranges_ready: bool,
    pub range_count: usize,
    pub total_hits: u64,
    pub entries: Vec<IpFilterEntry>,
}

pub struct IpFilter {
    blocked_ranges: Vec<IpRange>,
    enabled: bool,
    block_private: bool,
    /// See [`IpFilterSnapshot::ranges_ready`].
    ranges_ready: bool,
    /// Total range-based filter hits (atomic so readonly checks can also count)
    total_range_hits: AtomicU64,
    /// Hits from blocking private/reserved/special IPs (not in any range)
    total_special_hits: AtomicU64,
}

impl IpFilter {
    pub fn new(enabled: bool, block_private: bool) -> Self {
        IpFilter {
            blocked_ranges: Vec::new(),
            enabled,
            block_private,
            // Disabled ⇒ nothing to load. Enabled ⇒ fail closed until the
            // first load pass finishes (or confirms there is no file).
            ranges_ready: !enabled,
            total_range_hits: AtomicU64::new(0),
            total_special_hits: AtomicU64::new(0),
        }
    }

    /// Mark the range list as applied (or confirmed empty/absent). Clears the
    /// startup fail-closed gate.
    pub fn mark_ranges_ready(&mut self) {
        self.ranges_ready = true;
    }

    /// Keep enabled filters fail-closed after a readable-but-empty load. This
    /// is used by startup validation; normal imports reject zero-range files
    /// before they can replace a live filter.
    pub fn mark_ranges_not_ready(&mut self) {
        self.ranges_ready = false;
    }

    pub fn ranges_ready(&self) -> bool {
        self.ranges_ready
    }

    /// Replace `self.blocked_ranges` with `new_ranges` after sorting,
    /// merging overlaps, and carrying over hit counts for ranges that
    /// survive the reload unchanged (same start/end).
    ///
    /// This is the *only* place that mutates `self.blocked_ranges` on a
    /// (re)load path, and every loader below (`.dat`/`.txt`, `.p2p`, `.p2b`)
    /// calls it only after it has fully and successfully read the new data.
    /// That ordering is what guarantees a failed read (missing file, I/O
    /// error, corrupt header) never leaves `self` with fewer ranges than it
    /// started with — the old filter stays in effect until a fresh one is
    /// actually in hand, "clear-then-fail" is impossible by construction.
    fn commit_ranges(&mut self, mut new_ranges: Vec<IpRange>) -> usize {
        let saved_hits: std::collections::HashMap<(u32, u32), u64> = self
            .blocked_ranges
            .iter()
            .filter(|r| r.hit_count() > 0)
            .map(|r| ((r.start, r.end), r.hit_count()))
            .collect();

        new_ranges.sort_by_key(|r| r.start);
        self.blocked_ranges = new_ranges;
        self.merge_overlapping();

        if !saved_hits.is_empty() {
            for r in &self.blocked_ranges {
                if let Some(&hits) = saved_hits.get(&(r.start, r.end)) {
                    r.hits.store(hits, Ordering::Relaxed);
                }
            }
        }
        // A successful commit means the range list is intentional — clear the
        // fail-closed gate (also covers empty files that parse cleanly).
        self.ranges_ready = true;
        self.blocked_ranges.len()
    }

    /// (Re)load the filter from `path`, dispatching on extension: `.p2b` ->
    /// PeerGuardian binary, `.p2p` -> PeerGuardian text, anything else ->
    /// eMule `ipfilter.dat` / plain text.
    ///
    /// Returns `None` if the file could not be read at all (missing,
    /// unreadable, truncated/corrupt binary header, etc.) — `self` is left
    /// completely untouched in that case, so a bad path or a download gone
    /// wrong can never wipe out a filter that was working. Returns
    /// `Some(count)` with the number of ranges after merging once a new list
    /// has actually been read (a readable-but-empty or all-invalid file
    /// legitimately yields `Some(0)`; distinguishing that from "couldn't
    /// read it" is the caller's job — see `count_valid_entries` for
    /// pre-flight validation of downloaded/imported content).
    pub fn load_from_file(&mut self, path: &Path) -> Option<usize> {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        match ext.as_str() {
            "p2b" => self.load_p2b_file(path),
            "p2p" => self.load_p2p_file(path),
            _ => self.load_dat_file(path),
        }
    }

    /// Load the eMule `ipfilter.dat` / plain-text format. Also accepts
    /// PeerGuardian `.p2p`-style lines as a per-line fallback, since
    /// real-world "ipfilter.dat" downloads sometimes ship that format under
    /// a `.dat` name.
    fn load_dat_file(&mut self, path: &Path) -> Option<usize> {
        // K20: ipfilter.dat can legitimately be tens of MB and
        // pathologically-large files (from buggy crawlers or
        // malicious downloads) can be gigabytes. Read the file
        // line-by-line with a hard per-line cap instead of
        // slurping the whole thing into memory as a UTF-8
        // String. A single oversized line gets dropped, not the
        // entire file.
        use std::io::BufRead;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to open ipfilter.dat: {e}");
                return None;
            }
        };
        let mut reader = std::io::BufReader::new(file);
        let mut new_ranges = Vec::new();
        let mut count = 0usize;
        let mut overlong_drops = 0usize;
        let mut io_failed = false;
        let mut raw_line = Vec::new();
        for lineno in 0..MAX_TEXT_FILTER_LINES {
            raw_line.clear();
            // Read raw bytes rather than `BufRead::lines()`: the latter
            // hard-errors (and this loop used to abort entirely) on the
            // first byte sequence that isn't valid UTF-8. Real-world
            // ipfilter.dat mirrors occasionally carry a stray non-UTF8 byte
            // in a description field; one bad byte at line 30,000 of 60,000
            // shouldn't silently discard the other 30,000 good ranges. We
            // decode lossily instead, matching `count_valid_entries`'s
            // tolerance so pre-flight validation and the real load agree.
            let read = match reader.read_until(b'\n', &mut raw_line) {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        "Stopping ipfilter.dat parse after I/O error at line {}: {e}",
                        lineno + 1
                    );
                    io_failed = true;
                    break;
                }
            };
            if read == 0 {
                break; // EOF
            }
            if raw_line.len() > MAX_TEXT_FILTER_LINE_BYTES {
                overlong_drops += 1;
                continue;
            }
            let line = String::from_utf8_lossy(&raw_line);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some(range) = parse_ipfilter_line(line) {
                new_ranges.push(range);
                count += 1;
            } else if let Some(range) = parse_p2p_line(line) {
                new_ranges.push(range);
                count += 1;
            }
        }
        if overlong_drops > 0 {
            warn!(
                "ipfilter.dat: dropped {overlong_drops} lines longer than {MAX_TEXT_FILTER_LINE_BYTES} bytes"
            );
        }
        // Mid-file I/O failure: keep the previous range list rather than
        // committing a truncated parse as if it were a successful load.
        if io_failed {
            return None;
        }

        let final_count = self.commit_ranges(new_ranges);
        info!(
            "Loaded {count} IP filter entries ({final_count} ranges after merge) from {}",
            path.display()
        );
        Some(final_count)
    }

    fn merge_overlapping(&mut self) {
        if self.blocked_ranges.len() <= 1 {
            return;
        }
        let mut merged = Vec::with_capacity(self.blocked_ranges.len());
        merged.push(self.blocked_ranges[0].clone());
        for range in &self.blocked_ranges[1..] {
            let Some(last) = merged.last_mut() else { break };
            if range.start <= last.end.saturating_add(1) {
                last.end = last.end.max(range.end);
                if last.description.is_empty() && !range.description.is_empty() {
                    last.description = range.description.clone();
                }
                last.add_hits(range.hit_count());
            } else {
                merged.push(range.clone());
            }
        }
        self.blocked_ranges = merged;
    }

    pub fn is_blocked(&mut self, ip: Ipv4Addr) -> bool {
        if crate::security::is_bogus_v4(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.block_private && crate::security::is_lan_or_cgnat_v4(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled && !self.ranges_ready {
            self.total_range_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled {
            let ip_u32 = u32::from(ip);
            if let Ok(idx) = self.blocked_ranges.binary_search_by(|range| {
                if ip_u32 < range.start {
                    std::cmp::Ordering::Greater
                } else if ip_u32 > range.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                self.blocked_ranges[idx].add_hits(1);
                self.total_range_hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// Check if an IP is blocked without requiring &mut self.
    /// Increments both the atomic total and the matching per-range counter.
    pub fn is_blocked_readonly(&self, ip: Ipv4Addr) -> bool {
        if crate::security::is_bogus_v4(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.block_private && crate::security::is_lan_or_cgnat_v4(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled && !self.ranges_ready {
            self.total_range_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled {
            let ip_u32 = u32::from(ip);
            if let Ok(idx) = self.blocked_ranges.binary_search_by(|range| {
                if ip_u32 < range.start {
                    std::cmp::Ordering::Greater
                } else if ip_u32 > range.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                self.blocked_ranges[idx].add_hits(1);
                self.total_range_hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// KAD UDP ingress while ranges may still be loading — see
    /// [`IpFilterSnapshot::is_blocked_for_kad`].
    pub fn is_blocked_readonly_for_kad(&self, ip: Ipv4Addr) -> bool {
        if crate::security::is_bogus_v4(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.block_private && crate::security::is_lan_or_cgnat_v4(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled && self.ranges_ready {
            let ip_u32 = u32::from(ip);
            if let Ok(idx) = self.blocked_ranges.binary_search_by(|range| {
                if ip_u32 < range.start {
                    std::cmp::Ordering::Greater
                } else if ip_u32 > range.end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                self.blocked_ranges[idx].add_hits(1);
                self.total_range_hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    pub fn range_count(&self) -> usize {
        self.blocked_ranges.len()
    }

    /// Serialize the active ranges into the canonical text format used by
    /// `ipfilter.dat`. Binary `.p2b` imports must be converted before they
    /// replace that stable startup path; otherwise the next launch would
    /// dispatch their bytes to the text parser and lose every range.
    pub fn canonical_dat_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.blocked_ranges.len().saturating_mul(48));
        for range in &self.blocked_ranges {
            let start = Ipv4Addr::from(range.start);
            let end = Ipv4Addr::from(range.end);
            bytes.extend_from_slice(
                format!("{start} - {end} , 000 , Ember imported range\n").as_bytes(),
            );
        }
        bytes
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn blocks_private(&self) -> bool {
        self.block_private
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            // Nothing to await — clear fail-closed gate.
            self.ranges_ready = true;
        } else {
            // Caller must load (or confirm absence) then `mark_ranges_ready`.
            self.ranges_ready = false;
        }
    }

    pub fn set_block_private(&mut self, block_private: bool) {
        self.block_private = block_private;
    }

    /// Merge ranges from `other` into this filter. Used when a deferred
    /// ipfilter.dat load finishes and the live filter may already hold
    /// user-added ranges from AddIpRange during the load window.
    pub fn merge_ranges_from(&mut self, other: &IpFilter) {
        if other.blocked_ranges.is_empty() {
            return;
        }
        self.blocked_ranges
            .extend(other.blocked_ranges.iter().cloned());
        self.blocked_ranges.sort_by_key(|r| r.start);
        self.merge_overlapping();
    }

    /// Create a shared snapshot for use by the upload handler.
    pub fn create_shared_snapshot(&self) -> SharedIpFilter {
        let ranges: Vec<(u32, u32)> = self
            .blocked_ranges
            .iter()
            .map(|r| (r.start, r.end))
            .collect();
        let range_hits = (0..ranges.len()).map(|_| AtomicU64::new(0)).collect();
        std::sync::Arc::new(std::sync::RwLock::new(IpFilterSnapshot {
            ranges,
            range_hits,
            enabled: self.enabled,
            block_private: self.block_private,
            ranges_ready: self.ranges_ready,
            hit_counter: AtomicU64::new(0),
            special_hit_counter: AtomicU64::new(0),
        }))
    }

    /// Update an existing shared snapshot with current filter state, preserving
    /// its live hit counters (range and special) so an in-flight settings
    /// change or reload doesn't drop pending upload-path hits.
    pub fn update_shared_snapshot(&self, shared: &SharedIpFilter) {
        if let Ok(mut snap) = shared.write() {
            let pending: std::collections::HashMap<(u32, u32), u64> = snap
                .ranges
                .iter()
                .zip(snap.range_hits.iter())
                .filter_map(|(&(start, end), counter)| {
                    let n = counter.load(Ordering::Relaxed);
                    (n > 0).then_some(((start, end), n))
                })
                .collect();

            snap.ranges = self
                .blocked_ranges
                .iter()
                .map(|r| (r.start, r.end))
                .collect();
            snap.range_hits = snap
                .ranges
                .iter()
                .map(|&(start, end)| {
                    AtomicU64::new(pending.get(&(start, end)).copied().unwrap_or(0))
                })
                .collect();
            snap.enabled = self.enabled;
            snap.block_private = self.block_private;
            snap.ranges_ready = self.ranges_ready;
        }
    }

    /// Collect hits from the shared snapshot into the totals, preserving the
    /// range-vs-special split and attributing range hits to matching entries
    /// so the Security page Hits column stays in sync with the header total.
    pub fn collect_shared_hits(&self, shared: &SharedIpFilter) {
        if let Ok(snap) = shared.read() {
            let range_hits = snap.hit_counter.swap(0, Ordering::Relaxed);
            if range_hits > 0 {
                self.total_range_hits
                    .fetch_add(range_hits, Ordering::Relaxed);
            }
            let special_hits = snap.special_hit_counter.swap(0, Ordering::Relaxed);
            if special_hits > 0 {
                self.total_special_hits
                    .fetch_add(special_hits, Ordering::Relaxed);
            }

            for (i, counter) in snap.range_hits.iter().enumerate() {
                let n = counter.swap(0, Ordering::Relaxed);
                if n == 0 {
                    continue;
                }
                let Some(&(start, end)) = snap.ranges.get(i) else {
                    continue;
                };
                if let Some(range) = self
                    .blocked_ranges
                    .iter()
                    .find(|r| r.start == start && r.end == end)
                {
                    range.add_hits(n);
                }
            }
        }
    }

    pub fn get_stats(&self) -> IpFilterStats {
        let per_range_hits: u64 = self.blocked_ranges.iter().map(|r| r.hit_count()).sum();
        let atomic_range_hits = self.total_range_hits.load(Ordering::Relaxed);
        let special_hits = self.total_special_hits.load(Ordering::Relaxed);
        let total_hits = atomic_range_hits.max(per_range_hits) + special_hits;

        let entries: Vec<IpFilterEntry> = self
            .blocked_ranges
            .iter()
            .map(|r| IpFilterEntry {
                start_ip: Ipv4Addr::from(r.start).to_string(),
                end_ip: Ipv4Addr::from(r.end).to_string(),
                description: r.description.clone(),
                hits: r.hit_count(),
            })
            .collect();

        IpFilterStats {
            enabled: self.enabled,
            block_private: self.block_private,
            ranges_ready: self.ranges_ready,
            range_count: self.blocked_ranges.len(),
            total_hits,
            entries,
        }
    }

    pub fn add_range(&mut self, start: Ipv4Addr, end: Ipv4Addr, description: String) -> bool {
        let s = u32::from(start);
        let e = u32::from(end);
        if s > e {
            return false;
        }
        self.blocked_ranges.push(IpRange::new(s, e, description));
        self.blocked_ranges.sort_by_key(|r| r.start);
        self.merge_overlapping();
        true
    }

    pub fn remove_range(&mut self, start_ip: &str, end_ip: &str) -> bool {
        let start: Ipv4Addr = match start_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        let end: Ipv4Addr = match end_ip.parse() {
            Ok(ip) => ip,
            Err(_) => return false,
        };
        let s = u32::from(start);
        let e = u32::from(end);
        let before = self.blocked_ranges.len();
        self.blocked_ranges.retain(|r| r.start != s || r.end != e);
        self.blocked_ranges.len() < before
    }

    /// Load a PeerGuardian .p2p text file (format: "Description: IP1 - IP2")
    pub fn load_p2p_file(&mut self, path: &Path) -> Option<usize> {
        // Mirror the ipfilter.dat path: stream line-by-line with hard
        // per-line and total-line caps instead of slurping the whole file
        // into a String. A malicious/buggy multi-gigabyte list can't OOM us.
        use std::io::BufRead;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to read .p2p file: {e}");
                return None;
            }
        };
        let mut reader = std::io::BufReader::new(file);

        let mut new_ranges = Vec::new();
        let mut count = 0;
        let mut overlong_drops = 0usize;
        let mut io_failed = false;
        let mut raw_line = Vec::new();
        for lineno in 0..MAX_TEXT_FILTER_LINES {
            raw_line.clear();
            // Lossy byte-level read, not `BufRead::lines()` — see
            // `load_dat_file` for why a single non-UTF8 byte must not abort
            // the whole parse.
            let read = match reader.read_until(b'\n', &mut raw_line) {
                Ok(n) => n,
                Err(e) => {
                    warn!(
                        "Stopping .p2p parse after I/O error at line {}: {e}",
                        lineno + 1
                    );
                    io_failed = true;
                    break;
                }
            };
            if read == 0 {
                break; // EOF
            }
            if raw_line.len() > MAX_TEXT_FILTER_LINE_BYTES {
                overlong_drops += 1;
                continue;
            }
            let line = String::from_utf8_lossy(&raw_line);
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some(range) = parse_p2p_line(line) {
                new_ranges.push(range);
                count += 1;
            }
        }
        if overlong_drops > 0 {
            warn!(".p2p file: dropped {overlong_drops} lines longer than {MAX_TEXT_FILTER_LINE_BYTES} bytes");
        }
        if io_failed {
            return None;
        }

        let final_count = self.commit_ranges(new_ranges);
        info!(
            "Loaded {count} entries ({final_count} ranges after merge) from .p2p file {}",
            path.display()
        );
        Some(final_count)
    }

    /// Load a PeerGuardian .p2b binary file (v1 or v2).
    pub fn load_p2b_file(&mut self, path: &Path) -> Option<usize> {
        // A .p2b stores tiny fixed-size records, so a legitimate full list is
        // comfortably under this cap. Refuse to slurp a pathologically large
        // (or malicious) file into memory.
        const MAX_P2B_BYTES: u64 = 256 * 1024 * 1024;
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() > MAX_P2B_BYTES {
                warn!(
                    ".p2b file too large ({} bytes), refusing to load",
                    meta.len()
                );
                return None;
            }
        }
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read .p2b file: {e}");
                return None;
            }
        };

        if data.len() < 8 {
            warn!(".p2b file too small");
            return None;
        }

        if &data[0..4] != b"\xff\xff\xff\xff" || &data[4..7] != b"P2B" {
            warn!("Invalid .p2b header");
            return None;
        }

        let version = data[7];
        if version != 1 && version != 2 {
            warn!("Unsupported .p2b version: {version}");
            return None;
        }

        let mut pos = 8;
        let mut new_ranges = Vec::new();
        let mut count = 0;

        while pos < data.len() {
            let name_end = data[pos..].iter().position(|&b| b == 0);
            let name_end = match name_end {
                Some(e) => pos + e,
                None => break,
            };
            let desc = String::from_utf8_lossy(&data[pos..name_end]).to_string();
            pos = name_end + 1;

            if pos + 8 > data.len() {
                break;
            }

            let start =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            let end = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;

            if start <= end {
                new_ranges.push(IpRange::new(start, end, desc));
                count += 1;
            }
        }

        let final_count = self.commit_ranges(new_ranges);
        info!(
            "Loaded {count} entries ({final_count} ranges after merge) from .p2b file {}",
            path.display()
        );
        Some(final_count)
    }
}

/// Returns true if the IP is private (RFC1918), loopback, link-local, or any
/// other special-use / reserved range.
///
/// Thin alias over the crate-wide [`crate::security::is_special_use_v4`]
/// classifier so every code path agrees on what "private or reserved" means.
/// Kept as a named export for the KAD callback-source and routing call sites.
pub fn is_private_or_reserved(ip: Ipv4Addr) -> bool {
    crate::security::is_special_use_v4(ip)
}

pub fn is_lan_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

/// Whether `ip` is acceptable as a KAD contact / download source.
///
/// Always rejects truly-unroutable space ([`crate::security::is_bogus_v4`]):
/// `0.0.0.0/8`, class-E, broadcast, multicast, documentation / benchmarking,
/// etc. — none of which can be a real peer regardless of settings. RFC1918 /
/// link-local / CGNAT space is rejected only when `block_private` is set, so a
/// user who deliberately turns the toggle off to reach LAN peers still doesn't
/// admit obvious garbage into the routing table.
pub fn is_valid_contact_ip(ip: Ipv4Addr, block_private: bool) -> bool {
    if crate::security::is_bogus_v4(ip) {
        return false;
    }
    if block_private && crate::security::is_lan_or_cgnat_v4(ip) {
        return false;
    }
    true
}

fn parse_p2p_line(line: &str) -> Option<IpRange> {
    let colon_pos = line.rfind(':')?;
    let description = line[..colon_pos].trim().to_string();
    let ip_range = line[colon_pos + 1..].trim();
    let dash_pos = ip_range.find('-')?;
    let start_ip = parse_ip_lenient(&ip_range[..dash_pos])?;
    let end_ip = parse_ip_lenient(&ip_range[dash_pos + 1..])?;
    let start = u32::from(start_ip);
    let end = u32::from(end_ip);
    if start > end {
        return None;
    }
    Some(IpRange::new(start, end, description))
}

/// Parse an IP address string, handling leading zeros (e.g., "003.000.000.000")
/// which are common in ipfilter.dat files but rejected by Rust's Ipv4Addr parser.
fn parse_ip_lenient(s: &str) -> Option<Ipv4Addr> {
    let s = s.trim();
    // Try direct parse first (fast path for IPs without leading zeros)
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    // Strip leading zeros from each octet and retry
    let stripped: String = s
        .split('.')
        .map(|octet| {
            let trimmed = octet.trim_start_matches('0');
            if trimmed.is_empty() {
                "0"
            } else {
                trimmed
            }
        })
        .collect::<Vec<_>>()
        .join(".");
    stripped.parse().ok()
}

/// eMule's default IP-filter level. An ipfilter.dat entry blocks only when its
/// access level is *below* this value; `level >= 127` means "permitted" (kept
/// in the file for reference, not enforced). We expose no user-facing filter
/// level, so we hard-code eMule's documented default rather than the off-by-one
/// `>= 128` cutoff this used to apply (which wrongly blocked level-127 entries).
const IPFILTER_BLOCK_LEVEL: u32 = 127;

fn parse_ipfilter_line(line: &str) -> Option<IpRange> {
    let parts: Vec<&str> = line.splitn(3, ',').collect();
    if parts.len() < 2 {
        return None;
    }

    let access_level: u32 = parts[1].trim().parse().ok()?;
    if access_level >= IPFILTER_BLOCK_LEVEL {
        return None;
    }

    let description = if parts.len() >= 3 {
        parts[2].trim().to_string()
    } else {
        String::new()
    };

    // Range form is "start - end"; a bare single IP (no dash) is a /32 host.
    let ip_range_part = parts[0].trim();
    let (start_ip, end_ip) = match ip_range_part.split_once('-') {
        Some((s, e)) => (parse_ip_lenient(s)?, parse_ip_lenient(e)?),
        None => {
            let single = parse_ip_lenient(ip_range_part)?;
            (single, single)
        }
    };
    let start = u32::from(start_ip);
    let end = u32::from(end_ip);
    if start > end {
        return None;
    }

    Some(IpRange::new(start, end, description))
}

/// Count how many valid IP-filter entries `data` contains, without
/// constructing or mutating an [`IpFilter`] and without touching disk.
/// `ext_hint` selects the parser the same way [`IpFilter::load_from_file`]
/// dispatches on a path's extension (`"p2b"` -> PeerGuardian binary,
/// `"p2p"` -> PeerGuardian text, anything else -> eMule `ipfilter.dat` /
/// plain text, which also accepts `.p2p`-style lines as a fallback).
///
/// This exists so a downloaded or imported payload can be sanity-checked
/// *before* it's ever written over `ipfilter.dat` or handed to
/// `ReloadIpFilter` — a corrupt response, an HTML error page from a dead
/// mirror, or a truncated transfer parses to zero entries here, so the
/// command handler can reject it up front instead of letting
/// `load_from_file` faithfully replace a working filter with an empty one.
/// See `commands::security::download_and_load_ipfilter` and friends.
pub fn count_valid_entries(data: &[u8], ext_hint: &str) -> usize {
    match ext_hint.to_ascii_lowercase().as_str() {
        "p2b" => count_p2b_entries(data),
        "p2p" => count_text_entries(data, false),
        _ => count_text_entries(data, true),
    }
}

/// Shared line-counting pass for the `.dat`/`.txt` and `.p2p` formats.
/// `try_dat_format` mirrors `load_dat_file`'s fallback behavior (attempt the
/// eMule parser, then the PeerGuardian one) versus `load_p2p_file`, which
/// only ever accepts PeerGuardian-style lines.
fn count_text_entries(data: &[u8], try_dat_format: bool) -> usize {
    let mut count = 0;
    // `read_until` in the loaders includes the newline in its byte count and
    // only examines the first `MAX_TEXT_FILTER_LINES` records. Match both
    // details exactly so preflight cannot accept entries the real load drops.
    for raw_line in data
        .split_inclusive(|&b| b == b'\n')
        .take(MAX_TEXT_FILTER_LINES)
    {
        if raw_line.len() > MAX_TEXT_FILTER_LINE_BYTES {
            continue;
        }
        // Lossy decoding matches the tolerance real ipfilter.dat downloads
        // need (non-UTF8 bytes occasionally show up in description fields);
        // a strict UTF-8 requirement here would make this validator
        // *stricter* than the loader it's meant to predict.
        let line = String::from_utf8_lossy(raw_line);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let is_valid = if try_dat_format {
            parse_ipfilter_line(line).is_some() || parse_p2p_line(line).is_some()
        } else {
            parse_p2p_line(line).is_some()
        };
        if is_valid {
            count += 1;
        }
    }
    count
}

/// Mirrors [`IpFilter::load_p2b_file`]'s header check and record walk
/// without allocating descriptions or storing ranges.
fn count_p2b_entries(data: &[u8]) -> usize {
    if data.len() < 8 || &data[0..4] != b"\xff\xff\xff\xff" || &data[4..7] != b"P2B" {
        return 0;
    }
    let version = data[7];
    if version != 1 && version != 2 {
        return 0;
    }

    let mut pos = 8;
    let mut count = 0;
    while pos < data.len() {
        let name_end = match data[pos..].iter().position(|&b| b == 0) {
            Some(e) => pos + e,
            None => break,
        };
        pos = name_end + 1;
        if pos + 8 > data.len() {
            break;
        }
        let start = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        let end = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        if start <= end {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ips() {
        assert!(is_private_or_reserved(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_or_reserved(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_or_reserved(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_or_reserved(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_or_reserved(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_private_or_reserved(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_private_or_reserved(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(is_private_or_reserved(Ipv4Addr::new(100, 64, 0, 1))); // CGNAT
        assert!(is_private_or_reserved(Ipv4Addr::new(198, 18, 0, 1))); // benchmarking
        assert!(is_private_or_reserved(Ipv4Addr::new(192, 88, 99, 1))); // 6to4 anycast
        assert!(is_private_or_reserved(Ipv4Addr::new(224, 0, 0, 1))); // multicast
        assert!(!is_private_or_reserved(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_or_reserved(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_ip_filter_with_ranges() {
        let mut filter = IpFilter::new(true, false);
        filter.mark_ranges_ready();
        filter.add_range(
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 255),
            "test".to_string(),
        );
        assert!(filter.is_blocked(Ipv4Addr::new(1, 0, 0, 50)));
        assert!(!filter.is_blocked(Ipv4Addr::new(2, 0, 0, 50)));
    }

    #[test]
    fn test_ip_filter_disabled() {
        let mut filter = IpFilter::new(false, false);
        filter.add_range(
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 255),
            String::new(),
        );
        assert!(!filter.is_blocked(Ipv4Addr::new(1, 0, 0, 50)));
        assert!(filter.is_blocked(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_ip_filter_block_private() {
        let mut filter = IpFilter::new(false, true);
        assert!(filter.is_blocked(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!filter.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));

        let mut filter_no_priv = IpFilter::new(false, false);
        assert!(!filter_no_priv.is_blocked(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_valid_contact_ip() {
        assert!(is_valid_contact_ip(Ipv4Addr::new(8, 8, 8, 8), true));
        assert!(!is_valid_contact_ip(Ipv4Addr::new(192, 168, 1, 1), true));
        assert!(is_valid_contact_ip(Ipv4Addr::new(192, 168, 1, 1), false));
        assert!(!is_valid_contact_ip(Ipv4Addr::UNSPECIFIED, false));
        assert!(!is_valid_contact_ip(Ipv4Addr::LOCALHOST, false));
    }

    #[test]
    fn test_valid_contact_ip_rejects_bogus_even_when_private_allowed() {
        // With block_private = false a user may want LAN peers, but bogus /
        // unroutable space must still be refused — this is the regression that
        // motivated splitting "bogus (always)" from "LAN (gated)".
        for ip in [
            Ipv4Addr::new(0, 1, 2, 3),         // 0.0.0.0/8 "this network"
            Ipv4Addr::new(240, 0, 0, 1),       // class E / reserved
            Ipv4Addr::new(255, 255, 255, 255), // limited broadcast
            Ipv4Addr::new(224, 0, 0, 1),       // multicast
            Ipv4Addr::new(192, 0, 2, 5),       // TEST-NET-1 (documentation)
            Ipv4Addr::new(198, 51, 100, 7),    // TEST-NET-2
            Ipv4Addr::new(203, 0, 113, 9),     // TEST-NET-3
            Ipv4Addr::new(198, 18, 0, 1),      // benchmarking
            Ipv4Addr::new(192, 0, 0, 1),       // protocol assignments
            Ipv4Addr::new(192, 88, 99, 1),     // 6to4 relay anycast
        ] {
            assert!(
                !is_valid_contact_ip(ip, false),
                "{ip} must be rejected even with block_private = false"
            );
        }
        // LAN space, by contrast, is admitted only when block_private is off.
        assert!(is_valid_contact_ip(Ipv4Addr::new(10, 0, 0, 5), false));
        assert!(!is_valid_contact_ip(Ipv4Addr::new(10, 0, 0, 5), true));
        // A normal public address is always fine.
        assert!(is_valid_contact_ip(Ipv4Addr::new(1, 1, 1, 1), false));
    }

    #[test]
    fn test_is_blocked_rejects_bogus_when_filter_off_and_private_allowed() {
        // Filter disabled AND private allowed: still must drop unroutable IPs.
        let mut filter = IpFilter::new(false, false);
        assert!(filter.is_blocked(Ipv4Addr::new(0, 1, 2, 3)));
        assert!(filter.is_blocked(Ipv4Addr::new(240, 0, 0, 1)));
        assert!(filter.is_blocked(Ipv4Addr::new(192, 0, 2, 5)));
        // ...but a genuine public IP passes when the filter is off.
        assert!(!filter.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));
        // LAN is allowed through when block_private is off.
        assert!(!filter.is_blocked(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_hit_counting() {
        let mut filter = IpFilter::new(true, false);
        filter.mark_ranges_ready();
        filter.add_range(
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 255),
            "test range".to_string(),
        );
        filter.is_blocked(Ipv4Addr::new(1, 0, 0, 1));
        filter.is_blocked(Ipv4Addr::new(1, 0, 0, 2));
        filter.is_blocked(Ipv4Addr::new(1, 0, 0, 3));
        let stats = filter.get_stats();
        assert_eq!(stats.total_hits, 3);
        assert_eq!(stats.entries[0].hits, 3);
        assert_eq!(stats.entries[0].description, "test range");
    }

    #[test]
    fn test_remove_range() {
        let mut filter = IpFilter::new(true, false);
        filter.add_range(
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 255),
            String::new(),
        );
        assert_eq!(filter.range_count(), 1);
        assert!(filter.remove_range("1.0.0.0", "1.0.0.255"));
        assert_eq!(filter.range_count(), 0);
    }

    #[test]
    fn test_parse_ipfilter_dat_format() {
        // Standard emule ipfilter.dat format
        let line1 = "1.0.0.0 - 1.0.0.255 , 000 , Test Range";
        let r1 = parse_ipfilter_line(line1);
        assert!(r1.is_some(), "Failed to parse standard ipfilter.dat line");
        let r1 = r1.unwrap();
        assert_eq!(r1.start, u32::from(Ipv4Addr::new(1, 0, 0, 0)));
        assert_eq!(r1.end, u32::from(Ipv4Addr::new(1, 0, 0, 255)));
        assert_eq!(r1.description, "Test Range");

        // With leading zeros (common in ipfilter.dat files)
        let line2 = "003.000.000.000 - 003.255.255.255 , 000 , IANA-ARIN";
        let r2 = parse_ipfilter_line(line2);
        assert!(
            r2.is_some(),
            "Failed to parse ipfilter.dat line with leading zeros"
        );
        let r2 = r2.unwrap();
        assert_eq!(r2.start, u32::from(Ipv4Addr::new(3, 0, 0, 0)));
        assert_eq!(r2.end, u32::from(Ipv4Addr::new(3, 255, 255, 255)));
        assert_eq!(r2.description, "IANA-ARIN");

        // Without leading zeros (should always work)
        let line3 = "3.0.0.0 - 3.255.255.255 , 000 , IANA-ARIN";
        let r3 = parse_ipfilter_line(line3);
        assert!(
            r3.is_some(),
            "Failed to parse ipfilter.dat line without leading zeros"
        );

        // Access level boundary: eMule blocks `level < 127`, permits `>= 127`.
        assert!(
            parse_ipfilter_line("1.0.0.0 - 1.0.0.255 , 128 , Allowed").is_none(),
            "Should skip access level 128"
        );
        assert!(
            parse_ipfilter_line("1.0.0.0 - 1.0.0.255 , 127 , Allowed").is_none(),
            "Level 127 is permitted in eMule and must be skipped"
        );
        assert!(
            parse_ipfilter_line("1.0.0.0 - 1.0.0.255 , 126 , Blocked").is_some(),
            "Level 126 is below the filter level and must be kept"
        );

        // Single-host entry (no dash) is treated as a /32.
        let host = parse_ipfilter_line("1.2.3.4 , 0 , Single host");
        assert!(host.is_some(), "Failed to parse single-host ipfilter entry");
        let host = host.unwrap();
        assert_eq!(host.start, u32::from(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(host.end, u32::from(Ipv4Addr::new(1, 2, 3, 4)));

        // P2P format
        let p2p = "Test Range:1.0.0.0-1.0.0.255";
        let rp = parse_p2p_line(p2p);
        assert!(rp.is_some(), "Failed to parse P2P line");
    }

    #[test]
    fn test_snapshot_hit_accounting() {
        // Range hits and special/bogus hits must land in separate buckets so
        // the stats UI doesn't report private/bogus blocks as range matches.
        let mut filter = IpFilter::new(true, true);
        filter.mark_ranges_ready();
        filter.add_range(
            Ipv4Addr::new(5, 0, 0, 0),
            Ipv4Addr::new(5, 0, 0, 255),
            "range".to_string(),
        );
        let shared = filter.create_shared_snapshot();
        {
            let snap = shared.read().unwrap();
            assert!(snap.is_blocked(Ipv4Addr::new(5, 0, 0, 1))); // range hit
            assert!(snap.is_blocked(Ipv4Addr::new(192, 168, 0, 1))); // LAN (gated) hit
            assert!(snap.is_blocked(Ipv4Addr::new(240, 0, 0, 1))); // bogus hit
            assert!(!snap.is_blocked(Ipv4Addr::new(8, 8, 8, 8))); // public, allowed
            assert_eq!(snap.hit_counter.load(Ordering::Relaxed), 1);
            assert_eq!(snap.special_hit_counter.load(Ordering::Relaxed), 2);
        }
        filter.collect_shared_hits(&shared);
        let stats = filter.get_stats();
        // 1 range hit + 2 special hits, none double-counted.
        assert_eq!(stats.total_hits, 3);
        assert_eq!(
            stats.entries[0].hits, 1,
            "shared range hits must show in the Hits column"
        );
    }

    #[test]
    fn test_readonly_hit_counting_attributes_per_range() {
        let mut filter = IpFilter::new(true, false);
        filter.mark_ranges_ready();
        filter.add_range(
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 255),
            "test range".to_string(),
        );
        assert!(filter.is_blocked_readonly(Ipv4Addr::new(1, 0, 0, 1)));
        assert!(filter.is_blocked_readonly(Ipv4Addr::new(1, 0, 0, 2)));
        let stats = filter.get_stats();
        assert_eq!(stats.total_hits, 2);
        assert_eq!(stats.entries[0].hits, 2);
    }

    #[test]
    fn test_enabled_fail_closed_until_ranges_ready() {
        let mut filter = IpFilter::new(true, false);
        assert!(!filter.ranges_ready());
        // Public IP must be blocked while the deferred load has not finished.
        assert!(filter.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(filter.is_blocked_readonly(Ipv4Addr::new(1, 1, 1, 1)));

        filter.mark_ranges_ready();
        assert!(filter.ranges_ready());
        assert!(!filter.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));

        let snap = filter.create_shared_snapshot();
        let snap = snap.read().unwrap();
        assert!(snap.ranges_ready);
        assert!(!snap.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_kad_admission_skips_fail_closed_until_ranges_ready() {
        let mut filter = IpFilter::new(true, false);
        assert!(!filter.ranges_ready());
        // Peer gates still fail-closed…
        assert!(filter.is_blocked_readonly(Ipv4Addr::new(8, 8, 8, 8)));
        // …but KAD UDP / RT insert must admit so bootstrap can proceed.
        assert!(!filter.is_blocked_readonly_for_kad(Ipv4Addr::new(8, 8, 8, 8)));
        let snap = filter.create_shared_snapshot();
        let snap = snap.read().unwrap();
        assert!(snap.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!snap.is_blocked_for_kad(Ipv4Addr::new(8, 8, 8, 8)));
        drop(snap);

        filter.mark_ranges_ready();
        // With an empty intentional list, KAD path still admits public IPs.
        assert!(!filter.is_blocked_readonly_for_kad(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_set_enabled_reopens_fail_closed_gate() {
        let mut filter = IpFilter::new(false, false);
        assert!(filter.ranges_ready());
        filter.set_enabled(true);
        assert!(!filter.ranges_ready());
        assert!(filter.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));
        filter.mark_ranges_ready();
        assert!(!filter.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));
        filter.set_enabled(false);
        assert!(filter.ranges_ready());
    }

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "ember_ipfilter_test_{}_{}_{name}",
            std::process::id(),
            nanos,
        ))
    }

    #[test]
    fn test_load_from_file_fully_replaces_old_ranges() {
        // The core guarantee behind "downloading a fresh filter removes the
        // old one": reloading from a new file must not merge with whatever
        // was already in memory, whether that's a previous download or a
        // manually-added range.
        let path = unique_temp_path("replace.dat");
        std::fs::write(&path, "1.0.0.0 - 1.0.0.255 , 000 , First List\n")
            .expect("write first ipfilter.dat");

        let mut filter = IpFilter::new(true, false);
        assert_eq!(filter.load_from_file(&path), Some(1));
        assert!(filter.is_blocked(Ipv4Addr::new(1, 0, 0, 1)));

        filter.add_range(
            Ipv4Addr::new(9, 9, 9, 0),
            Ipv4Addr::new(9, 9, 9, 255),
            "manual".to_string(),
        );
        assert_eq!(filter.range_count(), 2);

        std::fs::write(&path, "2.0.0.0 - 2.0.0.255 , 000 , Second List\n")
            .expect("write second ipfilter.dat");
        assert_eq!(filter.load_from_file(&path), Some(1));

        assert_eq!(
            filter.range_count(),
            1,
            "old ranges must not survive a fresh load"
        );
        assert!(
            !filter.is_blocked(Ipv4Addr::new(1, 0, 0, 1)),
            "stale range from the first file must be gone"
        );
        assert!(
            !filter.is_blocked(Ipv4Addr::new(9, 9, 9, 1)),
            "manually-added range must be gone after a fresh load"
        );
        assert!(
            filter.is_blocked(Ipv4Addr::new(2, 0, 0, 1)),
            "the fresh list's range must be active"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_from_file_tolerates_invalid_utf8_mid_file() {
        // `BufRead::lines()` hard-errors (and used to abort the whole parse)
        // on the first byte sequence that isn't valid UTF-8. A stray bad
        // byte partway through a large real-world ipfilter.dat must not
        // silently discard every range that came after it.
        let path = unique_temp_path("invalid_utf8.dat");
        let mut data = Vec::new();
        data.extend_from_slice(b"1.0.0.0 - 1.0.0.255 , 000 , Before\n");
        data.extend_from_slice(&[0xFF, 0xFE, b'\n']); // invalid UTF-8, own line
        data.extend_from_slice(b"2.0.0.0 - 2.0.0.255 , 000 , After\n");
        std::fs::write(&path, &data).expect("write ipfilter.dat with invalid utf8");

        let mut filter = IpFilter::new(true, false);
        assert_eq!(filter.load_from_file(&path), Some(2));
        assert!(filter.is_blocked(Ipv4Addr::new(1, 0, 0, 1)));
        assert!(
            filter.is_blocked(Ipv4Addr::new(2, 0, 0, 1)),
            "ranges after an invalid-UTF8 line must still load"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_from_file_missing_file_keeps_existing_ranges() {
        let mut filter = IpFilter::new(true, false);
        filter.add_range(
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 255),
            "keep me".to_string(),
        );

        let missing = unique_temp_path("does-not-exist.dat");
        assert_eq!(filter.load_from_file(&missing), None);

        // A failed read must never wipe out a working filter — "fail
        // closed", not fail open — so a bad download/import path can't
        // silently drop protection.
        assert_eq!(filter.range_count(), 1);
        assert!(filter.is_blocked(Ipv4Addr::new(1, 0, 0, 1)));
    }

    #[test]
    fn test_load_from_file_corrupt_p2b_keeps_existing_ranges() {
        let mut filter = IpFilter::new(true, false);
        filter.add_range(
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 0, 0, 255),
            "keep me".to_string(),
        );

        let path = unique_temp_path("corrupt.p2b");
        std::fs::write(&path, b"not a p2b file").expect("write corrupt p2b");
        assert_eq!(filter.load_from_file(&path), None);
        assert_eq!(
            filter.range_count(),
            1,
            "a corrupt binary header must not clear the existing filter"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_count_valid_entries_dat_format() {
        let data = b"# comment\n1.0.0.0 - 1.0.0.255 , 000 , Blocked\n1.2.3.4 , 0 , Single host\n";
        assert_eq!(count_valid_entries(data, "dat"), 2);
    }

    #[test]
    fn test_count_valid_entries_rejects_garbage() {
        // An HTML error page (or any content with no parseable lines) from a
        // dead mirror must count as zero — this is what lets the download
        // commands refuse to overwrite a working filter with garbage.
        let html = b"<!DOCTYPE html>\n<html><body>404 Not Found</body></html>\n";
        assert_eq!(count_valid_entries(html, "dat"), 0);
        assert_eq!(count_valid_entries(b"", "dat"), 0);
    }

    #[test]
    fn preflight_rejects_entries_the_loader_drops_for_line_length() {
        let mut data = b"1.2.3.4 - 1.2.3.4 , 0 , ".to_vec();
        data.extend(vec![b'x'; MAX_TEXT_FILTER_LINE_BYTES]);
        data.push(b'\n');

        // This text is syntactically a valid range, but the streaming loader
        // drops it because the raw line exceeds its 8 KiB cap. Preflight must
        // make the identical decision so a live filter cannot be replaced by
        // an empty one.
        assert_eq!(count_valid_entries(&data, "dat"), 0);

        data.extend_from_slice(b"8.8.8.8 - 8.8.8.8 , 0 , valid\n");
        assert_eq!(count_valid_entries(&data, "dat"), 1);
    }

    #[test]
    fn test_count_valid_entries_p2p_format() {
        let data = b"Some List:1.0.0.0-1.0.0.255\nAnother:2.0.0.0-2.255.255.255\n";
        assert_eq!(count_valid_entries(data, "p2p"), 2);
    }

    #[test]
    fn test_count_valid_entries_p2b_format() {
        // Build a minimal valid .p2b (v1) buffer by hand, mirroring
        // `load_p2b_file`'s expected layout: magic + version, then a
        // NUL-terminated description followed by 4-byte start/end (BE).
        let mut data = Vec::new();
        data.extend_from_slice(b"\xff\xff\xff\xffP2B");
        data.push(1);
        data.extend_from_slice(b"desc\0");
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&10u32.to_be_bytes());
        assert_eq!(count_valid_entries(&data, "p2b"), 1);
        assert_eq!(count_valid_entries(b"not a p2b file", "p2b"), 0);
    }

    #[test]
    fn canonical_dat_bytes_preserve_p2b_ranges_across_restart() {
        let source = unique_temp_path("source.p2b");
        let persisted = unique_temp_path("ipfilter.dat");
        let mut data = Vec::new();
        data.extend_from_slice(b"\xff\xff\xff\xffP2B");
        data.push(1);
        data.extend_from_slice(b"binary\0");
        data.extend_from_slice(&u32::from(Ipv4Addr::new(8, 8, 8, 0)).to_be_bytes());
        data.extend_from_slice(&u32::from(Ipv4Addr::new(8, 8, 8, 255)).to_be_bytes());
        std::fs::write(&source, data).unwrap();

        let mut imported = IpFilter::new(true, false);
        assert_eq!(imported.load_from_file(&source), Some(1));
        std::fs::write(&persisted, imported.canonical_dat_bytes()).unwrap();

        let mut restarted = IpFilter::new(true, false);
        assert_eq!(restarted.load_from_file(&persisted), Some(1));
        assert!(restarted.is_blocked(Ipv4Addr::new(8, 8, 8, 8)));

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(persisted);
    }
}
