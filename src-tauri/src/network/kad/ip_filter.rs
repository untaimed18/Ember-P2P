use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use tracing::{info, warn};

#[derive(Debug, Clone)]
struct IpRange {
    start: u32,
    end: u32,
    description: String,
    hits: u64,
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
    pub enabled: bool,
    pub block_private: bool,
    pub hit_counter: AtomicU64,
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
    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
            self.hit_counter.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.block_private && is_private_or_reserved(ip) {
            self.hit_counter.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled {
            let ip_u32 = u32::from(ip);
            if self.ranges
                .binary_search_by(|&(start, end)| {
                    if ip_u32 < start {
                        std::cmp::Ordering::Greater
                    } else if ip_u32 > end {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Equal
                    }
                })
                .is_ok()
            {
                self.hit_counter.fetch_add(1, Ordering::Relaxed);
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
    pub range_count: usize,
    pub total_hits: u64,
    pub entries: Vec<IpFilterEntry>,
}

pub struct IpFilter {
    blocked_ranges: Vec<IpRange>,
    enabled: bool,
    block_private: bool,
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
            total_range_hits: AtomicU64::new(0),
            total_special_hits: AtomicU64::new(0),
        }
    }

    /// Transfer accumulated hit counts from another IpFilter (used when replacing the filter instance).
    #[allow(dead_code)]
    pub fn transfer_hits_from(&mut self, old: &IpFilter) {
        let old_total = old.total_range_hits.load(Ordering::Relaxed);
        let old_special = old.total_special_hits.load(Ordering::Relaxed);
        self.total_range_hits.fetch_add(old_total, Ordering::Relaxed);
        self.total_special_hits.fetch_add(old_special, Ordering::Relaxed);

        let mut old_hits: std::collections::HashMap<(u32, u32), u64> = std::collections::HashMap::new();
        for r in &old.blocked_ranges {
            if r.hits > 0 {
                old_hits.insert((r.start, r.end), r.hits);
            }
        }
        for r in &mut self.blocked_ranges {
            if let Some(&hits) = old_hits.get(&(r.start, r.end)) {
                r.hits = hits;
            }
        }
    }

    pub fn load_from_file(&mut self, path: &Path) -> usize {
        let saved_hits: std::collections::HashMap<(u32, u32), u64> = self.blocked_ranges
            .iter()
            .filter(|r| r.hits > 0)
            .map(|r| ((r.start, r.end), r.hits))
            .collect();
        self.blocked_ranges.clear();

        let ext = path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let count = match ext.as_str() {
            "p2b" => self.load_p2b_file(path),
            "p2p" => self.load_p2p_file(path),
            _ => {
                let content = match std::fs::read_to_string(path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to read ipfilter.dat: {e}");
                        return 0;
                    }
                };

                let mut count = 0;
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                        continue;
                    }
                    if let Some(range) = parse_ipfilter_line(line) {
                        self.blocked_ranges.push(range);
                        count += 1;
                    } else if let Some(range) = parse_p2p_line(line) {
                        self.blocked_ranges.push(range);
                        count += 1;
                    }
                }

                self.blocked_ranges.sort_by_key(|r| r.start);
                self.merge_overlapping();
                info!("Loaded {count} IP filter entries ({} ranges after merge) from {}", self.blocked_ranges.len(), path.display());
                count
            }
        };

        if !saved_hits.is_empty() {
            for r in &mut self.blocked_ranges {
                if let Some(&hits) = saved_hits.get(&(r.start, r.end)) {
                    r.hits = hits;
                }
            }
        }
        count
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
                last.hits += range.hits;
            } else {
                merged.push(range.clone());
            }
        }
        self.blocked_ranges = merged;
    }

    pub fn is_blocked(&mut self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.block_private && is_private_or_reserved(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
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
                self.blocked_ranges[idx].hits += 1;
                self.total_range_hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    /// Check if an IP is blocked without requiring &mut self.
    /// Increments the atomic total hit counter but not per-range counters.
    pub fn is_blocked_readonly(&self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.block_private && is_private_or_reserved(ip) {
            self.total_special_hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.enabled {
            let ip_u32 = u32::from(ip);
            if self.blocked_ranges
                .binary_search_by(|range| {
                    if ip_u32 < range.start {
                        std::cmp::Ordering::Greater
                    } else if ip_u32 > range.end {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Equal
                    }
                })
                .is_ok()
            {
                self.total_range_hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
        }
        false
    }

    pub fn range_count(&self) -> usize {
        self.blocked_ranges.len()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn blocks_private(&self) -> bool {
        self.block_private
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn set_block_private(&mut self, block_private: bool) {
        self.block_private = block_private;
    }

    /// Create a shared snapshot for use by the upload handler.
    pub fn create_shared_snapshot(&self) -> SharedIpFilter {
        std::sync::Arc::new(std::sync::RwLock::new(IpFilterSnapshot {
            ranges: self.blocked_ranges.iter().map(|r| (r.start, r.end)).collect(),
            enabled: self.enabled,
            block_private: self.block_private,
            hit_counter: AtomicU64::new(0),
        }))
    }

    /// Update an existing shared snapshot with current filter state, preserving its hit counter.
    pub fn update_shared_snapshot(&self, shared: &SharedIpFilter) {
        if let Ok(mut snap) = shared.write() {
            snap.ranges = self.blocked_ranges.iter().map(|r| (r.start, r.end)).collect();
            snap.enabled = self.enabled;
            snap.block_private = self.block_private;
        }
    }

    /// Collect hits from the shared snapshot into the total counter.
    pub fn collect_shared_hits(&self, shared: &SharedIpFilter) {
        if let Ok(snap) = shared.read() {
            let hits = snap.hit_counter.swap(0, Ordering::Relaxed);
            if hits > 0 {
                self.total_range_hits.fetch_add(hits, Ordering::Relaxed);
            }
        }
    }

    pub fn get_stats(&self) -> IpFilterStats {
        let per_range_hits: u64 = self.blocked_ranges.iter().map(|r| r.hits).sum();
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
                hits: r.hits,
            })
            .collect();

        IpFilterStats {
            enabled: self.enabled,
            block_private: self.block_private,
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
        self.blocked_ranges.push(IpRange {
            start: s,
            end: e,
            description,
            hits: 0,
        });
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
    pub fn load_p2p_file(&mut self, path: &Path) -> usize {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read .p2p file: {e}");
                return 0;
            }
        };

        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if let Some(range) = parse_p2p_line(line) {
                self.blocked_ranges.push(range);
                count += 1;
            }
        }

        self.blocked_ranges.sort_by_key(|r| r.start);
        self.merge_overlapping();
        info!("Loaded {count} entries ({} ranges after merge) from .p2p file {}", self.blocked_ranges.len(), path.display());
        count
    }

    /// Load a PeerGuardian .p2b binary file (v1 or v2).
    pub fn load_p2b_file(&mut self, path: &Path) -> usize {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to read .p2b file: {e}");
                return 0;
            }
        };

        if data.len() < 8 {
            warn!(".p2b file too small");
            return 0;
        }

        if &data[0..4] != b"\xff\xff\xff\xff" || &data[4..7] != b"P2B" {
            warn!("Invalid .p2b header");
            return 0;
        }

        let version = data[7];
        if version != 1 && version != 2 {
            warn!("Unsupported .p2b version: {version}");
            return 0;
        }

        let mut pos = 8;
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

            let start = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            let end = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;

            if start <= end {
                self.blocked_ranges.push(IpRange {
                    start,
                    end,
                    description: desc,
                    hits: 0,
                });
                count += 1;
            }
        }

        self.blocked_ranges.sort_by_key(|r| r.start);
        self.merge_overlapping();
        info!("Loaded {count} entries ({} ranges after merge) from .p2b file {}", self.blocked_ranges.len(), path.display());
        count
    }

}

/// Returns true if the IP is private (RFC1918), loopback, link-local, or reserved.
pub fn is_private_or_reserved(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    if ip.is_unspecified() || ip.is_broadcast() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }
    if octets[0] == 10 { return true; }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) { return true; }
    if octets[0] == 192 && octets[1] == 168 { return true; }
    if octets[0] == 169 && octets[1] == 254 { return true; }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) { return true; }
    if octets[0] == 0 { return true; }
    if octets[0] >= 240 { return true; }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) { return true; }
    if octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2) { return true; }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 { return true; }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 { return true; }

    false
}

pub fn is_lan_ip(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

pub fn is_valid_contact_ip(ip: Ipv4Addr, block_private: bool) -> bool {
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
        return false;
    }
    if block_private && is_private_or_reserved(ip) {
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
    if start > end { return None; }
    Some(IpRange { start, end, description, hits: 0 })
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
    let stripped: String = s.split('.')
        .map(|octet| {
            let trimmed = octet.trim_start_matches('0');
            if trimmed.is_empty() { "0" } else { trimmed }
        })
        .collect::<Vec<_>>()
        .join(".");
    stripped.parse().ok()
}

fn parse_ipfilter_line(line: &str) -> Option<IpRange> {
    let parts: Vec<&str> = line.splitn(3, ',').collect();
    if parts.len() < 2 { return None; }

    let access_level: u32 = parts[1].trim().parse().ok()?;
    if access_level >= 128 { return None; }

    let description = if parts.len() >= 3 {
        parts[2].trim().to_string()
    } else {
        String::new()
    };

    let ip_range_part = parts[0].trim();
    let ip_parts: Vec<&str> = ip_range_part.splitn(2, '-').collect();
    if ip_parts.len() != 2 { return None; }

    let start_ip = parse_ip_lenient(ip_parts[0])?;
    let end_ip = parse_ip_lenient(ip_parts[1])?;
    let start = u32::from(start_ip);
    let end = u32::from(end_ip);
    if start > end { return None; }

    Some(IpRange { start, end, description, hits: 0 })
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
        assert!(!is_private_or_reserved(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_or_reserved(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_ip_filter_with_ranges() {
        let mut filter = IpFilter::new(true, false);
        filter.add_range(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 255), "test".to_string());
        assert!(filter.is_blocked(Ipv4Addr::new(1, 0, 0, 50)));
        assert!(!filter.is_blocked(Ipv4Addr::new(2, 0, 0, 50)));
    }

    #[test]
    fn test_ip_filter_disabled() {
        let mut filter = IpFilter::new(false, false);
        filter.add_range(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 255), String::new());
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
    fn test_hit_counting() {
        let mut filter = IpFilter::new(true, false);
        filter.add_range(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 255), "test range".to_string());
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
        filter.add_range(Ipv4Addr::new(1, 0, 0, 0), Ipv4Addr::new(1, 0, 0, 255), String::new());
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
        assert!(r2.is_some(), "Failed to parse ipfilter.dat line with leading zeros");
        let r2 = r2.unwrap();
        assert_eq!(r2.start, u32::from(Ipv4Addr::new(3, 0, 0, 0)));
        assert_eq!(r2.end, u32::from(Ipv4Addr::new(3, 255, 255, 255)));
        assert_eq!(r2.description, "IANA-ARIN");

        // Without leading zeros (should always work)
        let line3 = "3.0.0.0 - 3.255.255.255 , 000 , IANA-ARIN";
        let r3 = parse_ipfilter_line(line3);
        assert!(r3.is_some(), "Failed to parse ipfilter.dat line without leading zeros");

        // Access level >= 128 should be skipped
        let line4 = "1.0.0.0 - 1.0.0.255 , 128 , Allowed";
        assert!(parse_ipfilter_line(line4).is_none(), "Should skip access level >= 128");

        // P2P format
        let p2p = "Test Range:1.0.0.0-1.0.0.255";
        let rp = parse_p2p_line(p2p);
        assert!(rp.is_some(), "Failed to parse P2P line");
    }
}
