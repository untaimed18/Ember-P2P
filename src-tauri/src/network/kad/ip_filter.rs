use std::net::Ipv4Addr;
use std::path::Path;

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

#[derive(Debug, Clone, Serialize)]
pub struct IpFilterStats {
    pub enabled: bool,
    pub block_private: bool,
    pub range_count: usize,
    pub total_hits: u64,
    pub entries: Vec<IpFilterEntry>,
}

/// IP filter supporting eMule's ipfilter.dat format and private/reserved IP blocking.
///
/// The ipfilter.dat format is: start_ip - end_ip , access_level , description
/// Lines with access_level < 128 are blocked.
pub struct IpFilter {
    blocked_ranges: Vec<IpRange>,
    enabled: bool,
    block_private: bool,
}

impl IpFilter {
    pub fn new(enabled: bool, block_private: bool) -> Self {
        IpFilter {
            blocked_ranges: Vec::new(),
            enabled,
            block_private,
        }
    }

    /// Load an ipfilter.dat file (eMule format). Replaces existing ranges.
    pub fn load_from_file(&mut self, path: &Path) -> usize {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to read ipfilter.dat: {e}");
                return 0;
            }
        };

        self.blocked_ranges.clear();

        let mut count = 0;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(range) = parse_ipfilter_line(line) {
                self.blocked_ranges.push(range);
                count += 1;
            }
        }

        self.blocked_ranges.sort_by_key(|r| r.start);
        self.merge_overlapping();

        info!("Loaded {count} IP filter ranges from {}", path.display());
        count
    }

    fn merge_overlapping(&mut self) {
        if self.blocked_ranges.len() <= 1 {
            return;
        }
        let mut merged = Vec::with_capacity(self.blocked_ranges.len());
        merged.push(self.blocked_ranges[0].clone());
        for range in &self.blocked_ranges[1..] {
            let last = merged.last_mut().unwrap();
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

    /// Check if an IPv4 address should be blocked, incrementing hit count if so.
    pub fn is_blocked(&mut self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            return true;
        }

        if self.block_private && is_private_or_reserved(ip) {
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
                return true;
            }
        }

        false
    }

    /// Check if an IPv4 address is blocked without modifying hit counts.
    pub fn is_blocked_readonly(&self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            return true;
        }

        if self.block_private && is_private_or_reserved(ip) {
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

    pub fn get_stats(&self) -> IpFilterStats {
        let total_hits: u64 = self.blocked_ranges.iter().map(|r| r.hits).sum();
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
}

/// Returns true if the IP is private (RFC1918), loopback, link-local, or reserved.
pub fn is_private_or_reserved(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    if ip.is_unspecified() || ip.is_broadcast() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }

    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // 100.64.0.0/10 (carrier-grade NAT)
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }

    // 0.0.0.0/8 ("this network")
    if octets[0] == 0 {
        return true;
    }

    // 240.0.0.0/4 (reserved for future use)
    if octets[0] >= 240 {
        return true;
    }

    // 198.18.0.0/15 (benchmarking)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }

    // 192.0.0.0/24 and 192.0.2.0/24 (IETF protocol assignments / TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && (octets[2] == 0 || octets[2] == 2) {
        return true;
    }

    // 198.51.100.0/24 (TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }

    // 203.0.113.0/24 (TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }

    false
}

/// Validate an IP address received from a remote peer in contact info.
pub fn is_valid_contact_ip(ip: Ipv4Addr, block_private: bool) -> bool {
    if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback() {
        return false;
    }
    if block_private && is_private_or_reserved(ip) {
        return false;
    }
    true
}

fn parse_ipfilter_line(line: &str) -> Option<IpRange> {
    // Format: start_ip - end_ip , access_level , description
    let parts: Vec<&str> = line.splitn(3, ',').collect();
    if parts.len() < 2 {
        return None;
    }

    let access_level: u32 = parts[1].trim().parse().ok()?;
    if access_level >= 128 {
        return None;
    }

    let description = if parts.len() >= 3 {
        parts[2].trim().to_string()
    } else {
        String::new()
    };

    let ip_range_part = parts[0].trim();
    let ip_parts: Vec<&str> = ip_range_part.splitn(2, '-').collect();
    if ip_parts.len() != 2 {
        return None;
    }

    let start_ip: Ipv4Addr = ip_parts[0].trim().parse().ok()?;
    let end_ip: Ipv4Addr = ip_parts[1].trim().parse().ok()?;

    let start = u32::from(start_ip);
    let end = u32::from(end_ip);

    if start > end {
        return None;
    }

    Some(IpRange {
        start,
        end,
        description,
        hits: 0,
    })
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
    fn test_hit_counting() {
        let mut filter = IpFilter::new(true, false);
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
}
