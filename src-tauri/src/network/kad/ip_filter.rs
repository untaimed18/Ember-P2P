use std::net::Ipv4Addr;
use std::path::Path;

use tracing::{info, warn};

/// An IP range that should be blocked.
#[derive(Debug, Clone)]
struct IpRange {
    start: u32,
    end: u32,
}

/// IP filter supporting eMule's ipfilter.dat format and private/reserved IP blocking.
///
/// The ipfilter.dat format is: start_ip - end_ip , access_level , description
/// Lines with access_level < 128 are blocked.
#[allow(dead_code)]
pub struct IpFilter {
    blocked_ranges: Vec<IpRange>,
    block_private: bool,
}

impl IpFilter {
    pub fn new() -> Self {
        IpFilter {
            blocked_ranges: Vec::new(),
            block_private: true,
        }
    }

    /// Load an ipfilter.dat file (eMule format).
    pub fn load_from_file(&mut self, path: &Path) -> usize {
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
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(range) = parse_ipfilter_line(line) {
                self.blocked_ranges.push(range);
                count += 1;
            }
        }

        self.blocked_ranges
            .sort_by_key(|r| r.start);

        info!("Loaded {count} IP filter ranges from {}", path.display());
        count
    }

    /// Check if an IPv4 address is blocked (by ipfilter.dat ranges or private/reserved).
    #[allow(dead_code)]
    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        if self.block_private && is_private_or_reserved(ip) {
            return true;
        }

        let ip_u32 = u32::from(ip);
        self.blocked_ranges
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
    }

    /// Check if an IP should be rejected for incoming packets from the network.
    /// Less strict than routing table insertion (allows some reserved ranges
    /// that might be legitimate in certain network configurations).
    pub fn is_blocked_for_packets(&self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            return true;
        }

        let ip_u32 = u32::from(ip);
        self.blocked_ranges
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
    }

    #[allow(dead_code)]
    pub fn range_count(&self) -> usize {
        self.blocked_ranges.len()
    }
}

/// Returns true if the IP is private (RFC1918), loopback, link-local, or reserved.
/// Used to prevent routing table pollution.
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
/// Returns true if the IP is valid for use in the routing table.
pub fn is_valid_contact_ip(ip: Ipv4Addr) -> bool {
    !is_private_or_reserved(ip)
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

    Some(IpRange { start, end })
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
    fn test_ip_filter() {
        let mut filter = IpFilter::new();
        filter.blocked_ranges.push(IpRange {
            start: u32::from(Ipv4Addr::new(1, 0, 0, 0)),
            end: u32::from(Ipv4Addr::new(1, 0, 0, 255)),
        });
        filter.blocked_ranges.sort_by_key(|r| r.start);
        filter.block_private = false;

        assert!(filter.is_blocked(Ipv4Addr::new(1, 0, 0, 50)));
        assert!(!filter.is_blocked(Ipv4Addr::new(2, 0, 0, 50)));
    }
}
