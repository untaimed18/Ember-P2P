//! `(IPv4, port)`-keyed map that can also say whether it holds any port for a
//! host without walking every key.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Deref;

/// A `HashMap` keyed by `(ip, port)` plus a per-host key count, so "do we hold
/// this host at any port" is a lookup rather than a scan. The Ember UDP gate
/// asks that for every inbound datagram, including a stranger's flood.
///
/// Reads go through `Deref` to the inner map. Nothing hands out the inner map
/// mutably: every change that can add or drop a key goes through a method here,
/// which is what keeps the counts exact.
pub(super) struct HostPortMap<V> {
    entries: HashMap<(Ipv4Addr, u16), V>,
    ports_per_host: HashMap<Ipv4Addr, usize>,
}

impl<V> Default for HostPortMap<V> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            ports_per_host: HashMap::new(),
        }
    }
}

impl<V> Deref for HostPortMap<V> {
    type Target = HashMap<(Ipv4Addr, u16), V>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl<V> HostPortMap<V> {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Whether any key names `ip`, at whatever port.
    pub(super) fn has_host(&self, ip: Ipv4Addr) -> bool {
        self.ports_per_host.contains_key(&ip)
    }

    /// How many keys name `ip`.
    pub(super) fn host_port_count(&self, ip: Ipv4Addr) -> usize {
        self.ports_per_host.get(&ip).copied().unwrap_or(0)
    }

    pub(super) fn insert(&mut self, key: (Ipv4Addr, u16), value: V) -> Option<V> {
        let old = self.entries.insert(key, value);
        if old.is_none() {
            *self.ports_per_host.entry(key.0).or_insert(0) += 1;
        }
        old
    }

    pub(super) fn remove(&mut self, key: &(Ipv4Addr, u16)) -> Option<V> {
        let old = self.entries.remove(key);
        if old.is_some() {
            release_port(&mut self.ports_per_host, key.0);
        }
        old
    }

    pub(super) fn retain(&mut self, mut keep: impl FnMut(&(Ipv4Addr, u16), &mut V) -> bool) {
        let ports_per_host = &mut self.ports_per_host;
        self.entries.retain(|key, value| {
            let kept = keep(key, value);
            if !kept {
                release_port(ports_per_host, key.0);
            }
            kept
        });
    }

    pub(super) fn get_mut(&mut self, key: &(Ipv4Addr, u16)) -> Option<&mut V> {
        self.entries.get_mut(key)
    }
}

fn release_port(ports_per_host: &mut HashMap<Ipv4Addr, usize>, ip: Ipv4Addr) {
    if let Entry::Occupied(mut held) = ports_per_host.entry(ip) {
        if *held.get() <= 1 {
            held.remove();
        } else {
            *held.get_mut() -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_counts_match(map: &HostPortMap<u32>) {
        for ip in (0..8u8).map(|d| Ipv4Addr::new(10, 0, 0, d)) {
            let scanned = map.keys().filter(|(held, _)| *held == ip).count();
            assert_eq!(map.host_port_count(ip), scanned, "count for {ip}");
            assert_eq!(map.has_host(ip), scanned > 0, "has_host for {ip}");
        }
        assert_eq!(
            map.ports_per_host.values().sum::<usize>(),
            map.len(),
            "no count may outlive its keys"
        );
    }

    #[test]
    fn host_counts_follow_every_mutation() {
        let mut map = HostPortMap::new();
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);

        assert!(map.insert((a, 1), 1).is_none());
        assert!(map.insert((a, 2), 2).is_none());
        assert_eq!(map.insert((a, 2), 3), Some(2), "overwriting keeps one key");
        assert!(map.insert((b, 1), 4).is_none());
        assert_counts_match(&map);
        assert_eq!(map.host_port_count(a), 2);

        assert_eq!(map.remove(&(a, 1)), Some(1));
        assert_eq!(map.remove(&(a, 1)), None, "a missing key releases nothing");
        assert_counts_match(&map);
        assert!(map.has_host(a));

        *map.get_mut(&(a, 2)).unwrap() = 9;
        assert_eq!(map.get(&(a, 2)), Some(&9));

        map.retain(|(ip, _), _| *ip != a);
        assert_counts_match(&map);
        assert!(!map.has_host(a));
        assert!(map.has_host(b));

        map.retain(|_, _| false);
        assert_counts_match(&map);
        assert!(!map.has_host(b));
    }

    /// The index answers exactly what the scan it replaces answered, across a
    /// long run of mixed inserts, removals and retains.
    #[test]
    fn host_counts_match_a_scan_under_churn() {
        let mut map = HostPortMap::new();
        let mut seed = 0x9E37_79B9u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        for step in 0..4_000u32 {
            let r = next();
            let key = (Ipv4Addr::new(10, 0, 0, (r % 8) as u8), ((r >> 8) % 5) as u16);
            match (r >> 16) % 7 {
                0..=2 => {
                    map.insert(key, step);
                }
                3..=4 => {
                    map.remove(&key);
                }
                5 => map.retain(|(_, port), v| !(*port as u32 + *v).is_multiple_of(3)),
                _ => {
                    if let Some(v) = map.get_mut(&key) {
                        *v = v.wrapping_add(1);
                    }
                }
            }
            assert_counts_match(&map);
        }
    }
}
