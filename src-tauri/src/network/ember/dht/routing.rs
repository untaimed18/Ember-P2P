use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;

use tracing::{debug, trace};

use super::{
    EmberContact, EmberNodeId, ID_BITS, K_BUCKET_SIZE, MAX_PER_SUBNET_GLOBAL,
    MAX_PER_SUBNET_PER_BUCKET,
};

/// A single routing-table bucket with a replacement cache.
struct Bucket {
    contacts: VecDeque<EmberContact>,
    /// Replacement cache: contacts that couldn't be added because the bucket was full.
    /// When a bucket contact is evicted (failed liveness), the newest cache entry replaces it.
    replacement_cache: VecDeque<EmberContact>,
    /// Timestamp of last activity in this bucket (for adaptive refresh).
    last_activity: i64,
}

impl Bucket {
    fn new() -> Self {
        Self {
            contacts: VecDeque::with_capacity(K_BUCKET_SIZE),
            replacement_cache: VecDeque::with_capacity(K_BUCKET_SIZE),
            last_activity: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.contacts.len() >= K_BUCKET_SIZE
    }

    fn subnet_count(&self, subnet: u64) -> usize {
        self.contacts
            .iter()
            .filter(|c| c.subnet_key() == subnet)
            .count()
    }

    fn find(&self, id: &EmberNodeId) -> Option<usize> {
        self.contacts.iter().position(|c| c.node_id == *id)
    }

    fn find_in_cache(&self, id: &EmberNodeId) -> Option<usize> {
        self.replacement_cache.iter().position(|c| c.node_id == *id)
    }

    fn oldest_contact(&self) -> Option<&EmberContact> {
        self.contacts.front()
    }
}

/// Result of attempting to add a contact to the routing table.
pub enum AddResult {
    /// Contact was added or updated.
    Added,
    /// Bucket is full; the caller should ping this contact to see if it's alive.
    /// If the ping fails, call `evict_and_replace` to swap it out. `noise_pub`
    /// is carried so the caller can open a Noise session to the oldest contact
    /// without a separate routing-table lookup.
    PingOldest {
        addr: SocketAddr,
        node_id: EmberNodeId,
        noise_pub: [u8; 32],
    },
    /// Contact was rejected (duplicate subnet, etc.).
    Rejected,
}

/// Ember DHT routing table: 128 buckets indexed by XOR distance bit position.
pub struct RoutingTable {
    local_id: EmberNodeId,
    buckets: Vec<Bucket>,
    /// Global subnet counter: subnet_key → count of contacts across all buckets.
    global_subnet_count: HashMap<u64, usize>,
}

impl RoutingTable {
    pub fn new(local_id: EmberNodeId) -> Self {
        let mut buckets = Vec::with_capacity(ID_BITS);
        for _ in 0..ID_BITS {
            buckets.push(Bucket::new());
        }
        Self {
            local_id,
            buckets,
            global_subnet_count: HashMap::new(),
        }
    }

    pub fn local_id(&self) -> &EmberNodeId {
        &self.local_id
    }

    pub fn total_contacts(&self) -> usize {
        self.buckets.iter().map(|b| b.contacts.len()).sum()
    }

    /// Add or update a contact. Returns what action the caller should take.
    pub fn add_contact(&mut self, contact: EmberContact) -> AddResult {
        if contact.node_id == self.local_id {
            return AddResult::Rejected;
        }

        let bucket_idx = match self.local_id.bucket_index(&contact.node_id) {
            Some(idx) => idx,
            None => return AddResult::Rejected,
        };

        if bucket_idx >= ID_BITS {
            return AddResult::Rejected;
        }

        let subnet = contact.subnet_key();
        let bucket = &mut self.buckets[bucket_idx];

        // If already in the bucket, update it and move to back (most recent)
        if let Some(pos) = bucket.find(&contact.node_id) {
            let mut existing = bucket.contacts.remove(pos).unwrap();
            existing.addr = contact.addr;
            existing.noise_pub = contact.noise_pub;
            existing.ed25519_pub = contact.ed25519_pub;
            existing.last_seen = contact.last_seen;
            existing.failed_queries = 0;
            bucket.contacts.push_back(existing);
            bucket.last_activity = contact.last_seen;
            return AddResult::Added;
        }

        // Subnet diversity check: per-bucket
        if bucket.subnet_count(subnet) >= MAX_PER_SUBNET_PER_BUCKET {
            trace!(
                "Rejected contact {} (subnet limit per bucket)",
                contact.node_id
            );
            self.add_to_cache(bucket_idx, contact);
            return AddResult::Rejected;
        }

        // Subnet diversity check: global
        let global_count = self.global_subnet_count.get(&subnet).copied().unwrap_or(0);
        if global_count >= MAX_PER_SUBNET_GLOBAL {
            trace!("Rejected contact {} (global subnet limit)", contact.node_id);
            self.add_to_cache(bucket_idx, contact);
            return AddResult::Rejected;
        }

        if !bucket.is_full() {
            *self.global_subnet_count.entry(subnet).or_insert(0) += 1;
            bucket.contacts.push_back(contact);
            bucket.last_activity = chrono::Utc::now().timestamp();
            return AddResult::Added;
        }

        // Bucket is full — add to replacement cache and request ping of oldest
        let oldest = bucket.oldest_contact().unwrap();
        let ping_addr = oldest.addr;
        let ping_id = oldest.node_id;
        let ping_noise = oldest.noise_pub;
        self.add_to_cache(bucket_idx, contact);

        AddResult::PingOldest {
            addr: ping_addr,
            node_id: ping_id,
            noise_pub: ping_noise,
        }
    }

    /// Called when a liveness ping to the oldest contact in a bucket fails.
    /// Evicts the dead contact and promotes the newest replacement cache entry.
    pub fn evict_and_replace(&mut self, dead_id: &EmberNodeId) -> bool {
        let bucket_idx = match self.local_id.bucket_index(dead_id) {
            Some(idx) => idx,
            None => return false,
        };

        if bucket_idx >= ID_BITS {
            return false;
        }

        let bucket = &mut self.buckets[bucket_idx];
        let pos = match bucket.find(dead_id) {
            Some(p) => p,
            None => return false,
        };

        let removed = bucket.contacts.remove(pos).unwrap();
        let subnet = removed.subnet_key();
        if let Some(count) = self.global_subnet_count.get_mut(&subnet) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.global_subnet_count.remove(&subnet);
            }
        }

        // Promote the newest replacement-cache entry that still satisfies the
        // subnet-diversity limits. Blindly promoting the newest entry (the old
        // behaviour) let a bucket fill up with contacts from one subnet via the
        // cache, defeating the eclipse-resistance the `add_contact` checks
        // provide. We scan newest→oldest so the freshest eligible contact wins.
        let bucket = &mut self.buckets[bucket_idx];
        let mut chosen: Option<usize> = None;
        for i in (0..bucket.replacement_cache.len()).rev() {
            let cand_subnet = bucket.replacement_cache[i].subnet_key();
            let per_bucket_ok = bucket.subnet_count(cand_subnet) < MAX_PER_SUBNET_PER_BUCKET;
            let global_ok = self
                .global_subnet_count
                .get(&cand_subnet)
                .copied()
                .unwrap_or(0)
                < MAX_PER_SUBNET_GLOBAL;
            if per_bucket_ok && global_ok {
                chosen = Some(i);
                break;
            }
        }

        match chosen {
            Some(i) => {
                let replacement = self.buckets[bucket_idx]
                    .replacement_cache
                    .remove(i)
                    .unwrap();
                let new_subnet = replacement.subnet_key();
                *self.global_subnet_count.entry(new_subnet).or_insert(0) += 1;
                debug!(
                    "Evicted dead contact {}, replaced with {}",
                    removed.node_id, replacement.node_id
                );
                self.buckets[bucket_idx].contacts.push_back(replacement);
                true
            }
            None => {
                debug!(
                    "Evicted dead contact {}, no subnet-eligible replacement available",
                    removed.node_id
                );
                false
            }
        }
    }

    /// Mark a contact as having responded successfully (reset fail count, update timestamp).
    pub fn mark_alive(&mut self, node_id: &EmberNodeId) {
        let bucket_idx = match self.local_id.bucket_index(node_id) {
            Some(idx) => idx,
            None => return,
        };
        if bucket_idx >= ID_BITS {
            return;
        }

        let bucket = &mut self.buckets[bucket_idx];
        if let Some(pos) = bucket.find(node_id) {
            // Move the contact to the back of the deque so it becomes the
            // most-recently-seen entry. Kademlia's liveness rule relies on the
            // front being the least-recently-seen (the one we ping when the
            // bucket is full); without this touch a freshly-confirmed contact
            // could still be picked as the "oldest" eviction candidate.
            let mut contact = bucket.contacts.remove(pos).unwrap();
            let now = chrono::Utc::now().timestamp();
            contact.last_seen = now;
            contact.failed_queries = 0;
            bucket.contacts.push_back(contact);
            bucket.last_activity = now;
        }
    }

    /// Increment the failed-queries counter for a contact.
    /// Returns true if the contact should be evicted (exceeded MAX_FAILED_QUERIES).
    pub fn mark_failed(&mut self, node_id: &EmberNodeId) -> bool {
        let bucket_idx = match self.local_id.bucket_index(node_id) {
            Some(idx) => idx,
            None => return false,
        };
        if bucket_idx >= ID_BITS {
            return false;
        }

        let bucket = &mut self.buckets[bucket_idx];
        if let Some(pos) = bucket.find(node_id) {
            // Saturating so a contact stuck at u8::MAX can't wrap back to 0 and
            // dodge eviction forever.
            bucket.contacts[pos].failed_queries =
                bucket.contacts[pos].failed_queries.saturating_add(1);
            bucket.contacts[pos].failed_queries >= super::MAX_FAILED_QUERIES
        } else {
            false
        }
    }

    /// Return the `count` closest contacts to `target` from the routing table.
    pub fn find_closest(&self, target: &EmberNodeId, count: usize) -> Vec<EmberContact> {
        let mut all: Vec<(EmberNodeId, &EmberContact)> = Vec::new();

        for bucket in &self.buckets {
            for contact in &bucket.contacts {
                let dist = target.distance(&contact.node_id);
                all.push((dist, contact));
            }
        }

        all.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        all.into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// Get a contact by node ID, if it exists in the routing table.
    pub fn get_contact(&self, node_id: &EmberNodeId) -> Option<&EmberContact> {
        let bucket_idx = match self.local_id.bucket_index(node_id) {
            Some(idx) => idx,
            None => return None,
        };
        if bucket_idx >= ID_BITS {
            return None;
        }
        self.buckets[bucket_idx]
            .find(&node_id)
            .map(|pos| &self.buckets[bucket_idx].contacts[pos])
    }

    /// Return bucket indices that need refreshing (no activity for `threshold_secs`).
    pub fn stale_buckets(&self, threshold_secs: i64) -> Vec<usize> {
        let now = chrono::Utc::now().timestamp();
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| !b.contacts.is_empty() && (now - b.last_activity) > threshold_secs)
            .map(|(i, _)| i)
            .collect()
    }

    /// Pick non-empty bucket indices to refresh, stalest first, capped at
    /// `max`. With `force` the staleness threshold is ignored (used by the
    /// on-demand maintenance command so a refresh can be exercised even on
    /// a freshly-active table); otherwise only buckets idle for longer than
    /// `threshold_secs` are returned.
    pub fn buckets_for_refresh(&self, threshold_secs: i64, max: usize, force: bool) -> Vec<usize> {
        let now = chrono::Utc::now().timestamp();
        let mut candidates: Vec<(usize, i64)> = self
            .buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                !b.contacts.is_empty() && (force || (now - b.last_activity) > threshold_secs)
            })
            .map(|(i, b)| (i, b.last_activity))
            .collect();
        candidates.sort_by_key(|(_, last_activity)| *last_activity);
        candidates.into_iter().take(max).map(|(i, _)| i).collect()
    }

    /// All contacts, for persistence.
    pub fn all_contacts(&self) -> Vec<EmberContact> {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter().cloned())
            .collect()
    }

    /// Bulk-load contacts (e.g., from persisted nodes_ember.dat).
    pub fn load_contacts(&mut self, contacts: Vec<EmberContact>) {
        let count = contacts.len();
        let mut added = 0;
        for contact in contacts {
            if matches!(self.add_contact(contact), AddResult::Added) {
                added += 1;
            }
        }
        debug!("Loaded {added}/{count} contacts into Ember routing table");
    }

    // ── Internal helpers ──

    fn add_to_cache(&mut self, bucket_idx: usize, contact: EmberContact) {
        let bucket = &mut self.buckets[bucket_idx];

        // Don't add duplicates to cache
        if bucket.find_in_cache(&contact.node_id).is_some() {
            return;
        }

        if bucket.replacement_cache.len() >= K_BUCKET_SIZE {
            bucket.replacement_cache.pop_front();
        }
        bucket.replacement_cache.push_back(contact);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_id(byte: u8) -> EmberNodeId {
        let mut id = [0u8; 16];
        id[0] = byte;
        EmberNodeId(id)
    }

    fn make_contact(id_byte: u8, port: u16) -> EmberContact {
        EmberContact {
            node_id: make_id(id_byte),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, id_byte, 1)), port),
            noise_pub: [id_byte; 32],
            ed25519_pub: [id_byte; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        }
    }

    #[test]
    fn distance_is_xor() {
        let a = EmberNodeId([0xFF; 16]);
        let b = EmberNodeId([0x00; 16]);
        assert_eq!(a.distance(&b), EmberNodeId([0xFF; 16]));
        assert_eq!(a.distance(&a), EmberNodeId([0x00; 16]));
    }

    #[test]
    fn bucket_index_correctness() {
        let local = make_id(0);
        let far = make_id(0x80); // bit 127 differs
        assert_eq!(local.bucket_index(&far), Some(127));

        let close = make_id(0x01); // bit 120 differs
        assert_eq!(local.bucket_index(&close), Some(120));
    }

    #[test]
    fn add_and_find_contact() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);

        let c = make_contact(1, 4662);
        assert!(matches!(rt.add_contact(c.clone()), AddResult::Added));
        assert_eq!(rt.total_contacts(), 1);

        let closest = rt.find_closest(&make_id(1), 10);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].node_id, make_id(1));
    }

    #[test]
    fn rejects_self() {
        let local = make_id(42);
        let mut rt = RoutingTable::new(local);
        let c = make_contact(42, 4662);
        assert!(matches!(rt.add_contact(c), AddResult::Rejected));
    }

    #[test]
    fn bucket_full_triggers_ping_oldest() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);

        // Fill bucket 127 (all contacts with high bit set)
        for i in 0x80..0x80 + K_BUCKET_SIZE as u8 {
            // Use different subnets to avoid diversity rejection
            let c = EmberContact {
                node_id: make_id(i),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, i, 1, 1)), 4662),
                noise_pub: [i; 32],
                ed25519_pub: [i; 32],
                last_seen: chrono::Utc::now().timestamp(),
                failed_queries: 0,
            };
            assert!(matches!(rt.add_contact(c), AddResult::Added));
        }
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE);

        // One more should trigger PingOldest
        let extra = EmberContact {
            node_id: make_id(0x80 + K_BUCKET_SIZE as u8),
            addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(80, 0x80 + K_BUCKET_SIZE as u8, 1, 1)),
                4662,
            ),
            noise_pub: [0xFF; 32],
            ed25519_pub: [0xFF; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        };
        assert!(matches!(
            rt.add_contact(extra),
            AddResult::PingOldest { .. }
        ));
    }

    #[test]
    fn evict_and_replace_works() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);

        // Fill bucket with different-subnet contacts
        for i in 0x80..0x80 + K_BUCKET_SIZE as u8 {
            let c = EmberContact {
                node_id: make_id(i),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, i, 1, 1)), 4662),
                noise_pub: [i; 32],
                ed25519_pub: [i; 32],
                last_seen: chrono::Utc::now().timestamp(),
                failed_queries: 0,
            };
            rt.add_contact(c);
        }

        // Add one more (goes to replacement cache, triggers PingOldest)
        let replacement_id = 0x80 + K_BUCKET_SIZE as u8;
        let extra = EmberContact {
            node_id: make_id(replacement_id),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, replacement_id, 1, 1)), 4662),
            noise_pub: [replacement_id; 32],
            ed25519_pub: [replacement_id; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        };
        rt.add_contact(extra);

        // Evict the oldest (0x80) and replace from cache
        let dead_id = make_id(0x80);
        assert!(rt.evict_and_replace(&dead_id));
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE);

        // The replacement should now be in the table
        assert!(rt.get_contact(&make_id(replacement_id)).is_some());
        assert!(rt.get_contact(&dead_id).is_none());
    }

    fn contact_at(id: u8, a: u8, b: u8, c: u8, d: u8) -> EmberContact {
        EmberContact {
            node_id: make_id(id),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 4662),
            noise_pub: [id; 32],
            ed25519_pub: [id; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        }
    }

    #[test]
    fn mark_alive_moves_contact_to_back() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        // Fill bucket 127 with distinct-subnet contacts.
        for i in 0x80..0x80 + K_BUCKET_SIZE as u8 {
            assert!(matches!(
                rt.add_contact(contact_at(i, 80, i, 1, 1)),
                AddResult::Added
            ));
        }
        // Refresh the current oldest (0x80); it must no longer be the eviction
        // candidate once it moves to the back of the LRU deque.
        rt.mark_alive(&make_id(0x80));
        // The next add overflows the bucket — the ping target is the new oldest.
        match rt.add_contact(contact_at(0x80 + K_BUCKET_SIZE as u8, 80, 200, 1, 1)) {
            AddResult::PingOldest { node_id, .. } => assert_eq!(node_id, make_id(0x81)),
            _ => panic!("expected PingOldest with 0x81 as the new oldest"),
        }
    }

    #[test]
    fn evict_promotes_subnet_eligible_replacement() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        // 3 contacts in subnet 80.1.1.x — hits MAX_PER_SUBNET_PER_BUCKET (3).
        rt.add_contact(contact_at(0x80, 80, 1, 1, 1));
        rt.add_contact(contact_at(0x81, 80, 1, 1, 2));
        rt.add_contact(contact_at(0x82, 80, 1, 1, 3));
        // Fill the rest of the 20-slot bucket with distinct subnets.
        for k in 0..(K_BUCKET_SIZE as u8 - 3) {
            rt.add_contact(contact_at(0x83 + k, 80, 10 + k, 1, 1));
        }
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE);

        // Cache a fresh-subnet contact, then an over-limit subnet-A contact so
        // the over-limit one is the *newest* cache entry.
        rt.add_contact(contact_at(0x95, 80, 50, 1, 1)); // subnet B → cached
        rt.add_contact(contact_at(0x94, 80, 1, 1, 4)); // subnet A (full) → cached

        // Evicting a distinct-subnet live contact must promote the eligible
        // entry (0x95), skipping the subnet-saturated newest (0x94).
        assert!(rt.evict_and_replace(&make_id(0x83)));
        assert!(rt.get_contact(&make_id(0x95)).is_some());
        assert!(rt.get_contact(&make_id(0x94)).is_none());
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE);
    }

    #[test]
    fn find_closest_sorted_by_distance() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);

        rt.add_contact(make_contact(0x80, 4662)); // far
        rt.add_contact(make_contact(0x01, 4662)); // close
        rt.add_contact(make_contact(0x40, 4662)); // medium

        let target = make_id(0);
        let closest = rt.find_closest(&target, 10);
        assert_eq!(closest.len(), 3);
        // Closest to target (0x00) should be 0x01, 0x40, 0x80
        assert_eq!(closest[0].node_id, make_id(0x01));
        assert_eq!(closest[1].node_id, make_id(0x40));
        assert_eq!(closest[2].node_id, make_id(0x80));
    }

    #[test]
    fn update_existing_contact() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);

        let c1 = make_contact(1, 4662);
        rt.add_contact(c1);

        // Update with new port
        let c2 = EmberContact {
            node_id: make_id(1),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 1, 1)), 9999),
            noise_pub: [1; 32],
            ed25519_pub: [1; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        };
        assert!(matches!(rt.add_contact(c2), AddResult::Added));
        assert_eq!(rt.total_contacts(), 1);
        assert_eq!(rt.get_contact(&make_id(1)).unwrap().addr.port(), 9999);
    }

    #[test]
    fn mark_alive_resets_failures() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        rt.add_contact(make_contact(1, 4662));

        rt.mark_failed(&make_id(1));
        rt.mark_failed(&make_id(1));
        rt.mark_alive(&make_id(1));

        let c = rt.get_contact(&make_id(1)).unwrap();
        assert_eq!(c.failed_queries, 0);
    }

    #[test]
    fn persistence_round_trip() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local);
        rt.add_contact(make_contact(1, 4662));
        rt.add_contact(make_contact(2, 4663));

        let contacts = rt.all_contacts();
        assert_eq!(contacts.len(), 2);

        let mut rt2 = RoutingTable::new(local);
        rt2.load_contacts(contacts);
        assert_eq!(rt2.total_contacts(), 2);
    }
}
