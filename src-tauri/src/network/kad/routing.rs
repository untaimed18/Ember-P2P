use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

use super::ip_filter;
use super::types::*;

const NUM_BUCKETS: usize = 128;
const BUCKET_REFRESH_INTERVAL_SECS: i64 = 3600;

/// eMule RoutingBin.cpp limits
const MAX_CONTACTS_IP: u32 = 1;
const MAX_CONTACTS_SUBNET: u32 = 10;
const MAX_CONTACTS_SUBNET_PER_BIN: usize = 2;

fn subnet_key(ip: Ipv4Addr) -> u32 {
    let octets = ip.octets();
    u32::from_be_bytes([octets[0], octets[1], octets[2], 0])
}

/// A pending eviction: we pinged the oldest contact; if it doesn't respond,
/// we evict it and insert the replacement.
#[derive(Debug, Clone)]
pub struct PendingEviction {
    pub bucket_idx: usize,
    pub old_contact_id: KadId,
    pub replacement: KadContact,
    pub pinged_at: i64,
}

#[derive(Debug)]
pub struct RoutingTable {
    local_id: KadId,
    buckets: Vec<KBucket>,
    pub pending_evictions: Vec<PendingEviction>,
    global_ip_count: HashMap<Ipv4Addr, u32>,
    global_subnet_count: HashMap<u32, u32>,
    block_private_ips: bool,
}

#[derive(Debug)]
struct KBucket {
    contacts: VecDeque<KadContact>,
    last_refresh: i64,
}

impl KBucket {
    fn new() -> Self {
        KBucket {
            contacts: VecDeque::with_capacity(K_BUCKET_SIZE),
            last_refresh: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.contacts.len() >= K_BUCKET_SIZE
    }

    fn needs_refresh(&self, now: i64) -> bool {
        now - self.last_refresh > BUCKET_REFRESH_INTERVAL_SECS
    }

    /// A bucket needs filling if it has contacts but is below 20% capacity.
    fn needs_fill(&self) -> bool {
        !self.contacts.is_empty() && self.contacts.len() < K_BUCKET_SIZE / 5
    }
}

impl RoutingTable {
    pub fn new(local_id: KadId, block_private_ips: bool) -> Self {
        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        for _ in 0..NUM_BUCKETS {
            buckets.push(KBucket::new());
        }
        RoutingTable {
            local_id,
            buckets,
            pending_evictions: Vec::new(),
            global_ip_count: HashMap::new(),
            global_subnet_count: HashMap::new(),
            block_private_ips,
        }
    }

    pub fn local_id(&self) -> &KadId {
        &self.local_id
    }

    fn track_ip_add(&mut self, ip: Ipv4Addr) {
        *self.global_ip_count.entry(ip).or_insert(0) += 1;
        *self.global_subnet_count.entry(subnet_key(ip)).or_insert(0) += 1;
    }

    fn track_ip_remove(&mut self, ip: Ipv4Addr) {
        if let Some(count) = self.global_ip_count.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.global_ip_count.remove(&ip);
            }
        }
        let snet = subnet_key(ip);
        if let Some(count) = self.global_subnet_count.get_mut(&snet) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.global_subnet_count.remove(&snet);
            }
        }
    }

    /// Remove a contact by ID. Returns true if it was present.
    pub fn remove(&mut self, id: &KadId) -> bool {
        let bucket_idx = self.bucket_for(id);
        let bucket = &mut self.buckets[bucket_idx];
        if let Some(pos) = bucket.contacts.iter().position(|c| c.id == *id) {
            let removed = bucket.contacts.remove(pos).unwrap();
            self.track_ip_remove(removed.ip);
            return true;
        }
        false
    }

    fn bucket_for(&self, id: &KadId) -> usize {
        let distance = self.local_id.xor_distance(id);
        distance.bucket_index().min(NUM_BUCKETS - 1)
    }

    /// Insert or update a contact. Returns `Some(PendingEviction)` if the bucket
    /// is full and we need to ping the oldest contact first before evicting.
    /// Returns `None` if the contact was inserted/updated normally.
    pub fn insert(&mut self, mut contact: KadContact) -> Option<PendingEviction> {
        if contact.id == self.local_id {
            return None;
        }
        if !ip_filter::is_valid_contact_ip(contact.ip, self.block_private_ips) {
            return None;
        }

        let bucket_idx = self.bucket_for(&contact.id);
        let bucket = &mut self.buckets[bucket_idx];

        if let Some(pos) = bucket.contacts.iter().position(|c| c.id == contact.id) {
            let mut existing = bucket.contacts.remove(pos).unwrap();
            existing.ip = contact.ip;
            existing.udp_port = contact.udp_port;
            existing.tcp_port = contact.tcp_port;
            existing.version = contact.version;
            if contact.verified {
                existing.verified = true;
            }
            if contact.udp_key.is_some() {
                existing.udp_key = contact.udp_key;
            }
            existing.kad_options = contact.kad_options;
            existing.update_type();
            bucket.contacts.push_back(existing);
            return None;
        }

        // Global IP limit (eMule: max 1 contact per IP)
        let ip_count = self.global_ip_count.get(&contact.ip).copied().unwrap_or(0);
        if ip_count >= MAX_CONTACTS_IP {
            return None;
        }

        // Global /24 subnet limit (eMule: max 10 contacts per subnet)
        let snet = subnet_key(contact.ip);
        let subnet_count = self.global_subnet_count.get(&snet).copied().unwrap_or(0);
        if subnet_count >= MAX_CONTACTS_SUBNET {
            return None;
        }

        // Per-bin subnet limit (eMule: max 2 per bin from same /24)
        let bucket = &self.buckets[bucket_idx];
        let bin_subnet_count = bucket
            .contacts
            .iter()
            .filter(|c| subnet_key(c.ip) == snet)
            .count();
        if bin_subnet_count >= MAX_CONTACTS_SUBNET_PER_BIN {
            return None;
        }

        // Set created_at for new contacts
        let now = chrono::Utc::now().timestamp();
        if contact.created_at == 0 {
            contact.created_at = now;
        }
        if contact.expires_at == 0 {
            contact.expires_at = now + 7200;
        }

        let bucket = &self.buckets[bucket_idx];
        if !bucket.is_full() {
            self.track_ip_add(contact.ip);
            self.buckets[bucket_idx].contacts.push_back(contact);
            return None;
        }

        // Bucket full: request ping-before-evict
        if let Some(oldest) = bucket.contacts.front() {
            let eviction = PendingEviction {
                bucket_idx,
                old_contact_id: oldest.id,
                replacement: contact,
                pinged_at: chrono::Utc::now().timestamp(),
            };
            self.pending_evictions.push(eviction.clone());
            return Some(eviction);
        }

        None
    }

    /// Mark a contact as verified (passed 3-way handshake).
    pub fn mark_verified(&mut self, id: &KadId) {
        let bucket_idx = self.bucket_for(id);
        let bucket = &mut self.buckets[bucket_idx];
        if let Some(contact) = bucket.contacts.iter_mut().find(|c| c.id == *id) {
            contact.verified = true;
            contact.update_type();
        }
    }

    /// Get closest contacts, preferring verified and non-firewalled ones.
    /// First fills from verified contacts sorted by distance, then tops up
    /// with unverified contacts. Within each group, non-firewalled contacts
    /// are preferred.
    pub fn find_closest_prefer_verified(&self, target: &KadId, count: usize) -> Vec<KadContact> {
        let mut verified = self.find_closest_verified(target, count);
        // Sort verified by firewall status (non-firewalled first)
        verified.sort_by_key(|c| c.is_udp_firewalled() as u8);

        if verified.len() >= count {
            return verified;
        }

        let remaining = count - verified.len();
        let verified_ids: HashSet<KadId> = verified.iter().map(|c| c.id).collect();
        let mut unverified: Vec<(KadId, &KadContact)> = self
            .all_contacts()
            .filter(|c| !c.verified && !verified_ids.contains(&c.id))
            .map(|c| (target.xor_distance(&c.id), c))
            .collect();
        // Sort unverified by: non-firewalled first, then distance
        unverified.sort_by(|a, b| {
            a.1.is_udp_firewalled().cmp(&b.1.is_udp_firewalled())
                .then_with(|| a.0.cmp(&b.0))
        });
        verified.extend(unverified.into_iter().take(remaining).map(|(_, c)| c.clone()));
        verified
    }

    /// Get only verified contacts closest to a target.
    pub fn find_closest_verified(&self, target: &KadId, count: usize) -> Vec<KadContact> {
        let mut all: Vec<(KadId, &KadContact)> = self
            .all_contacts()
            .filter(|c| c.verified)
            .map(|c| (target.xor_distance(&c.id), c))
            .collect();

        all.sort_by(|a, b| a.0.cmp(&b.0));
        all.into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// Called when a ping response is received from a contact.
    /// If the contact had a pending eviction, the eviction is cancelled (contact is alive).
    pub fn handle_pong(&mut self, contact_id: &KadId) {
        self.pending_evictions.retain(|e| e.old_contact_id != *contact_id);

        let bucket_idx = self.bucket_for(contact_id);
        let bucket = &mut self.buckets[bucket_idx];
        if let Some(pos) = bucket.contacts.iter().position(|c| c.id == *contact_id) {
            let mut contact = bucket.contacts.remove(pos).unwrap();
            contact.update_type();
            bucket.contacts.push_back(contact);
        }
    }

    /// Called on every incoming valid KAD message to refresh the sender.
    /// Looks up a contact by IP+port, calls update_type(), and moves to back of bucket.
    /// Returns true if the contact was found and refreshed.
    pub fn touch_contact_by_addr(&mut self, ip: Ipv4Addr, udp_port: u16) -> bool {
        for bucket in &mut self.buckets {
            if let Some(pos) = bucket
                .contacts
                .iter()
                .position(|c| c.ip == ip && c.udp_port == udp_port)
            {
                let mut contact = bucket.contacts.remove(pos).unwrap();
                contact.update_type();
                bucket.contacts.push_back(contact);
                return true;
            }
        }
        false
    }

    /// Process timed-out evictions (ping got no response within timeout_secs).
    /// Returns the contacts that should be replaced.
    pub fn process_eviction_timeouts(&mut self, timeout_secs: i64) -> Vec<PendingEviction> {
        let now = chrono::Utc::now().timestamp();
        let (timed_out, remaining): (Vec<_>, Vec<_>) = self
            .pending_evictions
            .drain(..)
            .partition(|e| now - e.pinged_at > timeout_secs);

        self.pending_evictions = remaining;

        for eviction in &timed_out {
            let bucket = &mut self.buckets[eviction.bucket_idx];
            if let Some(pos) = bucket.contacts.iter().position(|c| c.id == eviction.old_contact_id) {
                let old = bucket.contacts.remove(pos).unwrap();
                self.track_ip_remove(old.ip);
            }
            if !self.buckets[eviction.bucket_idx].is_full() {
                self.track_ip_add(eviction.replacement.ip);
                self.buckets[eviction.bucket_idx]
                    .contacts
                    .push_back(eviction.replacement.clone());
            }
        }

        timed_out
    }

    /// Find the K closest contacts to a target ID.
    pub fn find_closest(&self, target: &KadId, count: usize) -> Vec<KadContact> {
        let mut all: Vec<(KadId, &KadContact)> = self
            .all_contacts()
            .map(|c| (target.xor_distance(&c.id), c))
            .collect();

        all.sort_by(|a, b| a.0.cmp(&b.0));
        all.into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// Get all contacts as an iterator.
    pub fn all_contacts(&self) -> impl Iterator<Item = &KadContact> {
        self.buckets.iter().flat_map(|b| b.contacts.iter())
    }

    /// Total number of contacts.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.contacts.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get contacts from a specific bucket index.
    pub fn get_bucket_contacts(&self, idx: usize) -> Vec<&KadContact> {
        if idx >= NUM_BUCKETS {
            return Vec::new();
        }
        self.buckets[idx].contacts.iter().collect()
    }

    /// Return bucket indices that need a refresh (stale > 1h OR nearly empty < 20% full).
    pub fn stale_buckets(&self, now: i64) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                if b.contacts.is_empty() {
                    return false;
                }
                b.needs_refresh(now) || b.needs_fill()
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Return bucket indices that are nearly empty (< 20% full) and need filling.
    pub fn buckets_needing_fill(&self) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| b.needs_fill() && !b.contacts.is_empty())
            .map(|(i, _)| i)
            .collect()
    }

    /// Mark a bucket as refreshed.
    pub fn mark_refreshed(&mut self, idx: usize) {
        if idx < NUM_BUCKETS {
            self.buckets[idx].last_refresh = chrono::Utc::now().timestamp();
        }
    }

    /// Get a flat list of all contacts (for persistence).
    pub fn export_contacts(&self) -> Vec<KadContact> {
        self.all_contacts().cloned().collect()
    }

    /// Look up a specific contact by ID.
    pub fn get_contact(&self, id: &KadId) -> Option<&KadContact> {
        let bucket_idx = self.bucket_for(id);
        self.buckets[bucket_idx]
            .contacts
            .iter()
            .find(|c| c.id == *id)
    }

    /// Look up a specific contact by ID (mutable).
    pub fn get_contact_mut(&mut self, id: &KadId) -> Option<&mut KadContact> {
        let bucket_idx = self.bucket_for(id);
        self.buckets[bucket_idx]
            .contacts
            .iter_mut()
            .find(|c| c.id == *id)
    }

    /// Remove contacts not seen for longer than `max_age_secs`. Returns count removed.
    pub fn remove_stale(&mut self, max_age_secs: i64) -> usize {
        let now = chrono::Utc::now().timestamp();
        let mut removed = 0;
        let mut ips_to_remove = Vec::new();
        for bucket in &mut self.buckets {
            let before = bucket.contacts.len();
            bucket.contacts.retain(|c| {
                if now - c.last_seen >= max_age_secs || c.is_expired() {
                    ips_to_remove.push(c.ip);
                    false
                } else {
                    true
                }
            });
            removed += before - bucket.contacts.len();
        }
        for ip in ips_to_remove {
            self.track_ip_remove(ip);
        }
        removed
    }

    /// Remove all dead contacts (type >= 4 with expired time). Returns count removed.
    pub fn remove_dead_contacts(&mut self) -> usize {
        let now = chrono::Utc::now().timestamp();
        let mut removed = 0;
        let mut ips_to_remove = Vec::new();
        for bucket in &mut self.buckets {
            let before = bucket.contacts.len();
            bucket.contacts.retain(|c| {
                if c.is_dead() && c.expires_at > 0 && now > c.expires_at {
                    ips_to_remove.push(c.ip);
                    false
                } else {
                    true
                }
            });
            removed += before - bucket.contacts.len();
        }
        for ip in ips_to_remove {
            self.track_ip_remove(ip);
        }
        removed
    }

    /// SmallTimer: for each bucket, find the oldest contact (front) whose expires_at
    /// has passed. Returns a list of (bucket_idx, contact) pairs to probe with HELLO_REQ.
    /// Contacts that are dead (type 4) and expired are auto-removed.
    pub fn get_contacts_to_probe(&mut self) -> Vec<(usize, KadContact)> {
        let now = chrono::Utc::now().timestamp();
        let mut to_probe = Vec::new();
        let mut ips_removed = Vec::new();

        for (bucket_idx, bucket) in self.buckets.iter_mut().enumerate() {
            if bucket.contacts.is_empty() {
                continue;
            }

            // Check the oldest contact (front of deque)
            let should_probe = if let Some(oldest) = bucket.contacts.front() {
                if oldest.is_dead() && oldest.expires_at > 0 && now > oldest.expires_at {
                    // Dead and expired -- remove it
                    None
                } else if oldest.expires_at > 0 && now > oldest.expires_at {
                    // Expired but not yet dead -- probe it
                    Some(oldest.clone())
                } else {
                    // Not expired -- push to bottom (rotate)
                    None
                }
            } else {
                None
            };

            if let Some(contact) = should_probe {
                // Call checking_type on the contact
                if let Some(front) = bucket.contacts.front_mut() {
                    let is_dead = front.checking_type();
                    if is_dead {
                        // Will be cleaned up by remove_dead_contacts
                    }
                }
                to_probe.push((bucket_idx, contact));
            } else if let Some(front) = bucket.contacts.front() {
                if front.is_dead() && front.expires_at > 0 && now > front.expires_at {
                    let removed_ip = front.ip;
                    bucket.contacts.pop_front();
                    ips_removed.push(removed_ip);
                }
            }
        }

        for ip in ips_removed {
            self.track_ip_remove(ip);
        }

        to_probe
    }

    /// Get the least-recently-seen contact in a bucket (for ping-before-evict).
    pub fn least_recently_seen(&self, bucket_idx: usize) -> Option<&KadContact> {
        if bucket_idx >= NUM_BUCKETS {
            return None;
        }
        self.buckets[bucket_idx].contacts.front()
    }

    /// Get a random contact from a specific bucket (for refresh lookups).
    pub fn random_id_in_bucket(&self, bucket_idx: usize) -> KadId {
        let mut id = KadId::random();
        // Set the distance bit pattern so it falls in the target bucket
        let distance = self.local_id.xor_distance(&id);
        let target_bit = if bucket_idx < NUM_BUCKETS - 1 {
            bucket_idx
        } else {
            NUM_BUCKETS - 1
        };
        // XOR back to get an ID at roughly the right distance
        let mut result = distance.0;
        let byte_idx = (127 - target_bit) / 8;
        let bit_idx = target_bit % 8;
        // Clear higher bits and set the target bit
        for i in 0..byte_idx {
            result[i] = 0;
        }
        result[byte_idx] = 1 << bit_idx;
        // XOR with local ID to get the target ID
        for i in 0..KAD_ID_SIZE {
            id.0[i] = self.local_id.0[i] ^ result[i];
        }
        id
    }
}
