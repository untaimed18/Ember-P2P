use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

use super::ip_filter;
use super::types::*;

const NUM_BUCKETS: usize = 128;
const BUCKET_REFRESH_INTERVAL_SECS: i64 = 3600;
const SPARSE_REFRESH_INTERVAL_SECS: i64 = 60;
const REPLACEMENT_CACHE_SIZE: usize = 5;

/// Return a human-readable KAD version name for logging.
pub fn kad_version_name(version: u8) -> &'static str {
    match version {
        KADEMLIA_VERSION1_46C => "Kad1 (0.46c)",
        KADEMLIA_VERSION2_47A => "Kad2 (0.47a)",
        KADEMLIA_VERSION3_47B => "Kad2 (0.47b)",
        KADEMLIA_VERSION5_48A => "Kad2 (0.48a)",
        KADEMLIA_VERSION6_49ABETA => "Kad2 (0.49a-beta)",
        KADEMLIA_VERSION7_49A => "Kad2 (0.49a)",
        KADEMLIA_VERSION8_49B => "Kad2 (0.49b)",
        KADEMLIA_VERSION9_50A => "Kad2 (0.50a+)",
        _ => "Unknown",
    }
}

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
    replacements: VecDeque<KadContact>,
    last_refresh: i64,
}

impl KBucket {
    fn new() -> Self {
        KBucket {
            contacts: VecDeque::with_capacity(K_BUCKET_SIZE),
            replacements: VecDeque::with_capacity(REPLACEMENT_CACHE_SIZE),
            last_refresh: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.contacts.len() >= K_BUCKET_SIZE
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

    /// O(1) check if any contact in the table has this IP.
    pub fn has_contact_ip(&self, ip: Ipv4Addr) -> bool {
        self.global_ip_count.get(&ip).copied().unwrap_or(0) > 0
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

    /// Remove a contact by ID. Promotes a replacement from the cache if available.
    /// Returns true if it was present.
    pub fn remove(&mut self, id: &KadId) -> bool {
        let bucket_idx = self.bucket_for(id);
        let bucket = &mut self.buckets[bucket_idx];
        if let Some(pos) = bucket.contacts.iter().position(|c| c.id == *id) {
            let removed = bucket.contacts.remove(pos).unwrap();
            self.track_ip_remove(removed.ip);
            self.promote_replacement(bucket_idx);
            return true;
        }
        false
    }

    /// Try to promote a contact from the replacement cache into the main bucket.
    fn promote_replacement(&mut self, bucket_idx: usize) {
        let bucket = &mut self.buckets[bucket_idx];
        while let Some(candidate) = bucket.replacements.pop_back() {
            let ip_count = self.global_ip_count.get(&candidate.ip).copied().unwrap_or(0);
            if ip_count >= MAX_CONTACTS_IP { continue; }
            let snet = subnet_key(candidate.ip);
            let subnet_count = self.global_subnet_count.get(&snet).copied().unwrap_or(0);
            if subnet_count >= MAX_CONTACTS_SUBNET { continue; }
            let bin_snet = bucket.contacts.iter().filter(|c| subnet_key(c.ip) == snet).count();
            if bin_snet >= MAX_CONTACTS_SUBNET_PER_BIN { continue; }
            if !bucket.is_full() {
                tracing::debug!("RT promote replacement {}: bucket {}", candidate.ip, bucket_idx);
                self.track_ip_add(candidate.ip);
                self.buckets[bucket_idx].contacts.push_back(candidate);
                return;
            }
            break;
        }
    }

    fn bucket_for(&self, id: &KadId) -> usize {
        let distance = self.local_id.xor_distance(id);
        distance.bucket_index().min(NUM_BUCKETS - 1)
    }

    /// Insert or update a contact. Returns `Some(PendingEviction)` if the bucket
    /// is full and we need to ping the oldest contact first before evicting.
    /// Returns `None` if the contact was inserted/updated normally.
    ///
    /// Matches eMule RoutingZone::AddUnfiltered behavior:
    /// - Rejects contacts with version <= 1 (Kad1 only)
    /// - Rejects our own ID
    /// - Rejects invalid IPs
    /// - Rejects DNS port 53 for versions <= KADEMLIA_VERSION5_48a
    /// - On update: clears verified flag when IP changes (eMule SetIPAddress)
    /// - On update: does not downgrade version (eMule: pContact->GetVersion() >= pContactUpdate->GetVersion())
    pub fn insert(&mut self, mut contact: KadContact) -> Option<PendingEviction> {
        if contact.id == self.local_id {
            return None;
        }
        if !contact.is_kad2() {
            return None;
        }
        if !ip_filter::is_valid_contact_ip(contact.ip, self.block_private_ips) {
            return None;
        }
        if contact.udp_port == 53 && contact.version <= KADEMLIA_VERSION5_48A {
            tracing::debug!("Rejecting DNS port contact ({}) version {}", contact.ip, kad_version_name(contact.version));
            return None;
        }

        let bucket_idx = self.bucket_for(&contact.id);
        let bucket = &mut self.buckets[bucket_idx];

        if let Some(pos) = bucket.contacts.iter().position(|c| c.id == contact.id) {
            let mut existing = bucket.contacts.remove(pos).unwrap();
            let old_ip = existing.ip;
            // eMule SetIPAddress: clears verified flag when IP changes
            existing.set_ip(contact.ip);
            existing.udp_port = contact.udp_port;
            existing.tcp_port = contact.tcp_port;
            // eMule: do not let Kad1 responses overwrite Kad2 ones
            if contact.version >= existing.version {
                existing.version = contact.version;
            }
            // eMule: don't unset the verified flag (will clear itself on ip change)
            if contact.verified && !existing.verified {
                existing.verified = true;
            }
            if contact.udp_key.is_some() {
                existing.udp_key = contact.udp_key;
            }
            existing.kad_options = contact.kad_options;
            existing.update_type();
            bucket.contacts.push_back(existing);
            if old_ip != contact.ip {
                self.track_ip_remove(old_ip);
                self.track_ip_add(contact.ip);
            }
            return None;
        }

        // Global IP limit (eMule: max 1 contact per IP)
        let ip_count = self.global_ip_count.get(&contact.ip).copied().unwrap_or(0);
        if ip_count >= MAX_CONTACTS_IP {
            tracing::trace!("RT reject {}: duplicate IP ({})", contact.ip, ip_count);
            return None;
        }

        // Global /24 subnet limit (eMule: max 10 contacts per subnet, except LAN IPs)
        let snet = subnet_key(contact.ip);
        let is_lan = ip_filter::is_lan_ip(contact.ip);
        if !is_lan {
            let subnet_count = self.global_subnet_count.get(&snet).copied().unwrap_or(0);
            if subnet_count >= MAX_CONTACTS_SUBNET {
                tracing::trace!("RT reject {}: subnet limit ({}/{})", contact.ip, subnet_count, MAX_CONTACTS_SUBNET);
                return None;
            }
        }

        // Per-bin subnet limit (eMule: max 2 per bin from same /24, except LAN IPs)
        if !is_lan {
            let bucket = &self.buckets[bucket_idx];
            let bin_subnet_count = bucket
                .contacts
                .iter()
                .filter(|c| subnet_key(c.ip) == snet)
                .count();
            if bin_subnet_count >= MAX_CONTACTS_SUBNET_PER_BIN {
                tracing::trace!("RT reject {}: bin {} subnet limit ({}/{})", contact.ip, bucket_idx, bin_subnet_count, MAX_CONTACTS_SUBNET_PER_BIN);
                return None;
            }
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
            tracing::debug!("RT insert {}: bucket {} ({}/{})", contact.ip, bucket_idx, bucket.contacts.len() + 1, K_BUCKET_SIZE);
            self.track_ip_add(contact.ip);
            self.buckets[bucket_idx].contacts.push_back(contact);
            return None;
        }

        // Bucket full: add to replacement cache and request ping-before-evict
        tracing::trace!("RT evict-check {}: bucket {} full ({}/{})", contact.ip, bucket_idx, bucket.contacts.len(), K_BUCKET_SIZE);

        let bucket = &mut self.buckets[bucket_idx];
        if !bucket.replacements.iter().any(|c| c.id == contact.id) {
            if bucket.replacements.len() >= REPLACEMENT_CACHE_SIZE {
                bucket.replacements.pop_front();
            }
            bucket.replacements.push_back(contact.clone());
        }

        if let Some(oldest) = bucket.contacts.front() {
            let eviction = PendingEviction {
                bucket_idx,
                old_contact_id: oldest.id,
                replacement: contact,
                pinged_at: chrono::Utc::now().timestamp(),
            };
            if self.pending_evictions.len() >= 100 {
                self.pending_evictions.remove(0);
            }
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

    /// Get only verified contacts with type <= max_type, closest to a target.
    /// This matches eMule's GetClosestTo(uMaxType, target, distance, count, ...) which
    /// requires IsIpVerified() && GetType() <= uMaxType.
    pub fn find_closest_verified_by_type(
        &self,
        target: &KadId,
        count: usize,
        max_type: u8,
    ) -> Vec<KadContact> {
        let mut all: Vec<(KadId, &KadContact)> = self
            .all_contacts()
            .filter(|c| c.verified && c.contact_type <= max_type)
            .map(|c| (target.xor_distance(&c.id), c))
            .collect();

        all.sort_by(|a, b| a.0.cmp(&b.0));
        all.into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect()
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
    /// Evicts unresponsive contacts and inserts replacements.
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
            self.promote_replacement(eviction.bucket_idx);
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

    pub fn clear(&mut self) {
        for bucket in &mut self.buckets {
            bucket.contacts.clear();
            bucket.replacements.clear();
        }
        self.pending_evictions.clear();
        self.global_ip_count.clear();
        self.global_subnet_count.clear();
    }

    /// Return bucket indices that need a refresh.
    /// Empty/sparse buckets use a shorter refresh interval (60s) so they fill
    /// quickly during bootstrap. Full or nearly-full buckets use the standard
    /// 1-hour interval matching eMule's OnBigTimer.
    pub fn stale_buckets(&self, now: i64) -> Vec<usize> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(i, b)| {
                let is_sparse = b.contacts.len() < K_BUCKET_SIZE / 2;
                let interval = if is_sparse { SPARSE_REFRESH_INTERVAL_SECS } else { BUCKET_REFRESH_INTERVAL_SECS };
                if now - b.last_refresh < interval {
                    return false;
                }
                let remaining = K_BUCKET_SIZE.saturating_sub(b.contacts.len());
                let is_close = *i >= NUM_BUCKETS.saturating_sub(KK);
                let is_deep = *i < KBASE;
                let has_space = remaining as f64 >= K_BUCKET_SIZE as f64 * 0.8;
                is_close || is_deep || has_space
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Return bucket indices that are nearly empty or empty and need filling.
    /// Uses the shorter sparse refresh interval.
    pub fn buckets_needing_fill(&self) -> Vec<usize> {
        let now = chrono::Utc::now().timestamp();
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| {
                b.contacts.len() < K_BUCKET_SIZE / 5
                    && now - b.last_refresh >= SPARSE_REFRESH_INTERVAL_SECS
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// Mark a bucket as refreshed.
    pub fn mark_refreshed(&mut self, idx: usize) {
        if idx < NUM_BUCKETS {
            self.buckets[idx].last_refresh = chrono::Utc::now().timestamp();
        }
    }

    /// Return the index of the sparsest bucket (most remaining capacity).
    /// Prefers buckets that are completely empty, then those with fewest contacts.
    /// Used for targeted FindNode lookups to fill the routing table evenly.
    pub fn sparsest_bucket(&self) -> usize {
        self.buckets
            .iter()
            .enumerate()
            .min_by_key(|(_, b)| b.contacts.len())
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    /// Select up to `max_count` contacts for bootstrap persistence.
    /// Matches eMule's GetBootstrapContacts which calls TopDepth(LOG_BASE_EXPONENT=5).
    /// TopDepth traverses the routing tree to depth 5 (covering the top 2^5=32 buckets)
    /// and returns all contacts from those buckets. For our flat bucket array, this means
    /// contacts from buckets [max-31 .. max] (the closest buckets to our ID).
    pub fn export_bootstrap_contacts(&self, max_count: usize) -> Vec<KadContact> {
        let mut result = Vec::new();

        // eMule TopDepth(LOG_BASE_EXPONENT=5): collect from the top 2^5=32 buckets
        let top_depth = 1usize << LOG_BASE_EXPONENT; // 32
        let start_bucket = NUM_BUCKETS.saturating_sub(top_depth);
        for bucket_idx in start_bucket..NUM_BUCKETS {
            for c in &self.buckets[bucket_idx].contacts {
                if !c.is_dead() {
                    result.push(c.clone());
                }
            }
        }

        // If not enough from the top buckets, expand to lower buckets
        if result.len() < max_count {
            let existing_ids: HashSet<KadId> = result.iter().map(|c| c.id).collect();
            for bucket_idx in (0..start_bucket).rev() {
                for c in &self.buckets[bucket_idx].contacts {
                    if !c.is_dead() && !existing_ids.contains(&c.id) {
                        result.push(c.clone());
                        if result.len() >= max_count {
                            break;
                        }
                    }
                }
                if result.len() >= max_count {
                    break;
                }
            }
        }

        result.truncate(max_count);
        result
    }

    /// Check if a contact is acceptable for insertion into search results.
    /// Matches eMule's RoutingZone::IsAcceptableContact:
    /// - Version must be >= Kad2 (version >= 2)
    /// - If we already have a verified contact with the same ID but different IP, reject
    /// - If IP/subnet limits would be hit, reject
    pub fn is_acceptable_contact(&self, contact: &KadContact) -> bool {
        if !contact.is_kad2() {
            return false;
        }
        if let Some(existing) = self.get_contact(&contact.id) {
            // A verified node with different IP exists → reject
            if existing.verified && (existing.ip != contact.ip || existing.udp_port != contact.udp_port) {
                return false;
            }
            return true;
        }
        // Check global IP limits
        let ip_count = self.global_ip_count.get(&contact.ip).copied().unwrap_or(0);
        if ip_count >= MAX_CONTACTS_IP {
            return false;
        }
        let snet = subnet_key(contact.ip);
        let subnet_count = self.global_subnet_count.get(&snet).copied().unwrap_or(0);
        if subnet_count >= MAX_CONTACTS_SUBNET {
            return false;
        }
        true
    }

    /// Set all contacts as verified (eMule SetAllContactsVerified).
    /// Used when loading an old nodes.dat that has no verified contacts,
    /// to speed up Kad bootstrapping.
    pub fn set_all_contacts_verified(&mut self) {
        for bucket in &mut self.buckets {
            for contact in &mut bucket.contacts {
                contact.verified = true;
            }
        }
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
        let mut buckets_affected = Vec::new();
        for (idx, bucket) in self.buckets.iter_mut().enumerate() {
            let before = bucket.contacts.len();
            bucket.contacts.retain(|c| {
                if now - c.last_seen >= max_age_secs || c.is_expired() {
                    ips_to_remove.push(c.ip);
                    false
                } else {
                    true
                }
            });
            let delta = before - bucket.contacts.len();
            if delta > 0 {
                buckets_affected.push(idx);
            }
            removed += delta;
        }
        for ip in ips_to_remove {
            self.track_ip_remove(ip);
        }
        for idx in buckets_affected {
            self.promote_replacement(idx);
        }
        removed
    }

    /// Remove all dead contacts (type >= 4 with expired time). Returns count removed.
    pub fn remove_dead_contacts(&mut self) -> usize {
        let now = chrono::Utc::now().timestamp();
        let mut removed = 0;
        let mut ips_to_remove = Vec::new();
        let mut buckets_affected = Vec::new();
        for (idx, bucket) in self.buckets.iter_mut().enumerate() {
            let before = bucket.contacts.len();
            bucket.contacts.retain(|c| {
                if c.is_dead() && c.expires_at > 0 && now > c.expires_at {
                    ips_to_remove.push(c.ip);
                    false
                } else {
                    true
                }
            });
            let delta = before - bucket.contacts.len();
            if delta > 0 {
                buckets_affected.push(idx);
            }
            removed += delta;
        }
        for ip in ips_to_remove {
            self.track_ip_remove(ip);
        }
        for idx in buckets_affected {
            self.promote_replacement(idx);
        }
        removed
    }

    /// SmallTimer (matching eMule OnSmallTimer):
    /// 1. Remove dead+expired contacts from all entries
    /// 2. Set expires_at = now for contacts with expires_at == 0 (eMule behavior)
    /// 3. Check oldest contact in each bucket:
    ///    - If expired >= now or type == 4: push to bottom (rotate)
    ///    - Otherwise: call checking_type() and return for HELLO_REQ probing
    pub fn get_contacts_to_probe(&mut self) -> Vec<(usize, KadContact)> {
        let now = chrono::Utc::now().timestamp();
        let mut to_probe = Vec::new();
        let mut ips_removed = Vec::new();

        for (bucket_idx, bucket) in self.buckets.iter_mut().enumerate() {
            if bucket.contacts.is_empty() {
                continue;
            }

            // Step 1+2: Remove dead+expired, set expires_at for contacts with 0
            let mut dead_ips = Vec::new();
            bucket.contacts.retain_mut(|c| {
                if c.is_dead() && c.expires_at > 0 && now > c.expires_at {
                    dead_ips.push(c.ip);
                    return false;
                }
                if c.expires_at == 0 {
                    c.expires_at = now;
                }
                true
            });
            ips_removed.extend(dead_ips);

            if bucket.contacts.is_empty() {
                continue;
            }

            // Step 3: Check the oldest contact (front of deque)
            let oldest = bucket.contacts.front().unwrap();
            if oldest.expires_at >= now || oldest.contact_type >= CONTACT_TYPE_DEAD {
                // Not expired yet or dead — push to bottom (rotate)
                if let Some(c) = bucket.contacts.pop_front() {
                    bucket.contacts.push_back(c);
                }
            } else {
                // Expired but not dead — probe it
                let contact_clone = oldest.clone();
                if let Some(front) = bucket.contacts.front_mut() {
                    front.checking_type();
                }
                to_probe.push((bucket_idx, contact_clone));
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

    /// Generate a random KAD ID whose XOR distance from local_id falls in the given bucket.
    /// Uses eMule's CUInt128 bit ordering: each 4-byte chunk is LE, MSB at byte offset +3.
    pub fn random_id_in_bucket(&self, bucket_idx: usize) -> KadId {
        let mut rng = rand::thread_rng();
        let mut distance = [0u8; KAD_ID_SIZE];
        rand::Rng::fill(&mut rng, &mut distance);

        let target_bit = bucket_idx.min(NUM_BUCKETS - 1);
        // eMule bit position (0 = MSB of first chunk)
        let emu_bit = 127 - target_bit;

        // Clear all bits more significant than emu_bit, then set emu_bit
        for b in 0..emu_bit {
            let chunk = b / 32;
            let bit_in_chunk = 31 - (b % 32);
            let wire_byte = chunk * 4 + bit_in_chunk / 8;
            let bit_in_byte = bit_in_chunk % 8;
            distance[wire_byte] &= !(1u8 << bit_in_byte);
        }
        // Set the target bit
        let chunk = emu_bit / 32;
        let bit_in_chunk = 31 - (emu_bit % 32);
        let wire_byte = chunk * 4 + bit_in_chunk / 8;
        let bit_in_byte = bit_in_chunk % 8;
        distance[wire_byte] |= 1u8 << bit_in_byte;

        let mut id = KadId([0u8; KAD_ID_SIZE]);
        for i in 0..KAD_ID_SIZE {
            id.0[i] = self.local_id.0[i] ^ distance[i];
        }
        id
    }
}
