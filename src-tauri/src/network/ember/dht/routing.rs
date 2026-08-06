use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

use tracing::{debug, info, trace};

use crate::network::kad::ip_filter;

use super::{scale, EmberContact, EmberNodeId, ID_BITS, K_BUCKET_SIZE, MAX_PER_SUBNET_PER_BUCKET};

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
    /// Global per-address counter, so one host cannot fill the table with
    /// contacts under many self-generated keypairs.
    global_ip_count: HashMap<IpAddr, usize>,
    /// Whether LAN / CGNAT addresses are refused, mirroring the KAD table's
    /// setting so both stacks honour the same user preference.
    block_private_ips: bool,
    /// The user's range filter (`ipfilter.dat`), shared with the network layer.
    range_ip_filter: Option<ip_filter::SharedIpFilter>,
}

impl RoutingTable {
    pub fn new(local_id: EmberNodeId, block_private_ips: bool) -> Self {
        let mut buckets = Vec::with_capacity(ID_BITS);
        for _ in 0..ID_BITS {
            buckets.push(Bucket::new());
        }
        Self {
            local_id,
            buckets,
            global_subnet_count: HashMap::new(),
            global_ip_count: HashMap::new(),
            block_private_ips,
            range_ip_filter: None,
        }
    }

    /// Current permissiveness of the diversity limits, from table occupancy.
    pub fn scale(&self) -> scale::NetworkScale {
        scale::NetworkScale::from_contacts(self.total_contacts())
    }

    /// Share the user's range filter so blocked addresses are refused on
    /// admission, as [`crate::network::kad::routing::RoutingTable`] does.
    pub fn set_ip_filter(&mut self, filter: ip_filter::SharedIpFilter) {
        self.range_ip_filter = Some(filter);
    }

    /// Hot-update the LAN/CGNAT admission policy. Turning the block on also
    /// drops contacts already in the table that it now rejects, so the setting
    /// takes effect immediately rather than only for future contacts.
    pub fn set_block_private_ips(&mut self, block_private: bool) -> usize {
        let enabling = block_private && !self.block_private_ips;
        self.block_private_ips = block_private;
        if enabling {
            self.evict_filtered_contacts()
        } else {
            0
        }
    }

    /// Whether a contact at `addr` may enter the table.
    ///
    /// Without this the table accepted anything a peer gossiped, so it could
    /// be seeded with unroutable or user-blocked addresses that we would then
    /// dial, hand to other peers as if they were real, and persist. It also
    /// meant the user's IP filter applied to inbound traffic but not to
    /// anything we chose to contact ourselves.
    pub fn admits_addr(&self, addr: &SocketAddr) -> bool {
        // Port 0 is not dialable, so such a contact could only ever fail.
        if addr.port() == 0 {
            return false;
        }
        let IpAddr::V4(v4) = addr.ip() else {
            // Ember rides the shared KAD UDP socket, which is opened as
            // AF_INET. Every send to a v6 destination fails with
            // EAFNOSUPPORT, so admitting one just occupies a bucket slot with
            // an address we can never reach.
            return false;
        };
        if !ip_filter::is_valid_contact_ip(v4, self.block_private_ips) {
            return false;
        }
        if let Some(filter) = &self.range_ip_filter {
            match filter.read() {
                Ok(snap) => {
                    if snap.is_blocked_for_kad(v4) {
                        return false;
                    }
                }
                // A poisoned lock means we cannot consult the user's filter.
                // Refusing the contact is the safe reading of "blocked unless
                // known otherwise".
                Err(_) => return false,
            }
        }
        true
    }

    /// Whether an address is *known* to be disallowed, as opposed to merely
    /// not confirmable.
    ///
    /// Admission and eviction want opposite answers when the filter cannot be
    /// consulted. Refusing an unconfirmable newcomer costs one contact;
    /// evicting on the same answer would empty the entire table the first
    /// time the shared lock is poisoned. KAD draws the same distinction.
    fn definitely_blocked(&self, addr: &SocketAddr) -> bool {
        if addr.port() == 0 {
            return true;
        }
        let IpAddr::V4(v4) = addr.ip() else {
            return true;
        };
        if !ip_filter::is_valid_contact_ip(v4, self.block_private_ips) {
            return true;
        }
        match &self.range_ip_filter {
            Some(filter) => match filter.read() {
                Ok(snap) => snap.is_blocked_for_kad(v4),
                // Unreadable: keep what we have.
                Err(_) => false,
            },
            None => false,
        }
    }

    /// Drop verified contacts we have not heard from in `max_age_secs`,
    /// skipping any node an in-flight search is still walking.
    ///
    /// Eviction otherwise required three consecutive unanswered pings, and
    /// the ping budget is small, so a contact that quietly went away could
    /// hold its slot for a very long time — and a full bucket makes every
    /// newcomer wait on a probe to the contact it should be replacing.
    ///
    /// Unverified contacts are deliberately exempt: they have no meaningful
    /// `last_seen` to age, and they are leads we may not have tried yet.
    /// Their pressure is handled by the replacement-cache rules instead.
    pub fn remove_stale(
        &mut self,
        now: i64,
        max_age_secs: i64,
        in_use: &HashSet<EmberNodeId>,
    ) -> usize {
        let doomed: Vec<EmberNodeId> = self
            .buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter(|c| c.is_verified())
            .filter(|c| now.saturating_sub(c.last_seen) >= max_age_secs)
            .filter(|c| !in_use.contains(&c.node_id))
            .map(|c| c.node_id)
            .collect();

        let mut removed = 0;
        for id in &doomed {
            if self.remove_contact(id) {
                removed += 1;
            }
        }
        if removed > 0 {
            debug!("Ember DHT: purged {removed} stale contact(s)");
        }
        removed
    }

    /// Drop contacts the current IP policy would no longer admit. Run after
    /// the filter is reloaded or the private-IP setting is turned on.
    pub fn evict_filtered_contacts(&mut self) -> usize {
        let doomed: Vec<EmberNodeId> = self
            .all_contacts()
            .into_iter()
            .filter(|c| self.definitely_blocked(&c.addr))
            .map(|c| c.node_id)
            .collect();
        let mut removed = 0;
        for id in &doomed {
            if self.remove_contact(id) {
                removed += 1;
            }
        }
        // Same treatment for cached entries, using the same predicate so the
        // cache cannot hold addresses the table would refuse.
        let blocked_cached: Vec<(usize, EmberNodeId)> = self
            .buckets
            .iter()
            .enumerate()
            .flat_map(|(idx, b)| b.replacement_cache.iter().map(move |c| (idx, c)))
            .filter(|(_, c)| self.definitely_blocked(&c.addr))
            .map(|(idx, c)| (idx, c.node_id))
            .collect();
        for (idx, node_id) in blocked_cached {
            self.buckets[idx]
                .replacement_cache
                .retain(|c| c.node_id != node_id);
        }
        if removed > 0 {
            // info, not debug: this fires on filter reload and can empty a
            // table that only had a handful of contacts to begin with, which
            // looks exactly like "the overlay is dead" from the outside.
            info!(
                "Ember DHT: evicted {removed} contact(s) blocked by IP policy, {} left",
                self.total_contacts()
            );
        }
        removed
    }

    pub fn total_contacts(&self) -> usize {
        self.buckets.iter().map(|b| b.contacts.len()).sum()
    }

    /// Add or update a contact. Returns what action the caller should take.
    pub fn add_contact(&mut self, contact: EmberContact) -> AddResult {
        if contact.node_id == self.local_id {
            return AddResult::Rejected;
        }

        if !self.admits_addr(&contact.addr) {
            trace!(
                "Rejected contact {} at {} (IP policy)",
                contact.node_id,
                contact.addr
            );
            return AddResult::Rejected;
        }

        let bucket_idx = match self.local_id.bucket_index(&contact.node_id) {
            Some(idx) => idx,
            None => return AddResult::Rejected,
        };

        if bucket_idx >= ID_BITS {
            return AddResult::Rejected;
        }

        // Diversity limits scale with how much of the network we can see, so
        // read them once before borrowing a bucket.
        let scale = self.scale();
        let max_per_ip = scale.max_contacts_per_ip();
        let max_subnet_global = scale.max_contacts_per_subnet_global();

        let subnet = contact.subnet_key();
        let ip = contact.addr.ip();
        let bucket = &mut self.buckets[bucket_idx];

        // If already in the bucket: only mutate from a verified observation
        // (`last_seen > 0`, e.g. a direct signed frame). Unverified gossip
        // (FOUND_NODE / bootstrap entries use `last_seen == 0`) must not
        // rewrite addr/keys or reset freshness — that bypassed subnet caps
        // (eclipse) and could clobber a live contact with `last_seen = 0`.
        if let Some(pos) = bucket.find(&contact.node_id) {
            let mut existing = bucket.contacts.remove(pos).unwrap();
            if contact.last_seen <= 0 {
                bucket.contacts.insert(pos, existing);
                return AddResult::Added;
            }

            let old_subnet = existing.subnet_key();
            let old_ip = existing.addr.ip();
            if contact.addr != existing.addr {
                if subnet != old_subnet {
                    if bucket.subnet_count(subnet) >= MAX_PER_SUBNET_PER_BUCKET {
                        bucket.contacts.insert(pos, existing);
                        return AddResult::Rejected;
                    }
                    let global_count =
                        self.global_subnet_count.get(&subnet).copied().unwrap_or(0);
                    if global_count >= max_subnet_global {
                        bucket.contacts.insert(pos, existing);
                        return AddResult::Rejected;
                    }
                }
                if ip != old_ip
                    && self.global_ip_count.get(&ip).copied().unwrap_or(0) >= max_per_ip
                {
                    let bucket = &mut self.buckets[bucket_idx];
                    bucket.contacts.insert(pos, existing);
                    return AddResult::Rejected;
                }
                if subnet != old_subnet {
                    self.release_subnet(old_subnet);
                    *self.global_subnet_count.entry(subnet).or_insert(0) += 1;
                }
                if ip != old_ip {
                    self.release_ip(old_ip);
                    *self.global_ip_count.entry(ip).or_insert(0) += 1;
                }
                existing.addr = contact.addr;
            }

            existing.noise_pub = contact.noise_pub;
            existing.ed25519_pub = contact.ed25519_pub;
            existing.last_seen = contact.last_seen;
            existing.failed_queries = 0;
            let bucket = &mut self.buckets[bucket_idx];
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
        if global_count >= max_subnet_global {
            trace!("Rejected contact {} (global subnet limit)", contact.node_id);
            self.add_to_cache(bucket_idx, contact);
            return AddResult::Rejected;
        }

        // Per-IP cap. Cryptographic node IDs stop a peer from impersonating
        // another node, but nothing stops one host generating many keypairs,
        // so without this a single machine can occupy as many bucket slots as
        // it likes. KAD allows one contact per IP; we allow a few more so that
        // genuine instances sharing a NAT still get in.
        let ip_count = self.global_ip_count.get(&ip).copied().unwrap_or(0);
        if ip_count >= max_per_ip {
            trace!(
                "Rejected contact {} (per-IP limit {max_per_ip} for {ip})",
                contact.node_id
            );
            self.add_to_cache(bucket_idx, contact);
            return AddResult::Rejected;
        }

        let bucket = &mut self.buckets[bucket_idx];
        if !bucket.is_full() {
            // Drop any cached copy first. A contact can be cached behind a
            // full bucket, have a slot open up from an unrelated removal, and
            // then enter directly — leaving a stale cache entry that a later
            // eviction would promote into a second slot for the same peer.
            // The duplicate is returned twice by `find_closest` (halving real
            // replication wherever it lands), written twice on save, and only
            // its first copy is reachable by `mark_alive` / `mark_failed`.
            bucket
                .replacement_cache
                .retain(|c| c.node_id != contact.node_id);
            bucket.contacts.push_back(contact);
            bucket.last_activity = chrono::Utc::now().timestamp();
            *self.global_subnet_count.entry(subnet).or_insert(0) += 1;
            *self.global_ip_count.entry(ip).or_insert(0) += 1;
            return AddResult::Added;
        }

        // The bucket is full, but a contact that has answered us is worth
        // strictly more than one we have only been told about. Rather than
        // making the proven newcomer wait in the cache behind an unproven
        // squatter, take the squatter's slot directly.
        if contact.is_verified() {
            if let Some(pos) = bucket.contacts.iter().position(|c| !c.is_verified()) {
                let evicted = bucket.contacts.remove(pos).unwrap();
                // Same reason as the not-full path above: a contact can be
                // sitting in the cache and then enter the bucket directly, and
                // the leftover entry holds one of only twenty cache slots for
                // a peer that is already resident.
                bucket
                    .replacement_cache
                    .retain(|c| c.node_id != contact.node_id);
                bucket.contacts.push_back(contact);
                bucket.last_activity = chrono::Utc::now().timestamp();
                self.release_subnet(evicted.subnet_key());
                self.release_ip(evicted.addr.ip());
                *self.global_subnet_count.entry(subnet).or_insert(0) += 1;
                *self.global_ip_count.entry(ip).or_insert(0) += 1;
                trace!(
                    "Replaced unverified contact {} with verified {}",
                    evicted.node_id,
                    self.buckets[bucket_idx].contacts.back().unwrap().node_id
                );
                return AddResult::Added;
            }
        }

        let bucket = &mut self.buckets[bucket_idx];
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
        self.release_subnet(removed.subnet_key());
        self.release_ip(removed.addr.ip());

        // Promote the newest replacement-cache entry that still satisfies the
        // diversity limits. Blindly promoting the newest entry (the old
        // behaviour) let a bucket fill up with contacts from one subnet via the
        // cache, defeating the eclipse-resistance the `add_contact` checks
        // provide. We scan newest→oldest so the freshest eligible contact wins.
        let scale = self.scale();
        let max_per_ip = scale.max_contacts_per_ip();
        let max_subnet_global = scale.max_contacts_per_subnet_global();
        let bucket = &self.buckets[bucket_idx];
        let mut chosen: Option<usize> = None;
        for i in (0..bucket.replacement_cache.len()).rev() {
            let candidate = &bucket.replacement_cache[i];
            let cand_subnet = candidate.subnet_key();
            let cand_ip = candidate.addr.ip();
            // Never promote a peer that is already resident: that would give
            // one contact two slots in the same bucket.
            if bucket.find(&candidate.node_id).is_some() {
                continue;
            }
            // A cache entry can be stale: the policy may have tightened, or
            // the user may have blocked its address, since it was cached.
            if !self.admits_addr(&candidate.addr) {
                continue;
            }
            let per_bucket_ok = bucket.subnet_count(cand_subnet) < MAX_PER_SUBNET_PER_BUCKET;
            let global_ok = self
                .global_subnet_count
                .get(&cand_subnet)
                .copied()
                .unwrap_or(0)
                < max_subnet_global;
            let ip_ok = self.global_ip_count.get(&cand_ip).copied().unwrap_or(0) < max_per_ip;
            if per_bucket_ok && global_ok && ip_ok {
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
                *self
                    .global_subnet_count
                    .entry(replacement.subnet_key())
                    .or_insert(0) += 1;
                *self
                    .global_ip_count
                    .entry(replacement.addr.ip())
                    .or_insert(0) += 1;
                debug!(
                    "Evicted dead contact {}, replaced with {}",
                    removed.node_id, replacement.node_id
                );
                self.buckets[bucket_idx].contacts.push_back(replacement);
                true
            }
            None => {
                debug!(
                    "Evicted dead contact {}, no eligible replacement available",
                    removed.node_id
                );
                false
            }
        }
    }

    /// Remove a contact outright, without promoting a replacement.
    ///
    /// [`Self::evict_and_replace`] is the liveness path; this is for contacts
    /// that must simply go (policy eviction, staleness), where pulling a
    /// replacement in from the cache is not necessarily wanted.
    pub fn remove_contact(&mut self, node_id: &EmberNodeId) -> bool {
        let Some(bucket_idx) = self.local_id.bucket_index(node_id) else {
            return false;
        };
        if bucket_idx >= ID_BITS {
            return false;
        }
        let bucket = &mut self.buckets[bucket_idx];
        let Some(pos) = bucket.find(node_id) else {
            return false;
        };
        let removed = bucket.contacts.remove(pos).unwrap();
        self.release_subnet(removed.subnet_key());
        self.release_ip(removed.addr.ip());
        true
    }

    /// Drop one contact's claim on its subnet quota.
    fn release_subnet(&mut self, subnet: u64) {
        if let Some(count) = self.global_subnet_count.get_mut(&subnet) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.global_subnet_count.remove(&subnet);
            }
        }
    }

    /// Drop one contact's claim on its address quota.
    fn release_ip(&mut self, ip: IpAddr) {
        if let Some(count) = self.global_ip_count.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.global_ip_count.remove(&ip);
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

    /// The contact currently reachable at `addr`, if any.
    ///
    /// Used to attach a peer's verified identity to rate-limit accounting
    /// before its frame has been decoded.
    pub fn contact_at(&self, addr: SocketAddr) -> Option<&EmberContact> {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .find(|c| c.addr == addr)
    }

    /// How many contacts we have actually heard from.
    pub fn verified_len(&self) -> usize {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter(|c| c.is_verified())
            .count()
    }

    /// Return the `count` closest contacts to `target`, verified ones first
    /// and unverified leads only in slots that would otherwise be empty.
    ///
    /// For work we do ourselves — publish targets and lookup frontiers — as
    /// opposed to the contact lists we hand to other peers.
    /// [`Self::find_closest`] drops every lead the moment a single contact has
    /// answered us, which is right for gossip we propagate onward and for
    /// judging store responsibility, but on a young network it makes that one
    /// verified peer the *only* target for every key: records replicate to one
    /// node instead of k, and a lookup that starts from one contact can barely
    /// verify any more, so the table stays stuck where it is. Trying a lead
    /// costs a round trip; refusing to costs the join.
    ///
    /// The result is deliberately *not* globally distance-ordered — verified
    /// contacts lead regardless of distance — which is why the proximity gate
    /// and outbound contact lists keep using [`Self::find_closest`]. A table
    /// with `count` verified contacts behaves identically either way.
    pub fn find_closest_prefer_verified(
        &self,
        target: &EmberNodeId,
        count: usize,
    ) -> Vec<EmberContact> {
        if count == 0 {
            return Vec::new();
        }
        let mut verified: Vec<(EmberNodeId, &EmberContact)> = Vec::new();
        let mut leads: Vec<(EmberNodeId, &EmberContact)> = Vec::new();
        for bucket in &self.buckets {
            for contact in &bucket.contacts {
                let entry = (target.distance(&contact.node_id), contact);
                if contact.is_verified() {
                    verified.push(entry);
                } else {
                    leads.push(entry);
                }
            }
        }

        verified.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        let mut out: Vec<EmberContact> = verified
            .into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect();
        if out.len() < count {
            leads.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
            out.extend(
                leads
                    .into_iter()
                    .take(count - out.len())
                    .map(|(_, c)| c.clone()),
            );
        }
        out
    }

    /// Return the `count` closest contacts to `target`.
    ///
    /// Once we know any contact that has actually answered us, only those are
    /// returned. This is what we hand to other peers and what decides which
    /// keys we are responsible for storing: seeding a reply with addresses we
    /// have merely been told about propagates unverified gossip as if it were
    /// real, and letting gossip into the proximity comparison would let an
    /// attacker inject fake near-contacts to make us refuse legitimate stores.
    /// Before anything has answered we have no choice but to use the leads we
    /// have, which is the cold-start case.
    ///
    /// Callers picking targets for our *own* publishes and lookups want
    /// [`Self::find_closest_prefer_verified`] instead.
    pub fn find_closest(&self, target: &EmberNodeId, count: usize) -> Vec<EmberContact> {
        let verified_only = self.verified_len() > 0;
        let mut all: Vec<(EmberNodeId, &EmberContact)> = Vec::new();

        for bucket in &self.buckets {
            for contact in &bucket.contacts {
                if verified_only && !contact.is_verified() {
                    continue;
                }
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

    /// Contacts worth writing to `nodes_ember.dat`, closest-to-home first.
    ///
    /// Only proven contacts are persisted: an unverified lead is worth little
    /// at save time and nothing at all next launch, and saving the whole table
    /// means junk gossip survives restarts and re-seeds the table each
    /// session. Preferring contacts near our own ID mirrors KAD's
    /// `export_bootstrap_contacts` and reloads the buckets that matter most
    /// for deciding which keys we are responsible for.
    pub fn export_bootstrap_contacts(&self, max: usize) -> Vec<EmberContact> {
        let mut verified: Vec<(EmberNodeId, &EmberContact)> = self
            .buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            // Not `failed_queries == 0`: one unanswered probe is normal at any
            // moment during a refresh burst, and excluding those contacts
            // shrinks the saved set well below the live table. Only contacts
            // on the verge of eviction are dropped.
            .filter(|c| c.is_verified() && c.failed_queries < super::MAX_FAILED_QUERIES)
            .map(|c| (self.local_id.distance(&c.node_id), c))
            .collect();
        verified.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
        verified
            .into_iter()
            .take(max)
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// Get a contact by node ID, if it exists in the routing table.
    ///
    /// Exercised only by this module's tests; the engine reaches contacts
    /// through `find_closest` on the hot paths.
    #[allow(dead_code)]
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
        let scale = self.scale();
        let max_subnet_global = scale.max_contacts_per_subnet_global();
        let max_per_ip = scale.max_contacts_per_ip();

        // Don't add duplicates to cache
        if self.buckets[bucket_idx]
            .find_in_cache(&contact.node_id)
            .is_some()
        {
            return;
        }

        if self.buckets[bucket_idx].replacement_cache.len() >= K_BUCKET_SIZE {
            // Prefer evicting an entry that could not be promoted anyway.
            // Evicting purely by age let contacts rejected *because* of a
            // subnet limit displace promotable ones, so gossip spam could
            // fill the cache with entries that `evict_and_replace` would
            // skip, leaving a bucket with no usable replacement when a slot
            // finally opened.
            //
            // The per-IP limit has to be part of that test, not just the subnet
            // ones: `evict_and_replace` checks all three before promoting, so an
            // IP-saturated entry is exactly as unpromotable as a subnet-saturated
            // one and was being treated as worth keeping.
            let bucket = &self.buckets[bucket_idx];
            let ineligible = bucket.replacement_cache.iter().position(|c| {
                let s = c.subnet_key();
                bucket.subnet_count(s) >= MAX_PER_SUBNET_PER_BUCKET
                    || self.global_subnet_count.get(&s).copied().unwrap_or(0) >= max_subnet_global
                    || self
                        .global_ip_count
                        .get(&c.addr.ip())
                        .copied()
                        .unwrap_or(0)
                        >= max_per_ip
            });
            let bucket = &mut self.buckets[bucket_idx];
            match ineligible {
                Some(pos) => {
                    bucket.replacement_cache.remove(pos);
                }
                None => {
                    bucket.replacement_cache.pop_front();
                }
            }
        }
        self.buckets[bucket_idx].replacement_cache.push_back(contact);
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
        let mut rt = RoutingTable::new(local, false);

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
        let mut rt = RoutingTable::new(local, false);
        let c = make_contact(42, 4662);
        assert!(matches!(rt.add_contact(c), AddResult::Rejected));
    }

    #[test]
    fn bucket_full_triggers_ping_oldest() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

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
        let mut rt = RoutingTable::new(local, false);

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
        let mut rt = RoutingTable::new(local, false);
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
        let mut rt = RoutingTable::new(local, false);
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
        let mut rt = RoutingTable::new(local, false);

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
        let mut rt = RoutingTable::new(local, false);

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
    fn unverified_gossip_does_not_clobber_existing_contact() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        let verified = EmberContact {
            node_id: make_id(1),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 1, 1)), 4662),
            noise_pub: [1; 32],
            ed25519_pub: [1; 32],
            last_seen: 1_700_000_000,
            failed_queries: 0,
        };
        assert!(matches!(rt.add_contact(verified), AddResult::Added));

        // FOUND_NODE-style gossip (last_seen == 0) must not rewrite addr/keys.
        let gossip = EmberContact {
            node_id: make_id(1),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 9999),
            noise_pub: [9; 32],
            ed25519_pub: [9; 32],
            last_seen: 0,
            failed_queries: 0,
        };
        assert!(matches!(rt.add_contact(gossip), AddResult::Added));
        let kept = rt.get_contact(&make_id(1)).unwrap();
        assert_eq!(kept.addr.port(), 4662);
        assert_eq!(kept.noise_pub, [1; 32]);
        assert_eq!(kept.last_seen, 1_700_000_000);
    }

    #[test]
    fn mark_alive_resets_failures() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(1, 4662));

        rt.mark_failed(&make_id(1));
        rt.mark_failed(&make_id(1));
        rt.mark_alive(&make_id(1));

        let c = rt.get_contact(&make_id(1)).unwrap();
        assert_eq!(c.failed_queries, 0);
    }

    /// Gossip is the only way most contacts arrive, and a peer can put any
    /// address it likes in a FOUND_NODE. Without an admission check the table
    /// fills with addresses that can never answer, which we then also hand to
    /// other peers and write to disk.
    #[test]
    fn unroutable_and_undialable_addresses_are_refused() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        let cases: [(&str, SocketAddr); 5] = [
            (
                "broadcast",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 4672),
            ),
            (
                "multicast",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 4672),
            ),
            (
                "documentation range",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 4672),
            ),
            (
                "port zero",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 9, 9, 9)), 0),
            ),
            (
                "ipv6 on an ipv4 socket",
                "[2001:db8::1]:4672".parse().unwrap(),
            ),
        ];

        for (why, addr) in cases {
            let mut c = make_contact(1, 4672);
            c.addr = addr;
            assert!(
                matches!(rt.add_contact(c), AddResult::Rejected),
                "{why} must not be admitted"
            );
            assert_eq!(rt.total_contacts(), 0, "{why} must leave the table empty");
        }

        // A routable public address still gets in.
        assert!(matches!(
            rt.add_contact(make_contact(1, 4672)),
            AddResult::Added
        ));
    }

    fn gossip_contact(id_byte: u8) -> EmberContact {
        let mut c = make_contact(id_byte, 4672);
        // Gossip and disk entries arrive unproven.
        c.last_seen = 0;
        c
    }

    /// Lookups and the contact lists we hand to peers are both built from
    /// find_closest. Seeding either from addresses we have only been told
    /// about wastes round-trips and launders unverified gossip.
    #[test]
    fn lookups_prefer_contacts_that_have_answered_us() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // Cold start: gossip is all we have, so it must still be usable.
        rt.add_contact(gossip_contact(0x10));
        assert_eq!(rt.verified_len(), 0);
        assert_eq!(
            rt.find_closest(&make_id(0x10), 10).len(),
            1,
            "with nothing proven yet we must fall back to leads"
        );

        // Once anything has answered, only proven contacts seed lookups.
        rt.add_contact(make_contact(0x20, 4672));
        assert_eq!(rt.verified_len(), 1);
        let closest = rt.find_closest(&make_id(0x10), 10);
        assert_eq!(closest.len(), 1, "the unproven lead drops out");
        assert_eq!(closest[0].node_id, make_id(0x20));
    }

    /// Excluding leads outright is right for what we hand other peers, but it
    /// left our own publishes and lookups with a single target on a young
    /// network: one proven contact meant every record replicated to one node
    /// instead of k, and a lookup starting from one contact could not verify
    /// enough peers to escape.
    #[test]
    fn our_own_targets_top_up_with_leads_behind_the_proven_ones() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        rt.add_contact(make_contact(0x20, 4672));
        for lead in [0x10u8, 0x11, 0x12] {
            rt.add_contact(gossip_contact(lead));
        }
        assert_eq!(rt.verified_len(), 1);

        // The gossip-excluding path still returns exactly the one proven peer.
        assert_eq!(rt.find_closest(&make_id(0x10), 10).len(), 1);

        // Ours uses the leads for the slots that would otherwise sit empty,
        // and still puts the proven contact first however far away it is.
        let targets = rt.find_closest_prefer_verified(&make_id(0x10), 10);
        assert_eq!(targets.len(), 4, "the three leads fill the empty slots");
        assert_eq!(
            targets[0].node_id,
            make_id(0x20),
            "the proven contact leads regardless of distance"
        );

        // A table with enough proven contacts is unaffected by the change.
        for id in [0x21u8, 0x22] {
            rt.add_contact(make_contact(id, 4672));
        }
        let targets = rt.find_closest_prefer_verified(&make_id(0x10), 3);
        assert!(
            targets.iter().all(|c| c.is_verified()),
            "leads must not displace proven contacts inside the requested count"
        );

        // And a zero request stays empty rather than returning the whole table.
        assert!(rt.find_closest_prefer_verified(&make_id(0x10), 0).is_empty());
    }

    /// Unproven entries must not hold slots against contacts that have
    /// actually answered, or a burst of gossip can wall off a full bucket.
    #[test]
    fn a_proven_contact_displaces_an_unproven_squatter() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // Fill one bucket entirely with gossip.
        for i in 0x80..0x80 + K_BUCKET_SIZE as u8 {
            let mut c = contact_at(i, 80, i, 1, 1);
            c.last_seen = 0;
            assert!(matches!(rt.add_contact(c), AddResult::Added));
        }
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE);
        assert_eq!(rt.verified_len(), 0);

        // A contact that has answered takes a squatter's slot rather than
        // queueing behind it.
        let mut proven = contact_at(0x80 + K_BUCKET_SIZE as u8, 90, 1, 1, 1);
        proven.last_seen = chrono::Utc::now().timestamp();
        let proven_id = proven.node_id;
        assert!(matches!(rt.add_contact(proven), AddResult::Added));
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE, "bucket stays at K");
        assert!(rt.get_contact(&proven_id).is_some());
        assert_eq!(rt.verified_len(), 1);
    }

    /// A contact that quietly disappeared should not hold a bucket slot until
    /// the small ping budget happens to probe it three times.
    #[test]
    fn stale_contacts_are_purged_but_in_use_ones_are_spared() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let now = 1_700_000_000i64;

        let mut fresh = make_contact(1, 4672);
        fresh.last_seen = now - 10;
        let mut stale = make_contact(2, 4672);
        stale.last_seen = now - 10_000;
        let mut stale_but_walking = make_contact(3, 4672);
        stale_but_walking.last_seen = now - 10_000;
        // Never answered, so it has no age to judge and must be left alone.
        let lead = gossip_contact(4);

        for c in [
            fresh.clone(),
            stale.clone(),
            stale_but_walking.clone(),
            lead.clone(),
        ] {
            assert!(matches!(rt.add_contact(c), AddResult::Added));
        }

        let mut in_use = HashSet::new();
        in_use.insert(stale_but_walking.node_id);

        assert_eq!(rt.remove_stale(now, 3600, &in_use), 1);
        assert!(rt.get_contact(&fresh.node_id).is_some(), "fresh survives");
        assert!(rt.get_contact(&stale.node_id).is_none(), "stale is purged");
        assert!(
            rt.get_contact(&stale_but_walking.node_id).is_some(),
            "a search still walking this node must not lose it"
        );
        assert!(
            rt.get_contact(&lead.node_id).is_some(),
            "an unproven lead has no last_seen to age"
        );
    }

    /// The purge runs on the first maintenance tick, before any contact has
    /// been probed. Contacts restored from `nodes_ember.dat` must survive it,
    /// or a restart after the stale threshold leaves the node with nothing to
    /// bootstrap from.
    #[test]
    fn a_restored_bootstrap_set_survives_the_first_staleness_purge() {
        use super::super::bootstrap;

        let local = make_id(0);
        let dir = std::env::temp_dir().join("ember_purge_boot_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        // Persist contacts last heard from long ago, as a previous session
        // would have. Real keypairs, because the loader re-derives each node
        // id from its Ed25519 key rather than trusting the stored one.
        let long_ago = chrono::Utc::now().timestamp() - 100_000;
        let saved: Vec<EmberContact> = (1..=3u8)
            .map(|i| {
                let sk = ed25519_dalek::SigningKey::from_bytes(&[i; 32]);
                let ed25519_pub = sk.verifying_key().to_bytes();
                let node_id = EmberNodeId(
                    crate::network::ember::crypto::node_id_from_ed25519_bytes(&ed25519_pub)
                        .expect("a real key derives an id"),
                );
                EmberContact {
                    node_id,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, i, 1)), 4672),
                    noise_pub: [i; 32],
                    ed25519_pub,
                    last_seen: long_ago,
                    failed_queries: 0,
                }
            })
            .collect();
        bootstrap::save_nodes(&path, &saved).unwrap();

        let mut rt = RoutingTable::new(local, false);
        rt.load_contacts(bootstrap::load_nodes(&path).unwrap());
        assert_eq!(rt.total_contacts(), saved.len());

        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            rt.remove_stale(now, 7200, &HashSet::new()),
            0,
            "the purge must not delete contacts that have not been probed yet"
        );
        assert_eq!(rt.total_contacts(), saved.len());

        // Once one answers, it counts as proven and ages normally from there.
        rt.mark_alive(&saved[0].node_id);
        assert!(rt.get_contact(&saved[0].node_id).unwrap().is_verified());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Persisting the whole table meant junk gossip survived restarts and
    /// re-seeded the next session.
    #[test]
    fn only_proven_contacts_are_persisted() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(gossip_contact(0x11));
        rt.add_contact(make_contact(0x22, 4672));

        let exported = rt.export_bootstrap_contacts(200);
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].node_id, make_id(0x22));

        // And the cap is honoured.
        assert!(rt.export_bootstrap_contacts(0).is_empty());
    }

    /// A peer cached behind a full bucket can enter directly once a slot
    /// opens. If its cache entry survives, a later eviction promotes it into
    /// a second slot: the same peer then appears twice in every lookup,
    /// halving real replication wherever it lands, and only its first copy
    /// responds to liveness bookkeeping.
    #[test]
    fn a_contact_cannot_hold_two_slots_in_one_bucket() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // Fill bucket 127.
        for i in 0x80..0x80 + K_BUCKET_SIZE as u8 {
            assert!(matches!(
                rt.add_contact(contact_at(i, 80, i, 1, 1)),
                AddResult::Added
            ));
        }

        // A newcomer to the same bucket is cached, not admitted.
        let newcomer = contact_at(0xA5, 90, 1, 1, 1);
        let newcomer_id = newcomer.node_id;
        assert!(matches!(
            rt.add_contact(newcomer.clone()),
            AddResult::PingOldest { .. }
        ));

        // An unrelated removal frees a slot, and the newcomer arrives again
        // and is admitted directly.
        rt.remove_contact(&make_id(0x81));
        assert!(matches!(rt.add_contact(newcomer), AddResult::Added));

        // Now evict another contact: the stale cache entry must not be
        // promoted into a second slot for a peer already resident.
        rt.remove_contact(&make_id(0x82));
        rt.add_contact(contact_at(0xB7, 91, 1, 1, 1));
        let _ = rt.evict_and_replace(&make_id(0x83));

        let occurrences = rt
            .all_contacts()
            .iter()
            .filter(|c| c.node_id == newcomer_id)
            .count();
        assert_eq!(occurrences, 1, "a peer must occupy at most one slot");
    }

    /// Cryptographic node IDs stop a peer impersonating another node, but not
    /// one host minting many keypairs. Without a per-address cap a single
    /// machine can take as many bucket slots as it wants.
    #[test]
    fn one_address_cannot_take_unlimited_slots() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let shared = Ipv4Addr::new(80, 5, 5, 5);

        // Fill the table with distinct addresses so the limits reach their
        // strict tier, then see how many the shared address can add.
        let mut admitted_from_shared = 0;
        for i in 1..=200u16 {
            let mut c = make_contact((i % 251) as u8 + 1, 4672);
            // Unique node id per attempt so only the address is shared.
            let mut id = [0u8; 16];
            id[0] = (i & 0xFF) as u8;
            id[1] = (i >> 8) as u8;
            c.node_id = EmberNodeId(id);
            if c.node_id == local {
                continue;
            }
            c.addr = SocketAddr::new(IpAddr::V4(shared), 4672);
            if matches!(rt.add_contact(c), AddResult::Added) {
                admitted_from_shared += 1;
            }
        }

        let allowed = rt.scale().max_contacts_per_ip();
        assert!(
            admitted_from_shared <= allowed.max(8),
            "one address got {admitted_from_shared} slots, above every tier's cap"
        );
        assert!(
            admitted_from_shared > 0,
            "a shared address must not be shut out entirely"
        );
    }

    /// The cap must not lock out a node that has barely any contacts, since
    /// refusing a peer then can cost the only route into the network.
    #[test]
    fn a_shared_address_is_tolerated_while_bootstrapping() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let shared = Ipv4Addr::new(80, 6, 6, 6);

        for i in 1..=3u8 {
            let mut c = make_contact(i, 4672);
            c.addr = SocketAddr::new(IpAddr::V4(shared), 4670 + i as u16);
            assert!(
                matches!(rt.add_contact(c), AddResult::Added),
                "instance {i} behind a shared address must be admitted while bootstrapping"
            );
        }
        assert_eq!(rt.total_contacts(), 3);
    }

    /// The private-IP setting is a user preference that can change at runtime,
    /// so turning it on has to drop contacts already admitted under the old
    /// policy rather than only applying to future ones.
    #[test]
    fn enabling_the_private_block_evicts_lan_contacts() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        let mut lan = make_contact(1, 4672);
        lan.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 4672);
        assert!(matches!(rt.add_contact(lan), AddResult::Added));
        let public = make_contact(2, 4672);
        assert!(matches!(rt.add_contact(public), AddResult::Added));
        assert_eq!(rt.total_contacts(), 2);

        assert_eq!(rt.set_block_private_ips(true), 1);
        assert!(rt.get_contact(&make_id(1)).is_none(), "LAN contact evicted");
        assert!(rt.get_contact(&make_id(2)).is_some(), "public one stays");

        // And the policy now applies on admission too.
        let mut lan_again = make_contact(3, 4672);
        lan_again.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 4672);
        assert!(matches!(rt.add_contact(lan_again), AddResult::Rejected));
    }

    #[test]
    fn persistence_round_trip() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(make_contact(1, 4662));
        rt.add_contact(make_contact(2, 4663));

        let contacts = rt.all_contacts();
        assert_eq!(contacts.len(), 2);

        let mut rt2 = RoutingTable::new(local, false);
        rt2.load_contacts(contacts);
        assert_eq!(rt2.total_contacts(), 2);
    }
}
