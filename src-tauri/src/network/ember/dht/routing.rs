use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tracing::{debug, info, trace};

use crate::network::kad::{dht_common, ip_filter};

use super::{scale, EmberContact, EmberNodeId, ID_BITS, K_BUCKET_SIZE};

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

/// The address the shared IP gate can judge, or `None` when the contact is
/// disqualified before any policy applies.
///
/// Ember contacts carry a [`SocketAddr`] where KAD contacts carry a bare
/// [`Ipv4Addr`], so these two checks have no counterpart on the KAD side and
/// stay here rather than in [`dht_common`].
fn judgeable_ip(addr: &SocketAddr) -> Option<Ipv4Addr> {
    // Port 0 is not dialable, so such a contact could only ever fail.
    if addr.port() == 0 {
        return None;
    }
    match addr.ip() {
        IpAddr::V4(v4) => Some(v4),
        // Ember rides the shared KAD UDP socket, which is opened as
        // AF_INET. Every send to a v6 destination fails with
        // EAFNOSUPPORT, so admitting one just occupies a bucket slot with
        // an address we can never reach.
        IpAddr::V6(_) => None,
    }
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
    /// The LAN/CGNAT preference and the user's range filter (`ipfilter.dat`),
    /// in the same shared form the KAD table uses, so both stacks honour the
    /// same user preference through one implementation.
    ip_gate: dht_common::IpAdmissionGate,
    /// The strictest tier whose diversity quotas the *resident* set has been
    /// pruned down to. See [`Self::enforce_scale_quotas`].
    ///
    /// Tightens as soon as the table crosses a boundary and relaxes only once
    /// it has fallen a clear margin back below one, which is what keeps a table
    /// hovering near a boundary from demoting and re-admitting the same
    /// contacts forever.
    enforced_scale: scale::NetworkScale,
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
            ip_gate: dht_common::IpAdmissionGate::new(block_private_ips),
            enforced_scale: scale::NetworkScale::Bootstrap,
        }
    }

    /// Current permissiveness of the diversity limits, from how much of the
    /// network we have actually reached.
    ///
    /// Counted in verified contacts rather than table occupancy. A table
    /// padded with leads we have only been told about is not diversity, and
    /// counting it as such drove the limits to their strict tier while the
    /// node still had almost no peer it could reach — refusing real contacts
    /// at precisely the moment the permissive tier exists to admit them, and
    /// letting anyone who can gossip at us provoke it. Every other reading of
    /// "how much network do we have" — the liveness-ping budget, the KAD
    /// bridge cutoff, the rendezvous lookup — already counts verified only.
    ///
    /// The cost is that a node under a gossip flood stays permissive for
    /// longer, so leads are admitted up to the looser per-IP cap. That is
    /// bounded by the per-bucket subnet limit, and by eviction: a lead that
    /// never answers a liveness ping faults out after `MAX_FAILED_QUERIES`.
    pub fn scale(&self) -> scale::NetworkScale {
        scale::NetworkScale::from_contacts(self.verified_len())
    }

    /// The tier that governs *admission*: the stricter of what the table looks
    /// like now and what [`Self::enforce_scale_quotas`] has already pruned to.
    ///
    /// [`Self::scale`] counts verified contacts holding a bucket slot, and
    /// demotion moves them to a replacement cache — so pruning the table to a
    /// tier lowers the very reading that chose it. Prune 100 verified contacts
    /// down past 80 and the live tier falls back from `Established` to `Small`,
    /// whose per-IP allowance is twice as generous; `promote_cached_contacts`
    /// then runs in the same maintenance tick and re-admits exactly the
    /// contacts just demoted. The ratchet on [`Self::enforced_scale`] stops
    /// `enforce_scale_quotas` from re-running, but on its own it did nothing to
    /// stop the promotion pass undoing its work, which left the cold-start
    /// grandfathering hole open in the case that matters most — a table crowded
    /// enough for pruning to move it across a boundary.
    ///
    /// Only ever stricter than `scale()`, so this cannot admit something the
    /// live tier would refuse.
    pub fn admission_scale(&self) -> scale::NetworkScale {
        self.scale().max(self.enforced_scale)
    }

    /// Prune residents the current tier would no longer admit, moving them to
    /// their bucket's replacement cache.
    ///
    /// [`Self::scale`] tightens as the table fills, but until now it only ever
    /// governed *admission*: nothing re-examined a contact once it held a slot.
    /// A contact that answers liveness pings is not stale, never faults out, and
    /// is not displaced by the verified-over-lead rule, so whatever a cold start
    /// admitted it kept for the life of the process. That is the wrong half of
    /// the table to grandfather. Node IDs are uniform, so bucket occupancy is
    /// geometric — about half of all contacts land in the last bucket — and
    /// `find_closest` serves verified contacts only, which means those slots
    /// decide the contact lists we gossip, the store-responsibility comparison
    /// and every lookup frontier. An adversary present while we knew almost
    /// nobody could hold a quarter of the bucket that matters most, permanently.
    ///
    /// Demoted rather than dropped. The cache is where a contact the caps turn
    /// away already waits, `promote_cached_contacts` brings it back if a slot
    /// frees up, and the distinction between "we cannot route through this peer
    /// right now" and "stop remembering this peer" is one the rest of this
    /// subsystem is careful about — see [`super::peer_cache`].
    ///
    /// Acting is deliberately later than admitting. The tier is read from
    /// four-fifths of the verified count, so `Small` admission starts at 10
    /// verified contacts but the table is not pruned to it until 13, and
    /// `Established` at 80 against 100. Between those the caps still refuse
    /// newcomers, so the margin costs nothing and buys the property that a table
    /// sitting on a boundary cannot demote a contact one tick and re-admit it
    /// the next.
    ///
    /// The relaxation below is the other half of that, and it has to be
    /// explicit. [`Self::admission_scale`] is `scale().max(enforced_scale)`, so
    /// a tier this pass ratchets to governs admission until something lowers it
    /// — and nothing did. A node that reached 100 verified contacts and then
    /// lost them (a suspended laptop, a changed network, an upstream outage,
    /// a wave of evictions) sat on an almost empty table while still enforcing
    /// the caps meant for a full one: two contacts per address and ten per /24,
    /// applied at exactly the moment the `Bootstrap` allowances exist to get a
    /// node reconnected. It held for the life of the process, because nothing
    /// short of a restart rebuilt the table.
    ///
    /// Relaxing is measured from five-fourths of the verified count, mirroring
    /// the four-fifths above: acting later than the live tier in both
    /// directions leaves a dead band around every boundary, so the flapping
    /// this field exists to prevent still cannot happen. Nothing is demoted by
    /// relaxing, and the pass below cannot fire in the same call — a count low
    /// enough to widen the band has a `target` at or under the tier it widens
    /// to.
    ///
    /// Returns how many contacts were demoted.
    pub fn enforce_scale_quotas(&mut self) -> usize {
        let verified = self.verified_len();
        let floor = scale::NetworkScale::from_contacts(verified.saturating_mul(5) / 4);
        if floor < self.enforced_scale {
            self.enforced_scale = floor;
        }

        let target = scale::NetworkScale::from_contacts(verified * 4 / 5);
        if target <= self.enforced_scale {
            return 0;
        }
        self.enforced_scale = target;

        let max_per_ip = target.max_contacts_per_ip();
        let max_subnet_global = target.max_contacts_per_subnet_global();
        let max_subnet_bucket = target.max_contacts_per_subnet_per_bucket();

        // Re-admit the whole resident set under the new quotas, best first, and
        // demote whatever no longer fits. Expressing it as a re-admission rather
        // than as "find the excess and delete it" is what makes the victim
        // choice fall out instead of having to be invented: the contacts left
        // over are the least proven members of the most crowded groups, which is
        // exactly the shape of the occupation this exists to undo.
        let mut ranked: Vec<(usize, EmberNodeId, u64, IpAddr, bool, i64)> = Vec::new();
        for (idx, bucket) in self.buckets.iter().enumerate() {
            for c in &bucket.contacts {
                ranked.push((
                    idx,
                    c.node_id,
                    c.subnet_key(),
                    c.addr.ip(),
                    c.is_verified(),
                    c.last_seen,
                ));
            }
        }
        // Proven before unproven, then most recently heard from. The node id
        // breaks ties so the outcome does not depend on bucket iteration order.
        ranked.sort_by(|a, b| {
            b.4.cmp(&a.4)
                .then(b.5.cmp(&a.5))
                .then(a.1 .0.cmp(&b.1 .0))
        });

        let mut per_bucket_subnet: HashMap<(usize, u64), usize> = HashMap::new();
        let mut per_subnet: HashMap<u64, usize> = HashMap::new();
        let mut per_ip: HashMap<IpAddr, usize> = HashMap::new();
        let mut doomed: Vec<(usize, EmberNodeId)> = Vec::new();

        for (idx, node_id, subnet, ip, _, _) in ranked {
            let in_bucket = per_bucket_subnet
                .get(&(idx, subnet))
                .copied()
                .unwrap_or(0);
            let in_subnet = per_subnet.get(&subnet).copied().unwrap_or(0);
            let at_ip = per_ip.get(&ip).copied().unwrap_or(0);
            if in_bucket >= max_subnet_bucket
                || in_subnet >= max_subnet_global
                || at_ip >= max_per_ip
            {
                doomed.push((idx, node_id));
                continue;
            }
            *per_bucket_subnet.entry((idx, subnet)).or_insert(0) += 1;
            *per_subnet.entry(subnet).or_insert(0) += 1;
            *per_ip.entry(ip).or_insert(0) += 1;
        }

        let mut demoted = 0usize;
        for (idx, node_id) in doomed {
            let Some(pos) = self.buckets[idx].find(&node_id) else {
                continue;
            };
            let contact = self.buckets[idx].contacts.remove(pos).unwrap();
            self.release_subnet(contact.subnet_key());
            self.release_ip(contact.addr.ip());
            self.add_to_cache(idx, contact, target);
            demoted += 1;
        }
        if demoted > 0 {
            info!(
                "Ember DHT: limits tightened to {target:?}; demoted {demoted} over-quota \
                 contact(s) to their replacement caches"
            );
        }
        demoted
    }

    /// Share the user's range filter so blocked addresses are refused on
    /// admission, as [`crate::network::kad::routing::RoutingTable`] does.
    pub fn set_ip_filter(&mut self, filter: ip_filter::SharedIpFilter) {
        self.ip_gate.set_range_filter(filter);
    }

    /// Hot-update the LAN/CGNAT admission policy. Turning the block on also
    /// drops contacts already in the table that it now rejects, so the setting
    /// takes effect immediately rather than only for future contacts.
    pub fn set_block_private_ips(&mut self, block_private: bool) -> usize {
        if self.ip_gate.set_block_private_ips(block_private) {
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
        let Some(v4) = judgeable_ip(addr) else {
            return false;
        };
        matches!(self.ip_gate.admits(v4), dht_common::Admission::Allowed)
    }

    /// Whether an address is *known* to be disallowed, as opposed to merely
    /// not confirmable.
    ///
    /// Admission and eviction want opposite answers when the filter cannot be
    /// consulted, and KAD draws the same distinction — the reasoning lives with
    /// the shared gate, in
    /// [`dht_common::IpAdmissionGate::is_definitely_blocked`]. An address this
    /// table cannot judge at all is disallowed outright rather than handed to
    /// the gate; see [`judgeable_ip`].
    pub fn definitely_blocked(&self, addr: &SocketAddr) -> bool {
        match judgeable_ip(addr) {
            Some(v4) => self.ip_gate.is_definitely_blocked(v4),
            None => true,
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
            .filter(|c| dht_common::is_stale(now, c.last_seen, max_age_secs))
            .filter(|c| !in_use.contains(&c.node_id))
            .map(|c| c.node_id)
            .collect();

        let mut removed = 0;
        for id in &doomed {
            if self.remove_contact(id) {
                removed += 1;
            }
        }

        // Sweep the replacement caches on the same rule. Promotion and cache
        // eviction both now prefer contacts we have heard from, which is only
        // safe if a verified entry that has since gone silent can leave: a dead
        // one would otherwise hold a cache slot against fresh leads forever,
        // and be preferred for promotion when a bucket slot opened.
        let mut stale_cached = 0usize;
        for bucket in &mut self.buckets {
            let before = bucket.replacement_cache.len();
            bucket.replacement_cache.retain(|c| {
                !c.is_verified()
                    || !dht_common::is_stale(now, c.last_seen, max_age_secs)
                    || in_use.contains(&c.node_id)
            });
            stale_cached += before - bucket.replacement_cache.len();
        }

        if removed > 0 || stale_cached > 0 {
            debug!(
                "Ember DHT: purged {removed} stale contact(s) and {stale_cached} stale cache entry(s)"
            );
        }
        removed
    }

    /// Drop contacts the current IP policy would no longer admit. Run after
    /// the filter is reloaded or the private-IP setting is turned on.
    pub fn evict_filtered_contacts(&mut self) -> usize {
        let removed = dht_common::evict_blocked_contacts(self);
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
        let promoted = self.promote_cached_contacts();
        if promoted > 0 {
            info!(
                "Ember DHT: admitted {promoted} cached contact(s) now that the IP policy can be \
                 checked, {} in table",
                self.total_contacts()
            );
        }
        removed
    }

    /// Move cached leads into free bucket slots when the current IP policy
    /// admits them.
    ///
    /// The replacement cache is otherwise drained only by `evict_and_replace`,
    /// which needs a resident contact to die first. Leads parked while the
    /// filter was still loading would sit there indefinitely on a node whose
    /// buckets have plenty of room — which is exactly the cold-start table
    /// that needed them.
    pub fn promote_cached_contacts(&mut self) -> usize {
        let mut promoted = 0;
        let now = chrono::Utc::now().timestamp();
        for idx in 0..self.buckets.len() {
            // `scale()` walks the whole table, so do not pay for it on the
            // 128 buckets that have nothing parked — which is all of them in
            // steady state.
            if self.buckets[idx].replacement_cache.is_empty() {
                continue;
            }
            // Read once per bucket rather than once per promotion. This is a
            // full 128-bucket walk, and paying it per promotion mattered
            // precisely when it hurt most: right after `evict_filtered_contacts`
            // fires on an `ipfilter.dat` load, many buckets have parked leads
            // and free slots at once, so a single call could mean thousands of
            // whole-table walks on the task that also drains the UDP socket.
            // The tier can only tighten as verified contacts are promoted, and
            // only refuses admissions, so at worst one bucket's batch is
            // admitted a tier late — bounded, and re-evaluated on the next call.
            //
            // `admission_scale`, not `scale`: this runs immediately after
            // `enforce_scale_quotas` in the same maintenance tick, and the
            // demotion it just performed is what would otherwise loosen the
            // live tier enough to re-admit the demoted contacts here.
            let scale = self.admission_scale();
            let mut filled = false;
            while !self.buckets[idx].is_full() {
                let Some(i) = self.best_promotable_cached(idx, None, scale) else {
                    break;
                };
                let contact = self.buckets[idx].replacement_cache.remove(i).unwrap();
                *self
                    .global_subnet_count
                    .entry(contact.subnet_key())
                    .or_insert(0) += 1;
                *self.global_ip_count.entry(contact.addr.ip()).or_insert(0) += 1;
                self.buckets[idx].contacts.push_back(contact);
                promoted += 1;
                filled = true;
            }
            if filled {
                // Every other path that puts a contact into a bucket stamps
                // this; promotion was the one that did not. A bucket filled
                // only this way kept `last_activity == 0` and so looked
                // maximally idle forever, taking the three-per-cycle refresh
                // budget from buckets that had actually gone quiet.
                self.buckets[idx].last_activity = now;
            }
        }
        promoted
    }

    pub fn total_contacts(&self) -> usize {
        self.buckets.iter().map(|b| b.contacts.len()).sum()
    }

    /// Contacts in replacement caches. Fail-closed IP-filter parking and a
    /// full bucket both land here; they are not in [`Self::total_contacts`].
    pub fn cached_len(&self) -> usize {
        self.buckets
            .iter()
            .map(|b| b.replacement_cache.len())
            .sum()
    }

    /// Bucket slots plus replacement-cache entries.
    pub fn held_len(&self) -> usize {
        self.total_contacts() + self.cached_len()
    }

    /// Verified contacts in buckets or the replacement cache.
    pub fn verified_held(&self) -> usize {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter().chain(b.replacement_cache.iter()))
            .filter(|c| c.is_verified())
            .count()
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

        // Diversity limits scale with how much of the network we can see, so
        // read them once before borrowing a bucket. Carried into
        // `add_to_cache` rather than recomputed there: `scale()` walks all 128
        // buckets, and `merge_gossip_contacts` runs this whole path once per
        // contact in a FOUND_NODE — most of which land in the cache on a warm
        // table, so recomputing doubled the walks for a frame.
        //
        // The enforced tier floors this so a pruned table cannot re-admit
        // through the front door what `enforce_scale_quotas` just demoted —
        // see [`Self::admission_scale`].
        let scale = self.admission_scale();
        let max_per_ip = scale.max_contacts_per_ip();
        let max_subnet_global = scale.max_contacts_per_subnet_global();
        let max_subnet_bucket = scale.max_contacts_per_subnet_per_bucket();

        // Resident before the IP gate: during the fail-closed filter window
        // `admits_addr` refuses every non-seed, and Ember peers are never Kad
        // seeds. Applying the gate first diverted a verified observation for a
        // contact we already hold into the replacement cache (or dropped it,
        // because the cache refuses a duplicate of a resident). New contacts
        // still have to pass the gate below. An address *change* still has to
        // be admitted; a refused new address refreshes last_seen in place.
        if let Some(existing_addr) = self.buckets[bucket_idx]
            .find(&contact.node_id)
            .map(|pos| self.buckets[bucket_idx].contacts[pos].addr)
        {
            let admit_new_addr =
                contact.addr == existing_addr || self.admits_addr(&contact.addr);
            return self.apply_resident_contact(
                bucket_idx,
                contact,
                max_per_ip,
                max_subnet_global,
                max_subnet_bucket,
                admit_new_addr,
            );
        }

        if !self.admits_addr(&contact.addr) {
            // "Cannot confirm" is not "known bad". While `ipfilter.dat` is
            // still parsing, `is_blocked_for_kad` calls every non-seed address
            // blocked, and Ember peers are never Kad seeds — so dropping here
            // discarded every lead learned during the window, permanently.
            // A node whose table was thin at launch therefore threw away the
            // gossip that would have refilled it and stayed thin.
            //
            // Park it in the replacement cache instead. `promote_cached_contacts`
            // re-tests it once the ranges land, and `evict_filtered_contacts`
            // clears the cache of anything genuinely blocked, so nothing enters
            // the table without passing the real list.
            if !self.definitely_blocked(&contact.addr) {
                self.add_to_cache(bucket_idx, contact, scale);
                return AddResult::Rejected;
            }
            trace!(
                "Rejected contact {} at {} (IP policy)",
                contact.node_id,
                contact.addr
            );
            return AddResult::Rejected;
        }

        let subnet = contact.subnet_key();
        let ip = contact.addr.ip();

        // A verified observation is worth more than mute gossip in the same
        // /24. The subnet cap used to run first and park the live peer in the
        // replacement cache while unverified squatters kept the slots — and
        // `add_to_cache` then ignored a later verified copy as a duplicate.
        //
        // Only when the newcomer would otherwise be turned away. The predicate
        // below matches any unverified resident sharing the /24, which on a
        // bucket with free slots and no cap engaged evicted a lead to fill a
        // slot that was already empty — and `evicted_subnet == subnet` then
        // short-circuits `subnet_ok`, so nothing downstream noticed. A cold-start
        // node whose peers share an ISP /24 or sit behind one CGNAT is exactly
        // the case the Bootstrap tier exists to admit, and it was discarding
        // those leads at the moment they were the only route in.
        let would_be_refused = {
            let bucket = &self.buckets[bucket_idx];
            bucket.is_full()
                || bucket.subnet_count(subnet) >= max_subnet_bucket
                || self.global_subnet_count.get(&subnet).copied().unwrap_or(0) >= max_subnet_global
                || self.global_ip_count.get(&ip).copied().unwrap_or(0) >= max_per_ip
        };
        if contact.is_verified() && would_be_refused {
            let pos = {
                let bucket = &self.buckets[bucket_idx];
                bucket.contacts.iter().position(|c| {
                    !c.is_verified() && (c.subnet_key() == subnet || bucket.is_full())
                })
            };
            if let Some(pos) = pos {
                let evicted_ip = self.buckets[bucket_idx].contacts[pos].addr.ip();
                let evicted_subnet = self.buckets[bucket_idx].contacts[pos].subnet_key();
                let ip_ok = ip == evicted_ip
                    || self.global_ip_count.get(&ip).copied().unwrap_or(0) < max_per_ip;
                // Displacing a resident in our *own* /24 leaves both subnet
                // counts unchanged, so the caps cannot be exceeded and need not
                // be consulted — that is the case this fast path was written
                // for. Taking a slot from a different /24 raises our count, and
                // this branch returned `Added` without ever reaching the checks
                // below. Because the `|| bucket.is_full()` disjunct above
                // matches *any* unverified resident, and a contact counts as
                // verified after one signed frame, a single /24 running one
                // keypair per host could take every slot in a full bucket —
                // and `find_closest` serves verified contacts only, so those
                // slots decide the contact lists we gossip, the store
                // responsibility comparison, and every lookup frontier.
                let subnet_ok = evicted_subnet == subnet
                    || (self.buckets[bucket_idx].subnet_count(subnet) < max_subnet_bucket
                        && self.global_subnet_count.get(&subnet).copied().unwrap_or(0)
                            < max_subnet_global);
                if ip_ok && subnet_ok {
                    let bucket = &mut self.buckets[bucket_idx];
                    let evicted = bucket.contacts.remove(pos).unwrap();
                    bucket
                        .replacement_cache
                        .retain(|c| c.node_id != contact.node_id);
                    bucket.contacts.push_back(contact);
                    bucket.last_activity = chrono::Utc::now().timestamp();
                    self.release_subnet(evicted.subnet_key());
                    self.release_ip(evicted.addr.ip());
                    *self.global_subnet_count.entry(subnet).or_insert(0) += 1;
                    *self.global_ip_count.entry(ip).or_insert(0) += 1;
                    return AddResult::Added;
                }
            }
        }

        let bucket = &mut self.buckets[bucket_idx];

        // Subnet diversity check: per-bucket
        if bucket.subnet_count(subnet) >= max_subnet_bucket {
            trace!(
                "Rejected contact {} (subnet limit per bucket)",
                contact.node_id
            );
            self.add_to_cache(bucket_idx, contact, scale);
            return AddResult::Rejected;
        }

        // Subnet diversity check: global
        let global_count = self.global_subnet_count.get(&subnet).copied().unwrap_or(0);
        if global_count >= max_subnet_global {
            trace!("Rejected contact {} (global subnet limit)", contact.node_id);
            self.add_to_cache(bucket_idx, contact, scale);
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
            self.add_to_cache(bucket_idx, contact, scale);
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
        self.add_to_cache(bucket_idx, contact, scale);

        AddResult::PingOldest {
            addr: ping_addr,
            node_id: ping_id,
            noise_pub: ping_noise,
        }
    }

    fn apply_resident_contact(
        &mut self,
        bucket_idx: usize,
        contact: EmberContact,
        max_per_ip: usize,
        max_subnet_global: usize,
        max_subnet_bucket: usize,
        admit_new_addr: bool,
    ) -> AddResult {
        let bucket = &mut self.buckets[bucket_idx];
        let Some(pos) = bucket.find(&contact.node_id) else {
            return AddResult::Rejected;
        };
        let mut existing = bucket.contacts.remove(pos).unwrap();
        // Only mutate from a verified observation (`last_seen > 0`, e.g. a
        // direct signed frame). Unverified gossip (FOUND_NODE / bootstrap
        // entries use `last_seen == 0`) must not rewrite addr/keys or reset
        // freshness — that bypassed subnet caps (eclipse) and could clobber
        // a live contact with `last_seen = 0`.
        if contact.last_seen <= 0 {
            bucket.contacts.insert(pos, existing);
            return AddResult::Added;
        }

        // Pin the Noise static key once this node_id has answered us. The DHT
        // header signs Ed25519, not the session key, so a captured Alice PING
        // replayed inside Mallory's Noise session would otherwise overwrite
        // Alice's routing slot with Mallory's `noise_pub` and address.
        if existing.is_verified()
            && existing.noise_pub != [0u8; 32]
            && contact.noise_pub != existing.noise_pub
        {
            bucket.contacts.insert(pos, existing);
            return AddResult::Rejected;
        }

        let subnet = contact.subnet_key();
        let ip = contact.addr.ip();
        if contact.addr != existing.addr {
            if !admit_new_addr {
                // Refused move: keep the entry exactly as it stands. It used to
                // take the new session's `noise_pub` while keeping the old
                // address — a pairing that never existed, so every dial failed
                // the handshake even when the old address still routed. Worse,
                // it refreshed `last_seen` and zeroed `failed_queries`, so the
                // staleness purge would not retire it and the strike counter
                // could never reach `MAX_FAILED_QUERIES`. Each further frame
                // reset it again, leaving a permanently undialable, immortal
                // contact that we also gossiped and persisted.
                //
                // Reachable in two ordinary ways: during the fail-closed startup
                // window `admits_addr` refuses everything while the UDP gate
                // still lets known peers through, so a restored contact whose
                // address changed poisons its own entry; and a peer that moves
                // to LAN/CGNAT with `block_private_ips` on is refused forever.
                // Left untouched, the old address either still answers or the
                // contact faults out on schedule.
                bucket.contacts.insert(pos, existing);
                return AddResult::Added;
            }
            let old_subnet = existing.subnet_key();
            let old_ip = existing.addr.ip();
            if subnet != old_subnet {
                if bucket.subnet_count(subnet) >= max_subnet_bucket {
                    bucket.contacts.insert(pos, existing);
                    return AddResult::Rejected;
                }
                let global_count = self.global_subnet_count.get(&subnet).copied().unwrap_or(0);
                if global_count >= max_subnet_global {
                    bucket.contacts.insert(pos, existing);
                    return AddResult::Rejected;
                }
            }
            if ip != old_ip && self.global_ip_count.get(&ip).copied().unwrap_or(0) >= max_per_ip {
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
        AddResult::Added
    }

    /// The replacement-cache entry `bucket_idx` should promote next, or `None`
    /// if nothing there is currently eligible.
    ///
    /// Preference is verified-first, then newest — the same rule
    /// [`Self::find_closest_prefer_verified`] applies everywhere else a contact
    /// is chosen. Promotion used to take the newest eligible entry outright,
    /// which quietly made this the one selection point in the table that
    /// treated hearsay as equal to a contact we had actually spoken to. Since
    /// the cache is filled from `FOUND_NODE` / `PEER_LIST` gossip, and one peer
    /// can offer twenty contacts per frame, that handed a single gossiping peer
    /// the backfill for all natural bucket churn.
    ///
    /// `exclude` is the contact `evict_and_replace` just removed: `find` no
    /// longer sees it, and promoting its own cache entry would undo the
    /// eviction and hand it a clean failure count.
    fn best_promotable_cached(
        &self,
        bucket_idx: usize,
        exclude: Option<&EmberNodeId>,
        scale: scale::NetworkScale,
    ) -> Option<usize> {
        let max_per_ip = scale.max_contacts_per_ip();
        let max_subnet_global = scale.max_contacts_per_subnet_global();
        let max_subnet_bucket = scale.max_contacts_per_subnet_per_bucket();
        let bucket = &self.buckets[bucket_idx];
        let mut lead: Option<usize> = None;
        // Newest first, so the first hit at either rank is also the freshest.
        for i in (0..bucket.replacement_cache.len()).rev() {
            let candidate = &bucket.replacement_cache[i];
            // Never promote a peer that already holds a slot in this bucket:
            // that would give one contact two.
            if Some(&candidate.node_id) == exclude || bucket.find(&candidate.node_id).is_some() {
                continue;
            }
            // A cache entry can be stale: the policy may have tightened, or the
            // user may have blocked its address, since it was cached.
            if !self.admits_addr(&candidate.addr) {
                continue;
            }
            let subnet = candidate.subnet_key();
            let eligible = bucket.subnet_count(subnet) < max_subnet_bucket
                && self.global_subnet_count.get(&subnet).copied().unwrap_or(0) < max_subnet_global
                && self
                    .global_ip_count
                    .get(&candidate.addr.ip())
                    .copied()
                    .unwrap_or(0)
                    < max_per_ip;
            if !eligible {
                continue;
            }
            if candidate.is_verified() {
                return Some(i);
            }
            if lead.is_none() {
                lead = Some(i);
            }
        }
        // No proven contact is promotable, so a lead is still better than
        // leaving the slot empty — it is how a cold table grows at all.
        lead
    }

    /// Called when a liveness ping to the oldest contact in a bucket fails.
    /// Evicts the dead contact and promotes the best replacement cache entry.
    ///
    /// Returns whether a **replacement was promoted** — *not* whether the
    /// contact was evicted. `false` covers three different outcomes: the id was
    /// not in the table at all, or it was removed and nothing in the cache was
    /// eligible to take the slot, or the bucket index was out of range. Only
    /// the first leaves the table unchanged.
    ///
    /// The distinction matters because reading `false` as "the contact is still
    /// there" is wrong in two of the three cases. The sole production caller
    /// uses it to pick a log line, so nothing depends on it today; it is spelled
    /// out here because the signature invites exactly that misreading.
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

        // Promote the best replacement-cache entry that still satisfies the
        // diversity limits. Blindly promoting the newest entry (the original
        // behaviour) let a bucket fill up with contacts from one subnet via the
        // cache, defeating the eclipse-resistance the `add_contact` checks
        // provide — and treated gossip as equal to a proven contact.
        let chosen = self.best_promotable_cached(bucket_idx, Some(dead_id), self.admission_scale());

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
                // Same reason `promote_cached_contacts` stamps it: a bucket
                // whose contents just changed is not idle, and leaving it at
                // whatever it was makes it look stale to `buckets_for_refresh`.
                self.buckets[bucket_idx].last_activity = chrono::Utc::now().timestamp();
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
        // Prefer a contact we have actually heard from. Only one node can be
        // bound to a given `ip:port`, but nothing stops gossip from claiming
        // several node IDs there, and taking the first match let an inbound
        // datagram's rate-limit accounting land on whichever fabricated
        // identity happened to be filed first. A verified entry is one we have
        // exchanged signed frames with at that address, so it is the one the
        // datagram actually belongs to.
        let mut fallback = None;
        for contact in self.buckets.iter().flat_map(|b| b.contacts.iter()) {
            if contact.addr != addr {
                continue;
            }
            if contact.is_verified() {
                return Some(contact);
            }
            fallback.get_or_insert(contact);
        }
        fallback
    }

    /// How many contacts we have actually heard from.
    pub fn verified_len(&self) -> usize {
        self.buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter(|c| c.is_verified())
            .count()
    }

    /// Rough size of the whole network, from the density of the neighbourhood
    /// we can see.
    ///
    /// The nodes nearest us occupy a slice of the keyspace: if the furthest of
    /// the `m` closest sits at XOR distance `d`, then a `d / 2^128` fraction of
    /// the space holds `m` nodes, so the whole space holds about
    /// `m * 2^128 / d`. Counting leading zero bits turns that into a shift — a
    /// distance with `lz` leading zeros is about `2^(128 - lz)` — which leaves
    /// `m << lz`.
    ///
    /// eMule KAD extrapolates from the depth of its zone tree instead
    /// (`CRoutingZone::EstimateCount`), which this table has no equivalent of,
    /// being a flat bucket array. Measuring the neighbourhood directly is the
    /// standard alternative and does not care how the table is arranged.
    ///
    /// Only verified contacts count: gossip is free to send, so counting leads
    /// would let anyone move the figure by announcing invented neighbours.
    /// `None` until enough peers have answered for a density to mean anything.
    /// A sparse neighbourhood reads low rather than high, which is the safe
    /// direction — it never claims the network is bigger than we can see.
    ///
    /// This is a diagnostic, not an input to any limit. Someone willing to grind
    /// keys until several of them land very close to our ID could inflate what
    /// it reports, so nothing that decides admission or spending should be
    /// derived from it without thinking that through first.
    pub fn estimated_network_size(&self) -> Option<u64> {
        /// Below this many answered contacts the neighbourhood is too sparse
        /// for its density to say anything about the whole keyspace.
        const MIN_SAMPLE: usize = 4;

        let mut distances: Vec<[u8; 16]> = self
            .buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter(|c| c.is_verified())
            .map(|c| self.local_id.distance(&c.node_id).0)
            .collect();
        if distances.len() < MIN_SAMPLE {
            return None;
        }
        distances.sort_unstable();

        // One k-bucket's worth is the neighbourhood Kademlia actually keeps
        // track of; sampling wider would measure buckets we only partly fill.
        let sample = distances.len().min(K_BUCKET_SIZE);
        let furthest = distances[sample - 1];

        let mut leading_zeros = 0u32;
        for byte in furthest {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                leading_zeros += byte.leading_zeros();
                break;
            }
        }

        let span = 1u64.checked_shl(leading_zeros).unwrap_or(u64::MAX);
        Some((sample as u64).saturating_mul(span))
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

        // Distance, and only distance. Preferring healthier contacts here was
        // tried and reverted: it cannot help, because `IterativeSearch::new`
        // re-sorts the seeds by distance and walks that order, so this function
        // never decided which peer is asked first. What it does decide is which
        // contacts make the list at all when more than `count` are verified — and
        // both callers treat that list as a target set, not a queue. Dropping a
        // close contact with one transient strike in favour of a healthier but
        // farther one therefore aims publishes at nodes that may refuse them:
        // `store_proximity_ok` on the storer side is strictly distance-based. A
        // non-zero `failed_queries` is normal mid-refresh anyway (see
        // `remove_stale`), and three strikes evicts outright.
        verified.sort_by_key(|a| a.0 .0);
        let mut out: Vec<EmberContact> = verified
            .into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect();
        if out.len() < count {
            leads.sort_by_key(|a| a.0 .0);
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

        all.sort_by_key(|a| a.0 .0);
        all.into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect()
    }

    /// The distance of the `k`th closest contact to `target`, or `None` when
    /// fewer than `k` are eligible.
    ///
    /// Exactly the number [`Self::find_closest`] puts last in a `k`-long result,
    /// under the same verified-only rule — the proximity gate reads nothing else
    /// out of that call, and a `STORE_BATCH` asks it once per record. Going
    /// through `find_closest` therefore cost a table scan, a full sort and `k`
    /// [`EmberContact`] clones per record, up to sixty-four times for one
    /// datagram, for a value the caller compares and drops.
    ///
    /// A bounded max-heap of `k` distances answers the same question in one pass
    /// with no clone and no sort: the largest of the `k` smallest is the root
    /// once every contact has been offered. Contacts at equal distance can swap
    /// places against the stable sort `find_closest` uses, which is invisible
    /// here because only the distance leaves this function.
    pub fn kth_closest_distance(&self, target: &EmberNodeId, k: usize) -> Option<EmberNodeId> {
        if k == 0 {
            return None;
        }
        // `verified_len() > 0` with the count dropped: the gate is a boolean and
        // the first verified contact settles it.
        let verified_only = self
            .buckets
            .iter()
            .any(|b| b.contacts.iter().any(|c| c.is_verified()));

        let mut furthest: BinaryHeap<[u8; 16]> = BinaryHeap::with_capacity(k);
        for bucket in &self.buckets {
            for contact in &bucket.contacts {
                if verified_only && !contact.is_verified() {
                    continue;
                }
                let dist = target.distance(&contact.node_id).0;
                if furthest.len() < k {
                    furthest.push(dist);
                } else if furthest.peek().is_some_and(|worst| dist < *worst) {
                    furthest.pop();
                    furthest.push(dist);
                }
            }
        }

        (furthest.len() == k).then(|| EmberNodeId(furthest.pop().expect("k contacts, k > 0")))
    }

    /// What the table contributes to the bootstrap cache, closest-to-home first.
    ///
    /// Proven contacts lead: mute gossip must not crowd them out or come back
    /// as the whole bootstrap set. Remaining slots are filled with untried
    /// bucket leads (`last_seen == 0`, not yet 3-struck). Replacement-cache
    /// gossip stays out — that is the junk this filter exists to drop, and
    /// [`super::peer_cache::BootstrapCache`] admits cached entries only once
    /// they have actually answered. Preferring contacts near our own ID mirrors
    /// KAD.
    ///
    /// Not the file's contents on its own. `nodes_ember.dat` is written from the
    /// cache, which unions this with the peers that live outside the table and
    /// keeps entries the table has since evicted — so a save can no longer cut
    /// the file down to whatever survived the last few minutes.
    pub fn export_bootstrap_contacts(&self, max: usize) -> Vec<EmberContact> {
        if max == 0 {
            return Vec::new();
        }
        let persistable = |c: &&EmberContact| c.failed_queries < super::MAX_FAILED_QUERIES;
        let mut verified: Vec<(EmberNodeId, &EmberContact)> = self
            .buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter(|c| c.is_verified() && persistable(c))
            .map(|c| (self.local_id.distance(&c.node_id), c))
            .collect();
        verified.sort_by_key(|a| a.0 .0);
        let mut out: Vec<EmberContact> = verified
            .into_iter()
            .take(max)
            .map(|(_, c)| c.clone())
            .collect();
        if out.len() < max {
            let mut leads: Vec<(EmberNodeId, &EmberContact)> = self
                .buckets
                .iter()
                .flat_map(|b| b.contacts.iter())
                .filter(|c| !c.is_verified() && persistable(c))
                .map(|c| (self.local_id.distance(&c.node_id), c))
                .collect();
            leads.sort_by_key(|a| a.0 .0);
            let room = max - out.len();
            out.extend(leads.into_iter().take(room).map(|(_, c)| c.clone()));
        }
        out
    }

    /// Get a contact by node ID, from the bucket or its replacement cache.
    ///
    /// `None` therefore means the table is not holding this node anywhere — evicted
    /// as stale, faulted out on missed pings, or dropped by an IP-filter reload —
    /// which is what makes this the right way to resolve a remembered node ID before
    /// addressing it. Publishing does that on every republish, so this is a hot path.
    ///
    /// The replacement cache has to be included or the answer is misleading in the
    /// commonest case. The nodes a lookup returns are all close to the key, so they
    /// share one bucket index relative to us, and on any warm node that bucket is
    /// already full — `add_contact` files them in the replacement cache. Searching
    /// only `contacts` reported almost every remembered target as gone, which is not
    /// what "gone" is supposed to mean here.
    pub fn get_contact(&self, node_id: &EmberNodeId) -> Option<&EmberContact> {
        let bucket_idx = self.local_id.bucket_index(node_id)?;
        if bucket_idx >= ID_BITS {
            return None;
        }
        let bucket = &self.buckets[bucket_idx];
        bucket
            .find(node_id)
            .map(|pos| &bucket.contacts[pos])
            .or_else(|| {
                bucket
                    .find_in_cache(node_id)
                    .map(|pos| &bucket.replacement_cache[pos])
            })
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

    /// Replacement-cache entries, which [`Self::all_contacts`] does not return.
    ///
    /// Counted in the overlay figure the UI shows, so they have to be reachable
    /// from outside the table or the number on screen describes state nothing
    /// else can see. A full bucket is only one way in — fail-closed IP-filter
    /// parking and the diversity limits both land here too, which means a peer
    /// we have genuinely spoken to can be sitting in the cache rather than a
    /// bucket, and [`Self::export_bootstrap_contacts`] would never offer it for
    /// persistence.
    pub fn cached_contacts(&self) -> Vec<EmberContact> {
        self.buckets
            .iter()
            .flat_map(|b| b.replacement_cache.iter().cloned())
            .collect()
    }

    /// Bulk-load contacts (e.g., from persisted `nodes_ember.dat`).
    ///
    /// The range filter is detached for this pass. At startup it is fail-closed
    /// until `ipfilter.dat` loads, and Ember addresses are never Kad bootstrap
    /// seeds, so [`Self::admits_addr`] would refuse the entire file. Kad inserts
    /// `nodes.dat` before attaching the filter for the same reason. Port 0,
    /// non-v4, and the table's private/bogus rules still apply. Blocked ranges
    /// are dropped later by [`Self::evict_filtered_contacts`] once the list is
    /// ready.
    ///
    /// Returns the ids that took a bucket slot. Callers need that to be the
    /// *admitted* set and nothing wider: a contact refused by the IP policy or
    /// a diversity cap is parked in a replacement cache, and a parked contact
    /// is never dialled — [`Self::all_contacts`] does not return the cache, so
    /// it is not a liveness-ping target. Asking [`Self::get_contact`]
    /// afterwards cannot answer this, because it deliberately searches the
    /// cache too, so a parked seed reads back as if it had been tried.
    pub fn load_contacts(&mut self, contacts: Vec<EmberContact>) -> Vec<EmberNodeId> {
        let held = self.ip_gate.take_range_filter();
        let count = contacts.len();
        let mut admitted = Vec::with_capacity(contacts.len());
        for contact in contacts {
            let node_id = contact.node_id;
            if matches!(self.add_contact(contact), AddResult::Added) {
                admitted.push(node_id);
            }
        }
        self.ip_gate.restore_range_filter(held);
        debug!(
            "Loaded {}/{count} contacts into Ember routing table",
            admitted.len()
        );
        admitted
    }

    // ── Internal helpers ──

    fn add_to_cache(
        &mut self,
        bucket_idx: usize,
        contact: EmberContact,
        scale: scale::NetworkScale,
    ) {
        // A contact holding a bucket slot must never also hold a cache entry.
        // Other callers (and an older `add_contact` that parked before it
        // tested residency) can still hand a resident in here; refuse it.
        if self.buckets[bucket_idx].find(&contact.node_id).is_some() {
            return;
        }

        let max_subnet_global = scale.max_contacts_per_subnet_global();
        let max_subnet_bucket = scale.max_contacts_per_subnet_per_bucket();
        let max_per_ip = scale.max_contacts_per_ip();

        if let Some(pos) = self.buckets[bucket_idx].find_in_cache(&contact.node_id) {
            let existing = &mut self.buckets[bucket_idx].replacement_cache[pos];
            // Gossip (`last_seen == 0`) must not clobber a cached observation.
            if contact.last_seen <= 0 {
                return;
            }
            if existing.is_verified()
                && existing.noise_pub != [0u8; 32]
                && contact.noise_pub != existing.noise_pub
            {
                return;
            }
            if contact.is_verified() && !existing.is_verified() {
                *existing = contact;
                return;
            }
            if contact.last_seen >= existing.last_seen {
                existing.last_seen = contact.last_seen;
                existing.failed_queries = 0;
                existing.noise_pub = contact.noise_pub;
                existing.ed25519_pub = contact.ed25519_pub;
                existing.addr = contact.addr;
            }
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
                bucket.subnet_count(s) >= max_subnet_bucket
                    || self.global_subnet_count.get(&s).copied().unwrap_or(0) >= max_subnet_global
                    || self.global_ip_count.get(&c.addr.ip()).copied().unwrap_or(0) >= max_per_ip
            });
            let bucket = &mut self.buckets[bucket_idx];
            match ineligible {
                Some(pos) => {
                    bucket.replacement_cache.remove(pos);
                }
                None => {
                    // Then the oldest entry we have never heard from. Pure
                    // oldest-first let gossip recycle the whole cache: one peer
                    // may offer `MAX_CONTACTS_PER_RESPONSE` contacts per
                    // `FOUND_NODE`, all of them `last_seen == 0`, so a few
                    // frames displaced every firsthand observation in the
                    // bucket and left that peer owning the backfill for all
                    // natural churn. `remove_stale` sweeps this cache too, so
                    // preferring proven entries cannot ossify it.
                    let lead = bucket
                        .replacement_cache
                        .iter()
                        .position(|c| !c.is_verified());
                    match lead {
                        Some(pos) => {
                            bucket.replacement_cache.remove(pos);
                        }
                        None => {
                            bucket.replacement_cache.pop_front();
                        }
                    }
                }
            }
        }
        self.buckets[bucket_idx]
            .replacement_cache
            .push_back(contact);
    }
}

/// Bucket-array storage for the shared IP-policy sweep.
///
/// [`RoutingTable::remove_contact`] is the right eviction hook rather than
/// [`RoutingTable::evict_and_replace`]: a contact dropped on policy grounds
/// should not pull a replacement in from the cache, because the same sweep is
/// about to re-test the cache with the same predicate.
impl dht_common::PolicyEvictable for RoutingTable {
    type ContactId = EmberNodeId;

    fn ip_gate(&self) -> &dht_common::IpAdmissionGate {
        &self.ip_gate
    }

    fn resident_contacts(&self) -> Vec<(EmberNodeId, Option<Ipv4Addr>)> {
        self.all_contacts()
            .into_iter()
            .map(|c| (c.node_id, judgeable_ip(&c.addr)))
            .collect()
    }

    fn evict_contact(&mut self, id: &EmberNodeId) -> bool {
        self.remove_contact(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::kad::ip_filter::IpFilter;
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

    /// A contact with an explicit id and address, for the diversity tests:
    /// `make_contact` derives its /24 from the id, so it cannot express several
    /// peers sharing a subnet.
    fn contact_with(id: [u8; 16], ip: Ipv4Addr) -> EmberContact {
        EmberContact {
            node_id: EmberNodeId(id),
            addr: SocketAddr::new(IpAddr::V4(ip), 4672),
            noise_pub: [id[0]; 32],
            ed25519_pub: [id[1]; 32],
            last_seen: chrono::Utc::now().timestamp(),
            failed_queries: 0,
        }
    }

    /// Fill the table with peers that share nothing, to move the tier without
    /// tripping any cap on the way. Seven buckets so the crowded one under test
    /// is left alone.
    fn grow_verified(rt: &mut RoutingTable, per_bucket: u8) {
        for b in 0..7u8 {
            for i in 0..per_bucket {
                let mut id = [0u8; 16];
                id[0] = 1 << b;
                id[1] = i;
                id[2] = 0xA5;
                rt.add_contact(contact_with(id, Ipv4Addr::new(11 + b, i, 1, 1)));
            }
        }
    }

    /// A /24 that took its share of a bucket while we knew almost nobody kept it
    /// for the life of the process: admission tightened as the table filled, but
    /// nothing re-read a contact once it held a slot, and one that answers
    /// liveness pings is never stale, never faults out and is never displaced.
    /// Bucket occupancy is geometric, so that share sits in the bucket that
    /// decides most of what `find_closest` serves.
    #[test]
    fn growing_out_of_the_cold_start_tier_reclaims_the_share_it_allowed() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // One /24 takes the cold-start allowance in a single bucket. Distinct
        // addresses within it, so this is the subnet cap under test and not the
        // per-IP one.
        let crowded: Vec<EmberContact> = (1..=5u8)
            .map(|i| {
                let mut id = [0u8; 16];
                id[0] = 0x80;
                id[1] = i;
                contact_with(id, Ipv4Addr::new(80, 7, 7, i))
            })
            .collect();
        for c in &crowded {
            assert!(matches!(rt.add_contact(c.clone()), AddResult::Added));
        }
        let subnet = crowded[0].subnet_key();
        let bucket = local.bucket_index(&crowded[0].node_id).expect("a bucket");
        assert_eq!(
            rt.buckets[bucket].subnet_count(subnet),
            scale::NetworkScale::Bootstrap.max_contacts_per_subnet_per_bucket(),
            "the cold-start tier admits five of them"
        );

        // The network then grows past the point where the strict limits cost
        // nothing, which is the moment the old code stopped caring.
        grow_verified(&mut rt, 15);
        assert_eq!(rt.scale(), scale::NetworkScale::Established);

        let demoted = rt.enforce_scale_quotas();
        assert!(demoted > 0, "the grandfathered share has to be reclaimed");
        assert_eq!(
            rt.buckets[bucket].subnet_count(subnet),
            scale::NetworkScale::Established.max_contacts_per_subnet_per_bucket(),
            "the crowded /24 is cut to what this tier would admit"
        );

        // Demoted, not forgotten: the cache is where a contact the caps turn
        // away already waits, and `promote_cached_contacts` brings it back if a
        // slot frees up.
        let resident: HashSet<EmberNodeId> = rt.buckets[bucket]
            .contacts
            .iter()
            .map(|c| c.node_id)
            .collect();
        let cached: HashSet<EmberNodeId> = rt.buckets[bucket]
            .replacement_cache
            .iter()
            .map(|c| c.node_id)
            .collect();
        for c in &crowded {
            assert!(
                resident.contains(&c.node_id) || cached.contains(&c.node_id),
                "a demoted contact must still be remembered, not dropped"
            );
        }

        // The peers that were never crowding anything are untouched.
        assert!(
            rt.verified_len() >= 100,
            "only the excess goes, not the table: {} left",
            rt.verified_len()
        );
        assert_eq!(
            rt.enforce_scale_quotas(),
            0,
            "a tier already enforced does not re-run"
        );
    }

    /// The maintenance tick prunes and then promotes, in that order, and
    /// promotion reads the tier from the table it is promoting into. Demotion
    /// moves contacts to replacement caches, which the tier is not derived
    /// from — so pruning a table that sits just above a boundary drops the live
    /// reading back below it, and the promotion pass then re-admitted under the
    /// looser tier exactly what the prune had removed. The ratchet stops
    /// `enforce_scale_quotas` re-running; on its own it did nothing to stop the
    /// same tick undoing it.
    #[test]
    fn promotion_does_not_re_admit_what_the_quota_pass_just_demoted() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // Eight peers behind one address: exactly what the cold-start tier
        // allows. Spread across buckets so this is the per-IP cap under test
        // and not the per-bucket subnet one.
        let shared_ip = Ipv4Addr::new(80, 7, 7, 7);
        for b in 0..8u8 {
            let mut id = [0u8; 16];
            id[0] = 1 << b;
            id[1] = 0x11;
            assert!(matches!(
                rt.add_contact(contact_with(id, shared_ip)),
                AddResult::Added
            ));
        }

        // Five unrelated peers take the table to thirteen verified contacts —
        // the point at which the quota pass prunes to `Small`, since it reads
        // the tier from four-fifths of the count.
        for i in 0..5u8 {
            let mut id = [0u8; 16];
            id[0] = 1 << i;
            id[1] = 0xA5;
            id[2] = i;
            assert!(matches!(
                rt.add_contact(contact_with(id, Ipv4Addr::new(20 + i, 1, 1, 1))),
                AddResult::Added
            ));
        }
        assert_eq!(rt.verified_len(), 13);

        let demoted = rt.enforce_scale_quotas();
        assert_eq!(
            demoted,
            8 - scale::NetworkScale::Small.max_contacts_per_ip(),
            "the cold-start per-IP share is cut to what `Small` would admit"
        );

        // The trap: the contacts it just demoted are no longer counted, so the
        // live tier has fallen back to the very one whose allowance was pruned
        // away. Admission has to keep using the enforced tier here.
        assert_eq!(rt.scale(), scale::NetworkScale::Bootstrap);
        assert_eq!(rt.admission_scale(), scale::NetworkScale::Small);

        rt.promote_cached_contacts();

        let resident_on_shared_ip = rt
            .buckets
            .iter()
            .flat_map(|b| b.contacts.iter())
            .filter(|c| c.addr.ip() == IpAddr::V4(shared_ip))
            .count();
        assert_eq!(
            resident_on_shared_ip,
            scale::NetworkScale::Small.max_contacts_per_ip(),
            "promotion re-admitted the share the quota pass had just reclaimed"
        );
    }

    /// Acting on a tightening is deliberately later than admitting under it.
    /// Without the margin a table sitting on a boundary would demote a contact
    /// on one tick and re-admit it on the next, since admission below the
    /// boundary is looser than the pruning above it.
    #[test]
    fn enforcement_waits_for_a_margin_past_the_admission_boundary() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        let crowded: Vec<EmberContact> = (1..=5u8)
            .map(|i| {
                let mut id = [0u8; 16];
                id[0] = 0x80;
                id[1] = i;
                contact_with(id, Ipv4Addr::new(80, 7, 7, i))
            })
            .collect();
        for c in &crowded {
            assert!(matches!(rt.add_contact(c.clone()), AddResult::Added));
        }
        let subnet = crowded[0].subnet_key();
        let bucket = local.bucket_index(&crowded[0].node_id).expect("a bucket");

        // Ten verified contacts: `Small` is what admission uses from here, but
        // the table is not pruned to it yet.
        grow_verified(&mut rt, 1);
        assert_eq!(rt.verified_len(), 12);
        assert_eq!(rt.scale(), scale::NetworkScale::Small);
        assert_eq!(
            rt.enforce_scale_quotas(),
            0,
            "sitting just past the boundary must not prune"
        );
        assert_eq!(rt.buckets[bucket].subnet_count(subnet), 5);

        // A little further in and it does.
        grow_verified(&mut rt, 2);
        assert!(rt.verified_len() >= 13);
        assert!(rt.enforce_scale_quotas() > 0);
        assert_eq!(
            rt.buckets[bucket].subnet_count(subnet),
            scale::NetworkScale::Small.max_contacts_per_subnet_per_bucket(),
        );
    }

    /// The other direction of the same margin. `admission_scale` is the
    /// stricter of the live tier and the enforced one, so a tier that ratcheted
    /// tight while the table was full went on governing admission after the
    /// table emptied — for the life of the process, since nothing rebuilds it.
    /// A node that loses its peers is in the situation the `Bootstrap`
    /// allowances exist for, not the one `Established` was chosen for.
    #[test]
    fn a_table_that_loses_its_peers_stops_enforcing_the_tier_it_outgrew() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // 105 verified contacts, none of them sharing an address or a /24, so
        // the tier moves without any cap binding on the way.
        grow_verified(&mut rt, 15);
        assert_eq!(rt.verified_len(), 105);
        assert_eq!(
            rt.enforce_scale_quotas(),
            0,
            "nothing shares an address, so tightening demotes nobody"
        );
        assert_eq!(rt.admission_scale(), scale::NetworkScale::Established);

        // Keep enough to stay inside `Established`'s own band. Relaxing is read
        // from five-fourths of the count, mirroring the four-fifths that
        // tightening uses, so the tier does not drop the moment the count does.
        let resident: Vec<EmberNodeId> = rt.all_contacts().iter().map(|c| c.node_id).collect();
        for id in resident.iter().take(105 - 70) {
            assert!(rt.remove_contact(id));
        }
        assert_eq!(rt.verified_len(), 70);
        assert_eq!(
            rt.admission_scale(),
            scale::NetworkScale::Established,
            "70 verified is 87 with the margin, still an established table"
        );
        assert_eq!(rt.enforce_scale_quotas(), 0);
        assert_eq!(rt.admission_scale(), scale::NetworkScale::Established);

        // Far enough below and the caps have to loosen with the table.
        for id in resident.iter().skip(105 - 70).take(70 - 12) {
            assert!(rt.remove_contact(id));
        }
        assert_eq!(rt.verified_len(), 12);
        assert_eq!(
            rt.enforce_scale_quotas(),
            0,
            "relaxing demotes nobody — it only widens what may be admitted"
        );
        assert_eq!(
            rt.admission_scale(),
            scale::NetworkScale::Small,
            "a nearly empty table must not be admitting under a full table's caps"
        );

        // And all the way down, so a node rejoining from nothing gets the
        // allowances a cold start is supposed to have.
        let left: Vec<EmberNodeId> = rt.all_contacts().iter().map(|c| c.node_id).collect();
        for id in &left {
            assert!(rt.remove_contact(id));
        }
        assert_eq!(rt.verified_len(), 0);
        assert_eq!(rt.enforce_scale_quotas(), 0);
        assert_eq!(rt.admission_scale(), scale::NetworkScale::Bootstrap);
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
    fn verified_noise_pub_is_pinned_against_a_different_session() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let mut alice = make_contact(0x22, 4672);
        alice.noise_pub = [0xAA; 32];
        assert!(matches!(rt.add_contact(alice.clone()), AddResult::Added));

        let mut mallory = alice.clone();
        mallory.noise_pub = [0xBB; 32];
        mallory.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 9, 9, 9)), 4672);
        mallory.last_seen = chrono::Utc::now().timestamp();
        assert!(
            matches!(rt.add_contact(mallory), AddResult::Rejected),
            "a different Noise session must not steal Alice's slot"
        );
        let held = rt.get_contact(&alice.node_id).unwrap();
        assert_eq!(held.noise_pub, [0xAA; 32]);
        assert_eq!(held.addr, alice.addr);
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

    /// Fill one bucket, each contact in its own /24 so subnet diversity is not
    /// what is under test. Returns the table with `K_BUCKET_SIZE` residents.
    fn table_with_one_full_bucket() -> RoutingTable {
        let mut rt = RoutingTable::new(make_id(0), false);
        for i in 0x80..0x80 + K_BUCKET_SIZE as u8 {
            rt.add_contact(contact_at(i, 80, i, 1, 1));
        }
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE);
        rt
    }

    /// The bulk loader must report only the seeds that took a slot.
    ///
    /// Startup used to infer that by asking `get_contact` afterwards, which
    /// deliberately searches the replacement caches too — so a seed parked
    /// behind a full bucket read back as admitted, and the bootstrap cache
    /// charged it a missed session at shutdown for silence it was never given a
    /// chance to break. A parked contact is not a ping target either, which is
    /// what makes the charge simply untrue rather than merely early.
    #[test]
    fn load_contacts_reports_only_the_seeds_that_took_a_slot() {
        let mut rt = table_with_one_full_bucket();
        let parked = contact_at(0x80 + K_BUCKET_SIZE as u8, 80, 200, 1, 1);

        let admitted = rt.load_contacts(vec![parked.clone()]);

        assert!(
            admitted.is_empty(),
            "the bucket was full, so nothing was dialled"
        );
        assert!(
            rt.get_contact(&parked.node_id).is_some(),
            "it is still held — this is exactly what misled the caller"
        );
        assert!(
            !rt.all_contacts()
                .iter()
                .any(|c| c.node_id == parked.node_id),
            "and it is not a liveness-ping target, so it can never answer"
        );
    }

    /// Promotion was the one selection point in the table that ranked hearsay
    /// equal to a contact we had spoken to: it took the newest eligible cache
    /// entry outright. Since the cache is fed from `FOUND_NODE` / `PEER_LIST`,
    /// and one peer may offer twenty contacts in a frame, that let a single
    /// gossiping peer supply the backfill for all natural bucket churn.
    #[test]
    fn cache_promotion_prefers_contacts_that_have_answered_us() {
        let mut rt = table_with_one_full_bucket();

        // A proven contact lands in the cache, then gossip arrives on top of it.
        let proven = contact_at(0xA0, 80, 0xA0, 1, 1);
        rt.add_contact(proven.clone());
        for i in 0xB0..0xB5u8 {
            let mut lead = contact_at(i, 80, i, 1, 1);
            lead.last_seen = 0;
            rt.add_contact(lead);
        }

        assert!(rt.evict_and_replace(&make_id(0x80)));
        assert!(
            rt.get_contact(&proven.node_id).is_some(),
            "the proven cache entry must be promoted over newer gossip"
        );
    }

    /// The other half: pure oldest-first cache eviction let gossip recycle the
    /// whole cache, so the proven entry was gone before a slot ever opened.
    #[test]
    fn gossip_cannot_flush_proven_entries_out_of_the_replacement_cache() {
        let mut rt = table_with_one_full_bucket();

        let proven = contact_at(0xA0, 80, 0xA0, 1, 1);
        rt.add_contact(proven.clone());

        // Enough gossip to turn the cache over more than once.
        for i in 0..(K_BUCKET_SIZE as u8 * 2) {
            let mut lead = contact_at(0xC0 ^ i, 81, i, 1, 1);
            lead.last_seen = 0;
            rt.add_contact(lead);
        }

        assert!(rt.evict_and_replace(&make_id(0x81)));
        assert!(
            rt.get_contact(&proven.node_id).is_some(),
            "a firsthand observation must outlive a gossip flood in the cache"
        );
    }

    /// Preferring proven cache entries is only safe if one that has since gone
    /// silent can leave, or a dead entry would hold a slot against fresh leads
    /// and win promotion forever. `remove_stale` sweeps the cache for that.
    #[test]
    fn the_stale_sweep_reaches_the_replacement_cache() {
        let mut rt = table_with_one_full_bucket();
        let mut old = contact_at(0xA0, 80, 0xA0, 1, 1);
        old.last_seen = 1_000;
        rt.add_contact(old.clone());
        let mut lead = contact_at(0xA1, 80, 0xA1, 1, 1);
        lead.last_seen = 0;
        rt.add_contact(lead.clone());
        assert_eq!(rt.cached_len(), 2);

        let removed = rt.remove_stale(1_000_000, 3600, &HashSet::new());
        assert_eq!(removed, 0, "no resident contact was stale");
        assert_eq!(
            rt.cached_len(),
            1,
            "the stale proven entry goes; the lead has no timestamp to judge"
        );

        assert!(rt.evict_and_replace(&make_id(0x80)));
        assert!(
            rt.get_contact(&lead.node_id).is_some(),
            "with the dead entry swept, the lead is promotable again"
        );
        assert!(rt.get_contact(&old.node_id).is_none());
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
        // Saturate one subnet within the bucket. The limit is tier-dependent, so
        // it is read from the tier a full bucket lands in rather than hardcoded.
        let saturated =
            scale::NetworkScale::from_contacts(K_BUCKET_SIZE).max_contacts_per_subnet_per_bucket();
        assert!(
            saturated < K_BUCKET_SIZE,
            "the subnet must not fill the bucket"
        );
        for k in 0..saturated as u8 {
            rt.add_contact(contact_at(0x80 + k, 80, 1, 1, k + 1));
        }
        // Fill the rest of the 20-slot bucket with distinct subnets.
        for k in 0..(K_BUCKET_SIZE - saturated) as u8 {
            rt.add_contact(contact_at(0x80 + saturated as u8 + k, 80, 10 + k, 1, 1));
        }
        assert_eq!(rt.total_contacts(), K_BUCKET_SIZE);
        // The victim below has to be one of the distinct-subnet contacts.
        let victim = make_id(0x80 + saturated as u8);

        // Cache a fresh-subnet contact, then an over-limit subnet-A contact so
        // the over-limit one is the *newest* cache entry.
        rt.add_contact(contact_at(0x95, 80, 50, 1, 1)); // subnet B → cached
        rt.add_contact(contact_at(0x94, 80, 1, 1, 4)); // subnet A (full) → cached

        // Evicting a distinct-subnet live contact must promote the eligible
        // entry (0x95), skipping the subnet-saturated newest (0x94).
        //
        // Asked of the bucket rather than through `get_contact`, which also answers
        // from the replacement cache: 0x94 is still legitimately cached here, so the
        // question is whether it was promoted to a live slot, not whether the table
        // holds it at all.
        assert!(rt.evict_and_replace(&victim));
        let bucket = &rt.buckets[local.bucket_index(&make_id(0x95)).expect("a bucket")];
        assert!(
            bucket.find(&make_id(0x95)).is_some(),
            "the eligible entry is promoted"
        );
        assert!(
            bucket.find(&make_id(0x94)).is_none(),
            "the subnet-saturated one stays in the cache"
        );
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

    /// `store_proximity_ok` reads one number out of `find_closest`: the distance
    /// of the entry that lands last in a `k`-long result, and `true` outright
    /// when fewer than `k` came back. `kth_closest_distance` has to answer both
    /// halves identically at every table size — a disagreement at the boundary
    /// would silently change which keys this node accepts stores for.
    #[test]
    fn kth_closest_distance_agrees_with_find_closest() {
        let local = make_id(0);
        let target = make_id(0x33);

        // 0, 1, k-1, k and k+1 contacts. Distinct /24s so subnet diversity
        // admits every one of them, and IDs spread over buckets 120..124 so no
        // single bucket overflows at k+1.
        for size in [0, 1, K_BUCKET_SIZE - 1, K_BUCKET_SIZE, K_BUCKET_SIZE + 1] {
            for verified in [true, false] {
                let mut rt = RoutingTable::new(local, false);
                for i in 0..size {
                    let id = (i + 1) as u8;
                    let mut c = contact_at(id, 80, id, 1, 1);
                    if !verified {
                        // The cold-start branch: with nothing verified,
                        // `find_closest` falls back to every lead it holds.
                        c.last_seen = 0;
                    }
                    assert!(matches!(rt.add_contact(c), AddResult::Added));
                }
                assert_eq!(rt.total_contacts(), size, "table size {size}");

                for k in [1, 3, K_BUCKET_SIZE] {
                    let closest = rt.find_closest(&target, k);
                    let expected = (closest.len() == k)
                        .then(|| closest.last().expect("k > 0").node_id.distance(&target));
                    assert_eq!(
                        rt.kth_closest_distance(&target, k),
                        expected,
                        "size {size}, k {k}, verified {verified}"
                    );
                }
            }
        }
    }

    /// `k == 0` is the one input with no `find_closest` entry to name: it
    /// returns an empty vector, whose `last()` is `None`.
    #[test]
    fn kth_closest_distance_of_zero_names_nothing() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(contact_at(1, 80, 1, 1, 1));
        assert!(rt.find_closest(&make_id(0x33), 0).last().is_none());
        assert_eq!(rt.kth_closest_distance(&make_id(0x33), 0), None);
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
        assert!(rt
            .find_closest_prefer_verified(&make_id(0x10), 0)
            .is_empty());
    }

    /// Ranking these by health was tried and reverted; this pins the ordering so
    /// it is not tried again by accident. The seeds are a *target set*, and both
    /// callers use them as one — the search re-sorts by distance before walking,
    /// and publishing needs the genuinely closest nodes because the storer's own
    /// `store_proximity_ok` gate is distance-based and will refuse a record from a
    /// publisher that aimed it further out.
    #[test]
    fn seeds_are_ordered_by_distance_even_when_a_close_contact_has_missed() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // The nearest contact to the target is one strike down; a healthy one sits
        // further away.
        rt.add_contact(make_contact(0x11, 4672));
        rt.add_contact(make_contact(0x40, 4672));
        assert!(!rt.mark_failed(&make_id(0x11)), "one strike, not evicted");
        assert_eq!(rt.verified_len(), 2, "both are still in the table");

        let targets = rt.find_closest_prefer_verified(&make_id(0x10), 2);
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[0].node_id,
            make_id(0x11),
            "the closest contact leads, transient strike or not"
        );
        assert_eq!(targets[1].node_id, make_id(0x40));
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
        use super::super::{bootstrap, peer_cache};

        let local = make_id(0);
        let dir = std::env::temp_dir().join("ember_purge_boot_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        // Persist contacts last heard from long ago, as a previous session
        // would have. Real keypairs, because the loader re-derives each node
        // id from its Ed25519 key rather than trusting the stored one.
        let long_ago = chrono::Utc::now().timestamp() - 100_000;
        let saved: Vec<peer_cache::CachedContact> = (1..=3u8)
            .map(|i| {
                let sk = ed25519_dalek::SigningKey::from_bytes(&[i; 32]);
                let ed25519_pub = sk.verifying_key().to_bytes();
                let node_id = EmberNodeId(
                    crate::network::ember::crypto::node_id_from_ed25519_bytes(&ed25519_pub)
                        .expect("a real key derives an id"),
                );
                peer_cache::CachedContact::new(EmberContact {
                    node_id,
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, i, 1)), 4672),
                    noise_pub: [i; 32],
                    ed25519_pub,
                    last_seen: long_ago,
                    failed_queries: 0,
                })
            })
            .collect();
        bootstrap::save_nodes(&path, &saved, bootstrap::NodesFileState::Loaded).unwrap();

        // Through the cache, which is how the network loop restores a table:
        // the file keeps the previous session's timestamps and `seed_batch` is
        // what strips them.
        let mut cache = peer_cache::BootstrapCache::new();
        cache.load(bootstrap::load_nodes(&path).unwrap());
        let mut rt = RoutingTable::new(local, false);
        rt.load_contacts(cache.seed_batch(&local, &HashSet::new(), 200));
        assert_eq!(rt.total_contacts(), saved.len());

        let now = chrono::Utc::now().timestamp();
        assert_eq!(
            rt.remove_stale(now, 7200, &HashSet::new()),
            0,
            "the purge must not delete contacts that have not been probed yet"
        );
        assert_eq!(rt.total_contacts(), saved.len());

        // Once one answers, it counts as proven and ages normally from there.
        rt.mark_alive(&saved[0].contact.node_id);
        assert!(rt
            .get_contact(&saved[0].contact.node_id)
            .unwrap()
            .is_verified());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Proven contacts lead the bootstrap file; untried bucket leads fill
    /// remaining slots so a thin verified table does not throw away seeds.
    #[test]
    fn bootstrap_export_prefers_proven_then_fills_with_leads() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.add_contact(gossip_contact(0x11));
        rt.add_contact(make_contact(0x22, 4672));

        let exported = rt.export_bootstrap_contacts(200);
        assert_eq!(exported.len(), 2);
        assert_eq!(exported[0].node_id, make_id(0x22));
        assert_eq!(exported[1].node_id, make_id(0x11));
        assert!(exported[0].is_verified());
        assert!(!exported[1].is_verified());

        let proven_only = rt.export_bootstrap_contacts(1);
        assert_eq!(proven_only.len(), 1);
        assert_eq!(proven_only[0].node_id, make_id(0x22));

        assert!(rt.export_bootstrap_contacts(0).is_empty());
    }

    /// Mute gossip filling a /24 must not keep a live same-subnet peer in the
    /// replacement cache while those leads hold the bucket slots.
    #[test]
    fn verified_contact_replaces_unverified_subnet_squatter() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let cap = scale::NetworkScale::Bootstrap.max_contacts_per_subnet_per_bucket();
        for k in 0..cap as u8 {
            let mut c = contact_at(0x80 + k, 80, 1, 1, k + 1);
            c.last_seen = 0;
            assert!(matches!(rt.add_contact(c), AddResult::Added));
        }
        assert_eq!(rt.total_contacts(), cap);
        assert_eq!(rt.verified_len(), 0);

        let live = contact_at(0x90, 80, 1, 1, 9);
        assert!(
            matches!(rt.add_contact(live.clone()), AddResult::Added),
            "a verified same-/24 peer must take a bucket slot from a lead"
        );
        let bucket_idx = local.bucket_index(&live.node_id).expect("a bucket");
        assert!(
            rt.buckets[bucket_idx].find(&live.node_id).is_some(),
            "the live peer belongs in the bucket, not the cache"
        );
        assert_eq!(rt.verified_len(), 1);
    }

    /// The displacement is for when the newcomer would otherwise be refused. On
    /// a bucket with free slots and no cap engaged there is nothing to displace
    /// *for*, and taking a same-/24 lead's slot anyway threw away a bootstrap
    /// lead on the node least able to spare one.
    #[test]
    fn a_verified_peer_does_not_evict_a_lead_when_the_bucket_has_room() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        let mut lead = contact_at(0x80, 80, 1, 1, 5);
        lead.last_seen = 0;
        assert!(matches!(rt.add_contact(lead.clone()), AddResult::Added));
        assert_eq!(rt.total_contacts(), 1);

        // Same /24, verified, and the bucket has nineteen free slots.
        let live = contact_at(0x90, 80, 1, 1, 9);
        assert!(matches!(rt.add_contact(live.clone()), AddResult::Added));

        assert_eq!(
            rt.total_contacts(),
            2,
            "both belong in the table: the slot was free, so nothing had to go"
        );
        let bucket_idx = local.bucket_index(&lead.node_id).expect("a bucket");
        assert!(
            rt.buckets[bucket_idx].find(&lead.node_id).is_some(),
            "the lead keeps its slot"
        );
        assert!(rt.buckets[bucket_idx].find(&live.node_id).is_some());
    }

    /// A move we refuse must leave the entry alone. Pairing the old address
    /// with the new session's Noise key made every dial fail the handshake,
    /// and refreshing `last_seen` / clearing `failed_queries` meant neither the
    /// staleness purge nor the strike counter could ever retire it.
    #[test]
    fn a_refused_address_change_leaves_the_contact_dialable_and_mortal() {
        let local = make_id(0);
        // `block_private_ips` is what makes the new address inadmissible.
        let mut rt = RoutingTable::new(local, true);

        let original = contact_at(0x80, 80, 1, 1, 5);
        assert!(matches!(rt.add_contact(original.clone()), AddResult::Added));

        // The same node reappears from a LAN address the table will not admit.
        // Its static key is unchanged, as a peer that merely moves keeps it —
        // changing it here would trip the Noise-key pin *above* this branch and
        // the test would pass without ever reaching the code it is named for.
        let mut moved = original.clone();
        moved.addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 4672);
        moved.last_seen = original.last_seen + 500;
        rt.add_contact(moved);

        let held = rt.get_contact(&original.node_id).expect("still held");
        assert_eq!(held.addr, original.addr, "the dialable address is kept");
        assert_eq!(
            held.last_seen, original.last_seen,
            "and it is not refreshed by a frame from an address we will not use"
        );
        assert_eq!(
            held.failed_queries, 0,
            "with its strike counter left where it stood"
        );

        // Because nothing was refreshed, the strike counter can still reach the
        // eviction threshold — which is what "mortal" means here.
        for _ in 0..super::super::MAX_FAILED_QUERIES - 1 {
            assert!(
                !rt.mark_failed(&original.node_id),
                "not dead before the last strike"
            );
        }
        assert!(
            rt.mark_failed(&original.node_id),
            "a contact we cannot reach must still be able to fault out"
        );
    }

    /// A verified contact outranks mute gossip, but only within the /24
    /// diversity caps. The fast path consulted neither, and its
    /// `|| bucket.is_full()` disjunct matches *any* unverified resident — so
    /// one /24 running a keypair per host could take a whole full bucket
    /// simply by sending one signed frame from each. `find_closest` returns
    /// verified contacts only, so those slots decide the contacts we gossip,
    /// the store-responsibility comparison and every lookup frontier.
    #[test]
    fn a_single_subnet_cannot_take_a_full_bucket_by_being_verified() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // Fill one bucket with unverified leads, each in its own /24 so no
        // subnet cap is engaged yet.
        for k in 0..K_BUCKET_SIZE as u8 {
            let mut lead = contact_at(0x80 + k, 80, k, 1, 1);
            lead.last_seen = 0;
            assert!(matches!(rt.add_contact(lead), AddResult::Added));
        }
        assert_eq!(rt.verified_len(), 0, "all seeded contacts are mute gossip");

        // Now one /24 speaks from many hosts, each with its own keypair (so
        // distinct node ids) and its own address (so the per-IP cap is not
        // what binds).
        let attacker = contact_at(0xA0, 10, 0, 0, 1);
        let attacker_subnet = attacker.subnet_key();
        let bucket_idx = local.bucket_index(&attacker.node_id).expect("a bucket");
        for j in 0..K_BUCKET_SIZE as u8 {
            let _ = rt.add_contact(contact_at(0xA0 + j, 10, 0, 0, j + 1));
        }

        let taken = rt.buckets[bucket_idx]
            .contacts
            .iter()
            .filter(|c| c.subnet_key() == attacker_subnet)
            .count();
        assert!(
            taken < K_BUCKET_SIZE,
            "one /24 holds {taken} of {K_BUCKET_SIZE} slots — the diversity caps were bypassed"
        );
        assert!(
            taken <= scale::NetworkScale::Bootstrap.max_contacts_per_subnet_global(),
            "one /24 holds {taken} slots, past the global /24 cap"
        );
    }

    /// A later verified observation of a cached lead must upgrade the cache
    /// entry rather than being dropped as a duplicate.
    #[test]
    fn cached_lead_upgrades_when_it_answers() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        for i in 0x80..0x80 + K_BUCKET_SIZE as u8 {
            assert!(matches!(
                rt.add_contact(contact_at(i, 80, i, 1, 1)),
                AddResult::Added
            ));
        }
        let mut lead = contact_at(0x80 + K_BUCKET_SIZE as u8, 80, 200, 1, 1);
        lead.last_seen = 0;
        let _ = rt.add_contact(lead.clone());
        let bucket_idx = local.bucket_index(&lead.node_id).expect("a bucket");
        assert!(rt.buckets[bucket_idx].find(&lead.node_id).is_none());
        assert!(rt.buckets[bucket_idx]
            .find_in_cache(&lead.node_id)
            .is_some());

        lead.last_seen = chrono::Utc::now().timestamp();
        let _ = rt.add_contact(lead.clone());
        let cached = rt.get_contact(&lead.node_id).expect("still held");
        assert!(cached.is_verified(), "the cache entry must upgrade");
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

    /// The same rule from the other direction: a contact that already holds a
    /// slot must not acquire a cache entry either. `add_contact` parks a lead
    /// before it tests residency, so during the window every launch opens with
    /// — filter attached, ranges not parsed, known peers still answering —
    /// every resident contact filed a duplicate of itself. `evict_and_replace`
    /// removes the dead contact before it scans the cache, so that duplicate
    /// passed the already-resident test and promoted the peer straight back
    /// with a clean failure count, undoing the three missed pings that had just
    /// retired it.
    #[test]
    fn a_resident_contact_is_never_parked_as_its_own_replacement() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let resident = make_contact(0x11, 4672);
        let id = resident.node_id;
        assert!(matches!(rt.add_contact(resident.clone()), AddResult::Added));

        let mut filter = IpFilter::new(true, false);
        rt.set_ip_filter(filter.create_shared_snapshot());
        assert!(
            !rt.admits_addr(&resident.addr),
            "this only reproduces while the gate cannot judge the address yet"
        );
        rt.add_contact(resident.clone());

        let bucket_idx = local.bucket_index(&id).expect("a bucket");
        assert!(
            rt.buckets[bucket_idx].find_in_cache(&id).is_none(),
            "a contact holding a bucket slot must not also be its own cache entry"
        );

        filter.mark_ranges_ready();
        rt.set_ip_filter(filter.create_shared_snapshot());

        assert!(
            !rt.evict_and_replace(&id),
            "a dead contact must not be available as its own replacement"
        );
        assert!(
            rt.get_contact(&id).is_none(),
            "the eviction has to stick, in the bucket and in the cache"
        );
    }

    #[test]
    fn a_verified_observation_updates_a_resident_during_the_fail_closed_window() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let mut resident = make_contact(0x11, 4672);
        resident.last_seen = 1;
        let id = resident.node_id;
        assert!(matches!(rt.add_contact(resident.clone()), AddResult::Added));

        let mut filter = IpFilter::new(true, false);
        rt.set_ip_filter(filter.create_shared_snapshot());
        assert!(!rt.admits_addr(&resident.addr));

        resident.last_seen = 42;
        resident.failed_queries = 2;
        assert!(matches!(rt.add_contact(resident), AddResult::Added));
        let held = rt.get_contact(&id).expect("still resident");
        assert_eq!(held.last_seen, 42);
        assert_eq!(held.failed_queries, 0);

        // A new contact still has to pass the gate. It parks in the
        // replacement cache like any other refusal, and promotion re-checks
        // `admits_addr`, so a filtered address can never reach a bucket.
        let mut blocked = make_contact(0x22, 4672);
        blocked.last_seen = 99;
        let blocked_id = blocked.node_id;
        assert!(matches!(rt.add_contact(blocked), AddResult::Rejected));
        assert!(
            rt.get_contact(&blocked_id).is_some(),
            "a gated new contact parks in the replacement cache, not dropped"
        );
        assert_eq!(rt.promote_cached_contacts(), 0);
        filter.mark_ranges_ready();
        rt.set_ip_filter(filter.create_shared_snapshot());
        assert_eq!(rt.promote_cached_contacts(), 1);
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

    /// Gossip is cheap to send and proves nothing. Sizing the abuse limits by
    /// raw occupancy let anyone who could talk at us push the table to its
    /// strict tier, so a node that had reached almost no real peer started
    /// refusing them — the opposite of what the permissive tier is for.
    /// A contact one bit of XOR distance from `local`, so each `bucket` gets
    /// its own occupant rather than all of them crowding into one, in its own
    /// /24 so the diversity caps never refuse it.
    fn contact_in_bucket(local: EmberNodeId, bucket: usize, last_seen: i64) -> EmberContact {
        let mut id = local.0;
        id[15 - bucket / 8] ^= 1 << (bucket % 8);
        let b = bucket as u8;
        EmberContact {
            node_id: EmberNodeId(id),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, b.wrapping_add(1), 1)), 4672),
            noise_pub: [b; 32],
            ed25519_pub: [b; 32],
            last_seen,
            failed_queries: 0,
        }
    }

    #[test]
    fn unverified_gossip_does_not_tighten_the_limits() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        // Never heard from: leads, exactly as gossip arrives.
        for bucket in 0..120 {
            rt.add_contact(contact_in_bucket(local, bucket, 0));
        }

        assert!(
            rt.total_contacts() > K_BUCKET_SIZE * 4,
            "the table is padded well past the strict threshold"
        );
        assert_eq!(rt.verified_len(), 0, "but none of it has answered us");
        assert_eq!(
            rt.scale(),
            scale::NetworkScale::Bootstrap,
            "limits must follow contacts we have reached, not ones we were told about"
        );
    }

    /// The flip side: once contacts genuinely answer, the limits do tighten.
    #[test]
    fn verified_contacts_tighten_the_limits() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);

        for bucket in 0..120 {
            rt.add_contact(contact_in_bucket(local, bucket, 1_700_000_000));
        }

        assert!(rt.verified_len() >= K_BUCKET_SIZE * 4);
        assert_eq!(rt.scale(), scale::NetworkScale::Established);
    }

    /// KAD extrapolates network size from the depth of its zone tree, which a
    /// flat bucket array has no equivalent of. How tightly the peers we have
    /// proven are packed around our own ID answers the same question without
    /// depending on the table's shape. `contact_in_bucket` flips exactly one
    /// bit, so a contact in bucket `b` sits at distance `2^b` and the
    /// arithmetic below is exact rather than approximate.
    #[test]
    fn network_size_is_estimated_from_neighbourhood_density() {
        let local = make_id(0);
        let seen = 1_700_000_000;

        let mut rt = RoutingTable::new(local, false);
        for bucket in 124..127 {
            rt.add_contact(contact_in_bucket(local, bucket, seen));
        }
        assert_eq!(rt.verified_len(), 3);
        assert_eq!(
            rt.estimated_network_size(),
            None,
            "three peers is not a density"
        );

        // A fourth, the furthest of them half the keyspace away: four nodes
        // spread over everything is what a four-node network looks like.
        rt.add_contact(contact_in_bucket(local, 127, seen));
        assert_eq!(rt.estimated_network_size(), Some(4));

        // The same peer count packed ten bits tighter describes a network 2^10
        // times larger, which is the whole point of measuring density.
        let mut tight = RoutingTable::new(local, false);
        for bucket in 114..118 {
            tight.add_contact(contact_in_bucket(local, bucket, seen));
        }
        assert_eq!(tight.estimated_network_size(), Some(4 * 1024));

        // Gossip is free to send, so it must not move the figure at all.
        let mut gossiped = RoutingTable::new(local, false);
        for bucket in 114..118 {
            gossiped.add_contact(contact_in_bucket(local, bucket, 0));
        }
        assert!(gossiped.total_contacts() >= 4);
        assert_eq!(gossiped.estimated_network_size(), None);
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

    /// `nodes_ember.dat` is restored while the IP filter is still fail-closed.
    /// Ember contacts are not Kad bootstrap seeds, so ordinary admission would
    /// refuse every address in the file. Restore must still seed the table, and
    /// eviction must not wipe it until the real list is applied.
    #[test]
    fn restored_contacts_survive_a_fail_closed_ip_filter() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let filter = IpFilter::new(true, false);
        rt.set_ip_filter(filter.create_shared_snapshot());

        assert!(
            matches!(rt.add_contact(make_contact(1, 4672)), AddResult::Rejected),
            "newcomers still wait until ipfilter.dat is applied"
        );

        rt.load_contacts(vec![make_contact(1, 4672), make_contact(2, 4672)]);
        assert_eq!(
            rt.total_contacts(),
            2,
            "persist-restore must ignore the fail-closed range gate"
        );
        assert_eq!(
            rt.evict_filtered_contacts(),
            0,
            "eviction must not treat fail-closed as a real block"
        );
        assert_eq!(rt.total_contacts(), 2);
        assert!(
            matches!(rt.add_contact(make_contact(3, 4672)), AddResult::Rejected),
            "filter stays attached for later newcomers"
        );
    }

    /// Gossip learned while `ipfilter.dat` is still parsing used to be dropped
    /// outright, so a node whose table was thin at launch discarded the very
    /// contacts that would have refilled it and stayed thin. Park it instead,
    /// and admit it once the ranges land.
    #[test]
    fn gossip_refused_while_the_filter_loads_is_admitted_once_it_is_ready() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let mut filter = IpFilter::new(true, false);
        rt.set_ip_filter(filter.create_shared_snapshot());

        assert!(
            matches!(rt.add_contact(make_contact(1, 4672)), AddResult::Rejected),
            "it must not enter the table on an unconfirmable answer"
        );
        assert_eq!(rt.total_contacts(), 0);

        filter.mark_ranges_ready();
        rt.set_ip_filter(filter.create_shared_snapshot());
        assert_eq!(rt.evict_filtered_contacts(), 0);
        assert_eq!(rt.total_contacts(), 1, "the parked lead is admitted");
        assert!(rt.get_contact(&make_id(1)).is_some());
    }

    /// The parking rule must not launder an address the list really blocks:
    /// that would put it in the table the moment a slot opened.
    #[test]
    fn an_address_the_list_blocks_is_never_parked_for_later() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        let mut filter = IpFilter::new(true, false);
        filter.add_range(
            Ipv4Addr::new(80, 1, 1, 1),
            Ipv4Addr::new(80, 1, 1, 1),
            "blocked".to_string(),
        );
        filter.mark_ranges_ready();
        rt.set_ip_filter(filter.create_shared_snapshot());

        assert!(matches!(rt.add_contact(make_contact(1, 4672)), AddResult::Rejected));
        assert_eq!(rt.promote_cached_contacts(), 0);
        assert_eq!(rt.total_contacts(), 0);
    }

    /// Same for a LAN address while `block_private_ips` is on: that is a
    /// settled policy answer, not a "cannot check yet".
    #[test]
    fn a_private_address_is_never_parked_while_block_private_is_on() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, true);
        let lan = EmberContact {
            node_id: make_id(7),
            addr: SocketAddr::from(([192, 168, 1, 50], 4672)),
            noise_pub: [7; 32],
            ed25519_pub: [8; 32],
            last_seen: 100,
            failed_queries: 0,
        };
        assert!(matches!(rt.add_contact(lan), AddResult::Rejected));
        assert_eq!(rt.promote_cached_contacts(), 0);
        assert_eq!(rt.total_contacts(), 0);
    }

    #[test]
    fn evict_drops_blocked_contacts_once_ranges_are_ready() {
        let local = make_id(0);
        let mut rt = RoutingTable::new(local, false);
        rt.load_contacts(vec![make_contact(1, 4672), make_contact(2, 4672)]);
        assert_eq!(rt.total_contacts(), 2);

        let mut filter = IpFilter::new(true, false);
        filter.add_range(
            Ipv4Addr::new(80, 1, 1, 1),
            Ipv4Addr::new(80, 1, 1, 1),
            "blocked".to_string(),
        );
        filter.mark_ranges_ready();
        rt.set_ip_filter(filter.create_shared_snapshot());

        assert_eq!(rt.evict_filtered_contacts(), 1);
        assert!(rt.get_contact(&make_id(1)).is_none());
        assert!(rt.get_contact(&make_id(2)).is_some());
    }
}
