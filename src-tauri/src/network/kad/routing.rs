use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;

use super::ip_filter;
use super::types::*;

/// eMule HR2S(1): per-zone `m_tNextBigTimer` after a successful OnBigTimer.
const BIG_TIMER_INTERVAL_SECS: i64 = 3600;
/// eMule SEC(10): `StartTimer` initial delay; also `m_tBigTimer` gap after success.
const BIG_TIMER_INITIAL_SECS: i64 = 10;
/// eMule `CKademlia::Process`: `m_tBigTimer = tNow + SEC(10)` after each successful RandomLookup.
const BIG_TIMER_GLOBAL_GAP_SECS: i64 = 10;
/// eMule Opcodes.h `KADEMLIADISCONNECTDELAY` (20 minutes).
const KAD_DISCONNECT_DELAY_SECS: i64 = 20 * 60;
/// eMule: `uLastContact + KADEMLIADISCONNECTDELAY - MIN2S(5)` bypasses per-zone big timer.
const BIG_TIMER_DISCONNECT_BYPASS_SECS: i64 = KAD_DISCONNECT_DELAY_SECS - 5 * 60;
/// eMule MIN2S(1): per-zone small timer fires every minute for liveness probing.
const SMALL_TIMER_INTERVAL_SECS: i64 = 60;
/// Default contact time-to-live (eMule: 2 hours).
const CONTACT_DEFAULT_TTL_SECS: i64 = 7200;

pub fn kad_version_name(version: u8) -> &'static str {
    match version {
        KADEMLIA_VERSION1_46C => "Kad1 (0.46c)",
        KADEMLIA_VERSION2_47A => "Kad2 (0.47a)",
        KADEMLIA_VERSION3_47B => "Kad2 (0.47b)",
        KADEMLIA_VERSION4_47C => "Kad2 (0.47c)",
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

// ---------------------------------------------------------------------------
// RoutingBin -- leaf container (eMule CRoutingBin)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RoutingBin {
    contacts: VecDeque<KadContact>,
}

impl RoutingBin {
    fn new() -> Self {
        RoutingBin {
            contacts: VecDeque::with_capacity(K_BUCKET_SIZE),
        }
    }

    fn len(&self) -> usize {
        self.contacts.len()
    }

    fn remaining(&self) -> usize {
        K_BUCKET_SIZE.saturating_sub(self.contacts.len())
    }

    fn get_contact(&self, id: &KadId) -> Option<&KadContact> {
        self.contacts.iter().find(|c| c.id == *id)
    }

    fn get_contact_mut(&mut self, id: &KadId) -> Option<&mut KadContact> {
        self.contacts.iter_mut().find(|c| c.id == *id)
    }

    fn push_to_bottom(&mut self, id: &KadId) {
        if let Some(pos) = self.contacts.iter().position(|c| c.id == *id) {
            if let Some(contact) = self.contacts.remove(pos) {
                self.contacts.push_back(contact);
            }
        }
    }

    /// eMule RoutingBin::AddContact -- check per-bin subnet limit, add if space.
    /// Global IP/subnet checks are done by the caller (RoutingTable).
    fn add_contact(&mut self, contact: KadContact) -> bool {
        if self.contacts.iter().any(|c| c.id == contact.id) {
            return false;
        }
        let snet = subnet_key(contact.ip);
        let same_subnets = self.contacts.iter()
            .filter(|c| subnet_key(c.ip) == snet)
            .count();
        if same_subnets >= MAX_CONTACTS_SUBNET_PER_BIN && !ip_filter::is_lan_ip(contact.ip) {
            return false;
        }
        if self.contacts.len() < K_BUCKET_SIZE {
            self.contacts.push_back(contact);
            return true;
        }
        false
    }

    fn remove_contact(&mut self, id: &KadId) -> Option<KadContact> {
        if let Some(pos) = self.contacts.iter().position(|c| c.id == *id) {
            self.contacts.remove(pos)
        } else {
            None
        }
    }

    /// eMule RoutingBin::ChangeContactIPAddress -- validate and apply IP change.
    fn change_contact_ip(
        &mut self,
        id: &KadId,
        new_ip: Ipv4Addr,
        global_ip_count: &HashMap<Ipv4Addr, u32>,
        global_subnet_count: &HashMap<u32, u32>,
    ) -> bool {
        let contact = match self.contacts.iter().find(|c| c.id == *id) {
            Some(c) => c,
            None => return false,
        };
        if contact.ip == new_ip {
            return true;
        }

        let ip_count = global_ip_count.get(&new_ip).copied().unwrap_or(0);
        if ip_count >= MAX_CONTACTS_IP {
            return false;
        }

        let old_snet = subnet_key(contact.ip);
        let new_snet = subnet_key(new_ip);
        if old_snet != new_snet {
            let is_lan = ip_filter::is_lan_ip(new_ip);
            if !is_lan {
                let snet_count = global_subnet_count.get(&new_snet).copied().unwrap_or(0);
                if snet_count >= MAX_CONTACTS_SUBNET {
                    return false;
                }
                let bin_count = self.contacts.iter()
                    .filter(|c| subnet_key(c.ip) == new_snet)
                    .count();
                if bin_count >= MAX_CONTACTS_SUBNET_PER_BIN {
                    return false;
                }
            }
        }

        if let Some(c) = self.contacts.iter_mut().find(|c| c.id == *id) {
            c.set_ip(new_ip);
        }
        true
    }

    /// eMule RoutingBin::GetClosestTo -- collect contacts filtered by type+verified,
    /// keyed by XOR distance to target, keeping at most max_required.
    fn get_closest_to(
        &self,
        max_type: u8,
        target: &KadId,
        max_required: usize,
        result: &mut BTreeMap<KadId, KadContact>,
    ) {
        for c in &self.contacts {
            if c.contact_type <= max_type && c.verified {
                let dist = target.xor_distance(&c.id);
                result.insert(dist, c.clone());
            }
        }
        while result.len() > max_required {
            result.pop_last();
        }
    }
}

// ---------------------------------------------------------------------------
// RoutingZone -- binary tree node (eMule CRoutingZone)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RoutingZone {
    children: Option<Box<(RoutingZone, RoutingZone)>>,
    bin: Option<RoutingBin>,
    level: u32,
    zone_index: KadId,
    /// eMule `CKademlia::AddEvent` order — `std::map` iteration over zone pointers; we use
    /// monotonic assignment on split / consolidate so leaf order matches creation sequence.
    event_order: u64,
    next_big_timer: i64,
    next_small_timer: i64,
}

impl RoutingZone {
    fn new_leaf(level: u32, zone_index: KadId, event_order: u64) -> Self {
        let now = chrono::Utc::now().timestamp();
        RoutingZone {
            children: None,
            bin: Some(RoutingBin::new()),
            level,
            zone_index,
            event_order,
            next_big_timer: now + BIG_TIMER_INITIAL_SECS,
            next_small_timer: now + (zone_index.chunk(3) as i64 % 3600),
        }
    }

    fn is_leaf(&self) -> bool {
        self.bin.is_some()
    }

    fn can_split(&self) -> bool {
        if self.level >= 127 {
            return false;
        }
        let bin = match &self.bin {
            Some(b) => b,
            None => return false,
        };
        (self.zone_index.less_than_u32(KK as u32) || self.level < KBASE as u32)
            && bin.len() == K_BUCKET_SIZE
    }

    fn gen_sub_zone(
        level: u32,
        parent_index: &KadId,
        side: usize,
        order_gen: &mut u64,
    ) -> RoutingZone {
        let mut new_index = *parent_index;
        new_index.shift_left(1);
        if side != 0 {
            new_index.add_u32(1);
        }
        let id = *order_gen;
        *order_gen += 1;
        RoutingZone::new_leaf(level + 1, new_index, id)
    }

    fn split(&mut self, local_id: &KadId, order_gen: &mut u64, dropped_ips: &mut Vec<Ipv4Addr>) {
        let bin = match self.bin.take() {
            Some(b) => b,
            None => return,
        };

        // eMule GenSubZone(0) then GenSubZone(1) — lower pointer / registration id first.
        let mut child0 = Self::gen_sub_zone(self.level, &self.zone_index, 0, order_gen);
        let mut child1 = Self::gen_sub_zone(self.level, &self.zone_index, 1, order_gen);

        for contact in bin.contacts {
            let distance = local_id.xor_distance(&contact.id);
            let side = distance.get_bit_number(self.level);
            let ip = contact.ip;
            let target_bin = if side == 0 {
                child0.bin.as_mut()
            } else {
                child1.bin.as_mut()
            };
            let added = if let Some(bin) = target_bin {
                bin.add_contact(contact)
            } else {
                false
            };
            if !added {
                dropped_ips.push(ip);
            }
        }

        self.children = Some(Box::new((child0, child1)));
    }

    /// eMule CRoutingZone::Consolidate -- merge sibling leaves when sparse.
    fn consolidate(&mut self, order_gen: &mut u64, dropped_ips: &mut Vec<Ipv4Addr>) -> u32 {
        if self.is_leaf() {
            return 0;
        }
        let mut merge_count = 0u32;

        if let Some(children) = &mut self.children {
            if !children.0.is_leaf() {
                merge_count += children.0.consolidate(order_gen, dropped_ips);
            }
            if !children.1.is_leaf() {
                merge_count += children.1.consolidate(order_gen, dropped_ips);
            }
        }

        let should_merge = if let Some(children) = &self.children {
            children.0.is_leaf() && children.1.is_leaf()
                && children.0.get_num_contacts() + children.1.get_num_contacts() < (K_BUCKET_SIZE / 2) as u32
        } else {
            false
        };

        if should_merge {
            let Some(children) = self.children.take() else { return merge_count; };
            let mut new_bin = RoutingBin::new();
            if let Some(bin0) = children.0.bin {
                for c in bin0.contacts {
                    let ip = c.ip;
                    if !new_bin.add_contact(c) {
                        dropped_ips.push(ip);
                    }
                }
            }
            if let Some(bin1) = children.1.bin {
                for c in bin1.contacts {
                    let ip = c.ip;
                    if !new_bin.add_contact(c) {
                        dropped_ips.push(ip);
                    }
                }
            }
            self.bin = Some(new_bin);
            // eMule StartTimer(): new leaf registration + reset big timer
            self.event_order = *order_gen;
            *order_gen += 1;
            let now = chrono::Utc::now().timestamp();
            self.next_big_timer = now + BIG_TIMER_INITIAL_SECS;
            self.next_small_timer = now + (self.zone_index.chunk(3) as i64 % 3600);
            merge_count += 1;
        }

        merge_count
    }

    fn get_num_contacts(&self) -> u32 {
        if let Some(bin) = &self.bin {
            bin.len() as u32
        } else if let Some(children) = &self.children {
            children.0.get_num_contacts().saturating_add(children.1.get_num_contacts())
        } else {
            0
        }
    }

    // -- Tree traversal helpers --

    fn find_bin(&self, distance: &KadId) -> Option<&RoutingBin> {
        if let Some(bin) = &self.bin {
            return Some(bin);
        }
        if let Some(children) = &self.children {
            let side = distance.get_bit_number(self.level);
            if side == 0 {
                children.0.find_bin(distance)
            } else {
                children.1.find_bin(distance)
            }
        } else {
            tracing::error!("zone is neither leaf nor internal at level {}", self.level);
            None
        }
    }

    fn find_bin_mut(&mut self, distance: &KadId) -> Option<&mut RoutingBin> {
        if let Some(ref mut bin) = self.bin {
            return Some(bin);
        }
        if let Some(children) = &mut self.children {
            let side = distance.get_bit_number(self.level);
            if side == 0 {
                children.0.find_bin_mut(distance)
            } else {
                children.1.find_bin_mut(distance)
            }
        } else {
            tracing::error!("zone is neither leaf nor internal at level {}", self.level);
            None
        }
    }

    /// Attempt to add a new contact into the tree. Returns true if added.
    /// Handles splitting when the bin is full and the zone is allowed to split.
    fn add(
        &mut self,
        contact: KadContact,
        local_id: &KadId,
        global_ip_count: &HashMap<Ipv4Addr, u32>,
        global_subnet_count: &HashMap<u32, u32>,
        order_gen: &mut u64,
        split_dropped_ips: &mut Vec<Ipv4Addr>,
    ) -> AddResult {
        if !self.is_leaf() {
            if let Some(children) = &mut self.children {
                let distance = local_id.xor_distance(&contact.id);
                let side = distance.get_bit_number(self.level);
                return if side == 0 {
                    children.0.add(contact, local_id, global_ip_count, global_subnet_count, order_gen, split_dropped_ips)
                } else {
                    children.1.add(contact, local_id, global_ip_count, global_subnet_count, order_gen, split_dropped_ips)
                };
            }
        }

        let bin = match self.bin.as_mut() {
            Some(b) => b,
            None => return AddResult::Failed,
        };

        if bin.get_contact(&contact.id).is_some() {
            return AddResult::Existing;
        }

        if bin.remaining() > 0 {
            if check_global_limits(contact.ip, global_ip_count, global_subnet_count) {
                if bin.add_contact(contact) {
                    return AddResult::Added;
                }
            }
            return AddResult::Rejected;
        }

        if self.can_split() {
            self.split(local_id, order_gen, split_dropped_ips);
            if let Some(children) = &mut self.children {
                let distance = local_id.xor_distance(&contact.id);
                let side = distance.get_bit_number(self.level);
                return if side == 0 {
                    children.0.add(contact, local_id, global_ip_count, global_subnet_count, order_gen, split_dropped_ips)
                } else {
                    children.1.add(contact, local_id, global_ip_count, global_subnet_count, order_gen, split_dropped_ips)
                };
            }
        }

        AddResult::Rejected
    }

    /// eMule GetClosestTo -- recursive tree traversal, closer child first.
    fn get_closest_to(
        &self,
        max_type: u8,
        target: &KadId,
        distance: &KadId,
        max_required: usize,
        result: &mut BTreeMap<KadId, KadContact>,
    ) {
        if let Some(bin) = &self.bin {
            bin.get_closest_to(max_type, target, max_required, result);
            return;
        }

        if let Some(children) = &self.children {
            let closer = distance.get_bit_number(self.level);
            if closer == 0 {
                children.0.get_closest_to(max_type, target, distance, max_required, result);
                if result.len() < max_required {
                    children.1.get_closest_to(max_type, target, distance, max_required, result);
                }
            } else {
                children.1.get_closest_to(max_type, target, distance, max_required, result);
                if result.len() < max_required {
                    children.0.get_closest_to(max_type, target, distance, max_required, result);
                }
            }
        }
    }

    fn collect_all_contacts<'a>(&'a self, out: &mut Vec<&'a KadContact>) {
        if let Some(bin) = &self.bin {
            out.extend(bin.contacts.iter());
        } else if let Some(children) = &self.children {
            children.0.collect_all_contacts(out);
            children.1.collect_all_contacts(out);
        }
    }

    /// eMule TopDepth(iDepth) -- collect contacts from top 2^depth buckets.
    fn top_depth(&self, depth: usize, result: &mut Vec<KadContact>) {
        if self.is_leaf() {
            if let Some(bin) = &self.bin {
                for c in &bin.contacts {
                    result.push(c.clone());
                }
            }
        } else if depth == 0 {
            self.random_bin(result);
        } else if let Some(children) = &self.children {
            children.0.top_depth(depth - 1, result);
            children.1.top_depth(depth - 1, result);
        }
    }

    fn random_bin(&self, result: &mut Vec<KadContact>) {
        if self.is_leaf() {
            if let Some(bin) = &self.bin {
                for c in &bin.contacts {
                    result.push(c.clone());
                }
            }
        } else if let Some(children) = &self.children {
            let side = rand::Rng::gen_range(&mut rand::thread_rng(), 0..2);
            if side == 0 {
                children.0.random_bin(result);
            } else {
                children.1.random_bin(result);
            }
        }
    }

    /// eMule RandomLookup -- generate a random target ID in this zone's key space.
    fn random_lookup_target(&self, local_id: &KadId) -> KadId {
        let mut prefix = self.zone_index;
        prefix.shift_left(128 - self.level);
        let random = KadId::random_with_prefix(&prefix, self.level);
        random.xor_distance(local_id)
    }

    /// eMule `CRoutingZone::OnBigTimer` for a **leaf** only (caller iterates zones).
    fn try_big_timer_on_leaf(
        &mut self,
        now: i64,
        local_id: &KadId,
        last_kad_contact: Option<i64>,
        global_deadline: &mut i64,
    ) -> Option<KadId> {
        debug_assert!(self.is_leaf());
        if now < *global_deadline {
            return None;
        }

        let zone_time_ok = now >= self.next_big_timer
            || last_kad_contact
                .is_some_and(|t| now >= t + BIG_TIMER_DISCONNECT_BYPASS_SECS);
        if !zone_time_ok {
            return None;
        }

        let Some(bin) = self.bin.as_ref() else {
            return None;
        };
        let qualifies = self.zone_index.less_than_u32(KK as u32)
            || self.level < KBASE as u32
            || bin.remaining() as f64 >= K_BUCKET_SIZE as f64 * 0.8;
        if !qualifies {
            return None;
        }

        let target = self.random_lookup_target(local_id);
        self.next_big_timer = now + BIG_TIMER_INTERVAL_SECS;
        *global_deadline = now + BIG_TIMER_GLOBAL_GAP_SECS;
        Some(target)
    }

    /// eMule OnSmallTimer -- probe oldest contact, remove expired dead contacts.
    /// Contacts in `in_use_contacts` are not removed even if dead+expired (eMule InUse check).
    fn on_small_timer(
        &mut self,
        now: i64,
        to_probe: &mut Vec<KadContact>,
        ips_removed: &mut Vec<Ipv4Addr>,
        in_use_contacts: &HashMap<KadId, u32>,
    ) {
        if !self.is_leaf() {
            if let Some(children) = &mut self.children {
                children.0.on_small_timer(now, to_probe, ips_removed, in_use_contacts);
                children.1.on_small_timer(now, to_probe, ips_removed, in_use_contacts);
            }
            return;
        }

        let Some(bin) = self.bin.as_mut() else { return; };
        if bin.contacts.is_empty() {
            return;
        }
        if self.next_small_timer > now {
            return;
        }
        self.next_small_timer = now + SMALL_TIMER_INTERVAL_SECS;

        bin.contacts.retain_mut(|c| {
            if c.contact_type >= CONTACT_TYPE_DEAD && c.expires_at > 0 && now >= c.expires_at {
                if in_use_contacts.get(&c.id).copied().unwrap_or(0) > 0 {
                    return true;
                }
                ips_removed.push(c.ip);
                return false;
            }
            if c.expires_at == 0 {
                c.expires_at = now + CONTACT_DEFAULT_TTL_SECS;
            }
            true
        });

        if bin.contacts.is_empty() {
            return;
        }

        let Some(oldest) = bin.contacts.front() else { return; };
        if oldest.expires_at >= now || oldest.contact_type >= CONTACT_TYPE_DEAD {
            if let Some(c) = bin.contacts.pop_front() {
                bin.contacts.push_back(c);
            }
        } else {
            if let Some(front) = bin.contacts.front_mut() {
                front.checking_type();
            }
            if let Some(front) = bin.contacts.front() {
                to_probe.push(front.clone());
            }
        }
    }

    /// Remove stale/expired contacts from all bins. Returns IPs removed.
    fn remove_stale(&mut self, now: i64, max_age_secs: i64, ips_removed: &mut Vec<Ipv4Addr>) -> usize {
        if let Some(bin) = &mut self.bin {
            let before = bin.len();
            bin.contacts.retain(|c| {
                if now.saturating_sub(c.last_seen) >= max_age_secs || c.is_expired() {
                    ips_removed.push(c.ip);
                    false
                } else {
                    true
                }
            });
            before - bin.len()
        } else if let Some(children) = &mut self.children {
            children.0.remove_stale(now, max_age_secs, ips_removed)
                + children.1.remove_stale(now, max_age_secs, ips_removed)
        } else {
            0
        }
    }

    /// Remove dead+expired contacts from all bins. Returns IPs removed.
    /// Contacts referenced by active searches (`in_use_contacts`) are kept
    /// even if dead+expired, matching eMule's InUse protection.
    fn remove_dead(&mut self, now: i64, ips_removed: &mut Vec<Ipv4Addr>, in_use: &HashMap<KadId, u32>) -> usize {
        if let Some(bin) = &mut self.bin {
            let before = bin.len();
            bin.contacts.retain(|c| {
                if c.is_dead() && (c.expires_at == 0 || now >= c.expires_at) {
                    if in_use.get(&c.id).copied().unwrap_or(0) > 0 {
                        return true;
                    }
                    ips_removed.push(c.ip);
                    false
                } else {
                    true
                }
            });
            before - bin.len()
        } else if let Some(children) = &mut self.children {
            children.0.remove_dead(now, ips_removed, in_use)
                + children.1.remove_dead(now, ips_removed, in_use)
        } else {
            0
        }
    }

    fn set_all_contacts_verified(&mut self) {
        if let Some(bin) = &mut self.bin {
            for c in &mut bin.contacts {
                c.verified = true;
            }
        } else if let Some(children) = &mut self.children {
            children.0.set_all_contacts_verified();
            children.1.set_all_contacts_verified();
        }
    }

    /// Find the deepest leaf zone containing our own ID (always child[0] since
    /// our XOR distance to ourselves is zero). Returns its level.
    fn deepest_leaf_level(&self) -> u32 {
        if self.is_leaf() {
            return self.level;
        }
        if let Some(children) = &self.children {
            children.0.deepest_leaf_level()
        } else {
            self.level
        }
    }

    /// eMule EstimateCount helper: walk toward our own ID zone, stop 3 levels
    /// above the leaf, and return the contact count of that ancestor subtree.
    fn ancestor_contacts_at(&self, target_level: u32) -> u32 {
        if self.level >= target_level || self.is_leaf() {
            return self.get_num_contacts();
        }
        if let Some(children) = &self.children {
            children.0.ancestor_contacts_at(target_level)
        } else {
            self.get_num_contacts()
        }
    }

    /// Find contact by IP+port across all bins. Returns mutable ref for SetAlive.
    fn touch_contact_by_addr(&mut self, ip: Ipv4Addr, udp_port: u16) -> bool {
        if let Some(bin) = &mut self.bin {
            if let Some(pos) = bin.contacts.iter().position(|c| c.ip == ip && c.udp_port == udp_port) {
                let contact = &mut bin.contacts[pos];
                contact.update_type();
                let id = contact.id;
                bin.push_to_bottom(&id);
                return true;
            }
            false
        } else if let Some(children) = &mut self.children {
            children.0.touch_contact_by_addr(ip, udp_port)
                || children.1.touch_contact_by_addr(ip, udp_port)
        } else {
            false
        }
    }

}

#[derive(Debug, PartialEq)]
enum AddResult {
    Added,
    Existing,
    Rejected,
    Failed,
}

fn check_global_limits(
    ip: Ipv4Addr,
    global_ip_count: &HashMap<Ipv4Addr, u32>,
    global_subnet_count: &HashMap<u32, u32>,
) -> bool {
    let ip_count = global_ip_count.get(&ip).copied().unwrap_or(0);
    if ip_count >= MAX_CONTACTS_IP {
        return false;
    }
    let snet = subnet_key(ip);
    let is_lan = ip_filter::is_lan_ip(ip);
    if !is_lan {
        let snet_count = global_subnet_count.get(&snet).copied().unwrap_or(0);
        if snet_count >= MAX_CONTACTS_SUBNET {
            return false;
        }
    }
    true
}

fn collect_leaves_mut<'a>(z: &'a mut RoutingZone, out: &mut Vec<&'a mut RoutingZone>) {
    if z.is_leaf() {
        out.push(z);
        return;
    }
    if let Some(children) = &mut z.children {
        collect_leaves_mut(&mut children.0, out);
        collect_leaves_mut(&mut children.1, out);
    }
}

// ---------------------------------------------------------------------------
// RoutingTable -- public API wrapping the root RoutingZone
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct RoutingTable {
    root: RoutingZone,
    local_id: KadId,
    global_ip_count: HashMap<Ipv4Addr, u32>,
    global_subnet_count: HashMap<u32, u32>,
    block_private_ips: bool,
    /// Our external IP in host-order u32 (for UDPKey sender verification).
    external_ip: Option<u32>,
    /// eMule `CKademlia::m_tBigTimer` — next time a zone may successfully fire RandomLookup.
    big_timer_global_deadline: i64,
    /// Next `event_order` for new leaves (splits / consolidates), like eMule `AddEvent` sequence.
    next_zone_event_order: u64,
    /// eMule InUse counter: contacts referenced by active searches should not
    /// be deleted from the routing table even if they go dead.
    in_use_contacts: HashMap<KadId, u32>,
    /// Range-based IP filter shared with the network layer.
    range_ip_filter: Option<ip_filter::SharedIpFilter>,
}

impl RoutingTable {
    pub fn new(local_id: KadId, block_private_ips: bool) -> Self {
        let now = chrono::Utc::now().timestamp();
        RoutingTable {
            root: RoutingZone::new_leaf(0, KadId::from_u32(0), 0),
            local_id,
            global_ip_count: HashMap::new(),
            global_subnet_count: HashMap::new(),
            block_private_ips,
            external_ip: None,
            big_timer_global_deadline: now,
            next_zone_event_order: 1,
            in_use_contacts: HashMap::new(),
            range_ip_filter: None,
        }
    }

    /// eMule `Kademlia::Start`: `m_tBigTimer = tNow`.
    pub fn reset_big_timer_global(&mut self, now: i64) {
        self.big_timer_global_deadline = now;
    }

    /// Set our external/public IP for UDPKey sender verification.
    pub fn set_external_ip(&mut self, ip: Ipv4Addr) {
        self.external_ip = Some(u32::from(ip));
    }

    /// Set the range-based IP filter for blocking contacts on insert.
    pub fn set_ip_filter(&mut self, filter: ip_filter::SharedIpFilter) {
        self.range_ip_filter = Some(filter);
    }

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

    /// Insert or update a contact. Returns true if the contact was newly added.
    /// Matches eMule RoutingZone::Add / AddUnfiltered behavior.
    pub fn insert(&mut self, mut contact: KadContact) -> bool {
        if contact.kad_options & 0x01 != 0 {
            tracing::debug!("RT reject {}: UDP-firewalled contact", contact.id);
            return false;
        }
        if contact.id == KadId::zero() {
            tracing::debug!("RT reject: zero KadId");
            return false;
        }
        if contact.id == self.local_id {
            return false;
        }
        if !contact.is_kad2() {
            return false;
        }
        if !ip_filter::is_valid_contact_ip(contact.ip, self.block_private_ips) {
            return false;
        }
        if let Some(ref filter) = self.range_ip_filter {
            match filter.read() {
                Ok(snap) => {
                    if snap.is_blocked(contact.ip) {
                        tracing::debug!("RT reject {}: IP {} blocked by range filter", contact.id, contact.ip);
                        return false;
                    }
                }
                Err(_) => {
                    tracing::warn!("IP filter lock poisoned, rejecting contact {} as a precaution", contact.id);
                    return false;
                }
            }
        }
        if contact.udp_port == 53 && contact.version <= KADEMLIA_VERSION5_48A {
            tracing::debug!(
                "Rejecting DNS port contact ({}) version {}",
                contact.ip,
                kad_version_name(contact.version)
            );
            return false;
        }

        let distance = self.local_id.xor_distance(&contact.id);

        // Check if contact already exists -- handle update path
        {
            let Some(bin) = self.root.find_bin_mut(&distance) else { return false; };
            if let Some(existing) = bin.get_contact_mut(&contact.id) {
                // eMule UDPKey sender verification: if the existing contact has a
                // valid UDP key for our IP, the incoming contact must present the
                // same key. Prevents contact hijacking.
                if let Some(our_ip) = self.external_ip {
                    let existing_key_val = existing.udp_key
                        .map(|k| k.get_key_value(our_ip))
                        .unwrap_or(0);
                    if existing_key_val != 0 {
                        let incoming_key_val = contact.udp_key
                            .map(|k| k.get_key_value(our_ip))
                            .unwrap_or(0);
                        if existing_key_val != incoming_key_val {
                            tracing::debug!(
                                "RT reject update for {}: UDPKey mismatch (sender key empty: {})",
                                existing.id,
                                incoming_key_val == 0,
                            );
                            return false;
                        }
                    }
                }

                // eMule legacy Kad2 restriction: contacts with version >= 0.46c and
                // < 0.49a-beta that have already received a HELLO packet are limited
                // to timer-refresh-only updates (prevents value hijacking of legacy nodes).
                let is_legacy_kad2 = existing.version >= KADEMLIA_VERSION1_46C
                    && existing.version < KADEMLIA_VERSION6_49ABETA;
                if is_legacy_kad2 && existing.received_hello {
                    let same_values = existing.ip == contact.ip
                        && existing.tcp_port == contact.tcp_port
                        && existing.version == contact.version
                        && existing.udp_port == contact.udp_port;
                    if same_values {
                        existing.update_type();
                        let id = existing.id;
                        bin.push_to_bottom(&id);
                    }
                    return false;
                }

                let old_ip = existing.ip;
                if old_ip != contact.ip {
                    let ok = bin.change_contact_ip(
                        &contact.id,
                        contact.ip,
                        &self.global_ip_count,
                        &self.global_subnet_count,
                    );
                    if !ok {
                        return false;
                    }
                }
                if let Some(existing) = bin.get_contact_mut(&contact.id) {
                    existing.udp_port = contact.udp_port;
                    existing.tcp_port = contact.tcp_port;
                    if contact.version >= existing.version {
                        existing.version = contact.version;
                    }
                    if contact.verified && !existing.verified {
                        existing.verified = true;
                    }
                    if contact.udp_key.is_some() {
                        existing.udp_key = contact.udp_key.clone();
                    }
                    existing.kad_options = contact.kad_options;
                    if contact.received_hello {
                        existing.received_hello = true;
                    }
                    existing.update_type();
                    let new_ip = existing.ip;
                    let id = existing.id;
                    bin.push_to_bottom(&id);
                    if old_ip != new_ip {
                        self.track_ip_remove(old_ip);
                        self.track_ip_add(new_ip);
                    }
                }
                return false;
            }
        }

        let now = chrono::Utc::now().timestamp();
        if contact.created_at == 0 {
            contact.created_at = now;
        }
        if contact.expires_at == 0 {
            contact.expires_at = now + CONTACT_DEFAULT_TTL_SECS;
        }

        let contact_ip = contact.ip;
        let mut split_dropped = Vec::new();
        let result = self.root.add(
            contact,
            &self.local_id,
            &self.global_ip_count,
            &self.global_subnet_count,
            &mut self.next_zone_event_order,
            &mut split_dropped,
        );
        for ip in split_dropped {
            self.track_ip_remove(ip);
        }
        if result == AddResult::Added {
            self.track_ip_add(contact_ip);
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, id: &KadId) -> bool {
        let distance = self.local_id.xor_distance(id);
        let Some(bin) = self.root.find_bin_mut(&distance) else { return false; };
        if let Some(removed) = bin.remove_contact(id) {
            self.track_ip_remove(removed.ip);
            return true;
        }
        false
    }

    pub fn mark_verified(&mut self, id: &KadId) {
        let distance = self.local_id.xor_distance(id);
        let Some(bin) = self.root.find_bin_mut(&distance) else { return; };
        if let Some(contact) = bin.get_contact_mut(id) {
            contact.verified = true;
            contact.update_type();
        }
    }

    /// eMule GetClosestTo -- find contacts closest to target, filtered by type+verified.
    pub fn find_closest_verified_by_type(
        &self,
        target: &KadId,
        count: usize,
        max_type: u8,
    ) -> Vec<KadContact> {
        let distance = self.local_id.xor_distance(target);
        let mut result = BTreeMap::new();
        self.root.get_closest_to(max_type, target, &distance, count, &mut result);
        result.into_values().collect()
    }

    pub fn find_closest_verified(&self, target: &KadId, count: usize) -> Vec<KadContact> {
        self.find_closest_verified_by_type(target, count, CONTACT_TYPE_DEAD - 1)
    }

    pub fn find_closest_prefer_verified(&self, target: &KadId, count: usize) -> Vec<KadContact> {
        let mut verified = self.find_closest_verified(target, count);
        let t = *target;
        verified.sort_by(|a, b| {
            (a.is_udp_firewalled() as u8)
                .cmp(&(b.is_udp_firewalled() as u8))
                .then_with(|| t.xor_distance(&a.id).cmp(&t.xor_distance(&b.id)))
        });

        if verified.len() >= count {
            return verified;
        }

        let remaining = count - verified.len();
        let verified_ids: HashSet<KadId> = verified.iter().map(|c| c.id).collect();
        let all_contacts = self.all_contacts_vec();
        let mut unverified: Vec<(KadId, &KadContact)> = all_contacts
            .iter()
            .filter(|c| !c.verified && !verified_ids.contains(&c.id))
            .map(|c| (target.xor_distance(&c.id), *c))
            .collect();
        unverified.sort_by(|a, b| {
            a.1.is_udp_firewalled()
                .cmp(&b.1.is_udp_firewalled())
                .then_with(|| a.0.cmp(&b.0))
        });
        verified.extend(unverified.into_iter().take(remaining).map(|(_, c)| c.clone()));
        verified
    }

    pub fn find_closest(&self, target: &KadId, count: usize) -> Vec<KadContact> {
        let all_contacts = self.all_contacts_vec();
        let mut all: Vec<(KadId, &KadContact)> = all_contacts
            .iter()
            .map(|c| (target.xor_distance(&c.id), *c))
            .collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all.into_iter()
            .take(count)
            .map(|(_, c)| c.clone())
            .collect()
    }

    pub fn touch_contact_by_addr(&mut self, ip: Ipv4Addr, udp_port: u16) -> bool {
        self.root.touch_contact_by_addr(ip, udp_port)
    }

    fn all_contacts_vec(&self) -> Vec<&KadContact> {
        let mut out = Vec::new();
        self.root.collect_all_contacts(&mut out);
        out
    }

    pub fn all_contacts(&self) -> impl Iterator<Item = &KadContact> {
        let mut out = Vec::new();
        self.root.collect_all_contacts(&mut out);
        out.into_iter()
    }

    pub fn len(&self) -> usize {
        self.root.get_num_contacts() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.root = RoutingZone::new_leaf(0, KadId::from_u32(0), 0);
        self.big_timer_global_deadline = now;
        self.next_zone_event_order = 1;
        self.global_ip_count.clear();
        self.global_subnet_count.clear();
        self.in_use_contacts.clear();
    }

    pub fn get_contact(&self, id: &KadId) -> Option<&KadContact> {
        let distance = self.local_id.xor_distance(id);
        self.root.find_bin(&distance)?.get_contact(id)
    }

    pub fn get_contact_mut(&mut self, id: &KadId) -> Option<&mut KadContact> {
        let distance = self.local_id.xor_distance(id);
        self.root.find_bin_mut(&distance)?.get_contact_mut(id)
    }

    pub fn set_all_contacts_verified(&mut self) {
        self.root.set_all_contacts_verified();
    }

    /// eMule GetBootstrapContacts -- TopDepth(LOG_BASE_EXPONENT).
    pub fn export_bootstrap_contacts(&self, max_count: usize) -> Vec<KadContact> {
        let mut result = Vec::new();
        self.root.top_depth(LOG_BASE_EXPONENT, &mut result);
        result.retain(|c| !c.is_dead());
        result.truncate(max_count);
        result
    }

    pub fn is_acceptable_contact(&self, contact: &KadContact) -> bool {
        if !contact.is_kad2() {
            return false;
        }
        if let Some(existing) = self.get_contact(&contact.id) {
            if existing.verified
                && (existing.ip != contact.ip || existing.udp_port != contact.udp_port)
            {
                return false;
            }
            return true;
        }
        check_global_limits(contact.ip, &self.global_ip_count, &self.global_subnet_count)
    }

    pub fn remove_stale(&mut self, max_age_secs: i64) -> usize {
        let now = chrono::Utc::now().timestamp();
        let mut ips_removed = Vec::new();
        let removed = self.root.remove_stale(now, max_age_secs, &mut ips_removed);
        for ip in ips_removed {
            self.track_ip_remove(ip);
        }
        if removed > 0 {
            let mut consolidate_dropped = Vec::new();
            self.root.consolidate(&mut self.next_zone_event_order, &mut consolidate_dropped);
            for ip in consolidate_dropped {
                self.track_ip_remove(ip);
            }
        }
        removed
    }

    pub fn remove_dead_contacts(&mut self) -> usize {
        let now = chrono::Utc::now().timestamp();
        let mut ips_removed = Vec::new();
        let removed = self.root.remove_dead(now, &mut ips_removed, &self.in_use_contacts);
        for ip in ips_removed {
            self.track_ip_remove(ip);
        }
        if removed > 0 {
            let mut consolidate_dropped = Vec::new();
            self.root.consolidate(&mut self.next_zone_event_order, &mut consolidate_dropped);
            for ip in consolidate_dropped {
                self.track_ip_remove(ip);
            }
        }
        removed
    }

    /// eMule `CKademlia::Process` big-timer section: at most one `RandomLookup` (FindNode)
    /// per call. Leaf iteration order follows `event_order` (eMule `m_mapEvents` pointer order).
    pub fn try_fire_big_timer(&mut self, now: i64, last_kad_contact: Option<i64>) -> Option<KadId> {
        let mut deadline = self.big_timer_global_deadline;
        let local_id = self.local_id;
        let mut fired: Option<KadId> = None;
        {
            let mut leaves: Vec<&mut RoutingZone> = Vec::new();
            collect_leaves_mut(&mut self.root, &mut leaves);
            leaves.sort_by_key(|z| z.event_order);
            for leaf in leaves {
                if let Some(t) =
                    leaf.try_big_timer_on_leaf(now, &local_id, last_kad_contact, &mut deadline)
                {
                    fired = Some(t);
                    break;
                }
            }
        }
        self.big_timer_global_deadline = deadline;
        fired
    }

    /// eMule OnSmallTimer -- returns contacts to probe with HELLO_REQ.
    pub fn get_contacts_to_probe(&mut self) -> Vec<KadContact> {
        let now = chrono::Utc::now().timestamp();
        let mut to_probe = Vec::new();
        let mut ips_removed = Vec::new();
        let in_use = self.in_use_contacts.clone();
        self.root.on_small_timer(now, &mut to_probe, &mut ips_removed, &in_use);
        for ip in ips_removed {
            self.track_ip_remove(ip);
        }
        to_probe
    }

    /// eMule Consolidate -- merge sparse sibling leaf zones.
    pub fn consolidate(&mut self) -> u32 {
        let mut consolidate_dropped = Vec::new();
        let count = self.root.consolidate(&mut self.next_zone_event_order, &mut consolidate_dropped);
        for ip in consolidate_dropped {
            self.track_ip_remove(ip);
        }
        count
    }

    // -- InUse tracking (eMule CContact::IncUse / DecUse / InUse) --

    /// Mark contact IDs as in-use by an active search. In-use contacts are
    /// not deleted from the routing table even if they go dead+expired.
    pub fn mark_contacts_in_use(&mut self, ids: &[KadId]) {
        for id in ids {
            *self.in_use_contacts.entry(*id).or_insert(0) += 1;
        }
    }

    /// Release in-use marks when a search completes.
    pub fn release_contacts_in_use(&mut self, ids: &[KadId]) {
        for id in ids {
            if let Some(count) = self.in_use_contacts.get_mut(id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.in_use_contacts.remove(id);
                }
            }
        }
    }

    // -- EstimateCount (eMule CRoutingZone::EstimateCount) --

    /// Estimate total number of Kademlia nodes in the network.
    /// Matches eMule CRoutingZone::EstimateCount: find the deepest leaf zone
    /// containing our own ID, go up 3 levels, measure density, and extrapolate.
    pub fn estimate_count(&self) -> u32 {
        let leaf_level = self.root.deepest_leaf_level();

        if leaf_level < KBASE as u32 {
            return (2.0f64.powi(leaf_level as i32) * K_BUCKET_SIZE as f64) as u32;
        }

        let ancestor_level = leaf_level.saturating_sub(3);
        let ancestor_contacts = self.root.ancestor_contacts_at(ancestor_level);

        let modify = ancestor_contacts as f64 / (K_BUCKET_SIZE as f64 * 2.0);
        (2.0f64.powi(leaf_level as i32 - 2)
            * K_BUCKET_SIZE as f64
            * modify) as u32
    }
}
