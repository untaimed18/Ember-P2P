//! Protocol-independent glue shared by the two Kademlia stacks.
//!
//! [`crate::network::kad`] is a port of eMule's binary zone tree;
//! [`crate::network::ember::dht`] is a flat bucket array with a replacement
//! cache. The routing algorithms are genuinely different and are deliberately
//! left that way — merging them would be a rewrite, not a de-duplication.
//!
//! What *was* duplicated is the glue that has nothing to do with either shape:
//! the XOR fold, the IP-filter admission and eviction policy, and the age
//! comparison behind staleness. A fix to any of those previously had to be made
//! and tested twice, and the two copies could drift apart silently.
//!
//! # Why this lives under `kad`
//!
//! `network/mod.rs` is the only file a `network::dht_common` could be declared
//! in, and it is not ours to edit. `kad` is the right second choice regardless:
//! the [`ip_filter`](super::ip_filter) primitives this module is built on
//! already live here, and `ember::dht` already depends on them.

use std::net::Ipv4Addr;

use super::ip_filter;

// ---------------------------------------------------------------------------
// XOR metric
// ---------------------------------------------------------------------------

/// The XOR distance between two 128-bit node IDs.
///
/// This is the whole of the distance machinery the two stacks share: sixteen
/// byte-wise XORs, position for position.
///
/// Nothing built *on top* of it can be shared, because the two ID types do not
/// agree on what a bit position means:
///
/// * `KadId` stores bytes in eMule's `CUInt128` wire order — four `u32` chunks,
///   each little-endian — so its bit 0 (`get_bit_number(0)`, the bit the zone
///   tree descends on) is the MSB of `self.0[3]`, and its `Ord` compares chunk
///   by chunk through `u32::from_le_bytes`.
/// * `EmberNodeId` stores plain MSB-first bytes, so its bit position 0 is the
///   MSB of `self.0[0]` and it orders byte-wise lexicographically.
///
/// The two therefore derive a different bucket index *and* a different total
/// order from the same sixteen bytes, and both conventions are load-bearing:
/// KAD's is what makes it agree with eMule on the wire (pinned by the tests in
/// [`super::types`]), Ember's is what its own `leading_bit_index` assumes.
/// A shared bit-index or ordering helper would silently reorder one of them.
pub fn xor16(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut d = [0u8; 16];
    for i in 0..16 {
        d[i] = a[i] ^ b[i];
    }
    d
}

// ---------------------------------------------------------------------------
// IP admission / eviction policy
// ---------------------------------------------------------------------------

/// Why the gate refused an address, so a caller can log what its own stack
/// always logged. Both stacks reduce this to "may it enter the table"; only
/// KAD distinguishes the reasons in its tracing output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    /// Unroutable space, or LAN / CGNAT while the private block is on.
    BlockedByPolicy,
    /// The user's `ipfilter.dat` covers this address (or the fail-closed
    /// startup window does, for anything that is not a Kad bootstrap seed).
    BlockedByRanges,
    /// The shared snapshot could not be read.
    FilterUnreadable,
}

/// The private/LAN policy and the user's range filter, and the two questions
/// both routing tables ask of them.
///
/// Kept as one object because the two questions are not the same question and
/// must not be allowed to converge: see [`Self::admits`] versus
/// [`Self::is_definitely_blocked`].
#[derive(Debug)]
pub struct IpAdmissionGate {
    /// Whether LAN / CGNAT addresses are refused. A user preference that can
    /// change at runtime, so both tables honour the same setting.
    block_private_ips: bool,
    /// The user's range filter (`ipfilter.dat`), shared with the network layer.
    range_filter: Option<ip_filter::SharedIpFilter>,
}

impl IpAdmissionGate {
    pub fn new(block_private_ips: bool) -> Self {
        IpAdmissionGate {
            block_private_ips,
            range_filter: None,
        }
    }

    /// Share the user's range filter so blocked addresses are refused on
    /// admission.
    pub fn set_range_filter(&mut self, filter: ip_filter::SharedIpFilter) {
        self.range_filter = Some(filter);
    }

    /// Detach the range filter, handing it back for [`Self::restore_range_filter`].
    ///
    /// For a bulk restore from disk, which must not be judged by a filter that
    /// is still fail-closed: at startup every non-seed address reads as blocked
    /// until `ipfilter.dat` is applied, which would refuse an entire saved
    /// contact file. The private/bogus rules still apply while it is detached,
    /// and blocked ranges are dropped afterwards by
    /// [`evict_blocked_contacts`] once the list is ready.
    pub fn take_range_filter(&mut self) -> Option<ip_filter::SharedIpFilter> {
        self.range_filter.take()
    }

    /// Put back a filter taken by [`Self::take_range_filter`].
    pub fn restore_range_filter(&mut self, filter: Option<ip_filter::SharedIpFilter>) {
        self.range_filter = filter;
    }

    /// Hot-update the private/LAN admission flag.
    ///
    /// Returns whether this call *enabled* the block, i.e. whether the caller
    /// must now re-apply the policy to contacts already in its table. Only the
    /// off→on edge needs that sweep: turning the block off never invalidates a
    /// contact that was already admissible.
    pub fn set_block_private_ips(&mut self, block_private: bool) -> bool {
        let enabling = block_private && !self.block_private_ips;
        self.block_private_ips = block_private;
        enabling
    }

    /// Whether a contact at `ip` may enter a routing table.
    ///
    /// Without this a table accepted anything a peer gossiped, so it could be
    /// seeded with unroutable or user-blocked addresses that we would then
    /// dial, hand to other peers as if they were real, and persist. It also
    /// meant the user's IP filter applied to inbound traffic but not to
    /// anything we chose to contact ourselves.
    ///
    /// Fails closed on an unreadable snapshot: refusing one newcomer is the
    /// safe reading of "blocked unless known otherwise".
    pub fn admits(&self, ip: Ipv4Addr) -> Admission {
        if !ip_filter::is_valid_contact_ip(ip, self.block_private_ips) {
            return Admission::BlockedByPolicy;
        }
        match &self.range_filter {
            Some(filter) => match filter.read() {
                Ok(snap) => {
                    if snap.is_blocked_for_kad(ip) {
                        Admission::BlockedByRanges
                    } else {
                        Admission::Allowed
                    }
                }
                Err(_) => Admission::FilterUnreadable,
            },
            None => Admission::Allowed,
        }
    }

    /// Whether an address is *known* to be disallowed, as opposed to merely not
    /// confirmable.
    ///
    /// Admission and eviction want opposite answers when the filter cannot be
    /// consulted. Refusing an unconfirmable newcomer costs one contact;
    /// evicting on the same answer would empty the entire table the first time
    /// the shared lock is poisoned, and the insert path already fails closed
    /// for new contacts.
    ///
    /// The same distinction applies during the startup fail-closed window:
    /// [`ip_filter::IpFilterSnapshot::is_blocked_for_kad`] treats every
    /// non-seed as blocked until `ipfilter.dat` is applied, and Ember contacts
    /// are never Kad bootstrap seeds, so evicting against that answer would
    /// wipe the whole KAD routing table and `nodes_ember.dat` on every launch.
    /// Hence the plain [`ip_filter::IpFilterSnapshot::is_blocked`] here, gated
    /// on the ranges having actually landed.
    pub fn is_definitely_blocked(&self, ip: Ipv4Addr) -> bool {
        if !ip_filter::is_valid_contact_ip(ip, self.block_private_ips) {
            return true;
        }
        match &self.range_filter {
            Some(filter) => match filter.read() {
                Ok(snap) => {
                    if snap.enabled && !snap.ranges_ready {
                        return false;
                    }
                    snap.is_blocked(ip)
                }
                // Unreadable: keep what we have.
                Err(_) => false,
            },
            None => false,
        }
    }
}

/// The contact storage a policy sweep needs, so the sweep itself lives in one
/// place while each stack keeps its own layout — a zone tree on one side, a flat
/// bucket array on the other.
pub trait PolicyEvictable {
    /// How this stack names a contact for removal.
    type ContactId: Copy;

    /// The gate holding the policy to apply.
    fn ip_gate(&self) -> &IpAdmissionGate;

    /// Every contact currently occupying a slot, with the address the gate
    /// should judge.
    ///
    /// `None` for an address the gate cannot evaluate at all: Ember contacts
    /// carry a [`std::net::SocketAddr`], so an undialable port or a v6 address
    /// is possible in principle and counts as blocked, which is what its own
    /// predicate already did. KAD contacts are always v4 and always answer
    /// `Some`.
    fn resident_contacts(&self) -> Vec<(Self::ContactId, Option<Ipv4Addr>)>;

    /// Remove a contact the policy no longer admits. `true` if it was there.
    fn evict_contact(&mut self, id: &Self::ContactId) -> bool;
}

/// Drop every resident contact the gate *knows* is disallowed, returning how
/// many went. Run after the filter is reloaded or the private-IP setting is
/// turned on.
///
/// Collect first, then remove: both stacks' removal paths take `&mut self` and
/// re-derive where a contact lives (a leaf scan, a bucket index), so the doomed
/// set has to be fixed before the first eviction can perturb the layout.
pub fn evict_blocked_contacts<T: PolicyEvictable>(table: &mut T) -> usize {
    let doomed: Vec<T::ContactId> = {
        let gate = table.ip_gate();
        table
            .resident_contacts()
            .into_iter()
            .filter(|(_, ip)| match ip {
                Some(ip) => gate.is_definitely_blocked(*ip),
                None => true,
            })
            .map(|(id, _)| id)
            .collect()
    };
    let mut removed = 0;
    for id in &doomed {
        if table.evict_contact(id) {
            removed += 1;
        }
    }
    removed
}

// ---------------------------------------------------------------------------
// Staleness
// ---------------------------------------------------------------------------

/// Whether a contact last heard from at `last_seen` has been quiet for at least
/// `max_age_secs` as of `now`.
///
/// The boundary is inclusive, matching the TTL-boundary convention used by
/// `KadContact::is_expired` and `StoredEntry::is_expired`: a contact is stale
/// starting exactly at its deadline instead of one second late.
/// `saturating_sub` keeps a `last_seen` in the future — a clock step, or a
/// timestamp restored from a session on a machine whose clock has since moved
/// back — reading as no age at all rather than wrapping to an enormous one and
/// purging a contact that is perfectly fresh.
///
/// Only the comparison is shared. *Which* contacts are eligible to age out, and
/// what else can retire one, differ between the two stacks; see the notes on
/// each `remove_stale`.
pub fn is_stale(now: i64, last_seen: i64, max_age_secs: i64) -> bool {
    now.saturating_sub(last_seen) >= max_age_secs
}
