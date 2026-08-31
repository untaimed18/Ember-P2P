//! Network-size-adaptive limits for the Ember DHT.
//!
//! Every anti-abuse limit in the DHT has the same tension: strict values keep
//! one host from occupying the table or the store, but on a small network a
//! legitimate peer looks a lot like an attacker. Several real peers behind one
//! NAT, or a handful of instances during testing, are indistinguishable from a
//! Sybil cluster if you only count addresses.
//!
//! Rather than pick one compromise value, limits are derived from how much of
//! the network we can actually see — meaning contacts that have answered us,
//! not every entry in the routing table. Gossip is cheap to send and proves
//! nothing, so counting leads here would let anyone who can talk at us drive
//! the limits to their strict tier while we had reached almost nobody.
//!
//! While we have reached nearly no one the limits are permissive, because
//! refusing a contact then can cost us the only path into the network. As the
//! count of proven contacts grows, they tighten toward values at or below what
//! eMule KAD enforces, because by then there is enough diversity that refusing
//! a duplicate costs nothing.
//!
//! Tightening is always safe: it only refuses *new* admissions, never evicts
//! entries admitted under an earlier, looser limit.

use super::K_BUCKET_SIZE;

/// Below this many *verified* contacts we are still bootstrapping, and
/// refusing a peer risks having no route into the network at all.
const BOOTSTRAP_CONTACTS: usize = K_BUCKET_SIZE / 2;
/// Above this many verified contacts we have enough proven diversity that
/// strict limits cost nothing.
const ESTABLISHED_CONTACTS: usize = K_BUCKET_SIZE * 4;

/// How permissive the DHT's abuse limits currently are.
///
/// Ordered by strictness, so `Established > Small > Bootstrap`. Variant order
/// is load-bearing: [`super::routing::RoutingTable::enforce_scale_quotas`]
/// compares tiers to decide whether the limits have tightened since it last
/// pruned the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkScale {
    /// Nearly empty table: accept almost anything so we can get connected.
    Bootstrap,
    /// Enough peers to be useful, not enough to be picky.
    Small,
    /// Healthy table; enforce the strict limits.
    Established,
}

impl NetworkScale {
    /// Pick a tier from the number of contacts that have answered us. See
    /// [`super::routing::RoutingTable::scale`] for why leads do not count.
    pub fn from_contacts(verified: usize) -> Self {
        if verified < BOOTSTRAP_CONTACTS {
            NetworkScale::Bootstrap
        } else if verified < ESTABLISHED_CONTACTS {
            NetworkScale::Small
        } else {
            NetworkScale::Established
        }
    }

    /// Routing-table contacts allowed from a single IP address.
    ///
    /// eMule KAD allows exactly one. Ember settles at two rather than one
    /// because two genuine instances behind one NAT is an ordinary situation
    /// and, unlike KAD, Ember can tell them apart cryptographically — their
    /// node IDs are bound to distinct keypairs.
    pub fn max_contacts_per_ip(&self) -> usize {
        match self {
            NetworkScale::Bootstrap => 8,
            NetworkScale::Small => 4,
            NetworkScale::Established => 2,
        }
    }

    /// Routing-table contacts allowed from a single /24 across all buckets.
    /// Converges on KAD's value of 10.
    pub fn max_contacts_per_subnet_global(&self) -> usize {
        match self {
            NetworkScale::Bootstrap => 20,
            NetworkScale::Small => 16,
            NetworkScale::Established => 10,
        }
    }

    /// The same limit within one bucket. Converges on 3, which is what this was
    /// fixed at before.
    ///
    /// Scaling it matters more than the number suggests, because on a small
    /// network this is the limit that actually binds — and while it was fixed it
    /// quietly cancelled the generosity of the tier above. Node IDs are uniform,
    /// so bucket occupancy is geometric: about half of all contacts fall in the
    /// last bucket and a quarter in the one before. Four or five peers sharing a
    /// /24 — a handful of instances on one ISP, or several behind one CGNAT, which
    /// is exactly what a young network looks like — could never reach the
    /// eight-per-IP Bootstrap allowance, because half of them collided in one
    /// bucket and were pushed to the replacement cache.
    /// The curve is deliberately shallow. `Established` needs 80 verified
    /// contacts, so a node on a young network sits in `Small` more or less
    /// permanently and *that* is the value which decides eclipse resistance in
    /// practice, not the 3 at the far end. Tightening also never evicts contacts
    /// admitted under a looser tier, so whatever a cold start allows, an adversary
    /// present at that moment keeps for the life of the process — in the bucket
    /// that matters most, since geometric occupancy puts half of everyone there.
    pub fn max_contacts_per_subnet_per_bucket(&self) -> usize {
        match self {
            NetworkScale::Bootstrap => 5,
            NetworkScale::Small => 4,
            NetworkScale::Established => 3,
        }
    }

    /// Source records allowed under one key from a single IP, mirroring KAD's
    /// `MAX_SOURCES_PER_IP`.
    pub fn max_sources_per_ip(&self) -> usize {
        match self {
            NetworkScale::Bootstrap => 8,
            NetworkScale::Small => 5,
            NetworkScale::Established => 3,
        }
    }

    /// Records accepted from one peer per minute across all STORE traffic.
    ///
    /// Counted in records rather than frames, because that is what the work
    /// scales with: every record costs two signature verifications whether it
    /// arrives alone or batched. Charging per frame let one densely packed
    /// batch buy many times the admitted work of a well-behaved publisher.
    /// The floor stays comfortably above what our own publisher offers a
    /// single peer in one tick, so a large library is never throttled by it.
    pub fn max_stores_per_minute(&self) -> u32 {
        match self {
            NetworkScale::Bootstrap => 300,
            NetworkScale::Small => 200,
            NetworkScale::Established => 120,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_tighten_as_the_table_fills() {
        let boot = NetworkScale::from_contacts(0);
        let small = NetworkScale::from_contacts(K_BUCKET_SIZE);
        let full = NetworkScale::from_contacts(K_BUCKET_SIZE * 10);

        assert_eq!(boot, NetworkScale::Bootstrap);
        assert_eq!(small, NetworkScale::Small);
        assert_eq!(full, NetworkScale::Established);

        // Every limit is monotonically non-increasing as the network grows,
        // so growth can never loosen an abuse limit.
        for pair in [(boot, small), (small, full)] {
            let (looser, tighter) = pair;
            assert!(looser.max_contacts_per_ip() >= tighter.max_contacts_per_ip());
            assert!(
                looser.max_contacts_per_subnet_global() >= tighter.max_contacts_per_subnet_global()
            );
            assert!(
                looser.max_contacts_per_subnet_per_bucket()
                    >= tighter.max_contacts_per_subnet_per_bucket()
            );
            assert!(looser.max_sources_per_ip() >= tighter.max_sources_per_ip());
            assert!(looser.max_stores_per_minute() >= tighter.max_stores_per_minute());
        }
    }

    #[test]
    fn the_established_limits_match_or_beat_kad() {
        let full = NetworkScale::from_contacts(usize::MAX);
        // KAD: MAX_CONTACTS_SUBNET = 10, MAX_SOURCES_PER_IP = 3.
        assert_eq!(full.max_contacts_per_subnet_global(), 10);
        assert_eq!(full.max_sources_per_ip(), 3);
        // KAD allows 1 contact per IP; we allow 2 deliberately, because a
        // cryptographic identity makes a second instance behind one NAT
        // distinguishable from a spoof.
        assert_eq!(full.max_contacts_per_ip(), 2);
    }

    #[test]
    fn a_bootstrapping_node_is_not_locked_out_by_its_own_limits() {
        // The whole point of the Bootstrap tier: several peers sharing one
        // address must still be admissible when we know almost nobody.
        let boot = NetworkScale::from_contacts(1);
        assert!(boot.max_contacts_per_ip() >= 4);
        assert!(boot.max_contacts_per_subnet_global() >= K_BUCKET_SIZE);
        // The per-bucket limit has to move with the others or it becomes the one
        // that binds and the tier buys nothing. Node IDs are uniform, so about half
        // of everyone we meet lands in the same bucket — a per-IP allowance of
        // eight is unreachable if only three of them may share a bucket.
        assert!(
            boot.max_contacts_per_subnet_per_bucket()
                > NetworkScale::Established.max_contacts_per_subnet_per_bucket(),
            "the per-bucket subnet cap must not cancel the per-IP allowance"
        );
        // But not so loose that a cold-start adversary can hold a large share of
        // one bucket for the life of the process — tightening never evicts what an
        // earlier tier admitted.
        assert!(
            boot.max_contacts_per_subnet_per_bucket() <= K_BUCKET_SIZE / 4,
            "a single /24 must not be able to hold a quarter of a bucket"
        );
    }
}
