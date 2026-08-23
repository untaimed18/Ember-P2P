pub mod bootstrap;
pub mod engine;
pub mod messages;
pub mod observed;
pub mod protection;
pub mod publish;
pub mod routing;
pub mod scale;
pub mod search;
pub mod store;

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Wire version this build speaks.
///
/// Bumped to 3 for two changes that both alter the shape of existing frames, so
/// neither could ride the additive path earlier versions used:
///
/// * Contact lists no longer carry `node_id`. It was always redundant — the ID
///   *is* `BLAKE3(ed25519_pub)[..16]`, and every decoder re-derived and checked
///   it rather than trusting the wire — so it cost 16 of 87 bytes per contact to
///   restate something the receiver had to compute anyway. At 71 bytes a
///   `FOUND_NODE` carries 17 contacts instead of 14.
/// * `FIND_VALUE` carries a `start_position` and `FOUND_VALUE` answers with the
///   position to resume from plus the live total. A datagram fits roughly five
///   keyword records, so before this a searcher had no way to reach past the
///   first window of a popular key except by re-asking and hoping the responder
///   had rotated it.
///
/// v2 read the contact list at a fixed stride and the `FOUND_VALUE` header at a
/// fixed offset, so a v2 peer handed a v3 frame does not fail cleanly on its
/// own — the version byte is what makes it a refusal instead of a misparse.
pub const EMBER_DHT_VERSION: u8 = 3;

/// Oldest wire version this build can still parse.
///
/// Equal to [`EMBER_DHT_VERSION`] while no released version is compatible with
/// another. A future change that only *adds* to the format can lower this
/// instead of raising both, which is the whole point of keeping them separate:
/// the decoder then accepts the range rather than a single value.
pub const EMBER_DHT_MIN_VERSION: u8 = 3;
pub const K_BUCKET_SIZE: usize = 20;
pub const ALPHA: usize = 5;
pub const ID_BITS: usize = 128;
pub const MAX_CONTACTS_PER_RESPONSE: usize = 20;

/// Contact liveness
pub const CONTACT_TIMEOUT_SECS: i64 = 600;
pub const MAX_FAILED_QUERIES: u8 = 3;

// The subnet diversity limits, per bucket and global, both scale with table
// occupancy — see `scale::NetworkScale::max_contacts_per_subnet_per_bucket` and
// its global sibling. The per-bucket one used to be a fixed 3 here, which
// silently cancelled the wider allowance the small-network tiers grant.

/// 16-byte node ID derived from BLAKE3(Ed25519 public key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmberNodeId(pub [u8; 16]);

impl EmberNodeId {
    pub fn distance(&self, other: &EmberNodeId) -> EmberNodeId {
        EmberNodeId(crate::network::kad::dht_common::xor16(&self.0, &other.0))
    }

    /// Return the index of the highest set bit (0..127), or None if distance is zero.
    pub fn leading_bit_index(&self) -> Option<usize> {
        for i in 0..16 {
            if self.0[i] != 0 {
                let leading = self.0[i].leading_zeros() as usize;
                return Some(127 - (i * 8 + leading));
            }
        }
        None
    }

    /// Return the bucket index for the distance between self and other (0..127).
    pub fn bucket_index(&self, other: &EmberNodeId) -> Option<usize> {
        self.distance(other).leading_bit_index()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for EmberNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmberNodeId({}…)", &self.to_hex()[..8])
    }
}

impl std::fmt::Display for EmberNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}…", &self.to_hex()[..8])
    }
}

/// A contact in the Ember DHT routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmberContact {
    pub node_id: EmberNodeId,
    pub addr: SocketAddr,
    /// X25519 static public key for Noise transport.
    pub noise_pub: [u8; 32],
    /// Ed25519 public key for signature verification.
    pub ed25519_pub: [u8; 32],
    /// Last time this contact responded successfully (unix timestamp).
    pub last_seen: i64,
    /// Number of consecutive unanswered queries.
    #[serde(default)]
    pub failed_queries: u8,
}

impl EmberContact {
    /// Whether we have actually heard from this contact, as opposed to only
    /// having been told about it.
    ///
    /// A direct signed frame sets `last_seen`; gossip from `FOUND_NODE` /
    /// `PEER_LIST` and entries read back from disk arrive with `last_seen == 0`
    /// until they answer us. Contacts we have never reached are worth keeping
    /// as leads, but they should not be preferred over proven ones when
    /// seeding a lookup, answering a peer, or deciding what to persist.
    pub fn is_verified(&self) -> bool {
        self.last_seen > 0
    }

    /// Whether we can send Ember UDP to this contact on the shared IPv4 socket.
    pub fn is_dialable(&self) -> bool {
        self.addr.port() != 0 && self.addr.ip().is_ipv4()
    }

    /// Subnet key (first 3 octets for IPv4, first 48 bits for IPv6).
    pub fn subnet_key(&self) -> u64 {
        match self.addr.ip() {
            std::net::IpAddr::V4(ip) => {
                let o = ip.octets();
                u64::from(u32::from_be_bytes([o[0], o[1], o[2], 0]))
            }
            std::net::IpAddr::V6(ip) => {
                let s = ip.segments();
                ((s[0] as u64) << 32) | ((s[1] as u64) << 16) | (s[2] as u64)
            }
        }
    }
}
