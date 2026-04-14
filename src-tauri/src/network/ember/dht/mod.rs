pub mod bootstrap;
pub mod messages;
pub mod publish;
pub mod routing;
pub mod search;
pub mod store;

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

pub const EMBER_DHT_VERSION: u8 = 1;
pub const K_BUCKET_SIZE: usize = 20;
pub const ALPHA: usize = 5;
pub const ID_BITS: usize = 128;
pub const MAX_CONTACTS_PER_RESPONSE: usize = 20;

/// Republish intervals
pub const KEYWORD_REPUBLISH_SECS: u64 = 12 * 3600;
pub const SOURCE_REPUBLISH_SECS: u64 = 2 * 3600;

/// Contact liveness
pub const CONTACT_TIMEOUT_SECS: i64 = 600;
pub const MAX_FAILED_QUERIES: u8 = 3;

/// Subnet diversity limits
pub const MAX_PER_SUBNET_PER_BUCKET: usize = 3;
pub const MAX_PER_SUBNET_GLOBAL: usize = 20;

/// 16-byte node ID derived from BLAKE3(Ed25519 public key).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmberNodeId(pub [u8; 16]);

impl EmberNodeId {
    pub fn distance(&self, other: &EmberNodeId) -> EmberNodeId {
        let mut d = [0u8; 16];
        for i in 0..16 {
            d[i] = self.0[i] ^ other.0[i];
        }
        EmberNodeId(d)
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

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
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
