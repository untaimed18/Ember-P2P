use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{debug, info, warn};

use super::{EmberContact, EmberNodeId};

const NODES_EMBER_MAGIC: u32 = 0x454D_4233; // "EMB3" in LE
const NODES_EMBER_VERSION: u8 = 1;
const BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_BOOTSTRAP_NODES: usize = 200;

/// Persist the routing table to `nodes_ember.dat`.
///
/// Format:
///   magic(4) + version(1) + count(u16 LE) +
///   for each contact:
///     node_id(16) + addr_type(1) + ip(4 or 16) + port(2 BE) +
///     noise_pub(32) + ed25519_pub(32) + last_seen(i64 LE)
pub fn save_nodes(path: &Path, contacts: &[EmberContact]) -> anyhow::Result<()> {
    // Build the full file in memory first, then commit via
    // `atomic_write`. The previous implementation did
    // `File::create -> write -> drop -> rename` without `sync_all`,
    // which on a Windows or pre-fsync Linux crash can leave the
    // renamed file with zero / partial bytes. `atomic_write` does
    // tmp + write + sync + rename + dir-sync (Unix), matching what
    // `nodes.dat` and `known.met` use elsewhere.
    let mut buf: Vec<u8> = Vec::with_capacity(8 + contacts.len() * 100);
    buf.write_u32::<LittleEndian>(NODES_EMBER_MAGIC)?;
    buf.write_u8(NODES_EMBER_VERSION)?;
    let count = contacts.len().min(u16::MAX as usize);
    buf.write_u16::<LittleEndian>(count as u16)?;

    for contact in contacts.iter().take(count) {
        buf.write_all(&contact.node_id.0)?;

        match contact.addr.ip() {
            std::net::IpAddr::V4(ip) => {
                buf.write_u8(4)?;
                buf.write_all(&ip.octets())?;
            }
            std::net::IpAddr::V6(ip) => {
                buf.write_u8(6)?;
                buf.write_all(&ip.octets())?;
            }
        }
        buf.write_u16::<byteorder::BigEndian>(contact.addr.port())?;
        buf.write_all(&contact.noise_pub)?;
        buf.write_all(&contact.ed25519_pub)?;
        buf.write_i64::<LittleEndian>(contact.last_seen)?;
    }

    crate::security::atomic_write(path, &buf, false)?;
    info!("Saved {} Ember DHT contacts to {}", count, path.display());
    Ok(())
}

/// Load contacts from `nodes_ember.dat`.
pub fn load_nodes(path: &Path) -> anyhow::Result<Vec<EmberContact>> {
    let data = std::fs::read(path)?;
    if data.len() < 7 {
        anyhow::bail!("nodes_ember.dat too small");
    }

    let mut cursor = std::io::Cursor::new(&data);
    let magic = cursor.read_u32::<LittleEndian>()?;
    if magic != NODES_EMBER_MAGIC {
        anyhow::bail!("Invalid nodes_ember.dat magic: 0x{magic:08x}");
    }

    let version = cursor.read_u8()?;
    if version > NODES_EMBER_VERSION {
        anyhow::bail!("Unsupported nodes_ember.dat version {version}");
    }

    let count = cursor.read_u16::<LittleEndian>()? as usize;
    let mut contacts = Vec::with_capacity(count);

    for _ in 0..count {
        let mut node_id = [0u8; 16];
        if cursor.read_exact(&mut node_id).is_err() {
            break;
        }

        let addr_type = match cursor.read_u8() {
            Ok(t) => t,
            Err(_) => break,
        };
        let ip = match addr_type {
            4 => {
                let mut octets = [0u8; 4];
                if cursor.read_exact(&mut octets).is_err() {
                    break;
                }
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
            }
            6 => {
                let mut octets = [0u8; 16];
                if cursor.read_exact(&mut octets).is_err() {
                    break;
                }
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            _ => {
                warn!("Unknown address type {addr_type} in nodes_ember.dat, stopping");
                break;
            }
        };

        let port = match cursor.read_u16::<byteorder::BigEndian>() {
            Ok(p) => p,
            Err(_) => break,
        };

        let mut noise_pub = [0u8; 32];
        let mut ed25519_pub = [0u8; 32];
        if cursor.read_exact(&mut noise_pub).is_err()
            || cursor.read_exact(&mut ed25519_pub).is_err()
        {
            break;
        }

        let last_seen = cursor.read_i64::<LittleEndian>().unwrap_or(0);

        contacts.push(EmberContact {
            node_id: EmberNodeId(node_id),
            addr: SocketAddr::new(ip, port),
            noise_pub,
            ed25519_pub,
            last_seen,
            failed_queries: 0,
        });
    }

    // Detect partial/truncated load. The header declared `count`
    // contacts but the loop bailed early on the first short read,
    // leaving us with fewer. Without this check, the next save would
    // silently overwrite the on-disk file with the truncated list,
    // permanently shrinking the persisted DHT bootstrap set.
    // Mirrors `kad::bootstrap::backup_if_short_load`.
    if contacts.len() < count {
        warn!(
            "Ember DHT nodes file declared {count} contacts but only {} loaded; \
             likely a corrupted or truncated file. Backing up before next save.",
            contacts.len(),
        );
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bak = path.with_extension(format!("dat.bak.{ts}"));
        if let Err(e) = std::fs::copy(path, &bak) {
            warn!(
                "Failed to back up partial nodes_ember.dat to {}: {e}",
                bak.display(),
            );
        } else {
            info!("Backed up partial nodes_ember.dat to {}", bak.display());
        }
    }

    info!(
        "Loaded {} Ember DHT contacts from {}",
        contacts.len(),
        path.display()
    );
    Ok(contacts)
}

/// Fetch bootstrap nodes from the rendezvous server.
pub async fn fetch_bootstrap_nodes(rendezvous_url: &str) -> Result<Vec<BootstrapNode>, String> {
    let url = format!("{}/bootstrap", rendezvous_url.trim_end_matches('/'));
    // https_only mirrors the rendezvous client: refuse to send the bootstrap
    // request in cleartext (or follow an http redirect), so a tampered/mistyped
    // rendezvous URL can't downgrade the connection.
    let client = reqwest::Client::builder()
        .timeout(BOOTSTRAP_TIMEOUT)
        .https_only(true)
        .no_proxy()
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Bootstrap fetch error: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Bootstrap endpoint returned {}", resp.status()));
    }

    let nodes: Vec<BootstrapNode> = resp
        .json()
        .await
        .map_err(|e| format!("Bootstrap parse error: {e}"))?;

    let count = nodes.len().min(MAX_BOOTSTRAP_NODES);
    debug!("Fetched {count} bootstrap nodes from rendezvous server");
    Ok(nodes.into_iter().take(MAX_BOOTSTRAP_NODES).collect())
}

/// A bootstrap node returned by the rendezvous server.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BootstrapNode {
    pub node_id: String,
    pub addr: String,
    pub noise_pub: String,
    pub ed25519_pub: String,
}

impl BootstrapNode {
    /// Parse into an EmberContact, returning None if any field is invalid.
    pub fn to_contact(&self) -> Option<EmberContact> {
        let node_id_bytes = hex::decode(&self.node_id).ok()?;
        if node_id_bytes.len() != 16 {
            return None;
        }
        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&node_id_bytes);

        let addr: SocketAddr = self.addr.parse().ok()?;

        let noise_bytes = hex::decode(&self.noise_pub).ok()?;
        if noise_bytes.len() != 32 {
            return None;
        }
        let mut noise_pub = [0u8; 32];
        noise_pub.copy_from_slice(&noise_bytes);

        let ed_bytes = hex::decode(&self.ed25519_pub).ok()?;
        if ed_bytes.len() != 32 {
            return None;
        }
        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&ed_bytes);

        Some(EmberContact {
            node_id: EmberNodeId(node_id),
            addr,
            noise_pub,
            ed25519_pub,
            last_seen: 0,
            failed_queries: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn make_contact(id: u8) -> EmberContact {
        EmberContact {
            node_id: EmberNodeId([id; 16]),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 2, id)), 4662),
            noise_pub: [id; 32],
            ed25519_pub: [id; 32],
            last_seen: 1000 + id as i64,
            failed_queries: 0,
        }
    }

    #[test]
    fn save_load_round_trip() {
        let dir = std::env::temp_dir().join("ember_test_nodes");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        let contacts = vec![make_contact(1), make_contact(2), make_contact(3)];
        save_nodes(&path, &contacts).unwrap();
        let loaded = load_nodes(&path).unwrap();

        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].node_id, contacts[0].node_id);
        assert_eq!(loaded[0].addr, contacts[0].addr);
        assert_eq!(loaded[0].noise_pub, contacts[0].noise_pub);
        assert_eq!(loaded[0].last_seen, contacts[0].last_seen);
        assert_eq!(loaded[2].node_id, contacts[2].node_id);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_load_with_ipv6() {
        let dir = std::env::temp_dir().join("ember_test_nodes_v6");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember_v6.dat");

        let contacts = vec![EmberContact {
            node_id: EmberNodeId([0xAA; 16]),
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                9999,
            ),
            noise_pub: [0xBB; 32],
            ed25519_pub: [0xCC; 32],
            last_seen: 42,
            failed_queries: 0,
        }];
        save_nodes(&path, &contacts).unwrap();
        let loaded = load_nodes(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(
            loaded[0].addr,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                9999
            )
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bootstrap_node_to_contact() {
        let bn = BootstrapNode {
            node_id: hex::encode([1u8; 16]),
            addr: "1.2.3.4:4662".to_string(),
            noise_pub: hex::encode([2u8; 32]),
            ed25519_pub: hex::encode([3u8; 32]),
        };
        let c = bn.to_contact().unwrap();
        assert_eq!(c.node_id, EmberNodeId([1u8; 16]));
        assert_eq!(c.addr, "1.2.3.4:4662".parse::<SocketAddr>().unwrap());
        assert_eq!(c.noise_pub, [2u8; 32]);
    }

    #[test]
    fn rejects_invalid_bootstrap_node() {
        let bn = BootstrapNode {
            node_id: "too_short".to_string(),
            addr: "1.2.3.4:4662".to_string(),
            noise_pub: hex::encode([0u8; 32]),
            ed25519_pub: hex::encode([0u8; 32]),
        };
        assert!(bn.to_contact().is_none());
    }
}
