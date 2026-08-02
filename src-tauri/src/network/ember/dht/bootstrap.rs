use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{info, warn};

use super::{EmberContact, EmberNodeId};

const NODES_EMBER_MAGIC: u32 = 0x454D_4233; // "EMB3" in LE
const NODES_EMBER_VERSION: u8 = 1;

/// Persist the routing table to `nodes_ember.dat`.
///
/// Format:
///   magic(4) + version(1) + count(u16 LE) +
///   for each contact:
///     node_id(16) + addr_type(1) + ip(4 or 16) + port(2 BE) +
///     noise_pub(32) + ed25519_pub(32) + last_seen(i64 LE)
pub fn save_nodes(path: &Path, contacts: &[EmberContact]) -> anyhow::Result<()> {
    // Never trade a usable bootstrap file for an empty one. A table can be
    // momentarily empty (startup, the transport toggled off, a network drop),
    // and overwriting the file at that moment leaves the next launch with no
    // way back into the network at all.
    if contacts.is_empty() && path.exists() {
        info!(
            "Skipping Ember nodes save: routing table empty but {} already exists",
            path.display()
        );
        return Ok(());
    }

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
    // Contacts dropped because their persisted Ed25519 key was unusable. Tracked
    // separately so the truncation check below doesn't misfire when we
    // legitimately skip a corrupt entry mid-file.
    let mut dropped = 0usize;

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

        // The persisted timestamp records when the *previous* session last
        // heard from this contact. It is deliberately not carried forward:
        // `last_seen` is what marks a contact as proven, and a contact we
        // have not spoken to since launch has proven nothing. Restoring it
        // would make every entry look verified the moment it loads, so the
        // staleness purge would delete the whole bootstrap set — before a
        // single ping went out — for any restart after the stale threshold.
        // Zero also sorts them first for liveness probing, which is exactly
        // the order we want.
        let _persisted_last_seen = cursor.read_i64::<LittleEndian>().unwrap_or(0);

        // Re-derive the node id from the persisted Ed25519 key rather than
        // trusting the on-disk `node_id`. If the file was tampered with (or
        // corrupted), a mismatched id must not let a contact masquerade under
        // an identity it doesn't control — the derived id is authoritative and
        // matches what the first PING will re-verify.
        let Some(derived) = crate::network::ember::crypto::node_id_from_ed25519_bytes(&ed25519_pub)
        else {
            warn!("Skipping nodes_ember.dat contact with invalid Ed25519 key");
            dropped += 1;
            continue;
        };
        let _ = node_id; // persisted id is advisory; derived id is authoritative

        contacts.push(EmberContact {
            node_id: EmberNodeId(derived),
            addr: SocketAddr::new(ip, port),
            noise_pub,
            ed25519_pub,
            last_seen: 0,
            failed_queries: 0,
        });
    }

    // Detect partial/truncated load. The header declared `count`
    // contacts but the loop bailed early on the first short read,
    // leaving us with fewer. Without this check, the next save would
    // silently overwrite the on-disk file with the truncated list,
    // permanently shrinking the persisted DHT bootstrap set.
    // Mirrors `kad::bootstrap::backup_if_short_load`. `dropped` entries were
    // parsed successfully but discarded for an invalid key, so they don't count
    // as truncation.
    if contacts.len() + dropped < count {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn make_contact(id: u8) -> EmberContact {
        // `load_nodes` re-derives the node id from the Ed25519 key and drops
        // contacts whose key isn't a valid curve point, so use a real keypair
        // (any 32 bytes is a valid Ed25519 seed).
        let sk = ed25519_dalek::SigningKey::from_bytes(&[id; 32]);
        let vk = sk.verifying_key();
        EmberContact {
            node_id: EmberNodeId(crate::network::ember::crypto::node_id_from_public_key(&vk)),
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 2, id)), 4662),
            noise_pub: [id; 32],
            ed25519_pub: vk.to_bytes(),
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
        assert_eq!(loaded[2].node_id, contacts[2].node_id);
        // A loaded contact has proven nothing yet this session, so it comes
        // back unverified regardless of how recently the previous session
        // heard from it. Carrying the timestamp forward would make the
        // staleness purge delete the entire bootstrap set on any restart
        // after the stale threshold, before a single ping was sent.
        assert!(
            contacts[0].last_seen > 0,
            "the fixture must have a real timestamp for this to mean anything"
        );
        assert!(loaded.iter().all(|c| c.last_seen == 0));
        assert!(loaded.iter().all(|c| !c.is_verified()));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_load_with_ipv6() {
        let dir = std::env::temp_dir().join("ember_test_nodes_v6");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember_v6.dat");

        let sk = ed25519_dalek::SigningKey::from_bytes(&[0xCC; 32]);
        let vk = sk.verifying_key();
        let contacts = vec![EmberContact {
            node_id: EmberNodeId(crate::network::ember::crypto::node_id_from_public_key(&vk)),
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                9999,
            ),
            noise_pub: [0xBB; 32],
            ed25519_pub: vk.to_bytes(),
            last_seen: 42,
            failed_queries: 0,
        }];
        save_nodes(&path, &contacts).unwrap();
        let loaded = load_nodes(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].node_id, contacts[0].node_id);
        assert_eq!(
            loaded[0].addr,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                9999
            )
        );

        std::fs::remove_dir_all(&dir).ok();
    }

}
