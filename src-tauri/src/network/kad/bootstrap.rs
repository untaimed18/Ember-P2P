use std::io::Cursor;
use std::net::Ipv4Addr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{debug, info, warn};

use super::types::*;

/// Well-known bootstrap nodes for the eMule KAD network.
/// These are long-running public nodes that help new clients join.
pub fn default_bootstrap_contacts() -> Vec<KadContact> {
    let nodes = [
        ("212.63.206.35", 4672u16, 4662u16),
        ("82.141.38.69", 4672, 4662),
        ("212.63.206.36", 4672, 4662),
        ("94.23.196.180", 4672, 4662),
        ("95.217.44.50", 4672, 4662),
    ];

    nodes
        .iter()
        .filter_map(|(ip_str, udp, tcp)| {
            let ip: Ipv4Addr = ip_str.parse().ok()?;
            Some(KadContact {
                id: KadId::zero(),
                ip,
                udp_port: *udp,
                tcp_port: *tcp,
                version: KADEMLIA_VERSION,
                last_seen: 0,
                verified: false,
                contact_type: CONTACT_TYPE_NEW,
                udp_key: None,
                kad_options: 0,
                created_at: 0,
                expires_at: 0,
                last_type_set: 0,
            })
        })
        .collect()
}

/// Read contacts from a nodes.dat file.
/// Supports format version 0, 1, and 2.
pub fn load_nodes_dat(path: &Path) -> anyhow::Result<Vec<KadContact>> {
    let data = std::fs::read(path)?;
    if data.len() < 6 {
        anyhow::bail!("nodes.dat too small");
    }

    let data_slice: &[u8] = &data;
    let mut cursor = Cursor::new(data_slice);
    let mut contacts = Vec::new();

    // Check for v2/v3 header: first 4 bytes == 0
    let first_u32 = cursor.read_u32::<LittleEndian>()?;
    if first_u32 == 0 {
        let version = cursor.read_u32::<LittleEndian>()?;
        if version == 3 {
            // eMule v3: check bootstrap edition flag
            let bootstrap_edition = cursor.read_u32::<LittleEndian>()?;
            if bootstrap_edition == 1 {
                // Bootstrap-only nodes.dat: contacts are v1-format (no UDP key/verified)
                let count = cursor.read_u32::<LittleEndian>()? as usize;
                info!("Loading {count} contacts from bootstrap nodes.dat v3");
                for _ in 0..count {
                    match read_contact_v0(&mut cursor) {
                        Ok(c) => {
                            if c.version > 1 {
                                contacts.push(c);
                            }
                        }
                        Err(e) => {
                            debug!("Failed to read v3 bootstrap contact: {e}");
                            break;
                        }
                    }
                }
                info!("Loaded {} valid contacts from bootstrap nodes.dat", contacts.len());
                return Ok(contacts);
            }
            // v3 with bootstrap_edition != 1: treat as normal (count follows)
            let count = bootstrap_edition as usize; // re-interpret as count
            info!("Loading {count} contacts from nodes.dat v3");
            for _ in 0..count {
                match read_contact_v2(&mut cursor) {
                    Ok(c) => contacts.push(c),
                    Err(e) => {
                        debug!("Failed to read contact: {e}");
                        break;
                    }
                }
            }
        } else if version == 2 || version == 1 {
            let count = cursor.read_u32::<LittleEndian>()? as usize;
            info!("Loading {count} contacts from nodes.dat v{version}");
            for _ in 0..count {
                if version >= 2 {
                    match read_contact_v2(&mut cursor) {
                        Ok(c) => contacts.push(c),
                        Err(e) => {
                            debug!("Failed to read contact: {e}");
                            break;
                        }
                    }
                } else {
                    match read_contact_v0(&mut cursor) {
                        Ok(c) => contacts.push(c),
                        Err(e) => {
                            debug!("Failed to read v1 contact: {e}");
                            break;
                        }
                    }
                }
            }
        } else {
            warn!("Unknown nodes.dat version: {version}, trying as v2");
            let count = cursor.read_u32::<LittleEndian>()? as usize;
            info!("Loading {count} contacts from nodes.dat v{version}");
            for _ in 0..count {
                match read_contact_v2(&mut cursor) {
                    Ok(c) => contacts.push(c),
                    Err(e) => {
                        debug!("Failed to read contact: {e}");
                        break;
                    }
                }
            }
        }
    } else {
        // Version 0/1 format: first_u32 is the contact count
        let count = first_u32 as usize;
        info!("Loading {count} contacts from nodes.dat v0");

        for _ in 0..count {
            match read_contact_v0(&mut cursor) {
                Ok(c) => contacts.push(c),
                Err(e) => {
                    debug!("Failed to read v0 contact: {e}");
                    break;
                }
            }
        }
    }

    info!("Loaded {} valid contacts from nodes.dat", contacts.len());
    Ok(contacts)
}

fn read_contact_v0(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<KadContact> {
    let id = KadId::read_from(cursor)?;
    let ip_raw = cursor.read_u32::<LittleEndian>()?;
    let ip = Ipv4Addr::from(ip_raw.to_be_bytes());
    let udp_port = cursor.read_u16::<LittleEndian>()?;
    let tcp_port = cursor.read_u16::<LittleEndian>()?;
    let version = cursor.read_u8()?;

    Ok(KadContact {
        id,
        ip,
        udp_port,
        tcp_port,
        version,
        last_seen: 0,
        verified: false,
        contact_type: CONTACT_TYPE_NEW,
        udp_key: None,
        kad_options: 0,
        created_at: 0,
        expires_at: 0,
        last_type_set: 0,
    })
}

fn read_contact_v2(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<KadContact> {
    let id = KadId::read_from(cursor)?;
    let ip_raw = cursor.read_u32::<LittleEndian>()?;
    let ip = Ipv4Addr::from(ip_raw.to_be_bytes());
    let udp_port = cursor.read_u16::<LittleEndian>()?;
    let tcp_port = cursor.read_u16::<LittleEndian>()?;
    let version = cursor.read_u8()?;
    // v2 has extra kad_udp_key (8 bytes) and verified (1 byte)
    let kad_udp_key_raw = cursor.read_u64::<LittleEndian>().unwrap_or(0);
    let verified_byte = cursor.read_u8().unwrap_or(0);

    let udp_key = if kad_udp_key_raw != 0 {
        Some(KadUDPKey {
            key: (kad_udp_key_raw & 0xFFFFFFFF) as u32,
            ip: (kad_udp_key_raw >> 32) as u32,
        })
    } else {
        None
    };

    Ok(KadContact {
        id,
        ip,
        udp_port,
        tcp_port,
        version,
        last_seen: 0,
        verified: verified_byte != 0,
        contact_type: if verified_byte != 0 { CONTACT_TYPE_VERIFIED } else { CONTACT_TYPE_NEW },
        udp_key,
        kad_options: 0,
        created_at: 0,
        expires_at: 0,
        last_type_set: 0,
    })
}

/// Save contacts to a nodes.dat file (v2 format).
/// Uses atomic write (temp file + rename) to prevent corruption on crash.
/// Skips saving if contacts is empty and a valid nodes.dat already exists
/// (matching eMule's protection against overwriting good data with nothing).
pub fn save_nodes_dat(path: &Path, contacts: &[KadContact]) -> anyhow::Result<()> {
    if contacts.is_empty() && path.exists() {
        info!("Skipping nodes.dat save: routing table empty but existing file present");
        return Ok(());
    }
    if contacts.is_empty() {
        return Ok(());
    }

    let mut buf = Vec::with_capacity(contacts.len() * 35 + 12);

    // v2 header
    buf.write_u32::<LittleEndian>(0)?; // marker for v2
    buf.write_u32::<LittleEndian>(2)?; // version
    buf.write_u32::<LittleEndian>(contacts.len() as u32)?;

    for c in contacts {
        c.id.write_to(&mut buf)?;
        let octets = c.ip.octets();
        let ip_raw = u32::from_be_bytes(octets);
        buf.write_u32::<LittleEndian>(ip_raw)?;
        buf.write_u16::<LittleEndian>(c.udp_port)?;
        buf.write_u16::<LittleEndian>(c.tcp_port)?;
        buf.write_u8(c.version)?;
        let key_val = c.udp_key.map_or(0u64, |k| (k.ip as u64) << 32 | k.key as u64);
        buf.write_u64::<LittleEndian>(key_val)?;
        buf.write_u8(if c.verified { 1 } else { 0 })?;
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Atomic write: write to temporary file, then rename over the target.
    let tmp_path = path.with_extension("dat.tmp");
    std::fs::write(&tmp_path, &buf)?;
    std::fs::rename(&tmp_path, path)?;
    info!("Saved {} contacts to nodes.dat", contacts.len());
    Ok(())
}
