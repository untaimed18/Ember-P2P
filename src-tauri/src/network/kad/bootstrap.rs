use std::io::Cursor;
use std::net::Ipv4Addr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{debug, info, warn};

use super::types::*;

/// Upper bound for local `nodes.dat` before reading it into memory. Valid eMule
/// contact records are tiny; 16 MiB still allows hundreds of thousands of
/// contacts, far beyond what the routing table can use.
const MAX_NODES_DAT_BYTES: u64 = 16 * 1024 * 1024;

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
        .enumerate()
        .filter_map(|(idx, (ip_str, udp, tcp))| {
            let ip: Ipv4Addr = ip_str.parse().ok()?;
            // Use a deterministic but unique placeholder ID per bootstrap node
            // so routing table insertion doesn't collapse them into one entry.
            // The real IDs are learned via the HELLO exchange.
            let mut id_bytes = [0u8; 16];
            id_bytes[0] = (idx + 1) as u8;
            let id = KadId(id_bytes);
            Some(KadContact {
                id,
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
                received_hello: false,
            })
        })
        .collect()
}

/// Which wire format was parsed from a `nodes.dat`. Carries security-relevant
/// detail the caller needs for K3: legacy formats don't encode a per-contact
/// `verified` bit and were previously blanket-verified on load, which an
/// attacker-supplied file (URL bootstrap) could abuse. Callers should only
/// mass-verify legacy-format contacts when they come from the app's own
/// on-disk `nodes.dat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodesDatFormat {
    /// Pre-verified-bit format saved by an older client during a live
    /// session (v0 contacts or a v1 whole file): no `verified` field on the
    /// wire, but trustworthy because we wrote it ourselves.
    LegacyNoVerified,
    /// eMule v3 "bootstrap edition" file: a list of *unverified* bootstrap
    /// hints (typically fetched from a bootstrap URL/server), carrying no
    /// `verified` field. These contacts must NOT be promoted to verified on
    /// load — eMule treats them as unproven seeds, and trusting them would
    /// let an attacker-supplied file inject contacts straight into
    /// lookup/publish target selection.
    BootstrapHints,
    /// Modern format where each contact carries its own `verified` byte.
    WithVerifiedBit,
}

/// Read contacts from a nodes.dat file, returning the format variant so
/// callers can decide whether to trust a "no verified bits present" file.
pub fn load_nodes_dat_with_format(
    path: &Path,
) -> anyhow::Result<(Vec<KadContact>, NodesDatFormat)> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_NODES_DAT_BYTES {
            anyhow::bail!(
                "nodes.dat too large ({} bytes, max {})",
                meta.len(),
                MAX_NODES_DAT_BYTES
            );
        }
    }
    let data = std::fs::read(path)?;
    if data.len() < 6 {
        anyhow::bail!("nodes.dat too small");
    }

    let data_slice: &[u8] = &data;
    let mut cursor = Cursor::new(data_slice);
    let mut contacts = Vec::new();
    let mut format = NodesDatFormat::LegacyNoVerified;
    // Track the count the file *claims* so we can detect short loads
    // below. If the parser stops early (truncation or a bad record)
    // we'd silently return a partial list â€” and the next
    // `save_nodes_dat` would overwrite the original file with the
    // shorter list, permanently losing every contact we couldn't
    // parse. The end-of-function guard backs the file up before
    // that can happen. Use `0` as the sentinel for "header didn't
    // declare a count" (e.g. file has only header bytes); the guard
    // skips backup when expected == loaded.
    //
    // Each version branch below assigns this from its own count
    // field, so the initial 0 is dead — silence the warning rather
    // than pull the variable into every branch.
    #[allow(unused_assignments)]
    let mut expected_count: usize = 0;

    // Check for v2/v3 header: first 4 bytes == 0
    let first_u32 = cursor.read_u32::<LittleEndian>()?;
    if first_u32 == 0 {
        let version = cursor.read_u32::<LittleEndian>()?;
        if version == 3 {
            // eMule v3: check bootstrap edition flag
            let bootstrap_edition = cursor.read_u32::<LittleEndian>()?;
            if bootstrap_edition == 1 {
                // Bootstrap-only nodes.dat: contacts are v1-format (no UDP key/verified)
                let count = (cursor.read_u32::<LittleEndian>()? as usize).min(50_000);
                expected_count = count;
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
                info!(
                    "Loaded {} valid contacts from bootstrap nodes.dat",
                    contacts.len()
                );
                backup_if_short_load(path, contacts.len(), expected_count);
                return Ok((contacts, NodesDatFormat::BootstrapHints));
            }
            // v3 with bootstrap_edition != 1: separate count follows (eMule RoutingZone format)
            format = NodesDatFormat::WithVerifiedBit;
            let count = (cursor.read_u32::<LittleEndian>()? as usize).min(50_000);
            expected_count = count;
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
            if version == 2 {
                format = NodesDatFormat::WithVerifiedBit;
            }
            let count = (cursor.read_u32::<LittleEndian>()? as usize).min(50_000);
            expected_count = count;
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
            debug!("Unknown nodes.dat version: {version}, trying as v2");
            format = NodesDatFormat::WithVerifiedBit;
            let count = (cursor.read_u32::<LittleEndian>()? as usize).min(50_000);
            expected_count = count;
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
        let count = (first_u32 as usize).min(50_000);
        expected_count = count;
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
    backup_if_short_load(path, contacts.len(), expected_count);
    Ok((contacts, format))
}

/// If the load was short (file claimed N contacts, parser only got
/// M < N), copy the original file aside as `nodes.dat.bak.<unix_ts>`
/// before any subsequent save can overwrite it. Without this, a
/// single corrupt or truncated record causes permanent loss of every
/// later contact on the very next `save_nodes_dat`. The backup is
/// best-effort: if we can't write it (disk full, perms), we still
/// return â€” the user just loses recovery rather than getting a worse
/// outcome than today.
fn backup_if_short_load(path: &Path, loaded: usize, expected: usize) {
    // expected == 0 means the header didn't declare a count (or
    // declared zero), so a "short" load is not meaningful here.
    if expected == 0 || loaded >= expected {
        return;
    }
    let now = chrono::Utc::now().timestamp();
    let bak = path.with_extension(format!("dat.bak.{now}"));
    match std::fs::copy(path, &bak) {
        Ok(bytes) => warn!(
            "nodes.dat parse stopped at {loaded}/{expected} contacts â€” backup written to {} ({bytes} bytes); the next save will overwrite the live file with {loaded} contacts",
            bak.display(),
        ),
        Err(e) => warn!(
            "nodes.dat parse stopped at {loaded}/{expected} contacts and backup to {} failed: {e}; subsequent save will overwrite the live file with {loaded} contacts",
            bak.display(),
        ),
    }
}

/// Backward-compatible thin wrapper that drops the format tag. Prefer
/// `load_nodes_dat_with_format` for new call sites that care about the
/// "file has no verified bits" discriminator (K3).
pub fn load_nodes_dat(path: &Path) -> anyhow::Result<Vec<KadContact>> {
    load_nodes_dat_with_format(path).map(|(c, _)| c)
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
        received_hello: false,
    })
}

fn read_contact_v2(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<KadContact> {
    let id = KadId::read_from(cursor)?;
    let ip_raw = cursor.read_u32::<LittleEndian>()?;
    let ip = Ipv4Addr::from(ip_raw.to_be_bytes());
    let udp_port = cursor.read_u16::<LittleEndian>()?;
    let tcp_port = cursor.read_u16::<LittleEndian>()?;
    let version = cursor.read_u8()?;
    let kad_udp_key_raw = cursor.read_u64::<LittleEndian>()?;
    let verified_byte = cursor.read_u8()?;

    let udp_key = if kad_udp_key_raw != 0 {
        Some(KadUDPKey {
            key: (kad_udp_key_raw >> 32) as u32,
            ip: (kad_udp_key_raw & 0xFFFFFFFF) as u32,
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
        contact_type: if verified_byte != 0 {
            CONTACT_TYPE_VERIFIED
        } else {
            CONTACT_TYPE_NEW
        },
        udp_key,
        kad_options: 0,
        created_at: 0,
        expires_at: 0,
        last_type_set: 0,
        received_hello: false,
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
    buf.write_u32::<LittleEndian>(contacts.len().min(u32::MAX as usize) as u32)?;

    for c in contacts {
        c.id.write_to(&mut buf)?;
        let octets = c.ip.octets();
        let ip_raw = u32::from_be_bytes(octets);
        buf.write_u32::<LittleEndian>(ip_raw)?;
        buf.write_u16::<LittleEndian>(c.udp_port)?;
        buf.write_u16::<LittleEndian>(c.tcp_port)?;
        buf.write_u8(c.version)?;
        let key_val = c
            .udp_key
            .map_or(0u64, |k| (k.key as u64) << 32 | k.ip as u64);
        buf.write_u64::<LittleEndian>(key_val)?;
        buf.write_u8(if c.verified { 1 } else { 0 })?;
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // LOW-backend: before overwriting the existing nodes.dat, keep a
    // `.bak` copy so an unclean shutdown during the atomic write (or a
    // corrupted buffer that still parses enough to pass header checks)
    // doesn't wipe out our only working contact list. The `.bak` is
    // intentionally silent on failure â€” we'd rather save the new file
    // than refuse because a backup couldn't be made.
    if path.exists() {
        let bak = path.with_extension("dat.bak");
        if let Err(e) = std::fs::copy(path, &bak) {
            tracing::debug!("Could not create nodes.dat.bak: {e}");
        }
    }

    crate::security::atomic_write(path, &buf, false)?;
    info!("Saved {} contacts to nodes.dat", contacts.len());
    Ok(())
}
