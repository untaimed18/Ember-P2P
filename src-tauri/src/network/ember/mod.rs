#[allow(dead_code)]
pub mod crypto;
#[allow(dead_code)]
pub mod dht;
#[allow(dead_code)]
pub mod friends;
#[allow(dead_code)]
pub mod nat;
#[allow(dead_code)]
pub mod quic;
#[allow(dead_code)]
pub mod reputation;
#[allow(dead_code)]
pub mod transfer;
#[allow(dead_code)]
pub mod transport;
#[allow(dead_code)]
pub mod broker;
#[allow(dead_code)]
pub mod relay;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::sync::RwLock;

pub const EPX_VERSION: u8 = 4;
pub const MAX_EPX_FILES: usize = 200;
pub const MAX_EPX_SOURCES_PER_FILE: usize = 100;
pub const MAX_EPX_PAYLOAD: usize = 65536;
/// Max total sources accepted from a single EPX event (anti-poisoning)
pub const MAX_EPX_TOTAL_SOURCES: usize = 2000;
/// Max EPX packets accepted per TCP connection (anti-flood)
pub const MAX_EPX_PACKETS_PER_CONNECTION: u8 = 3;
/// Max ember peers in peer discovery section
pub const MAX_EPX_PEERS: usize = 50;

/// Per-file flags (v3+)
pub const FILE_FLAG_HAS_AICH: u8 = 0x01;

/// Per-source flags (v3+)
pub const SOURCE_FLAG_FIREWALLED: u8 = 0x01;
pub const SOURCE_FLAG_OBFUSCATION: u8 = 0x02;
/// Peer is willing to act as a relay for LowID-to-LowID transfers (v4+).
#[allow(dead_code)]
pub const SOURCE_FLAG_RELAY_CAPABLE: u8 = 0x04;

// v2 wire sizes (backward compat parsing)
const V2_FILE_ENTRY_HEADER_SIZE: usize = 16 + 8 + 2;
const V2_SOURCE_ENTRY_SIZE: usize = 4 + 2;

// v3 wire sizes
const V3_FILE_ENTRY_HEADER_SIZE: usize = 16 + 8 + 1 + 2; // hash + size + file_flags + source_count
const V3_SOURCE_ENTRY_SIZE: usize = 4 + 2 + 2 + 1; // ipv4 + tcp_port + udp_port + flags

#[derive(Debug, Clone)]
pub struct EmberFileEntry {
    pub file_hash: [u8; 16],
    pub file_size: u64,
    pub aich_root: Option<[u8; 20]>,
    pub sources: Vec<EmberSource>,
}

#[derive(Debug, Clone)]
pub struct EmberSource {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub flags: u8,
}

#[derive(Debug, Clone)]
pub struct EmberPeer {
    pub ip: Ipv4Addr,
    pub tcp_port: u16,
}

/// Result of parsing an EPX payload.
#[derive(Debug, Clone)]
pub struct ExchangeResult {
    pub files: Vec<EmberFileEntry>,
    pub peers: Vec<EmberPeer>,
}

/// Pre-serialized exchange payload shared across download/upload tasks.
/// Inner Arc<Vec<u8>> allows cheap cloning (pointer copy instead of 64KB data copy).
pub type SharedEmberPayload = Arc<RwLock<Arc<Vec<u8>>>>;

/// Generation counter incremented each time the EPX payload is rebuilt.
/// Send sites compare against their last-sent generation to detect changes.
pub type EmberPayloadGeneration = Arc<AtomicU64>;

/// Build the v3 wire-format payload.
///
/// Wire format (v3):
///   version(1) + file_count(u16 LE) +
///     for each file:
///       ed2k_hash(16) + file_size(u64 LE) + file_flags(u8) +
///       [aich_root(20) if FILE_FLAG_HAS_AICH] +
///       source_count(u16 LE) +
///       for each source: ipv4(4) + tcp_port(u16 LE) + udp_port(u16 LE) + flags(u8)
///   + ember_peer_count(u16 LE) +
///     for each peer: ipv4(4) + tcp_port(u16 LE)
pub fn build_exchange_payload(entries: &[EmberFileEntry], peers: &[EmberPeer]) -> Vec<u8> {
    let file_count = entries.len().min(MAX_EPX_FILES);
    let mut buf = Vec::with_capacity(3 + file_count * V3_FILE_ENTRY_HEADER_SIZE);
    buf.write_u8(EPX_VERSION).unwrap();
    let file_count_pos = buf.len();
    buf.write_u16::<LittleEndian>(0).unwrap();

    let mut files_written = 0u16;
    for entry in entries.iter().take(file_count) {
        let src_count = entry.sources.len().min(MAX_EPX_SOURCES_PER_FILE);
        let aich_size = if entry.aich_root.is_some() { 20 } else { 0 };
        let entry_size = V3_FILE_ENTRY_HEADER_SIZE + aich_size + src_count * V3_SOURCE_ENTRY_SIZE;

        if buf.len() + entry_size > MAX_EPX_PAYLOAD - 2 {
            break;
        }

        buf.write_all(&entry.file_hash).unwrap();
        buf.write_u64::<LittleEndian>(entry.file_size).unwrap();

        let file_flags = if entry.aich_root.is_some() { FILE_FLAG_HAS_AICH } else { 0 };
        buf.write_u8(file_flags).unwrap();
        if let Some(ref aich) = entry.aich_root {
            buf.write_all(aich).unwrap();
        }

        buf.write_u16::<LittleEndian>(src_count as u16).unwrap();
        for src in entry.sources.iter().take(src_count) {
            buf.write_all(&src.ip.octets()).unwrap();
            buf.write_u16::<LittleEndian>(src.tcp_port).unwrap();
            buf.write_u16::<LittleEndian>(src.udp_port).unwrap();
            buf.write_u8(src.flags).unwrap();
        }

        files_written += 1;
    }

    buf[file_count_pos] = (files_written & 0xFF) as u8;
    buf[file_count_pos + 1] = ((files_written >> 8) & 0xFF) as u8;

    // Peer discovery section
    let peer_count = peers.len().min(MAX_EPX_PEERS);
    let peers_size = 2 + peer_count * 6;
    if buf.len() + peers_size <= MAX_EPX_PAYLOAD {
        buf.write_u16::<LittleEndian>(peer_count as u16).unwrap();
        for peer in peers.iter().take(peer_count) {
            buf.write_all(&peer.ip.octets()).unwrap();
            buf.write_u16::<LittleEndian>(peer.tcp_port).unwrap();
        }
    } else {
        buf.write_u16::<LittleEndian>(0).unwrap();
    }

    buf
}

/// Parse a received exchange payload (v2 or v3).
pub fn parse_exchange_payload(data: &[u8]) -> anyhow::Result<ExchangeResult> {
    if data.len() < 3 {
        anyhow::bail!("EPX payload too short ({} bytes)", data.len());
    }
    if data.len() > MAX_EPX_PAYLOAD {
        anyhow::bail!("EPX payload too large ({} bytes)", data.len());
    }

    let mut cursor = Cursor::new(data);
    let version = cursor.read_u8()?;
    if version > EPX_VERSION {
        anyhow::bail!("unsupported EPX version {version} (we support up to {EPX_VERSION})");
    }

    let file_count = cursor.read_u16::<LittleEndian>()? as usize;
    if file_count > MAX_EPX_FILES {
        anyhow::bail!("EPX file_count {file_count} exceeds limit");
    }

    let mut entries = Vec::with_capacity(file_count);
    for _ in 0..file_count {
        let remaining = data.len() - cursor.position() as usize;
        let min_header = if version >= 3 { V3_FILE_ENTRY_HEADER_SIZE } else { V2_FILE_ENTRY_HEADER_SIZE };
        if remaining < min_header {
            tracing::debug!("EPX payload truncated: declared {file_count} files but only parsed {}", entries.len());
            break;
        }

        let mut file_hash = [0u8; 16];
        cursor.read_exact(&mut file_hash)?;
        let file_size = cursor.read_u64::<LittleEndian>()?;

        let (aich_root, source_entry_size) = if version >= 3 {
            let file_flags = cursor.read_u8()?;
            let aich = if file_flags & FILE_FLAG_HAS_AICH != 0 {
                let remaining = data.len() - cursor.position() as usize;
                if remaining < 20 {
                    tracing::debug!("EPX payload truncated: missing AICH root for {}", hex::encode(file_hash));
                    break;
                }
                let mut root = [0u8; 20];
                cursor.read_exact(&mut root)?;
                Some(root)
            } else {
                None
            };
            (aich, V3_SOURCE_ENTRY_SIZE)
        } else {
            (None, V2_SOURCE_ENTRY_SIZE)
        };

        let source_count = cursor.read_u16::<LittleEndian>()? as usize;
        if source_count > MAX_EPX_SOURCES_PER_FILE {
            anyhow::bail!("EPX source_count {source_count} exceeds limit for hash {}", hex::encode(file_hash));
        }

        let sources_bytes_needed = source_count * source_entry_size;
        let remaining = data.len() - cursor.position() as usize;
        if remaining < sources_bytes_needed {
            tracing::debug!("EPX payload truncated: not enough bytes for sources of file {}", hex::encode(file_hash));
            break;
        }

        let mut sources = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            let mut ip_bytes = [0u8; 4];
            cursor.read_exact(&mut ip_bytes)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            let (udp_port, flags) = if version >= 3 {
                (cursor.read_u16::<LittleEndian>()?, cursor.read_u8()?)
            } else {
                (0, 0)
            };
            let ip = Ipv4Addr::from(ip_bytes);

            if ip.is_unspecified() || tcp_port == 0 {
                continue;
            }
            if crate::security::is_special_use_v4(ip) {
                continue;
            }

            sources.push(EmberSource { ip, tcp_port, udp_port, flags });
        }

        if file_hash == [0u8; 16] || file_size == 0 {
            continue;
        }
        entries.push(EmberFileEntry {
            file_hash,
            file_size,
            aich_root,
            sources,
        });
    }

    // Parse peer discovery section (v3+)
    let mut peers = Vec::new();
    if version >= 3 {
        let remaining = data.len() - cursor.position() as usize;
        if remaining >= 2 {
            let peer_count = cursor.read_u16::<LittleEndian>()? as usize;
            let count = peer_count.min(MAX_EPX_PEERS);
            for _ in 0..count {
                let remaining = data.len() - cursor.position() as usize;
                if remaining < 6 {
                    break;
                }
                let mut ip_bytes = [0u8; 4];
                cursor.read_exact(&mut ip_bytes)?;
                let tcp_port = cursor.read_u16::<LittleEndian>()?;
                let ip = Ipv4Addr::from(ip_bytes);

                if ip.is_unspecified() || tcp_port == 0 || crate::security::is_special_use_v4(ip) {
                    continue;
                }
                peers.push(EmberPeer { ip, tcp_port });
            }
        }
    }

    Ok(ExchangeResult { files: entries, peers })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_source(a: u8, b: u8, c: u8, d: u8, tcp: u16) -> EmberSource {
        EmberSource {
            ip: Ipv4Addr::new(a, b, c, d),
            tcp_port: tcp,
            udp_port: tcp + 10,
            flags: 0,
        }
    }

    #[test]
    fn round_trip_empty() {
        let payload = build_exchange_payload(&[], &[]);
        assert_eq!(payload.len(), 5); // version + file_count + peer_count
        let result = parse_exchange_payload(&payload).unwrap();
        assert!(result.files.is_empty());
        assert!(result.peers.is_empty());
    }

    #[test]
    fn round_trip_with_sources() {
        let entries = vec![EmberFileEntry {
            file_hash: [1u8; 16],
            file_size: 12345,
            aich_root: None,
            sources: vec![
                make_source(1, 2, 3, 4, 4662),
                make_source(5, 6, 7, 8, 4663),
            ],
        }];
        let payload = build_exchange_payload(&entries, &[]);
        let result = parse_exchange_payload(&payload).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].file_hash, [1u8; 16]);
        assert_eq!(result.files[0].file_size, 12345);
        assert_eq!(result.files[0].aich_root, None);
        assert_eq!(result.files[0].sources.len(), 2);
        assert_eq!(result.files[0].sources[0].ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(result.files[0].sources[0].tcp_port, 4662);
        assert_eq!(result.files[0].sources[0].udp_port, 4672);
        assert_eq!(result.files[0].sources[1].ip, Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(result.files[0].sources[1].tcp_port, 4663);
    }

    #[test]
    fn round_trip_with_aich() {
        let aich = [0xAA; 20];
        let entries = vec![EmberFileEntry {
            file_hash: [5u8; 16],
            file_size: 99999,
            aich_root: Some(aich),
            sources: vec![make_source(44, 55, 66, 77, 4662)],
        }];
        let payload = build_exchange_payload(&entries, &[]);
        let result = parse_exchange_payload(&payload).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].aich_root, Some(aich));
    }

    #[test]
    fn round_trip_with_flags() {
        let entries = vec![EmberFileEntry {
            file_hash: [6u8; 16],
            file_size: 1000,
            aich_root: None,
            sources: vec![EmberSource {
                ip: Ipv4Addr::new(80, 1, 2, 3),
                tcp_port: 4662,
                udp_port: 4672,
                flags: SOURCE_FLAG_FIREWALLED | SOURCE_FLAG_OBFUSCATION,
            }],
        }];
        let payload = build_exchange_payload(&entries, &[]);
        let result = parse_exchange_payload(&payload).unwrap();
        assert_eq!(result.files[0].sources[0].flags, SOURCE_FLAG_FIREWALLED | SOURCE_FLAG_OBFUSCATION);
    }

    #[test]
    fn round_trip_with_peers() {
        let peers = vec![
            EmberPeer { ip: Ipv4Addr::new(1, 1, 1, 1), tcp_port: 4662 },
            EmberPeer { ip: Ipv4Addr::new(2, 2, 2, 2), tcp_port: 4663 },
        ];
        let payload = build_exchange_payload(&[], &peers);
        let result = parse_exchange_payload(&payload).unwrap();
        assert!(result.files.is_empty());
        assert_eq!(result.peers.len(), 2);
        assert_eq!(result.peers[0].ip, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(result.peers[0].tcp_port, 4662);
        assert_eq!(result.peers[1].ip, Ipv4Addr::new(2, 2, 2, 2));
    }

    #[test]
    fn skips_zero_hash_and_zero_port() {
        let entries = vec![
            EmberFileEntry {
                file_hash: [0u8; 16],
                file_size: 100,
                aich_root: None,
                sources: vec![],
            },
            EmberFileEntry {
                file_hash: [2u8; 16],
                file_size: 200,
                aich_root: None,
                sources: vec![
                    EmberSource { ip: Ipv4Addr::UNSPECIFIED, tcp_port: 100, udp_port: 0, flags: 0 },
                    EmberSource { ip: Ipv4Addr::new(10, 0, 0, 1), tcp_port: 0, udp_port: 0, flags: 0 },
                    EmberSource { ip: Ipv4Addr::new(88, 1, 2, 3), tcp_port: 4662, udp_port: 4672, flags: 0 },
                ],
            },
        ];
        let payload = build_exchange_payload(&entries, &[]);
        let result = parse_exchange_payload(&payload).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].sources.len(), 1);
        assert_eq!(result.files[0].sources[0].ip, Ipv4Addr::new(88, 1, 2, 3));
    }

    #[test]
    fn rejects_bad_version() {
        let mut payload = build_exchange_payload(&[], &[]);
        payload[0] = 99;
        assert!(parse_exchange_payload(&payload).is_err());
    }

    #[test]
    fn accepts_current_version() {
        let payload = build_exchange_payload(&[], &[]);
        assert!(parse_exchange_payload(&payload).is_ok());
    }

    #[test]
    fn parses_v2_payload() {
        // Manually build a v2 payload
        let mut buf = Vec::new();
        buf.write_u8(2).unwrap(); // version 2
        buf.write_u16::<LittleEndian>(1).unwrap(); // 1 file
        buf.write_all(&[1u8; 16]).unwrap(); // hash
        buf.write_u64::<LittleEndian>(5000).unwrap(); // size
        buf.write_u16::<LittleEndian>(1).unwrap(); // 1 source
        buf.write_all(&Ipv4Addr::new(80, 1, 2, 3).octets()).unwrap();
        buf.write_u16::<LittleEndian>(4662).unwrap();

        let result = parse_exchange_payload(&buf).unwrap();
        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].sources.len(), 1);
        assert_eq!(result.files[0].sources[0].tcp_port, 4662);
        assert_eq!(result.files[0].sources[0].udp_port, 0);
        assert_eq!(result.files[0].sources[0].flags, 0);
        assert_eq!(result.files[0].aich_root, None);
        assert!(result.peers.is_empty());
    }

    #[test]
    fn file_count_header_matches_actual_entries() {
        let mut entries = Vec::new();
        for i in 0..250u8 {
            let mut hash = [0u8; 16];
            hash[0] = i;
            hash[1] = i.wrapping_add(1);
            entries.push(EmberFileEntry {
                file_hash: hash,
                file_size: 1000,
                aich_root: None,
                sources: vec![make_source(80, 1, 2, i, 4662)],
            });
        }
        let payload = build_exchange_payload(&entries, &[]);
        assert!(payload.len() <= MAX_EPX_PAYLOAD);

        let mut cursor = Cursor::new(&payload);
        let _version = cursor.read_u8().unwrap();
        let header_count = cursor.read_u16::<LittleEndian>().unwrap() as usize;

        let result = parse_exchange_payload(&payload).unwrap();
        assert_eq!(result.files.len(), header_count);
        assert!(header_count <= MAX_EPX_FILES);
    }

    #[test]
    fn payload_never_exceeds_max_size() {
        let mut entries = Vec::new();
        for i in 0..200u8 {
            let mut hash = [0u8; 16];
            hash[0] = i;
            let sources: Vec<EmberSource> = (0..100u16)
                .map(|j| EmberSource {
                    ip: Ipv4Addr::new(80, i, (j >> 8) as u8, (j & 0xFF) as u8),
                    tcp_port: 4662 + j,
                    udp_port: 4672 + j,
                    flags: 0,
                })
                .collect();
            entries.push(EmberFileEntry {
                file_hash: hash,
                file_size: 1_000_000,
                aich_root: Some([0xBB; 20]),
                sources,
            });
        }
        let payload = build_exchange_payload(&entries, &[]);
        assert!(payload.len() <= MAX_EPX_PAYLOAD);
        let result = parse_exchange_payload(&payload).unwrap();
        assert!(!result.files.is_empty());
    }

    #[test]
    fn filters_private_and_link_local_ips() {
        let entries = vec![EmberFileEntry {
            file_hash: [3u8; 16],
            file_size: 500,
            aich_root: None,
            sources: vec![
                EmberSource { ip: Ipv4Addr::new(192, 168, 1, 1), tcp_port: 4662, udp_port: 0, flags: 0 },
                EmberSource { ip: Ipv4Addr::new(10, 0, 0, 1), tcp_port: 4663, udp_port: 0, flags: 0 },
                EmberSource { ip: Ipv4Addr::new(172, 16, 0, 1), tcp_port: 4664, udp_port: 0, flags: 0 },
                EmberSource { ip: Ipv4Addr::new(169, 254, 1, 1), tcp_port: 4665, udp_port: 0, flags: 0 },
                EmberSource { ip: Ipv4Addr::new(127, 0, 0, 1), tcp_port: 4666, udp_port: 0, flags: 0 },
                EmberSource { ip: Ipv4Addr::new(44, 55, 66, 77), tcp_port: 4667, udp_port: 4677, flags: 0 },
            ],
        }];
        let payload = build_exchange_payload(&entries, &[]);
        let result = parse_exchange_payload(&payload).unwrap();
        assert_eq!(result.files[0].sources.len(), 1);
        assert_eq!(result.files[0].sources[0].ip, Ipv4Addr::new(44, 55, 66, 77));
    }

    #[test]
    fn filters_private_peers() {
        let peers = vec![
            EmberPeer { ip: Ipv4Addr::new(192, 168, 1, 1), tcp_port: 4662 },
            EmberPeer { ip: Ipv4Addr::new(44, 55, 66, 77), tcp_port: 4662 },
        ];
        let payload = build_exchange_payload(&[], &peers);
        let result = parse_exchange_payload(&payload).unwrap();
        assert_eq!(result.peers.len(), 1);
        assert_eq!(result.peers[0].ip, Ipv4Addr::new(44, 55, 66, 77));
    }

    #[test]
    fn full_round_trip_all_features() {
        let aich = [0xCC; 20];
        let entries = vec![
            EmberFileEntry {
                file_hash: [1u8; 16],
                file_size: 50000,
                aich_root: Some(aich),
                sources: vec![
                    EmberSource {
                        ip: Ipv4Addr::new(80, 1, 2, 3),
                        tcp_port: 4662,
                        udp_port: 4672,
                        flags: SOURCE_FLAG_OBFUSCATION,
                    },
                ],
            },
            EmberFileEntry {
                file_hash: [2u8; 16],
                file_size: 100000,
                aich_root: None,
                sources: vec![
                    EmberSource {
                        ip: Ipv4Addr::new(90, 1, 2, 3),
                        tcp_port: 4662,
                        udp_port: 0,
                        flags: SOURCE_FLAG_FIREWALLED,
                    },
                ],
            },
        ];
        let peers = vec![
            EmberPeer { ip: Ipv4Addr::new(33, 44, 55, 66), tcp_port: 4662 },
        ];
        let payload = build_exchange_payload(&entries, &peers);
        let result = parse_exchange_payload(&payload).unwrap();

        assert_eq!(result.files.len(), 2);
        assert_eq!(result.files[0].aich_root, Some(aich));
        assert_eq!(result.files[0].sources[0].flags, SOURCE_FLAG_OBFUSCATION);
        assert_eq!(result.files[0].sources[0].udp_port, 4672);
        assert_eq!(result.files[1].aich_root, None);
        assert_eq!(result.files[1].sources[0].flags, SOURCE_FLAG_FIREWALLED);
        assert_eq!(result.peers.len(), 1);
        assert_eq!(result.peers[0].ip, Ipv4Addr::new(33, 44, 55, 66));
    }
}
