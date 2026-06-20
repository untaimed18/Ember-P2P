use std::io::{self, Cursor, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use flate2::read::{DeflateDecoder, ZlibDecoder};
use flate2::write::ZlibEncoder;
use flate2::Compression;

use super::types::*;

// Protocol headers
pub const OP_KADEMLIAHEADER: u8 = 0xE4;
pub const OP_KADEMLIAPACKEDPROT: u8 = 0xE5;

// KAD2 opcodes
pub const KADEMLIA2_BOOTSTRAP_REQ: u8 = 0x01;
pub const KADEMLIA2_BOOTSTRAP_RES: u8 = 0x09;
pub const KADEMLIA2_HELLO_REQ: u8 = 0x11;
pub const KADEMLIA2_HELLO_RES: u8 = 0x19;
pub const KADEMLIA2_HELLO_RES_ACK: u8 = 0x22;
pub const KADEMLIA2_REQ: u8 = 0x21;
pub const KADEMLIA2_RES: u8 = 0x29;
pub const KADEMLIA2_SEARCH_KEY_REQ: u8 = 0x33;
pub const KADEMLIA2_SEARCH_SOURCE_REQ: u8 = 0x34;
pub const KADEMLIA2_SEARCH_NOTES_REQ: u8 = 0x35;
pub const KADEMLIA2_SEARCH_RES: u8 = 0x3B;
pub const KADEMLIA2_PUBLISH_KEY_REQ: u8 = 0x43;
pub const KADEMLIA2_PUBLISH_SOURCE_REQ: u8 = 0x44;
pub const KADEMLIA2_PUBLISH_NOTES_REQ: u8 = 0x45;
pub const KADEMLIA2_PUBLISH_RES: u8 = 0x4B;
pub const KADEMLIA2_PUBLISH_RES_ACK: u8 = 0x4C;
pub const KADEMLIA_FIREWALLED_REQ: u8 = 0x50;
pub const KADEMLIA_FIREWALLED_RES: u8 = 0x58;
pub const KADEMLIA_FINDBUDDY_REQ: u8 = 0x51;
pub const KADEMLIA_FINDBUDDY_RES: u8 = 0x5A;
pub const KADEMLIA_FIREWALLED_ACK_RES: u8 = 0x59;
pub const KADEMLIA2_PING: u8 = 0x60;
pub const KADEMLIA2_PONG: u8 = 0x61;
pub const KADEMLIA2_FIREWALLUDP: u8 = 0x62;

// Legacy Kad1.0 opcodes (for decode fallback)
pub const KADEMLIA_BOOTSTRAP_REQ_OLD: u8 = 0x00;
pub const KADEMLIA_BOOTSTRAP_RES_OLD: u8 = 0x08;
pub const KADEMLIA_HELLO_REQ_OLD: u8 = 0x10;
pub const KADEMLIA_HELLO_RES_OLD: u8 = 0x18;
pub const KADEMLIA_REQ_OLD: u8 = 0x20;
pub const KADEMLIA_RES_OLD: u8 = 0x28;
pub const KADEMLIA_SEARCH_REQ_OLD: u8 = 0x30;
pub const KADEMLIA_SEARCH_NOTES_REQ_OLD: u8 = 0x32;
pub const KADEMLIA_SEARCH_RES_OLD: u8 = 0x38;
pub const KADEMLIA_SEARCH_NOTES_RES_OLD: u8 = 0x3A;
pub const KADEMLIA_PUBLISH_REQ_OLD: u8 = 0x40;
pub const KADEMLIA_PUBLISH_NOTES_REQ_OLD: u8 = 0x42;
pub const KADEMLIA_PUBLISH_RES_OLD: u8 = 0x48;
pub const KADEMLIA_PUBLISH_NOTES_RES_OLD: u8 = 0x4A;

pub const KADEMLIA_CALLBACK_REQ: u8 = 0x52;

// Firewalled2 opcode
pub const KADEMLIA_FIREWALLED2_REQ: u8 = 0x53;

// Search types for KADEMLIA2_REQ
pub const KADEMLIA_FIND_VALUE: u8 = 0x02;
pub const KADEMLIA_STORE: u8 = 0x04;
pub const KADEMLIA_FIND_NODE: u8 = 0x0B;

pub const UDP_KAD_MAXFRAGMENT: usize = 1420;

/// Maximum allowed decompressed payload size (512 KiB) to prevent decompression bombs.
const MAX_DECOMPRESSED_SIZE: usize = 512 * 1024;

#[derive(Debug, Clone)]
pub enum KadMessage {
    BootstrapReq,
    BootstrapRes {
        sender_id: KadId,
        tcp_port: u16,
        version: u8,
        contacts: Vec<KadContact>,
    },
    HelloReq {
        sender_id: KadId,
        tcp_port: u16,
        version: u8,
        tags: Vec<KadTag>,
    },
    HelloRes {
        sender_id: KadId,
        tcp_port: u16,
        version: u8,
        tags: Vec<KadTag>,
    },
    HelloResAck {
        sender_id: KadId,
        tags: Vec<KadTag>,
    },
    KadReq {
        search_type: u8,
        target: KadId,
        receiver: KadId,
    },
    KadRes {
        target: KadId,
        contacts: Vec<KadContact>,
    },
    SearchKeyReq {
        target: KadId,
        start_position: u16,
        search_terms: Vec<u8>,
    },
    SearchSourceReq {
        target: KadId,
        start_position: u16,
        file_size: u64,
    },
    SearchNotesReq {
        target: KadId,
        file_size: u64,
    },
    SearchRes {
        sender_id: KadId,
        target: KadId,
        results: Vec<SearchResultEntry>,
    },
    PublishKeyReq {
        target: KadId,
        entries: Vec<PublishEntry>,
    },
    PublishSourceReq {
        target: KadId,
        sender_id: KadId,
        tags: Vec<KadTag>,
    },
    PublishNotesReq {
        target: KadId,
        sender_id: KadId,
        tags: Vec<KadTag>,
    },
    PublishRes {
        target: KadId,
        load: u8,
        /// Set when the sender included the optional trailing options byte
        /// with bit0 set, i.e. it explicitly requested a
        /// `KADEMLIA2_PUBLISH_RES_ACK`. eMule documents this byte as "for
        /// future use" and never sets it, and we never set it on our own
        /// outgoing `PublishRes`, so the encoder ignores this field (eMule's
        /// storage-node response is always a bare 17-byte target+load). It is
        /// only consulted on the decode/handler path to decide whether to ack.
        request_ack: bool,
    },
    PublishResAck,
    Ping,
    Pong {
        udp_port: u16,
    },
    FirewalledReq {
        tcp_port: u16,
    },
    Firewalled2Req {
        tcp_port: u16,
        user_hash: [u8; 16],
        connect_options: u8,
    },
    FirewalledRes {
        ip: u32,
    },
    FirewallUdp {
        error_code: u8,
        udp_port: u16,
    },
    FindBuddyReq {
        buddy_id: KadId,
        user_id: KadId,
        tcp_port: u16,
    },
    FindBuddyRes {
        buddy_id: KadId,
        user_hash: [u8; 16],
        tcp_port: u16,
        connect_options: u8,
    },
    CallbackReq {
        buddy_id: KadId,
        file_id: KadId,
        tcp_port: u16,
    },
    /// Acknowledgement from a peer that received our KADEMLIA_FIREWALLED_RES (null payload)
    FirewalledAckRes,
    /// eMule-compatible handling for legacy Kad1 opcodes: ignore silently.
    IgnoredLegacy {
        opcode: u8,
    },
}

#[derive(Debug, Clone)]
pub struct SearchResultEntry {
    pub id: KadId,
    pub tags: Vec<KadTag>,
}

#[derive(Debug, Clone)]
pub struct PublishEntry {
    pub id: KadId,
    pub tags: Vec<KadTag>,
}

/// Decode a raw UDP packet into a KadMessage.
pub fn decode_packet(data: &[u8]) -> io::Result<KadMessage> {
    if data.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty packet"));
    }

    let header = data[0];
    let payload = match header {
        OP_KADEMLIAHEADER => data[1..].to_vec(),
        OP_KADEMLIAPACKEDPROT => {
            if data.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed packet too short",
                ));
            }
            let opcode = data[1];
            let compressed = &data[2..];
            let mut decompressed = Vec::new();

            let decompress_result = {
                let mut decoder = ZlibDecoder::new(compressed);
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = match decoder.read(&mut buf) {
                        Ok(0) => break Ok(()),
                        Ok(n) => n,
                        Err(e) => break Err(e),
                    };
                    decompressed.extend_from_slice(&buf[..n]);
                    if decompressed.len() > MAX_DECOMPRESSED_SIZE {
                        break Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "decompressed KAD packet exceeds size limit",
                        ));
                    }
                }
            };

            if matches!(&decompress_result, Err(e) if matches!(e.kind(), io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof | io::ErrorKind::Other))
            {
                decompressed.clear();
                let mut decoder2 = DeflateDecoder::new(compressed);
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = decoder2.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    decompressed.extend_from_slice(&buf[..n]);
                    if decompressed.len() > MAX_DECOMPRESSED_SIZE {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "decompressed KAD packet exceeds size limit",
                        ));
                    }
                }
            } else if let Err(e) = decompress_result {
                return Err(e);
            }

            let mut result = Vec::with_capacity(1 + decompressed.len());
            result.push(opcode);
            result.extend_from_slice(&decompressed);
            result
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown kad header: 0x{:02X}", header),
            ));
        }
    };

    if payload.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty payload"));
    }

    let opcode = payload[0];
    let mut cursor = Cursor::new(&payload[1..]);

    decode_message(opcode, &mut cursor)
}

fn decode_message(opcode: u8, cursor: &mut Cursor<&[u8]>) -> io::Result<KadMessage> {
    match opcode {
        KADEMLIA2_BOOTSTRAP_REQ => Ok(KadMessage::BootstrapReq),

        KADEMLIA2_BOOTSTRAP_RES => {
            let sender_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            let version = cursor.read_u8()?;
            // Cap the parsed count at 200 (sanity bound + allocation cap), then
            // read exactly that many fixed-size contacts, failing on truncation
            // rather than silently accepting a partial list as complete.
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let take = count.min(200);
            let mut contacts = Vec::with_capacity(take);
            for _ in 0..take {
                contacts.push(KadContact::read_from(cursor)?);
            }
            Ok(KadMessage::BootstrapRes {
                sender_id,
                tcp_port,
                version,
                contacts,
            })
        }

        KADEMLIA2_HELLO_REQ => {
            let sender_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            let version = cursor.read_u8()?;
            let tags = read_tag_list(cursor)?;
            Ok(KadMessage::HelloReq {
                sender_id,
                tcp_port,
                version,
                tags,
            })
        }

        KADEMLIA2_HELLO_RES => {
            let sender_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            let version = cursor.read_u8()?;
            let tags = read_tag_list(cursor)?;
            Ok(KadMessage::HelloRes {
                sender_id,
                tcp_port,
                version,
                tags,
            })
        }

        KADEMLIA2_HELLO_RES_ACK => {
            let sender_id = KadId::read_from(cursor)?;
            let tags = read_tag_list(cursor)?;
            Ok(KadMessage::HelloResAck { sender_id, tags })
        }

        KADEMLIA2_REQ => {
            let search_type = cursor.read_u8()?;
            let target = KadId::read_from(cursor)?;
            let receiver = KadId::read_from(cursor)?;
            Ok(KadMessage::KadReq {
                search_type,
                target,
                receiver,
            })
        }

        KADEMLIA2_RES => {
            let target = KadId::read_from(cursor)?;
            // `count` is a u8 (≤ 255) and each contact is a fixed 25-byte
            // record, so `with_capacity(count)` is not an allocation risk.
            // Read exactly `count` contacts and fail (via `?`) if the packet is
            // truncated — previously a short/hostile packet was silently
            // accepted as a partial-but-"complete" contact list.
            let count = cursor.read_u8()? as usize;
            let mut contacts = Vec::with_capacity(count);
            for _ in 0..count {
                contacts.push(KadContact::read_from(cursor)?);
            }
            Ok(KadMessage::KadRes { target, contacts })
        }

        KADEMLIA2_SEARCH_KEY_REQ => {
            let target = KadId::read_from(cursor)?;
            let start_position = if cursor.position() < cursor.get_ref().len() as u64 {
                cursor.read_u16::<LittleEndian>().unwrap_or(0)
            } else {
                0
            };
            let search_terms = if start_position & 0x8000 != 0 {
                let mut terms = Vec::new();
                cursor.read_to_end(&mut terms).unwrap_or(0);
                terms
            } else {
                Vec::new()
            };
            Ok(KadMessage::SearchKeyReq {
                target,
                start_position: start_position & 0x7FFF,
                search_terms,
            })
        }

        KADEMLIA2_SEARCH_SOURCE_REQ => {
            let target = KadId::read_from(cursor)?;
            let start_position = cursor.read_u16::<LittleEndian>()?;
            let file_size = cursor.read_u64::<LittleEndian>()?;
            Ok(KadMessage::SearchSourceReq {
                target,
                start_position,
                file_size,
            })
        }

        KADEMLIA2_SEARCH_RES => {
            let sender_id = KadId::read_from(cursor)?;
            let target = KadId::read_from(cursor)?;
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let capped = count.min(300);
            if count > 300 {
                tracing::warn!("KAD SEARCH_RES declared {count} results, capping parse to 300");
            }
            let mut results = Vec::with_capacity(capped);
            for _ in 0..capped {
                let id = KadId::read_from(cursor)?;
                let tags = read_tag_list(cursor)?;
                results.push(SearchResultEntry { id, tags });
            }
            Ok(KadMessage::SearchRes {
                sender_id,
                target,
                results,
            })
        }

        KADEMLIA2_PUBLISH_KEY_REQ => {
            let target = KadId::read_from(cursor)?;
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let mut entries = Vec::with_capacity(count.min(50));
            for _ in 0..count.min(50) {
                let id = KadId::read_from(cursor)?;
                let tags = read_tag_list(cursor)?;
                entries.push(PublishEntry { id, tags });
            }
            Ok(KadMessage::PublishKeyReq { target, entries })
        }

        KADEMLIA2_PUBLISH_SOURCE_REQ => {
            let target = KadId::read_from(cursor)?;
            let sender_id = KadId::read_from(cursor)?;
            let tags = read_tag_list(cursor)?;
            Ok(KadMessage::PublishSourceReq {
                target,
                sender_id,
                tags,
            })
        }

        KADEMLIA2_PUBLISH_RES => {
            let target = KadId::read_from(cursor)?;
            let load = cursor.read_u8()?;
            // Optional trailing options byte (eMule `Process_KADEMLIA2_PUBLISH_RES`,
            // "for future use"): bit0 requests a KADEMLIA2_PUBLISH_RES_ACK.
            let request_ack = if cursor.position() < cursor.get_ref().len() as u64 {
                (cursor.read_u8().unwrap_or(0) & 0x01) != 0
            } else {
                false
            };
            Ok(KadMessage::PublishRes {
                target,
                load,
                request_ack,
            })
        }

        KADEMLIA2_SEARCH_NOTES_REQ => {
            let target = KadId::read_from(cursor)?;
            let file_size = if cursor.position() < cursor.get_ref().len() as u64 {
                cursor.read_u64::<LittleEndian>().unwrap_or(0)
            } else {
                0
            };
            Ok(KadMessage::SearchNotesReq { target, file_size })
        }

        KADEMLIA2_PUBLISH_NOTES_REQ => {
            let target = KadId::read_from(cursor)?;
            let sender_id = KadId::read_from(cursor)?;
            let tags = read_tag_list(cursor)?;
            Ok(KadMessage::PublishNotesReq {
                target,
                sender_id,
                tags,
            })
        }

        KADEMLIA2_PUBLISH_RES_ACK => Ok(KadMessage::PublishResAck),

        KADEMLIA2_PING => Ok(KadMessage::Ping),

        KADEMLIA2_PONG => {
            let udp_port = if cursor.position() < cursor.get_ref().len() as u64 {
                cursor.read_u16::<LittleEndian>().unwrap_or(0)
            } else {
                0
            };
            Ok(KadMessage::Pong { udp_port })
        }

        KADEMLIA_FIREWALLED_REQ => {
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::FirewalledReq { tcp_port })
        }

        KADEMLIA_FIREWALLED2_REQ => {
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            let mut user_hash = [0u8; 16];
            cursor.read_exact(&mut user_hash)?;
            let connect_options = cursor.read_u8()?;
            Ok(KadMessage::Firewalled2Req {
                tcp_port,
                user_hash,
                connect_options,
            })
        }

        KADEMLIA_FIREWALLED_RES => {
            let ip = cursor.read_u32::<LittleEndian>()?;
            Ok(KadMessage::FirewalledRes { ip })
        }

        KADEMLIA2_FIREWALLUDP => {
            let error_code = cursor.read_u8()?;
            let udp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::FirewallUdp {
                error_code,
                udp_port,
            })
        }

        KADEMLIA_FINDBUDDY_REQ => {
            let buddy_id = KadId::read_from(cursor)?;
            let user_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::FindBuddyReq {
                buddy_id,
                user_id,
                tcp_port,
            })
        }

        KADEMLIA_FINDBUDDY_RES => {
            let buddy_id = KadId::read_from(cursor)?;
            let mut user_hash = [0u8; 16];
            cursor.read_exact(&mut user_hash)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            let connect_options = if cursor.position() < cursor.get_ref().len() as u64 {
                cursor.read_u8().unwrap_or(0)
            } else {
                0
            };
            Ok(KadMessage::FindBuddyRes {
                buddy_id,
                user_hash,
                tcp_port,
                connect_options,
            })
        }

        KADEMLIA_CALLBACK_REQ => {
            let buddy_id = KadId::read_from(cursor)?;
            let file_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::CallbackReq {
                buddy_id,
                file_id,
                tcp_port,
            })
        }

        KADEMLIA_FIREWALLED_ACK_RES => Ok(KadMessage::FirewalledAckRes),

        // Legacy Kad1.0 opcodes - decode into equivalent Kad2 messages where possible
        KADEMLIA_BOOTSTRAP_REQ_OLD => Ok(KadMessage::BootstrapReq),
        KADEMLIA_BOOTSTRAP_RES_OLD => {
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let take = count.min(200);
            let mut contacts = Vec::with_capacity(take);
            for _ in 0..take {
                contacts.push(KadContact::read_from(cursor)?);
            }
            Ok(KadMessage::BootstrapRes {
                sender_id: KadId::zero(),
                tcp_port: 0,
                version: 1,
                contacts,
            })
        }
        // Legacy Kad1 search/publish responses are still seen in the wild —
        // must be matched before the IgnoredLegacy catch-all below.
        KADEMLIA_SEARCH_RES_OLD | KADEMLIA_SEARCH_NOTES_RES_OLD => {
            let target = KadId::read_from(cursor)?;
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let mut results = Vec::with_capacity(count.min(300));
            for _ in 0..count.min(300) {
                let id = KadId::read_from(cursor)?;
                let tags = read_tag_list(cursor)?;
                results.push(SearchResultEntry { id, tags });
            }
            Ok(KadMessage::SearchRes {
                sender_id: KadId::zero(),
                target,
                results,
            })
        }

        KADEMLIA_PUBLISH_RES_OLD => {
            let target = KadId::read_from(cursor)?;
            Ok(KadMessage::PublishRes {
                target,
                load: 0,
                request_ack: false,
            })
        }

        KADEMLIA_HELLO_REQ_OLD
        | KADEMLIA_HELLO_RES_OLD
        | KADEMLIA_REQ_OLD
        | KADEMLIA_RES_OLD
        | KADEMLIA_SEARCH_REQ_OLD
        | KADEMLIA_SEARCH_NOTES_REQ_OLD
        | KADEMLIA_PUBLISH_REQ_OLD
        | KADEMLIA_PUBLISH_NOTES_REQ_OLD
        | KADEMLIA_PUBLISH_NOTES_RES_OLD => Ok(KadMessage::IgnoredLegacy { opcode }),

        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown kad opcode: 0x{:02X}", opcode),
        )),
    }
}

/// Encode a KadMessage into a raw UDP packet.
pub fn encode_packet(msg: &KadMessage) -> io::Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(256);
    encode_message(msg, &mut payload)?;

    // Wire format: [header][opcode][body]
    // Compressed:  [0xE5][opcode][zlib(body)]   -- opcode is NOT compressed
    // Uncompressed:[0xE4][opcode][body]
    if payload.len() > UDP_KAD_MAXFRAGMENT - 1 {
        let opcode = payload[0];
        let body = &payload[1..];
        let mut compressed_body = Vec::with_capacity(body.len());
        {
            let mut encoder = ZlibEncoder::new(&mut compressed_body, Compression::best());
            encoder.write_all(body)?;
            encoder.finish()?;
        }
        if 2 + compressed_body.len() > UDP_KAD_MAXFRAGMENT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed KAD packet still exceeds UDP fragment limit",
            ));
        }
        let mut packet = Vec::with_capacity(2 + compressed_body.len());
        packet.push(OP_KADEMLIAPACKEDPROT);
        packet.push(opcode);
        packet.extend_from_slice(&compressed_body);
        Ok(packet)
    } else {
        let mut packet = Vec::with_capacity(1 + payload.len());
        packet.push(OP_KADEMLIAHEADER);
        packet.extend_from_slice(&payload);
        Ok(packet)
    }
}

fn encode_message(msg: &KadMessage, out: &mut Vec<u8>) -> io::Result<()> {
    match msg {
        KadMessage::BootstrapReq => {
            out.write_u8(KADEMLIA2_BOOTSTRAP_REQ)?;
        }

        KadMessage::BootstrapRes {
            sender_id,
            tcp_port,
            version,
            contacts,
        } => {
            out.write_u8(KADEMLIA2_BOOTSTRAP_RES)?;
            sender_id.write_to(out)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
            out.write_u8(*version)?;
            out.write_u16::<LittleEndian>(contacts.len() as u16)?;
            for c in contacts {
                c.write_to(out)?;
            }
        }

        KadMessage::HelloReq {
            sender_id,
            tcp_port,
            version,
            tags,
        } => {
            out.write_u8(KADEMLIA2_HELLO_REQ)?;
            sender_id.write_to(out)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
            out.write_u8(*version)?;
            write_tag_list(out, tags)?;
        }

        KadMessage::HelloRes {
            sender_id,
            tcp_port,
            version,
            tags,
        } => {
            out.write_u8(KADEMLIA2_HELLO_RES)?;
            sender_id.write_to(out)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
            out.write_u8(*version)?;
            write_tag_list(out, tags)?;
        }

        KadMessage::HelloResAck { sender_id, tags } => {
            out.write_u8(KADEMLIA2_HELLO_RES_ACK)?;
            sender_id.write_to(out)?;
            write_tag_list(out, tags)?;
        }

        KadMessage::KadReq {
            search_type,
            target,
            receiver,
        } => {
            out.write_u8(KADEMLIA2_REQ)?;
            out.write_u8(*search_type)?;
            target.write_to(out)?;
            receiver.write_to(out)?;
        }

        KadMessage::KadRes { target, contacts } => {
            out.write_u8(KADEMLIA2_RES)?;
            target.write_to(out)?;
            let count = contacts.len().min(255);
            out.write_u8(count as u8)?;
            for c in contacts.iter().take(count) {
                c.write_to(out)?;
            }
        }

        KadMessage::SearchKeyReq {
            target,
            start_position,
            search_terms,
        } => {
            out.write_u8(KADEMLIA2_SEARCH_KEY_REQ)?;
            target.write_to(out)?;
            if search_terms.is_empty() {
                out.write_u16::<LittleEndian>(*start_position)?;
            } else {
                out.write_u16::<LittleEndian>(*start_position | 0x8000)?;
                out.write_all(search_terms)?;
            }
        }

        KadMessage::SearchSourceReq {
            target,
            start_position,
            file_size,
        } => {
            out.write_u8(KADEMLIA2_SEARCH_SOURCE_REQ)?;
            target.write_to(out)?;
            out.write_u16::<LittleEndian>(*start_position)?;
            out.write_u64::<LittleEndian>(*file_size)?;
        }

        KadMessage::SearchRes {
            sender_id,
            target,
            results,
        } => {
            out.write_u8(KADEMLIA2_SEARCH_RES)?;
            sender_id.write_to(out)?;
            target.write_to(out)?;
            out.write_u16::<LittleEndian>(results.len() as u16)?;
            for r in results {
                r.id.write_to(out)?;
                write_tag_list(out, &r.tags)?;
            }
        }

        KadMessage::PublishKeyReq { target, entries } => {
            out.write_u8(KADEMLIA2_PUBLISH_KEY_REQ)?;
            target.write_to(out)?;
            out.write_u16::<LittleEndian>(entries.len() as u16)?;
            for e in entries {
                e.id.write_to(out)?;
                write_tag_list(out, &e.tags)?;
            }
        }

        KadMessage::PublishSourceReq {
            target,
            sender_id,
            tags,
        } => {
            out.write_u8(KADEMLIA2_PUBLISH_SOURCE_REQ)?;
            target.write_to(out)?;
            sender_id.write_to(out)?;
            write_tag_list(out, tags)?;
        }

        KadMessage::PublishRes { target, load, .. } => {
            out.write_u8(KADEMLIA2_PUBLISH_RES)?;
            target.write_to(out)?;
            out.write_u8(*load)?;
            // No trailing options byte: like eMule's storage-node response
            // this is always a bare 17-byte target+load and never requests an
            // ack (`request_ack` is decode-only).
        }

        KadMessage::SearchNotesReq { target, file_size } => {
            out.write_u8(KADEMLIA2_SEARCH_NOTES_REQ)?;
            target.write_to(out)?;
            out.write_u64::<LittleEndian>(*file_size)?;
        }

        KadMessage::PublishNotesReq {
            target,
            sender_id,
            tags,
        } => {
            out.write_u8(KADEMLIA2_PUBLISH_NOTES_REQ)?;
            target.write_to(out)?;
            sender_id.write_to(out)?;
            write_tag_list(out, tags)?;
        }

        KadMessage::PublishResAck => {
            out.write_u8(KADEMLIA2_PUBLISH_RES_ACK)?;
        }

        KadMessage::Ping => {
            out.write_u8(KADEMLIA2_PING)?;
        }

        KadMessage::Pong { udp_port } => {
            out.write_u8(KADEMLIA2_PONG)?;
            out.write_u16::<LittleEndian>(*udp_port)?;
        }

        KadMessage::FirewalledReq { tcp_port } => {
            out.write_u8(KADEMLIA_FIREWALLED_REQ)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
        }

        KadMessage::Firewalled2Req {
            tcp_port,
            user_hash,
            connect_options,
        } => {
            out.write_u8(KADEMLIA_FIREWALLED2_REQ)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
            out.write_all(user_hash)?;
            out.write_u8(*connect_options)?;
        }

        KadMessage::FirewalledRes { ip } => {
            out.write_u8(KADEMLIA_FIREWALLED_RES)?;
            out.write_u32::<LittleEndian>(*ip)?;
        }

        KadMessage::FirewallUdp {
            error_code,
            udp_port,
        } => {
            out.write_u8(KADEMLIA2_FIREWALLUDP)?;
            out.write_u8(*error_code)?;
            out.write_u16::<LittleEndian>(*udp_port)?;
        }

        KadMessage::FindBuddyReq {
            buddy_id,
            user_id,
            tcp_port,
        } => {
            out.write_u8(KADEMLIA_FINDBUDDY_REQ)?;
            buddy_id.write_to(out)?;
            user_id.write_to(out)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
        }

        KadMessage::FindBuddyRes {
            buddy_id,
            user_hash,
            tcp_port,
            connect_options,
        } => {
            out.write_u8(KADEMLIA_FINDBUDDY_RES)?;
            buddy_id.write_to(out)?;
            out.write_all(user_hash)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
            out.write_u8(*connect_options)?;
        }

        KadMessage::CallbackReq {
            buddy_id,
            file_id,
            tcp_port,
        } => {
            out.write_u8(KADEMLIA_CALLBACK_REQ)?;
            buddy_id.write_to(out)?;
            file_id.write_to(out)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
        }

        KadMessage::FirewalledAckRes => {
            out.write_u8(KADEMLIA_FIREWALLED_ACK_RES)?;
        }

        KadMessage::IgnoredLegacy { .. } => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot encode legacy-ignored Kad message",
            ));
        }
    }

    Ok(())
}

/// Convenience: build a KADEMLIA2_HELLO_REQ wire packet.
pub fn build_hello_req(
    sender_id: &KadId,
    tcp_port: u16,
    version: u8,
    tags: &[KadTag],
) -> io::Result<Vec<u8>> {
    encode_packet(&KadMessage::HelloReq {
        sender_id: *sender_id,
        tcp_port,
        version,
        tags: tags.to_vec(),
    })
}

/// Numeric / string constraints that eMule AND-combines with the keyword
/// expression in a search request. Mirrors the attributes appended by
/// `GetSearchPacket` (eMule `SearchResultsWnd.cpp`): file type, extension,
/// min/max size and minimum availability.
///
/// Encoding these into the wire expression lets the remote node (eD2k server
/// or Kad peer) filter *before* it truncates to its result cap (servers reply
/// with at most ~200/300 hits), which a purely client-side filter cannot do —
/// a tight size filter would otherwise discard most of a single unfiltered
/// page and surface very few matches even when many exist.
#[derive(Debug, Default, Clone, Copy)]
pub struct SearchConstraints<'a> {
    /// eD2k file-type label (e.g. "Video", "Audio") — FT_FILETYPE.
    pub file_type: Option<&'a str>,
    /// File extension without a leading dot (e.g. "mkv") — FT_FILEFORMAT.
    pub file_extension: Option<&'a str>,
    /// Minimum file size in bytes (inclusive) — FT_FILESIZE >=.
    pub min_size: Option<u64>,
    /// Maximum file size in bytes (inclusive) — FT_FILESIZE <=.
    pub max_size: Option<u64>,
    /// Minimum source/availability count (inclusive) — FT_SOURCES >=.
    pub min_availability: Option<u32>,
}

// eD2k search comparison operators (eMule Opcodes.h ED2K_SEARCH_OP_*).
const ED2K_SEARCH_OP_GREATER_EQUAL: u8 = 3;
const ED2K_SEARCH_OP_LESS_EQUAL: u8 = 4;
// eD2k meta-tag IDs (eMule Opcodes.h FT_*). FT_FILESIZE/FILETYPE/SOURCES are
// re-exported from `types` as TAG_*; FT_FILEFORMAT has no TAG_* alias.
const FT_FILEFORMAT: u8 = 0x04;

/// Build a binary search expression for keywords plus optional constraints
/// (eMule AND-tree format).
///
/// For N keywords, builds a left-leaning AND tree:
///   AND(AND(kw1, kw2), kw3) for 3 keywords, etc.
/// A single keyword produces a plain string leaf. Any present constraints
/// (type / extension / size / availability) are each emitted as their own
/// leaf and AND-combined with the keyword tree, matching eMule's
/// `GetSearchPacket`.
///
/// Returns empty only when there are zero keywords AND no constraints.
///
/// Wire format (eMule `CSearchExprTarget`):
///   0x00 0x00      = AND operator (followed by left child, right child)
///   0x01           = String leaf  (u16-len UTF-8 string)
///   0x02           = Meta-string  (u16-len value, u16-len tag-name, tag id)
///   0x03 / 0x08    = Numeric u32/u64 (value, 1-byte op, u16-len tag-name, tag id)
pub fn build_search_expression(keywords: &[String], constraints: &SearchConstraints) -> Vec<u8> {
    fn write_string_leaf(buf: &mut Vec<u8>, s: &str) {
        buf.push(0x01);
        let bytes = s.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(bytes);
    }

    fn write_meta_string(buf: &mut Vec<u8>, value: &str, tag_id: u8) {
        buf.push(0x02); // META_STRING
        let bytes = value.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(bytes);
        buf.extend_from_slice(&1u16.to_le_bytes()); // tag name length = 1
        buf.push(tag_id);
    }

    // Numeric leaf. eMule uses the 32-bit form (type 0x03) when the value
    // fits in a u32 and the 64-bit form (type 0x08) otherwise; Kad searches
    // always advertise 64-bit support, so a >4 GiB size constraint is encoded
    // losslessly rather than clamped.
    fn write_numeric_leaf(buf: &mut Vec<u8>, value: u64, op: u8, tag_id: u8) {
        if value > u32::MAX as u64 {
            buf.push(0x08);
            buf.extend_from_slice(&value.to_le_bytes());
        } else {
            buf.push(0x03);
            buf.extend_from_slice(&(value as u32).to_le_bytes());
        }
        buf.push(op);
        buf.extend_from_slice(&1u16.to_le_bytes()); // tag name length = 1
        buf.push(tag_id);
    }

    fn write_keyword_tree(buf: &mut Vec<u8>, keywords: &[String], end: usize) {
        if end == 1 {
            write_string_leaf(buf, &keywords[0]);
            return;
        }
        buf.push(0x00); // operator
        buf.push(0x00); // AND
        if end == 2 {
            write_string_leaf(buf, &keywords[0]);
            write_string_leaf(buf, &keywords[1]);
        } else {
            write_keyword_tree(buf, keywords, end - 1);
            write_string_leaf(buf, &keywords[end - 1]);
        }
    }

    // Each operand of the top-level AND is serialized independently, then
    // folded into a right-leaning AND chain below.
    let mut nodes: Vec<Vec<u8>> = Vec::new();

    if !keywords.is_empty() {
        let mut kw = Vec::with_capacity(32);
        write_keyword_tree(&mut kw, keywords, keywords.len());
        nodes.push(kw);
    }

    if let Some(ft) = constraints.file_type.filter(|t| !t.is_empty()) {
        let mut n = Vec::new();
        write_meta_string(&mut n, ft, TAG_FILETYPE);
        nodes.push(n);
    }

    if let Some(ext) = constraints.file_extension {
        // FT_FILEFORMAT carries the bare extension (no leading dot).
        let ext = ext.trim().trim_start_matches('.');
        if !ext.is_empty() {
            let mut n = Vec::new();
            write_meta_string(&mut n, ext, FT_FILEFORMAT);
            nodes.push(n);
        }
    }

    if let Some(min_size) = constraints.min_size.filter(|v| *v > 0) {
        let mut n = Vec::new();
        write_numeric_leaf(&mut n, min_size, ED2K_SEARCH_OP_GREATER_EQUAL, TAG_FILESIZE);
        nodes.push(n);
    }

    if let Some(max_size) = constraints.max_size.filter(|v| *v > 0) {
        let mut n = Vec::new();
        write_numeric_leaf(&mut n, max_size, ED2K_SEARCH_OP_LESS_EQUAL, TAG_FILESIZE);
        nodes.push(n);
    }

    if let Some(min_avail) = constraints.min_availability.filter(|v| *v > 0) {
        let mut n = Vec::new();
        write_numeric_leaf(
            &mut n,
            min_avail as u64,
            ED2K_SEARCH_OP_GREATER_EQUAL,
            TAG_SOURCES,
        );
        nodes.push(n);
    }

    if nodes.is_empty() {
        return Vec::new();
    }

    // Fold operands into a right-leaning AND chain:
    //   [n0]                -> n0
    //   [n0, n1]            -> AND n0 n1
    //   [n0, n1, n2]        -> AND n0 AND n1 n2
    // For a single node (the common keyword-only / type-only case) this emits
    // exactly the bare leaf, byte-identical to the previous implementation.
    let mut buf = Vec::with_capacity(64);
    let last = nodes.len() - 1;
    for node in &nodes[..last] {
        buf.push(0x00); // operator
        buf.push(0x00); // AND
        buf.extend_from_slice(node);
    }
    buf.extend_from_slice(&nodes[last]);
    buf
}

#[cfg(test)]
mod search_expr_tests {
    use super::*;

    fn kw(s: &str) -> Vec<String> {
        vec![s.to_string()]
    }

    fn string_leaf(s: &str) -> Vec<u8> {
        let mut v = vec![0x01];
        v.extend_from_slice(&(s.len() as u16).to_le_bytes());
        v.extend_from_slice(s.as_bytes());
        v
    }

    fn meta_string(value: &str, tag: u8) -> Vec<u8> {
        let mut v = vec![0x02];
        v.extend_from_slice(&(value.len() as u16).to_le_bytes());
        v.extend_from_slice(value.as_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        v.push(tag);
        v
    }

    #[test]
    fn empty_when_no_keywords_and_no_constraints() {
        assert!(build_search_expression(&[], &SearchConstraints::default()).is_empty());
    }

    #[test]
    fn single_keyword_is_bare_string_leaf() {
        let out = build_search_expression(&kw("movie"), &SearchConstraints::default());
        assert_eq!(out, string_leaf("movie"));
    }

    #[test]
    fn keyword_plus_filetype_matches_legacy_and_layout() {
        // Backward-compat: AND(keyword, FT_FILETYPE meta-string).
        let out = build_search_expression(
            &kw("movie"),
            &SearchConstraints {
                file_type: Some("Video"),
                ..Default::default()
            },
        );
        let mut expected = vec![0x00, 0x00];
        expected.extend(string_leaf("movie"));
        expected.extend(meta_string("Video", TAG_FILETYPE));
        assert_eq!(out, expected);
    }

    #[test]
    fn min_size_emits_u32_numeric_ge_filesize() {
        let out = build_search_expression(
            &kw("movie"),
            &SearchConstraints {
                min_size: Some(1024),
                ..Default::default()
            },
        );
        let mut expected = vec![0x00, 0x00];
        expected.extend(string_leaf("movie"));
        // numeric u32 leaf: type 0x03, value LE, op GE(3), taglen=1, FT_FILESIZE
        expected.push(0x03);
        expected.extend_from_slice(&1024u32.to_le_bytes());
        expected.push(ED2K_SEARCH_OP_GREATER_EQUAL);
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.push(TAG_FILESIZE);
        assert_eq!(out, expected);
    }

    #[test]
    fn max_size_above_u32_uses_u64_numeric() {
        let big = (u32::MAX as u64) + 1; // 4 GiB + 1 byte
        let out = build_search_expression(
            &kw("iso"),
            &SearchConstraints {
                max_size: Some(big),
                ..Default::default()
            },
        );
        let mut expected = vec![0x00, 0x00];
        expected.extend(string_leaf("iso"));
        expected.push(0x08); // 64-bit numeric type
        expected.extend_from_slice(&big.to_le_bytes());
        expected.push(ED2K_SEARCH_OP_LESS_EQUAL);
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.push(TAG_FILESIZE);
        assert_eq!(out, expected);
    }

    #[test]
    fn extension_is_dot_stripped_fileformat_meta() {
        let out = build_search_expression(
            &kw("song"),
            &SearchConstraints {
                file_extension: Some(".mp3"),
                ..Default::default()
            },
        );
        let mut expected = vec![0x00, 0x00];
        expected.extend(string_leaf("song"));
        expected.extend(meta_string("mp3", FT_FILEFORMAT));
        assert_eq!(out, expected);
    }

    #[test]
    fn zero_valued_numeric_constraints_are_omitted() {
        let out = build_search_expression(
            &kw("movie"),
            &SearchConstraints {
                min_size: Some(0),
                max_size: Some(0),
                min_availability: Some(0),
                file_extension: Some(""),
                file_type: Some(""),
            },
        );
        assert_eq!(out, string_leaf("movie"));
    }

    #[test]
    fn constraints_only_no_keywords() {
        // No keywords: the lone constraint leaf is emitted without an AND.
        let out = build_search_expression(
            &[],
            &SearchConstraints {
                file_type: Some("Audio"),
                ..Default::default()
            },
        );
        assert_eq!(out, meta_string("Audio", TAG_FILETYPE));
    }

    #[test]
    fn multiple_constraints_and_chain_is_parseable_length() {
        // Two keywords + type + min size + availability should produce a
        // right-leaning AND chain with one fewer AND than operands.
        let out = build_search_expression(
            &[String::from("big"), String::from("movie")],
            &SearchConstraints {
                file_type: Some("Video"),
                min_size: Some(1_000_000),
                min_availability: Some(5),
                ..Default::default()
            },
        );
        // Operands: keyword_tree, filetype, min_size, availability = 4 nodes
        // => 3 leading AND operator pairs (0x00 0x00) at the chain joints,
        //    plus the internal AND from the 2-keyword tree.
        let and_pairs = out.windows(2).filter(|w| w == b"\x00\x00").count();
        assert!(
            and_pairs >= 3,
            "expected at least 3 AND joints, got {and_pairs}"
        );
        assert!(!out.is_empty());
    }
}

#[cfg(test)]
mod publish_res_tests {
    use super::*;

    #[test]
    fn encoded_publish_res_is_bare_target_load() {
        // Our outgoing PublishRes never carries the optional options byte:
        // header + opcode + 16-byte target + 1-byte load = 19 bytes on the
        // wire (eMule's storage-node response is the equivalent 17-byte body).
        let msg = KadMessage::PublishRes {
            target: KadId([0x33; 16]),
            load: 42,
            request_ack: true, // must be ignored by the encoder
        };
        let bytes = encode_packet(&msg).unwrap();
        assert_eq!(bytes.len(), 1 + 1 + 16 + 1);
        assert_eq!(bytes[0], OP_KADEMLIAHEADER);
        assert_eq!(bytes[1], KADEMLIA2_PUBLISH_RES);
    }

    #[test]
    fn publish_res_without_options_byte_does_not_request_ack() {
        let msg = KadMessage::PublishRes {
            target: KadId([0x33; 16]),
            load: 42,
            request_ack: false,
        };
        let bytes = encode_packet(&msg).unwrap();
        match decode_packet(&bytes).unwrap() {
            KadMessage::PublishRes {
                target,
                load,
                request_ack,
            } => {
                assert_eq!(target, KadId([0x33; 16]));
                assert_eq!(load, 42);
                assert!(!request_ack, "no trailing options byte => no ack request");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn publish_res_options_bit0_requests_ack() {
        // eMule peers may append an options byte; bit0 requests a
        // KADEMLIA2_PUBLISH_RES_ACK.
        let mut bytes = encode_packet(&KadMessage::PublishRes {
            target: KadId([0x44; 16]),
            load: 7,
            request_ack: false,
        })
        .unwrap();
        bytes.push(0x01); // options byte, bit0 set
        match decode_packet(&bytes).unwrap() {
            KadMessage::PublishRes { request_ack, .. } => {
                assert!(request_ack, "options bit0 must request an ack");
            }
            other => panic!("unexpected message: {other:?}"),
        }

        // bit0 clear => still no ack.
        let mut bytes = encode_packet(&KadMessage::PublishRes {
            target: KadId([0x44; 16]),
            load: 7,
            request_ack: false,
        })
        .unwrap();
        bytes.push(0x02); // some other (non-ack) option bit
        match decode_packet(&bytes).unwrap() {
            KadMessage::PublishRes { request_ack, .. } => {
                assert!(!request_ack, "options without bit0 must not request an ack");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }
}
