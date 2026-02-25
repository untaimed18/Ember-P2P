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
pub const KADEMLIA_SEARCH_RES_OLD: u8 = 0x38;
pub const KADEMLIA_PUBLISH_REQ_OLD: u8 = 0x40;
pub const KADEMLIA_PUBLISH_RES_OLD: u8 = 0x48;

pub const KADEMLIA_CALLBACK_REQ: u8 = 0x52;

// Firewalled2 opcode
pub const KADEMLIA_FIREWALLED2_REQ: u8 = 0x53;

// Search types for KADEMLIA2_REQ
pub const KADEMLIA_FIND_VALUE: u8 = 0x02;
pub const KADEMLIA_STORE: u8 = 0x04;
pub const KADEMLIA_FIND_NODE: u8 = 0x0B;

pub const UDP_KAD_MAXFRAGMENT: usize = 1420;

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
            // Wire format: [0xE5][opcode][zlib_compressed(body)]
            // The opcode byte sits between the header and compressed data.
            if data.len() < 3 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed packet too short",
                ));
            }
            let opcode = data[1];
            let compressed = &data[2..];
            let mut decoder = ZlibDecoder::new(compressed);
            let mut decompressed = Vec::new();
            match decoder.read_to_end(&mut decompressed) {
                Ok(_) => {}
                Err(_) => {
                    let mut decoder2 = DeflateDecoder::new(compressed);
                    decompressed.clear();
                    decoder2.read_to_end(&mut decompressed)?;
                }
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
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let mut contacts = Vec::with_capacity(count.min(200));
            for _ in 0..count.min(200) {
                match KadContact::read_from(cursor) {
                    Ok(c) => contacts.push(c),
                    Err(_) => break,
                }
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
            let count = cursor.read_u8()? as usize;
            let capped = count.min(K_BUCKET_SIZE + 1); // eMule caps at K+1=11
            let mut contacts = Vec::with_capacity(capped);
            for _ in 0..capped {
                match KadContact::read_from(cursor) {
                    Ok(c) => contacts.push(c),
                    Err(_) => break,
                }
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
            Ok(KadMessage::SearchKeyReq {
                target,
                start_position,
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
            let mut results = Vec::with_capacity(count.min(300));
            for _ in 0..count.min(300) {
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
            Ok(KadMessage::PublishRes { target, load })
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
            Ok(KadMessage::PublishNotesReq { target, sender_id, tags })
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
            Ok(KadMessage::Firewalled2Req { tcp_port, user_hash, connect_options })
        }

        KADEMLIA_FIREWALLED_RES => {
            let ip = cursor.read_u32::<LittleEndian>()?;
            Ok(KadMessage::FirewalledRes { ip })
        }

        KADEMLIA2_FIREWALLUDP => {
            let error_code = cursor.read_u8()?;
            let udp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::FirewallUdp { error_code, udp_port })
        }

        KADEMLIA_FINDBUDDY_REQ => {
            let buddy_id = KadId::read_from(cursor)?;
            let user_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::FindBuddyReq { buddy_id, user_id, tcp_port })
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
            Ok(KadMessage::FindBuddyRes { buddy_id, user_hash, tcp_port, connect_options })
        }

        KADEMLIA_CALLBACK_REQ => {
            let buddy_id = KadId::read_from(cursor)?;
            let file_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::CallbackReq { buddy_id, file_id, tcp_port })
        }

        // Legacy Kad1.0 opcodes - decode into equivalent Kad2 messages where possible
        KADEMLIA_BOOTSTRAP_REQ_OLD => Ok(KadMessage::BootstrapReq),
        KADEMLIA_BOOTSTRAP_RES_OLD => {
            let count = cursor.read_u16::<LittleEndian>()? as usize;
            let mut contacts = Vec::with_capacity(count.min(200));
            for _ in 0..count.min(200) {
                match KadContact::read_from(cursor) {
                    Ok(c) => contacts.push(c),
                    Err(_) => break,
                }
            }
            Ok(KadMessage::BootstrapRes {
                sender_id: KadId::zero(),
                tcp_port: 0,
                version: 1,
                contacts,
            })
        }
        KADEMLIA_HELLO_REQ_OLD => {
            let sender_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::HelloReq { sender_id, tcp_port, version: 1, tags: Vec::new() })
        }
        KADEMLIA_HELLO_RES_OLD => {
            let sender_id = KadId::read_from(cursor)?;
            let tcp_port = cursor.read_u16::<LittleEndian>()?;
            Ok(KadMessage::HelloRes { sender_id, tcp_port, version: 1, tags: Vec::new() })
        }
        KADEMLIA_REQ_OLD => {
            let search_type = cursor.read_u8()?;
            let target = KadId::read_from(cursor)?;
            let receiver = KadId::read_from(cursor)?;
            Ok(KadMessage::KadReq { search_type, target, receiver })
        }
        KADEMLIA_RES_OLD => {
            let target = KadId::read_from(cursor)?;
            let count = cursor.read_u8()? as usize;
            let mut contacts = Vec::with_capacity(count.min(K_BUCKET_SIZE));
            for _ in 0..count.min(K_BUCKET_SIZE) {
                match KadContact::read_from(cursor) {
                    Ok(c) => contacts.push(c),
                    Err(_) => break,
                }
            }
            Ok(KadMessage::KadRes { target, contacts })
        }
        KADEMLIA_SEARCH_REQ_OLD | KADEMLIA_PUBLISH_REQ_OLD | KADEMLIA_PUBLISH_RES_OLD | KADEMLIA_SEARCH_RES_OLD => {
            tracing::debug!("Received legacy Kad1.0 opcode 0x{:02X}, ignoring", opcode);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported legacy kad opcode: 0x{:02X}", opcode),
            ))
        }

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
            out.write_u8(contacts.len() as u8)?;
            for c in contacts {
                c.write_to(out)?;
            }
        }

        KadMessage::SearchKeyReq {
            target,
            start_position,
        } => {
            out.write_u8(KADEMLIA2_SEARCH_KEY_REQ)?;
            target.write_to(out)?;
            out.write_u16::<LittleEndian>(*start_position)?;
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

        KadMessage::PublishRes { target, load } => {
            out.write_u8(KADEMLIA2_PUBLISH_RES)?;
            target.write_to(out)?;
            out.write_u8(*load)?;
        }

        KadMessage::SearchNotesReq { target, file_size } => {
            out.write_u8(KADEMLIA2_SEARCH_NOTES_REQ)?;
            target.write_to(out)?;
            out.write_u64::<LittleEndian>(*file_size)?;
        }

        KadMessage::PublishNotesReq { target, sender_id, tags } => {
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

        KadMessage::Firewalled2Req { tcp_port, user_hash, connect_options } => {
            out.write_u8(KADEMLIA_FIREWALLED2_REQ)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
            out.write_all(user_hash)?;
            out.write_u8(*connect_options)?;
        }

        KadMessage::FirewalledRes { ip } => {
            out.write_u8(KADEMLIA_FIREWALLED_RES)?;
            out.write_u32::<LittleEndian>(*ip)?;
        }

        KadMessage::FirewallUdp { error_code, udp_port } => {
            out.write_u8(KADEMLIA2_FIREWALLUDP)?;
            out.write_u8(*error_code)?;
            out.write_u16::<LittleEndian>(*udp_port)?;
        }

        KadMessage::FindBuddyReq { buddy_id, user_id, tcp_port } => {
            out.write_u8(KADEMLIA_FINDBUDDY_REQ)?;
            buddy_id.write_to(out)?;
            user_id.write_to(out)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
        }

        KadMessage::FindBuddyRes { buddy_id, user_hash, tcp_port, connect_options } => {
            out.write_u8(KADEMLIA_FINDBUDDY_RES)?;
            buddy_id.write_to(out)?;
            out.write_all(user_hash)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
            out.write_u8(*connect_options)?;
        }

        KadMessage::CallbackReq { buddy_id, file_id, tcp_port } => {
            out.write_u8(0x52)?; // KADEMLIA_CALLBACK_REQ
            buddy_id.write_to(out)?;
            file_id.write_to(out)?;
            out.write_u16::<LittleEndian>(*tcp_port)?;
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
) -> Vec<u8> {
    encode_packet(&KadMessage::HelloReq {
        sender_id: *sender_id,
        tcp_port,
        version,
        tags: tags.to_vec(),
    })
    .unwrap_or_default()
}
