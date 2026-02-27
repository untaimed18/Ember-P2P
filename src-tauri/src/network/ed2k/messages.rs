use std::io::{self, Cursor, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

// Protocol headers
pub const OP_EDONKEYHEADER: u8 = 0xE3;
pub const OP_EMULEPROT: u8 = 0xC5;

// Client-to-client opcodes (OP_EDONKEYHEADER)
pub const OP_HELLO: u8 = 0x01;
pub const OP_HELLOANSWER: u8 = 0x4C;
pub const OP_SETREQFILEID: u8 = 0x4F;
pub const OP_FILESTATUS: u8 = 0x50;
pub const OP_REQUESTFILENAME: u8 = 0x58;
pub const OP_REQFILENAMEANSWER: u8 = 0x59;
pub const OP_STARTUPLOADREQ: u8 = 0x54;
pub const OP_ACCEPTUPLOADREQ: u8 = 0x55;
pub const OP_CANCELTRANSFER: u8 = 0x56;
pub const OP_OUTOFPARTREQS: u8 = 0x57;
pub const OP_REQUESTPARTS: u8 = 0x47;
pub const OP_SENDINGPART: u8 = 0x46;
pub const OP_END_OF_DOWNLOAD: u8 = 0x49;
pub const OP_FILEREQANSNOFIL: u8 = 0x48;

// Extended opcodes (OP_EMULEPROT)
pub const OP_EMULEINFO: u8 = 0x01;
pub const OP_EMULEINFOANSWER: u8 = 0x02;
pub const OP_COMPRESSEDPART: u8 = 0x40;
pub const OP_QUEUERANKING: u8 = 0x60;
pub const OP_MULTIPACKET: u8 = 0x92;
pub const OP_MULTIPACKETANSWER: u8 = 0x93;
pub const OP_AICHREQUEST: u8 = 0x9B;
pub const OP_AICHANSWER: u8 = 0x9C;
pub const OP_COMPRESSEDPART_I64: u8 = 0xA1;
pub const OP_SENDINGPART_I64: u8 = 0xA2;
pub const OP_REQUESTPARTS_I64: u8 = 0xA3;
pub const OP_MULTIPACKET_EXT: u8 = 0xA4;
pub const OP_MULTIPACKET_EXT2: u8 = 0xA9;
pub const OP_MULTIPACKETANSWER_EXT2: u8 = 0xB0;
pub const OP_PORTTEST: u8 = 0xFE;

// Hashset opcodes (OP_EDONKEYHEADER)
pub const OP_HASHSETREQ: u8 = 0x51;
pub const OP_HASHSETANSWER: u8 = 0x52;

// Legacy opcodes (OP_EDONKEYHEADER)
pub const OP_QUEUERANK: u8 = 0x5C;

// Source exchange opcodes (OP_EMULEPROT)
pub const OP_REQUESTSOURCES: u8 = 0x81;
pub const OP_ANSWERSOURCES2: u8 = 0x83;

// Secure identification opcodes (OP_EMULEPROT)
pub const OP_PUBLICKEY: u8 = 0x85;
pub const OP_SIGNATURE: u8 = 0x86;
pub const OP_SECIDENTSTATE: u8 = 0x87;

// Constants
pub const EMBLOCKSIZE: u64 = 184_320;
pub const PARTSIZE: u64 = 9_728_000;

#[derive(Debug, Clone)]
pub enum Ed2kTagValue {
    String(String),
    Uint32(u32),
    Uint16(u16),
    Uint8(u8),
}

/// Build a Hello packet payload.
pub fn build_hello(user_hash: &[u8; 16], client_id: u32, tcp_port: u16, nickname: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    buf.write_u8(16).unwrap(); // hash size marker
    buf.write_all(user_hash).unwrap();
    buf.write_u32::<LittleEndian>(client_id).unwrap();
    buf.write_u16::<LittleEndian>(tcp_port).unwrap();

    let mut tags: Vec<(&[u8], Ed2kTagValue)> = Vec::new();
    tags.push((&[0x01], Ed2kTagValue::String(nickname.to_string()))); // CT_NAME
    tags.push((&[0x11], Ed2kTagValue::Uint32(0x3C))); // CT_VERSION = EDONKEYVERSION
    tags.push((&[0x0F], Ed2kTagValue::Uint32(tcp_port as u32))); // CT_PORT

    // CT_EMULE_VERSION (0xFB): identifies us as an eMule-compatible client
    // Format: (compat_client << 24) | (major << 17) | (minor << 10) | (update << 7)
    // We use SO_COMPAT_UNK (0) as the client type with version 0.1.0
    let emule_version: u32 = (0 << 24) | (0 << 17) | (1 << 10) | (0 << 7);
    tags.push((&[0xFB], Ed2kTagValue::Uint32(emule_version)));

    // CT_MOD_VERSION (0x55): identifies our client name to other peers
    tags.push((&[0x55], Ed2kTagValue::String("Nexus 0.1".to_string())));

    // Tag count
    buf.write_u32::<LittleEndian>(tags.len() as u32).unwrap();

    for (name, value) in &tags {
        match value {
            Ed2kTagValue::String(s) => {
                buf.write_u8(0x02).unwrap(); // TAGTYPE_STRING
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u16::<LittleEndian>(s.len() as u16).unwrap();
                buf.write_all(s.as_bytes()).unwrap();
            }
            Ed2kTagValue::Uint32(v) => {
                buf.write_u8(0x03).unwrap(); // TAGTYPE_UINT32
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u32::<LittleEndian>(*v).unwrap();
            }
            Ed2kTagValue::Uint16(v) => {
                buf.write_u8(0x08).unwrap(); // TAGTYPE_UINT16
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u16::<LittleEndian>(*v).unwrap();
            }
            Ed2kTagValue::Uint8(v) => {
                buf.write_u8(0x09).unwrap(); // TAGTYPE_UINT8
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u8(*v).unwrap();
            }
        }
    }

    // Server IP and Port (0 = no server, we're KAD only)
    buf.write_u32::<LittleEndian>(0).unwrap();
    buf.write_u16::<LittleEndian>(0).unwrap();

    buf
}

/// Build an EmuleInfo packet payload with capability flags.
///
/// eMule MiscOptions1 bit layout (from opcodes.h):
///   bits 0-3:   AICH version (we send 1)
///   bit  4:     Unicode support (1)
///   bits 5-7:   UDP version (4)
///   bits 8-11:  Data compression version (1)
///   bit  12:    Secure ident support (1)
///   bits 13-15: Source exchange version (4)
///   bits 16-19: Extended requests version (2)
///   bits 20-23: Comments version (1)
///   bit  24:    Peer cache (0)
///   bit  25:    No 'view shared files' (1)
///   bit  26:    Multi-packet (1)
///   bit  27:    Supports preview (0)
///
/// MiscOptions2 bit layout:
///   bit  0:     KAD version (>= 1)
///   bits 1-3:   Reserved
///   bit  4:     Supports large files (>4GB) (1)
///   bit  5:     Ext multi-packet (1)
///   bits 6-12:  Reserved
///   bit  13:    Supports captcha (0)
///   bit  14:    Supports source exchange2 (1)
///   bit  15:    Requires crypt layer (0)
///   bit  16:    Requests crypt layer (0)
///   bit  17:    Supports crypt layer (1)
pub fn build_emule_info(udp_port: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);

    buf.write_u8(1).unwrap(); // version

    // MiscOptions1: AICH=1 | Unicode=1 | UDPver=4 | Compress=1 | SrcExch=4 | ExtReq=2 | Comments=1 | NoViewShared=1 | MultiPacket=1
    let misc_options1: u32 =
          1              // AICH ver 1
        | (1 << 4)      // Unicode
        | (4 << 5)      // UDP ver 4
        | (1 << 8)      // Compression ver 1
        | (1 << 12)     // Secure ident supported
        | (4 << 13)     // Source exchange ver 4
        | (2 << 16)     // Extended requests ver 2
        | (1 << 20)     // Comments ver 1
        | (0 << 24)     // No peer cache
        | (1 << 25)     // No view shared files
        | (1 << 26);    // Multi-packet support

    // MiscOptions2: KAD=1 | LargeFiles=1 | ExtMultiPacket=1 | SrcExch2=1 | CryptSupport=1
    let misc_options2: u32 =
          1              // KAD version
        | (1 << 4)      // Large files (>4GB)
        | (1 << 5)      // Extended multi-packet
        | (1 << 14)     // Source exchange 2
        | (1 << 17);    // Supports crypt layer

    let tags: Vec<(&[u8], Ed2kTagValue)> = vec![
        (&[0x21], Ed2kTagValue::Uint16(udp_port)),       // ET_UDPPORT
        (&[0x20], Ed2kTagValue::Uint8(1)),                // ET_COMPRESSION
        (&[0x23], Ed2kTagValue::Uint32(4)),               // ET_SOURCEEXCHANGE2_VERSION
        (&[0xF5], Ed2kTagValue::Uint32(misc_options1)),   // CT_EMULE_MISCOPTIONS1
        (&[0xF6], Ed2kTagValue::Uint32(misc_options2)),   // CT_EMULE_MISCOPTIONS2
    ];

    buf.write_u32::<LittleEndian>(tags.len() as u32).unwrap();

    for (name, value) in &tags {
        match value {
            Ed2kTagValue::String(s) => {
                buf.write_u8(0x02).unwrap();
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u16::<LittleEndian>(s.len() as u16).unwrap();
                buf.write_all(s.as_bytes()).unwrap();
            }
            Ed2kTagValue::Uint32(v) => {
                buf.write_u8(0x03).unwrap();
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u32::<LittleEndian>(*v).unwrap();
            }
            Ed2kTagValue::Uint16(v) => {
                buf.write_u8(0x08).unwrap();
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u16::<LittleEndian>(*v).unwrap();
            }
            Ed2kTagValue::Uint8(v) => {
                buf.write_u8(0x09).unwrap();
                buf.write_u16::<LittleEndian>(name.len() as u16).unwrap();
                buf.write_all(name).unwrap();
                buf.write_u8(*v).unwrap();
            }
        }
    }

    buf
}

/// Build a SetReqFileId + RequestFileName packet payload.
pub fn build_file_request(file_hash: &[u8; 16]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.write_all(file_hash).unwrap();
    buf
}

/// Build a RequestParts_I64 payload (3 part requests).
pub fn build_request_parts_i64(file_hash: &[u8; 16], offsets: &[(u64, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 48);
    buf.write_all(file_hash).unwrap();

    // Always write 3 start/end pairs, using 0/0 for unused slots
    for i in 0..3 {
        if i < offsets.len() {
            buf.write_u64::<LittleEndian>(offsets[i].0).unwrap();
        } else {
            buf.write_u64::<LittleEndian>(0).unwrap();
        }
    }
    for i in 0..3 {
        if i < offsets.len() {
            buf.write_u64::<LittleEndian>(offsets[i].1).unwrap();
        } else {
            buf.write_u64::<LittleEndian>(0).unwrap();
        }
    }

    buf
}

/// Parse a SendingPart_I64 payload.
pub fn parse_sending_part_i64(payload: &[u8]) -> io::Result<([u8; 16], u64, u64, &[u8])> {
    if payload.len() < 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "sending part too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut hash = [0u8; 16];
    cursor.read_exact(&mut hash)?;
    let start = cursor.read_u64::<LittleEndian>()?;
    let end = cursor.read_u64::<LittleEndian>()?;
    let data_start = cursor.position() as usize;
    Ok((hash, start, end, &payload[data_start..]))
}

/// Parse a CompressedPart_I64 payload.
pub fn parse_compressed_part_i64(payload: &[u8]) -> io::Result<([u8; 16], u64, u32, &[u8])> {
    if payload.len() < 28 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "compressed part too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut hash = [0u8; 16];
    cursor.read_exact(&mut hash)?;
    let start = cursor.read_u64::<LittleEndian>()?;
    let packed_len = cursor.read_u32::<LittleEndian>()?;
    let data_start = cursor.position() as usize;
    Ok((hash, start, packed_len, &payload[data_start..]))
}

/// Build a HashSetReq payload (just the file hash).
pub fn build_hashset_request(file_hash: &[u8; 16]) -> Vec<u8> {
    file_hash.to_vec()
}

/// Parse a HashSetAnswer payload. Returns (file_hash, part_hashes).
pub fn parse_hashset_answer(payload: &[u8]) -> io::Result<([u8; 16], Vec<[u8; 16]>)> {
    if payload.len() < 18 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hashset answer too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut hash = [0u8; 16];
    cursor.read_exact(&mut hash)?;
    let count = cursor.read_u16::<LittleEndian>()? as usize;

    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut h = [0u8; 16];
        cursor.read_exact(&mut h)?;
        hashes.push(h);
    }

    Ok((hash, hashes))
}

/// Sub-opcode inside a MultiPacket request.
#[derive(Debug)]
pub enum MultiPacketSubReq {
    RequestFileName,
    SetReqFileId,
}

/// Parsed MultiPacket request.
#[derive(Debug)]
pub struct MultiPacketRequest {
    pub file_hash: [u8; 16],
    pub file_size: Option<u64>,
    pub sub_opcodes: Vec<MultiPacketSubReq>,
    pub is_ext2: bool,
}

/// Parse an OP_MULTIPACKET / OP_MULTIPACKET_EXT / OP_MULTIPACKET_EXT2 payload.
///
/// Wire format (eMule ListenSocket.cpp ProcessExtPacket):
///   OP_MULTIPACKET:      <hash 16> <sub-opcodes...>
///   OP_MULTIPACKET_EXT:  <hash 16> <filesize u64> <sub-opcodes...>
///   OP_MULTIPACKET_EXT2: <hash 16> [<AICH hash 20>] <sub-opcodes...>
///     (EXT2 uses a FileIdentifier: MD4 hash + optional AICH. Minimal = 16 + 1 byte AICH flag.)
///
/// Each sub-opcode is a single u8 that may be followed by extra data depending
/// on the opcode. We handle the two that eMule always sends:
///   OP_REQUESTFILENAME (0x58) - no extra data
///   OP_SETREQFILEID    (0x4F) - no extra data
pub fn parse_multipacket(payload: &[u8], opcode: u8) -> io::Result<MultiPacketRequest> {
    if payload.len() < 17 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "multipacket too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut file_hash = [0u8; 16];
    cursor.read_exact(&mut file_hash)?;

    let is_ext2 = opcode == OP_MULTIPACKET_EXT2;
    let mut file_size = None;

    if opcode == OP_MULTIPACKET_EXT {
        file_size = Some(cursor.read_u64::<LittleEndian>()?);
    } else if is_ext2 {
        // EXT2 FileIdentifier: the MD4 hash is already read above.
        // Next comes an optional AICH hash. eMule writes:
        //   bool hasAICH (1 byte), then if true, 20-byte AICH hash.
        // We just need to skip past it.
        if (cursor.position() as usize) < payload.len() {
            let has_aich = cursor.read_u8()?;
            if has_aich != 0 {
                let mut _aich = [0u8; 20];
                if cursor.read_exact(&mut _aich).is_err() {
                    // Truncated AICH, ignore
                }
            }
        }
    }

    let mut sub_opcodes = Vec::new();
    while (cursor.position() as usize) < payload.len() {
        let sub_op = cursor.read_u8()?;
        match sub_op {
            OP_REQUESTFILENAME => {
                // eMule: client->ProcessExtendedInfo reads additional data here,
                // but only if the sender's ExtendedRequestsVersion > 0.
                // Skip any extended info: read u16 num_complete_sources if present
                // (eMule writes partcount(u16) + part_status_bitmap + complete_sources(u16)).
                // We consume the rest of the sub-opcode's data by reading the part count.
                // However, since we can't reliably know the peer's ExtReqVersion from
                // just the packet, we handle this safely: if there's data left and
                // the next byte looks like another known sub-opcode, we stop.
                // For simplicity, just record the sub-request.
                sub_opcodes.push(MultiPacketSubReq::RequestFileName);
            }
            OP_SETREQFILEID => {
                sub_opcodes.push(MultiPacketSubReq::SetReqFileId);
            }
            _ => {
                // Unknown sub-opcode; stop parsing to avoid misinterpreting data
                break;
            }
        }
    }

    Ok(MultiPacketRequest {
        file_hash,
        file_size,
        sub_opcodes,
        is_ext2,
    })
}

/// Build a MultiPacketAnswer payload based on the sub-opcodes requested.
///
/// Wire format:
///   <hash 16> (<sub-opcode u8> <sub-data>)*
///
/// Each sub-opcode in the request maps to a response sub-opcode:
///   OP_REQUESTFILENAME  -> OP_REQFILENAMEANSWER (0x59): <name_len u16> <name bytes>
///   OP_SETREQFILEID     -> OP_FILESTATUS        (0x50): <part_count u16> <bitmap>
pub fn build_multipacket_answer(
    file_hash: &[u8; 16],
    file_name: &str,
    file_size: u64,
    is_ext2: bool,
    sub_opcodes: &[MultiPacketSubReq],
) -> Vec<u8> {
    let part_count = ((file_size + PARTSIZE - 1) / PARTSIZE) as u16;
    let bitmap_bytes = ((part_count as usize) + 7) / 8;
    let name_bytes = file_name.as_bytes();

    let mut buf = Vec::with_capacity(16 + 1 + 2 + name_bytes.len() + 1 + 2 + bitmap_bytes + 8);

    buf.write_all(file_hash).unwrap();

    if is_ext2 {
        buf.write_u8(0).unwrap(); // hasAICH = false
    }

    for sub in sub_opcodes {
        match sub {
            MultiPacketSubReq::RequestFileName => {
                buf.write_u8(OP_REQFILENAMEANSWER).unwrap();
                buf.write_u16::<LittleEndian>(name_bytes.len() as u16).unwrap();
                buf.write_all(name_bytes).unwrap();
            }
            MultiPacketSubReq::SetReqFileId => {
                buf.write_u8(OP_FILESTATUS).unwrap();
                buf.write_u16::<LittleEndian>(part_count).unwrap();
                for i in 0..bitmap_bytes {
                    let remaining_bits = part_count as usize - i * 8;
                    if remaining_bits >= 8 {
                        buf.write_u8(0xFF).unwrap();
                    } else {
                        buf.write_u8((1u8 << remaining_bits) - 1).unwrap();
                    }
                }
            }
        }
    }

    buf
}

/// Parse a FileStatus response.
pub fn parse_file_status(payload: &[u8]) -> io::Result<([u8; 16], Vec<bool>)> {
    if payload.len() < 18 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file status too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut hash = [0u8; 16];
    cursor.read_exact(&mut hash)?;
    let part_count = cursor.read_u16::<LittleEndian>()? as usize;
    let bitmap_bytes = (part_count + 7) / 8;
    let mut bitmap = vec![0u8; bitmap_bytes];
    if bitmap_bytes > 0 {
        cursor.read_exact(&mut bitmap)?;
    }

    let mut parts = Vec::with_capacity(part_count);
    for i in 0..part_count {
        parts.push((bitmap[i / 8] >> (i % 8)) & 1 != 0);
    }

    Ok((hash, parts))
}
