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
pub const OP_AICHFILEHASHANS: u8 = 0x9D;
pub const OP_AICHFILEHASHREQ: u8 = 0x9E;
pub const OP_COMPRESSEDPART_I64: u8 = 0xA1;
pub const OP_SENDINGPART_I64: u8 = 0xA2;
pub const OP_REQUESTPARTS_I64: u8 = 0xA3;
pub const OP_MULTIPACKET_EXT: u8 = 0xA4;
pub const OP_FWCHECKUDPREQ: u8 = 0xA7;
pub const OP_KAD_FWTCPCHECK_ACK: u8 = 0xA8;
pub const OP_MULTIPACKET_EXT2: u8 = 0xA9;
pub const OP_MULTIPACKETANSWER_EXT2: u8 = 0xB0;
pub const OP_PORTTEST: u8 = 0xFE;

// Hashset opcodes (v1: OP_EDONKEYHEADER, v2: OP_EMULEPROT)
pub const OP_HASHSETREQ: u8 = 0x51;
pub const OP_HASHSETANSWER: u8 = 0x52;
pub const OP_HASHSETREQUEST2: u8 = 0xB1; // OP_EMULEPROT
pub const OP_HASHSETANSWER2: u8 = 0xB2;  // OP_EMULEPROT

// Legacy opcodes (OP_EDONKEYHEADER)
pub const OP_QUEUERANK: u8 = 0x5C;

// Source exchange opcodes (OP_EMULEPROT)
pub const OP_REQUESTSOURCES: u8 = 0x81;
pub const OP_ANSWERSOURCES: u8 = 0x82;
pub const OP_REQUESTSOURCES2: u8 = 0x83;
pub const OP_ANSWERSOURCES2: u8 = 0x84;
pub const SOURCEEXCHANGE2_VERSION: u8 = 4;

// Queue opcodes (OP_EMULEPROT)
// NOTE: OP_QUEUEFULL on TCP is 0x93 (same value as OP_MULTIPACKETANSWER).
// Disambiguation is by context: 0x93 on a peer TCP connection where we sent a
// file request and are awaiting a queue response is OP_QUEUEFULL; 0x93 in
// response to OP_MULTIPACKET is OP_MULTIPACKETANSWER.
pub const OP_QUEUEFULL: u8 = 0x93;

// UDP reask opcodes (OP_EMULEPROT, peer-to-peer UDP)
pub const OP_REASKFILEPING: u8 = 0x90;
pub const OP_REASKACK: u8 = 0x91;
pub const OP_FILENOTFOUND_UDP: u8 = 0x92;
pub const OP_QUEUEFULL_UDP: u8 = 0x93;
pub const OP_REASKCALLBACKUDP: u8 = 0x94;
pub const OP_DIRECTCALLBACKREQ: u8 = 0x95;

// Public IP exchange (OP_EMULEPROT)
pub const OP_PUBLICIP_REQ: u8 = 0x97;
pub const OP_PUBLICIP_ANSWER: u8 = 0x98;

// Callback / relay opcodes (OP_EMULEPROT)
pub const OP_CALLBACK: u8 = 0x99;
pub const OP_REASKCALLBACKTCP: u8 = 0x9A;

// Server-protocol callback opcodes (OP_EDONKEYHEADER, sent to/from the server).
// See also: ed2k::server::{OP_CALLBACKREQUEST, OP_CALLBACKREQUESTED, OP_CALLBACK_FAIL}
#[allow(dead_code)]
pub const OP_CALLBACKREQUEST_SERVER: u8 = 0x1C;
#[allow(dead_code)]
pub const OP_CALLBACKREQUESTED_SERVER: u8 = 0x35;
#[allow(dead_code)]
pub const OP_CALLBACK_FAIL_SERVER: u8 = 0x36;

// Buddy keepalive (OP_EMULEPROT)
pub const OP_BUDDYPING: u8 = 0x9F;
pub const OP_BUDDYPONG: u8 = 0xA0;

// Comment/rating exchange (OP_EMULEPROT)
pub const OP_FILEDESC: u8 = 0x61;

// Secure identification opcodes (OP_EMULEPROT)
pub const OP_PUBLICKEY: u8 = 0x85;
pub const OP_SIGNATURE: u8 = 0x86;
pub const OP_SECIDENTSTATE: u8 = 0x87;

// Ember extensions (OP_EMULEPROT) — silently ignored by non-Ember peers
pub const OP_EMBER_SOURCEEXCHANGE: u8 = 0xF0;
pub const OP_EMBER_CHAT_MSG: u8 = 0xF1;
pub const OP_EMBER_BROWSE_REQ: u8 = 0xF2;
pub const OP_EMBER_BROWSE_RES: u8 = 0xF3;
pub const OP_EMBER_FRIEND_REQ: u8 = 0xF4;
pub const OP_EMBER_KEEPALIVE: u8 = 0xF5;

// Constants
pub const EMBLOCKSIZE: u64 = 184_320;
pub const PARTSIZE: u64 = 9_728_000;

/// Number of actual data chunks (≈9.28 MiB each) for a given file size.
///
/// Matches eMule `CKnownFile::GetPartCount()` = `ceil(filesize / PARTSIZE)`.
/// Use for internal part tracking, hash verification, and chunk management.
/// For wire-protocol part counts (OP_FILESTATUS, extended requests), use
/// [`ed2k_wire_part_count`] instead.
pub fn ed2k_part_count_for_size(file_size: u64) -> usize {
    if file_size == 0 {
        0
    } else {
        file_size.div_ceil(PARTSIZE) as usize
    }
}

/// ED2K wire-protocol part count matching eMule `GetED2KPartCount()`.
///
/// Formula: `floor(filesize / PARTSIZE) + 1`.  Differs from
/// [`ed2k_part_count_for_size`] when file size is an exact multiple of
/// PARTSIZE — eMule always adds one extra "part" on the wire.  Using the wrong
/// count causes the peer's `ProcessExtendedInfo` to reject us with FNF.
pub fn ed2k_wire_part_count(file_size: u64) -> usize {
    if file_size == 0 {
        0
    } else {
        (file_size / PARTSIZE + 1) as usize
    }
}

pub fn source_exchange_id_to_ipv4(version: u8, source_id: u32) -> std::net::Ipv4Addr {
    if version < 3 {
        std::net::Ipv4Addr::from(source_id.to_le_bytes())
    } else {
        std::net::Ipv4Addr::from(source_id.to_be_bytes())
    }
}

#[derive(Debug, Clone)]
pub enum Ed2kTagValue {
    String(String),
    Uint32(u32),
    Uint16(u16),
    Uint8(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentifier {
    pub md4_hash: [u8; 16],
    pub file_size: Option<u64>,
    pub aich_hash: Option<[u8; 20]>,
}

impl FileIdentifier {
    pub fn compare_relaxed(&self, other: &Self) -> bool {
        self.md4_hash == other.md4_hash
            && (self.file_size.is_none()
                || other.file_size.is_none()
                || self.file_size == other.file_size)
            && (self.aich_hash.is_none()
                || other.aich_hash.is_none()
                || self.aich_hash == other.aich_hash)
    }

    pub fn write_identifier(&self, buf: &mut Vec<u8>) {
        let includes_md4 = 1u8;
        let includes_size = self.file_size.is_some() as u8;
        let includes_aich = self.aich_hash.is_some() as u8;
        let desc = includes_md4 | (includes_size << 1) | (includes_aich << 2);
        buf.push(desc);
        buf.extend_from_slice(&self.md4_hash);
        if let Some(size) = self.file_size {
            buf.extend_from_slice(&size.to_le_bytes());
        }
        if let Some(aich) = self.aich_hash {
            buf.extend_from_slice(&aich);
        }
    }

    pub fn read_identifier(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let desc = cursor.read_u8()?;
        let has_md4 = (desc & 0x01) != 0;
        let has_size = (desc & 0x02) != 0;
        let has_aich = (desc & 0x04) != 0;
        let mandatory_opts = (desc >> 3) & 0x03;
        if mandatory_opts != 0 || !has_md4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid file identifier"));
        }
        let mut md4_hash = [0u8; 16];
        cursor.read_exact(&mut md4_hash)?;
        let file_size = if has_size {
            Some(cursor.read_u64::<LittleEndian>()?)
        } else {
            None
        };
        let aich_hash = if has_aich {
            let mut aich = [0u8; 20];
            cursor.read_exact(&mut aich)?;
            Some(aich)
        } else {
            None
        };
        Ok(Self { md4_hash, file_size, aich_hash })
    }
}

/// Optional buddy info to include in Hello/HelloAnswer tags.
#[derive(Clone)]
pub struct BuddyInfo {
    pub buddy_ip: u32,
    pub buddy_port: u16,
}

#[derive(Debug, Clone)]
pub struct HelloOptions {
    pub udp_port: u16,
    pub kad_port: u16,
    pub supports_crypt_layer: bool,
    pub requests_crypt_layer: bool,
    pub requires_crypt_layer: bool,
    pub supports_direct_udp_callback: bool,
    pub supports_captcha: bool,
    pub server_ip: u32,
    pub server_port: u16,
    pub kad_version: u8,
}

impl HelloOptions {
    pub fn default_for_udp_port(udp_port: u16) -> Self {
        Self {
            udp_port,
            kad_port: udp_port,
            supports_crypt_layer: true,
            requests_crypt_layer: true,
            requires_crypt_layer: false,
            supports_direct_udp_callback: false,
            supports_captcha: false,
            server_ip: 0,
            server_port: 0,
            kad_version: 0x09,
        }
    }
}

/// Peer capability flags parsed from Hello/EmuleInfo exchanges.
#[derive(Debug, Clone, Default)]
pub struct PeerCapabilities {
    pub tcp_port: u16,
    pub udp_port: u16,
    pub kad_port: u16,
    pub compression_ver: u8,
    pub udp_ver: u8,
    pub source_exchange_ver: u8,
    pub extended_requests_ver: u8,
    pub comments_ver: u8,
    pub supports_large_files: bool,
    pub supports_crypt_layer: bool,
    pub requests_crypt_layer: bool,
    pub requires_crypt_layer: bool,
    pub supports_source_ex2: bool,
    pub ext_multi_packet: bool,
    pub supports_file_ident: bool,
    pub supports_direct_udp_callback: bool,
    pub supports_captcha: bool,
    pub kad_version: u8,
    pub supports_aich: bool,
    pub supports_unicode: bool,
    pub supports_secure_ident: bool,
    pub secure_ident_level: u8,
    pub supports_preview: bool,
    pub supports_multi_packet: bool,
    pub compatible_client: u8,
    pub version_major: u8,
    pub emule_version_min: u8,
    pub version_update: u8,
    pub mod_version: String,
    pub peer_name: String,
    /// Ember Peer Exchange support (MISCOPTIONS2 bit 20)
    pub is_ember: bool,
    /// EPX protocol version (MISCOPTIONS2 bits 21-23, 0-7)
    pub epx_version: u8,
    /// Ember-specific identity hash for the friend system (from EmuleInfo tag 0x56)
    pub ember_hash: Option<[u8; 16]>,
}

/// Build Hello with buddy info tags.
pub fn build_hello_with_buddy(user_hash: &[u8; 16], client_id: u32, tcp_port: u16, udp_port: u16, nickname: &str, buddy: Option<BuddyInfo>) -> Vec<u8> {
    build_hello_inner(
        user_hash,
        client_id,
        tcp_port,
        nickname,
        true,
        buddy,
        &HelloOptions::default_for_udp_port(udp_port),
    )
}

pub fn build_hello_with_buddy_opts(
    user_hash: &[u8; 16],
    client_id: u32,
    tcp_port: u16,
    nickname: &str,
    buddy: Option<BuddyInfo>,
    options: &HelloOptions,
) -> Vec<u8> {
    build_hello_inner(user_hash, client_id, tcp_port, nickname, true, buddy, options)
}

pub fn build_hello_answer_with_buddy_opts(
    user_hash: &[u8; 16],
    client_id: u32,
    tcp_port: u16,
    nickname: &str,
    buddy: Option<BuddyInfo>,
    options: &HelloOptions,
) -> Vec<u8> {
    build_hello_inner(user_hash, client_id, tcp_port, nickname, false, buddy, options)
}

/// Compute CT_EMULE_MISCOPTIONS1 matching eMule BaseClient.cpp SendHelloTypePacket.
pub fn build_misc_options1() -> u32 {
      (1u32 << 29)   // AICH ver 1
    | (1u32 << 28)   // Unicode
    | (4u32 << 24)   // UDP ver 4
    | (1u32 << 20)   // Compression ver 1
    | (3u32 << 16)   // Secure ident ver 3
    | (4u32 << 12)   // Source exchange ver 4
    | (2u32 << 8)    // Extended requests ver 2
    | (1u32 << 4)    // Comments ver 1
    | (0u32 << 3)    // No peer cache
    | (1u32 << 2)    // No view shared files
    | (1u32 << 1)    // Multi-packet support
    | (0u32 << 0)    // Preview support
}

/// Compute CT_EMULE_MISCOPTIONS2 matching eMule BaseClient.cpp SendHelloTypePacket.
/// Only standard eMule-defined bits are set; Ember identification uses the
/// ET_MOD_VERSION tag in EmuleInfo instead to avoid triggering anti-leecher
/// detection in eMule mods that reject unknown bits in reserved positions.
pub fn build_misc_options2(options: &HelloOptions) -> u32 {
    let kad_version = options.kad_version as u32;
      (1u32 << 13)       // uFileIdentifiers
    | ((options.supports_direct_udp_callback as u32) << 12)
    | ((options.supports_captcha as u32) << 11)
    | (1u32 << 10)       // uSupportsSourceEx2
    | ((options.requires_crypt_layer as u32) << 9)
    | ((options.requests_crypt_layer as u32) << 8)
    | ((options.supports_crypt_layer as u32) << 7)
    | (0u32 << 6)        // reserved
    | (1u32 << 5)        // uExtMultiPacket
    | (1u32 << 4)        // uSupportLargeFiles
    | (kad_version << 0) // uKadVersion (bits 0-3)
}

fn build_hello_inner(
    user_hash: &[u8; 16],
    client_id: u32,
    tcp_port: u16,
    nickname: &str,
    include_hash_size: bool,
    buddy: Option<BuddyInfo>,
    options: &HelloOptions,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    if include_hash_size {
        buf.write_u8(16).unwrap();
    }
    buf.write_all(user_hash).unwrap();
    buf.write_u32::<LittleEndian>(client_id).unwrap();
    buf.write_u16::<LittleEndian>(tcp_port).unwrap();

    // eMule SendHelloTypePacket sends 6 base tags (+2 if buddy)
    let mut tag_count: u32 = 6;
    if buddy.is_some() {
        tag_count += 2;
    }
    buf.write_u32::<LittleEndian>(tag_count).unwrap();

    // Tag 1: CT_NAME (0x01)
    write_ed2k_tag(&mut buf, 0x01, &Ed2kTagValue::String(nickname.to_string()));
    // Tag 2: CT_VERSION (0x11) = EDONKEYVERSION (0x3C)
    write_ed2k_tag(&mut buf, 0x11, &Ed2kTagValue::Uint32(0x3C));
    // Tag 3: CT_EMULE_UDPPORTS (0xF9) = (kadPort << 16) | udpPort
    let udp_ports: u32 = ((options.kad_port as u32) << 16) | (options.udp_port as u32);
    write_ed2k_tag(&mut buf, 0xF9, &Ed2kTagValue::Uint32(udp_ports));
    // Tag 4: CT_EMULE_MISCOPTIONS1 (0xFA)
    write_ed2k_tag(&mut buf, 0xFA, &Ed2kTagValue::Uint32(build_misc_options1()));
    // Tag 5: CT_EMULE_MISCOPTIONS2 (0xFE)
    write_ed2k_tag(&mut buf, 0xFE, &Ed2kTagValue::Uint32(build_misc_options2(options)));
    // Tag 6: CT_EMULE_VERSION (0xFB) - claim 0.50a (last official eMule release)
    // Using a real version avoids anti-leecher detection for impossible version numbers.
    let emule_version: u32 = (0u32 << 24) | (0u32 << 17) | (50u32 << 10) | (0u32 << 7);
    write_ed2k_tag(&mut buf, 0xFB, &Ed2kTagValue::Uint32(emule_version));

    // Optional buddy tags
    if let Some(ref bi) = buddy {
        write_ed2k_tag(&mut buf, 0xFC, &Ed2kTagValue::Uint32(bi.buddy_ip));
        write_ed2k_tag(&mut buf, 0xFD, &Ed2kTagValue::Uint32(bi.buddy_port as u32));
    }

    buf.write_u32::<LittleEndian>(options.server_ip).unwrap();
    buf.write_u16::<LittleEndian>(options.server_port).unwrap();

    buf
}

/// Write a single ed2k tag in old format (type, name_len=1, name_id, value).
fn write_ed2k_tag(buf: &mut Vec<u8>, name_id: u8, value: &Ed2kTagValue) {
    match value {
        Ed2kTagValue::String(s) => {
            buf.write_u8(0x02).unwrap();
            buf.write_u16::<LittleEndian>(1).unwrap();
            buf.write_u8(name_id).unwrap();
            let bytes = s.as_bytes();
            let clamped = &bytes[..bytes.len().min(u16::MAX as usize)];
            buf.write_u16::<LittleEndian>(clamped.len() as u16).unwrap();
            buf.write_all(clamped).unwrap();
        }
        Ed2kTagValue::Uint32(v) => {
            buf.write_u8(0x03).unwrap();
            buf.write_u16::<LittleEndian>(1).unwrap();
            buf.write_u8(name_id).unwrap();
            buf.write_u32::<LittleEndian>(*v).unwrap();
        }
        Ed2kTagValue::Uint16(v) => {
            buf.write_u8(0x08).unwrap();
            buf.write_u16::<LittleEndian>(1).unwrap();
            buf.write_u8(name_id).unwrap();
            buf.write_u16::<LittleEndian>(*v).unwrap();
        }
        Ed2kTagValue::Uint8(v) => {
            buf.write_u8(0x09).unwrap();
            buf.write_u16::<LittleEndian>(1).unwrap();
            buf.write_u8(name_id).unwrap();
            buf.write_u8(*v).unwrap();
        }
    }
}

/// Build an EmuleInfo packet payload matching eMule BaseClient.cpp SendMuleInfoPacket.
/// Format: version(1) + EMULE_PROTOCOL(1) + tag_count(4) + 8 ET_ tags.
pub fn build_emule_info(udp_port: u16, obfuscation_enabled: bool, ember_hash: Option<&[u8; 16]>) -> Vec<u8> {
    let mut buf = Vec::with_capacity(100);

    // eMule: data.WriteUInt8((uint8)theApp.m_uCurVersionShort) -- 0x32 for 0.50
    buf.write_u8(0x32).unwrap();
    // eMule: data.WriteUInt8(EMULE_PROTOCOL) -- 0x01, CRITICAL: peers discard without this
    buf.write_u8(0x01).unwrap();

    let tag_count: u32 = if ember_hash.is_some() { 9 } else { 8 };
    buf.write_u32::<LittleEndian>(tag_count).unwrap();

    // ET_COMPRESSION (0x20) = 1
    write_ed2k_tag(&mut buf, 0x20, &Ed2kTagValue::Uint8(1));
    // ET_UDPVER (0x22) = 4 (must match MISCOPTIONS1 UDP ver to avoid downgrade)
    write_ed2k_tag(&mut buf, 0x22, &Ed2kTagValue::Uint8(4));
    // ET_UDPPORT (0x21) = udp_port
    write_ed2k_tag(&mut buf, 0x21, &Ed2kTagValue::Uint16(udp_port));
    // ET_SOURCEEXCHANGE (0x23) = 4 — must match MISCOPTIONS1 SX version
    write_ed2k_tag(&mut buf, 0x23, &Ed2kTagValue::Uint8(4));
    // ET_COMMENTS (0x24) = 1
    write_ed2k_tag(&mut buf, 0x24, &Ed2kTagValue::Uint8(1));
    // ET_EXTENDEDREQUEST (0x25) = 2
    write_ed2k_tag(&mut buf, 0x25, &Ed2kTagValue::Uint8(2));
    // ET_FEATURES (0x27): bits 0-1 = SecureIdent level, bit 2 = preview,
    // bit 3 = SupportsCryptLayer, bit 4 = RequestsCryptLayer, bit 5 = RequiresCryptLayer
    let features: u8 = 3        // SecIdent level 3
        | (0 << 2)              // no preview
        | ((obfuscation_enabled as u8) << 3)  // SupportsCryptLayer — must match Hello MISCOPTIONS2
        | ((obfuscation_enabled as u8) << 4)  // RequestsCryptLayer — must match Hello MISCOPTIONS2
        | (0 << 5);             // no RequiresCryptLayer
    write_ed2k_tag(&mut buf, 0x27, &Ed2kTagValue::Uint8(features));
    // ET_MOD_VERSION (0x55) — identifies this client as Ember
    write_ed2k_tag(&mut buf, 0x55, &Ed2kTagValue::String(format!("Ember {}", env!("CARGO_PKG_VERSION"))));
    // ET_EMBER_HASH (0x56) — Ember-specific identity for the friend system
    if let Some(hash) = ember_hash {
        buf.write_u8(0x01).unwrap(); // tag type HASH (16 bytes)
        buf.write_u16::<LittleEndian>(1).unwrap(); // name length = 1
        buf.write_u8(0x56).unwrap(); // name_id
        buf.write_all(hash).unwrap();
    }

    buf
}

/// Parse an EmuleInfo or EmuleInfoAnswer payload into peer capabilities.
/// Format: version(1) + protocol(1) + tag_count(u32) + tags.
/// Also handles legacy format without protocol byte (version(1) + tag_count(u32) + tags).
pub fn parse_emule_info(payload: &[u8]) -> PeerCapabilities {
    let mut caps = PeerCapabilities::default();
    if payload.len() < 6 { return caps; }
    let mut cursor = Cursor::new(payload);
    let _version = cursor.read_u8().unwrap_or(0);
    let protocol_or_tag_count_byte = cursor.read_u8().unwrap_or(0);

    let tag_count = if protocol_or_tag_count_byte == 0x01 {
        // New format with EMULE_PROTOCOL byte
        cursor.read_u32::<LittleEndian>().unwrap_or(0)
    } else {
        // Legacy format without protocol byte -- rewind and read u32
        cursor.set_position(1);
        cursor.read_u32::<LittleEndian>().unwrap_or(0)
    };

    for _ in 0..tag_count.min(20) {
        let pos = cursor.position() as usize;
        if pos >= payload.len() { break; }

        let tag_type = cursor.read_u8().unwrap_or(0);
        let name_len = match cursor.read_u16::<LittleEndian>() {
            Ok(n) => n as usize,
            Err(_) => break,
        };
        if pos + 3 + name_len > payload.len() { break; }
        let mut name_buf = vec![0u8; name_len];
        if cursor.read_exact(&mut name_buf).is_err() { break; }
        let name_id = if name_len == 1 { name_buf[0] } else { 0 };

        let int_val = match tag_type {
            0x03 => cursor.read_u32::<LittleEndian>().unwrap_or(0),
            0x08 => cursor.read_u16::<LittleEndian>().unwrap_or(0) as u32,
            0x09 => cursor.read_u8().unwrap_or(0) as u32,
            0x0B => { cursor.read_u64::<LittleEndian>().unwrap_or(0); continue; } // UINT64 — skip
            0x02 => {
                let slen = cursor.read_u16::<LittleEndian>().unwrap_or(0) as usize;
                let p = cursor.position() as usize;
                if p + slen > payload.len() { break; }
                if name_id == 0x55 { // ET_MOD_VERSION
                    let bytes = &payload[p..p + slen];
                    caps.mod_version = String::from_utf8_lossy(bytes).to_string();
                    if caps.mod_version.starts_with("Ember") {
                        caps.is_ember = true;
                    }
                }
                cursor.set_position((p + slen) as u64);
                continue;
            }
            0x01 => { // HASH — 16 bytes
                let p = cursor.position() as usize;
                if p + 16 > payload.len() { break; }
                if name_id == 0x56 { // ET_EMBER_HASH
                    let mut h = [0u8; 16];
                    h.copy_from_slice(&payload[p..p + 16]);
                    if h != [0u8; 16] {
                        caps.ember_hash = Some(h);
                    }
                }
                cursor.set_position((p + 16) as u64);
                continue;
            }
            0x04 => { cursor.read_u32::<LittleEndian>().unwrap_or(0); continue; } // FLOAT32
            0x05 => { cursor.read_u8().unwrap_or(0); continue; } // BOOL
            0x06 => { // BOOLARRAY
                let count = cursor.read_u16::<LittleEndian>().unwrap_or(0) as usize;
                let byte_count = (count + 7) / 8;
                let p = cursor.position() as usize;
                if p + byte_count > payload.len() { break; }
                cursor.set_position((p + byte_count) as u64);
                continue;
            }
            0x07 => { // BLOB
                let blen = cursor.read_u32::<LittleEndian>().unwrap_or(0) as usize;
                let p = cursor.position() as usize;
                if blen > payload.len() || p > payload.len() - blen { break; }
                cursor.set_position((p + blen) as u64);
                continue;
            }
            0x0A => { // BSOB
                let blen = cursor.read_u8().unwrap_or(0) as usize;
                let p = cursor.position() as usize;
                if p + blen > payload.len() { break; }
                cursor.set_position((p + blen) as u64);
                continue;
            }
            t if (0x11..=0x20).contains(&t) => { // STR1..STR16
                let slen = (t - 0x11 + 1) as usize;
                let p = cursor.position() as usize;
                if p + slen > payload.len() { break; }
                cursor.set_position((p + slen) as u64);
                continue;
            }
            _ => {
                tracing::debug!("parse_emule_info: unknown tag type 0x{tag_type:02X} at offset {pos}, stopping parse");
                break;
            }
        };

        match name_id {
            0x20 => caps.compression_ver = int_val as u8,   // ET_COMPRESSION
            0x21 => caps.udp_port = int_val as u16,         // ET_UDPPORT
            0x22 => caps.udp_ver = int_val as u8,           // ET_UDPVER
            0x23 => caps.source_exchange_ver = int_val as u8, // ET_SOURCEEXCHANGE
            0x24 => caps.comments_ver = int_val as u8,      // ET_COMMENTS
            0x25 => caps.extended_requests_ver = int_val as u8, // ET_EXTENDEDREQUEST
            0x26 => caps.compatible_client = int_val as u8,  // ET_COMPATIBLECLIENT
            0x27 => {                                         // ET_FEATURES
                caps.secure_ident_level = (int_val & 0x03) as u8;
                caps.supports_secure_ident = caps.secure_ident_level != 0;
                // eMule BaseClient.cpp: bit 2 = preview, bits 3-5 = crypt layer
                caps.supports_preview = (int_val & 0x04) != 0;
                caps.supports_crypt_layer |= (int_val & 0x08) != 0;
                caps.requests_crypt_layer |= (int_val & 0x10) != 0;
                caps.requires_crypt_layer |= (int_val & 0x20) != 0;
            }
            _ => {}
        }
    }
    caps
}

/// Parse capabilities from an OP_HELLOANSWER payload using the classic eMule
/// hello tag layout from BaseClient.cpp.
pub fn parse_hello_answer(payload: &[u8]) -> io::Result<([u8; 16], PeerCapabilities)> {
    if payload.len() < 16 + 4 + 2 + 4 + 4 + 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "helloanswer too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut user_hash = [0u8; 16];
    cursor.read_exact(&mut user_hash)?;
    let _client_id = cursor.read_u32::<LittleEndian>()?;
    let hello_tcp_port = cursor.read_u16::<LittleEndian>()?;
    let tag_count = cursor.read_u32::<LittleEndian>()?;

    let mut caps = PeerCapabilities::default();
    caps.tcp_port = hello_tcp_port;
    for _ in 0..tag_count.min(32) {
        let tag_type_raw = cursor.read_u8().unwrap_or(0);
        // Support new-format tags (0x80 bit = 1-byte name)
        let (tag_type, name_id) = if tag_type_raw & 0x80 != 0 {
            let real_type = tag_type_raw & 0x7F;
            let nid = cursor.read_u8().unwrap_or(0);
            (real_type, nid)
        } else {
            let name_len = cursor.read_u16::<LittleEndian>().unwrap_or(0) as usize;
            let nid = if name_len == 1 {
                cursor.read_u8().unwrap_or(0)
            } else {
                let mut name = vec![0u8; name_len];
                if cursor.read_exact(&mut name).is_err() {
                    break;
                }
                0
            };
            (tag_type_raw, nid)
        };

        let int_val = match tag_type {
            0x03 => cursor.read_u32::<LittleEndian>().unwrap_or(0),
            0x08 => cursor.read_u16::<LittleEndian>().unwrap_or(0) as u32,
            0x09 => cursor.read_u8().unwrap_or(0) as u32,
            0x0B => { cursor.read_u64::<LittleEndian>().unwrap_or(0); continue; }
            0x02 => {
                let slen = cursor.read_u16::<LittleEndian>().unwrap_or(0) as usize;
                let pos = cursor.position() as usize;
                if pos + slen > payload.len() {
                    break;
                }
                if name_id == 0x01 {
                    caps.peer_name = String::from_utf8_lossy(&payload[pos..pos + slen]).to_string();
                }
                cursor.set_position((pos + slen) as u64);
                continue;
            }
            0x01 => { let p = cursor.position() as usize; if p + 16 > payload.len() { break; } cursor.set_position((p + 16) as u64); continue; }
            0x04 => { cursor.read_u32::<LittleEndian>().unwrap_or(0); continue; }
            0x05 => { cursor.read_u8().unwrap_or(0); continue; }
            0x06 => { let count = cursor.read_u16::<LittleEndian>().unwrap_or(0) as usize; let bc = (count + 7) / 8; let p = cursor.position() as usize; if p + bc > payload.len() { break; } cursor.set_position((p + bc) as u64); continue; }
            0x07 => { let blen = cursor.read_u32::<LittleEndian>().unwrap_or(0) as usize; let p = cursor.position() as usize; if blen > payload.len() || p > payload.len() - blen { break; } cursor.set_position((p + blen) as u64); continue; }
            0x0A => { let blen = cursor.read_u8().unwrap_or(0) as usize; let p = cursor.position() as usize; if p + blen > payload.len() { break; } cursor.set_position((p + blen) as u64); continue; }
            t if (0x11..=0x20).contains(&t) => { let slen = (t - 0x11 + 1) as usize; let p = cursor.position() as usize; if p + slen > payload.len() { break; } cursor.set_position((p + slen) as u64); continue; }
            _ => { break; }
        };

        match name_id {
            0xF9 => {
                caps.kad_port = (int_val >> 16) as u16;
                caps.udp_port = int_val as u16;
            }
            0xFA => {
                caps.supports_aich = ((int_val >> 29) & 0x07) != 0;
                caps.supports_unicode = ((int_val >> 28) & 0x01) != 0;
                caps.udp_ver = ((int_val >> 24) & 0x0F) as u8;
                caps.compression_ver = ((int_val >> 20) & 0x0F) as u8;
                caps.secure_ident_level = ((int_val >> 16) & 0x0F) as u8;
                caps.supports_secure_ident = caps.secure_ident_level != 0;
                caps.source_exchange_ver = ((int_val >> 12) & 0x0F) as u8;
                caps.extended_requests_ver = ((int_val >> 8) & 0x0F) as u8;
                caps.comments_ver = ((int_val >> 4) & 0x0F) as u8;
                caps.supports_multi_packet = ((int_val >> 1) & 0x01) != 0;
                caps.supports_preview = (int_val & 0x01) != 0;
            }
            0xFE => {
                caps.is_ember = ((int_val >> 20) & 0x01) != 0;
                caps.epx_version = ((int_val >> 21) & 0x07) as u8;
                caps.supports_file_ident = ((int_val >> 13) & 0x01) != 0;
                caps.supports_direct_udp_callback = ((int_val >> 12) & 0x01) != 0;
                caps.supports_captcha = ((int_val >> 11) & 0x01) != 0;
                caps.supports_source_ex2 = ((int_val >> 10) & 0x01) != 0;
                caps.requires_crypt_layer = ((int_val >> 9) & 0x01) != 0;
                caps.requests_crypt_layer = ((int_val >> 8) & 0x01) != 0;
                caps.supports_crypt_layer = ((int_val >> 7) & 0x01) != 0;
                caps.ext_multi_packet = ((int_val >> 5) & 0x01) != 0;
                caps.supports_large_files = ((int_val >> 4) & 0x01) != 0;
                caps.kad_version = (int_val & 0x0F) as u8;
                caps.requests_crypt_layer &= caps.supports_crypt_layer;
                caps.requires_crypt_layer &= caps.requests_crypt_layer;
            }
            0xFB => {
                caps.compatible_client = (int_val >> 24) as u8;
                caps.version_major = ((int_val >> 17) & 0x7F) as u8;
                caps.emule_version_min = ((int_val >> 10) & 0x7F) as u8;
                caps.version_update = ((int_val >> 7) & 0x07) as u8;
            }
            _ => {}
        }
    }

    // eMule appends server_ip(u32) + server_port(u16) after the tag list
    let remaining = payload.len() - cursor.position() as usize;
    if remaining >= 6 {
        let _server_ip = cursor.read_u32::<LittleEndian>().unwrap_or(0);
        let _server_port = cursor.read_u16::<LittleEndian>().unwrap_or(0);
    }

    Ok((user_hash, caps))
}

pub fn parse_hello_packet(payload: &[u8]) -> io::Result<([u8; 16], PeerCapabilities)> {
    if payload.first().copied() == Some(16) {
        parse_hello_answer(&payload[1..])
    } else {
        parse_hello_answer(payload)
    }
}

/// Build an enhanced OP_REASKFILEPING UDP payload (udp_ver > 3).
///
/// Wire format (eMule CUpDownClient::UDPReaskForDownload):
///   file_hash (16) + part_count (u16) + bitmap (ceil(part_count/8)) + complete_sources (u16)
///
/// `completed_parts` may be `None` to send an all-zeros bitmap (= "we need every part").
pub fn build_reask_file_ping(
    file_hash: &[u8; 16],
    file_size: u64,
    complete_source_count: u16,
    completed_parts: Option<&[bool]>,
) -> Vec<u8> {
    let part_count = ed2k_wire_part_count(file_size) as u16;
    let bitmap_bytes = ((part_count as usize) + 7) / 8;
    let mut buf = Vec::with_capacity(16 + 2 + bitmap_bytes + 2);
    buf.extend_from_slice(file_hash);
    buf.extend_from_slice(&part_count.to_le_bytes());
    for byte_idx in 0..bitmap_bytes {
        let mut byte = 0u8;
        if let Some(parts) = completed_parts {
            for bit in 0..8 {
                let idx = byte_idx * 8 + bit;
                if idx < part_count as usize {
                    if parts.get(idx).copied().unwrap_or(false) {
                        byte |= 1 << bit;
                    }
                }
            }
        }
        buf.push(byte);
    }
    buf.extend_from_slice(&complete_source_count.to_le_bytes());
    buf
}

/// Build a SetReqFileId + RequestFileName packet payload.
pub fn build_file_request(file_hash: &[u8; 16]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.write_all(file_hash).unwrap();
    buf
}

/// Build a RequestParts payload with 32-bit offsets for legacy peers.
/// Used when peer does not advertise SupportsLargeFiles.
///
/// Callers MUST filter out any offsets exceeding `u32::MAX` before calling this.
/// Any offset above `u32::MAX` is treated as a logic error (debug_assert) and
/// clamped to 0 in release builds as a safety net.
pub fn build_request_parts(file_hash: &[u8; 16], offsets: &[(u64, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 24);
    buf.write_all(file_hash).unwrap();
    for i in 0..3 {
        if i < offsets.len() {
            debug_assert!(offsets[i].0 <= u32::MAX as u64, "caller must filter >4GiB offsets");
            let v = offsets[i].0.min(u32::MAX as u64) as u32;
            buf.write_u32::<LittleEndian>(v).unwrap();
        } else {
            buf.write_u32::<LittleEndian>(0).unwrap();
        }
    }
    for i in 0..3 {
        if i < offsets.len() {
            debug_assert!(offsets[i].1 <= u32::MAX as u64, "caller must filter >4GiB offsets");
            let v = offsets[i].1.min(u32::MAX as u64) as u32;
            buf.write_u32::<LittleEndian>(v).unwrap();
        } else {
            buf.write_u32::<LittleEndian>(0).unwrap();
        }
    }
    buf
}

/// Build a RequestParts_I64 payload (3 part requests).
/// Callers pass exclusive end offsets (byte past last data byte).
pub fn build_request_parts_i64(file_hash: &[u8; 16], offsets: &[(u64, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + 48);
    buf.write_all(file_hash).unwrap();

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

/// Parse a CompressedPart_I64 payload (64-bit start offset).
/// Returns (hash, start_offset, total_packed_size, compressed_chunk).
/// `total_packed_size` is the total compressed byte count for this block
/// (eMule may split compressed data across multiple packets of up to 10240 bytes each).
pub fn parse_compressed_part_i64(payload: &[u8]) -> io::Result<([u8; 16], u64, u32, &[u8])> {
    if payload.len() < 28 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "compressed part i64 too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut hash = [0u8; 16];
    cursor.read_exact(&mut hash)?;
    let start = cursor.read_u64::<LittleEndian>()?;
    let total_packed_size = cursor.read_u32::<LittleEndian>()?;
    let data_start = cursor.position() as usize;
    Ok((hash, start, total_packed_size, &payload[data_start..]))
}

/// Parse a CompressedPart payload (32-bit start offset).
/// Returns (hash, start_offset, total_packed_size, compressed_chunk).
/// `total_packed_size` is the total compressed byte count for this block
/// (eMule may split compressed data across multiple packets of up to 10240 bytes each).
pub fn parse_compressed_part_32(payload: &[u8]) -> io::Result<([u8; 16], u64, u32, &[u8])> {
    if payload.len() < 24 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "compressed part 32 too short"));
    }
    let mut cursor = Cursor::new(payload);
    let mut hash = [0u8; 16];
    cursor.read_exact(&mut hash)?;
    let start = cursor.read_u32::<LittleEndian>()? as u64;
    let total_packed_size = cursor.read_u32::<LittleEndian>()?;
    let data_start = cursor.position() as usize;
    Ok((hash, start, total_packed_size, &payload[data_start..]))
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

    const MAX_HASHSET_PARTS: usize = 10_000;
    if count > MAX_HASHSET_PARTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("hashset answer claims {count} hashes, exceeds maximum {MAX_HASHSET_PARTS}"),
        ));
    }

    let remaining = payload.len() - cursor.position() as usize;
    if remaining < count * 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("hashset answer claims {count} hashes but only {remaining} bytes remain"),
        ));
    }

    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut h = [0u8; 16];
        cursor.read_exact(&mut h)?;
        hashes.push(h);
    }

    Ok((hash, hashes))
}

pub fn build_hashset_request2(
    file_hash: &[u8; 16],
    file_size: u64,
    aich_hash: Option<[u8; 20]>,
    request_md4: bool,
    request_aich: bool,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    FileIdentifier {
        md4_hash: *file_hash,
        file_size: Some(file_size),
        aich_hash,
    }
    .write_identifier(&mut buf);
    let mut options = 0u8;
    if request_md4 {
        options |= 0x01;
    }
    if request_aich {
        options |= 0x02;
    }
    buf.push(options);
    buf
}

pub struct Hashset2Response {
    pub identifier: FileIdentifier,
    pub md4_hashes: Option<Vec<[u8; 16]>>,
    pub aich_master_hash: Option<[u8; 20]>,
    pub aich_part_hashes: Option<Vec<[u8; 20]>>,
}

pub fn merge_caps(base: &mut PeerCapabilities, update: PeerCapabilities) {
    if update.udp_port != 0 { base.udp_port = update.udp_port; }
    if update.kad_port != 0 { base.kad_port = update.kad_port; }
    base.compression_ver = base.compression_ver.max(update.compression_ver);
    base.udp_ver = base.udp_ver.max(update.udp_ver);
    base.source_exchange_ver = base.source_exchange_ver.max(update.source_exchange_ver);
    base.extended_requests_ver = base.extended_requests_ver.max(update.extended_requests_ver);
    base.comments_ver = base.comments_ver.max(update.comments_ver);
    base.supports_large_files |= update.supports_large_files;
    base.supports_crypt_layer |= update.supports_crypt_layer;
    base.requests_crypt_layer |= update.requests_crypt_layer;
    base.requires_crypt_layer |= update.requires_crypt_layer;
    base.requires_crypt_layer &= base.requests_crypt_layer;
    base.requests_crypt_layer &= base.supports_crypt_layer;
    base.supports_source_ex2 |= update.supports_source_ex2;
    base.ext_multi_packet |= update.ext_multi_packet;
    base.supports_file_ident |= update.supports_file_ident;
    base.supports_direct_udp_callback |= update.supports_direct_udp_callback;
    base.supports_captcha |= update.supports_captcha;
    base.kad_version = base.kad_version.max(update.kad_version);
    base.supports_aich |= update.supports_aich;
    base.supports_unicode |= update.supports_unicode;
    base.supports_secure_ident |= update.supports_secure_ident;
    base.secure_ident_level = base.secure_ident_level.max(update.secure_ident_level);
    base.supports_preview |= update.supports_preview;
    base.supports_multi_packet |= update.supports_multi_packet;
    if update.compatible_client != 0 { base.compatible_client = update.compatible_client; }
    if update.version_major != 0 { base.version_major = update.version_major; }
    if update.emule_version_min != 0 { base.emule_version_min = update.emule_version_min; }
    if update.version_update != 0 { base.version_update = update.version_update; }
    if !update.mod_version.is_empty() { base.mod_version = update.mod_version; }
    if !update.peer_name.is_empty() { base.peer_name = update.peer_name; }
    base.is_ember |= update.is_ember;
    base.epx_version = base.epx_version.max(update.epx_version);
    if update.ember_hash.is_some() { base.ember_hash = update.ember_hash; }
}

/// Build a human-readable client software string from peer capabilities.
pub fn client_software_from_caps(caps: &PeerCapabilities) -> String {
    if caps.is_ember {
        if caps.mod_version.starts_with("Ember") && caps.mod_version.len() > 5 {
            return caps.mod_version.clone();
        }
        return "Ember".to_string();
    }
    let name = match caps.compatible_client {
        0 => "eMule",
        1 => "cDonkey",
        2 => "xMule",
        3 => "aMule",
        4 => "Shareaza",
        5 => "eMule Plus",
        6 => "Hydranode",
        10 => "MLDonkey",
        20 => "lphant",
        0x26 => "IMule",
        40 => "Shareaza",
        _ if caps.compatible_client != 0 => "eMule Compat",
        _ => "eD2k",
    };
    if caps.version_major != 0 || caps.emule_version_min != 0 {
        if caps.version_update != 0 {
            format!("{name} {}.{}.{}", caps.version_major, caps.emule_version_min, caps.version_update)
        } else {
            format!("{name} {}.{}", caps.version_major, caps.emule_version_min)
        }
    } else {
        name.to_string()
    }
}

pub fn parse_hashset_answer2(payload: &[u8]) -> io::Result<Hashset2Response> {
    let mut cursor = Cursor::new(payload);
    let ident = FileIdentifier::read_identifier(&mut cursor)?;
    let options = cursor.read_u8()?;
    let has_md4 = (options & 0x01) != 0;
    let has_aich = (options & 0x02) != 0;
    const MAX_HASHSET2_PARTS: usize = 10_000;
    let mut md4_hashes = None;
    if has_md4 {
        let mut md4_hash = [0u8; 16];
        cursor.read_exact(&mut md4_hash)?;
        if md4_hash != ident.md4_hash {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "hashset2 md4 header mismatch"));
        }
        let count = cursor.read_u16::<LittleEndian>()? as usize;
        if count > MAX_HASHSET2_PARTS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("hashset2 md4 count {count} exceeds maximum")));
        }
        let remaining = payload.len() - cursor.position() as usize;
        if remaining < count * 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("hashset2 md4 claims {count} hashes but only {remaining} bytes remain")));
        }
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            let mut h = [0u8; 16];
            cursor.read_exact(&mut h)?;
            hashes.push(h);
        }
        md4_hashes = Some(hashes);
    }
    let (aich_master_hash, aich_part_hashes) = if has_aich {
        let mut master = [0u8; 20];
        cursor.read_exact(&mut master)?;
        let count = cursor.read_u16::<LittleEndian>()? as usize;
        if count > MAX_HASHSET2_PARTS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("hashset2 aich count {count} exceeds maximum")));
        }
        let remaining = payload.len() - cursor.position() as usize;
        if remaining < count * 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("hashset2 aich claims {count} hashes but only {remaining} bytes remain")));
        }
        let mut hashes = Vec::with_capacity(count);
        for _ in 0..count {
            let mut h = [0u8; 20];
            cursor.read_exact(&mut h)?;
            hashes.push(h);
        }
        (Some(master), Some(hashes))
    } else {
        (None, None)
    };
    Ok(Hashset2Response {
        identifier: ident,
        md4_hashes,
        aich_master_hash,
        aich_part_hashes,
    })
}

#[derive(Debug, Clone)]
pub struct SourceExchange1Entry {
    pub source_id: u32,
    pub tcp_port: u16,
    pub server_ip: u32,
    pub server_port: u16,
    pub user_hash: Option<[u8; 16]>,
    pub crypt_options: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct SourceExchange2Entry {
    pub source_id: u32,
    pub tcp_port: u16,
    pub server_ip: u32,
    pub server_port: u16,
    pub user_hash: Option<[u8; 16]>,
    pub crypt_options: Option<u8>,
}

/// Parse an OP_ANSWERSOURCES2 payload using the fixed-size eMule SX2 layout.
///
/// Wire format:
///   version(1) + file_hash(16) + count(u16) + entries[count]
///
/// Entry sizes by version (matching eMule PartFile::AddClientSources):
///   v1: 4 + 2 + 4 + 2
///   v2/v3: v1 + 16-byte user hash
///   v4: v2/v3 + 1-byte crypt options
pub fn parse_answer_sources2(payload: &[u8]) -> io::Result<(u8, [u8; 16], Vec<SourceExchange2Entry>)> {
    if payload.len() < 19 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "answersources2 too short"));
    }

    let version = payload[0];
    let entry_size = match version {
        1 => 12usize,
        2 | 3 => 28usize,
        4 => 29usize,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SX2 version {version}"),
            ))
        }
    };

    let mut file_hash = [0u8; 16];
    file_hash.copy_from_slice(&payload[1..17]);
    let count = u16::from_le_bytes([payload[17], payload[18]]) as usize;
    let expected_len = 19 + count * entry_size;
    if payload.len() < expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid SX2 payload size: got {}, expected {} for version {} count {}",
                payload.len(),
                expected_len,
                version,
                count
            ),
        ));
    }

    let mut cursor = Cursor::new(&payload[19..]);
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let source_id = cursor.read_u32::<LittleEndian>()?;
        let tcp_port = cursor.read_u16::<LittleEndian>()?;
        let server_ip = cursor.read_u32::<LittleEndian>()?;
        let server_port = cursor.read_u16::<LittleEndian>()?;
        let user_hash = if version >= 2 {
            let mut hash = [0u8; 16];
            cursor.read_exact(&mut hash)?;
            Some(hash)
        } else {
            None
        };
        let crypt_options = if version >= 4 {
            Some(cursor.read_u8()?)
        } else {
            None
        };
        entries.push(SourceExchange2Entry {
            source_id,
            tcp_port,
            server_ip,
            server_port,
            user_hash,
            crypt_options,
        });
    }

    Ok((version, file_hash, entries))
}

pub fn parse_answer_sources(
    payload: &[u8],
    client_sx_version: u8,
) -> io::Result<(u8, [u8; 16], Vec<SourceExchange1Entry>)> {
    if payload.len() < 18 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "answersources too short",
        ));
    }

    let mut cursor = Cursor::new(payload);
    let mut file_hash = [0u8; 16];
    cursor.read_exact(&mut file_hash)?;
    let count = cursor.read_u16::<LittleEndian>()? as usize;
    let data_size = payload.len() - 18;
    let packet_version = if count * 12 == data_size {
        1
    } else if count * 28 == data_size {
        if client_sx_version == 2 { 2 } else { 3 }
    } else if count * 29 == data_size {
        4
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid legacy SX payload size: count={count} data_size={data_size} client_ver={client_sx_version}"
            ),
        ));
    };
    let mut entries = Vec::with_capacity(count);

    for _ in 0..count {
        let source_id = cursor.read_u32::<LittleEndian>()?;
        let tcp_port = cursor.read_u16::<LittleEndian>()?;
        let server_ip = cursor.read_u32::<LittleEndian>()?;
        let server_port = cursor.read_u16::<LittleEndian>()?;
        let user_hash = if packet_version >= 2 {
            let mut hash = [0u8; 16];
            cursor.read_exact(&mut hash)?;
            Some(hash)
        } else {
            None
        };
        let crypt_options = if packet_version >= 4 {
            Some(cursor.read_u8()?)
        } else {
            None
        };
        entries.push(SourceExchange1Entry {
            source_id,
            tcp_port,
            server_ip,
            server_port,
            user_hash,
            crypt_options,
        });
    }

    Ok((packet_version, file_hash, entries))
}

pub fn build_answer_sources1_versioned(
    sources: &[super::sources::SourceEntry],
    file_hash: &[u8; 16],
    requested_version: u8,
) -> Vec<u8> {
    let version = requested_version.clamp(1, 4);
    let entry_size = match version {
        1 => 12,
        2 | 3 => 28,
        _ => 29,
    };
    let mut resp = Vec::with_capacity(16 + 2 + sources.len() * entry_size);
    resp.extend_from_slice(file_hash);
    resp.extend_from_slice(&(sources.len() as u16).to_le_bytes());
    for src in sources {
        if version < 3 {
            resp.extend_from_slice(&src.ip.octets());
        } else {
            resp.extend_from_slice(&u32::from(src.ip).to_le_bytes());
        }
        resp.extend_from_slice(&src.tcp_port.to_le_bytes());
        resp.extend_from_slice(&src.server_ip.to_le_bytes());
        resp.extend_from_slice(&src.server_port.to_le_bytes());
        if version >= 2 {
            resp.extend_from_slice(&src.user_hash);
        }
        if version >= 4 {
            resp.push(src.connect_options);
        }
    }
    resp
}

/// Sub-opcode inside a MultiPacket request.
#[derive(Debug)]
pub enum MultiPacketSubReq {
    RequestFileName,
    SetReqFileId,
    RequestSources,
    RequestSources2 { version: u8, _options: u16 },
    AichFileHashReq,
}

/// Parsed MultiPacket request.
#[derive(Debug)]
pub struct MultiPacketRequest {
    pub file_hash: [u8; 16],
    pub file_size: Option<u64>,
    pub file_identifier: Option<FileIdentifier>,
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

    let is_ext2 = opcode == OP_MULTIPACKET_EXT2;
    let mut file_size = None;
    let mut file_identifier = None;

    if opcode == OP_MULTIPACKET_EXT2 {
        let ident = FileIdentifier::read_identifier(&mut cursor)?;
        file_hash = ident.md4_hash;
        file_size = ident.file_size;
        file_identifier = Some(ident);
    } else {
        cursor.read_exact(&mut file_hash)?;
    }

    if opcode == OP_MULTIPACKET_EXT {
        file_size = Some(cursor.read_u64::<LittleEndian>()?);
    }

    let mut sub_opcodes = Vec::new();
    while (cursor.position() as usize) < payload.len() {
        let sub_op = cursor.read_u8()?;
        match sub_op {
            OP_REQUESTFILENAME => {
                sub_opcodes.push(MultiPacketSubReq::RequestFileName);
                // eMule ExtendedRequests v1+: partcount(u16) + part_status_bitmap
                // eMule ExtendedRequests v2+: + complete_sources(u16)
                // We must consume this data to keep alignment with subsequent sub-opcodes.
                let remaining = payload.len() - cursor.position() as usize;
                if remaining >= 2 {
                    let part_count = cursor.read_u16::<LittleEndian>()? as usize;
                    let bitmap_bytes = (part_count + 7) / 8;
                    let pos = cursor.position() as usize;
                    if pos + bitmap_bytes <= payload.len() {
                        cursor.set_position((pos + bitmap_bytes) as u64);
                        // v2: complete sources count. Only consume it if it does not
                        // look like the next byte is already another sub-opcode.
                        let next_pos = cursor.position() as usize;
                        if next_pos + 2 <= payload.len() {
                            let next_byte = payload[next_pos];
                            let next_after_u16 = payload.get(next_pos + 2).copied();
                            let is_known_subop = |b: u8| {
                                matches!(
                                    b,
                                    OP_REQUESTFILENAME
                                        | OP_SETREQFILEID
                                        | OP_REQUESTSOURCES
                                        | OP_REQUESTSOURCES2
                                        | OP_AICHFILEHASHREQ
                                )
                            };
                            if !is_known_subop(next_byte)
                                && next_after_u16.is_some_and(is_known_subop)
                            {
                                let _complete_sources = cursor.read_u16::<LittleEndian>()?;
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
            OP_SETREQFILEID => {
                sub_opcodes.push(MultiPacketSubReq::SetReqFileId);
            }
            OP_REQUESTSOURCES => {
                sub_opcodes.push(MultiPacketSubReq::RequestSources);
            }
            OP_REQUESTSOURCES2 => {
                let version = cursor.read_u8()?;
                let options = cursor.read_u16::<LittleEndian>()?;
                sub_opcodes.push(MultiPacketSubReq::RequestSources2 { version, _options: options });
            }
            OP_AICHFILEHASHREQ => {
                sub_opcodes.push(MultiPacketSubReq::AichFileHashReq);
            }
            unknown => {
                tracing::debug!("parse_multipacket: unknown sub-opcode 0x{unknown:02X}, stopping parse");
                break;
            }
        }
    }

    Ok(MultiPacketRequest {
        file_hash,
        file_size,
        file_identifier,
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
    is_complete: bool,
    completed_parts: Option<&[bool]>,
    aich_hash: Option<[u8; 20]>,
    is_ext2: bool,
    sub_opcodes: &[MultiPacketSubReq],
) -> Vec<u8> {
    let ed2k_part_count = ed2k_wire_part_count(file_size) as u16;
    let bitmap_bytes = ((ed2k_part_count as usize) + 7) / 8;
    let name_bytes = file_name.as_bytes();

    let mut buf = Vec::with_capacity(16 + 1 + 2 + name_bytes.len() + 1 + 2 + bitmap_bytes + 8);

    if is_ext2 {
        FileIdentifier {
            md4_hash: *file_hash,
            file_size: Some(file_size),
            aich_hash,
        }
        .write_identifier(&mut buf);
    } else {
        buf.write_all(file_hash).unwrap();
    }

    for sub in sub_opcodes {
        match sub {
            MultiPacketSubReq::RequestFileName => {
                buf.write_u8(OP_REQFILENAMEANSWER).unwrap();
                let clamped_len = name_bytes.len().min(u16::MAX as usize);
                buf.write_u16::<LittleEndian>(clamped_len as u16).unwrap();
                buf.write_all(&name_bytes[..clamped_len]).unwrap();
            }
            MultiPacketSubReq::SetReqFileId => {
                buf.write_u8(OP_FILESTATUS).unwrap();
                if is_complete {
                    buf.write_u16::<LittleEndian>(0).unwrap();
                } else {
                    buf.write_u16::<LittleEndian>(ed2k_part_count).unwrap();
                    for byte_idx in 0..bitmap_bytes {
                        let mut byte = 0u8;
                        for bit in 0..8 {
                            let part_idx = byte_idx * 8 + bit;
                            if part_idx < ed2k_part_count as usize {
                                let is_available = completed_parts
                                    .and_then(|parts| parts.get(part_idx).copied())
                                    .unwrap_or(false);
                                if is_available {
                                    byte |= 1 << bit;
                                }
                            }
                        }
                        buf.write_u8(byte).unwrap();
                    }
                }
            }
            MultiPacketSubReq::RequestSources
            | MultiPacketSubReq::RequestSources2 { .. } => {}
            MultiPacketSubReq::AichFileHashReq => {
                if let Some(aich_hash) = aich_hash {
                    buf.write_u8(OP_AICHFILEHASHANS).unwrap();
                    buf.write_all(&aich_hash).unwrap();
                }
            }
        }
    }

    buf
}

/// Parsed MultiPacketAnswer payload.
#[derive(Debug, Default)]
pub struct MultiPacketAnswer {
    pub file_hash: [u8; 16],
    pub file_identifier: Option<FileIdentifier>,
    pub file_name: Option<String>,
    pub file_status: Option<Vec<bool>>,
    pub aich_hash: Option<[u8; 20]>,
    pub no_file: bool,
}

/// Parse OP_MULTIPACKETANSWER / OP_MULTIPACKETANSWER_EXT2 payload.
///
/// Wire format:
///   <hash 16> [<hasAICH 1> [<AICH 20>]] (<sub-opcode u8><sub-data>)*
pub fn parse_multipacket_answer(payload: &[u8], opcode: u8) -> io::Result<MultiPacketAnswer> {
    if payload.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "multipacket answer too short",
        ));
    }

    let mut cursor = Cursor::new(payload);
    let (file_hash, file_identifier) = if opcode == OP_MULTIPACKETANSWER_EXT2 {
        let ident = FileIdentifier::read_identifier(&mut cursor)?;
        (ident.md4_hash, Some(ident))
    } else {
        let mut file_hash = [0u8; 16];
        cursor.read_exact(&mut file_hash)?;
        (file_hash, None)
    };

    let mut out = MultiPacketAnswer {
        file_hash,
        file_identifier,
        ..Default::default()
    };

    while (cursor.position() as usize) < payload.len() {
        let sub_op = cursor.read_u8()?;
        match sub_op {
            OP_REQFILENAMEANSWER => {
                if cursor.position() as usize + 2 > payload.len() {
                    break;
                }
                let len = cursor.read_u16::<LittleEndian>()? as usize;
                if cursor.position() as usize + len > payload.len() {
                    break;
                }
                let mut name = vec![0u8; len];
                cursor.read_exact(&mut name)?;
                out.file_name = Some(String::from_utf8_lossy(&name).to_string());
            }
            OP_FILESTATUS => {
                if cursor.position() as usize + 2 > payload.len() {
                    break;
                }
                let part_count = cursor.read_u16::<LittleEndian>()? as usize;
                let bitmap_bytes = (part_count + 7) / 8;
                if cursor.position() as usize + bitmap_bytes > payload.len() {
                    break;
                }
                let mut bitmap = vec![0u8; bitmap_bytes];
                if bitmap_bytes > 0 {
                    cursor.read_exact(&mut bitmap)?;
                }
                let mut parts = Vec::with_capacity(part_count);
                for i in 0..part_count {
                    parts.push((bitmap[i / 8] >> (i % 8)) & 1 != 0);
                }
                out.file_status = Some(parts);
            }
            OP_FILEREQANSNOFIL => {
                out.no_file = true;
            }
            OP_AICHFILEHASHANS => {
                if cursor.position() as usize + 20 > payload.len() {
                    break;
                }
                let mut aich = [0u8; 20];
                cursor.read_exact(&mut aich)?;
                out.aich_hash = Some(aich);
            }
            _ => break,
        }
    }

    Ok(out)
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

    const MAX_FILE_STATUS_PARTS: usize = 10_000;
    if part_count > MAX_FILE_STATUS_PARTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file status claims {part_count} parts, exceeds maximum {MAX_FILE_STATUS_PARTS}"),
        ));
    }

    let bitmap_bytes = (part_count + 7) / 8;
    let remaining = payload.len() - cursor.position() as usize;
    if bitmap_bytes > remaining {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file status bitmap needs {bitmap_bytes} bytes but only {remaining} remain"),
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_identifier_roundtrip_preserves_optional_fields() {
        let ident = FileIdentifier {
            md4_hash: [0x11; 16],
            file_size: Some(123_456_789),
            aich_hash: Some([0x22; 20]),
        };

        let mut buf = Vec::new();
        ident.write_identifier(&mut buf);
        let mut cursor = Cursor::new(buf.as_slice());
        let parsed = FileIdentifier::read_identifier(&mut cursor).unwrap();

        assert_eq!(parsed, ident);
    }

    #[test]
    fn parse_hello_packet_roundtrip_preserves_core_capabilities() {
        let user_hash = [0x33; 16];
        let opts = HelloOptions {
            udp_port: 4672,
            kad_port: 4672,
            supports_crypt_layer: true,
            requests_crypt_layer: true,
            requires_crypt_layer: false,
            supports_direct_udp_callback: true,
            supports_captcha: false,
            server_ip: 0x0102_0304,
            server_port: 4661,
            kad_version: 0x09,
        };

        let payload = build_hello_with_buddy_opts(
            &user_hash,
            0x7F00_0001,
            4662,
            "ember",
            None,
            &opts,
        );
        let (parsed_hash, caps) = parse_hello_packet(&payload).unwrap();

        assert_eq!(parsed_hash, user_hash);
        assert_eq!(caps.udp_port, 4672);
        assert_eq!(caps.kad_port, 4672);
        assert!(caps.supports_large_files);
        assert!(caps.supports_multi_packet);
        assert!(caps.supports_source_ex2);
        assert!(caps.supports_direct_udp_callback);
        assert_eq!(caps.extended_requests_ver, 2);
    }

    #[test]
    fn parse_emule_info_roundtrip_preserves_flags() {
        let caps = parse_emule_info(&build_emule_info(4672, true, None));

        assert_eq!(caps.udp_port, 4672);
        assert_eq!(caps.compression_ver, 1);
        assert_eq!(caps.extended_requests_ver, 2);
        assert!(caps.source_exchange_ver > 0);
    }

    #[test]
    fn ed2k_part_count_for_size_matrix() {
        assert_eq!(ed2k_part_count_for_size(0), 0);
        assert_eq!(ed2k_part_count_for_size(1), 1);
        assert_eq!(ed2k_part_count_for_size(PARTSIZE), 1);
        assert_eq!(ed2k_part_count_for_size(PARTSIZE + 1), 2);
        assert_eq!(ed2k_part_count_for_size(PARTSIZE * 2), 2);
        assert_eq!(ed2k_part_count_for_size(PARTSIZE * 2 + 1), 3);
    }

    #[test]
    fn ed2k_wire_part_count_matches_emule() {
        // eMule GetED2KPartCount() = floor(size/PARTSIZE) + 1
        assert_eq!(ed2k_wire_part_count(0), 0);
        assert_eq!(ed2k_wire_part_count(1), 1);
        // Key difference from ed2k_part_count_for_size: exact multiples get +1
        assert_eq!(ed2k_wire_part_count(PARTSIZE), 2);
        assert_eq!(ed2k_wire_part_count(PARTSIZE + 1), 2);
        assert_eq!(ed2k_wire_part_count(PARTSIZE * 2), 3);
        assert_eq!(ed2k_wire_part_count(PARTSIZE * 2 + 1), 3);
    }
}
