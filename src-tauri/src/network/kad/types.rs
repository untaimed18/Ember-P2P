use std::fmt;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use digest::Digest;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const KAD_ID_SIZE: usize = 16;

/// Swap bytes within each 4-byte group to convert between raw ed2k user_hash
/// bytes and eMule's CUInt128 wire format (little-endian uint32 groups that
/// get byte-reversed by `CUInt128::ToByteArray`). Self-inverse.
pub fn cuint128_swap(bytes: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..4 {
        let b = i * 4;
        out[b] = bytes[b + 3];
        out[b + 1] = bytes[b + 2];
        out[b + 2] = bytes[b + 1];
        out[b + 3] = bytes[b];
    }
    out
}
pub const KADEMLIA_VERSION: u8 = KADEMLIA_VERSION9_50A;
pub const K_BUCKET_SIZE: usize = 10;
pub const ALPHA: usize = 3;
pub const DEFAULT_TCP_PORT: u16 = 4662;
pub const DEFAULT_UDP_PORT: u16 = 4672;

/// SEARCHTOLERANCE: max XOR distance (first 4 bytes as u32) for accepting publishes
pub const SEARCH_TOLERANCE: u32 = 0x0100_0000;

/// eMule KAD version constants (from opcodes.h)
pub const KADEMLIA_VERSION1_46C: u8 = 0x01;
pub const KADEMLIA_VERSION2_47A: u8 = 0x02;
pub const KADEMLIA_VERSION3_47B: u8 = 0x03;
pub const KADEMLIA_VERSION4_47C: u8 = 0x04;
pub const KADEMLIA_VERSION5_48A: u8 = 0x05;
pub const KADEMLIA_VERSION6_49ABETA: u8 = 0x06;
pub const KADEMLIA_VERSION7_49A: u8 = 0x07;
pub const KADEMLIA_VERSION8_49B: u8 = 0x08;
pub const KADEMLIA_VERSION9_50A: u8 = 0x09;

/// eMule Defines.h: KBASE=4, KK=5, LOG_BASE_EXPONENT=5
pub const KBASE: usize = 4;
pub const KK: usize = 5;
pub const LOG_BASE_EXPONENT: usize = 5;

/// TAG_KADMISCOPTIONS carries firewall/ACK status bits (eMule opcodes.h: 0xF2)
pub const TAG_KADMISCOPTIONS: u8 = 0xF2;
/// KAD contact types -- matching eMule semantics (lower = better)
/// In eMule: type 0 = best (2+h proven), type 3 = unknown, type 4 = dead
/// We map: 0=ACTIVE(best), 1=VERIFIED, 2=OPEN, 3=NEW(unknown), 4=DEAD
pub const CONTACT_TYPE_ACTIVE: u8 = 0;
pub const CONTACT_TYPE_VERIFIED: u8 = 1;
pub const CONTACT_TYPE_OPEN: u8 = 2;
pub const CONTACT_TYPE_NEW: u8 = 3;
pub const CONTACT_TYPE_DEAD: u8 = 4;

/// Expiry durations per contact type (matching eMule Contact.cpp UpdateType)
const EXPIRE_ACTIVE_SECS: i64 = 7200; // type 0: 2 hours
const EXPIRE_VERIFIED_SECS: i64 = 5400; // type 1: 1.5 hours
const EXPIRE_OPEN_SECS: i64 = 3600; // type 2: 1 hour
const EXPIRE_CHECKING_SECS: i64 = 120; // CheckingType probe: 2 minutes

/// UDP verification key for KAD 3-way handshake
#[derive(Debug, Clone, Copy, Default)]
pub struct KadUDPKey {
    pub key: u32,
    pub ip: u32,
}

impl KadUDPKey {
    /// Generate a UDP verify key for a specific peer IP using a keyed hash.
    /// eMule CPrefs::GetUDPVerifyKey packs into uint64: (key << 32) | ip,
    /// which on x86 LE means memory layout is [ip_le_4][key_le_4].
    /// Then XOR-folds the MD5 output and applies % 0xFFFFFFFE + 1.
    pub fn generate(our_udp_key: u32, their_ip: u32) -> Self {
        let mut hasher = md5::Md5::new();
        // eMule: uint64 buf = (key << 32) | ip => on LE: [ip bytes][key bytes]
        hasher.update(their_ip.to_le_bytes());
        hasher.update(our_udp_key.to_le_bytes());
        let result = hasher.finalize();
        // XOR-fold all 4 MD5 u32 words, then % 0xFFFFFFFE + 1 (guarantees nonzero)
        let w0 = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
        let w1 = u32::from_le_bytes([result[4], result[5], result[6], result[7]]);
        let w2 = u32::from_le_bytes([result[8], result[9], result[10], result[11]]);
        let w3 = u32::from_le_bytes([result[12], result[13], result[14], result[15]]);
        let folded = w0 ^ w1 ^ w2 ^ w3;
        let key = (folded % 0xFFFFFFFE) + 1;
        KadUDPKey { key, ip: their_ip }
    }

    pub fn get_key_value(&self, ip: u32) -> u32 {
        if ip == self.ip { self.key } else { 0 }
    }

    pub fn is_valid(&self) -> bool {
        self.key != 0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KadId(pub [u8; KAD_ID_SIZE]);

impl KadId {
    pub fn random() -> Self {
        let mut id = [0u8; KAD_ID_SIZE];
        rand::thread_rng().fill(&mut id);
        KadId(id)
    }

    pub fn zero() -> Self {
        KadId([0u8; KAD_ID_SIZE])
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < KAD_ID_SIZE {
            return None;
        }
        let mut id = [0u8; KAD_ID_SIZE];
        id.copy_from_slice(&bytes[..KAD_ID_SIZE]);
        Some(KadId(id))
    }

    pub fn xor_distance(&self, other: &KadId) -> KadId {
        let mut result = [0u8; KAD_ID_SIZE];
        for i in 0..KAD_ID_SIZE {
            result[i] = self.0[i] ^ other.0[i];
        }
        KadId(result)
    }

    pub(crate) fn chunk(&self, i: usize) -> u32 {
        debug_assert!(i < KAD_ID_SIZE / 4, "KadId::chunk index out of bounds");
        let base = i * 4;
        u32::from_le_bytes([self.0[base], self.0[base + 1], self.0[base + 2], self.0[base + 3]])
    }

    fn set_chunk(&mut self, i: usize, val: u32) {
        debug_assert!(i < KAD_ID_SIZE / 4, "KadId::set_chunk index out of bounds");
        let base = i * 4;
        let bytes = val.to_le_bytes();
        self.0[base] = bytes[0];
        self.0[base + 1] = bytes[1];
        self.0[base + 2] = bytes[2];
        self.0[base + 3] = bytes[3];
    }

    /// CUInt128((ULONG)val) -- value stored in least-significant chunk.
    pub fn from_u32(val: u32) -> Self {
        let mut id = KadId([0u8; KAD_ID_SIZE]);
        id.set_chunk(3, val);
        id
    }

    /// CUInt128::GetBitNumber -- bit 0 is MSB of chunk 0, bit 127 is LSB of chunk 3.
    pub fn get_bit_number(&self, bit: u32) -> usize {
        let chunk_idx = (bit / 32) as usize;
        let bit_in_chunk = 31 - (bit % 32);
        ((self.chunk(chunk_idx) >> bit_in_chunk) & 1) as usize
    }

    /// CUInt128::ShiftLeft -- shift entire 128-bit value left by `bits` positions.
    pub fn shift_left(&mut self, bits: u32) {
        if bits == 0 {
            return;
        }
        if bits > 127 {
            self.0 = [0u8; KAD_ID_SIZE];
            return;
        }
        let chunk_shift = (bits / 32) as usize;
        if chunk_shift > 0 {
            for i in 0..=(3 - chunk_shift) {
                let val = self.chunk(i + chunk_shift);
                self.set_chunk(i, val);
            }
            for i in (4 - chunk_shift)..4 {
                self.set_chunk(i, 0);
            }
        }
        let bit_shift = bits % 32;
        if bit_shift > 0 {
            for i in 0..3 {
                let val = (self.chunk(i) << bit_shift) | (self.chunk(i + 1) >> (32 - bit_shift));
                self.set_chunk(i, val);
            }
            let val = self.chunk(3) << bit_shift;
            self.set_chunk(3, val);
        }
    }

    /// CUInt128::Add(uint32) -- add a small integer to the 128-bit value.
    pub fn add_u32(&mut self, val: u32) {
        let mut carry = val as u64;
        for i in (0..4).rev() {
            let sum = self.chunk(i) as u64 + carry;
            self.set_chunk(i, sum as u32);
            carry = sum >> 32;
            if carry == 0 {
                break;
            }
        }
    }

    /// Compare this 128-bit value with a small u32 (zone_index < KK).
    pub fn less_than_u32(&self, val: u32) -> bool {
        if self.chunk(0) != 0 || self.chunk(1) != 0 || self.chunk(2) != 0 {
            return false;
        }
        self.chunk(3) < val
    }

    /// CUInt128(uValue, numBits) -- random ID with `num_bits` prefix copied from `prefix`.
    pub fn random_with_prefix(prefix: &KadId, num_bits: u32) -> KadId {
        let mut id = KadId::random();
        let full_chunks = (num_bits / 32) as usize;
        for i in 0..full_chunks {
            id.set_chunk(i, prefix.chunk(i));
        }
        let remaining_bits = num_bits % 32;
        if remaining_bits > 0 && full_chunks < 4 {
            let mask = !((1u32 << (32 - remaining_bits)) - 1);
            let val = (prefix.chunk(full_chunks) & mask) | (id.chunk(full_chunks) & !mask);
            id.set_chunk(full_chunks, val);
        }
        id
    }

    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut id = [0u8; KAD_ID_SIZE];
        reader.read_exact(&mut id)?;
        Ok(KadId(id))
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.0)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        Self::from_bytes(&bytes)
    }
}

impl fmt::Debug for KadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KadId({})", self.to_hex())
    }
}

impl fmt::Display for KadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl PartialOrd for KadId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KadId {
    /// Match eMule's CUInt128 comparison: compare 4 little-endian u32 chunks
    /// from most significant (chunk 0 = bytes 0..3) to least significant.
    /// Each 4-byte group is interpreted as a LE u32 for the comparison.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in 0..4 {
            let base = i * 4;
            let a = u32::from_le_bytes([
                self.0[base], self.0[base + 1], self.0[base + 2], self.0[base + 3],
            ]);
            let b = u32::from_le_bytes([
                other.0[base], other.0[base + 1], other.0[base + 2], other.0[base + 3],
            ]);
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        std::cmp::Ordering::Equal
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KadContact {
    pub id: KadId,
    pub ip: Ipv4Addr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
    pub last_seen: i64,
    #[serde(default)]
    pub verified: bool,
    #[serde(default = "default_contact_type_new")]
    pub contact_type: u8,
    #[serde(skip)]
    pub udp_key: Option<KadUDPKey>,
    #[serde(default)]
    pub kad_options: u8,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub last_type_set: i64,
    /// eMule CContact::m_bReceivedHelloPacket -- set when a HELLO was received.
    /// Legacy Kad2 contacts (version < 0.49a) that have received a HELLO are
    /// restricted to timer-refresh-only updates to prevent hijacking.
    #[serde(skip)]
    pub received_hello: bool,
}

fn default_contact_type_new() -> u8 {
    CONTACT_TYPE_NEW
}

impl KadContact {
    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let id = KadId::read_from(reader)?;
        let ip_raw = reader.read_u32::<LittleEndian>()?;
        let ip = Ipv4Addr::from(ip_raw.to_be_bytes());
        let udp_port = reader.read_u16::<LittleEndian>()?;
        let tcp_port = reader.read_u16::<LittleEndian>()?;
        let version = reader.read_u8()?;
        let now = chrono::Utc::now().timestamp();

        Ok(KadContact {
            id,
            ip,
            udp_port,
            tcp_port,
            version,
            last_seen: now,
            verified: false,
            contact_type: CONTACT_TYPE_NEW,
            udp_key: None,
            kad_options: 0,
            created_at: now,
            expires_at: 0,
            last_type_set: 0,
            received_hello: false,
        })
    }

    /// Called when a contact responds. Sets type based on age (eMule UpdateType).
    pub fn update_type(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let age = now - self.created_at;

        if age < 3600 {
            self.contact_type = CONTACT_TYPE_OPEN;
            self.expires_at = now + EXPIRE_OPEN_SECS;
        } else if age < 7200 {
            self.contact_type = CONTACT_TYPE_VERIFIED;
            self.expires_at = now + EXPIRE_VERIFIED_SECS;
        } else {
            self.contact_type = CONTACT_TYPE_ACTIVE;
            self.expires_at = now + EXPIRE_ACTIVE_SECS;
        }

        self.last_seen = now;
        self.last_type_set = now;
    }

    /// Called when probing an unresponsive contact. Increments type (eMule CheckingType).
    /// Returns true if the contact is now dead (type 4).
    /// eMule has a 10-second guard: if called within 10s of last type set, or already
    /// dead, does nothing.
    pub fn checking_type(&mut self) -> bool {
        let now = chrono::Utc::now().timestamp();
        if now - self.last_type_set < 10 || self.contact_type >= CONTACT_TYPE_DEAD {
            return self.contact_type >= CONTACT_TYPE_DEAD;
        }
        self.last_type_set = now;
        self.expires_at = now + EXPIRE_CHECKING_SECS;
        self.contact_type = (self.contact_type + 1).min(CONTACT_TYPE_DEAD);
        self.contact_type >= CONTACT_TYPE_DEAD
    }

    /// Whether this contact's expiry time has passed.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        chrono::Utc::now().timestamp() > self.expires_at
    }

    /// Whether this contact is dead (type 4).
    pub fn is_dead(&self) -> bool {
        self.contact_type >= CONTACT_TYPE_DEAD
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        self.id.write_to(writer)?;
        let octets = self.ip.octets();
        let ip_raw = u32::from_be_bytes(octets);
        writer.write_u32::<LittleEndian>(ip_raw)?;
        writer.write_u16::<LittleEndian>(self.udp_port)?;
        writer.write_u16::<LittleEndian>(self.tcp_port)?;
        writer.write_u8(self.version)?;
        Ok(())
    }

    /// Set IP address with eMule-compatible verified flag clearing.
    /// In eMule Contact.cpp SetIPAddress(), when a contact's IP changes,
    /// SetIpVerified(false) is called to invalidate the old verification.
    pub fn set_ip(&mut self, new_ip: Ipv4Addr) {
        if self.ip != new_ip {
            self.verified = false;
            self.ip = new_ip;
        }
    }

    pub fn is_udp_firewalled(&self) -> bool {
        self.kad_options & 0x01 != 0
    }

    pub fn is_tcp_firewalled(&self) -> bool {
        self.kad_options & 0x02 != 0
    }

    pub fn supports_obfuscation(&self) -> bool {
        self.version >= KADEMLIA_VERSION6_49ABETA
    }

    /// Whether this is a Kad2+ contact (version >= 2). eMule rejects Kad1 contacts.
    pub fn is_kad2(&self) -> bool {
        self.version >= KADEMLIA_VERSION2_47A
    }
}

// Tag types as defined in eMule opcodes.h
pub const TAGTYPE_HASH: u8 = 0x01;
pub const TAGTYPE_STRING: u8 = 0x02;
pub const TAGTYPE_UINT32: u8 = 0x03;
pub const TAGTYPE_FLOAT32: u8 = 0x04;
pub const TAGTYPE_BOOL: u8 = 0x05;
pub const TAGTYPE_BOOLARRAY: u8 = 0x06;
pub const TAGTYPE_BLOB: u8 = 0x07;
pub const TAGTYPE_UINT16: u8 = 0x08;
pub const TAGTYPE_UINT8: u8 = 0x09;
pub const TAGTYPE_BSOB: u8 = 0x0A;
pub const TAGTYPE_UINT64: u8 = 0x0B;
pub const TAGTYPE_STR1: u8 = 0x11;
pub const TAGTYPE_STR16: u8 = 0x20;
pub const TAGTYPE_STR22: u8 = 0x26;

// Well-known tag name IDs
pub const TAG_FILENAME: u8 = 0x01;
pub const TAG_FILESIZE: u8 = 0x02;
pub const TAG_FILETYPE: u8 = 0x03;
pub const TAG_SOURCES: u8 = 0x15;
pub const TAG_COMPLETE_SOURCES: u8 = 0x30;
pub const TAG_DESCRIPTION: u8 = 0x0B;
pub const TAG_SOURCEIP: u8 = 0xFE;
pub const TAG_SOURCEPORT: u8 = 0xFD;
pub const TAG_SOURCEUPORT: u8 = 0xFC;
pub const TAG_SOURCETYPE: u8 = 0xFF;
pub const TAG_ENCRYPTION: u8 = 0xF3;
pub const TAG_FILERATING: u8 = 0xF7;
pub const TAG_SERVERIP: u8 = 0xFB;
pub const TAG_SERVERPORT: u8 = 0xFA;
pub const TAG_BUDDYHASH: u8 = 0xF8;

#[derive(Debug, Clone)]
pub enum TagName {
    Id(u8),
    Str(String),
}

#[derive(Debug, Clone)]
pub enum TagValue {
    Hash([u8; 16]),
    String(String),
    Uint64(u64),
    Uint32(u32),
    Uint16(u16),
    Uint8(u8),
    Float32(f32),
    Bool(bool),
    Blob(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct KadTag {
    pub name: TagName,
    pub value: TagValue,
}

impl KadTag {
        /// Maximum allowed string length in tags (64 KiB, matching eMule limits)
    const MAX_TAG_STRING_LEN: usize = 65536;
    /// Maximum allowed blob size in tags (256 KiB)
    const MAX_TAG_BLOB_LEN: usize = 262144;
    /// Maximum allowed tag name length (256 bytes)
    const MAX_TAG_NAME_LEN: usize = 256;

    pub fn read_from<R: Read>(reader: &mut R) -> io::Result<Self> {
        let tag_type = reader.read_u8()?;

        let name = if tag_type & 0x80 != 0 {
            let name_id = reader.read_u8()?;
            TagName::Id(name_id)
        } else {
            let name_len = reader.read_u16::<LittleEndian>()? as usize;
            if name_len > Self::MAX_TAG_NAME_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("tag name too long: {name_len}"),
                ));
            }
            if name_len == 1 {
                let name_id = reader.read_u8()?;
                TagName::Id(name_id)
            } else {
                let mut name_bytes = vec![0u8; name_len];
                reader.read_exact(&mut name_bytes)?;
                TagName::Str(String::from_utf8_lossy(&name_bytes).to_string())
            }
        };

        let real_type = tag_type & 0x7F;
        let value = match real_type {
            TAGTYPE_HASH => {
                let mut hash = [0u8; 16];
                reader.read_exact(&mut hash)?;
                TagValue::Hash(hash)
            }
            TAGTYPE_STRING => {
                let len = reader.read_u16::<LittleEndian>()? as usize;
                if len > Self::MAX_TAG_STRING_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tag string too long: {len}"),
                    ));
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                TagValue::String(String::from_utf8_lossy(&buf).to_string())
            }
            TAGTYPE_UINT64 => TagValue::Uint64(reader.read_u64::<LittleEndian>()?),
            TAGTYPE_UINT32 => TagValue::Uint32(reader.read_u32::<LittleEndian>()?),
            TAGTYPE_UINT16 => TagValue::Uint16(reader.read_u16::<LittleEndian>()?),
            TAGTYPE_UINT8 => TagValue::Uint8(reader.read_u8()?),
            TAGTYPE_FLOAT32 => TagValue::Float32(reader.read_f32::<LittleEndian>()?),
            TAGTYPE_BOOL => TagValue::Bool(reader.read_u8()? != 0),
            TAGTYPE_BOOLARRAY => {
                let len = reader.read_u16::<LittleEndian>()? as usize;
                let byte_count = (len + 7) / 8;
                if byte_count > Self::MAX_TAG_BLOB_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("boolarray too large: {byte_count}"),
                    ));
                }
                let mut buf = vec![0u8; byte_count];
                reader.read_exact(&mut buf)?;
                TagValue::Blob(buf)
            }
            TAGTYPE_BLOB => {
                let len = reader.read_u32::<LittleEndian>()? as usize;
                if len > Self::MAX_TAG_BLOB_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("blob too large: {len}"),
                    ));
                }
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                TagValue::Blob(buf)
            }
            TAGTYPE_BSOB => {
                let len = reader.read_u8()? as usize;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                TagValue::Blob(buf)
            }
            t if (TAGTYPE_STR1..=TAGTYPE_STR22).contains(&t) => {
                let len = (t - TAGTYPE_STR1 + 1) as usize;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                TagValue::String(String::from_utf8_lossy(&buf).to_string())
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown tag type: 0x{:02X}", real_type),
                ));
            }
        };

        Ok(KadTag { name, value })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        let type_byte = match &self.value {
            TagValue::Hash(_) => TAGTYPE_HASH,
            TagValue::String(s) => {
                let len = s.len();
                if (1..=16).contains(&len) {
                    TAGTYPE_STR1 + len as u8 - 1
                } else {
                    TAGTYPE_STRING
                }
            }
            TagValue::Uint64(_) => TAGTYPE_UINT64,
            TagValue::Uint32(_) => TAGTYPE_UINT32,
            TagValue::Uint16(_) => TAGTYPE_UINT16,
            TagValue::Uint8(_) => TAGTYPE_UINT8,
            TagValue::Float32(_) => TAGTYPE_FLOAT32,
            TagValue::Bool(_) => TAGTYPE_BOOL,
            TagValue::Blob(_) => TAGTYPE_BLOB,
        };

        match &self.name {
            TagName::Id(id) => {
                writer.write_u8(type_byte | 0x80)?;
                writer.write_u8(*id)?;
            }
            TagName::Str(s) => {
                writer.write_u8(type_byte)?;
                let name_len = u16::try_from(s.len()).unwrap_or(u16::MAX);
                writer.write_u16::<LittleEndian>(name_len)?;
                writer.write_all(&s.as_bytes()[..name_len as usize])?;
            }
        }

        match &self.value {
            TagValue::Hash(h) => writer.write_all(h)?,
            TagValue::String(s) => {
                let len = s.len();
                if !(1..=16).contains(&len) {
                    let wire_len = u16::try_from(len).unwrap_or(u16::MAX);
                    writer.write_u16::<LittleEndian>(wire_len)?;
                    writer.write_all(&s.as_bytes()[..wire_len as usize])?;
                } else {
                    writer.write_all(s.as_bytes())?;
                }
            }
            TagValue::Uint64(v) => writer.write_u64::<LittleEndian>(*v)?,
            TagValue::Uint32(v) => writer.write_u32::<LittleEndian>(*v)?,
            TagValue::Uint16(v) => writer.write_u16::<LittleEndian>(*v)?,
            TagValue::Uint8(v) => writer.write_u8(*v)?,
            TagValue::Float32(v) => writer.write_f32::<LittleEndian>(*v)?,
            TagValue::Bool(v) => writer.write_u8(if *v { 1 } else { 0 })?,
            TagValue::Blob(b) => {
                writer.write_u32::<LittleEndian>(b.len() as u32)?;
                writer.write_all(b)?;
            }
        }

        Ok(())
    }

    pub fn string_value(&self) -> Option<&str> {
        match &self.value {
            TagValue::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn uint32_value(&self) -> Option<u32> {
        match &self.value {
            TagValue::Uint32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn uint16_value(&self) -> Option<u16> {
        match &self.value {
            TagValue::Uint16(v) => Some(*v),
            _ => None,
        }
    }

    pub fn uint8_value(&self) -> Option<u8> {
        match &self.value {
            TagValue::Uint8(v) => Some(*v),
            _ => None,
        }
    }

    pub fn uint64_value(&self) -> Option<u64> {
        match &self.value {
            TagValue::Uint64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn hash_value(&self) -> Option<[u8; 16]> {
        match &self.value {
            TagValue::Hash(h) => Some(*h),
            _ => None,
        }
    }
}

/// Maximum tags per tag list (eMule typically sends < 10 tags per message)
const MAX_TAG_LIST_SIZE: usize = 32;

pub fn read_tag_list<R: Read>(reader: &mut R) -> io::Result<Vec<KadTag>> {
    let count = reader.read_u8()? as usize;
    if count > MAX_TAG_LIST_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tag list too large: {count} (max {MAX_TAG_LIST_SIZE})"),
        ));
    }
    let mut tags = Vec::with_capacity(count);
    for _ in 0..count {
        tags.push(KadTag::read_from(reader)?);
    }
    Ok(tags)
}

pub fn write_tag_list<W: Write>(writer: &mut W, tags: &[KadTag]) -> io::Result<()> {
    if tags.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tag list too large: {} (max 255)", tags.len()),
        ));
    }
    writer.write_u8(tags.len() as u8)?;
    for tag in tags {
        tag.write_to(writer)?;
    }
    Ok(())
}
