use std::fmt;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use digest::Digest;
use rand::Rng;
use serde::{Deserialize, Serialize};

pub const KAD_ID_SIZE: usize = 16;
pub const KADEMLIA_VERSION: u8 = 0x0A;
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
pub const KADEMLIA_VERSION5_48A: u8 = 0x05;
pub const KADEMLIA_VERSION6_49ABETA: u8 = 0x06;
pub const KADEMLIA_VERSION7_49A: u8 = 0x07;
pub const KADEMLIA_VERSION8_49B: u8 = 0x08;
pub const KADEMLIA_VERSION9_50A: u8 = 0x09;

/// eMule Defines.h: KBASE=4, KK=5, LOG_BASE_EXPONENT=5
pub const KBASE: usize = 4;
pub const KK: usize = 5;
pub const LOG_BASE_EXPONENT: usize = 5;

/// TAG_KADMISCOPTIONS carries firewall/ACK status bits
pub const TAG_KADMISCOPTIONS: u8 = 0xF7;
/// TAG_KADUDPKEY carries the sender's UDP verify key for the receiver
pub const TAG_KADUDPKEY: u8 = 0xF8;

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
    /// Uses MD5(seed || ip) following eMule's approach.
    /// eMule hashes the raw bytes of the IP struct. On Little-Endian (x86) Windows,
    /// the IP (stored in network byte order / BE) is in memory as [d, c, b, a].
    /// So we must use to_le_bytes() on the BE integer to get that byte sequence.
    pub fn generate(our_udp_key: u32, their_ip: u32) -> Self {
        let mut hasher = md5::Md5::new();
        hasher.update(our_udp_key.to_le_bytes());
        hasher.update(their_ip.to_le_bytes());
        let result = hasher.finalize();
        let key = u32::from_le_bytes([result[0], result[1], result[2], result[3]]);
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

    /// Returns the index of the highest set bit (0-127), or None if zero.
    /// Used to determine which k-bucket a contact belongs to.
    /// Count leading zeros matching eMule's CUInt128 bit ordering.
    /// Each 4-byte chunk is LE, so within a chunk the MSB is at offset +3.
    pub fn leading_zeros(&self) -> u32 {
        let mut total = 0u32;
        for chunk in 0..4 {
            let base = chunk * 4;
            for offset in (0..4).rev() {
                let byte = self.0[base + offset];
                if byte == 0 {
                    total += 8;
                } else {
                    total += byte.leading_zeros();
                    return total;
                }
            }
        }
        total
    }

    /// Bucket index for this distance (0 = closest, 127 = farthest)
    pub fn bucket_index(&self) -> usize {
        let lz = self.leading_zeros() as usize;
        let total_bits = KAD_ID_SIZE * 8;
        if lz >= total_bits {
            0
        } else {
            total_bits - 1 - lz
        }
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
        self.contact_type += 1;
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

// Well-known tag name IDs
pub const TAG_FILENAME: u8 = 0x01;
pub const TAG_FILESIZE: u8 = 0x02;
pub const TAG_FILETYPE: u8 = 0x03;
pub const TAG_SOURCES: u8 = 0x15;
pub const TAG_COMPLETE_SOURCES: u8 = 0x30;
pub const TAG_SOURCEIP: u8 = 0xFE;
pub const TAG_SOURCEPORT: u8 = 0xFD;
pub const TAG_SOURCEUPORT: u8 = 0xFC;
pub const TAG_SOURCETYPE: u8 = 0xFF;

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
            t if (TAGTYPE_STR1..=TAGTYPE_STR16).contains(&t) => {
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
        let (type_byte, use_short_name) = match &self.value {
            TagValue::Hash(_) => (TAGTYPE_HASH, true),
            TagValue::String(s) => {
                let len = s.len();
                if (1..=16).contains(&len) {
                    (TAGTYPE_STR1 + len as u8 - 1, true)
                } else {
                    (TAGTYPE_STRING, true)
                }
            }
            TagValue::Uint64(_) => (TAGTYPE_UINT64, true),
            TagValue::Uint32(_) => (TAGTYPE_UINT32, true),
            TagValue::Uint16(_) => (TAGTYPE_UINT16, true),
            TagValue::Uint8(_) => (TAGTYPE_UINT8, true),
            TagValue::Float32(_) => (TAGTYPE_FLOAT32, true),
            TagValue::Bool(_) => (TAGTYPE_BOOL, true),
            TagValue::Blob(_) => (TAGTYPE_BLOB, true),
        };

        match &self.name {
            TagName::Id(id) => {
                if use_short_name {
                    writer.write_u8(type_byte | 0x80)?;
                    writer.write_u8(*id)?;
                } else {
                    writer.write_u8(type_byte)?;
                    writer.write_u16::<LittleEndian>(1)?;
                    writer.write_u8(*id)?;
                }
            }
            TagName::Str(s) => {
                writer.write_u8(type_byte)?;
                writer.write_u16::<LittleEndian>(s.len() as u16)?;
                writer.write_all(s.as_bytes())?;
            }
        }

        match &self.value {
            TagValue::Hash(h) => writer.write_all(h)?,
            TagValue::String(s) => {
                let len = s.len();
                if !(1..=16).contains(&len) {
                    writer.write_u16::<LittleEndian>(len as u16)?;
                    writer.write_all(s.as_bytes())?;
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
