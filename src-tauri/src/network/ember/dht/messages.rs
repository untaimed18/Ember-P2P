use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

use super::{EmberContact, EmberNodeId, EMBER_DHT_VERSION, MAX_CONTACTS_PER_RESPONSE};
use crate::network::ember::crypto;

// ── Message types ──

pub const MSG_PING: u8 = 0x01;
pub const MSG_PONG: u8 = 0x02;
pub const MSG_FIND_NODE: u8 = 0x03;
pub const MSG_FOUND_NODE: u8 = 0x04;
pub const MSG_STORE_RECORD: u8 = 0x05;
pub const MSG_STORE_ACK: u8 = 0x06;
pub const MSG_FIND_VALUE: u8 = 0x07;
pub const MSG_FOUND_VALUE: u8 = 0x08;
pub const MSG_ANNOUNCE_PEER: u8 = 0x09;
pub const MSG_PEER_LIST: u8 = 0x0A;

// Address type flags
const ADDR_IPV4: u8 = 0x04;
const ADDR_IPV6: u8 = 0x06;

/// Header size without public key (used after encrypted session established):
/// version(1) + msg_type(1) + request_id(4) + sender_node_id(16) = 22 bytes
const HEADER_MIN_SIZE: usize = 22;

/// Parsed Ember DHT message.
#[derive(Debug, Clone)]
pub struct DhtMessage {
    pub version: u8,
    pub msg_type: u8,
    pub request_id: u32,
    pub sender_id: EmberNodeId,
    /// Sender's Ed25519 public key (only present in cleartext/handshake messages,
    /// omitted in encrypted sessions where we already know it).
    pub sender_pub_key: Option<[u8; 32]>,
    pub payload: DhtPayload,
    pub signature: [u8; 64],
}

/// Payload variants for each message type.
#[derive(Debug, Clone)]
pub enum DhtPayload {
    Ping,
    Pong,
    FindNode {
        target: EmberNodeId,
    },
    FoundNode {
        contacts: Vec<EmberContact>,
    },
    StoreRecord {
        key: [u8; 16],
        record: Vec<u8>,
        record_signature: [u8; 64],
    },
    StoreAck {
        key: [u8; 16],
    },
    FindValue {
        keys: Vec<[u8; 16]>,
    },
    FoundValue {
        key: [u8; 16],
        records: Vec<Vec<u8>>,
    },
    AnnouncePeer {
        contacts: Vec<EmberContact>,
    },
    PeerList {
        contacts: Vec<EmberContact>,
    },
    Unknown(Vec<u8>),
}

/// Encode a DHT message into wire format, signing with the sender's Ed25519 key.
///
/// If `include_pub_key` is true, the sender's 32-byte Ed25519 public key is
/// included in the header (used for initial messages before encryption is established).
pub fn encode_message(
    msg: &DhtMessage,
    signing_key: &ed25519_dalek::SigningKey,
    include_pub_key: bool,
) -> Vec<u8> {
    let payload_bytes = encode_payload(&msg.payload);
    let payload_len = payload_bytes.len();

    let pub_key_bytes = if include_pub_key { 32 } else { 0 };
    let total = HEADER_MIN_SIZE + pub_key_bytes + 2 + payload_len + 64;

    let mut buf = Vec::with_capacity(total);
    buf.write_u8(msg.version).unwrap();
    buf.write_u8(msg.msg_type).unwrap();
    buf.write_u32::<LittleEndian>(msg.request_id).unwrap();
    buf.write_all(&msg.sender_id.0).unwrap();

    if include_pub_key {
        buf.write_all(&signing_key.verifying_key().to_bytes())
            .unwrap();
    }

    buf.write_u16::<LittleEndian>(payload_len as u16).unwrap();
    buf.write_all(&payload_bytes).unwrap();

    // Sign everything so far
    let sig = crypto::sign(signing_key, &buf);
    buf.write_all(&sig).unwrap();

    buf
}

/// Decode a DHT message from wire format.
///
/// `has_pub_key`: whether the sender's public key is present in the header
/// (should be true for messages received outside encrypted sessions).
pub fn decode_message(data: &[u8], has_pub_key: bool) -> anyhow::Result<DhtMessage> {
    let pub_key_size = if has_pub_key { 32 } else { 0 };
    let min_size = HEADER_MIN_SIZE + pub_key_size + 2 + 64; // header + payload_len + signature
    if data.len() < min_size {
        anyhow::bail!(
            "DHT message too short ({} bytes, need at least {min_size})",
            data.len()
        );
    }

    let mut cursor = Cursor::new(data);
    let version = cursor.read_u8()?;
    if version > EMBER_DHT_VERSION {
        anyhow::bail!("Unsupported DHT version {version}");
    }
    let msg_type = cursor.read_u8()?;
    let request_id = cursor.read_u32::<LittleEndian>()?;

    let mut sender_id_bytes = [0u8; 16];
    cursor.read_exact(&mut sender_id_bytes)?;
    let sender_id = EmberNodeId(sender_id_bytes);

    let sender_pub_key = if has_pub_key {
        let mut key = [0u8; 32];
        cursor.read_exact(&mut key)?;
        Some(key)
    } else {
        None
    };

    let payload_len = cursor.read_u16::<LittleEndian>()? as usize;
    let pos = cursor.position() as usize;
    if pos + payload_len + 64 > data.len() {
        anyhow::bail!(
            "DHT message truncated: payload_len={payload_len}, remaining={}",
            data.len() - pos
        );
    }

    let payload_data = &data[pos..pos + payload_len];
    let sig_offset = pos + payload_len;
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[sig_offset..sig_offset + 64]);

    // Verify signature if we have the public key
    if let Some(ref pk_bytes) = sender_pub_key {
        if let Some(pk) = crypto::verifying_key_from_bytes(pk_bytes) {
            let signed_data = &data[..sig_offset];
            if !crypto::verify(&pk, signed_data, &signature) {
                anyhow::bail!("DHT message signature verification failed");
            }
            // Bind sender_id to the public key. The signature only proves the
            // sender holds *some* key; without this check a peer could sign with
            // their own key while claiming a victim's sender_id (routing-table
            // poisoning / impersonation in FOUND_NODE, STORE_RECORD, etc.).
            // `node_id == BLAKE3(pubkey)[..16]` everywhere else in Ember.
            if !crypto::verify_ember_hash_binding(pk_bytes, &sender_id.0) {
                anyhow::bail!("DHT message sender_id does not match its public key");
            }
        } else {
            anyhow::bail!("Invalid Ed25519 public key in DHT message");
        }
    }

    let payload = decode_payload(msg_type, payload_data)?;

    Ok(DhtMessage {
        version,
        msg_type,
        request_id,
        sender_id,
        sender_pub_key,
        payload,
        signature,
    })
}

/// Build a PING message.
pub fn build_ping(sender_id: EmberNodeId, request_id: u32) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_PING,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::Ping,
        signature: [0u8; 64], // filled by encode_message
    }
}

/// Build a PONG response.
pub fn build_pong(sender_id: EmberNodeId, request_id: u32) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_PONG,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::Pong,
        signature: [0u8; 64],
    }
}

/// Build a FIND_NODE request.
pub fn build_find_node(sender_id: EmberNodeId, request_id: u32, target: EmberNodeId) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FIND_NODE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FindNode { target },
        signature: [0u8; 64],
    }
}

/// Build a FOUND_NODE response.
pub fn build_found_node(
    sender_id: EmberNodeId,
    request_id: u32,
    contacts: Vec<EmberContact>,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FOUND_NODE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FoundNode { contacts },
        signature: [0u8; 64],
    }
}

/// Build a STORE_RECORD request. `record` is the publisher-signed record
/// bytes ([`super::publish::SignedRecord::data`]) and `record_signature`
/// is that publisher's Ed25519 signature over it — distinct from the
/// per-frame signature `encode_message` adds with the sender's key.
pub fn build_store_record(
    sender_id: EmberNodeId,
    request_id: u32,
    key: [u8; 16],
    record: Vec<u8>,
    record_signature: [u8; 64],
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_STORE_RECORD,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::StoreRecord {
            key,
            record,
            record_signature,
        },
        signature: [0u8; 64],
    }
}

/// Build a STORE_ACK response (echoes the stored key).
pub fn build_store_ack(sender_id: EmberNodeId, request_id: u32, key: [u8; 16]) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_STORE_ACK,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::StoreAck { key },
        signature: [0u8; 64],
    }
}

/// Build a FIND_VALUE request for one or more keys.
pub fn build_find_value(
    sender_id: EmberNodeId,
    request_id: u32,
    keys: Vec<[u8; 16]>,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FIND_VALUE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FindValue { keys },
        signature: [0u8; 64],
    }
}

/// Build a FOUND_VALUE response carrying the records held for `key`.
pub fn build_found_value(
    sender_id: EmberNodeId,
    request_id: u32,
    key: [u8; 16],
    records: Vec<Vec<u8>>,
) -> DhtMessage {
    DhtMessage {
        version: EMBER_DHT_VERSION,
        msg_type: MSG_FOUND_VALUE,
        request_id,
        sender_id,
        sender_pub_key: None,
        payload: DhtPayload::FoundValue { key, records },
        signature: [0u8; 64],
    }
}

// ── Payload encoding ──

fn encode_payload(payload: &DhtPayload) -> Vec<u8> {
    match payload {
        DhtPayload::Ping | DhtPayload::Pong => Vec::new(),
        DhtPayload::FindNode { target } => target.0.to_vec(),
        DhtPayload::FoundNode { contacts }
        | DhtPayload::AnnouncePeer { contacts }
        | DhtPayload::PeerList { contacts } => encode_contact_list(contacts),
        DhtPayload::StoreRecord {
            key,
            record,
            record_signature,
        } => {
            let mut buf = Vec::with_capacity(16 + 2 + record.len() + 64);
            buf.extend_from_slice(key);
            buf.write_u16::<LittleEndian>(record.len() as u16).unwrap();
            buf.extend_from_slice(record);
            buf.extend_from_slice(record_signature);
            buf
        }
        DhtPayload::StoreAck { key } => key.to_vec(),
        DhtPayload::FindValue { keys } => {
            let mut buf = Vec::with_capacity(1 + keys.len() * 16);
            buf.write_u8(keys.len() as u8).unwrap();
            for key in keys {
                buf.extend_from_slice(key);
            }
            buf
        }
        DhtPayload::FoundValue { key, records } => {
            let mut buf = Vec::with_capacity(16 + 2 + records.len() * 128);
            buf.extend_from_slice(key);
            buf.write_u16::<LittleEndian>(records.len() as u16).unwrap();
            for rec in records {
                buf.write_u16::<LittleEndian>(rec.len() as u16).unwrap();
                buf.extend_from_slice(rec);
            }
            buf
        }
        DhtPayload::Unknown(data) => data.clone(),
    }
}

fn encode_contact_list(contacts: &[EmberContact]) -> Vec<u8> {
    let count = contacts.len().min(MAX_CONTACTS_PER_RESPONSE);
    let mut buf = Vec::with_capacity(1 + count * 85);
    buf.write_u8(count as u8).unwrap();

    for contact in contacts.iter().take(count) {
        buf.extend_from_slice(&contact.node_id.0);
        encode_socket_addr(&contact.addr, &mut buf);
        buf.extend_from_slice(&contact.noise_pub);
        buf.extend_from_slice(&contact.ed25519_pub);
    }
    buf
}

fn encode_socket_addr(addr: &SocketAddr, buf: &mut Vec<u8>) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.write_u8(ADDR_IPV4).unwrap();
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.write_u8(ADDR_IPV6).unwrap();
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.write_u16::<BigEndian>(addr.port()).unwrap();
}

// ── Payload decoding ──

fn decode_payload(msg_type: u8, data: &[u8]) -> anyhow::Result<DhtPayload> {
    match msg_type {
        MSG_PING => Ok(DhtPayload::Ping),
        MSG_PONG => Ok(DhtPayload::Pong),
        MSG_FIND_NODE => {
            if data.len() < 16 {
                anyhow::bail!("FIND_NODE payload too short");
            }
            let mut target = [0u8; 16];
            target.copy_from_slice(&data[..16]);
            Ok(DhtPayload::FindNode {
                target: EmberNodeId(target),
            })
        }
        MSG_FOUND_NODE | MSG_ANNOUNCE_PEER | MSG_PEER_LIST => {
            let contacts = decode_contact_list(data)?;
            match msg_type {
                MSG_FOUND_NODE => Ok(DhtPayload::FoundNode { contacts }),
                MSG_ANNOUNCE_PEER => Ok(DhtPayload::AnnouncePeer { contacts }),
                _ => Ok(DhtPayload::PeerList { contacts }),
            }
        }
        MSG_STORE_RECORD => {
            if data.len() < 16 + 2 + 64 {
                anyhow::bail!("STORE_RECORD too short");
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            let mut cursor = Cursor::new(&data[16..]);
            let record_len = cursor.read_u16::<LittleEndian>()? as usize;
            let offset = 18;
            if offset + record_len + 64 > data.len() {
                anyhow::bail!("STORE_RECORD truncated");
            }
            let record = data[offset..offset + record_len].to_vec();
            let mut record_signature = [0u8; 64];
            record_signature.copy_from_slice(&data[offset + record_len..offset + record_len + 64]);
            Ok(DhtPayload::StoreRecord {
                key,
                record,
                record_signature,
            })
        }
        MSG_STORE_ACK => {
            if data.len() < 16 {
                anyhow::bail!("STORE_ACK too short");
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            Ok(DhtPayload::StoreAck { key })
        }
        MSG_FIND_VALUE => {
            if data.is_empty() {
                anyhow::bail!("FIND_VALUE empty");
            }
            let count = data[0] as usize;
            if data.len() < 1 + count * 16 {
                anyhow::bail!("FIND_VALUE truncated");
            }
            let mut keys = Vec::with_capacity(count);
            for i in 0..count {
                let mut key = [0u8; 16];
                key.copy_from_slice(&data[1 + i * 16..1 + (i + 1) * 16]);
                keys.push(key);
            }
            Ok(DhtPayload::FindValue { keys })
        }
        MSG_FOUND_VALUE => {
            if data.len() < 18 {
                anyhow::bail!("FOUND_VALUE too short");
            }
            let mut key = [0u8; 16];
            key.copy_from_slice(&data[..16]);
            let mut cursor = Cursor::new(&data[16..]);
            let record_count = cursor.read_u16::<LittleEndian>()? as usize;
            // A peer can claim up to 65535 records in a packet that can't
            // physically hold them. The loop below is bounded by the actual
            // data length (each record needs >= 2 bytes), so only reserve what
            // the remaining bytes could contain to avoid a large eager alloc.
            let mut records = Vec::with_capacity(record_count.min(data.len() / 2 + 1));
            let mut offset = 18usize;
            for _ in 0..record_count {
                // A declared record count that the buffer can't satisfy is a
                // framing error, not a partial list to be silently accepted —
                // reject the whole frame so a peer can't smuggle a truncated
                // payload that we'd misinterpret.
                if offset + 2 > data.len() {
                    anyhow::bail!("FOUND_VALUE truncated (declared {record_count} records)");
                }
                let rlen = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if offset + rlen > data.len() {
                    anyhow::bail!("FOUND_VALUE record length {rlen} exceeds buffer");
                }
                records.push(data[offset..offset + rlen].to_vec());
                offset += rlen;
            }
            Ok(DhtPayload::FoundValue { key, records })
        }
        _ => Ok(DhtPayload::Unknown(data.to_vec())),
    }
}

fn decode_contact_list(data: &[u8]) -> anyhow::Result<Vec<EmberContact>> {
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let count = data[0] as usize;
    if count > MAX_CONTACTS_PER_RESPONSE {
        anyhow::bail!("Contact list count {count} exceeds max {MAX_CONTACTS_PER_RESPONSE}");
    }

    let mut contacts = Vec::with_capacity(count);
    let mut offset = 1usize;

    for _ in 0..count {
        // node_id (16) + addr_type (1) + ip (4 or 16) + port (2) + noise_pub (32) + ed25519_pub (32)
        // A declared count the buffer can't satisfy is a framing error: reject
        // the whole frame instead of returning a silently-truncated prefix.
        if offset + 16 + 1 > data.len() {
            anyhow::bail!("contact list truncated (declared {count} contacts)");
        }
        // The wire still carries a node_id for format stability, but we never
        // trust it — a contact's identity is re-derived from its Ed25519 key
        // below. Consume the bytes to keep the cursor aligned.
        offset += 16;

        let addr_type = data[offset];
        offset += 1;

        let (ip, ip_len) = match addr_type {
            ADDR_IPV4 => {
                if offset + 4 > data.len() {
                    anyhow::bail!("contact list truncated (ipv4 address)");
                }
                let ip = IpAddr::V4(Ipv4Addr::new(
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ));
                (ip, 4)
            }
            ADDR_IPV6 => {
                if offset + 16 > data.len() {
                    anyhow::bail!("contact list truncated (ipv6 address)");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                let ip = IpAddr::V6(Ipv6Addr::from(octets));
                (ip, 16)
            }
            _ => {
                anyhow::bail!("Unknown address type 0x{addr_type:02x}");
            }
        };
        offset += ip_len;

        if offset + 2 + 32 + 32 > data.len() {
            anyhow::bail!("contact list truncated (port/keys)");
        }
        let port = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        let mut noise_pub = [0u8; 32];
        noise_pub.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Re-derive the node ID from the Ed25519 key rather than trusting the
        // wire-supplied value. This mirrors the identity binding `decode_message`
        // enforces for direct senders and `BootstrapNode::to_contact` applies to
        // rendezvous peers: an indirectly-learned contact cannot be injected
        // under an ID it doesn't control. A contact whose key isn't a valid
        // Ed25519 point can never be dialed or verified, so drop it silently
        // (one bad entry must not void the rest of an otherwise honest list).
        let Some(derived_id) = crypto::node_id_from_ed25519_bytes(&ed25519_pub) else {
            continue;
        };

        contacts.push(EmberContact {
            node_id: EmberNodeId(derived_id),
            addr: SocketAddr::new(ip, port),
            noise_pub,
            ed25519_pub,
            last_seen: 0,
            failed_queries: 0,
        });
    }

    Ok(contacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ember::crypto;
    use ed25519_dalek::SigningKey;

    /// A signing key paired with the node ID it actually binds to
    /// (`node_id == BLAKE3(pubkey)[..16]`). `decode_message` enforces
    /// that binding, so tests must use a consistent (key, id) pair
    /// rather than an arbitrary placeholder id.
    fn test_keypair() -> (SigningKey, EmberNodeId) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let id = EmberNodeId(crypto::node_id_from_public_key(&sk.verifying_key()));
        (sk, id)
    }

    /// Build a contact whose `node_id` is correctly derived from a real
    /// Ed25519 key. `decode_contact_list` re-derives the ID from the key and
    /// drops contacts with non-curve-valid keys, so tests must use genuine
    /// keypairs rather than placeholder bytes.
    fn test_contact(seed: u8, addr: &str, noise: u8) -> EmberContact {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let vk = sk.verifying_key();
        EmberContact {
            node_id: EmberNodeId(crypto::node_id_from_public_key(&vk)),
            addr: addr.parse().unwrap(),
            noise_pub: [noise; 32],
            ed25519_pub: vk.to_bytes(),
            last_seen: 0,
            failed_queries: 0,
        }
    }

    #[test]
    fn ping_pong_round_trip() {
        let (sk, id) = test_keypair();

        let ping = build_ping(id, 42);
        let encoded = encode_message(&ping, &sk, true);
        let decoded = decode_message(&encoded, true).unwrap();

        assert_eq!(decoded.version, EMBER_DHT_VERSION);
        assert_eq!(decoded.msg_type, MSG_PING);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.sender_id, id);
        assert!(matches!(decoded.payload, DhtPayload::Ping));

        let pong = build_pong(id, 42);
        let encoded = encode_message(&pong, &sk, false);
        let decoded = decode_message(&encoded, false).unwrap();
        assert!(matches!(decoded.payload, DhtPayload::Pong));
    }

    #[test]
    fn find_node_round_trip() {
        let (sk, id) = test_keypair();
        let target = EmberNodeId([0xAA; 16]);

        let msg = build_find_node(id, 99, target);
        let encoded = encode_message(&msg, &sk, true);
        let decoded = decode_message(&encoded, true).unwrap();

        match decoded.payload {
            DhtPayload::FindNode { target: t } => {
                assert_eq!(t, target);
            }
            _ => panic!("expected FindNode"),
        }
    }

    #[test]
    fn found_node_with_contacts_round_trip() {
        let (sk, id) = test_keypair();

        let contacts = vec![
            test_contact(11, "1.2.3.4:4662", 0xAA),
            test_contact(12, "[::1]:4663", 0xCC),
        ];

        let msg = build_found_node(id, 100, contacts.clone());
        let encoded = encode_message(&msg, &sk, true);
        let decoded = decode_message(&encoded, true).unwrap();

        match decoded.payload {
            DhtPayload::FoundNode {
                contacts: decoded_contacts,
            } => {
                assert_eq!(decoded_contacts.len(), 2);
                // node_id is re-derived from the Ed25519 key on decode and
                // must match the (correctly derived) id we encoded.
                assert_eq!(decoded_contacts[0].node_id, contacts[0].node_id);
                assert_eq!(decoded_contacts[0].addr, contacts[0].addr);
                assert_eq!(decoded_contacts[0].noise_pub, contacts[0].noise_pub);
                assert_eq!(decoded_contacts[0].ed25519_pub, contacts[0].ed25519_pub);
                assert_eq!(decoded_contacts[1].node_id, contacts[1].node_id);
                assert_eq!(decoded_contacts[1].addr, contacts[1].addr);
            }
            _ => panic!("expected FoundNode"),
        }
    }

    #[test]
    fn contact_list_drops_invalid_ed25519_keys() {
        use ed25519_dalek::VerifyingKey;
        // Find a 32-byte value that is NOT a valid Ed25519 point encoding
        // (roughly half of all y-coordinates fail to decompress).
        let bad_ed = (1u8..=255)
            .map(|i| [i; 32])
            .find(|c| VerifyingKey::from_bytes(c).is_err())
            .expect("an invalid Ed25519 encoding should exist");

        // A contact whose Ed25519 key isn't a valid curve point can't be
        // verified or dialed; decode must drop it rather than admit a contact
        // under an unverifiable identity.
        let good = test_contact(21, "9.9.9.9:1111", 0x01);
        let mut encoded = encode_contact_list(&[good.clone()]);
        // Append a second hand-rolled contact with the invalid key.
        encoded[0] = 2; // bump declared count
        encoded.extend_from_slice(&[0u8; 16]); // node_id (ignored on decode)
        encoded.push(ADDR_IPV4);
        encoded.extend_from_slice(&[8, 8, 8, 8]);
        encoded.extend_from_slice(&2000u16.to_be_bytes());
        encoded.extend_from_slice(&[0x02; 32]); // noise_pub
        encoded.extend_from_slice(&bad_ed); // invalid ed25519_pub

        let decoded = decode_contact_list(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].node_id, good.node_id);
    }

    #[test]
    fn contact_list_rejects_truncation() {
        let good = test_contact(22, "9.9.9.9:1111", 0x01);
        let mut encoded = encode_contact_list(&[good]);
        // Claim two contacts but provide bytes for only one.
        encoded[0] = 2;
        assert!(decode_contact_list(&encoded).is_err());
    }

    #[test]
    fn signature_verification_fails_on_tamper() {
        let (sk, id) = test_keypair();
        let msg = build_ping(id, 1);
        let mut encoded = encode_message(&msg, &sk, true);

        // Tamper with the request_id
        encoded[3] ^= 0xFF;

        let result = decode_message(&encoded, true);
        assert!(result.is_err());
    }

    #[test]
    fn contact_list_ipv4_and_ipv6() {
        let contacts = vec![
            test_contact(31, "10.0.0.1:1000", 0x10),
            test_contact(32, "[2001:db8::1]:2000", 0x20),
        ];

        let encoded = encode_contact_list(&contacts);
        let decoded = decode_contact_list(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(
            decoded[0].addr,
            "10.0.0.1:1000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(decoded[0].node_id, contacts[0].node_id);
        assert_eq!(
            decoded[1].addr,
            "[2001:db8::1]:2000".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(decoded[1].node_id, contacts[1].node_id);
    }
}
