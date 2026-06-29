// SECURITY NOTE: This module implements eMule-compatible KAD protocol obfuscation
// using RC4 with MD5-derived keys. RC4 is a cryptographically weak stream cipher
// and MD5 is a broken hash function. This layer provides only traffic obfuscation
// (preventing casual deep-packet inspection), NOT meaningful confidentiality.
// It is retained solely for interoperability with the existing eMule/KAD network.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::types::{KadId, KadUDPKey};
use digest::Digest;

const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F2EC1;

/// eMule's `MAGICVALUE_UDP` (decimal 91) mixed into the ED2K client-to-client
/// UDP obfuscation key. See `EncryptedDatagramSocket.cpp::EncryptSendClient`.
const MAGICVALUE_UDP: u8 = 91;

const VALID_INNER_HEADERS: [u8; 7] = [
    0xE3, // OP_EDONKEYHEADER / OP_EDONKEYPROT
    0xC5, // OP_EMULEPROT
    0xE5, // OP_KADEMLIAPACKEDPROT
    0xE4, // OP_KADEMLIAHEADER
    0xA3, // OP_UDPRESERVEDPROT1
    0xB2, // OP_UDPRESERVEDPROT2
    0xD4, // OP_PACKEDPROT
];

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    pub fn new(key: &[u8]) -> Self {
        debug_assert!(!key.is_empty(), "Rc4State::new requires a non-empty key");
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }
        // Every caller passes a fixed-length key (an MD5 digest), so an empty
        // key is unreachable in practice — but guard the `% key.len()` below so
        // a future empty-key caller degrades to an (unused) identity state
        // rather than panicking with a divide-by-zero in release builds.
        if key.is_empty() {
            return Rc4State { s, i: 0, j: 0 };
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4State { s, i: 0, j: 0 }
    }

    pub fn process(&mut self, data: &[u8], out: &mut [u8]) {
        for k in 0..data.len() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            out[k] = data[k] ^ self.s[idx as usize];
        }
    }

    pub fn skip(&mut self, count: usize) {
        for _ in 0..count {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
        }
    }
}

pub struct DecryptedKadPacket {
    pub payload: Vec<u8>,
    pub sender_udp_key: Option<KadUDPKey>,
    pub valid_receiver_key: bool,
}

/// Try to decrypt a KAD obfuscated UDP packet using all 3 eMule key types.
///
/// Returns packet metadata if successfully decrypted (the payload starts with a
/// protocol header byte like 0xE4/0xE5), or `None` if decryption failed.
///
/// eMule tries 3 keys in order:
/// - Key 0 (NodeID): MD5(local_kad_id[16] + random_key_part[2])
/// - Key 1 (UserHash/ed2k): MD5(user_hash[16] + sender_ip[4] + 91[1] + random_key_part[2])
/// - Key 2 (ReceiverVerifyKey): MD5(receiver_verify_key[4] + random_key_part[2])
pub fn try_decrypt_kad_packet(
    data: &[u8],
    local_kad_id: &KadId,
    user_hash: &[u8; 16],
    receiver_verify_key: u32,
    sender_ip: u32,
) -> Option<DecryptedKadPacket> {
    if data.len() < 16 {
        return None;
    }

    let random_key_part = u16::from_le_bytes([data[1], data[2]]);

    // eMule uses marker bits in the first byte to hint which key was used:
    //   bit0 == 1 -> UserHash (ed2k), bit1 == 1 & bit0 == 0 -> ReceiverVerifyKey, else -> NodeID
    let marker = data[0] & 0x03;

    let mut key_data = [0u8; 23];

    if marker == 1 {
        // UserHash key: user_hash(16) + IP(4) + MAGICVALUE_UDP(1=91) + random_key_part(2)
        key_data[..16].copy_from_slice(user_hash);
        key_data[16..20].copy_from_slice(&sender_ip.to_le_bytes());
        key_data[20] = 91; // MAGICVALUE_UDP
        key_data[21..23].copy_from_slice(&random_key_part.to_le_bytes());
        if let Some(result) = try_decrypt_with_key(
            data,
            &md5::Md5::digest(&key_data[..23]),
            receiver_verify_key,
            sender_ip,
        ) {
            return Some(result);
        }
    } else if marker == 2 && receiver_verify_key != 0 {
        // Likely ReceiverVerifyKey
        let mut vkey_data = [0u8; 6];
        vkey_data[..4].copy_from_slice(&receiver_verify_key.to_le_bytes());
        vkey_data[4..6].copy_from_slice(&random_key_part.to_le_bytes());
        if let Some(result) = try_decrypt_with_key(
            data,
            &md5::Md5::digest(&vkey_data),
            receiver_verify_key,
            sender_ip,
        ) {
            return Some(result);
        }
    }

    // Try NodeID (always valid fallback, and primary for marker == 0)
    let mut nid_data = [0u8; 18];
    nid_data[..16].copy_from_slice(&local_kad_id.0);
    nid_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
    if let Some(result) = try_decrypt_with_key(
        data,
        &md5::Md5::digest(&nid_data),
        receiver_verify_key,
        sender_ip,
    ) {
        return Some(result);
    }

    // Try remaining keys as fallback (UserHash with full 23-byte derivation)
    key_data[..16].copy_from_slice(user_hash);
    key_data[16..20].copy_from_slice(&sender_ip.to_le_bytes());
    key_data[20] = 91;
    key_data[21..23].copy_from_slice(&random_key_part.to_le_bytes());
    if let Some(result) = try_decrypt_with_key(
        data,
        &md5::Md5::digest(&key_data[..23]),
        receiver_verify_key,
        sender_ip,
    ) {
        return Some(result);
    }

    if receiver_verify_key != 0 {
        let mut vkey_data = [0u8; 6];
        vkey_data[..4].copy_from_slice(&receiver_verify_key.to_le_bytes());
        vkey_data[4..6].copy_from_slice(&random_key_part.to_le_bytes());
        if let Some(result) = try_decrypt_with_key(
            data,
            &md5::Md5::digest(&vkey_data),
            receiver_verify_key,
            sender_ip,
        ) {
            return Some(result);
        }
    }

    None
}

/// Encrypt a KAD UDP packet for obfuscated sending.
///
/// `packet` is the raw KAD packet (starting with 0xE4/0xE5 header).
/// `target_kad_id` is the receiver's KAD ID (used to derive the RC4 key).
/// If `target_kad_id` is zero/unknown, falls back to `receiver_key` (marker=0x02).
/// `sender_key` and `receiver_key` are the UDP verify keys.
pub fn encrypt_kad_packet(
    packet: &[u8],
    target_kad_id: &KadId,
    sender_key: u32,
    receiver_key: u32,
) -> Vec<u8> {
    // OsRng: key material for UDP obfuscation must remain unpredictable
    // from the network; using the OS entropy source keeps the security
    // property reviewable independent of the thread-RNG seeding story.
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut rng = OsRng;

    let random_key_part: u16 = (rng.next_u32() & 0xFFFF) as u16;
    let pad_len = ((rng.next_u32() & 0x0F) as u8) as usize;

    let use_verify_key = *target_kad_id == KadId::zero() && receiver_key != 0;

    let (md5_hash, marker_bits) = if use_verify_key {
        // ReceiverVerifyKey path (marker = 0x02)
        let mut vkey_data = [0u8; 6];
        vkey_data[..4].copy_from_slice(&receiver_key.to_le_bytes());
        vkey_data[4..6].copy_from_slice(&random_key_part.to_le_bytes());
        (md5::Md5::digest(&vkey_data), 0x02u8)
    } else {
        // NodeID path (marker = 0x00)
        let mut key_data = [0u8; 18];
        key_data[..16].copy_from_slice(&target_kad_id.0);
        key_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
        (md5::Md5::digest(&key_data), 0x00u8)
    };

    let mut rc4 = Rc4State::new(&md5_hash);

    let plain_len = 4 + 1 + pad_len + 4 + 4 + packet.len();
    let mut plaintext = Vec::with_capacity(plain_len);

    plaintext.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes());
    plaintext.push(pad_len as u8);
    if pad_len > 0 {
        let pad_start = plaintext.len();
        plaintext.resize(pad_start + pad_len, 0);
        rng.fill_bytes(&mut plaintext[pad_start..]);
    }
    plaintext.extend_from_slice(&receiver_key.to_le_bytes());
    plaintext.extend_from_slice(&sender_key.to_le_bytes());
    plaintext.extend_from_slice(packet);

    let mut encrypted = vec![0u8; plaintext.len()];
    rc4.process(&plaintext, &mut encrypted);

    let semi_random = {
        let mut result = None;
        for _ in 0..256 {
            let mut b: u8 = (rng.next_u32() & 0xFF) as u8;
            b = (b & 0xFC) | marker_bits;
            if !VALID_INNER_HEADERS.contains(&b) && b != 0x00 {
                result = Some(b);
                break;
            }
        }
        result.unwrap_or(0x4C | marker_bits)
    };

    let mut result = Vec::with_capacity(3 + encrypted.len());
    result.push(semi_random);
    result.extend_from_slice(&random_key_part.to_le_bytes());
    result.extend_from_slice(&encrypted);
    result
}

/// Encrypt an ED2K **client-to-client** UDP packet (e.g. `OP_DIRECTCALLBACKREQ`)
/// using eMule's client UDP obfuscation. This is distinct from KAD obfuscation:
/// it carries **no** receiver/sender verify keys and is keyed on the *target*
/// client's ED2K user hash plus *our* public IP (mirrors
/// `EncryptedDatagramSocket.cpp::EncryptSendClient` with `bKad == false`).
///
/// Key = `MD5(target_user_hash[16] + our_public_ip[4] + 91 + random_key_part[2])`.
///
/// Wire layout (padding length is always 0, matching eMule's
/// `CRYPT_HEADER_PADDING == 0`):
/// `semi_random[1] | random_key_part[2 LE] | RC4( magic[4 LE] | pad_len(0)[1] | packet )`
///
/// * `packet` is the raw plain packet starting with its protocol byte
///   (`0xC5` = `OP_EMULEPROT`), then the opcode and payload — exactly what would
///   otherwise go on the wire unobfuscated.
/// * `target_user_hash` is the receiving client's 16-byte ED2K user hash.
/// * `our_public_ip` is our external IPv4 address in octet order (`a.b.c.d`),
///   i.e. `Ipv4Addr::octets()`. The receiver derives the same key from the
///   source IP of our datagram, so these must match.
pub fn encrypt_client_ed2k_packet(
    packet: &[u8],
    target_user_hash: &[u8; 16],
    our_public_ip: [u8; 4],
) -> Vec<u8> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut rng = OsRng;

    let random_key_part: u16 = (rng.next_u32() & 0xFFFF) as u16;

    // Sendkey: MD5(UserHashTarget[16] + OurPublicIP[4] + MAGICVALUE_UDP[1] + RandomKeyPart[2])
    let mut key_data = [0u8; 23];
    key_data[..16].copy_from_slice(target_user_hash);
    key_data[16..20].copy_from_slice(&our_public_ip);
    key_data[20] = MAGICVALUE_UDP;
    key_data[21..23].copy_from_slice(&random_key_part.to_le_bytes());
    let md5_hash = md5::Md5::digest(key_data);

    let mut rc4 = Rc4State::new(&md5_hash);

    // Encrypted region: magic(4) + padding-length(1, always 0) + payload.
    let mut plaintext = Vec::with_capacity(4 + 1 + packet.len());
    plaintext.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes());
    plaintext.push(0u8); // CRYPT_HEADER_PADDING == 0
    plaintext.extend_from_slice(packet);

    let mut encrypted = vec![0u8; plaintext.len()];
    rc4.process(&plaintext, &mut encrypted);

    // First (unencrypted) byte must have the ED2K marker bit (bit 0) set and
    // must not collide with any real protocol header byte, otherwise the
    // receiver treats the datagram as plaintext and never attempts to decrypt.
    let semi_random = {
        let mut result = None;
        for _ in 0..256 {
            let b: u8 = ((rng.next_u32() & 0xFF) as u8) | 0x01;
            if !VALID_INNER_HEADERS.contains(&b) {
                result = Some(b);
                break;
            }
        }
        // 0x4D = 'M', odd, and not a protocol header byte — safe fallback.
        result.unwrap_or(0x4D)
    };

    let mut out = Vec::with_capacity(3 + encrypted.len());
    out.push(semi_random);
    out.extend_from_slice(&random_key_part.to_le_bytes());
    out.extend_from_slice(&encrypted);
    out
}

fn try_decrypt_with_key(
    data: &[u8],
    rc4_key: &[u8],
    expected_receiver_key: u32,
    sender_ip: u32,
) -> Option<DecryptedKadPacket> {
    let mut rc4 = Rc4State::new(rc4_key);

    // Decrypt the magic value (4 bytes starting at offset 3)
    let mut magic_bytes = [0u8; 4];
    rc4.process(&data[3..7], &mut magic_bytes);
    let magic = u32::from_le_bytes(magic_bytes);

    if magic != MAGICVALUE_UDP_SYNC_CLIENT {
        return None;
    }

    // Decrypt padding length byte
    let mut pad_byte = [0u8; 1];
    rc4.process(&data[7..8], &mut pad_byte);
    let pad_len = (pad_byte[0] & 0x0F) as usize;

    // Header so far: 1 (protocol) + 2 (random) + 4 (magic) + 1 (padding byte) = 8
    let mut offset = 8;

    if pad_len > 0 {
        if offset + pad_len > data.len() {
            return None;
        }
        rc4.skip(pad_len);
        offset += pad_len;
    }

    // KAD packets have 8 bytes of verify keys (receiver + sender)
    if offset + 8 > data.len() {
        return None;
    }
    let mut receiver_key_bytes = [0u8; 4];
    let mut sender_key_bytes = [0u8; 4];
    rc4.process(&data[offset..offset + 4], &mut receiver_key_bytes);
    rc4.process(&data[offset + 4..offset + 8], &mut sender_key_bytes);
    offset += 8;

    let remaining = data.len() - offset;
    if remaining == 0 {
        return None;
    }

    let mut decrypted = vec![0u8; remaining];
    rc4.process(&data[offset..], &mut decrypted);

    if !VALID_INNER_HEADERS.contains(&decrypted[0]) {
        return None;
    }

    let receiver_key = u32::from_le_bytes(receiver_key_bytes);
    let sender_key = u32::from_le_bytes(sender_key_bytes);
    let sender_udp_key = if sender_key != 0 {
        Some(KadUDPKey {
            key: sender_key,
            ip: sender_ip,
        })
    } else {
        None
    };

    Some(DecryptedKadPacket {
        payload: decrypted,
        sender_udp_key,
        valid_receiver_key: expected_receiver_key != 0 && receiver_key == expected_receiver_key,
    })
}
