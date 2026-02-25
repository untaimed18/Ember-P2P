// SECURITY NOTE: This module implements eMule-compatible KAD protocol obfuscation
// using RC4 with MD5-derived keys. RC4 is a cryptographically weak stream cipher
// and MD5 is a broken hash function. This layer provides only traffic obfuscation
// (preventing casual deep-packet inspection), NOT meaningful confidentiality.
// It is retained solely for interoperability with the existing eMule/KAD network.

use rand::Rng;

use super::types::KadId;
use digest::Digest;

const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F2EC1;

const VALID_INNER_HEADERS: [u8; 6] = [
    0xE3, // OP_EMULEPROT
    0xE5, // OP_KADEMLIAPACKEDPROT
    0xE4, // OP_KADEMLIAHEADER
    0xA3, // OP_UDPRESERVEDPROT1
    0xB2, // OP_UDPRESERVEDPROT2
    0xD4, // OP_PACKEDPROT
];

struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4State { s, i: 0, j: 0 }
    }

    fn process(&mut self, data: &[u8], out: &mut [u8]) {
        for k in 0..data.len() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            out[k] = data[k] ^ self.s[idx as usize];
        }
    }

    fn skip(&mut self, count: usize) {
        for _ in 0..count {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
        }
    }
}

/// Try to decrypt a KAD obfuscated UDP packet.
///
/// Returns `Some(decrypted_payload)` if successfully decrypted (the payload starts
/// with a protocol header byte like 0xE4/0xE5), or `None` if decryption failed.
///
/// `local_kad_id` is our node's KAD ID, used as the decryption key for NodeID-based
/// obfuscation (the most common case for incoming KAD responses).
pub fn try_decrypt_kad_packet(data: &[u8], local_kad_id: &KadId) -> Option<Vec<u8>> {
    if data.len() < 16 {
        return None;
    }

    let random_key_part = u16::from_le_bytes([data[1], data[2]]);

    // Try NodeID key first (most common for search responses)
    // Key = MD5(local_kad_id[16] + random_key_part[2])
    let mut key_data = [0u8; 18];
    key_data[..16].copy_from_slice(&local_kad_id.0);
    key_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
    let md5_hash = md5::Md5::digest(&key_data);

    if let Some(result) = try_decrypt_with_key(data, &md5_hash) {
        return Some(result);
    }

    None
}

/// Encrypt a KAD UDP packet for obfuscated sending.
///
/// `packet` is the raw KAD packet (starting with 0xE4/0xE5 header).
/// `target_kad_id` is the receiver's KAD ID (used to derive the RC4 key).
/// `sender_key` and `receiver_key` are the UDP verify keys.
pub fn encrypt_kad_packet(
    packet: &[u8],
    target_kad_id: &KadId,
    sender_key: u32,
    receiver_key: u32,
) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let random_key_part: u16 = rng.gen();
    let pad_len = (rng.gen::<u8>() & 0x0F) as usize;

    // Derive RC4 key: MD5(target_kad_id[16] + random_key_part[2])
    let mut key_data = [0u8; 18];
    key_data[..16].copy_from_slice(&target_kad_id.0);
    key_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
    let md5_hash = md5::Md5::digest(&key_data);

    let mut rc4 = Rc4State::new(&md5_hash);

    // Build the plaintext: magic(4) + pad_byte(1) + padding(N) + receiver_key(4) + sender_key(4) + packet
    let plain_len = 4 + 1 + pad_len + 4 + 4 + packet.len();
    let mut plaintext = Vec::with_capacity(plain_len);

    plaintext.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes());
    plaintext.push(pad_len as u8);
    for _ in 0..pad_len {
        plaintext.push(rng.gen());
    }
    plaintext.extend_from_slice(&receiver_key.to_le_bytes());
    plaintext.extend_from_slice(&sender_key.to_le_bytes());
    plaintext.extend_from_slice(packet);

    let mut encrypted = vec![0u8; plaintext.len()];
    rc4.process(&plaintext, &mut encrypted);

    // Semi-random first byte: use a value that doesn't collide with known protocol headers
    let semi_random = loop {
        let b: u8 = rng.gen();
        if !VALID_INNER_HEADERS.contains(&b) && b != 0x00 {
            break b;
        }
    };

    // Output: semi_random(1) + random_key_part(2) + encrypted(N)
    let mut result = Vec::with_capacity(3 + encrypted.len());
    result.push(semi_random);
    result.extend_from_slice(&random_key_part.to_le_bytes());
    result.extend_from_slice(&encrypted);
    result
}

fn try_decrypt_with_key(data: &[u8], rc4_key: &[u8]) -> Option<Vec<u8>> {
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
    let mut _receiver_key_bytes = [0u8; 4];
    let mut _sender_key_bytes = [0u8; 4];
    rc4.process(&data[offset..offset + 4], &mut _receiver_key_bytes);
    rc4.process(&data[offset + 4..offset + 8], &mut _sender_key_bytes);
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

    Some(decrypted)
}
