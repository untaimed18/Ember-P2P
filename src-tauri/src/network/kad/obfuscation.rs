// SECURITY NOTE: This module implements eMule-compatible KAD protocol obfuscation
// using RC4 with MD5-derived keys. RC4 is a cryptographically weak stream cipher
// and MD5 is a broken hash function. This layer provides only traffic obfuscation
// (preventing casual deep-packet inspection), NOT meaningful confidentiality.
// It is retained solely for interoperability with the existing eMule/KAD network.

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::types::KadId;
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

/// First bytes eMule passes through as plaintext without trying to decrypt
/// (`EncryptedDatagramSocket.cpp:164-171`), the same set its senders keep
/// their marker off (`:338-346`). Unlike [`VALID_INNER_HEADERS`] it leaves out
/// `OP_EDONKEYHEADER`.
const EMULE_PLAINTEXT_UDP_HEADERS: [u8; 6] = [0xC5, 0xE5, 0xE4, 0xA3, 0xB2, 0xD4];

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
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
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

    /// Keystream one byte per input byte into `out`. Zipping the two slices
    /// makes the length reconciliation structural: every current caller sizes
    /// `out` exactly, and indexing `out` by the input's length would panic on
    /// the packet path the first time one did not.
    pub fn process(&mut self, data: &[u8], out: &mut [u8]) {
        for (input, output) in data.iter().zip(out.iter_mut()) {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            *output = *input ^ self.s[idx as usize];
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
    /// The sender's verify key exactly as it arrived. Binding it to our public
    /// IP is the caller's job (see [`KadUDPKey::received`]); this layer knows
    /// the sender's address but not ours.
    pub sender_verify_key: Option<u32>,
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
        ) {
            return Some(result);
        }
    } else if marker == 2 && receiver_verify_key != 0 {
        // Likely ReceiverVerifyKey
        let mut vkey_data = [0u8; 6];
        vkey_data[..4].copy_from_slice(&receiver_verify_key.to_le_bytes());
        vkey_data[4..6].copy_from_slice(&random_key_part.to_le_bytes());
        if let Some(result) =
            try_decrypt_with_key(data, &md5::Md5::digest(vkey_data), receiver_verify_key)
        {
            return Some(result);
        }
    }

    // Try NodeID (always valid fallback, and primary for marker == 0)
    let mut nid_data = [0u8; 18];
    nid_data[..16].copy_from_slice(&local_kad_id.0);
    nid_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
    if let Some(result) =
        try_decrypt_with_key(data, &md5::Md5::digest(nid_data), receiver_verify_key)
    {
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
    ) {
        return Some(result);
    }

    if receiver_verify_key != 0 {
        let mut vkey_data = [0u8; 6];
        vkey_data[..4].copy_from_slice(&receiver_verify_key.to_le_bytes());
        vkey_data[4..6].copy_from_slice(&random_key_part.to_le_bytes());
        if let Some(result) =
            try_decrypt_with_key(data, &md5::Md5::digest(vkey_data), receiver_verify_key)
        {
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
        (md5::Md5::digest(vkey_data), 0x02u8)
    } else {
        // NodeID path (marker = 0x00)
        let mut key_data = [0u8; 18];
        key_data[..16].copy_from_slice(&target_kad_id.0);
        key_data[16..18].copy_from_slice(&random_key_part.to_le_bytes());
        (md5::Md5::digest(key_data), 0x00u8)
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

/// Decrypt an obfuscated ED2K **client-to-client** UDP packet addressed to
/// us: the receive half of [`encrypt_client_ed2k_packet`] and of eMule's
/// `DecryptReceivedClient` ed2k branch (`EncryptedDatagramSocket.cpp`).
///
/// Key = `MD5(our_user_hash[16] + sender_ip[4] + 91 + random_key_part[2])`,
/// the sender having keyed on our hash and its own public address. Unlike
/// KAD there are no verify keys after the padding.
///
/// Returns the plain packet (starting with its protocol byte) or `None` when
/// the datagram is not one of these. eMule always sets marker bit 0 on this
/// kind and clears it on KAD, so only such datagrams are tried.
///
/// A marker of `OP_EDONKEYHEADER` (0xE3) is tried too: eMule does not keep its
/// senders off that value, so about one obfuscated datagram in 125 starts with
/// it. The magic check below is what tells it from a plaintext 0xE3 packet.
pub fn try_decrypt_client_ed2k_packet(
    data: &[u8],
    our_user_hash: &[u8; 16],
    sender_ip: [u8; 4],
) -> Option<Vec<u8>> {
    // marker(1) + random key part(2) + magic(4) + padding length(1) + at
    // least a protocol byte and an opcode.
    if data.len() < 10
        || data[0] & 0x01 == 0
        || EMULE_PLAINTEXT_UDP_HEADERS.contains(&data[0])
    {
        return None;
    }
    let mut key_data = [0u8; 23];
    key_data[..16].copy_from_slice(our_user_hash);
    key_data[16..20].copy_from_slice(&sender_ip);
    key_data[20] = MAGICVALUE_UDP;
    key_data[21..23].copy_from_slice(&data[1..3]);
    let mut rc4 = Rc4State::new(&md5::Md5::digest(key_data));

    let mut magic = [0u8; 4];
    rc4.process(&data[3..7], &mut magic);
    if u32::from_le_bytes(magic) != MAGICVALUE_UDP_SYNC_CLIENT {
        return None;
    }
    let mut pad = [0u8; 1];
    rc4.process(&data[7..8], &mut pad);
    let pad_len = usize::from(pad[0] & 0x0F);
    let body_start = 8 + pad_len;
    if body_start + 2 > data.len() {
        return None;
    }
    rc4.skip(pad_len);
    let mut plain = vec![0u8; data.len() - body_start];
    rc4.process(&data[body_start..], &mut plain);
    VALID_INNER_HEADERS.contains(&plain[0]).then_some(plain)
}

fn try_decrypt_with_key(
    data: &[u8],
    rc4_key: &[u8],
    expected_receiver_key: u32,
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

    Some(DecryptedKadPacket {
        payload: decrypted,
        sender_verify_key: (sender_key != 0).then_some(sender_key),
        valid_receiver_key: expected_receiver_key != 0 && receiver_key == expected_receiver_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::kad::messages::{
        decode_packet, KadMessage, KADEMLIA2_BOOTSTRAP_REQ, OP_KADEMLIAPACKEDPROT,
    };
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;

    #[test]
    fn normal_obfuscated_packed_kad_survives_decrypt_then_decode() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&[]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut packed = vec![OP_KADEMLIAPACKEDPROT, KADEMLIA2_BOOTSTRAP_REQ];
        packed.extend_from_slice(&compressed);

        let local_id = KadId([0x42; 16]);
        let encrypted = encrypt_kad_packet(&packed, &local_id, 0x1122_3344, 0);
        let decrypted = try_decrypt_kad_packet(&encrypted, &local_id, &[0x24; 16], 0, 0x0102_0304)
            .expect("normal obfuscated KAD packet must decrypt");
        assert_eq!(decrypted.payload[0], OP_KADEMLIAPACKEDPROT);
        assert!(matches!(
            decode_packet(&decrypted.payload).unwrap(),
            KadMessage::BootstrapReq
        ));
    }

    #[test]
    fn client_ed2k_packet_round_trips_and_needs_the_right_key() {
        let our_hash = [0x5A; 16];
        let sender_ip = [198, 51, 100, 9];
        let plain = [0xC5, 0x90, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let wire = encrypt_client_ed2k_packet(&plain, &our_hash, sender_ip);
        assert_eq!(wire[0] & 0x01, 1, "ed2k marker bit");
        assert_eq!(
            try_decrypt_client_ed2k_packet(&wire, &our_hash, sender_ip).as_deref(),
            Some(&plain[..])
        );
        assert!(try_decrypt_client_ed2k_packet(&wire, &[0x5B; 16], sender_ip).is_none());
        assert!(try_decrypt_client_ed2k_packet(&wire, &our_hash, [198, 51, 100, 10]).is_none());
    }

    /// eMule pads with up to 15 random bytes before the packet; the receiver
    /// skips that much keystream.
    #[test]
    fn client_ed2k_packet_with_padding_decrypts() {
        let our_hash = [0x11; 16];
        let sender_ip = [203, 0, 113, 4];
        let plain = [0xC5u8, 0x91, 0xAA, 0xBB];
        let pad = [0x77u8; 5];
        let random_key_part = [0x34u8, 0x12];
        let mut key_data = [0u8; 23];
        key_data[..16].copy_from_slice(&our_hash);
        key_data[16..20].copy_from_slice(&sender_ip);
        key_data[20] = MAGICVALUE_UDP;
        key_data[21..23].copy_from_slice(&random_key_part);
        let mut rc4 = Rc4State::new(&md5::Md5::digest(key_data));
        let mut inner = MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes().to_vec();
        inner.push(pad.len() as u8);
        inner.extend_from_slice(&pad);
        inner.extend_from_slice(&plain);
        let mut enc = vec![0u8; inner.len()];
        rc4.process(&inner, &mut enc);
        let mut wire = vec![0x4D];
        wire.extend_from_slice(&random_key_part);
        wire.extend_from_slice(&enc);
        assert_eq!(
            try_decrypt_client_ed2k_packet(&wire, &our_hash, sender_ip).as_deref(),
            Some(&plain[..])
        );

        // eMule may pick `OP_EDONKEYHEADER` as the marker; the key does not
        // cover the marker, so the same body decrypts under it.
        wire[0] = 0xE3;
        assert_eq!(
            try_decrypt_client_ed2k_packet(&wire, &our_hash, sender_ip).as_deref(),
            Some(&plain[..])
        );
        // eMule's plaintext set is still never tried.
        wire[0] = 0xC5;
        assert!(try_decrypt_client_ed2k_packet(&wire, &our_hash, sender_ip).is_none());
    }

    /// A plaintext 0xE3 datagram is tried now, and has to fail the magic check.
    #[test]
    fn plaintext_edonkey_udp_is_not_mistaken_for_obfuscated() {
        let plain = [0xE3u8, 0x96, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert!(try_decrypt_client_ed2k_packet(&plain, &[0x22; 16], [192, 0, 2, 1]).is_none());
    }
}
