//! eMule client⇄server UDP obfuscation (a.k.a. "encrypted datagram socket"
//! for the **server** path).
//!
//! Direct port of `CEncryptedDatagramSocket::EncryptSendServer` and
//! `DecryptReceivedServer` from `emulesource/EncryptedDatagramSocket.cpp`.
//! The KAD client⇄client obfuscation lives in `kad/obfuscation.rs` and uses
//! a different key schedule (NodeID / UserHash / ReceiverVerifyKey) — do
//! NOT mix them up.
//!
//! ## Wire format
//! ```text
//! offset  size  field         encryption  notes
//! 0       1     byProtocol    plain       semi-random byte ≠ 0xE3
//! 1       2     wRandomKeyPart plain      LE u16, used to derive RC4 key
//! 3       4     dwMagic       RC4         LE u32 = MAGICVALUE_UDP_SYNC_SERVER (0x13EF24D5)
//! 7       1     byPadding     RC4         low 4 bits = padding length (eMule sets 0)
//! 8..     N     padding+pkt   RC4         padding bytes (currently 0), then the original ED2K UDP packet
//! ```
//! Total overhead: **8 bytes** (matches eMule `CRYPT_HEADER_SIZE`).
//!
//! ## Key schedule
//! Both directions use the same per-server `BaseKey` (server's
//! `dwServerUDPKey`, learned from the extended `OP_GLOBSERVSTATRES`
//! payload — see `server_udp.rs::parse_server_udp_response` for the
//! offset). The direction byte differs:
//!
//! ```text
//! Send key   (client → server) = MD5( BaseKey | 0x6B (CLIENTSERVER) | RandomKeyPart )
//! Recv key   (server → client) = MD5( BaseKey | 0xA5 (SERVERCLIENT) | RandomKeyPart )
//! ```
//!
//! Per the eMule comment, the first 1024 bytes of the RC4 stream are
//! **NOT** discarded for UDP keys (to save CPU) — `Rc4State::new` in
//! `kad/obfuscation.rs` already starts the stream from byte 0, which
//! matches.
//!
//! ## Detection
//! On receive, eMule decides "is this an obfuscated server packet?"
//! purely by the first byte: if it's `OP_EDONKEYPROT` (0xE3) the packet
//! is plain, otherwise try server obfuscation with that server's
//! `BaseKey`. We mirror that, and additionally require a successful
//! magic-value check before trusting the decrypted bytes — same as
//! `DecryptReceivedServer` in the reference.

use md5::{Digest, Md5};

use super::server_udp::OP_EDONKEYPROT;
use crate::network::kad::obfuscation::Rc4State;

// === eMule constants (`EncryptedDatagramSocket.cpp`) ===

/// Magic value the *server* writes in the encrypted payload to prove
/// it knows the BaseKey. Decrypt → check this u32 → if mismatch, the
/// packet isn't obfuscated by us / wasn't keyed for us.
const MAGICVALUE_UDP_SYNC_SERVER: u32 = 0x13EF_24D5;

/// Direction byte used in the *receive* key schedule (server → client).
const MAGICVALUE_UDP_SERVERCLIENT: u8 = 0xA5;

/// Direction byte used in the *send* key schedule (client → server).
const MAGICVALUE_UDP_CLIENTSERVER: u8 = 0x6B;

/// Padding length is 0 by default in eMule (`#define CRYPT_HEADER_PADDING 0`).
/// We follow that — variable padding is allowed by the protocol but adds
/// CPU work and isn't expected by any current server.
const CRYPT_HEADER_PADDING: usize = 0;

/// Total overhead bytes per encrypted server UDP packet, matching the
/// reference implementation's `CRYPT_HEADER_SIZE`:
///   1 byProtocol + 2 wRandomKeyPart + 4 dwMagic + 1 byPadding = 8
pub const SERVER_OBFUSCATION_OVERHEAD: usize = 8;

/// Build a server-obfuscation RC4 key. `direction_magic` is
/// `MAGICVALUE_UDP_CLIENTSERVER` for sends, `MAGICVALUE_UDP_SERVERCLIENT`
/// for receives (eMule symmetric layout — same MD5 input shape, only the
/// magic byte differs by direction).
fn build_key(base_key: u32, direction_magic: u8, random_key_part: u16) -> [u8; 16] {
    let mut key_data = [0u8; 7];
    key_data[0..4].copy_from_slice(&base_key.to_le_bytes());
    key_data[4] = direction_magic;
    key_data[5..7].copy_from_slice(&random_key_part.to_le_bytes());
    Md5::digest(&key_data).into()
}

/// Pick a "semi-random not protocol marker" byte for the unencrypted
/// `byProtocol` field. Mirrors the loop in `EncryptSendServer`: any byte
/// is acceptable except `OP_EDONKEYPROT` (0xE3), which would make the
/// receiver think the packet is plain. eMule retries up to 8 times then
/// asserts; we just retry indefinitely (the modulo-256 chance of
/// drawing 0xE3 every time is essentially zero).
fn random_non_protocol_marker() -> u8 {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    loop {
        let b = (rng.next_u32() & 0xFF) as u8;
        if b != OP_EDONKEYPROT {
            return b;
        }
    }
}

/// Encrypt an outgoing client→server UDP packet for a server whose
/// `BaseKey` (== `dwServerUDPKey` from the extended status response) is
/// `base_key`. `payload` is the original plain packet (typically
/// starting with `0xE3 + opcode + …`). The returned vector includes the
/// 8-byte obfuscation header followed by the encrypted payload.
///
/// `base_key` must be non-zero; eMule asserts the same. If a server has
/// not yet replied to a status ping (so we don't have its `BaseKey`),
/// the caller must send the packet plaintext instead.
pub fn encrypt_send_server(payload: &[u8], base_key: u32) -> Vec<u8> {
    debug_assert!(
        base_key != 0,
        "encrypt_send_server requires a non-zero BaseKey"
    );

    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let random_key_part: u16 = (rng.next_u32() & 0xFFFF) as u16;

    let key = build_key(base_key, MAGICVALUE_UDP_CLIENTSERVER, random_key_part);
    let mut rc4 = Rc4State::new(&key);

    // Layout: [byProtocol u8][wRandomKeyPart u16 LE][dwMagic u32 LE]
    //         [byPadding u8][padding bytes][payload bytes]
    // RC4 covers everything from dwMagic onwards.
    let total_len = SERVER_OBFUSCATION_OVERHEAD + CRYPT_HEADER_PADDING + payload.len();
    let mut out = Vec::with_capacity(total_len);

    // Unencrypted header
    out.push(random_non_protocol_marker());
    out.extend_from_slice(&random_key_part.to_le_bytes());

    // Build the plaintext for the encrypted region into a scratch buffer
    // first, then RC4-encode in one pass. Doing it in-place is also fine
    // but the scratch buffer reads more clearly and the cost is one extra
    // allocation per packet (rare path; pings + source-asks).
    let mut plain_enc = Vec::with_capacity(5 + CRYPT_HEADER_PADDING + payload.len());
    plain_enc.extend_from_slice(&MAGICVALUE_UDP_SYNC_SERVER.to_le_bytes());
    plain_enc.push(CRYPT_HEADER_PADDING as u8);
    // Currently unreachable (CRYPT_HEADER_PADDING is 0) but kept for parity
    // with eMule's reference layout — if the constant is ever bumped this
    // block lights up automatically. `absurd_extreme_comparisons` would
    // otherwise reject the `> 0` check against a `usize` minimum.
    #[allow(clippy::absurd_extreme_comparisons)]
    if CRYPT_HEADER_PADDING > 0 {
        let mut pad = vec![0u8; CRYPT_HEADER_PADDING];
        rng.fill_bytes(&mut pad);
        plain_enc.extend_from_slice(&pad);
    }
    plain_enc.extend_from_slice(payload);

    let mut enc = vec![0u8; plain_enc.len()];
    rc4.process(&plain_enc, &mut enc);
    out.extend_from_slice(&enc);
    debug_assert_eq!(out.len(), total_len);
    out
}

/// Result of a server-obfuscation decrypt attempt.
pub enum DecryptOutcome<'a> {
    /// The packet's first byte is `0xE3` — it's plain, no obfuscation
    /// applied. Caller should parse `data` directly.
    Plain,
    /// Successfully decrypted; `payload` is the inner plain packet
    /// (typically starting with `0xE3 + opcode + …`).
    Decrypted(Vec<u8>),
    /// First byte wasn't `0xE3` so we attempted decrypt, but the magic
    /// check failed — either the packet wasn't keyed for us, or
    /// `base_key` is wrong, or it's something else entirely. Caller
    /// should drop / log.
    Mismatch,
    /// The buffer was too short to even hold a valid obfuscated header.
    TooShort,
    /// The decrypted padding-length field claimed more bytes than the
    /// rest of the packet. Either corrupt or maliciously crafted.
    InvalidPadding,
    /// `base_key` was 0 — caller must skip decryption.
    NoKey,
    #[allow(dead_code)]
    /// Reserved for future use (e.g. an explicit "this peer is on the
    /// banned list" gate). Currently never returned; included so callers
    /// that exhaustively match get a stable surface.
    Rejected(&'a str),
}

/// Try to interpret an inbound UDP datagram as either plain or
/// server-obfuscated. Mirrors `DecryptReceivedServer` semantics:
///
/// 1. If `data[0] == 0xE3` → return `Plain` (no decryption needed).
/// 2. Otherwise build the receive-direction RC4 key from `base_key` +
///    the unencrypted `wRandomKeyPart`, RC4-decrypt the magic field,
///    and check it equals `MAGICVALUE_UDP_SYNC_SERVER`.
/// 3. If yes → decrypt the rest, strip padding, return the inner packet.
/// 4. If no → `Mismatch`.
///
/// `base_key` must be the server's known `dwServerUDPKey`; pass 0 to
/// short-circuit (returns `NoKey`).
pub fn decrypt_received_server(data: &[u8], base_key: u32) -> DecryptOutcome<'static> {
    if data.is_empty() {
        return DecryptOutcome::TooShort;
    }
    if data[0] == OP_EDONKEYPROT {
        return DecryptOutcome::Plain;
    }
    if base_key == 0 {
        return DecryptOutcome::NoKey;
    }
    if data.len() <= SERVER_OBFUSCATION_OVERHEAD {
        return DecryptOutcome::TooShort;
    }

    let random_key_part = u16::from_le_bytes([data[1], data[2]]);
    let key = build_key(base_key, MAGICVALUE_UDP_SERVERCLIENT, random_key_part);
    let mut rc4 = Rc4State::new(&key);

    // Decrypt the magic value (4 bytes starting at offset 3).
    let mut magic_bytes = [0u8; 4];
    rc4.process(&data[3..7], &mut magic_bytes);
    let magic = u32::from_le_bytes(magic_bytes);
    if magic != MAGICVALUE_UDP_SYNC_SERVER {
        return DecryptOutcome::Mismatch;
    }

    // Decrypt the padding-length byte.
    let mut pad_byte = [0u8; 1];
    rc4.process(&data[7..8], &mut pad_byte);
    let padding_len = (pad_byte[0] & 0x0F) as usize;

    // Bounds: header(8) + padding + at-least-1-byte-payload ≤ data.len()
    if data.len() < SERVER_OBFUSCATION_OVERHEAD + padding_len + 1 {
        return DecryptOutcome::InvalidPadding;
    }

    // Skip (decrypt-and-discard) padding bytes to advance the RC4 stream.
    if padding_len > 0 {
        let mut pad_scratch = vec![0u8; padding_len];
        let pad_start = SERVER_OBFUSCATION_OVERHEAD;
        let pad_end = pad_start + padding_len;
        rc4.process(&data[pad_start..pad_end], &mut pad_scratch);
    }

    // Decrypt the actual payload.
    let payload_start = SERVER_OBFUSCATION_OVERHEAD + padding_len;
    let payload_len = data.len() - payload_start;
    let mut payload = vec![0u8; payload_len];
    rc4.process(&data[payload_start..], &mut payload);

    DecryptOutcome::Decrypted(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a representative server UDP packet through
    /// `encrypt_send_server` → `decrypt_received_server`. Note we cross
    /// the direction barrier: encrypt with CLIENTSERVER key, decrypt
    /// with SERVERCLIENT key — that's NOT a valid round-trip path on
    /// the actual wire (both ends use opposite directions). For a
    /// realistic test we'd need a recorded server reply; here we
    /// simulate "server-side encrypted" by manually building a packet
    /// with the receive-direction key derivation reversed.
    #[test]
    fn encrypt_then_decrypt_with_swapped_direction_keys() {
        let base_key = 0xDEAD_BEEFu32;
        // The original ED2K packet (must start with 0xE3).
        let plain = vec![0xE3, 0x9A, 0x11, 0x22, 0x33, 0x44];

        // Pretend we're the server: build a packet with the
        // receive-direction key (because that's what the client decrypts
        // with). We do that by temporarily flipping the encrypt direction
        // — easier than spinning up a separate `encrypt_recv_server`.
        let random_key_part: u16 = 0xAA55;
        let key = build_key(base_key, MAGICVALUE_UDP_SERVERCLIENT, random_key_part);
        let mut rc4 = Rc4State::new(&key);
        let mut wire = Vec::new();
        wire.push(0x42); // any non-0xE3 marker
        wire.extend_from_slice(&random_key_part.to_le_bytes());
        let mut enc_region = Vec::new();
        enc_region.extend_from_slice(&MAGICVALUE_UDP_SYNC_SERVER.to_le_bytes());
        enc_region.push(0u8); // padding length 0
        enc_region.extend_from_slice(&plain);
        let mut ciphered = vec![0u8; enc_region.len()];
        rc4.process(&enc_region, &mut ciphered);
        wire.extend_from_slice(&ciphered);

        match decrypt_received_server(&wire, base_key) {
            DecryptOutcome::Decrypted(payload) => {
                assert_eq!(payload, plain, "round-trip payload mismatch");
            }
            other => panic!("expected Decrypted, got {:?}", outcome_label(&other)),
        }
    }

    /// Plain packets (first byte 0xE3) must short-circuit without
    /// touching RC4 — verifies the decrypt path doesn't accidentally
    /// reject legitimate plain replies from non-obfuscated servers.
    #[test]
    fn plain_packets_pass_through_unchanged() {
        let plain = vec![0xE3u8, 0x9B, 0x00, 0x01, 0x02, 0x03];
        match decrypt_received_server(&plain, 0xDEAD_BEEF) {
            DecryptOutcome::Plain => {}
            other => panic!("expected Plain, got {:?}", outcome_label(&other)),
        }
    }

    /// `base_key == 0` (server hasn't replied to our status ping yet)
    /// must short-circuit so we don't waste cycles on a guaranteed-fail
    /// MD5+RC4 pass.
    #[test]
    fn zero_base_key_short_circuits() {
        let wire = vec![0x42u8, 0xAA, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE3];
        match decrypt_received_server(&wire, 0) {
            DecryptOutcome::NoKey => {}
            other => panic!("expected NoKey, got {:?}", outcome_label(&other)),
        }
    }

    /// Packets shorter than the obfuscation header can't be valid. We
    /// must NOT panic on slicing.
    #[test]
    fn too_short_packet_does_not_panic() {
        let wire = vec![0x42u8, 0xAA];
        match decrypt_received_server(&wire, 0xDEAD_BEEF) {
            DecryptOutcome::TooShort => {}
            other => panic!("expected TooShort, got {:?}", outcome_label(&other)),
        }
    }

    /// A non-0xE3 packet that ISN'T actually obfuscated (random data
    /// long enough to look like a header) must fail the magic check
    /// instead of pretending to decrypt garbage.
    #[test]
    fn random_data_fails_magic_check() {
        let wire = vec![
            0x42u8, 0xAA, 0x55, // header: marker + random_key_part
            0xDE, 0xAD, 0xBE, 0xEF, // would-be magic
            0x00, // padding len
            0xFF, 0xFF, 0xFF, // pretend payload
        ];
        match decrypt_received_server(&wire, 0xDEAD_BEEF) {
            DecryptOutcome::Mismatch => {}
            other => panic!("expected Mismatch, got {:?}", outcome_label(&other)),
        }
    }

    /// `EncryptSendServer` overhead must equal eMule's `CRYPT_HEADER_SIZE`
    /// (8 bytes). Pinning this constant guards against silent additions
    /// to the obfuscation header that would break wire compatibility.
    #[test]
    fn overhead_matches_emule_crypt_header_size() {
        assert_eq!(SERVER_OBFUSCATION_OVERHEAD, 8);
        let plain = vec![0xE3u8; 10];
        let enc = encrypt_send_server(&plain, 0xDEAD_BEEF);
        assert_eq!(enc.len(), plain.len() + SERVER_OBFUSCATION_OVERHEAD);
        // First byte must NOT be 0xE3 (the disambiguator on receive).
        assert_ne!(enc[0], OP_EDONKEYPROT);
    }

    /// Symmetric round-trip on the **encrypt path**: feed our
    /// `encrypt_send_server` output to a hand-rolled CLIENTSERVER-key
    /// decrypt (which is what an eMule server's
    /// `DecryptReceivedServer` does on its side — same algorithm,
    /// same magic, just the server-side direction). If our encrypt
    /// is wire-correct, this MUST decrypt back to the input. Catches
    /// any future regression where the encrypt layout drifts from
    /// the wire spec without anyone noticing because the production
    /// path only tests against itself.
    #[test]
    fn encrypt_send_server_round_trips_via_server_side_decrypt() {
        let base_key = 0xCAFE_BABEu32;
        let plain: Vec<u8> = (0..40).map(|i| 0xE3u8.wrapping_add(i as u8)).collect();
        // (Use varying bytes including the 0xE3 marker to catch any
        // off-by-one in the RC4 region.)

        let wire = encrypt_send_server(&plain, base_key);
        assert_eq!(wire.len(), plain.len() + SERVER_OBFUSCATION_OVERHEAD);

        // Server side: extract wRandomKeyPart from the unencrypted
        // header, derive the CLIENTSERVER key (the *server* uses
        // CLIENTSERVER for receive because we sent with CLIENTSERVER),
        // and decrypt magic + padding-len + payload.
        let random_key_part = u16::from_le_bytes([wire[1], wire[2]]);
        let key = build_key(base_key, MAGICVALUE_UDP_CLIENTSERVER, random_key_part);
        let mut rc4 = Rc4State::new(&key);

        let mut magic_bytes = [0u8; 4];
        rc4.process(&wire[3..7], &mut magic_bytes);
        let magic = u32::from_le_bytes(magic_bytes);
        assert_eq!(
            magic, MAGICVALUE_UDP_SYNC_SERVER,
            "encrypt produced wrong magic value"
        );

        let mut pad_byte = [0u8; 1];
        rc4.process(&wire[7..8], &mut pad_byte);
        let padding_len = (pad_byte[0] & 0x0F) as usize;
        assert_eq!(padding_len, 0, "encrypt put non-zero padding (we expect 0)");

        let mut decoded = vec![0u8; wire.len() - 8 - padding_len];
        rc4.process(&wire[8 + padding_len..], &mut decoded);
        assert_eq!(
            decoded, plain,
            "encrypt-then-server-decrypt did not round-trip"
        );
    }

    fn outcome_label(o: &DecryptOutcome<'_>) -> &'static str {
        match o {
            DecryptOutcome::Plain => "Plain",
            DecryptOutcome::Decrypted(_) => "Decrypted",
            DecryptOutcome::Mismatch => "Mismatch",
            DecryptOutcome::TooShort => "TooShort",
            DecryptOutcome::InvalidPadding => "InvalidPadding",
            DecryptOutcome::NoKey => "NoKey",
            DecryptOutcome::Rejected(_) => "Rejected",
        }
    }
}
