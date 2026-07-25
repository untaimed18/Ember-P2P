use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

/// Derive a 16-byte Ember node ID from an Ed25519 public key.
///
/// Uses BLAKE3 to hash the 32-byte public key, then truncates to 16 bytes.
/// This produces a 128-bit ID compatible with the existing `ember_hash` field
/// while being cryptographically bound to the keypair.
pub fn node_id_from_public_key(public_key: &VerifyingKey) -> [u8; 16] {
    let hash = blake3::hash(public_key.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash.as_bytes()[..16]);
    id
}

/// Derive the 16-byte Ember node ID directly from raw Ed25519 public-key
/// bytes, returning `None` if the bytes are not a valid curve point.
///
/// This is the canonical way to (re)derive a contact's identity from material
/// that arrived over the wire (`FOUND_NODE` contact lists) or off disk
/// (`nodes_ember.dat`). Because the node ID is `BLAKE3(ed25519_pub)[..16]`, a
/// peer-supplied `node_id` is always redundant and must never be trusted — we
/// recompute it here so a malicious or corrupt source cannot inject a contact
/// under an ID it does not actually control (routing-table poisoning / eclipse
/// defense).
pub fn node_id_from_ed25519_bytes(bytes: &[u8; 32]) -> Option<[u8; 16]> {
    verifying_key_from_bytes(bytes).map(|vk| node_id_from_public_key(&vk))
}

/// Verify the identity-binding claim `BLAKE3(pubkey)[0..16] == advertised_hash`.
///
/// This is the cheap, offline half of full Ember identity verification: it
/// confirms that the peer is consistent about which Ed25519 key they claim
/// backs their 16-byte Ember hash, without requiring an interactive
/// challenge-response round trip. A peer that advertises a `pubkey` whose
/// BLAKE3 prefix doesn't match their `ember_hash` is lying about one of the
/// two; treat them as unverified.
///
/// Returns `false` if `pubkey` cannot be parsed as a valid Ed25519 point
/// (bad encoding / subgroup) — we refuse to bind an identity to a
/// non-curve-valid key under any circumstances.
///
/// This check is NOT a proof of private-key possession. Anyone who has
/// observed a peer's legitimate public key on the wire can replay it with
/// a matching hash. The full anti-replay gate is
/// `friend_connect::perform_ember_auth`, which runs an Ed25519 signature
/// round-trip over a fresh nonce. Use this binding check as an always-on
/// pre-filter and the challenge-response as the authoritative gate
/// whenever you're granting friend-level trust.
pub fn verify_ember_hash_binding(pubkey: &[u8; 32], advertised_hash: &[u8; 16]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => node_id_from_public_key(&vk) == *advertised_hash,
        Err(_) => false,
    }
}

/// Sign an arbitrary message with an Ed25519 signing key.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> [u8; 64] {
    signing_key.sign(message).to_bytes()
}

/// Verify an Ed25519 signature against a public key and message.
pub fn verify(public_key: &VerifyingKey, message: &[u8], signature: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(signature);
    public_key.verify_strict(message, &sig).is_ok()
}

/// Reconstruct a [`VerifyingKey`] from raw 32-byte public key material.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).ok()
}

/// Reconstruct a [`SigningKey`] from raw 32-byte secret key material.
pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(bytes)
}

/// Compute the BLAKE3 hash of a file's contents, returning the 32-byte digest.
///
/// This is the "Ember file hash" used for content integrity on the Ember
/// network (alongside the legacy ed2k MD4 hash for KAD/ED2K discovery).
pub fn blake3_hash_file(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Incremental BLAKE3 hasher for large files that cannot be loaded into memory.
pub struct Blake3FileHasher {
    hasher: blake3::Hasher,
}

impl Blake3FileHasher {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        *self.hasher.finalize().as_bytes()
    }
}

/// Streaming BLAKE3 of a file on disk (slice 18). Returns hex for storage
/// on `FileInfo` / `known.met`.
pub fn blake3_hash_file_path(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Blake3FileHasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

// --- Friend-chat end-to-end encryption -------------------------------
//
// Friend chat (`OP_EMBER_CHAT_MSG`) is encrypted with an AEAD key derived
// from an X25519 Diffie-Hellman exchange between the two friends'
// long-term Ed25519 identity keys — the same keys that already back
// `ember_hash` and proof-of-possession, converted to their X25519
// (Montgomery) form via the standard birational map between the two
// curve representations (the same technique libsodium's
// `crypto_sign_ed25519_{sk,pk}_to_curve25519` use). We deliberately reuse
// this identity key rather than minting a separate chat keypair: every
// friend session already requires both sides to have proven possession
// of it (`perform_ember_auth`), so there is no additional trust bootstrap
// needed, and no extra key to advertise, persist, or rotate.
//
// This gives confidentiality and integrity against anyone relaying or
// observing the TCP session (including a malicious/compromised
// rendezvous or relay hop — see `broker.rs`), but it is a *static* DH,
// not a ratcheting protocol: it does not provide forward secrecy against
// a future compromise of either party's long-term Ed25519 secret key.
// That tradeoff matches what's achievable without a persistent
// session/ratchet state store, and is a strict improvement over today's
// plaintext-on-the-wire chat.

/// Version tag for the friend-chat AEAD envelope (`version || nonce ||
/// ciphertext‖tag`). Bumped whenever the wire format, algorithm, or KDF
/// context changes, so old and new builds can never silently misinterpret
/// each other's bytes — see [`decrypt_chat_message`].
pub const CHAT_ENVELOPE_VERSION: u8 = 1;

/// XChaCha20-Poly1305 nonce length in bytes.
const CHAT_NONCE_LEN: usize = 24;
/// Poly1305 authentication tag length in bytes.
const CHAT_TAG_LEN: usize = 16;

/// Fixed per-message overhead `encrypt_chat_message` adds on top of the
/// plaintext (`version(1) + nonce(24) + tag(16)`). Any caller enforcing a
/// wire-size cap on `OP_EMBER_CHAT_MSG` payloads must add this to the
/// plaintext limit, or legitimate encrypted messages at the plaintext cap
/// will be rejected as oversized.
pub const CHAT_ENVELOPE_OVERHEAD: usize = 1 + CHAT_NONCE_LEN + CHAT_TAG_LEN;

/// HKDF "info" context binding the derived key to this exact purpose, so
/// the same raw X25519 DH output can never be reused (even accidentally)
/// as a key for some other protocol layered on the same identity keys.
const CHAT_KEY_INFO: &[u8] = b"ember-friend-chat-v1";
const PAIRWISE_KEY_INFO: &[u8] = b"ember-pairwise-capability-v1\0";
/// Rotating rendezvous capabilities change every fifteen minutes. Presence
/// entries expire sooner server-side, so accepting the previous epoch only
/// bridges a clock/boundary race and does not create a long-lived identifier.
pub const PAIRWISE_CAPABILITY_EPOCH_SECS: i64 = 15 * 60;

/// Derive the X25519 secret scalar corresponding to an Ed25519 signing
/// key's seed, per the standard Ed25519-to-X25519 conversion: hash the
/// 32-byte seed with SHA-512 and take the low 32 bytes (clamping is
/// applied later, at scalar-multiplication time, by `x25519-dalek`
/// itself). This is the exact same scalar Ed25519 uses internally to
/// compute the Edwards public key from the seed — X25519 and Ed25519
/// operate over the same underlying group, just with different point
/// encodings (Montgomery vs. Edwards).
fn ed25519_seed_to_x25519_scalar(seed: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);
    hash.zeroize();
    scalar
}

/// Convert the persistent Ed25519 identity seed into the X25519 static
/// private key used by Ember's Noise protocols.  Keeping this conversion in
/// one place prevents the UDP and stream transports from accidentally binding
/// different long-term identities.
pub(crate) fn ed25519_seed_to_x25519_private(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_seed_to_x25519_scalar(seed)
}

/// Convert an Ed25519 public key (Edwards form) to its X25519
/// (Montgomery form) equivalent via the standard birational map between
/// the two curve representations.
///
/// Returns `None` if `ed25519_pubkey` isn't a strictly-valid, canonically
/// encoded Ed25519 point — we first run it through
/// [`VerifyingKey::from_bytes`] (the same strict check
/// [`verify_ember_hash_binding`] and every Ed25519 signature verification
/// in this codebase relies on) rather than only the more permissive
/// `curve25519-dalek` decompression, which accepts some non-canonical
/// encodings that reduce mod p. Callers must treat `None` as "cannot
/// derive a chat key with this peer" rather than panicking or falling
/// back to an insecure default.
fn ed25519_pubkey_to_x25519(ed25519_pubkey: &[u8; 32]) -> Option<X25519PublicKey> {
    VerifyingKey::from_bytes(ed25519_pubkey).ok()?;
    let point = CompressedEdwardsY(*ed25519_pubkey).decompress()?;
    Some(X25519PublicKey::from(point.to_montgomery().to_bytes()))
}

/// Public-key half of [`ed25519_seed_to_x25519_private`].
pub(crate) fn ed25519_public_to_x25519(ed25519_pubkey: &[u8; 32]) -> Option<[u8; 32]> {
    Some(ed25519_pubkey_to_x25519(ed25519_pubkey)?.to_bytes())
}

/// Derive the symmetric AEAD key used to encrypt/decrypt friend-chat
/// messages exchanged with `peer_ed25519_pubkey`, from our own Ed25519
/// identity seed.
///
/// Both sides of a friend session compute this independently (each using
/// their own secret and the other's already PoP-verified public key) and
/// arrive at the same 32-byte key, via X25519 Diffie-Hellman stretched
/// through HKDF-SHA256.
///
/// Returns `None` if `peer_ed25519_pubkey` isn't a valid curve point, or
/// if the DH exchange was non-contributory (see
/// [`x25519_dalek::SharedSecret::was_contributory`] — this rejects
/// degenerate/low-order peer keys that could otherwise force a
/// predictable shared secret).
pub fn derive_chat_key(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
) -> Option<[u8; 32]> {
    let their_x25519_pub = ed25519_pubkey_to_x25519(peer_ed25519_pubkey)?;
    let mut our_scalar = ed25519_seed_to_x25519_scalar(our_ed25519_seed);
    let our_secret = X25519StaticSecret::from(our_scalar);
    our_scalar.zeroize();
    let shared = our_secret.diffie_hellman(&their_x25519_pub);
    if !shared.was_contributory() {
        return None;
    }
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut key = [0u8; 32];
    // 32 bytes is always a valid HKDF-SHA256 output length (max is
    // 255 * 32), so `expand` cannot fail here.
    hk.expand(CHAT_KEY_INFO, &mut key)
        .expect("32-byte OKM is within HKDF-SHA256's output range");
    Some(key)
}

/// Current rotating epoch for pairwise rendezvous capabilities.
pub fn pairwise_capability_epoch(unix_seconds: i64) -> i64 {
    unix_seconds.div_euclid(PAIRWISE_CAPABILITY_EPOCH_SECS)
}

/// Derive a purpose- and epoch-bound pairwise capability from static X25519
/// DH. Only the two holders of the corresponding Ed25519 private keys can
/// compute it; knowing either stable Ember/Friend ID is insufficient.
pub fn derive_pairwise_capability(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    purpose: &[u8],
    epoch: i64,
) -> Option<[u8; 32]> {
    if purpose.is_empty() || purpose.len() > 64 {
        return None;
    }
    let their_x25519_pub = ed25519_pubkey_to_x25519(peer_ed25519_pubkey)?;
    let signing = SigningKey::from_bytes(our_ed25519_seed);
    let our_ed25519_pubkey = signing.verifying_key().to_bytes();
    let mut our_scalar = ed25519_seed_to_x25519_scalar(our_ed25519_seed);
    let our_secret = X25519StaticSecret::from(our_scalar);
    our_scalar.zeroize();
    let shared = our_secret.diffie_hellman(&their_x25519_pub);
    if !shared.was_contributory() {
        return None;
    }
    let (first, second) = if our_ed25519_pubkey <= *peer_ed25519_pubkey {
        (&our_ed25519_pubkey, peer_ed25519_pubkey)
    } else {
        (peer_ed25519_pubkey, &our_ed25519_pubkey)
    };
    let mut info = Vec::with_capacity(
        PAIRWISE_KEY_INFO.len() + 8 + 2 + purpose.len() + first.len() + second.len(),
    );
    info.extend_from_slice(PAIRWISE_KEY_INFO);
    info.extend_from_slice(&epoch.to_le_bytes());
    info.extend_from_slice(&(purpose.len() as u16).to_le_bytes());
    info.extend_from_slice(purpose);
    info.extend_from_slice(first);
    info.extend_from_slice(second);
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut capability = [0u8; 32];
    hk.expand(&info, &mut capability).ok()?;
    Some(capability)
}

/// Directional presence capability for `owner_ed25519_pubkey`. A friend pair
/// shares the DH secret, but each member registers a different owner-bound
/// capability, preventing the rendezvous server's key/value entry for one
/// peer from overwriting the other's presence.
pub fn derive_pairwise_presence_capability(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    owner_ed25519_pubkey: &[u8; 32],
    epoch: i64,
) -> Option<[u8; 32]> {
    let mut purpose = Vec::with_capacity(b"presence-owner-v1\0".len() + 32);
    purpose.extend_from_slice(b"presence-owner-v1\0");
    purpose.extend_from_slice(owner_ed25519_pubkey);
    derive_pairwise_capability(our_ed25519_seed, peer_ed25519_pubkey, &purpose, epoch)
}

/// Encrypt a friend-chat plaintext with a fresh random nonce.
///
/// Wire layout: `version(1) || nonce(24) || ciphertext‖tag`.
pub fn encrypt_chat_message(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce_bytes = [0u8; CHAT_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    // A 32-byte key and a 24-byte random nonce make encryption failure
    // impossible for XChaCha20-Poly1305 at chat-message sizes (there's no
    // realistic way to hit its ~256 GiB per-nonce plaintext limit here).
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .expect("XChaCha20-Poly1305 encryption cannot fail for chat-sized plaintext");
    let mut out = Vec::with_capacity(1 + CHAT_NONCE_LEN + ciphertext.len());
    out.push(CHAT_ENVELOPE_VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Decrypt a friend-chat envelope produced by [`encrypt_chat_message`].
///
/// Returns `None` on any malformed input, unrecognised version byte, or
/// AEAD authentication failure. Callers must treat `None` as "could not
/// decrypt" and must never fall back to displaying the raw envelope bytes
/// as if they were plaintext — the only safe legacy fallback is to
/// re-attempt parsing the *original, un-decrypted* wire payload as
/// plain UTF-8 (for interop with a peer that hasn't upgraded yet).
pub fn decrypt_chat_message(key: &[u8; 32], envelope: &[u8]) -> Option<Vec<u8>> {
    if envelope.len() < CHAT_ENVELOPE_OVERHEAD || envelope[0] != CHAT_ENVELOPE_VERSION {
        return None;
    }
    let nonce = XNonce::from_slice(&envelope[1..1 + CHAT_NONCE_LEN]);
    let ciphertext = &envelope[1 + CHAT_NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Convenience wrapper: derive the shared key for `peer_ed25519_pubkey`
/// and encrypt `plaintext` in one call. Returns `None` only if key
/// derivation fails (see [`derive_chat_key`]) — this should not happen in
/// practice for any peer that has already passed `perform_ember_auth`,
/// since that requires the same pubkey to be a valid, non-degenerate
/// curve point.
pub fn encrypt_chat_for_peer(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let key = derive_chat_key(our_ed25519_seed, peer_ed25519_pubkey)?;
    Some(encrypt_chat_message(&key, plaintext))
}

/// Convenience wrapper: derive the shared key for `peer_ed25519_pubkey`
/// and decrypt `envelope` in one call.
pub fn decrypt_chat_from_peer(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    envelope: &[u8],
) -> Option<Vec<u8>> {
    let key = derive_chat_key(our_ed25519_seed, peer_ed25519_pubkey)?;
    decrypt_chat_message(&key, envelope)
}

/// Maximum on-wire size for an `OP_EMBER_CHAT_MSG` payload: the plaintext
/// UTF-8 size cap enforced client-side (see
/// `commands::peers::send_chat_message`'s 4096-byte limit) plus the fixed
/// AEAD envelope overhead `encrypt_chat_message` adds. Every
/// `OP_EMBER_CHAT_MSG` receive site must check incoming payloads against
/// this constant rather than the plaintext-only 4096 the wire format used
/// pre-encryption, or legitimate encrypted messages at the plaintext cap
/// get silently dropped as "too large".
pub const MAX_CHAT_WIRE_LEN: usize = 4096 + CHAT_ENVELOPE_OVERHEAD;

/// Decode an inbound `OP_EMBER_CHAT_MSG` payload for display.
///
/// Returns `None` if the payload fails to decrypt or the plaintext isn't
/// valid UTF-8 — callers must drop the packet in that case, not display
/// anything.
///
/// Deliberately has **no legacy-plaintext fallback**. An earlier version
/// of this function fell back to treating any payload that failed to
/// decrypt as legacy plain UTF-8 text, reasoning that AEAD authentication
/// makes a *legitimate* legacy message and *ciphertext* unambiguous. That
/// reasoning covered the accidental-collision case but missed the actual
/// threat: `perform_ember_auth`'s proof-of-possession authenticates a
/// peer once, at session setup, not per-packet, so anyone on-path for the
/// remainder of an already-established session — a compromised
/// rendezvous/relay hop (see `broker.rs`), or a TCP/Wi-Fi MITM on a
/// direct connection — can inject an arbitrary `OP_EMBER_CHAT_MSG` packet
/// of their own choosing. Since both sides of this protocol always
/// encrypt (there is no plaintext-send path — see `encrypt_chat_for_peer`
/// and its call sites), any payload that fails to decrypt here is never
/// legitimate, and a fallback would let that attacker's arbitrary
/// ASCII/UTF-8 bytes be silently displayed as a genuine message from the
/// PoP-verified friend. Dropping instead closes that hole; the cost is
/// that a friend still running a pre-encryption build simply can't
/// exchange chat with an upgraded one until they update too.
pub fn decrypt_chat_payload(
    our_ed25519_seed: &[u8; 32],
    peer_ed25519_pubkey: &[u8; 32],
    payload: &[u8],
) -> Option<String> {
    let plaintext = decrypt_chat_from_peer(our_ed25519_seed, peer_ed25519_pubkey, payload)?;
    String::from_utf8(plaintext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn node_id_deterministic() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let id1 = node_id_from_public_key(&pk);
        let id2 = node_id_from_public_key(&pk);
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_keys_different_ids() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let id1 = node_id_from_public_key(&sk1.verifying_key());
        let id2 = node_id_from_public_key(&sk2.verifying_key());
        assert_ne!(id1, id2);
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let msg = b"hello ember network";
        let sig = sign(&sk, msg);
        assert!(verify(&pk, msg, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let sig = sign(&sk, b"original message");
        assert!(!verify(&pk, b"tampered message", &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let msg = b"test message";
        let sig = sign(&sk1, msg);
        assert!(!verify(&sk2.verifying_key(), msg, &sig));
    }

    #[test]
    fn binding_matches_deterministic_derivation() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        let pk_bytes = pk.to_bytes();
        let hash = node_id_from_public_key(&pk);
        assert!(verify_ember_hash_binding(&pk_bytes, &hash));
    }

    #[test]
    fn binding_rejects_wrong_hash() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_bytes = sk.verifying_key().to_bytes();
        let bogus_hash = [0xABu8; 16];
        assert!(!verify_ember_hash_binding(&pk_bytes, &bogus_hash));
    }

    #[test]
    fn binding_rejects_mismatched_key() {
        let sk1 = SigningKey::generate(&mut OsRng);
        let sk2 = SigningKey::generate(&mut OsRng);
        let hash1 = node_id_from_public_key(&sk1.verifying_key());
        let pk2_bytes = sk2.verifying_key().to_bytes();
        // Same 128-bit space; chance of collision between two freshly
        // generated keys is negligible — this asserts the function
        // correctly separates distinct identities rather than falling
        // into a silent accept.
        assert!(!verify_ember_hash_binding(&pk2_bytes, &hash1));
    }

    #[test]
    fn binding_rejects_invalid_pubkey_bytes() {
        // A 32-byte buffer that's not a valid Ed25519 point encoding —
        // `from_bytes` must reject it, and we must refuse to bind.
        let bad_key = [0xFFu8; 32];
        let some_hash = [0x00u8; 16];
        assert!(!verify_ember_hash_binding(&bad_key, &some_hash));
    }

    #[test]
    fn key_serialization_round_trip() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();

        let sk_bytes = sk.to_bytes();
        let pk_bytes = pk.to_bytes();

        let sk2 = signing_key_from_bytes(&sk_bytes);
        let pk2 = verifying_key_from_bytes(&pk_bytes).unwrap();

        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn blake3_file_hash_deterministic() {
        let data = b"some file content for hashing";
        let h1 = blake3_hash_file(data);
        let h2 = blake3_hash_file(data);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn blake3_incremental_matches_oneshot() {
        let data = b"chunk one chunk two chunk three";
        let oneshot = blake3_hash_file(data);

        let mut hasher = Blake3FileHasher::new();
        hasher.update(b"chunk one ");
        hasher.update(b"chunk two ");
        hasher.update(b"chunk three");
        let incremental = hasher.finalize();

        assert_eq!(oneshot, incremental);
    }

    fn gen_seed() -> [u8; 32] {
        SigningKey::generate(&mut OsRng).to_bytes()
    }

    #[test]
    fn chat_key_derivation_is_symmetric() {
        let alice_seed = gen_seed();
        let bob_seed = gen_seed();
        let alice_pub = signing_key_from_bytes(&alice_seed)
            .verifying_key()
            .to_bytes();
        let bob_pub = signing_key_from_bytes(&bob_seed).verifying_key().to_bytes();

        let alice_key = derive_chat_key(&alice_seed, &bob_pub).expect("valid peer key");
        let bob_key = derive_chat_key(&bob_seed, &alice_pub).expect("valid peer key");
        assert_eq!(
            alice_key, bob_key,
            "both sides must derive the same shared chat key"
        );
    }

    #[test]
    fn chat_key_derivation_differs_per_peer_pair() {
        let alice_seed = gen_seed();
        let bob_pub = signing_key_from_bytes(&gen_seed())
            .verifying_key()
            .to_bytes();
        let carol_pub = signing_key_from_bytes(&gen_seed())
            .verifying_key()
            .to_bytes();

        let key_with_bob = derive_chat_key(&alice_seed, &bob_pub).unwrap();
        let key_with_carol = derive_chat_key(&alice_seed, &carol_pub).unwrap();
        assert_ne!(key_with_bob, key_with_carol);
    }

    #[test]
    fn pairwise_capabilities_are_symmetric_and_rotate() {
        let alice_seed = gen_seed();
        let bob_seed = gen_seed();
        let alice_pub = signing_key_from_bytes(&alice_seed)
            .verifying_key()
            .to_bytes();
        let bob_pub = signing_key_from_bytes(&bob_seed).verifying_key().to_bytes();
        let epoch = 42;
        let alice = derive_pairwise_capability(&alice_seed, &bob_pub, b"presence", epoch).unwrap();
        let bob = derive_pairwise_capability(&bob_seed, &alice_pub, b"presence", epoch).unwrap();
        assert_eq!(alice, bob);
        assert_ne!(
            alice,
            derive_pairwise_capability(&alice_seed, &bob_pub, b"presence", epoch + 1).unwrap()
        );
    }

    #[test]
    fn pairwise_capabilities_differ_per_friend_and_purpose() {
        let alice_seed = gen_seed();
        let bob_pub = signing_key_from_bytes(&gen_seed())
            .verifying_key()
            .to_bytes();
        let carol_pub = signing_key_from_bytes(&gen_seed())
            .verifying_key()
            .to_bytes();
        let bob = derive_pairwise_presence_capability(&alice_seed, &bob_pub, &bob_pub, 9).unwrap();
        let carol =
            derive_pairwise_presence_capability(&alice_seed, &carol_pub, &carol_pub, 9).unwrap();
        let mailbox = derive_pairwise_capability(&alice_seed, &bob_pub, b"mailbox", 9).unwrap();
        assert_ne!(bob, carol);
        assert_ne!(bob, mailbox);
    }

    #[test]
    fn pairwise_presence_is_directional_per_owner() {
        let alice_seed = gen_seed();
        let bob_seed = gen_seed();
        let alice_pub = signing_key_from_bytes(&alice_seed)
            .verifying_key()
            .to_bytes();
        let bob_pub = signing_key_from_bytes(&bob_seed).verifying_key().to_bytes();
        let alice_presence =
            derive_pairwise_presence_capability(&alice_seed, &bob_pub, &alice_pub, 12).unwrap();
        let bob_lookup_alice =
            derive_pairwise_presence_capability(&bob_seed, &alice_pub, &alice_pub, 12).unwrap();
        let bob_presence =
            derive_pairwise_presence_capability(&bob_seed, &alice_pub, &bob_pub, 12).unwrap();
        assert_eq!(alice_presence, bob_lookup_alice);
        assert_ne!(alice_presence, bob_presence);
    }

    #[test]
    fn chat_key_derivation_rejects_invalid_peer_pubkey() {
        let our_seed = gen_seed();
        // y=2 (sign bit clear) does not correspond to any point on the
        // Edwards curve — confirmed by brute-force scan, since not every
        // byte pattern with the high bit clear is actually rejected by
        // decompression (e.g. all-0xFF bytes *does* decode, just to a
        // non-canonically-encoded but otherwise valid point).
        let mut bad_pubkey = [0u8; 32];
        bad_pubkey[0] = 2;
        assert!(derive_chat_key(&our_seed, &bad_pubkey).is_none());
    }

    #[test]
    fn chat_message_round_trip() {
        let key = [0x42u8; 32];
        let plaintext = b"hey, want to grab lunch later?";
        let envelope = encrypt_chat_message(&key, plaintext);
        let decrypted = decrypt_chat_message(&key, &envelope).expect("must decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn chat_message_envelope_has_expected_overhead() {
        let key = [0x11u8; 32];
        let plaintext = b"short";
        let envelope = encrypt_chat_message(&key, plaintext);
        assert_eq!(envelope.len(), plaintext.len() + CHAT_ENVELOPE_OVERHEAD);
        assert_eq!(envelope[0], CHAT_ENVELOPE_VERSION);
    }

    #[test]
    fn chat_message_nonces_are_not_reused() {
        let key = [0x77u8; 32];
        let a = encrypt_chat_message(&key, b"same message");
        let b = encrypt_chat_message(&key, b"same message");
        assert_ne!(
            a, b,
            "two encryptions of the same plaintext must differ (random nonce)"
        );
    }

    #[test]
    fn chat_message_decrypt_rejects_wrong_key() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let envelope = encrypt_chat_message(&key_a, b"secret");
        assert!(decrypt_chat_message(&key_b, &envelope).is_none());
    }

    #[test]
    fn chat_message_decrypt_rejects_tampered_ciphertext() {
        let key = [0x03u8; 32];
        let mut envelope = encrypt_chat_message(&key, b"do not tamper with me");
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;
        assert!(decrypt_chat_message(&key, &envelope).is_none());
    }

    #[test]
    fn chat_message_decrypt_rejects_truncated_envelope() {
        let key = [0x04u8; 32];
        let envelope = encrypt_chat_message(&key, b"hello");
        assert!(decrypt_chat_message(&key, &envelope[..envelope.len() - 1]).is_none());
        assert!(decrypt_chat_message(&key, &[]).is_none());
    }

    #[test]
    fn chat_message_decrypt_rejects_unknown_version() {
        let key = [0x05u8; 32];
        let mut envelope = encrypt_chat_message(&key, b"hello");
        envelope[0] = 0x02;
        assert!(decrypt_chat_message(&key, &envelope).is_none());
    }

    #[test]
    fn chat_message_decrypt_rejects_legacy_plaintext_payload() {
        // A pre-upgrade peer's raw UTF-8 chat payload must never be
        // misinterpreted as a valid encrypted envelope.
        let key = [0x06u8; 32];
        let legacy_payload = b"hello from an old client";
        assert!(decrypt_chat_message(&key, legacy_payload).is_none());
    }

    #[test]
    fn decrypt_chat_payload_decrypts_valid_envelope() {
        let alice_seed = gen_seed();
        let bob_seed = gen_seed();
        let alice_pub = signing_key_from_bytes(&alice_seed)
            .verifying_key()
            .to_bytes();
        let bob_pub = signing_key_from_bytes(&bob_seed).verifying_key().to_bytes();

        let envelope = encrypt_chat_for_peer(&alice_seed, &bob_pub, b"encrypted hello").unwrap();
        let decoded = decrypt_chat_payload(&bob_seed, &alice_pub, &envelope).unwrap();
        assert_eq!(decoded, "encrypted hello");
    }

    #[test]
    fn decrypt_chat_payload_has_no_legacy_plaintext_fallback() {
        // Regression test for the integrity gap a security review caught:
        // a bare/attacker-forged UTF-8 payload with no valid envelope
        // must be dropped (`None`), never displayed as if it were a
        // genuine message from the PoP-verified peer. PoP only
        // authenticates the peer once at session setup, not per packet,
        // so an on-path attacker (malicious relay hop, TCP MITM) can
        // inject arbitrary bytes into an already-established session at
        // any time — accepting a plaintext fallback here would let them
        // forge chat messages.
        let our_seed = gen_seed();
        let peer_pub = signing_key_from_bytes(&gen_seed())
            .verifying_key()
            .to_bytes();
        let forged = b"pretend this is from the real friend";
        assert!(decrypt_chat_payload(&our_seed, &peer_pub, forged).is_none());
    }

    #[test]
    fn decrypt_chat_payload_rejects_wrong_recipient() {
        let alice_seed = gen_seed();
        let bob_seed = gen_seed();
        let mallory_seed = gen_seed();
        let alice_pub = signing_key_from_bytes(&alice_seed)
            .verifying_key()
            .to_bytes();
        let mallory_pub = signing_key_from_bytes(&mallory_seed)
            .verifying_key()
            .to_bytes();

        // Encrypted for Mallory, not Bob: Bob must not be able to decrypt
        // it, and it must be dropped outright (no plaintext fallback).
        let envelope =
            encrypt_chat_for_peer(&alice_seed, &mallory_pub, b"for mallory only").unwrap();
        assert!(decrypt_chat_payload(&bob_seed, &alice_pub, &envelope).is_none());
    }

    #[test]
    fn encrypt_decrypt_for_peer_round_trip() {
        let alice_seed = gen_seed();
        let bob_seed = gen_seed();
        let alice_pub = signing_key_from_bytes(&alice_seed)
            .verifying_key()
            .to_bytes();
        let bob_pub = signing_key_from_bytes(&bob_seed).verifying_key().to_bytes();

        let envelope = encrypt_chat_for_peer(&alice_seed, &bob_pub, b"ping").unwrap();
        let decrypted = decrypt_chat_from_peer(&bob_seed, &alice_pub, &envelope).unwrap();
        assert_eq!(decrypted, b"ping");
    }
}
