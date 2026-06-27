use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

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
/// This is the "Ember file hash" used for file identification on the Ember
/// network (alongside the legacy ed2k MD4 hash for KAD/ED2K interop).
#[allow(dead_code)]
pub fn blake3_hash_file(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Incremental BLAKE3 hasher for large files that cannot be loaded into memory.
#[allow(dead_code)]
pub struct Blake3FileHasher {
    hasher: blake3::Hasher,
}

#[allow(dead_code)]
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
}
