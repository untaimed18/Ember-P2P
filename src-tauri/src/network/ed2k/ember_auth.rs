//! Reactive Ember Ed25519 auth state machine for the upload-side TCP
//! read loop.
//!
//! ## Why a state machine and not just a function call?
//!
//! The download side (`multi_source.rs`) and the friend-connect dial
//! path (`friend_connect.rs`) both *initiate* Ember auth — they own
//! their reader directly and can drive a synchronous four-message
//! round-trip via `friend_connect::perform_ember_auth`. The upload
//! side cannot: its reader is moved into a dedicated `reader_task`
//! that pushes whole packets through an mpsc channel to the
//! dispatcher. A blocking `perform_ember_auth` call from inside the
//! dispatcher would have nothing to read from. So instead we model
//! the responder side of the same protocol as a small event-driven
//! state machine and let the dispatcher feed it `(opcode, payload)`
//! events.
//!
//! ## Wire protocol (mirror of `friend_connect::perform_ember_auth`)
//!
//! Initiator (download side):
//!   1. Send `OP_EMBER_AUTH_CHALLENGE` carrying `our_nonce_init`.
//!   2. Read peer's `OP_EMBER_AUTH_CHALLENGE` carrying `our_nonce_resp`.
//!   3. Send `OP_EMBER_AUTH_RESPONSE` carrying `our_pubkey || sig_init(our_nonce_resp)`.
//!   4. Read peer's `OP_EMBER_AUTH_RESPONSE` carrying `peer_pubkey || sig_resp(our_nonce_init)`,
//!      verify the binding `BLAKE3(peer_pubkey)[..16] == peer_ember_hash`,
//!      and verify the signature.
//!
//! Responder (upload side, this module):
//!   1. Receive initiator's CHALLENGE, save their nonce, generate ours.
//!   2. Send our CHALLENGE (our nonce) and immediately our RESPONSE
//!      (our pubkey || sig over their nonce). The dispatcher writes
//!      both packets in order; TCP guarantees the initiator reads
//!      CHALLENGE first then RESPONSE.
//!   3. Receive initiator's RESPONSE, verify pubkey matches what they
//!      advertised in `OP_EMBER_HELLO`, verify the binding, verify
//!      the signature over our nonce.
//!
//! ## Re-entry / replay rules
//!
//! - A second CHALLENGE in any state other than `NotStarted` is
//!   rejected (`UnexpectedPacket`). This stops a peer from rolling
//!   their nonce mid-session to evade verification.
//! - A RESPONSE in any state other than `PeerChallenged` is rejected.
//! - Once `Verified` or `Failed`, the state machine stays terminal —
//!   subsequent auth packets log and drop.
//! - Bad signature, pubkey mismatch (advertised vs. signed), and
//!   binding mismatch all transition to `Failed`. The dispatcher
//!   should treat the session as un-verified from that point on.
//!
//! ## What this module deliberately does NOT do
//!
//! - It doesn't read or write TCP. The dispatcher is responsible for
//!   delivering events and emitting the returned `AuthOutbound` packets.
//! - It doesn't generate the *initiator* side of the exchange — that
//!   stays in `friend_connect::perform_ember_auth`.
//! - It doesn't gate any access-control decisions on its own. Callers
//!   should check `state.is_verified()` at the appropriate gate
//!   (e.g. friend-slot priority, EmberFriendRequest emit).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::warn;

use crate::network::ember::crypto;

/// Length of an `OP_EMBER_AUTH_CHALLENGE` payload (raw nonce).
pub const NONCE_LEN: usize = 32;

/// Length of an `OP_EMBER_AUTH_RESPONSE` payload (`pubkey || signature`).
pub const RESPONSE_LEN: usize = 32 + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmberAuthState {
    /// No CHALLENGE seen yet on this session. May transition to
    /// `PeerChallenged` when the initiator sends one, or stay here
    /// indefinitely (vanilla peer / older Ember release).
    NotStarted,
    /// We received the peer's CHALLENGE, generated our nonce, and the
    /// dispatcher has been told to emit both our CHALLENGE and our
    /// RESPONSE. We're now waiting for their RESPONSE so we can
    /// verify proof of possession.
    PeerChallenged { our_nonce: [u8; NONCE_LEN] },
    /// Peer's RESPONSE verified successfully. Identity is bound
    /// (`BLAKE3(pk)[..16] == ember_hash`) AND the peer signed our
    /// nonce. Use as the canonical "PoP-verified" signal.
    Verified,
    /// Peer failed verification — bad signature, advertised vs.
    /// response pubkey mismatch, binding mismatch, or unexpected
    /// packet ordering. Stays terminal for the rest of the session.
    Failed,
}

impl Default for EmberAuthState {
    fn default() -> Self {
        EmberAuthState::NotStarted
    }
}

impl EmberAuthState {
    pub fn is_verified(&self) -> bool {
        matches!(self, EmberAuthState::Verified)
    }

    #[allow(dead_code)]
    pub fn is_terminal(&self) -> bool {
        matches!(self, EmberAuthState::Verified | EmberAuthState::Failed)
    }
}

/// Outbound packets the dispatcher should write back to the peer in
/// response to an inbound auth packet. Packets are listed in send
/// order (CHALLENGE first, then RESPONSE) — the caller writes them
/// in that order so the initiator's read sequence completes correctly.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct AuthOutbound {
    pub our_challenge_payload: Option<[u8; NONCE_LEN]>,
    pub our_response_payload: Option<[u8; RESPONSE_LEN]>,
}

/// Reasons the state machine rejects a packet without sending a
/// reply. Surfaced for logging / metrics; the dispatcher does not
/// need to act on the variant beyond bumping a counter.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    /// Payload length didn't match the protocol fixed length.
    InvalidPayloadLength,
    /// Packet arrived in a state where it isn't expected (e.g. a
    /// second CHALLENGE in `Verified`, a RESPONSE in `NotStarted`).
    UnexpectedPacket,
    /// We don't have the peer's pubkey from `OP_EMBER_HELLO` yet, so
    /// we can't verify a RESPONSE. Should be rare in practice because
    /// the initiator sends `OP_EMBER_HELLO` before CHALLENGE and
    /// CHALLENGE before RESPONSE; TCP preserves the order.
    PeerPubkeyUnknown,
    /// `BLAKE3(advertised_pubkey)[..16] != advertised_ember_hash`.
    /// Either side is lying about their identity binding.
    BindingMismatch,
    /// The pubkey embedded in the RESPONSE doesn't match the one the
    /// peer advertised in `OP_EMBER_HELLO`. Stops a peer from rolling
    /// keys mid-handshake.
    PubkeyMismatch,
    /// Pubkey bytes don't decode to a valid Ed25519 point.
    InvalidPubkeyEncoding,
    /// Ed25519 signature verification failed against the peer's
    /// pubkey + our challenge nonce.
    BadSignature,
}

/// Processes an `OP_EMBER_AUTH_CHALLENGE` payload. On success
/// transitions to `PeerChallenged` and returns the packets the
/// dispatcher should send back (CHALLENGE + RESPONSE). On any error
/// the state is left unchanged (so the dispatcher can choose to drop
/// the connection or just log).
pub fn handle_challenge(
    state: &mut EmberAuthState,
    payload: &[u8],
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
) -> Result<AuthOutbound, AuthError> {
    if payload.len() != NONCE_LEN {
        // Log at warn so malformed auth packets are visible in the
        // default log stream without having to flip to debug — this
        // is also what anomaly detection / rate-limit heuristics at
        // higher layers want to count.
        warn!(
            "Ember auth: dropping CHALLENGE with wrong nonce length ({} bytes, expected {})",
            payload.len(),
            NONCE_LEN
        );
        return Err(AuthError::InvalidPayloadLength);
    }
    if !matches!(state, EmberAuthState::NotStarted) {
        // A second CHALLENGE after we already processed one (or after
        // we've reached Verified/Failed) is either a buggy peer or a
        // deliberate replay — either way it's anomalous and the
        // dispatcher may want to bump a counter. Surface it at warn
        // so "CHALLENGE replay observed" is greppable without
        // custom instrumentation.
        warn!(
            "Ember auth: rejecting CHALLENGE in unexpected state {state:?} (possible replay)"
        );
        return Err(AuthError::UnexpectedPacket);
    }

    let mut their_nonce = [0u8; NONCE_LEN];
    their_nonce.copy_from_slice(payload);

    // OsRng (system CSPRNG) for protocol nonces — `thread_rng` is
    // typically OK in practice but `OsRng` makes the cryptographic
    // sourcing explicit, removes any reliance on the thread-local
    // seeding chain, and matches the rest of the Ember crypto code
    // (`SigningKey::generate(&mut OsRng)` in tests).
    let mut our_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut our_nonce);

    let signing_key = SigningKey::from_bytes(our_secret_key);
    let signature = signing_key.sign(&their_nonce);

    let mut response = [0u8; RESPONSE_LEN];
    response[..32].copy_from_slice(our_pubkey);
    response[32..].copy_from_slice(&signature.to_bytes());

    *state = EmberAuthState::PeerChallenged { our_nonce };

    Ok(AuthOutbound {
        our_challenge_payload: Some(our_nonce),
        our_response_payload: Some(response),
    })
}

/// Processes an `OP_EMBER_AUTH_RESPONSE` payload. Requires the peer
/// to have already advertised their pubkey via `OP_EMBER_HELLO`
/// (passed as `expected_peer_pubkey`) and their `ember_hash` (passed
/// as `expected_ember_hash`).
///
/// On success, state transitions to `Verified`. On any error, state
/// transitions to `Failed` (terminal) so subsequent auth packets are
/// rejected even if they would otherwise have valid format.
pub fn handle_response(
    state: &mut EmberAuthState,
    payload: &[u8],
    expected_peer_pubkey: &[u8; 32],
    expected_ember_hash: &[u8; 16],
) -> Result<(), AuthError> {
    if payload.len() != RESPONSE_LEN {
        warn!(
            "Ember auth: dropping RESPONSE with wrong payload length ({} bytes, expected {})",
            payload.len(),
            RESPONSE_LEN
        );
        return Err(AuthError::InvalidPayloadLength);
    }

    let our_nonce = match state {
        EmberAuthState::PeerChallenged { our_nonce } => *our_nonce,
        _ => {
            // RESPONSE in NotStarted means the peer skipped the
            // CHALLENGE; in Verified/Failed it's a replay or a buggy
            // peer. Same forensics rationale as the CHALLENGE path
            // above — log at warn so the anomaly is visible.
            warn!(
                "Ember auth: rejecting RESPONSE in unexpected state {state:?}"
            );
            return Err(AuthError::UnexpectedPacket);
        }
    };

    // Slice arithmetic is bounds-checked above. Unwrap is fine.
    let resp_pubkey: [u8; 32] = payload[..32].try_into().unwrap();
    let sig_bytes: [u8; 64] = payload[32..].try_into().unwrap();

    if &resp_pubkey != expected_peer_pubkey {
        *state = EmberAuthState::Failed;
        return Err(AuthError::PubkeyMismatch);
    }

    let peer_vk = match VerifyingKey::from_bytes(&resp_pubkey) {
        Ok(vk) => vk,
        Err(_) => {
            *state = EmberAuthState::Failed;
            return Err(AuthError::InvalidPubkeyEncoding);
        }
    };

    if !crypto::verify_ember_hash_binding(&resp_pubkey, expected_ember_hash) {
        *state = EmberAuthState::Failed;
        return Err(AuthError::BindingMismatch);
    }

    let peer_sig = Signature::from_bytes(&sig_bytes);
    if peer_vk.verify(&our_nonce, &peer_sig).is_err() {
        *state = EmberAuthState::Failed;
        return Err(AuthError::BadSignature);
    }

    *state = EmberAuthState::Verified;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn keypair() -> ([u8; 32], [u8; 32], [u8; 16]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_bytes = sk.verifying_key().to_bytes();
        let sk_bytes = sk.to_bytes();
        let hash = crate::network::ember::crypto::node_id_from_public_key(&sk.verifying_key());
        (pk_bytes, sk_bytes, hash)
    }

    #[test]
    fn happy_path_full_mutual_auth() {
        // Two simulated peers: "responder" (this module) and
        // "initiator" (mirrors `friend_connect::perform_ember_auth`
        // by-hand so we can drive both halves in one test).
        let (resp_pk, resp_sk, resp_hash) = keypair();
        let (init_pk, init_sk, init_hash) = keypair();

        // Initiator generates and sends CHALLENGE.
        let mut init_nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut init_nonce);

        // Responder receives initiator's CHALLENGE.
        let mut resp_state = EmberAuthState::default();
        let outbound = handle_challenge(&mut resp_state, &init_nonce, &resp_pk, &resp_sk)
            .expect("CHALLENGE should be accepted in NotStarted");

        // Responder must have emitted both packets.
        let resp_nonce = outbound.our_challenge_payload.expect("CHALLENGE");
        let resp_response = outbound.our_response_payload.expect("RESPONSE");
        assert!(matches!(resp_state, EmberAuthState::PeerChallenged { .. }));

        // Initiator-side: receives responder's CHALLENGE, signs it,
        // builds RESPONSE.
        let init_signing = SigningKey::from_bytes(&init_sk);
        let init_sig = init_signing.sign(&resp_nonce);
        let mut init_response = [0u8; RESPONSE_LEN];
        init_response[..32].copy_from_slice(&init_pk);
        init_response[32..].copy_from_slice(&init_sig.to_bytes());

        // Initiator-side: verifies responder's RESPONSE against init_nonce.
        let resp_response_pk: [u8; 32] = resp_response[..32].try_into().unwrap();
        let resp_response_sig_bytes: [u8; 64] = resp_response[32..].try_into().unwrap();
        let resp_response_sig = Signature::from_bytes(&resp_response_sig_bytes);
        let resp_vk = VerifyingKey::from_bytes(&resp_response_pk).unwrap();
        assert!(resp_vk.verify(&init_nonce, &resp_response_sig).is_ok());
        assert!(crate::network::ember::crypto::verify_ember_hash_binding(&resp_response_pk, &resp_hash));

        // Responder receives initiator's RESPONSE. Must transition to Verified.
        let result = handle_response(&mut resp_state, &init_response, &init_pk, &init_hash);
        assert_eq!(result, Ok(()));
        assert_eq!(resp_state, EmberAuthState::Verified);
    }

    #[test]
    fn challenge_with_wrong_nonce_length_is_rejected() {
        let (pk, sk, _) = keypair();
        let mut state = EmberAuthState::default();
        let bad_nonce = [0u8; 16]; // wrong length
        assert_eq!(
            handle_challenge(&mut state, &bad_nonce, &pk, &sk),
            Err(AuthError::InvalidPayloadLength)
        );
        // State should be unchanged on rejection.
        assert_eq!(state, EmberAuthState::NotStarted);
    }

    #[test]
    fn second_challenge_after_first_is_rejected() {
        let (pk, sk, _) = keypair();
        let mut state = EmberAuthState::default();
        let nonce1 = [0u8; NONCE_LEN];
        handle_challenge(&mut state, &nonce1, &pk, &sk).unwrap();
        assert!(matches!(state, EmberAuthState::PeerChallenged { .. }));
        let nonce2 = [1u8; NONCE_LEN];
        assert_eq!(
            handle_challenge(&mut state, &nonce2, &pk, &sk),
            Err(AuthError::UnexpectedPacket)
        );
    }

    #[test]
    fn response_in_not_started_is_rejected() {
        let (init_pk, _init_sk, init_hash) = keypair();
        let mut state = EmberAuthState::default();
        let payload = [0u8; RESPONSE_LEN];
        assert_eq!(
            handle_response(&mut state, &payload, &init_pk, &init_hash),
            Err(AuthError::UnexpectedPacket)
        );
        // State should NOT transition to Failed for ordering errors
        // (so it can still legitimately accept a CHALLENGE later).
        assert_eq!(state, EmberAuthState::NotStarted);
    }

    #[test]
    fn response_with_wrong_pubkey_is_rejected_and_terminal() {
        let (resp_pk, resp_sk, _) = keypair();
        let (init_pk, init_sk, init_hash) = keypair();
        let mut state = EmberAuthState::default();
        let init_nonce = [9u8; NONCE_LEN];
        let outbound = handle_challenge(&mut state, &init_nonce, &resp_pk, &resp_sk).unwrap();
        let resp_nonce = outbound.our_challenge_payload.unwrap();

        // Build an init RESPONSE but with a DIFFERENT pubkey than
        // what's "advertised" (we'll pass `expected_peer_pubkey =
        // init_pk` but embed a bogus one in the response).
        let init_signing = SigningKey::from_bytes(&init_sk);
        let init_sig = init_signing.sign(&resp_nonce);
        let mut bad_response = [0u8; RESPONSE_LEN];
        bad_response[..32].copy_from_slice(&[0xFFu8; 32]);
        bad_response[32..].copy_from_slice(&init_sig.to_bytes());

        let result = handle_response(&mut state, &bad_response, &init_pk, &init_hash);
        assert_eq!(result, Err(AuthError::PubkeyMismatch));
        assert_eq!(state, EmberAuthState::Failed);
    }

    #[test]
    fn response_with_bad_signature_is_rejected_and_terminal() {
        let (resp_pk, resp_sk, _) = keypair();
        let (init_pk, _init_sk, init_hash) = keypair();
        let mut state = EmberAuthState::default();
        let init_nonce = [9u8; NONCE_LEN];
        handle_challenge(&mut state, &init_nonce, &resp_pk, &resp_sk).unwrap();

        // Sign the WRONG nonce — produces a sig that won't verify
        // against our_nonce.
        let other_sk = SigningKey::generate(&mut OsRng);
        let bogus_sig = other_sk.sign(&[0u8; 32]).to_bytes();
        let mut bad_response = [0u8; RESPONSE_LEN];
        bad_response[..32].copy_from_slice(&init_pk);
        bad_response[32..].copy_from_slice(&bogus_sig);

        let result = handle_response(&mut state, &bad_response, &init_pk, &init_hash);
        assert_eq!(result, Err(AuthError::BadSignature));
        assert_eq!(state, EmberAuthState::Failed);
    }

    #[test]
    fn response_with_binding_mismatch_is_rejected_and_terminal() {
        let (resp_pk, resp_sk, _) = keypair();
        let (init_pk, init_sk, _init_real_hash) = keypair();
        let attacker_hash = [0xABu8; 16]; // attacker claims this hash
        let mut state = EmberAuthState::default();
        let init_nonce = [9u8; NONCE_LEN];
        let outbound = handle_challenge(&mut state, &init_nonce, &resp_pk, &resp_sk).unwrap();
        let resp_nonce = outbound.our_challenge_payload.unwrap();

        // Real signature, real pubkey — but pubkey doesn't BLAKE3-bind
        // to the claimed ember_hash. Should reject.
        let init_signing = SigningKey::from_bytes(&init_sk);
        let init_sig = init_signing.sign(&resp_nonce);
        let mut response = [0u8; RESPONSE_LEN];
        response[..32].copy_from_slice(&init_pk);
        response[32..].copy_from_slice(&init_sig.to_bytes());

        let result = handle_response(&mut state, &response, &init_pk, &attacker_hash);
        assert_eq!(result, Err(AuthError::BindingMismatch));
        assert_eq!(state, EmberAuthState::Failed);
    }

    #[test]
    fn response_after_verified_is_rejected() {
        // Drive a happy path to Verified, then try to RESPONSE again.
        let (resp_pk, resp_sk, _) = keypair();
        let (init_pk, init_sk, init_hash) = keypair();
        let mut state = EmberAuthState::default();
        let init_nonce = [9u8; NONCE_LEN];
        let outbound = handle_challenge(&mut state, &init_nonce, &resp_pk, &resp_sk).unwrap();
        let resp_nonce = outbound.our_challenge_payload.unwrap();

        let init_signing = SigningKey::from_bytes(&init_sk);
        let init_sig = init_signing.sign(&resp_nonce);
        let mut response = [0u8; RESPONSE_LEN];
        response[..32].copy_from_slice(&init_pk);
        response[32..].copy_from_slice(&init_sig.to_bytes());

        handle_response(&mut state, &response, &init_pk, &init_hash).unwrap();
        assert_eq!(state, EmberAuthState::Verified);

        // Replay: a second RESPONSE should be rejected as unexpected,
        // and crucially must NOT downgrade us out of Verified.
        let result = handle_response(&mut state, &response, &init_pk, &init_hash);
        assert_eq!(result, Err(AuthError::UnexpectedPacket));
        assert_eq!(state, EmberAuthState::Verified);
    }

    #[test]
    fn malformed_pubkey_in_response_lands_in_failed_terminal_state() {
        let (resp_pk, resp_sk, _) = keypair();
        let mut state = EmberAuthState::default();
        let init_nonce = [9u8; NONCE_LEN];
        handle_challenge(&mut state, &init_nonce, &resp_pk, &resp_sk).unwrap();

        // Feed an all-0xFF pubkey as both "expected" and "embedded"
        // so the equality check passes, but the resulting
        // (advertised pubkey, expected hash) pair fails verification
        // somewhere downstream — either at `VerifyingKey::from_bytes`
        // (older ed25519-dalek), at `verify_ember_hash_binding`
        // (BLAKE3(0xFF…) won't equal a zero hash), or at the
        // signature check. The exact rejection variant depends on
        // the dalek version's strictness; what matters for the
        // session is that we land in `Failed` and never accidentally
        // reach `Verified`.
        let bad_pk = [0xFFu8; 32];
        let mut response = [0u8; RESPONSE_LEN];
        response[..32].copy_from_slice(&bad_pk);
        response[32..].fill(0x42);
        let any_hash = [0u8; 16];
        let result = handle_response(&mut state, &response, &bad_pk, &any_hash);
        assert!(result.is_err(), "expected rejection, got {:?}", result);
        assert!(matches!(
            result,
            Err(AuthError::InvalidPubkeyEncoding)
                | Err(AuthError::BindingMismatch)
                | Err(AuthError::BadSignature),
        ));
        assert_eq!(state, EmberAuthState::Failed);
    }

    #[test]
    fn response_wrong_length_is_rejected_without_state_transition() {
        let (resp_pk, resp_sk, _) = keypair();
        let (init_pk, _init_sk, init_hash) = keypair();
        let mut state = EmberAuthState::default();
        let init_nonce = [9u8; NONCE_LEN];
        handle_challenge(&mut state, &init_nonce, &resp_pk, &resp_sk).unwrap();

        let too_short = vec![0u8; RESPONSE_LEN - 1];
        let result = handle_response(&mut state, &too_short, &init_pk, &init_hash);
        assert_eq!(result, Err(AuthError::InvalidPayloadLength));
        // Wrong length is a malformed packet, NOT a verification
        // failure — we don't want to permanently kill the session
        // for one stray bad packet.
        assert!(matches!(state, EmberAuthState::PeerChallenged { .. }));
    }

    #[test]
    fn is_verified_only_in_verified_state() {
        assert!(!EmberAuthState::NotStarted.is_verified());
        assert!(!EmberAuthState::PeerChallenged { our_nonce: [0u8; NONCE_LEN] }.is_verified());
        assert!(!EmberAuthState::Failed.is_verified());
        assert!(EmberAuthState::Verified.is_verified());
    }
}
