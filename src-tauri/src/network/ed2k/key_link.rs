//! Proof, on one eD2K session, that an Ember key and an eD2K user hash's
//! SecIdent key belong to the same client.
//!
//! Ember-stream credit (`CreditManager::add_downloaded_over_ember`) needs to
//! know which eD2K user hash belongs to the holder of an Ember key. The proof
//! is one statement signed twice: "this Ember key and this SecIdent key
//! belong to this user hash, answering this challenger's nonce". The Ember
//! key signs it with Ed25519, and the SecIdent RSA key on record for the
//! user hash signs it with SecIdent's own primitive. Each key endorses the
//! other, so neither half can be borrowed: a replayed Ember public key has
//! no Ed25519 signature, and a SecIdent answer relayed from the real owner
//! of the user hash is no RSA signature over someone else's Ember key.
//! Verified, it makes the link (`CreditManager::note_session_proven_ember`).
//!
//! ## Wire
//!
//! Two [`super::messages::OP_EMBER_EXT`] sub-types on an eD2K session, sent
//! only once the peer's `OP_EMBER_HELLO` showed it is an Ember client:
//!
//! - [`super::messages::EMBER_EXT_KEY_LINK_CHALLENGE`]: `nonce(32)`, fresh
//!   from the OS RNG, at most one per session.
//! - [`super::messages::EMBER_EXT_KEY_LINK_PROOF`]: `ember_pubkey(32) ||
//!   ed25519_sig(64) || rsa_sig_len(1) || rsa_sig(rsa_sig_len)`, the answer.
//!   `rsa_sig_len` must be 48, the signature size of the RSA-384 keys eMule,
//!   aMule and Ember use for SecIdent; anything else is refused.
//!
//! The statement is the 151 bytes
//! `"ember-ed2k-key-link-v1\0" || nonce(32) || prover_user_hash(16) ||
//! challenger_user_hash(16) || prover_ember_pubkey(32) ||
//! BLAKE3(prover_secident_pubkey)(32)`, the SecIdent public key hashed
//! exactly as `OP_PUBLICKEY` carries it. The Ed25519 signature covers it as
//! is. The RSA signature (PKCS#1 v1.5 over SHA-1, as SecIdent signs) covers
//! it followed by zero bytes to [`KEY_LINK_RSA_INPUT_LEN`] (320): a SecIdent
//! signer of any Ember or eMule version signs only `peer_key || challenge`
//! with an optional 5-byte IP tail and a peer key of at most 255 bytes, 264
//! bytes in all, so no SecIdent answer can ever be, or be steered into
//! being, a key-link RSA signature.
//!
//! The prover always fills in its own user hash, its own Ember key, its own
//! SecIdent key and the user hash its session's peer sent in Hello. The
//! verifier checks the Ember key against the identity the peer's HELLO
//! advertised, and both signatures with its peer's user hash, its own, and
//! the SecIdent key on record for the peer's user hash, which must be one
//! SecIdent has proven, on this session or an earlier one. When the record
//! holds no proven key yet (first contact), the proof waits for SecIdent on
//! this session to prove one and is checked then.
//!
//! A peer that predates these sub-types ignores both, and a peer that never
//! answers simply never gets the link.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tracing::{debug, info};

use super::credits::CreditManager;
use super::messages::{
    build_ember_ext, parse_ember_ext, EMBER_EXT_KEY_LINK_CHALLENGE, EMBER_EXT_KEY_LINK_PROOF,
    OP_EMBER_EXT, OP_EMULEPROT,
};
use crate::network::ember::crypto;

/// Length of an [`super::messages::EMBER_EXT_KEY_LINK_CHALLENGE`] body.
pub const KEY_LINK_NONCE_LEN: usize = 32;

/// The only RSA signature length taken: RSA-384, SecIdent's key size.
pub const KEY_LINK_RSA_SIG_LEN: usize = 48;

/// `ember_pubkey(32) || ed25519_sig(64) || rsa_sig_len(1)`.
const KEY_LINK_PROOF_HEAD_LEN: usize = 32 + 64 + 1;

/// Length of an [`super::messages::EMBER_EXT_KEY_LINK_PROOF`] body.
pub const KEY_LINK_PROOF_LEN: usize = KEY_LINK_PROOF_HEAD_LEN + KEY_LINK_RSA_SIG_LEN;

/// Domain prefix of the signed statement. Nothing else is ever signed under
/// it, by either key.
pub const KEY_LINK_DOMAIN: &[u8] = b"ember-ed2k-key-link-v1\0";

/// Length of the signed statement.
pub const KEY_LINK_MESSAGE_LEN: usize = KEY_LINK_DOMAIN.len() + KEY_LINK_NONCE_LEN + 16 + 16 + 32 + 32;

/// Length of what the RSA signature covers: the statement, zero-padded past
/// the 264 bytes any SecIdent signer will sign.
pub const KEY_LINK_RSA_INPUT_LEN: usize = 320;

/// Challenges one session answers. A well-behaved peer sends one; the
/// second is slack for a peer that re-greets. More would make the session a
/// signing service.
pub const MAX_KEY_LINK_ANSWERS: u8 = 2;

/// BLAKE3 of a SecIdent public key as `OP_PUBLICKEY` carries it.
pub fn secident_key_digest(secident_key: &[u8]) -> [u8; 32] {
    *blake3::hash(secident_key).as_bytes()
}

/// The statement both signatures cover.
fn key_link_message(
    nonce: &[u8; KEY_LINK_NONCE_LEN],
    prover_user_hash: &[u8; 16],
    challenger_user_hash: &[u8; 16],
    prover_ember_pubkey: &[u8; 32],
    prover_secident_digest: &[u8; 32],
) -> [u8; KEY_LINK_MESSAGE_LEN] {
    let mut message = [0u8; KEY_LINK_MESSAGE_LEN];
    let mut at = 0;
    for field in [
        KEY_LINK_DOMAIN,
        nonce.as_slice(),
        prover_user_hash.as_slice(),
        challenger_user_hash.as_slice(),
        prover_ember_pubkey.as_slice(),
        prover_secident_digest.as_slice(),
    ] {
        message[at..at + field.len()].copy_from_slice(field);
        at += field.len();
    }
    message
}

/// What the RSA signature covers: `message` and zero bytes to
/// [`KEY_LINK_RSA_INPUT_LEN`].
fn key_link_rsa_input(message: &[u8; KEY_LINK_MESSAGE_LEN]) -> [u8; KEY_LINK_RSA_INPUT_LEN] {
    let mut input = [0u8; KEY_LINK_RSA_INPUT_LEN];
    input[..KEY_LINK_MESSAGE_LEN].copy_from_slice(message);
    input
}

/// An Ember key whose key-link proof answered a nonce we issued, co-signed
/// by the proven SecIdent key on record for the prover's user hash, with
/// the Ember hash derived from the key itself.
///
/// Only [`KeyLinkSession`] makes one, from a proof it has verified, so
/// neither a replayed public key nor the legacy `OP_EMBER_AUTH_RESPONSE`
/// (whose signature names no user hash, and which builds before 1.7.5 gave
/// for any nonce) has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenEmberKey {
    ember_hash: [u8; 16],
    secident_digest: [u8; 32],
}

impl ProvenEmberKey {
    pub fn ember_hash(&self) -> [u8; 16] {
        self.ember_hash
    }

    /// Whether `secident_key` is the SecIdent key that co-signed the proof.
    pub fn secident_key_matches(&self, secident_key: &[u8]) -> bool {
        !secident_key.is_empty() && secident_key_digest(secident_key) == self.secident_digest
    }
}

/// Why a proof was not taken. All are dropped quietly: the session goes on,
/// without the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLinkError {
    /// No challenge of ours is outstanding: never sent, or already answered.
    Unsolicited,
    /// Body is shorter than its fixed head or longer or shorter than its
    /// RSA signature length says.
    InvalidLength,
    /// The RSA signature length is not [`KEY_LINK_RSA_SIG_LEN`].
    RsaSignatureLength,
    /// The peer's HELLO named no Ember hash to bind the key to.
    NoAdvertisedIdentity,
    /// One of the two user hashes is the all-zero placeholder.
    NoUserHash,
    /// The key does not hash to the Ember identity the peer advertised.
    BindingMismatch,
    /// The Ember key's signature does not verify over the statement.
    BadSignature,
    /// The SecIdent key on record did not sign the statement.
    BadRsaSignature,
}

/// The sub-type and body of an `OP_EMULEPROT` packet that is one of the two
/// key-link frames, `None` for anything else (other `OP_EMBER_EXT` sub-types
/// included, which their own handlers keep).
pub fn key_link_frame(proto: u8, opcode: u8, payload: &[u8]) -> Option<(u8, &[u8])> {
    if proto != OP_EMULEPROT || opcode != OP_EMBER_EXT {
        return None;
    }
    let (sub_type, body) = parse_ember_ext(payload)?;
    matches!(sub_type, EMBER_EXT_KEY_LINK_CHALLENGE | EMBER_EXT_KEY_LINK_PROOF)
        .then_some((sub_type, body))
}

/// What this session knows about its peer when a key-link frame arrives.
#[derive(Debug, Clone, Copy)]
pub struct KeyLinkPeer<'a> {
    /// Its `OP_EMBER_HELLO` has shown it is an Ember client.
    pub is_ember: bool,
    /// The Ember identity that HELLO named.
    pub advertised_ember_hash: Option<&'a [u8; 16]>,
    /// The user hash its eD2K Hello named.
    pub user_hash: &'a [u8; 16],
    /// The SecIdent key on record for that user hash, if SecIdent has
    /// proven it ([`CreditManager::proven_public_key`]).
    pub proven_secident_key: Option<&'a [u8]>,
}

/// What we prove with: our user hash, our Ember key, and the credit ledger
/// holding our SecIdent key pair (without one we answer nothing).
#[derive(Clone, Copy)]
pub struct KeyLinkUs<'a> {
    pub user_hash: &'a [u8; 16],
    pub key: &'a SigningKey,
    pub credits: &'a CreditManager,
}

/// What to do with one key-link frame.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyLinkStep {
    /// Send this `OP_EMBER_EXT` payload back: our proof.
    Reply(Vec<u8>),
    /// The peer's proof of our challenge verified: link it
    /// ([`link_proven_key`]).
    Proven(ProvenEmberKey),
    /// The peer's user hash has no proven SecIdent key yet; the proof is
    /// kept until SecIdent proves one on this session
    /// ([`KeyLinkSession::note_secident`]).
    AwaitingSecIdent,
    /// Nothing to do.
    Ignored,
}

/// A proof that answered our nonce and binds to the advertised identity,
/// kept until the peer's user hash has a proven SecIdent key to check it by.
#[derive(Debug)]
struct PendingProof {
    nonce: [u8; KEY_LINK_NONCE_LEN],
    ember_pubkey: [u8; 32],
    ed25519_sig: [u8; 64],
    rsa_sig: [u8; KEY_LINK_RSA_SIG_LEN],
}

/// Key-link state of one eD2K session, both roles.
#[derive(Debug, Default)]
pub struct KeyLinkSession {
    /// Whether we have challenged this session's peer.
    challenged: bool,
    /// The nonce of our challenge, until a proof answers it.
    outstanding: Option<[u8; KEY_LINK_NONCE_LEN]>,
    /// Challenges from the peer we have answered.
    answered: u8,
    /// The peer's proof, until its user hash has a proven SecIdent key.
    pending: Option<PendingProof>,
}

impl KeyLinkSession {
    /// The `OP_EMBER_EXT` payload challenging this session's peer, once its
    /// HELLO has shown it is an Ember client and only the first time.
    pub fn challenge_payload(&mut self, peer_is_ember: bool) -> Option<Vec<u8>> {
        if !peer_is_ember {
            return None;
        }
        let nonce = self.start_challenge()?;
        Some(build_ember_ext(EMBER_EXT_KEY_LINK_CHALLENGE, &nonce))
    }

    /// Handle one key-link frame ([`key_link_frame`]) from `peer`: answer a
    /// challenge as `us`, or take a proof of ours. A challenge from a peer
    /// not known to be Ember goes unanswered.
    pub fn on_frame(
        &mut self,
        sub_type: u8,
        body: &[u8],
        peer: KeyLinkPeer<'_>,
        us: KeyLinkUs<'_>,
    ) -> KeyLinkStep {
        match sub_type {
            EMBER_EXT_KEY_LINK_CHALLENGE if peer.is_ember => {
                match self.answer_challenge(body, us, peer.user_hash) {
                    Some(proof) => KeyLinkStep::Reply(build_ember_ext(EMBER_EXT_KEY_LINK_PROOF, &proof)),
                    None => {
                        debug!("Key link: not answering a challenge ({} bytes)", body.len());
                        KeyLinkStep::Ignored
                    }
                }
            }
            EMBER_EXT_KEY_LINK_PROOF => {
                match self.accept_proof(
                    body,
                    peer.advertised_ember_hash,
                    peer.user_hash,
                    us.user_hash,
                    peer.proven_secident_key,
                ) {
                    Ok(Some(proven)) => KeyLinkStep::Proven(proven),
                    Ok(None) => KeyLinkStep::AwaitingSecIdent,
                    Err(e) => {
                        debug!("Key link: proof refused: {e:?}");
                        KeyLinkStep::Ignored
                    }
                }
            }
            _ => KeyLinkStep::Ignored,
        }
    }

    /// The challenge body to send this session's peer, the first time only.
    /// Remembers its nonce for [`Self::accept_proof`].
    pub fn start_challenge(&mut self) -> Option<[u8; KEY_LINK_NONCE_LEN]> {
        if self.challenged {
            return None;
        }
        self.challenged = true;
        let mut nonce = [0u8; KEY_LINK_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        self.outstanding = Some(nonce);
        Some(nonce)
    }

    /// Our proof for the peer's challenge `body`: our own Ember key, our own
    /// user hash, our own SecIdent key, and the user hash the peer sent in
    /// Hello as challenger, whatever else the peer may want. `None` for a
    /// malformed challenge, an unknown user hash, no SecIdent key pair of
    /// ours, or past [`MAX_KEY_LINK_ANSWERS`] on this session.
    pub fn answer_challenge(
        &mut self,
        body: &[u8],
        us: KeyLinkUs<'_>,
        peer_user_hash: &[u8; 16],
    ) -> Option<[u8; KEY_LINK_PROOF_LEN]> {
        let nonce: &[u8; KEY_LINK_NONCE_LEN] = body.try_into().ok()?;
        let our_secident_key = us.credits.our_public_key();
        if self.answered >= MAX_KEY_LINK_ANSWERS
            || *us.user_hash == [0u8; 16]
            || *peer_user_hash == [0u8; 16]
            || our_secident_key.is_empty()
        {
            return None;
        }
        let ember_pubkey = us.key.verifying_key().to_bytes();
        let message = key_link_message(
            nonce,
            us.user_hash,
            peer_user_hash,
            &ember_pubkey,
            &secident_key_digest(our_secident_key),
        );
        let rsa_sig = us.credits.sign_key_link(&key_link_rsa_input(&message));
        if rsa_sig.len() != KEY_LINK_RSA_SIG_LEN {
            return None;
        }
        self.answered += 1;
        let mut proof = [0u8; KEY_LINK_PROOF_LEN];
        proof[..32].copy_from_slice(&ember_pubkey);
        proof[32..96].copy_from_slice(&us.key.sign(&message).to_bytes());
        proof[96] = KEY_LINK_RSA_SIG_LEN as u8;
        proof[KEY_LINK_PROOF_HEAD_LEN..].copy_from_slice(&rsa_sig);
        Some(proof)
    }

    /// Take the peer's proof `body` of our outstanding challenge. The nonce
    /// is spent by any proof, good or bad, so each challenge is answered at
    /// most once; a proof with nothing outstanding is refused.
    ///
    /// `advertised_ember_hash` is the identity the peer's HELLO named;
    /// `peer_user_hash` the user hash its Hello named, which must be the
    /// prover's, and `our_user_hash` ours, which must be the challenger's.
    /// `peer_proven_key` is the proven SecIdent key on record for the peer's
    /// user hash: with one the proof is checked now (`Ok(Some)`), without
    /// one it is kept for [`Self::note_secident`] (`Ok(None)`).
    pub fn accept_proof(
        &mut self,
        body: &[u8],
        advertised_ember_hash: Option<&[u8; 16]>,
        peer_user_hash: &[u8; 16],
        our_user_hash: &[u8; 16],
        peer_proven_key: Option<&[u8]>,
    ) -> Result<Option<ProvenEmberKey>, KeyLinkError> {
        let nonce = self.outstanding.take().ok_or(KeyLinkError::Unsolicited)?;
        let rsa_len = *body
            .get(KEY_LINK_PROOF_HEAD_LEN - 1)
            .ok_or(KeyLinkError::InvalidLength)?;
        if usize::from(rsa_len) != KEY_LINK_RSA_SIG_LEN {
            return Err(KeyLinkError::RsaSignatureLength);
        }
        if body.len() != KEY_LINK_PROOF_LEN {
            return Err(KeyLinkError::InvalidLength);
        }
        let advertised = advertised_ember_hash.ok_or(KeyLinkError::NoAdvertisedIdentity)?;
        if *peer_user_hash == [0u8; 16] || *our_user_hash == [0u8; 16] {
            return Err(KeyLinkError::NoUserHash);
        }
        let field = |range: std::ops::Range<usize>| body.get(range).ok_or(KeyLinkError::InvalidLength);
        let ember_pubkey: [u8; 32] = field(0..32)?.try_into().map_err(|_| KeyLinkError::InvalidLength)?;
        if !crypto::verify_ember_hash_binding(&ember_pubkey, advertised) {
            return Err(KeyLinkError::BindingMismatch);
        }
        let pending = PendingProof {
            nonce,
            ember_pubkey,
            ed25519_sig: field(32..96)?.try_into().map_err(|_| KeyLinkError::InvalidLength)?,
            rsa_sig: field(KEY_LINK_PROOF_HEAD_LEN..KEY_LINK_PROOF_LEN)?
                .try_into()
                .map_err(|_| KeyLinkError::InvalidLength)?,
        };
        match peer_proven_key {
            Some(key) => verify_proof(&pending, peer_user_hash, our_user_hash, key).map(Some),
            None => {
                self.pending = Some(pending);
                Ok(None)
            }
        }
    }

    /// SecIdent has just proven `peer_proven_key` for the peer's user hash on
    /// this session: check a proof that came before it had one. `Some` if
    /// that proof now verifies; a kept proof is checked once either way.
    pub fn note_secident(
        &mut self,
        peer_proven_key: &[u8],
        peer_user_hash: &[u8; 16],
        our_user_hash: &[u8; 16],
    ) -> Option<ProvenEmberKey> {
        if peer_proven_key.is_empty() {
            return None;
        }
        let pending = self.pending.take()?;
        match verify_proof(&pending, peer_user_hash, our_user_hash, peer_proven_key) {
            Ok(proven) => Some(proven),
            Err(e) => {
                debug!("Key link: waiting proof refused once SecIdent passed: {e:?}");
                None
            }
        }
    }
}

/// Both signatures of a proof against the statement built from our nonce,
/// the two user hashes, the proof's Ember key and the peer's proven
/// SecIdent key, and the RSA one by that key.
fn verify_proof(
    proof: &PendingProof,
    peer_user_hash: &[u8; 16],
    our_user_hash: &[u8; 16],
    peer_secident_key: &[u8],
) -> Result<ProvenEmberKey, KeyLinkError> {
    let secident_digest = secident_key_digest(peer_secident_key);
    let message = key_link_message(
        &proof.nonce,
        peer_user_hash,
        our_user_hash,
        &proof.ember_pubkey,
        &secident_digest,
    );
    let ember_key =
        VerifyingKey::from_bytes(&proof.ember_pubkey).map_err(|_| KeyLinkError::BindingMismatch)?;
    ember_key
        .verify_strict(&message, &Signature::from_bytes(&proof.ed25519_sig))
        .map_err(|_| KeyLinkError::BadSignature)?;
    if !super::credits::secident_rsa_verify(
        peer_secident_key,
        &key_link_rsa_input(&message),
        &proof.rsa_sig,
    ) {
        return Err(KeyLinkError::BadRsaSignature);
    }
    Ok(ProvenEmberKey {
        ember_hash: crypto::node_id_from_public_key(&ember_key),
        secident_digest,
    })
}

/// The one way a verified proof becomes a link, whether it verified as it
/// arrived or once SecIdent proved the key it waited for.
pub(crate) async fn link_proven_key(
    credits: &tokio::sync::RwLock<CreditManager>,
    peer_user_hash: [u8; 16],
    signer: &ProvenEmberKey,
    peer: std::net::SocketAddr,
) {
    info!("Key link: {peer} proved its Ember key");
    credits.write().await.note_session_proven_ember(peer_user_hash, signer);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Identity {
        pub key: SigningKey,
        pub pubkey: [u8; 32],
        pub ember_hash: [u8; 16],
    }

    pub(crate) fn identity() -> Identity {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();
        let ember_hash = crypto::node_id_from_public_key(&key.verifying_key());
        Identity { key, pubkey, ember_hash }
    }

    /// A client that can prove: an Ember identity, a user hash, and a
    /// SecIdent key pair.
    pub(crate) struct Prover {
        pub id: Identity,
        pub user_hash: [u8; 16],
        pub credits: CreditManager,
    }

    impl Prover {
        pub(crate) fn new(user_hash: [u8; 16]) -> Self {
            Self { id: identity(), user_hash, credits: CreditManager::with_generated_keys() }
        }

        /// Its SecIdent public key, as `OP_PUBLICKEY` carries it.
        pub(crate) fn rsa(&self) -> Vec<u8> {
            self.credits.our_public_key().to_vec()
        }

        /// Its proof for a challenger it knows as `challenger`.
        pub(crate) fn prove(&self, nonce: &[u8], challenger: [u8; 16]) -> [u8; KEY_LINK_PROOF_LEN] {
            let us = KeyLinkUs { user_hash: &self.user_hash, key: &self.id.key, credits: &self.credits };
            KeyLinkSession::default()
                .answer_challenge(nonce, us, &challenger)
                .expect("answered")
        }
    }

    /// A proof by the Ember identity `ember` over the statement naming
    /// `prover_hash`, `challenger`, its own key and the digest of
    /// `digest_key`, carrying whatever `rsa_sig` an attacker has to hand.
    pub(crate) fn proof_with_rsa(
        ember: &Identity,
        nonce: &[u8; 32],
        prover_hash: [u8; 16],
        challenger: [u8; 16],
        digest_key: &[u8],
        rsa_sig: &[u8],
    ) -> Vec<u8> {
        let statement = key_link_message(
            nonce,
            &prover_hash,
            &challenger,
            &ember.pubkey,
            &secident_key_digest(digest_key),
        );
        let mut proof = Vec::with_capacity(KEY_LINK_PROOF_HEAD_LEN + rsa_sig.len());
        proof.extend_from_slice(&ember.pubkey);
        proof.extend_from_slice(&ember.key.sign(&statement).to_bytes());
        proof.push(rsa_sig.len() as u8);
        proof.extend_from_slice(rsa_sig);
        proof
    }

    /// Our SecIdent RSA signature, as `signer`, over the statement
    /// [`proof_with_rsa`] builds.
    pub(crate) fn rsa_sig_by(
        signer: &CreditManager,
        ember: &Identity,
        nonce: &[u8; 32],
        prover_hash: [u8; 16],
        challenger: [u8; 16],
        digest_key: &[u8],
    ) -> Vec<u8> {
        let statement = key_link_message(
            nonce,
            &prover_hash,
            &challenger,
            &ember.pubkey,
            &secident_key_digest(digest_key),
        );
        signer.sign_key_link(&key_link_rsa_input(&statement))
    }

    /// One whole exchange: the verifier (user hash `verifier_hash`), which
    /// holds `record_key` as the proven SecIdent key for the prover's user
    /// hash, challenges; `prover` answers; the verifier checks the proof
    /// against the identity `advertised` the prover's HELLO named.
    pub(crate) fn exchange(
        prover: &Prover,
        verifier_hash: [u8; 16],
        advertised: [u8; 16],
        record_key: &[u8],
    ) -> Result<ProvenEmberKey, KeyLinkError> {
        let mut verifier = KeyLinkSession::default();
        let nonce = verifier.start_challenge().expect("first challenge");
        let proof = prover.prove(&nonce, verifier_hash);
        verifier
            .accept_proof(&proof, Some(&advertised), &prover.user_hash, &verifier_hash, Some(record_key))
            .map(|proven| proven.expect("a proven key checks at once"))
    }

    const PROVER: [u8; 16] = [0x11; 16];
    const VERIFIER: [u8; 16] = [0x22; 16];

    /// A verifier that has challenged, with the proof `prover` gives it.
    fn challenged(prover: &Prover) -> (KeyLinkSession, [u8; KEY_LINK_PROOF_LEN]) {
        let mut verifier = KeyLinkSession::default();
        let nonce = verifier.start_challenge().unwrap();
        let proof = prover.prove(&nonce, VERIFIER);
        (verifier, proof)
    }

    fn check(
        verifier: &mut KeyLinkSession,
        proof: &[u8],
        prover: &Prover,
        record_key: Option<&[u8]>,
    ) -> Result<Option<ProvenEmberKey>, KeyLinkError> {
        verifier.accept_proof(proof, Some(&prover.id.ember_hash), &prover.user_hash, &VERIFIER, record_key)
    }

    #[test]
    fn signed_statement_and_proof_have_the_documented_layout() {
        let nonce = [0x5A; 32];
        let ember = [0x6B; 32];
        let digest = secident_key_digest(b"rsa");
        assert_eq!(digest, *blake3::hash(b"rsa").as_bytes());
        let message = key_link_message(&nonce, &PROVER, &VERIFIER, &ember, &digest);
        assert_eq!(message.len(), 151);
        assert_eq!(&message[..23], b"ember-ed2k-key-link-v1\0");
        assert_eq!(&message[23..55], &nonce);
        assert_eq!(&message[55..71], &PROVER);
        assert_eq!(&message[71..87], &VERIFIER);
        assert_eq!(&message[87..119], &ember);
        assert_eq!(&message[119..], &digest);
        let rsa_input = key_link_rsa_input(&message);
        assert_eq!(rsa_input.len(), 320);
        assert_eq!(&rsa_input[..151], &message);
        assert!(rsa_input[151..].iter().all(|&b| b == 0));

        let prover = Prover::new(PROVER);
        let proof = prover.prove(&nonce, VERIFIER);
        assert_eq!(proof.len(), 145);
        assert_eq!(&proof[..32], &prover.id.pubkey);
        assert_eq!(proof[96], 48);
        let statement = key_link_message(
            &nonce,
            &PROVER,
            &VERIFIER,
            &prover.id.pubkey,
            &secident_key_digest(&prover.rsa()),
        );
        let ed_sig = Signature::from_bytes(proof[32..96].try_into().unwrap());
        assert!(prover.id.key.verifying_key().verify_strict(&statement, &ed_sig).is_ok());
        assert!(super::super::credits::secident_rsa_verify(
            &prover.rsa(),
            &key_link_rsa_input(&statement),
            &proof[97..]
        ));
    }

    /// No SecIdent signer, of any Ember or eMule version, signs more than
    /// 264 bytes: a peer key of at most 255 bytes (one length byte), the
    /// 4-byte challenge and the 5-byte IP tail. Our own signs key-link input
    /// only in its exact shape.
    #[test]
    fn no_secident_answer_can_be_a_key_link_rsa_signature() {
        const LONGEST_SECIDENT_INPUT: usize = 255 + 4 + 5;
        const { assert!(KEY_LINK_RSA_INPUT_LEN > LONGEST_SECIDENT_INPUT) };
        let us = CreditManager::with_generated_keys();
        let message = key_link_message(&[1; 32], &PROVER, &VERIFIER, &[2; 32], &[3; 32]);
        assert_eq!(us.sign_key_link(&key_link_rsa_input(&message)).len(), 48);
        assert!(us.sign_key_link(&message).is_empty(), "not padded");
        let mut foreign = key_link_rsa_input(&message);
        foreign[0] = b'x';
        assert!(us.sign_key_link(&foreign).is_empty(), "not the domain");
        assert!(CreditManager::new().sign_key_link(&key_link_rsa_input(&message)).is_empty());
    }

    #[test]
    fn a_valid_proof_yields_the_key_that_signed() {
        let prover = Prover::new(PROVER);
        let proven = exchange(&prover, VERIFIER, prover.id.ember_hash, &prover.rsa()).expect("valid");
        assert_eq!(proven.ember_hash(), prover.id.ember_hash);
        assert!(proven.secident_key_matches(&prover.rsa()));
        assert!(!proven.secident_key_matches(b"another key"));
        assert!(!proven.secident_key_matches(b""));
    }

    #[test]
    fn a_proof_naming_another_user_hash_is_refused() {
        let prover = Prover::new([0x33; 16]);
        let (mut verifier, proof) = challenged(&prover);
        assert_eq!(
            verifier.accept_proof(&proof, Some(&prover.id.ember_hash), &PROVER, &VERIFIER, Some(&prover.rsa())),
            Err(KeyLinkError::BadSignature),
            "another prover user hash"
        );

        let prover = Prover::new(PROVER);
        let mut verifier = KeyLinkSession::default();
        let nonce = verifier.start_challenge().unwrap();
        let proof = prover.prove(&nonce, [0x44; 16]);
        assert_eq!(
            check(&mut verifier, &proof, &prover, Some(&prover.rsa())),
            Err(KeyLinkError::BadSignature),
            "another challenger user hash"
        );
    }

    /// The SecIdent key on record for the user hash is not the prover's:
    /// the statement names the wrong digest, and the RSA signature is not
    /// by the key on record.
    #[test]
    fn a_proof_checked_against_another_secident_key_is_refused() {
        let prover = Prover::new(PROVER);
        let other = Prover::new(PROVER);
        let (mut verifier, proof) = challenged(&prover);
        assert_eq!(
            check(&mut verifier, &proof, &prover, Some(&other.rsa())),
            Err(KeyLinkError::BadSignature)
        );
    }

    /// A proof over a nonce we did not issue, one over a nonce an earlier
    /// session issued, and a second proof for a nonce already answered are
    /// all refused.
    #[test]
    fn wrong_expired_and_reused_nonces_are_refused() {
        let prover = Prover::new(PROVER);
        let rsa = prover.rsa();

        let mut verifier = KeyLinkSession::default();
        verifier.start_challenge().unwrap();
        assert_eq!(
            check(&mut verifier, &prover.prove(&[9u8; 32], VERIFIER), &prover, Some(&rsa)),
            Err(KeyLinkError::BadSignature),
            "a nonce we never issued"
        );

        let old_nonce = KeyLinkSession::default().start_challenge().unwrap();
        let mut verifier = KeyLinkSession::default();
        verifier.start_challenge().unwrap();
        assert_eq!(
            check(&mut verifier, &prover.prove(&old_nonce, VERIFIER), &prover, Some(&rsa)),
            Err(KeyLinkError::BadSignature),
            "an earlier session's nonce"
        );

        let (mut verifier, proof) = challenged(&prover);
        assert!(matches!(check(&mut verifier, &proof, &prover, Some(&rsa)), Ok(Some(_))));
        assert_eq!(
            check(&mut verifier, &proof, &prover, Some(&rsa)),
            Err(KeyLinkError::Unsolicited),
            "the nonce is spent"
        );
        assert_eq!(verifier.start_challenge(), None, "one challenge per session");
    }

    #[test]
    fn a_bad_proof_spends_the_nonce_and_an_unsolicited_one_is_refused() {
        let prover = Prover::new(PROVER);
        let rsa = prover.rsa();
        let mut fresh = KeyLinkSession::default();
        assert_eq!(
            check(&mut fresh, &[0u8; KEY_LINK_PROOF_LEN], &prover, Some(&rsa)),
            Err(KeyLinkError::Unsolicited)
        );
        let (mut verifier, good) = challenged(&prover);
        assert_eq!(check(&mut verifier, &[0u8; 10], &prover, Some(&rsa)), Err(KeyLinkError::InvalidLength));
        assert_eq!(
            check(&mut verifier, &good, &prover, Some(&rsa)),
            Err(KeyLinkError::Unsolicited),
            "a late good proof after a bad one finds nothing outstanding"
        );
    }

    /// A corrupted RSA signature, one cut short, one with bytes after it,
    /// and any length byte but 48 are all refused.
    #[test]
    fn a_bad_truncated_or_oversized_rsa_signature_is_refused() {
        let prover = Prover::new(PROVER);
        let rsa = prover.rsa();
        let attempt = |mutate: &dyn Fn(&mut Vec<u8>)| {
            let (mut verifier, proof) = challenged(&prover);
            let mut proof = proof.to_vec();
            mutate(&mut proof);
            check(&mut verifier, &proof, &prover, Some(&rsa))
        };
        assert!(matches!(attempt(&|_| {}), Ok(Some(_))), "untouched, it verifies");
        assert_eq!(attempt(&|p| p[KEY_LINK_PROOF_LEN - 1] ^= 1), Err(KeyLinkError::BadRsaSignature));
        assert_eq!(attempt(&|p| p[100] ^= 0x80), Err(KeyLinkError::BadRsaSignature));
        assert_eq!(attempt(&|p| p.truncate(KEY_LINK_PROOF_LEN - 8)), Err(KeyLinkError::InvalidLength));
        assert_eq!(attempt(&|p| p.truncate(KEY_LINK_PROOF_HEAD_LEN - 1)), Err(KeyLinkError::InvalidLength));
        assert_eq!(attempt(&|p| p.push(0)), Err(KeyLinkError::InvalidLength));
        for declared in [0u8, 47, 49, 64, 128, 255] {
            assert_eq!(
                attempt(&|p| {
                    p[96] = declared;
                    p.resize(KEY_LINK_PROOF_HEAD_LEN + usize::from(declared), 0);
                }),
                Err(KeyLinkError::RsaSignatureLength),
                "rsa_sig_len {declared}"
            );
        }
    }

    /// A key that signs correctly but does not hash to the identity the
    /// peer's HELLO named, as when a stranger advertises a publisher's
    /// identity and signs with its own key.
    #[test]
    fn a_signature_by_a_key_that_does_not_bind_to_the_advertised_hash_is_refused() {
        let publisher = identity();
        let stranger = Prover::new(PROVER);
        assert_eq!(
            exchange(&stranger, VERIFIER, publisher.ember_hash, &stranger.rsa()),
            Err(KeyLinkError::BindingMismatch)
        );
        let (mut verifier, mut proof) = challenged(&stranger);
        proof[..32].copy_from_slice(&publisher.pubkey);
        assert_eq!(
            verifier.accept_proof(&proof, Some(&publisher.ember_hash), &PROVER, &VERIFIER, Some(&stranger.rsa())),
            Err(KeyLinkError::BadSignature),
            "the publisher's key over the stranger's signature"
        );
    }

    /// The forwarding attack. A stranger (user hash `STRANGER`) connects to
    /// us and to the publisher at once, passes our nonce on to the publisher
    /// and our challenge's answer back. The publisher signs for its own
    /// session with the stranger, so the proof names the publisher's user
    /// hash and the stranger's, and fails against ours with the stranger.
    #[test]
    fn a_proof_the_key_holder_made_for_another_challenger_is_refused() {
        const STRANGER: [u8; 16] = [0x66; 16];
        let publisher = Prover::new([0x77; 16]);
        let mut us = KeyLinkSession::default();
        let our_nonce = us.start_challenge().unwrap();
        let relayed = publisher.prove(&our_nonce, STRANGER);
        assert_eq!(
            us.accept_proof(
                &relayed,
                Some(&publisher.id.ember_hash),
                &STRANGER,
                &VERIFIER,
                Some(Prover::new(STRANGER).rsa().as_slice())
            ),
            Err(KeyLinkError::BadSignature)
        );
    }

    /// The first-contact relay: a stranger reached us first under the
    /// publisher's user hash, so the key on record for it is the stranger's.
    /// The publisher's own proof, relayed, is co-signed by the publisher's
    /// RSA key, not the one on record, so it fails.
    #[test]
    fn the_first_contact_relay_is_refused() {
        let publisher = Prover::new([0x77; 16]);
        let stranger_rsa = Prover::new([0x77; 16]).rsa();
        let mut us = KeyLinkSession::default();
        let nonce = us.start_challenge().unwrap();
        let relayed = publisher.prove(&nonce, VERIFIER);
        assert!(us
            .accept_proof(&relayed, Some(&publisher.id.ember_hash), &publisher.user_hash, &VERIFIER, None)
            .unwrap()
            .is_none());
        assert_eq!(us.note_secident(&stranger_rsa, &publisher.user_hash, &VERIFIER), None);
    }

    /// The relayed-SecIdent wipe: the publisher's proven key is on record
    /// for its user hash. A stranger who passed SecIdent for that hash by
    /// relaying the publisher's own SecIdent answer now proves its own
    /// Ember key over the publisher's key digest. It has no RSA signature by
    /// the publisher over its own Ember key: not its own RSA key's, not the
    /// relayed SecIdent answer, and not the publisher's real key-link one,
    /// which endorses the publisher's Ember key. Every try is refused.
    #[test]
    fn the_relayed_secident_wipe_is_refused() {
        let publisher = Prover::new([0x77; 16]);
        let record_key = publisher.rsa();
        let stranger = Prover::new(publisher.user_hash);
        let stranger_ember = &stranger.id;

        let try_with = |rsa_sig: &dyn Fn(&[u8; 32]) -> Vec<u8>| {
            let mut us = KeyLinkSession::default();
            let nonce = us.start_challenge().unwrap();
            let proof = proof_with_rsa(
                stranger_ember,
                &nonce,
                publisher.user_hash,
                VERIFIER,
                &record_key,
                &rsa_sig(&nonce),
            );
            us.accept_proof(&proof, Some(&stranger_ember.ember_hash), &publisher.user_hash, &VERIFIER, Some(&record_key))
        };

        // Its own SecIdent key signs the statement.
        assert_eq!(
            try_with(&|nonce| {
                rsa_sig_by(&stranger.credits, stranger_ember, nonce, publisher.user_hash, VERIFIER, &record_key)
            }),
            Err(KeyLinkError::BadRsaSignature)
        );
        // A SecIdent answer the publisher gave for our key and challenge.
        let mut publisher_ledger = CreditManager::with_generated_keys();
        let our_rsa = CreditManager::with_generated_keys().our_public_key().to_vec();
        assert!(publisher_ledger.set_public_key(VERIFIER, our_rsa));
        let secident_answer = publisher_ledger.create_signature_for_peer(&VERIFIER, 0x1234_5678, 0, None);
        assert_eq!(secident_answer.len(), 48);
        assert_eq!(try_with(&|_| secident_answer.clone()), Err(KeyLinkError::BadRsaSignature));
        // The publisher's own key-link RSA signature for this very nonce,
        // endorsing the publisher's Ember key.
        assert_eq!(
            try_with(&|nonce| publisher.prove(nonce, VERIFIER)[97..].to_vec()),
            Err(KeyLinkError::BadRsaSignature)
        );
        // And the honest publisher still links.
        assert!(exchange(&publisher, VERIFIER, publisher.id.ember_hash, &record_key).is_ok());
    }

    /// A user hash whose key was proven earlier (a restart, or a session
    /// where SecIdent ran) needs no SecIdent on this session.
    #[test]
    fn a_proof_checks_at_once_against_a_key_proven_earlier() {
        let prover = Prover::new(PROVER);
        let (mut verifier, proof) = challenged(&prover);
        let Ok(Some(proven)) = check(&mut verifier, &proof, &prover, Some(&prover.rsa())) else {
            panic!("verified without SecIdent here");
        };
        assert_eq!(proven.ember_hash(), prover.id.ember_hash);
        assert_eq!(verifier.note_secident(&prover.rsa(), &PROVER, &VERIFIER), None, "nothing kept");
    }

    /// First contact: no proven key on record yet. The proof is kept, not
    /// refused, and verifies once SecIdent proves the prover's key; a kept
    /// proof meets a SecIdent that proves some other key only once.
    #[test]
    fn a_proof_before_first_secident_is_checked_once_secident_passes() {
        let prover = Prover::new(PROVER);
        let our = Prover::new(VERIFIER);
        let mut session = KeyLinkSession::default();
        let challenge = session.challenge_payload(true).unwrap();
        let proof = build_ember_ext(EMBER_EXT_KEY_LINK_PROOF, &prover.prove(&challenge[1..], VERIFIER));
        let (sub_type, body) = key_link_frame(OP_EMULEPROT, OP_EMBER_EXT, &proof).unwrap();
        let peer = KeyLinkPeer {
            is_ember: true,
            advertised_ember_hash: Some(&prover.id.ember_hash),
            user_hash: &PROVER,
            proven_secident_key: None,
        };
        let us = KeyLinkUs { user_hash: &VERIFIER, key: &our.id.key, credits: &our.credits };
        assert_eq!(session.on_frame(sub_type, body, peer, us), KeyLinkStep::AwaitingSecIdent);
        let proven = session.note_secident(&prover.rsa(), &PROVER, &VERIFIER).expect("verifies now");
        assert_eq!(proven.ember_hash(), prover.id.ember_hash);
        assert_eq!(session.on_frame(sub_type, body, peer, us), KeyLinkStep::Ignored, "spent");

        let (mut session, proof) = challenged(&prover);
        assert_eq!(check(&mut session, &proof, &prover, None), Ok(None));
        assert_eq!(session.note_secident(&Prover::new(PROVER).rsa(), &PROVER, &VERIFIER), None);
        assert_eq!(session.note_secident(&prover.rsa(), &PROVER, &VERIFIER), None, "nothing kept");
    }

    #[test]
    fn a_session_answers_a_bounded_number_of_well_formed_challenges() {
        let prover = Prover::new(PROVER);
        let us = |user_hash: &'static [u8; 16]| KeyLinkUs {
            user_hash,
            key: &prover.id.key,
            credits: &prover.credits,
        };
        let mut session = KeyLinkSession::default();
        assert_eq!(session.answer_challenge(&[1u8; 31], us(&PROVER), &VERIFIER), None);
        assert_eq!(session.answer_challenge(&[1u8; 32], us(&[0u8; 16]), &VERIFIER), None);
        assert_eq!(session.answer_challenge(&[1u8; 32], us(&PROVER), &[0u8; 16]), None);
        let keyless = CreditManager::new();
        let without_rsa = KeyLinkUs { user_hash: &PROVER, key: &prover.id.key, credits: &keyless };
        assert_eq!(
            session.answer_challenge(&[1u8; 32], without_rsa, &VERIFIER),
            None,
            "no SecIdent key pair of ours, no proof"
        );
        for _ in 0..MAX_KEY_LINK_ANSWERS {
            assert!(session.answer_challenge(&[1u8; 32], us(&PROVER), &VERIFIER).is_some());
        }
        assert_eq!(session.answer_challenge(&[2u8; 32], us(&PROVER), &VERIFIER), None);
    }

    /// A plain eMule peer never sends `OP_EMBER_HELLO`, so it is never
    /// challenged, and a challenge from a peer not known to be Ember goes
    /// unanswered.
    #[test]
    fn only_ember_peers_are_challenged_or_answered() {
        let prover = Prover::new(VERIFIER);
        let mut session = KeyLinkSession::default();
        assert_eq!(session.challenge_payload(false), None);
        let plain = KeyLinkPeer {
            is_ember: false,
            advertised_ember_hash: None,
            user_hash: &PROVER,
            proven_secident_key: None,
        };
        let us = KeyLinkUs { user_hash: &VERIFIER, key: &prover.id.key, credits: &prover.credits };
        assert_eq!(
            session.on_frame(EMBER_EXT_KEY_LINK_CHALLENGE, &[1u8; 32], plain, us),
            KeyLinkStep::Ignored
        );
        assert!(session.challenge_payload(true).is_some(), "an Ember peer is, once");
        assert_eq!(session.challenge_payload(true), None);
    }

    /// Two of our own clients on one eD2K session, each challenging the other
    /// and answering the other's challenge, through the same frames the
    /// session loops pass on. One already holds the other's proven key from
    /// an earlier session, so its proof verifies at once with no SecIdent
    /// here; the other has never met it, so its proof waits for SecIdent.
    /// Both end up crediting the other's Ember-stream bytes to its user hash.
    #[test]
    fn two_clients_complete_the_exchange_both_ways() {
        use super::super::credits::IdentState;

        struct Client {
            me: Prover,
            session: KeyLinkSession,
            ledger: CreditManager,
        }
        impl Client {
            fn new(user_hash: [u8; 16]) -> Self {
                Self {
                    me: Prover::new(user_hash),
                    session: KeyLinkSession::default(),
                    ledger: CreditManager::new(),
                }
            }
            /// Hand one `OP_EMBER_EXT` packet from `from` to this client.
            fn receive(&mut self, from: &Client, payload: &[u8]) -> KeyLinkStep {
                let (sub_type, body) =
                    key_link_frame(OP_EMULEPROT, OP_EMBER_EXT, payload).expect("a key-link frame");
                let peer = KeyLinkPeer {
                    is_ember: true,
                    advertised_ember_hash: Some(&from.me.id.ember_hash),
                    user_hash: &from.me.user_hash,
                    proven_secident_key: self.ledger.proven_public_key(&from.me.user_hash),
                };
                let us = KeyLinkUs {
                    user_hash: &self.me.user_hash,
                    key: &self.me.id.key,
                    credits: &self.me.credits,
                };
                self.session.on_frame(sub_type, body, peer, us)
            }
            /// SecIdent proving `peer`'s key here.
            fn secident_verified(&mut self, peer: &Client) {
                assert!(self.ledger.set_public_key(peer.me.user_hash, peer.me.rsa()));
                self.ledger.set_ident_state(peer.me.user_hash, IdentState::Verified);
            }
        }

        let mut a = Client::new([0xA0; 16]);
        let mut b = Client::new([0xB0; 16]);
        // An earlier session proved b's key to a; a restart reset the state.
        a.secident_verified(&b);
        a.ledger.set_ident_state(b.me.user_hash, IdentState::Needed);

        let a_challenge = a.session.challenge_payload(true).unwrap();
        let b_challenge = b.session.challenge_payload(true).unwrap();
        let KeyLinkStep::Reply(b_proof) = b.receive(&a, &a_challenge) else {
            panic!("b answers a");
        };
        let KeyLinkStep::Reply(a_proof) = a.receive(&b, &b_challenge) else {
            panic!("a answers b");
        };

        let KeyLinkStep::Proven(b_key) = a.receive(&b, &b_proof) else {
            panic!("a checks b's proof at once");
        };
        assert_eq!(b_key.ember_hash(), b.me.id.ember_hash);
        a.ledger.note_session_proven_ember(b.me.user_hash, &b_key);

        assert_eq!(b.receive(&a, &a_proof), KeyLinkStep::AwaitingSecIdent);
        b.secident_verified(&a);
        let a_record_key = b.ledger.proven_public_key(&a.me.user_hash).unwrap().to_vec();
        let a_key = b
            .session
            .note_secident(&a_record_key, &a.me.user_hash, &b.me.user_hash)
            .expect("checked once SecIdent proved a's key");
        b.ledger.note_session_proven_ember(a.me.user_hash, &a_key);

        assert!(a.ledger.add_downloaded_over_ember(&b.me.id.ember_hash, 5 << 20));
        assert!(b.ledger.add_downloaded_over_ember(&a.me.id.ember_hash, 7 << 20));
        assert_eq!(a.ledger.get_record(&b.me.user_hash).unwrap().downloaded, 5 << 20);
        assert_eq!(b.ledger.get_record(&a.me.user_hash).unwrap().downloaded, 7 << 20);

        assert_eq!(a.receive(&b, &b_proof), KeyLinkStep::Ignored, "a replayed proof");
    }

    #[test]
    fn a_proof_without_an_advertised_identity_or_user_hash_is_refused() {
        let prover = Prover::new(PROVER);
        let rsa = prover.rsa();
        let (mut verifier, proof) = challenged(&prover);
        assert_eq!(
            verifier.accept_proof(&proof, None, &PROVER, &VERIFIER, Some(&rsa)),
            Err(KeyLinkError::NoAdvertisedIdentity)
        );
        let (mut verifier, _) = challenged(&prover);
        assert_eq!(
            verifier.accept_proof(&proof, Some(&prover.id.ember_hash), &[0u8; 16], &VERIFIER, Some(&rsa)),
            Err(KeyLinkError::NoUserHash)
        );
    }
}
