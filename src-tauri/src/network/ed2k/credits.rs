use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

const MAX_CREDIT_RATIO: f64 = 10.0;
const MIN_CREDIT_RATIO: f64 = 1.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentState {
    Unknown,
    Verified,
    Failed,
    BadGuy,
    Needed,
}

pub const CRYPT_CIP_REMOTECLIENT: u8 = 10;
pub const CRYPT_CIP_LOCALCLIENT: u8 = 20;
pub const CRYPT_CIP_NONECLIENT: u8 = 30;

#[derive(Debug, Clone)]
pub struct CreditRecord {
    pub user_hash: [u8; 16],
    pub uploaded: u64,
    pub downloaded: u64,
    pub last_seen: i64,
    pub public_key: Vec<u8>,
    pub ident_state: IdentState,
    pub ident_ip: u32,
}

impl CreditRecord {
    pub fn new(user_hash: [u8; 16]) -> Self {
        Self {
            user_hash,
            uploaded: 0,
            downloaded: 0,
            last_seen: chrono::Utc::now().timestamp(),
            public_key: Vec::new(),
            ident_state: IdentState::Unknown,
            ident_ip: 0,
        }
    }
}

/// SecIdent credit tracker.
///
/// ## Cryptographic threat model
///
/// SecIdent is **wire-compatible with eMule 0.50a**, and therefore uses the
/// same parameters as the rest of the ecosystem:
///
/// - **RSA keys are 384 bits.** By modern standards this is well below the
///   2048-bit minimum for strong signing keys. A motivated attacker with
///   significant compute could potentially factor a captured public key and
///   forge signatures, spoofing another peer's credit identity.
/// - **Signatures use SHA-1** over the challenge material. SHA-1 is broken
///   for collision resistance but only second-preimage attacks would matter
///   here (signing a specific challenge); those are still infeasible.
/// - **Keys are reused across sessions** (persisted in `cryptkey.dat`). Loss
///   of the key file silently forfeits accumulated credits; access to the
///   file lets anyone impersonate this node.
///
/// The practical impact is limited by what credits actually buy: upload
/// queue priority in eMule-family clients. Forged SecIdent cannot read
/// another peer's shared files, downgrade our own transfers, or intercept
/// content — it can only let an attacker reap the slot advantage the
/// legitimate peer built up.
///
/// We accept these parameters because:
/// 1. Raising the key size or hash would break interop with every eMule
///    peer we participate with — the whole point of this feature is the
///    shared network-wide credit ledger.
/// 2. The stronger security property ("no one downloads our files without
///    paying") is provided by the upload slot / queue rules, not by
///    SecIdent itself.
///
/// Do **not** rely on SecIdent for any property stronger than "this peer
/// has the same cryptkey file it had last time". Everything that actually
/// matters for file integrity is covered by MD4 part hashes and AICH.
#[derive(ZeroizeOnDrop)]
pub struct CreditManager {
    #[zeroize(skip)]
    credits: HashMap<[u8; 16], CreditRecord>,
    #[zeroize(skip)]
    our_public_key: Vec<u8>,
    our_private_key: Vec<u8>,
    #[zeroize(skip)]
    crypto_available: bool,
}

impl CreditManager {
    pub fn new() -> Self {
        Self {
            credits: HashMap::new(),
            our_public_key: Vec::new(),
            our_private_key: Vec::new(),
            crypto_available: false,
        }
    }

    /// Load or generate the RSA keypair for secure identification.
    /// eMule persists this in cryptkey.dat; we use a data_dir file.
    pub fn load_or_create_keypair(&mut self, data_dir: &std::path::Path) {
        let key_path = data_dir.join("cryptkey.dat");
        if let Ok(data) = std::fs::read(&key_path) {
            if data.len() >= 8 {
                let pub_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if data.len() >= 4 + pub_len + 4 {
                    let pub_key = data[4..4 + pub_len].to_vec();
                    let priv_off = 4 + pub_len;
                    let priv_len = u32::from_le_bytes([
                        data[priv_off], data[priv_off + 1], data[priv_off + 2], data[priv_off + 3],
                    ]) as usize;
                    if data.len() >= priv_off + 4 + priv_len {
                        let priv_key = data[priv_off + 4..priv_off + 4 + priv_len].to_vec();
                        if !pub_key.is_empty() && !priv_key.is_empty() {
                            // Normalise legacy PKCS#1 public keys from older
                            // Ember builds to SPKI so peers' X509PublicKey
                            // decoders accept them (see
                            // `normalize_public_key_to_spki` and
                            // `generate_rsa_keypair` for why this matters).
                            // If re-encoding changes the bytes, rewrite the
                            // keyfile atomically so the next launch starts
                            // clean.
                            let (final_pub, migrated) = match normalize_public_key_to_spki(&pub_key) {
                                Some(n) => {
                                    let migrated = n != pub_key;
                                    (n, migrated)
                                }
                                None => (pub_key.clone(), false),
                            };
                            self.our_public_key = final_pub;
                            self.our_private_key = priv_key;
                            self.crypto_available = true;
                            tracing::info!("Loaded RSA keypair from {}", key_path.display());
                            if migrated {
                                let mut out = Vec::new();
                                out.extend_from_slice(&(self.our_public_key.len() as u32).to_le_bytes());
                                out.extend_from_slice(&self.our_public_key);
                                out.extend_from_slice(&(self.our_private_key.len() as u32).to_le_bytes());
                                out.extend_from_slice(&self.our_private_key);
                                if let Err(e) = crate::security::atomic_write(&key_path, &out, true) {
                                    tracing::warn!(
                                        "Failed to persist SPKI-normalised keypair: {e}"
                                    );
                                } else {
                                    tracing::info!(
                                        "Migrated cryptkey.dat public key from PKCS#1 to SPKI"
                                    );
                                }
                            }
                            return;
                        }
                    }
                }
            }
            tracing::warn!("Corrupt cryptkey.dat, regenerating keypair");
        }

        let (public_key, private_key) = generate_rsa_keypair();
        self.our_public_key = public_key;
        self.our_private_key = private_key;
        self.crypto_available = !self.our_public_key.is_empty();

        if !self.our_public_key.is_empty() {
            let mut out = Vec::new();
            out.extend_from_slice(&(self.our_public_key.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.our_public_key);
            out.extend_from_slice(&(self.our_private_key.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.our_private_key);
            match crate::security::atomic_write(&key_path, &out, true) {
                Ok(()) => tracing::info!("Generated and saved new RSA keypair to {}", key_path.display()),
                Err(e) => tracing::warn!("Failed to save RSA keypair: {e}"),
            }
        }
    }

    pub fn get_or_create(&mut self, user_hash: [u8; 16]) -> &mut CreditRecord {
        self.credits.entry(user_hash).or_insert_with(|| CreditRecord::new(user_hash))
    }

    /// eMule: only accumulate credits when identity is verified via SecIdent.
    /// When crypto is available we require `IdentState::Verified` — Unknown,
    /// Needed, Failed, and BadGuy all reject. A peer that never completes the
    /// public-key + challenge/response exchange cannot farm credits.
    /// When crypto is unavailable (no local RSA key) we fall back to the
    /// permissive behavior but still reject Failed/BadGuy.
    /// Returns false if credits were rejected due to identity state.
    pub fn add_uploaded(&mut self, user_hash: [u8; 16], bytes: u64) -> bool {
        let crypto = self.crypto_available;
        let record = self.get_or_create(user_hash);
        if crypto {
            if !matches!(record.ident_state, IdentState::Verified) {
                return false;
            }
        } else if matches!(record.ident_state, IdentState::Failed | IdentState::BadGuy) {
            return false;
        }
        record.uploaded = record.uploaded.saturating_add(bytes);
        record.last_seen = chrono::Utc::now().timestamp();
        true
    }

    pub fn add_downloaded(&mut self, user_hash: [u8; 16], bytes: u64) -> bool {
        let crypto = self.crypto_available;
        let record = self.get_or_create(user_hash);
        if crypto {
            if !matches!(record.ident_state, IdentState::Verified) {
                return false;
            }
        } else if matches!(record.ident_state, IdentState::Failed | IdentState::BadGuy) {
            return false;
        }
        record.downloaded = record.downloaded.saturating_add(bytes);
        record.last_seen = chrono::Utc::now().timestamp();
        true
    }

    /// eMule IS_IDBADGUY: record the IP only when identity is first verified
    /// (ident_ip == 0). Subsequent calls leave ident_ip unchanged so that
    /// `get_current_ident_state` can detect IP changes dynamically without
    /// permanently mutating stored state.
    pub fn check_identity_ip(&mut self, user_hash: [u8; 16], current_ip: u32) {
        let record = self.get_or_create(user_hash);
        if record.ident_state == IdentState::Verified && record.ident_ip == 0 {
            record.ident_ip = current_ip;
        }
    }

    /// eMule CClientCredits::GetCurrentIdentState(dwForIP): returns BadGuy
    /// dynamically when a verified client's IP doesn't match, without mutating
    /// the stored ident_state.
    pub fn get_current_ident_state(&self, user_hash: &[u8; 16], current_ip: u32) -> IdentState {
        match self.credits.get(user_hash) {
            Some(record) => {
                if record.ident_state == IdentState::Verified
                    && record.ident_ip != 0
                    && record.ident_ip != current_ip
                {
                    IdentState::BadGuy
                } else {
                    record.ident_state
                }
            }
            None => IdentState::Unknown,
        }
    }

    /// eMule credit ratio formula from CClientCredits::GetScoreRatio.
    /// Returns 1.0 for bad identity states when crypto is available.
    pub fn get_score_ratio(&self, user_hash: &[u8; 16], current_ip: u32) -> f64 {
        let record = match self.credits.get(user_hash) {
            Some(r) => r,
            None => return MIN_CREDIT_RATIO,
        };
        let ident = self.get_current_ident_state(user_hash, current_ip);
        if self.crypto_available && matches!(ident, IdentState::Failed | IdentState::BadGuy | IdentState::Needed) {
            return MIN_CREDIT_RATIO;
        }

        // eMule: if downloaded < 1MB, return 1.0 (no credits for trivial transfers)
        if record.downloaded < 1_048_576 {
            return MIN_CREDIT_RATIO;
        }

        let uploaded = record.uploaded.max(1) as f64;
        let downloaded = record.downloaded as f64;

        let ratio1 = (downloaded * 2.0) / uploaded;
        let ratio2 = (downloaded / 1_048_576.0 + 2.0).sqrt();
        // eMule result3: linear ramp from 1.0 at 1 MB to 3.34 at ~9.2 MB, then 10.0
        let ratio3 = if downloaded < 9_646_899.0 {
            (downloaded - 1_048_576.0) / 8_598_323.0 * 2.34 + 1.0
        } else {
            MAX_CREDIT_RATIO
        };

        ratio1.min(ratio2).min(ratio3).min(MAX_CREDIT_RATIO).max(MIN_CREDIT_RATIO)
    }

    /// Queue score for upload slot selection.
    /// Matches eMule CUpDownClient::GetScore: wait_seconds * credit_ratio * (file_prio / 10)
    pub fn get_queue_score(&self, user_hash: &[u8; 16], wait_secs: u64, file_priority: f64, current_ip: u32) -> f64 {
        let ident = self.get_current_ident_state(user_hash, current_ip);
        if matches!(ident, IdentState::BadGuy) {
            return 0.0;
        }
        let ratio = self.get_score_ratio(user_hash, current_ip);
        let wait = wait_secs as f64;
        wait * ratio * file_priority
    }

    pub fn our_public_key(&self) -> &[u8] {
        &self.our_public_key
    }

    pub fn secident_request_state(&self, user_hash: &[u8; 16], current_ip: u32, peer_level: u8) -> Option<u8> {
        if !self.crypto_available {
            return None;
        }
        if peer_level == 0 {
            return None;
        }
        match self.credits.get(user_hash) {
            Some(record) if !record.public_key.is_empty()
                && record.ident_state == IdentState::Verified
                && record.ident_ip == current_ip => None,
            Some(record) if !record.public_key.is_empty() => Some(1),
            _ => Some(2),
        }
    }

    pub fn has_public_key(&self, user_hash: &[u8; 16]) -> bool {
        self.credits.get(user_hash).map(|r| !r.public_key.is_empty()).unwrap_or(false)
    }

    /// Returns true if this peer has uploaded significant data to us (>1 MB),
    /// meaning we're actively benefiting from their uploads and they deserve
    /// a queue score bonus (eMule download-bonus equivalent).
    pub fn has_download_bonus(&self, user_hash: &[u8; 16]) -> bool {
        self.credits.get(user_hash).map(|r| r.downloaded > 1_048_576).unwrap_or(false)
    }

    pub fn create_signature_for_peer(
        &self,
        peer_user_hash: &[u8; 16],
        challenge: u32,
        challenge_ip: u32,
        challenge_ip_kind: Option<u8>,
    ) -> Vec<u8> {
        let record = match self.credits.get(peer_user_hash) {
            Some(r) if !r.public_key.is_empty() => r,
            _ => return Vec::new(),
        };
        sign_challenge(
            &self.our_private_key,
            &record.public_key,
            challenge,
            challenge_ip,
            challenge_ip_kind,
        )
    }

    pub fn verify_signature(
        &self,
        user_hash: &[u8; 16],
        challenge: u32,
        challenge_ip_kind: Option<u8>,
        peer_ip: u32,
        local_ip_for_remoteclient: u32,
        signature: &[u8],
    ) -> bool {
        let record = match self.credits.get(user_hash) {
            Some(r) if !r.public_key.is_empty() => r,
            _ => return false,
        };
        verify_challenge(
            &record.public_key,
            &self.our_public_key,
            challenge,
            challenge_ip_kind,
            peer_ip,
            local_ip_for_remoteclient,
            signature,
        )
    }

    pub fn set_public_key(&mut self, user_hash: [u8; 16], key: Vec<u8>) {
        if key.len() > 4096 {
            tracing::warn!("Rejecting oversized public key ({} bytes) from {}", key.len(), hex::encode(user_hash));
            return;
        }
        let record = self.get_or_create(user_hash);
        record.public_key = key;
    }

    pub fn set_ident_state(&mut self, user_hash: [u8; 16], state: IdentState) {
        let record = self.get_or_create(user_hash);
        // eMule Verified(): on first-time crypto verification, reset pre-existing
        // credits to prevent credit theft via identity spoofing before crypto
        // was established. Only reset if transitioning from Unknown → Verified,
        // meaning the record existed without any prior crypto handshake.
        if state == IdentState::Verified
            && record.ident_state == IdentState::Unknown
            && (record.uploaded > 0 || record.downloaded > 0)
        {
            // Log only the user-hash prefix — the full 16-byte value is PII
            // that can be correlated across sessions. 4 bytes is enough for a
            // developer to correlate with a peer log entry.
            tracing::info!(
                "Resetting credits for peer {}\u{2026} on first SecureIdent verification (was up={} down={})",
                &hex::encode(user_hash)[..8], record.uploaded, record.downloaded
            );
            record.uploaded = 1;
            record.downloaded = 1;
        }
        record.ident_state = state;
    }

    pub fn all_records(&self) -> Vec<&CreditRecord> {
        self.credits.values().collect()
    }

    pub fn cleanup_stale(&mut self, max_age_days: i64) {
        let cutoff = chrono::Utc::now().timestamp() - (max_age_days * 86400);
        self.credits.retain(|_, r| r.last_seen > cutoff);
    }

    /// Serialize credits to bytes (eMule clients.met format).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let records: Vec<_> = self.credits.values().filter(|r| r.uploaded > 0 || r.downloaded > 0).collect();
        buf.extend_from_slice(&(records.len() as u32).to_le_bytes());
        for r in &records {
            buf.extend_from_slice(&r.user_hash);
            buf.extend_from_slice(&r.uploaded.to_le_bytes());
            buf.extend_from_slice(&r.downloaded.to_le_bytes());
            buf.extend_from_slice(&r.last_seen.to_le_bytes());
            buf.extend_from_slice(&(r.public_key.len() as u16).to_le_bytes());
            buf.extend_from_slice(&r.public_key);
        }
        buf
    }

    /// Load credits from clients.met.
    pub fn load_from_file(&mut self, path: &std::path::Path) -> std::io::Result<usize> {
        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 50 * 1024 * 1024 {
            tracing::warn!("clients.met too large ({} bytes), skipping", metadata.len());
            return Ok(0);
        }
        let data = std::fs::read(path)?;
        if data.len() < 4 { return Ok(0); }
        let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut offset = 4;
        let mut loaded = 0;
        for _ in 0..count.min(50000) {
            if offset + 16 + 8 + 8 + 8 + 2 > data.len() { break; }
            let mut user_hash = [0u8; 16];
            user_hash.copy_from_slice(&data[offset..offset + 16]);
            offset += 16;
            let uploaded = u64::from_le_bytes(
                data[offset..offset + 8].try_into().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad credit record"))?,
            );
            offset += 8;
            let downloaded = u64::from_le_bytes(
                data[offset..offset + 8].try_into().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad credit record"))?,
            );
            offset += 8;
            let last_seen = i64::from_le_bytes(
                data[offset..offset + 8].try_into().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad credit record"))?,
            );
            offset += 8;
            let pk_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let public_key = if offset + pk_len <= data.len() {
                let pk = data[offset..offset + pk_len].to_vec();
                offset += pk_len;
                pk
            } else {
                break;
            };
            let record = CreditRecord {
                user_hash,
                uploaded,
                downloaded,
                last_seen,
                public_key,
                ident_state: IdentState::Unknown,
                ident_ip: 0,
            };
            self.credits.insert(user_hash, record);
            loaded += 1;
        }
        tracing::info!("Loaded {} credit records from {}", loaded, path.display());
        Ok(loaded)
    }
}

fn generate_rsa_keypair() -> (Vec<u8>, Vec<u8>) {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
    // 384-bit RSA matches eMule's SecureIdent key size for wire-level compatibility.
    // This is intentionally low by modern standards; it provides credit-abuse
    // deterrence rather than strong cryptographic security.
    let bits = 384;
    let private_key = match RsaPrivateKey::new(&mut rng, bits) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("RSA keygen failed: {e}, credits will be disabled");
            return (Vec::new(), Vec::new());
        }
    };
    let public_key = private_key.to_public_key();

    let priv_der = match private_key.to_pkcs8_der() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("RSA private key encode failed: {e}");
            return (Vec::new(), Vec::new());
        }
    };
    // Emit the public key as an X.509 SubjectPublicKeyInfo (SPKI) — the
    // SEQUENCE { AlgorithmIdentifier{rsaEncryption,NULL}, BIT STRING{n,e} }
    // envelope. That's what eMule's Crypto++ produces from
    // `pubkey.GetMaterial().Save(asink)` in CClientCreditsList::InitalizeCrypting,
    // and that's the format its `RSASSA_PKCS1v15_SHA_Verifier(StringSource&)`
    // constructor feeds into X509PublicKey::BERDecode when verifying our
    // signatures in CClientCreditsList::VerifyIdent. An earlier version of
    // this code used the inner `to_pkcs1_der()` RSAPublicKey form — that
    // parses fine with our own rsa-crate fallback on verify, but Crypto++'s
    // X509PublicKey BERDecode refuses it, which silently tripped the
    // `try {...} catch(...)` in VerifyIdent and pinned our peers at
    // `Identification: Invalid` even though uploads were flowing. ~78 bytes
    // for a 384-bit key, well within eMule's `MAXPUBKEYSIZE = 80`.
    let pub_der = match public_key.to_public_key_der() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("RSA public key encode failed: {e}");
            return (Vec::new(), Vec::new());
        }
    };

    (pub_der.as_ref().to_vec(), priv_der.as_bytes().to_vec())
}

/// Re-encode a cached public key as SPKI if it's in the bare PKCS#1
/// `RSAPublicKey` form. Users who ran an older build of Ember have an
/// on-disk `cryptkey.dat` whose `our_public_key` field is PKCS#1 — valid
/// cryptographically, but incompatible with eMule's X509PublicKey decoder
/// (see `generate_rsa_keypair` above). On load we parse whichever form
/// we find and normalise to SPKI in memory so every outgoing OP_PUBLICKEY
/// uses the eMule-compatible envelope. Returns `None` and leaves the
/// original bytes alone if the key parses as neither (likely corrupt,
/// caller will regenerate).
fn normalize_public_key_to_spki(pub_der: &[u8]) -> Option<Vec<u8>> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
    use rsa::RsaPublicKey;

    if RsaPublicKey::from_public_key_der(pub_der).is_ok() {
        return Some(pub_der.to_vec());
    }
    let key = RsaPublicKey::from_pkcs1_der(pub_der).ok()?;
    let spki = key.to_public_key_der().ok()?;
    Some(spki.as_ref().to_vec())
}

fn sign_challenge(
    private_key_der: &[u8],
    peer_public_key: &[u8],
    challenge: u32,
    challenge_ip: u32,
    challenge_ip_kind: Option<u8>,
) -> Vec<u8> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::SignerMut;
    use rsa::RsaPrivateKey;
    use sha1::Sha1;

    let key = match RsaPrivateKey::from_pkcs8_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };
    let mut signing_key = SigningKey::<Sha1>::new(key);

    let mut msg = Vec::with_capacity(peer_public_key.len() + 9);
    msg.extend_from_slice(peer_public_key);
    msg.extend_from_slice(&challenge.to_le_bytes());
    if let Some(kind) = challenge_ip_kind {
        msg.extend_from_slice(&challenge_ip.to_le_bytes());
        msg.push(kind);
    }

    match signing_key.try_sign(&msg) {
        Ok(sig) => {
            let bytes: Box<[u8]> = sig.into();
            bytes.into_vec()
        }
        Err(_) => Vec::new(),
    }
}

fn verify_challenge(
    public_key_der: &[u8],
    our_public_key: &[u8],
    challenge: u32,
    challenge_ip_kind: Option<u8>,
    peer_ip: u32,
    local_ip_for_remoteclient: u32,
    signature: &[u8],
) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    use sha1::Sha1;

    // eMule sends raw PKCS#1 RSA public key DER {n, e}. Try PKCS#1 first,
    // then fall back to SPKI for forward compatibility.
    let key = match RsaPublicKey::from_pkcs1_der(public_key_der)
        .or_else(|_| {
            use rsa::pkcs8::DecodePublicKey;
            RsaPublicKey::from_public_key_der(public_key_der)
        }) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let verifying_key = VerifyingKey::<Sha1>::new(key);

    let mut msg = Vec::with_capacity(our_public_key.len() + 9);
    msg.extend_from_slice(our_public_key);
    msg.extend_from_slice(&challenge.to_le_bytes());
    if let Some(kind) = challenge_ip_kind {
        let challenge_ip = match kind {
            CRYPT_CIP_LOCALCLIENT => peer_ip,
            CRYPT_CIP_REMOTECLIENT => local_ip_for_remoteclient,
            CRYPT_CIP_NONECLIENT => 0,
            _ => return false,
        };
        msg.extend_from_slice(&challenge_ip.to_le_bytes());
        msg.push(kind);
    }

    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(&msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// eMule's Crypto++ `RSASSA_PKCS1v15_SHA_Verifier(StringSource&)`
    /// constructor feeds the raw OP_PUBLICKEY bytes into
    /// `X509PublicKey::BERDecode`, which expects a SubjectPublicKeyInfo
    /// envelope: `SEQUENCE { AlgorithmIdentifier{rsaEncryption, NULL},
    /// BIT STRING { SEQUENCE { n, e } } }`. If we emit bare PKCS#1
    /// `SEQUENCE { n, e }` eMule throws inside the try/catch and our
    /// session ends up at IS_IDFAILED. Guard against regressing back to
    /// PKCS#1 by asserting the generated key starts with the SPKI outer
    /// SEQUENCE followed immediately by the algorithm-identifier
    /// SEQUENCE whose contents start with the rsaEncryption OID.
    #[test]
    fn generated_public_key_is_spki_and_fits_emule_buffer() {
        let (pub_der, priv_der) = generate_rsa_keypair();
        assert!(!pub_der.is_empty() && !priv_der.is_empty(), "keygen failed");
        assert!(
            pub_der.len() <= 80,
            "pub key {} bytes exceeds eMule MAXPUBKEYSIZE=80",
            pub_der.len()
        );

        // SPKI byte-prefix sanity — not a full ASN.1 parse, just enough to
        // distinguish PKCS#1 `SEQUENCE { INTEGER n, INTEGER e }` (which
        // starts 0x30 <len> 0x02 ...) from SPKI `SEQUENCE { SEQUENCE {
        // OID rsaEncryption, NULL }, BIT STRING ... }` (starts 0x30 <len>
        // 0x30 0x0D 0x06 0x09 ...).
        assert_eq!(pub_der[0], 0x30, "SPKI must start with SEQUENCE tag");
        // Skip the outer SEQUENCE length (1 or 2 bytes depending on content size).
        let algid_pos = if pub_der[1] & 0x80 == 0 {
            2
        } else {
            2 + (pub_der[1] & 0x7F) as usize
        };
        assert_eq!(
            pub_der[algid_pos], 0x30,
            "SPKI body must begin with AlgorithmIdentifier SEQUENCE, got 0x{:02X} — \
             we probably regressed to PKCS#1 output",
            pub_der[algid_pos]
        );
        assert_eq!(pub_der[algid_pos + 2], 0x06, "AlgorithmIdentifier must start with OID");

        // A round-trip through the decoder we actually use on verify must work:
        // this is the same path eMule takes before it tries to crypto-verify us.
        use rsa::pkcs8::DecodePublicKey;
        rsa::RsaPublicKey::from_public_key_der(&pub_der).expect("generated key must parse as SPKI");
    }

    /// Confirm `normalize_public_key_to_spki` upgrades a legacy
    /// PKCS#1-encoded public key (what older Ember builds persisted in
    /// cryptkey.dat) to the SPKI envelope on load, so existing users
    /// don't have to delete their keyfile to get secure identification
    /// working.
    #[test]
    fn normalize_pkcs1_public_key_to_spki() {
        use rsa::pkcs1::EncodeRsaPublicKey;
        use rsa::pkcs8::DecodePublicKey;
        use rsa::RsaPrivateKey;

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 384).expect("keygen");
        let pkcs1 = private_key
            .to_public_key()
            .to_pkcs1_der()
            .expect("pkcs1 encode")
            .as_ref()
            .to_vec();
        assert!(
            rsa::RsaPublicKey::from_public_key_der(&pkcs1).is_err(),
            "test fixture precondition: raw PKCS#1 must NOT parse as SPKI",
        );

        let spki = normalize_public_key_to_spki(&pkcs1).expect("normalisation returned None");
        rsa::RsaPublicKey::from_public_key_der(&spki)
            .expect("normalised key must parse as SPKI");
        assert_ne!(spki, pkcs1, "normalisation must actually re-encode the key");

        // A key that's already SPKI should come back byte-identical.
        let already_spki = normalize_public_key_to_spki(&spki).expect("idempotent normalise");
        assert_eq!(already_spki, spki);
    }
}
