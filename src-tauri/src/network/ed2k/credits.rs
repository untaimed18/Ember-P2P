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
                            self.our_public_key = pub_key;
                            self.our_private_key = priv_key;
                            self.crypto_available = true;
                            tracing::info!("Loaded RSA keypair from {}", key_path.display());
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
            let tmp_path = key_path.with_extension("dat.tmp");
            if let Err(e) = std::fs::write(&tmp_path, &out) {
                tracing::warn!("Failed to save RSA keypair: {e}");
            } else {
                crate::security::restrict_file_permissions(&tmp_path);
                if let Err(e) = std::fs::rename(&tmp_path, &key_path) {
                    tracing::warn!("Failed to finalize RSA keypair save: {e}");
                } else {
                    tracing::info!("Generated and saved new RSA keypair to {}", key_path.display());
                }
            }
        }
    }

    pub fn get_or_create(&mut self, user_hash: [u8; 16]) -> &mut CreditRecord {
        self.credits.entry(user_hash).or_insert_with(|| CreditRecord::new(user_hash))
    }

    /// eMule: only accumulate credits when identity is verified.
    /// Rejects credits for Failed/BadGuy peers regardless of crypto availability.
    /// Returns false if credits were rejected due to identity state.
    pub fn add_uploaded(&mut self, user_hash: [u8; 16], bytes: u64) -> bool {
        let crypto = self.crypto_available;
        let record = self.get_or_create(user_hash);
        if matches!(record.ident_state, IdentState::Failed | IdentState::BadGuy) {
            return false;
        }
        if crypto && matches!(record.ident_state, IdentState::Needed) {
            return false;
        }
        record.uploaded = record.uploaded.saturating_add(bytes);
        record.last_seen = chrono::Utc::now().timestamp();
        true
    }

    pub fn add_downloaded(&mut self, user_hash: [u8; 16], bytes: u64) -> bool {
        let crypto = self.crypto_available;
        let record = self.get_or_create(user_hash);
        if matches!(record.ident_state, IdentState::Failed | IdentState::BadGuy) {
            return false;
        }
        if crypto && matches!(record.ident_state, IdentState::Needed) {
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
            tracing::info!(
                "Resetting credits for {} on first SecureIdent verification (was up={} down={})",
                hex::encode(user_hash), record.uploaded, record.downloaded
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
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::EncodePrivateKey;
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
    // eMule uses raw PKCS#1 RSA public key DER {n, e} (Crypto++ Save()),
    // NOT SPKI (SubjectPublicKeyInfo). Use to_pkcs1_der for compatibility.
    let pub_der = match public_key.to_pkcs1_der() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("RSA public key encode failed: {e}");
            return (Vec::new(), Vec::new());
        }
    };

    (pub_der.as_ref().to_vec(), priv_der.as_bytes().to_vec())
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
