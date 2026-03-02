use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

const MAX_CREDIT_RATIO: f64 = 10.0;
const MIN_CREDIT_RATIO: f64 = 1.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentState {
    Unknown,
    Verified,
    Failed,
}

#[derive(Debug, Clone)]
pub struct CreditRecord {
    pub user_hash: [u8; 16],
    pub uploaded: u64,
    pub downloaded: u64,
    pub last_seen: i64,
    pub public_key: Vec<u8>,
    pub ident_state: IdentState,
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
}

impl CreditManager {
    pub fn new() -> Self {
        Self {
            credits: HashMap::new(),
            our_public_key: Vec::new(),
            our_private_key: Vec::new(),
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

        if !self.our_public_key.is_empty() {
            let mut out = Vec::new();
            out.extend_from_slice(&(self.our_public_key.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.our_public_key);
            out.extend_from_slice(&(self.our_private_key.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.our_private_key);
            if let Err(e) = std::fs::write(&key_path, &out) {
                tracing::warn!("Failed to save RSA keypair: {e}");
            } else {
                tracing::info!("Generated and saved new RSA keypair to {}", key_path.display());
            }
        }
    }

    pub fn get_or_create(&mut self, user_hash: [u8; 16]) -> &mut CreditRecord {
        self.credits.entry(user_hash).or_insert_with(|| CreditRecord::new(user_hash))
    }

    pub fn add_uploaded(&mut self, user_hash: [u8; 16], bytes: u64) {
        let record = self.get_or_create(user_hash);
        record.uploaded = record.uploaded.saturating_add(bytes);
        record.last_seen = chrono::Utc::now().timestamp();
    }

    pub fn add_downloaded(&mut self, user_hash: [u8; 16], bytes: u64) {
        let record = self.get_or_create(user_hash);
        record.downloaded = record.downloaded.saturating_add(bytes);
        record.last_seen = chrono::Utc::now().timestamp();
    }

    /// eMule credit ratio formula from CClientCredits::GetScoreRatio.
    /// Uses all three eMule ratio formulas with 1MB minimum threshold.
    pub fn get_score_ratio(&self, user_hash: &[u8; 16]) -> f64 {
        let record = match self.credits.get(user_hash) {
            Some(r) => r,
            None => return MIN_CREDIT_RATIO,
        };

        // eMule: if downloaded < 1MB, return 1.0 (no credits for trivial transfers)
        if record.downloaded < 1_048_576 {
            return MIN_CREDIT_RATIO;
        }

        let uploaded = record.uploaded.max(1) as f64;
        let downloaded = record.downloaded as f64;

        let ratio1 = (downloaded * 2.0) / uploaded;
        let ratio2 = (downloaded / 1_048_576.0 + 2.0).sqrt();
        // ratio3: linear ramp from 1.0 to ~3.34 for the first ~9.2 MB, then cap at 10.0
        let ratio3 = if downloaded < 9_646_899.0 {
            (downloaded - 1_048_576.0) / 8_598_323.0 * 2.34 + 1.0
        } else {
            MAX_CREDIT_RATIO
        };

        ratio1.min(ratio2).min(ratio3).min(MAX_CREDIT_RATIO).max(MIN_CREDIT_RATIO)
    }

    /// Queue score for upload slot selection.
    /// score = effective_wait_time * credit_ratio * file_priority
    /// eMule: unverified clients don't benefit from accumulated wait time.
    pub fn get_queue_score(&self, user_hash: &[u8; 16], wait_secs: u64, file_priority: f64) -> f64 {
        let ratio = self.get_score_ratio(user_hash);
        let effective_wait = if let Some(record) = self.credits.get(user_hash) {
            match record.ident_state {
                IdentState::Failed => (wait_secs as f64 * 0.1).max(1.0),
                IdentState::Unknown => wait_secs as f64 * 0.5,
                IdentState::Verified => wait_secs as f64,
            }
        } else {
            wait_secs as f64
        };
        effective_wait * ratio * file_priority
    }

    pub fn our_public_key(&self) -> &[u8] {
        &self.our_public_key
    }

    pub fn create_signature(&self, challenge: u32, ip_for_sign: u32) -> Vec<u8> {
        sign_challenge(&self.our_private_key, challenge, ip_for_sign)
    }

    pub fn verify_signature(&self, user_hash: &[u8; 16], challenge: u32, ip_for_sign: u32, signature: &[u8]) -> bool {
        let record = match self.credits.get(user_hash) {
            Some(r) if !r.public_key.is_empty() => r,
            _ => return false,
        };
        verify_challenge(&record.public_key, challenge, ip_for_sign, signature)
    }

    pub fn set_public_key(&mut self, user_hash: [u8; 16], key: Vec<u8>) {
        let record = self.get_or_create(user_hash);
        record.public_key = key;
    }

    pub fn set_ident_state(&mut self, user_hash: [u8; 16], state: IdentState) {
        let record = self.get_or_create(user_hash);
        record.ident_state = state;
    }

    pub fn all_records(&self) -> Vec<&CreditRecord> {
        self.credits.values().collect()
    }

    pub fn cleanup_stale(&mut self, max_age_days: i64) {
        let cutoff = chrono::Utc::now().timestamp() - (max_age_days * 86400);
        self.credits.retain(|_, r| r.last_seen > cutoff);
    }
}

fn generate_rsa_keypair() -> (Vec<u8>, Vec<u8>) {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rsa::RsaPrivateKey;

    let mut rng = rand::thread_rng();
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
    let pub_der = match public_key.to_public_key_der() {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("RSA public key encode failed: {e}");
            return (Vec::new(), Vec::new());
        }
    };

    (pub_der.as_ref().to_vec(), priv_der.as_bytes().to_vec())
}

fn sign_challenge(private_key_der: &[u8], challenge: u32, ip_for_sign: u32) -> Vec<u8> {
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::SignerMut;
    use rsa::RsaPrivateKey;
    use sha1::Sha1;

    let key = match RsaPrivateKey::from_pkcs8_der(private_key_der) {
        Ok(k) => k,
        Err(_) => return Vec::new(),
    };
    let mut signing_key = SigningKey::<Sha1>::new_unprefixed(key);

    let mut msg = Vec::with_capacity(8);
    msg.extend_from_slice(&challenge.to_le_bytes());
    msg.extend_from_slice(&ip_for_sign.to_le_bytes());

    match signing_key.try_sign(&msg) {
        Ok(sig) => {
            use signature::SignatureEncoding;
            sig.to_vec()
        }
        Err(_) => Vec::new(),
    }
}

fn verify_challenge(public_key_der: &[u8], challenge: u32, ip_for_sign: u32, signature: &[u8]) -> bool {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    use sha1::Sha1;

    let key = match RsaPublicKey::from_public_key_der(public_key_der) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let verifying_key = VerifyingKey::<Sha1>::new_unprefixed(key);

    let mut msg = Vec::with_capacity(8);
    msg.extend_from_slice(&challenge.to_le_bytes());
    msg.extend_from_slice(&ip_for_sign.to_le_bytes());

    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    verifying_key.verify(&msg, &sig).is_ok()
}
