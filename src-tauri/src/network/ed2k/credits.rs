use std::collections::HashMap;
use zeroize::ZeroizeOnDrop;

const MAX_CREDIT_RATIO: f64 = 10.0;
const MIN_CREDIT_RATIO: f64 = 1.0;

// --- Ember credit scoring constants ---
//
// The Ember credit system layers three multiplicative factors on top of the
// baseline eMule credit-ratio formula: time-decayed ratio, session
// reliability, and upload-speed fairness. Each factor is clamped to a
// narrow band so no single signal can dominate scoring; the plan target is
// "slightly more nuanced than eMule", not "completely rewrite priority".
//
// Exposed at module level so the unit tests can reference the same
// constants the runtime uses — avoids the "tests pass but drift from
// code" trap.

/// Half-life for the exponential credit-ratio decay, in seconds. A peer
/// who uploaded 10 GB 90 days ago counts for half as much as one who
/// uploaded 10 GB yesterday. Tuned to roughly match observed session
/// inter-arrival times on a typical P2P swarm — longer and the decay
/// becomes imperceptible; shorter and even daily users get penalised.
pub(crate) const EMBER_DECAY_HALF_LIFE_SECS: f64 = 90.0 * 86_400.0;

/// Minimum `completed / total` reliability multiplier, applied to a peer
/// with 0 % completion. A fully unreliable peer still gets some queue
/// wait credit so they aren't completely shut out (plan spec: 0.8).
pub(crate) const EMBER_RELIABILITY_MIN: f64 = 0.8;
/// Maximum reliability multiplier at 100 % completion (plan spec: 1.5).
pub(crate) const EMBER_RELIABILITY_MAX: f64 = 1.5;

/// Minimum speed-fairness multiplier at far-below-baseline upload rate.
pub(crate) const EMBER_SPEED_FACTOR_MIN: f64 = 0.9;
/// Maximum speed-fairness multiplier at or above 2× the baseline.
pub(crate) const EMBER_SPEED_FACTOR_MAX: f64 = 1.2;

/// Baseline upload rate (bytes/sec) that maps to a neutral 1.0 speed
/// multiplier. Uploads below this get penalised down to
/// `EMBER_SPEED_FACTOR_MIN`; uploads at 2× and above cap at
/// `EMBER_SPEED_FACTOR_MAX`. 512 KiB/s is a reasonable "decent home
/// broadband upload" line — generous enough that most honest peers
/// sit near 1.0 rather than eating a penalty.
pub(crate) const EMBER_SPEED_BASELINE_BPS: f64 = 512.0 * 1024.0;

/// EWMA smoothing weight for new session speed samples. The new sample
/// contributes `EMBER_SPEED_EWMA_ALPHA` and the prior average
/// contributes `1 - EMBER_SPEED_EWMA_ALPHA`. 0.3 gives the series a
/// visible memory (prior ~3 sessions still show through) while still
/// tracking persistent speed changes over ~10 sessions.
pub(crate) const EMBER_SPEED_EWMA_ALPHA: f64 = 0.3;

/// Minimum session duration (seconds) that's allowed to update the EWMA
/// speed estimate. Sub-second sessions are dominated by handshake
/// overhead and produce wildly noisy "speeds"; ignoring them keeps the
/// EWMA honest for the real data-transfer sessions it's trying to
/// characterise.
pub(crate) const EMBER_MIN_SESSION_SECS_FOR_SPEED: u64 = 5;

/// Minimum downloaded bytes before the decayed ratio contributes. Mirrors
/// the eMule `downloaded < 1 MiB → ratio = 1.0` guard so a peer can't
/// game scoring by trickling a few bytes and then riding a miraculously
/// good ratio.
pub(crate) const EMBER_MIN_DOWNLOADED_FOR_RATIO: u64 = 1_048_576;

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

/// Enhanced credit record for verified Ember peers.
///
/// Identity is anchored on the peer's 32-byte Ed25519 public key rather
/// than the wire `user_hash` so a peer can't farm credit by cycling
/// user_hash bytes — the credit row is bound to a keypair they must
/// prove possession of via the PoP state machine in `ember_auth.rs`.
/// `ident_verified == true` implies the peer completed full Ed25519
/// proof-of-possession on at least one session; binding-only peers
/// (older Ember releases that don't ship the AUTH opcodes) still get a
/// record so their activity is tracked, but they don't earn the
/// enhanced scoring bonuses until they pass PoP on a future session.
///
/// `completed_sessions / total_sessions` rewards peers who stay
/// connected through a full upload session rather than disconnecting
/// mid-transfer. `avg_upload_speed` is an EWMA of observed bytes/sec so
/// artificially throttled uploaders don't score as high as peers doing
/// honest fast work.
#[derive(Debug, Clone)]
pub struct EmberCreditRecord {
    pub pub_key: [u8; 32],
    pub uploaded: u64,
    pub downloaded: u64,
    pub last_upload_time: i64,
    pub last_download_time: i64,
    pub completed_sessions: u32,
    pub total_sessions: u32,
    pub avg_upload_speed: u64,
    pub last_seen: i64,
    pub ident_verified: bool,
}

impl EmberCreditRecord {
    pub fn new(pub_key: [u8; 32]) -> Self {
        Self {
            pub_key,
            uploaded: 0,
            downloaded: 0,
            last_upload_time: 0,
            last_download_time: 0,
            completed_sessions: 0,
            total_sessions: 0,
            avg_upload_speed: 0,
            last_seen: chrono::Utc::now().timestamp(),
            ident_verified: false,
        }
    }

    /// Reliability multiplier: `EMBER_RELIABILITY_MIN` at 0 %
    /// completion → `EMBER_RELIABILITY_MAX` at 100 %. Neutral (1.0)
    /// for new peers with no session history so they aren't
    /// penalised for having no track record. Visible units keep the
    /// formula debuggable in logs without a separate helper.
    pub fn reliability_multiplier(&self) -> f64 {
        if self.total_sessions == 0 {
            return 1.0;
        }
        let completed = self.completed_sessions.min(self.total_sessions) as f64;
        let total = self.total_sessions as f64;
        let rate = completed / total;
        EMBER_RELIABILITY_MIN + rate * (EMBER_RELIABILITY_MAX - EMBER_RELIABILITY_MIN)
    }

    /// Speed-fairness multiplier: piecewise-linear ramp centred on
    /// `EMBER_SPEED_BASELINE_BPS`. No sample (0 bytes/sec average)
    /// is neutral so a first-contact peer isn't penalised, but ANY
    /// recorded sample enters the band — including very slow uploads
    /// that tip towards `EMBER_SPEED_FACTOR_MIN`.
    pub fn speed_multiplier(&self) -> f64 {
        if self.avg_upload_speed == 0 {
            return 1.0;
        }
        let speed = self.avg_upload_speed as f64;
        let baseline = EMBER_SPEED_BASELINE_BPS;
        if speed >= 2.0 * baseline {
            EMBER_SPEED_FACTOR_MAX
        } else if speed >= baseline {
            // Interpolate 1.0 → max over [baseline, 2×baseline].
            1.0 + (EMBER_SPEED_FACTOR_MAX - 1.0) * ((speed - baseline) / baseline)
        } else {
            // Interpolate min → 1.0 over [0, baseline]. Clamp the
            // bottom at MIN so an absurdly slow upload (bytes/sec in
            // the single digits) doesn't punch below the floor.
            let frac = (speed / baseline).clamp(0.0, 1.0);
            EMBER_SPEED_FACTOR_MIN + frac * (1.0 - EMBER_SPEED_FACTOR_MIN)
        }
    }

    /// Apply a new session-observation to the EWMA. Ignores sessions
    /// too short to produce a useful speed sample (handshake noise
    /// dominates). The first real sample seeds the EWMA rather than
    /// being smoothed with the 0 default — that way a fresh record
    /// reflects what we actually measured rather than half-mixing
    /// with a zero.
    pub fn record_session(&mut self, bytes_transferred: u64, duration_secs: u64, completed: bool) {
        self.total_sessions = self.total_sessions.saturating_add(1);
        if completed {
            self.completed_sessions = self.completed_sessions.saturating_add(1);
        }
        if duration_secs >= EMBER_MIN_SESSION_SECS_FOR_SPEED && bytes_transferred > 0 {
            let sample = (bytes_transferred as f64) / (duration_secs as f64);
            let new_avg = if self.avg_upload_speed == 0 {
                sample
            } else {
                EMBER_SPEED_EWMA_ALPHA * sample
                    + (1.0 - EMBER_SPEED_EWMA_ALPHA) * (self.avg_upload_speed as f64)
            };
            self.avg_upload_speed = new_avg.round().max(0.0) as u64;
        }
        self.last_seen = chrono::Utc::now().timestamp();
    }
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
    /// Enhanced credit records for Ember peers, keyed on Ed25519
    /// public key. Parallel to `credits` rather than sharing storage
    /// because the key material is different (32-byte pubkey vs.
    /// 16-byte user_hash) and the scoring formula is different
    /// (decay + reliability + speed factors, not just bytes).
    /// Only populated for peers that have either passed binding
    /// verification or full PoP on at least one session.
    #[zeroize(skip)]
    ember_credits: HashMap<[u8; 32], EmberCreditRecord>,
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
            ember_credits: HashMap::new(),
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
        // Every mutating credit operation (set_public_key, set_ident_state,
        // check_identity_ip, add_uploaded, add_downloaded) routes through
        // here, so this is the single place to keep `last_seen` honest.
        // Read-only paths (`get_score_ratio`, `get_current_ident_state`,
        // `secident_request_state`, `verify_signature`) use
        // `self.credits.get(...)` and therefore do NOT bump the timestamp,
        // which is correct — those are just queries, not "we saw them now"
        // events.
        //
        // Without this bump, `last_seen` was only ever advanced by
        // `add_uploaded` / `add_downloaded`. Peers that connected, did a
        // partial handshake, and never transferred bytes (Unknown / Failed
        // / Needed states) kept their creation-time `last_seen` forever,
        // so the 90-day `cleanup_stale` sweep evicted them by *first
        // contact* age rather than *last contact* age — visible in the
        // Known Clients tab as months-old "Unknown" rows for peers we
        // actually still talked to recently.
        let now = chrono::Utc::now().timestamp();
        let record = self
            .credits
            .entry(user_hash)
            .or_insert_with(|| CreditRecord::new(user_hash));
        record.last_seen = now;
        record
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
        // `last_seen` already bumped by `get_or_create` above.
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
        // `last_seen` already bumped by `get_or_create` above.
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

    /// Lookup a single credit record by user hash. Returns `None` for
    /// peers we have not yet recorded any credit data for (the upload
    /// pane uses this to populate the per-row uploaded/downloaded
    /// totals on the Queued tab without round-tripping through
    /// `all_records`).
    pub fn get_record(&self, user_hash: &[u8; 16]) -> Option<&CreditRecord> {
        self.credits.get(user_hash)
    }

    pub fn cleanup_stale(&mut self, max_age_days: i64) {
        let cutoff = chrono::Utc::now().timestamp() - (max_age_days * 86400);
        self.credits.retain(|_, r| r.last_seen > cutoff);
        // Same cutoff for Ember records so the two tables age in
        // lockstep. `last_seen` on EmberCreditRecord is bumped by
        // every credit-granting or session-recording operation, so
        // active peers stay regardless of their public-key format.
        self.ember_credits.retain(|_, r| r.last_seen > cutoff);
    }

    // ---- Ember credit helpers ----

    /// Look up or create an Ember credit record for this pubkey.
    /// Mirrors `get_or_create` on the eMule side: bumps `last_seen`
    /// so evictions track contact freshness. Non-mutating queries
    /// (`get_ember_record`, `get_ember_score_ratio`,
    /// `get_ember_queue_score`) route through `ember_credits.get`
    /// and deliberately do NOT bump the timestamp.
    pub fn get_or_create_ember(&mut self, pub_key: [u8; 32]) -> &mut EmberCreditRecord {
        let now = chrono::Utc::now().timestamp();
        let record = self
            .ember_credits
            .entry(pub_key)
            .or_insert_with(|| EmberCreditRecord::new(pub_key));
        record.last_seen = now;
        record
    }

    #[allow(dead_code)]
    pub fn get_ember_record(&self, pub_key: &[u8; 32]) -> Option<&EmberCreditRecord> {
        self.ember_credits.get(pub_key)
    }

    pub fn all_ember_records(&self) -> Vec<&EmberCreditRecord> {
        self.ember_credits.values().collect()
    }

    /// Credit peer `pub_key` for `bytes` they uploaded to us. `verified`
    /// must be `true` (full PoP completed on this session) for bytes to
    /// land on the record — without PoP a spoofer who claimed the
    /// pubkey could farm credit for a genuine peer. Binding-only
    /// peers still get their bytes tracked via the legacy `CreditRecord`
    /// upstream; this method only governs the Ember-specific ledger.
    ///
    /// Returns `true` when the write landed, `false` when it was
    /// rejected so callers can emit a metric/log.
    pub fn add_ember_uploaded(&mut self, pub_key: [u8; 32], bytes: u64, verified: bool) -> bool {
        if !verified {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        let record = self.get_or_create_ember(pub_key);
        record.uploaded = record.uploaded.saturating_add(bytes);
        record.last_upload_time = now;
        record.ident_verified = true;
        true
    }

    pub fn add_ember_downloaded(&mut self, pub_key: [u8; 32], bytes: u64, verified: bool) -> bool {
        if !verified {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        let record = self.get_or_create_ember(pub_key);
        record.downloaded = record.downloaded.saturating_add(bytes);
        record.last_download_time = now;
        record.ident_verified = true;
        true
    }

    /// Record a completed/aborted upload session for the peer so the
    /// reliability multiplier and speed EWMA stay up to date. Called
    /// from `upload.rs` once per session (normal completion OR
    /// preemption OR mid-session failure) — NOT once per chunk.
    ///
    /// `completed == true` iff the session ended in the "healthy"
    /// state (out-of-parts, session-limit expired, queue rotation).
    /// `false` for aborted sessions (connection closed mid-transfer,
    /// queue-full reissues, etc.) so the reliability multiplier
    /// actually penalises peers that cut and run.
    pub fn record_ember_session(
        &mut self,
        pub_key: [u8; 32],
        bytes_transferred: u64,
        duration_secs: u64,
        completed: bool,
        verified: bool,
    ) {
        if !verified {
            return;
        }
        let record = self.get_or_create_ember(pub_key);
        record.record_session(bytes_transferred, duration_secs, completed);
        record.ident_verified = true;
    }

    /// Decayed credit ratio — like the eMule formula but with an
    /// exponential time-decay on downloaded bytes so stale credit
    /// fades out. Clamped to the same [MIN_CREDIT_RATIO,
    /// MAX_CREDIT_RATIO] band as the eMule version so the Ember
    /// scoring formula's multiplier structure doesn't blow up.
    ///
    /// Returns `MIN_CREDIT_RATIO` for peers we have no record of,
    /// peers we've downloaded less than `EMBER_MIN_DOWNLOADED_FOR_RATIO`
    /// from (matches the eMule <1 MiB guard), or peers where the
    /// decay has effectively zeroed out their historical downloads.
    pub fn get_ember_score_ratio(&self, pub_key: &[u8; 32]) -> f64 {
        let record = match self.ember_credits.get(pub_key) {
            Some(r) => r,
            None => return MIN_CREDIT_RATIO,
        };
        if record.downloaded < EMBER_MIN_DOWNLOADED_FOR_RATIO {
            return MIN_CREDIT_RATIO;
        }

        let now = chrono::Utc::now().timestamp();
        let age_secs = (now - record.last_download_time).max(0) as f64;
        let decay = 0.5f64.powf(age_secs / EMBER_DECAY_HALF_LIFE_SECS);
        let decayed_downloaded = (record.downloaded as f64) * decay;
        if decayed_downloaded < EMBER_MIN_DOWNLOADED_FOR_RATIO as f64 {
            return MIN_CREDIT_RATIO;
        }

        let uploaded = record.uploaded.max(1) as f64;
        // Mirror the eMule three-way minimum so the ratio grows
        // sub-linearly with download volume. Dropping any of the
        // three would let a peer ride a single large download
        // forever; keeping them all keeps scoring bounded.
        let ratio1 = (decayed_downloaded * 2.0) / uploaded;
        let ratio2 = (decayed_downloaded / 1_048_576.0 + 2.0).sqrt();
        let ratio3 = if decayed_downloaded < 9_646_899.0 {
            (decayed_downloaded - 1_048_576.0) / 8_598_323.0 * 2.34 + 1.0
        } else {
            MAX_CREDIT_RATIO
        };

        ratio1
            .min(ratio2)
            .min(ratio3)
            .min(MAX_CREDIT_RATIO)
            .max(MIN_CREDIT_RATIO)
    }

    /// Composite Ember queue score.
    ///
    /// `wait_seconds * decayed_ratio * file_priority * reliability * speed_factor`
    ///
    /// Call this INSTEAD of `get_queue_score` when the peer has a
    /// verified Ember credit record. The three extra factors are
    /// clamped narrowly (reliability ∈ [0.8, 1.5], speed ∈ [0.9,
    /// 1.2]) so the overall scoring stays within a ~2.25× multiplier
    /// of the eMule baseline in either direction — enough to
    /// reshape rankings when history exists without producing
    /// pathological queue-jumps.
    pub fn get_ember_queue_score(
        &self,
        pub_key: &[u8; 32],
        wait_secs: u64,
        file_priority: f64,
    ) -> f64 {
        let ratio = self.get_ember_score_ratio(pub_key);
        let (reliability, speed) = match self.ember_credits.get(pub_key) {
            Some(r) => (r.reliability_multiplier(), r.speed_multiplier()),
            None => (1.0, 1.0),
        };
        (wait_secs as f64) * ratio * file_priority * reliability * speed
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

    /// Regression: every mutating credit operation must bump
    /// `last_seen` so the 90-day `cleanup_stale` sweep evicts records
    /// based on time-since-last-contact, not time-since-first-contact.
    /// Before this was fixed, peers we connected with regularly but
    /// never traded bytes with (Unknown / Failed / Needed states) kept
    /// their creation-time timestamp forever and aged out at first
    /// contact + 90d, surfacing in the Known Clients tab as months-old
    /// entries we had in fact talked to that morning.
    #[test]
    fn last_seen_bumps_on_every_mutation() {
        let mut cm = CreditManager::new();
        let user = [0x42u8; 16];

        // Seed a record dated to ~120 days ago by hand so any
        // cleanup_stale(90) call would normally evict it. Each mutation
        // below must push `last_seen` forward to roughly "now", proving
        // the timestamp tracks contact freshness.
        let stale_ts = chrono::Utc::now().timestamp() - 120 * 86400;
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let now_floor = chrono::Utc::now().timestamp() - 5;

        // 1. set_public_key — the most common "we just heard from them" event.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        cm.set_public_key(user, vec![0xAB; 64]);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "set_public_key must bump last_seen",
        );

        // 2. set_ident_state — every state transition counts.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        cm.set_ident_state(user, IdentState::Verified);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "set_ident_state must bump last_seen",
        );

        // 3. check_identity_ip — a successful signature means we just
        //    completed a SecIdent round trip with this peer.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        cm.check_identity_ip(user, 0x0100_0000);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "check_identity_ip must bump last_seen",
        );

        // 4 & 5. add_uploaded / add_downloaded must bump too — these are
        //        the original paths that did so explicitly. After the
        //        get_or_create refactor they bump via the helper, so
        //        prove the path still works (regardless of accept/reject
        //        outcome — the peer talked to us, that counts).
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let _ = cm.add_uploaded(user, 1024);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "add_uploaded must bump last_seen",
        );
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let _ = cm.add_downloaded(user, 1024);
        assert!(
            cm.get_record(&user).unwrap().last_seen >= now_floor,
            "add_downloaded must bump last_seen",
        );

        // Read-only queries must NOT bump — those don't represent
        // contact, and bumping on every poll would defeat cleanup_stale
        // entirely (a record would never expire as long as the UI was
        // open). Re-stale and assert the timestamp survives a query.
        {
            let r = cm.get_or_create(user);
            r.last_seen = stale_ts;
        }
        let _ = cm.get_score_ratio(&user, 0);
        let _ = cm.get_current_ident_state(&user, 0);
        let _ = cm.get_record(&user);
        assert_eq!(
            cm.get_record(&user).unwrap().last_seen,
            stale_ts,
            "read-only credit queries must NOT touch last_seen",
        );
    }

    /// `cleanup_stale` evicts records past the cutoff regardless of
    /// `ident_state`. Without `last_seen` being kept fresh on every
    /// contact, the Known Clients list would slowly fill with months-
    /// old "Unknown" entries — the symptom that surfaced in the UI.
    #[test]
    fn cleanup_stale_evicts_past_cutoff() {
        let mut cm = CreditManager::new();
        let fresh = [0x01u8; 16];
        let stale = [0x02u8; 16];
        let now = chrono::Utc::now().timestamp();
        cm.get_or_create(fresh).last_seen = now;
        cm.get_or_create(stale).last_seen = now - 100 * 86400;

        cm.cleanup_stale(90);
        assert!(cm.get_record(&fresh).is_some(), "fresh record must survive 90d cutoff");
        assert!(cm.get_record(&stale).is_none(), "100d-old record must be pruned");
    }

    // ---- Ember credit tests ----

    /// Unverified peers cannot farm Ember credit — the `add_ember_uploaded`
    /// and `add_ember_downloaded` helpers must reject writes when
    /// `verified == false`. Without this check a hash-spoofer could
    /// claim a verified friend's pubkey on the wire and burn
    /// their real reputation by uploading garbage in their name.
    #[test]
    fn ember_credit_writes_require_verification() {
        let mut cm = CreditManager::new();
        let pk = [0xEBu8; 32];

        assert!(!cm.add_ember_uploaded(pk, 4096, false), "unverified upload must be rejected");
        assert!(!cm.add_ember_downloaded(pk, 4096, false), "unverified download must be rejected");
        assert!(cm.get_ember_record(&pk).is_none(), "rejected writes must not create a record");

        assert!(cm.add_ember_uploaded(pk, 4096, true));
        assert!(cm.add_ember_downloaded(pk, 2048, true));
        let r = cm.get_ember_record(&pk).expect("verified writes must land");
        assert_eq!(r.uploaded, 4096);
        assert_eq!(r.downloaded, 2048);
        assert!(r.ident_verified, "verified writes must set ident_verified");
    }

    /// `record_ember_session` tracks completion + speed EWMA. A first
    /// session seeds the EWMA directly (no smoothing with the zero
    /// default) so the ratio is honest on cold start.
    #[test]
    fn record_ember_session_seeds_ewma_on_first_sample() {
        let mut cm = CreditManager::new();
        let pk = [0xC0u8; 32];

        // Short/fast session — 1 MiB over 10s = ~104857 bytes/sec.
        // Below the 5s floor this would be dropped; above it the
        // first real sample should seed the EWMA directly.
        cm.record_ember_session(pk, 1_048_576, 10, true, true);
        let r = cm.get_ember_record(&pk).unwrap();
        assert_eq!(r.total_sessions, 1);
        assert_eq!(r.completed_sessions, 1);
        let expected = (1_048_576u64 as f64 / 10.0).round() as u64;
        assert_eq!(r.avg_upload_speed, expected, "first sample must seed EWMA without prior-zero mixing");
    }

    /// Subsequent sessions smooth with `EMBER_SPEED_EWMA_ALPHA` so a
    /// single outlier can't yank the long-run estimate. A fast
    /// session after a slow one should move the average but not
    /// all the way to the new value.
    #[test]
    fn record_ember_session_ewma_smooths_subsequent_samples() {
        let mut cm = CreditManager::new();
        let pk = [0xA1u8; 32];

        cm.record_ember_session(pk, 100 * 1024, 10, true, true);
        let base = cm.get_ember_record(&pk).unwrap().avg_upload_speed;

        // Now a 10× faster session. The EWMA should move upward but
        // well short of the full 10× — with α = 0.3, expect roughly
        // 0.3 × fast + 0.7 × base.
        cm.record_ember_session(pk, 1000 * 1024, 10, true, true);
        let after = cm.get_ember_record(&pk).unwrap().avg_upload_speed;
        assert!(after > base, "fast session should pull average up");
        let new_sample = 1000u64 * 1024 / 10;
        assert!(
            after < new_sample,
            "α=0.3 smoothing must NOT fully adopt the new sample (got {after}, new {new_sample})",
        );
    }

    /// Too-short sessions skip the EWMA update (noise dominates) but
    /// still count toward total_sessions / completed_sessions so
    /// reliability doesn't get hidden for rapid disconnects.
    #[test]
    fn record_ember_session_skips_ewma_for_tiny_sessions() {
        let mut cm = CreditManager::new();
        let pk = [0x07u8; 32];

        cm.record_ember_session(pk, 99_999, 1, false, true);
        let r = cm.get_ember_record(&pk).unwrap();
        assert_eq!(r.total_sessions, 1);
        assert_eq!(r.completed_sessions, 0, "aborted session must NOT count completed");
        assert_eq!(r.avg_upload_speed, 0, "sub-threshold sessions must NOT touch EWMA");
    }

    /// Reliability multiplier is neutral (1.0) with no history, grows
    /// toward `EMBER_RELIABILITY_MAX` with successful completions,
    /// and sinks toward `EMBER_RELIABILITY_MIN` for peers that abort.
    #[test]
    fn reliability_multiplier_spans_expected_range() {
        let mut r = EmberCreditRecord::new([0u8; 32]);
        assert_eq!(r.reliability_multiplier(), 1.0, "no sessions = neutral");

        // 100% completion → max.
        r.total_sessions = 10;
        r.completed_sessions = 10;
        assert!((r.reliability_multiplier() - EMBER_RELIABILITY_MAX).abs() < 1e-9);

        // 0% completion → min.
        r.completed_sessions = 0;
        assert!((r.reliability_multiplier() - EMBER_RELIABILITY_MIN).abs() < 1e-9);

        // 50% completion lands halfway in the band.
        r.completed_sessions = 5;
        let expected = EMBER_RELIABILITY_MIN + 0.5 * (EMBER_RELIABILITY_MAX - EMBER_RELIABILITY_MIN);
        assert!((r.reliability_multiplier() - expected).abs() < 1e-9);
    }

    /// Speed multiplier: zero avg (no sample yet) is neutral, below-
    /// baseline is penalised toward MIN, exactly-baseline is 1.0,
    /// and ≥2× baseline caps at MAX.
    #[test]
    fn speed_multiplier_covers_piecewise_ramp() {
        let mut r = EmberCreditRecord::new([0u8; 32]);
        assert_eq!(r.speed_multiplier(), 1.0, "no sample = neutral");

        // Exactly baseline → 1.0.
        r.avg_upload_speed = EMBER_SPEED_BASELINE_BPS as u64;
        assert!((r.speed_multiplier() - 1.0).abs() < 1e-6);

        // 0 bytes/sec interpolation anchor (but we can't set avg = 0
        // and expect the penalised branch, because 0 trips the neutral
        // guard). Use a very small positive speed instead: should be
        // very close to MIN but may float-jitter above it.
        r.avg_upload_speed = 1;
        assert!(
            r.speed_multiplier() < 1.0 && r.speed_multiplier() >= EMBER_SPEED_FACTOR_MIN - 1e-9,
            "slow upload must sit in the [MIN, 1.0) band, got {}",
            r.speed_multiplier()
        );

        // 2× baseline → capped at MAX.
        r.avg_upload_speed = (2.0 * EMBER_SPEED_BASELINE_BPS) as u64;
        assert!((r.speed_multiplier() - EMBER_SPEED_FACTOR_MAX).abs() < 1e-6);

        // Way past 2× → still capped at MAX, never above.
        r.avg_upload_speed = (100.0 * EMBER_SPEED_BASELINE_BPS) as u64;
        assert!((r.speed_multiplier() - EMBER_SPEED_FACTOR_MAX).abs() < 1e-6);
    }

    /// Score-ratio decay: a peer that downloaded from us yesterday
    /// scores higher than a peer that downloaded from us long ago,
    /// even with identical upload/download totals. The half-life is
    /// `EMBER_DECAY_HALF_LIFE_SECS` — so a record back-dated that
    /// long should have ratio roughly halved (approximately).
    #[test]
    fn score_ratio_decays_over_time() {
        let mut cm = CreditManager::new();
        let fresh = [0xF1u8; 32];
        let aged = [0xA1u8; 32];

        // Two peers with identical uploaded / downloaded. Only the
        // `last_download_time` differs: `fresh` downloaded just now,
        // `aged` downloaded `EMBER_DECAY_HALF_LIFE_SECS` seconds ago.
        for pk in [fresh, aged] {
            let r = cm.get_or_create_ember(pk);
            r.uploaded = 5_000_000;
            r.downloaded = 20_000_000;
        }
        let now = chrono::Utc::now().timestamp();
        cm.get_or_create_ember(fresh).last_download_time = now;
        cm.get_or_create_ember(aged).last_download_time =
            now - EMBER_DECAY_HALF_LIFE_SECS as i64;

        let fresh_ratio = cm.get_ember_score_ratio(&fresh);
        let aged_ratio = cm.get_ember_score_ratio(&aged);
        assert!(
            fresh_ratio > aged_ratio,
            "fresh downloads should score higher than aged (got fresh={fresh_ratio}, aged={aged_ratio})",
        );
        assert!(aged_ratio >= MIN_CREDIT_RATIO, "aged must floor at MIN");
        assert!(fresh_ratio <= MAX_CREDIT_RATIO, "fresh must cap at MAX");
    }

    /// Ratio guard: peers who've downloaded below the 1 MiB floor
    /// score at MIN, same as eMule. Prevents trivial transfers from
    /// producing spuriously large ratios via tiny denominators.
    #[test]
    fn score_ratio_returns_min_below_one_mib_downloaded() {
        let mut cm = CreditManager::new();
        let pk = [0xABu8; 32];
        {
            let r = cm.get_or_create_ember(pk);
            r.uploaded = 1;
            r.downloaded = 1024; // well under 1 MiB
            r.last_download_time = chrono::Utc::now().timestamp();
        }
        assert_eq!(cm.get_ember_score_ratio(&pk), MIN_CREDIT_RATIO);
    }

    /// Queue score composition: all five factors multiply, so a
    /// 100% reliable fast peer with decent ratio should outscore an
    /// unreliable slow peer with identical ratio even at the same
    /// wait time.
    #[test]
    fn queue_score_rewards_reliable_fast_peers() {
        let mut cm = CreditManager::new();
        let good = [0x01u8; 32];
        let bad = [0x02u8; 32];

        // Identical "headline" credits for both peers so only the
        // reliability+speed factors separate them.
        let now = chrono::Utc::now().timestamp();
        for pk in [good, bad] {
            let r = cm.get_or_create_ember(pk);
            r.uploaded = 1_000_000;
            r.downloaded = 5_000_000;
            r.last_download_time = now;
        }

        // `good`: 100% completion, 2× baseline speed.
        {
            let r = cm.get_or_create_ember(good);
            r.total_sessions = 10;
            r.completed_sessions = 10;
            r.avg_upload_speed = (2.0 * EMBER_SPEED_BASELINE_BPS) as u64;
        }
        // `bad`: 0% completion, well below baseline speed.
        {
            let r = cm.get_or_create_ember(bad);
            r.total_sessions = 10;
            r.completed_sessions = 0;
            r.avg_upload_speed = (0.1 * EMBER_SPEED_BASELINE_BPS) as u64;
        }

        let good_score = cm.get_ember_queue_score(&good, 300, 1.0);
        let bad_score = cm.get_ember_queue_score(&bad, 300, 1.0);
        assert!(
            good_score > bad_score,
            "reliable+fast peer must outscore unreliable+slow (got good={good_score} bad={bad_score})",
        );
        // Bracket the split: it should be meaningfully different,
        // not just float-jitter. `good` picks up 1.5 × 1.2 = 1.8;
        // `bad` eats 0.8 × 0.9 = 0.72 → ~2.5× gap. Asserting 1.5×
        // leaves headroom for ratio differences if we ever retune.
        assert!(good_score >= bad_score * 1.5);
    }

    /// `cleanup_stale` prunes the Ember table in lockstep with the
    /// eMule table so one doesn't silently outlast the other.
    #[test]
    fn cleanup_stale_also_prunes_ember_records() {
        let mut cm = CreditManager::new();
        let fresh = [0xF0u8; 32];
        let stale = [0x5Au8; 32];
        let now = chrono::Utc::now().timestamp();
        cm.get_or_create_ember(fresh).last_seen = now;
        cm.get_or_create_ember(stale).last_seen = now - 100 * 86400;

        cm.cleanup_stale(90);
        assert!(cm.get_ember_record(&fresh).is_some());
        assert!(cm.get_ember_record(&stale).is_none());
    }
}
