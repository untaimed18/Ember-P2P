use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use futures::StreamExt;
use minisign_verify::{PublicKey, Signature};
use reqwest::{
    header::{ACCEPT, CONTENT_LENGTH, LOCATION},
    redirect::Policy as RedirectPolicy,
    Client, Response, StatusCode,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{ipc::Channel, AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use tokio::{
    net::lookup_host,
    sync::Mutex,
    time::{timeout, Instant},
};
use url::{Host, Url};

use crate::commands::errors::coded;

const MANIFEST_MAX_BYTES: usize = 512 * 1024;
const SIGNATURE_MAX_BYTES: usize = 16 * 1024;
const ARTIFACT_MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(20);
const METADATA_DEADLINE: Duration = Duration::from_secs(60);
const ARTIFACT_DEADLINE: Duration = Duration::from_secs(30 * 60);
const CURRENT_SECURITY_EPOCH: u64 = 1;
const STATE_FILE: &str = "updater-security-state.json";
/// Records that we handed a verified installer to the OS and expected not to
/// come back. See [`save_handoff`].
const HANDOFF_FILE: &str = "update-handoff.json";
/// Where the verified installer is kept so a failed hand-off leaves something
/// the user can still run.
const PENDING_DIR: &str = "updates";
/// A hand-off this old is forgotten rather than reported. Long enough that
/// someone who leaves Ember closed for weeks still gets told, short enough that
/// a stale marker and its 15 MB installer do not live on the disk forever.
const HANDOFF_MAX_AGE_SECS: i64 = 30 * 24 * 3600;

/// Manifest asset is absent at the configured endpoint. Treated as
/// "no update available" rather than a hard check failure. A missing
/// `latest.json.sig` when the manifest exists is [`UpdaterSignatureMissing`].
#[derive(Debug)]
struct UpdaterResourceMissing;

impl std::fmt::Display for UpdaterResourceMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("updater resource not found")
    }
}

impl std::error::Error for UpdaterResourceMissing {}

/// `latest.json` was present but `latest.json.sig` was not. Unlike a missing
/// manifest (no update published), this is a check failure — never "up to date".
#[derive(Debug)]
struct UpdaterSignatureMissing;

impl std::fmt::Display for UpdaterSignatureMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("updater signature not found")
    }
}

impl std::error::Error for UpdaterSignatureMissing {}

fn is_missing_updater_signature(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<UpdaterSignatureMissing>().is_some())
}

fn is_missing_updater_resource(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<UpdaterResourceMissing>().is_some())
}

#[derive(Default)]
pub struct UpdaterService {
    operation: Mutex<()>,
    pending: Mutex<Option<PendingUpdate>>,
}

struct PendingUpdate {
    update: Update,
    platform: SignedPlatform,
    rollback_path: PathBuf,
    candidate_state: RollbackState,
    /// UI-facing metadata retained with the installable artifact so a later
    /// empty/failed re-check can still rehydrate the Install affordance.
    info: UpdateInfo,
    /// The signed manifest this update came from and its detached signature,
    /// both verbatim. Carried this far only so that staging an installer for
    /// later recovery can keep them — see [`UpdateHandoff::manifest`].
    manifest: String,
    manifest_signature: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedManifest {
    version: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    pub_date: Option<String>,
    security_epoch: u64,
    platforms: BTreeMap<String, SignedPlatform>,
}

#[derive(Debug, Clone, Deserialize)]
struct SignedPlatform {
    target: String,
    url: Url,
    signature: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    version: String,
    security_epoch: u64,
    notes: Option<String>,
    date: Option<String>,
}

/// Result of a secure update check, including whether a previously staged
/// installable artifact is still retained after floor/retention logic.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureUpdateCheckResult {
    update: Option<UpdateInfo>,
    pending_retained: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default)]
    signature_missing: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", content = "data")]
pub enum UpdateProgress {
    Started {
        #[serde(rename = "contentLength")]
        content_length: u64,
    },
    Progress {
        #[serde(rename = "chunkLength")]
        chunk_length: u64,
    },
    Finished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RollbackState {
    security_epoch: u64,
    highest_version: String,
}

#[derive(Clone, Copy)]
struct NetworkPolicy {
    allow_http_loopback: bool,
}

impl NetworkPolicy {
    const PRODUCTION: Self = Self {
        allow_http_loopback: false,
    };

    #[cfg(test)]
    const fn local_fixture() -> Self {
        Self {
            allow_http_loopback: true,
        }
    }

    fn allows_ip(self, ip: IpAddr) -> bool {
        if self.allow_http_loopback && ip.is_loopback() {
            return true;
        }
        is_public_ip(ip)
    }
}

#[derive(Debug)]
struct FetchedBytes {
    bytes: Vec<u8>,
    final_url: Url,
    final_addresses: Vec<SocketAddr>,
}

struct EmbeddedUpdaterConfig {
    endpoint: Url,
    public_key: String,
}

#[derive(Debug)]
struct SignedObservationPersistenceFailed;

impl std::fmt::Display for SignedObservationPersistenceFailed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("failed to persist signed updater observation floor")
    }
}

impl std::error::Error for SignedObservationPersistenceFailed {}

#[derive(Deserialize)]
struct EmbeddedConfig {
    plugins: EmbeddedPlugins,
}

#[derive(Deserialize)]
struct EmbeddedPlugins {
    updater: EmbeddedUpdater,
}

#[derive(Deserialize)]
struct EmbeddedUpdater {
    pubkey: String,
    endpoints: Vec<Url>,
}

fn embedded_updater_config() -> Result<EmbeddedUpdaterConfig> {
    let config: EmbeddedConfig = serde_json::from_str(include_str!("../../tauri.conf.json"))
        .context("embedded Tauri updater configuration is invalid")?;
    if config.plugins.updater.endpoints.len() != 1 {
        bail!("exactly one embedded updater endpoint is required");
    }
    let endpoint = config.plugins.updater.endpoints[0].clone();
    validate_url(&endpoint, NetworkPolicy::PRODUCTION)?;
    Ok(EmbeddedUpdaterConfig {
        endpoint,
        public_key: config.plugins.updater.pubkey,
    })
}

fn signature_url(manifest_url: &Url) -> Result<Url> {
    let mut url = manifest_url.clone();
    let path = url.path();
    if path.is_empty() || path.ends_with('/') {
        bail!("updater manifest URL has no filename");
    }
    url.set_path(&format!("{path}.sig"));
    Ok(url)
}

fn decode_utf8_base64(input: &str, label: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .with_context(|| format!("{label} is not valid base64"))?;
    String::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))
}

fn parse_public_key(encoded: &str) -> Result<PublicKey> {
    let trimmed = encoded.trim();
    if trimmed.starts_with("untrusted comment:") {
        return PublicKey::decode(trimmed).context("updater public key is invalid");
    }
    if let Ok(key) = PublicKey::from_base64(trimmed) {
        return Ok(key);
    }
    let decoded = decode_utf8_base64(trimmed, "updater public key")?;
    PublicKey::decode(decoded.trim()).context("updater public key is invalid")
}

fn parse_signature(encoded: &[u8]) -> Result<Signature> {
    let text = std::str::from_utf8(encoded).context("minisign signature is not UTF-8")?;
    let decoded;
    let minisign = if text.trim().starts_with("untrusted comment:") {
        text.trim()
    } else {
        decoded = decode_utf8_base64(text, "minisign signature")?;
        decoded.trim()
    };
    Signature::decode(minisign).context("minisign signature is invalid")
}

fn verify_minisign(payload: &[u8], encoded_signature: &[u8], encoded_key: &str) -> Result<()> {
    let public_key = parse_public_key(encoded_key)?;
    let signature = parse_signature(encoded_signature)?;
    public_key
        .verify(payload, &signature, true)
        .context("minisign verification failed")
}

fn validate_manifest(
    value: serde_json::Value,
    public_key: &str,
) -> Result<(SignedManifest, serde_json::Value, Version)> {
    let manifest: SignedManifest = serde_json::from_value(value.clone())
        .context("signed updater manifest has invalid fields")?;
    let version = Version::parse(&manifest.version).context("signed updater version is invalid")?;
    if manifest.version != version.to_string() {
        bail!("signed updater version is not canonical");
    }
    if manifest.security_epoch == 0 {
        bail!("signed updater security epoch must be positive");
    }
    if manifest.platforms.is_empty() || manifest.platforms.len() > 16 {
        bail!("signed updater manifest has an invalid platform count");
    }
    if manifest
        .notes
        .as_ref()
        .is_some_and(|notes| notes.len() > 64 * 1024)
    {
        bail!("signed updater notes are too large");
    }
    if manifest
        .pub_date
        .as_ref()
        .is_some_and(|date| date.len() > 64)
    {
        bail!("signed updater date is too large");
    }

    for (target, platform) in &manifest.platforms {
        if target != &platform.target
            || target.is_empty()
            || target.len() > 128
            || !target
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("signed updater target is invalid");
        }
        validate_url(&platform.url, NetworkPolicy::PRODUCTION)?;
        if platform.size == 0 || platform.size > ARTIFACT_MAX_BYTES {
            bail!("signed updater artifact size is invalid");
        }
        if platform.sha256.len() != 64
            || !platform
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("signed updater artifact hash is invalid");
        }
        if platform.signature.len() > SIGNATURE_MAX_BYTES || platform.signature.trim().is_empty() {
            bail!("signed updater artifact signature is invalid");
        }
        // Parse now so a malformed signed artifact signature is rejected at
        // check time, before the user downloads a potentially large bundle.
        parse_signature(platform.signature.as_bytes())?;
        parse_public_key(public_key)?;
    }

    Ok((manifest, value, version))
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn ipv4_in(ip: Ipv4Addr, base: [u8; 4], prefix: u8) -> bool {
    let ip = u32::from(ip);
    let base = u32::from(Ipv4Addr::from(base));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    ip & mask == base & mask
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    const SPECIAL: &[([u8; 4], u8)] = &[
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 31, 196, 0], 24),
        ([192, 52, 193, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([192, 175, 48, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ];
    !SPECIAL
        .iter()
        .any(|(base, prefix)| ipv4_in(ip, *base, *prefix))
}

fn ipv6_in(ip: Ipv6Addr, base: [u16; 8], prefix: u8) -> bool {
    let ip = u128::from(ip);
    let base = u128::from(Ipv6Addr::new(
        base[0], base[1], base[2], base[3], base[4], base[5], base[6], base[7],
    ));
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    ip & mask == base & mask
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    // Only global-unicast 2000::/3 is eligible, then remove IANA special-use
    // assignments inside that range (protocol assignments and 6to4).
    ipv6_in(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3)
        && !ipv6_in(ip, [0x2001, 0, 0, 0, 0, 0, 0, 0], 23)
        && !ipv6_in(ip, [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32)
        && !ipv6_in(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16)
        && !ipv6_in(ip, [0x3fff, 0, 0, 0, 0, 0, 0, 0], 20)
}

fn validate_url(url: &Url, policy: NetworkPolicy) -> Result<()> {
    if url.as_str().len() > 4096 || url.fragment().is_some() {
        bail!("updater URL is malformed");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("updater URL credentials are forbidden");
    }
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("updater URL has no valid port"))?;
    match url.scheme() {
        "https" if port == 443 => {}
        "http" if policy.allow_http_loopback => {}
        _ => bail!("updater URL must use HTTPS on port 443"),
    }
    match url
        .host()
        .ok_or_else(|| anyhow!("updater URL has no host"))?
    {
        Host::Ipv4(ip) if policy.allows_ip(IpAddr::V4(ip)) => {}
        Host::Ipv6(ip) if policy.allows_ip(IpAddr::V6(ip)) => {}
        Host::Domain(domain)
            if !domain.is_empty()
                && !domain.eq_ignore_ascii_case("localhost")
                && !domain.ends_with(".localhost") => {}
        Host::Domain(_) if policy.allow_http_loopback => {}
        Host::Ipv4(_) | Host::Ipv6(_) | Host::Domain(_) => {
            bail!("updater URL resolves to a private or special-use destination")
        }
    }
    Ok(())
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| anyhow!("updater request deadline exceeded"))
}

async fn client_for_url(
    url: &Url,
    policy: NetworkPolicy,
    deadline: Instant,
) -> Result<(Client, Vec<SocketAddr>)> {
    validate_url(url, policy)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("updater URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("updater URL has no port"))?;
    let mut builder = Client::builder()
        .user_agent(concat!("ember-secure-updater/", env!("CARGO_PKG_VERSION")))
        .no_proxy()
        .redirect(RedirectPolicy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT);

    let addresses = if matches!(url.host(), Some(Host::Domain(_))) {
        let dns_deadline = remaining(deadline)?.min(DNS_TIMEOUT);
        let addresses: Vec<SocketAddr> = timeout(dns_deadline, lookup_host((host, port)))
            .await
            .context("updater DNS lookup timed out")?
            .context("updater DNS lookup failed")?
            .collect();
        if addresses.is_empty() {
            bail!("updater DNS lookup returned no addresses");
        }
        if addresses
            .iter()
            .any(|address| !policy.allows_ip(address.ip()))
        {
            bail!("updater DNS returned a private or special-use address");
        }
        builder = builder.resolve_to_addrs(host, &addresses);
        addresses
    } else {
        let ip = match url.host() {
            Some(Host::Ipv4(ip)) => IpAddr::V4(ip),
            Some(Host::Ipv6(ip)) => IpAddr::V6(ip),
            _ => bail!("updater URL has no valid IP host"),
        };
        vec![SocketAddr::new(ip, port)]
    };

    Ok((
        builder
            .build()
            .context("failed to build updater HTTP client")?,
        addresses,
    ))
}

async fn send_with_redirects(
    initial_url: &Url,
    policy: NetworkPolicy,
    deadline: Instant,
    accept: &'static str,
) -> Result<(Response, Url, Vec<SocketAddr>)> {
    let mut url = initial_url.clone();
    for redirect_count in 0..=MAX_REDIRECTS {
        let (client, addresses) = client_for_url(&url, policy, deadline).await?;
        let response = timeout(
            remaining(deadline)?,
            client.get(url.clone()).header(ACCEPT, accept).send(),
        )
        .await
        .context("updater request timed out")?
        .context("updater request failed")?;

        if response.status().is_redirection() {
            if redirect_count == MAX_REDIRECTS {
                bail!("updater redirect limit exceeded");
            }
            let location = response
                .headers()
                .get(LOCATION)
                .ok_or_else(|| anyhow!("updater redirect omitted Location"))?
                .to_str()
                .context("updater redirect Location is invalid")?;
            let next = url
                .join(location)
                .context("updater redirect URL is invalid")?;
            validate_url(&next, policy)?;
            url = next;
            continue;
        }
        if !response.status().is_success() {
            if response.status() == StatusCode::NOT_FOUND {
                return Err(UpdaterResourceMissing.into());
            }
            bail!("updater server returned HTTP {}", response.status());
        }
        return Ok((response, url, addresses));
    }
    bail!("updater redirect limit exceeded")
}

async fn fetch_capped(
    url: &Url,
    cap: usize,
    deadline_duration: Duration,
    accept: &'static str,
    policy: NetworkPolicy,
) -> Result<FetchedBytes> {
    let deadline = Instant::now() + deadline_duration;
    let (response, final_url, final_addresses) =
        send_with_redirects(url, policy, deadline, accept).await?;
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > cap as u64)
    {
        bail!("updater response exceeds its size limit");
    }

    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = timeout(remaining(deadline)?, stream.next())
        .await
        .context("updater response body timed out")?
    {
        let chunk = chunk.context("failed to read updater response body")?;
        if bytes.len().saturating_add(chunk.len()) > cap {
            bail!("updater response exceeds its size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(FetchedBytes {
        bytes,
        final_url,
        final_addresses,
    })
}

fn rollback_floor<'a>(
    current_epoch: u64,
    current_version: &'a Version,
    stored: Option<&'a RollbackState>,
) -> Result<(u64, Version)> {
    let current = (current_epoch, current_version.clone());
    let Some(stored) = stored else {
        return Ok(current);
    };
    let stored_version =
        Version::parse(&stored.highest_version).context("updater rollback state is corrupt")?;
    Ok(current.max((stored.security_epoch, stored_version)))
}

fn reject_rollback(
    current_epoch: u64,
    current_version: &Version,
    stored: Option<&RollbackState>,
    candidate_epoch: u64,
    candidate_version: &Version,
) -> Result<()> {
    let floor = rollback_floor(current_epoch, current_version, stored)?;
    if (candidate_epoch, candidate_version.clone()) < floor {
        bail!("signed updater manifest was rolled back");
    }
    Ok(())
}

/// Distinguishes "the endpoint advertises something older than what I am
/// running" from "the endpoint advertises something older than a signed
/// document I have already seen".
///
/// Only the second is a rollback signal. The first happens legitimately when a
/// maintainer yanks a release so GitHub's `latest` reverts, or when the user
/// runs a pre-release/self-built binary — and because the floor is
/// `max(running identity, stored)`, [`reject_rollback`] cannot tell them apart
/// and turns every such check into a hard error instead of "you're up to date".
fn candidate_is_older_than_running_build_only(
    current_epoch: u64,
    current_version: &Version,
    stored: Option<&RollbackState>,
    candidate_epoch: u64,
    candidate_version: &Version,
) -> Result<bool> {
    let candidate = (candidate_epoch, candidate_version.clone());
    if candidate >= (current_epoch, current_version.clone()) {
        return Ok(false);
    }
    match stored {
        // The persisted floor is the attack-relevant one: it records a signed
        // manifest this install has already accepted. Dropping below it stays a
        // hard failure.
        Some(stored) => Ok(candidate >= rollback_state_identity(stored)?),
        None => Ok(true),
    }
}

/// Offer an update when the signed candidate is strictly newer than the running
/// binary identity `(CURRENT_SECURITY_EPOCH, current_version)`.
///
/// Tuple ordering lets a higher `security_epoch` authorize a lower version
/// number (emergency epoch bump). Anti-rollback is enforced separately by
/// [`reject_rollback`] against the persisted observation floor.
fn should_offer_update(
    current_epoch: u64,
    current_version: &Version,
    candidate_epoch: u64,
    candidate_version: &Version,
) -> bool {
    (candidate_epoch, candidate_version.clone()) > (current_epoch, current_version.clone())
}

/// After a signed manifest passes anti-rollback, the observed candidate becomes
/// the new floor (it is already `>=` the previous floor).
fn observed_rollback_state(observed_epoch: u64, observed_version: &Version) -> RollbackState {
    RollbackState {
        security_epoch: observed_epoch,
        highest_version: observed_version.to_string(),
    }
}

fn state_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(crate::storage::paths::ensure_data_dir_with_app(app)
        .context("failed to resolve updater state directory")?
        .join(STATE_FILE))
}

/// What we handed to the OS, so a launch that finds itself still running the old
/// version can say so and offer the installer again.
///
/// Installing ends in `std::process::exit(0)` inside the updater plugin, which
/// means the moment the installer is spawned nothing of ours is left to notice
/// whether it actually ran. Windows or an antivirus refusing to execute a
/// freshly written, unsigned installer therefore looked exactly like a
/// successful update from inside Ember: the app closed and nothing happened.
/// Recording the attempt, and keeping the verified bytes on disk, is what turns
/// that dead end into something recoverable.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateHandoff {
    /// Version the saved installer installs, for logs and the UI only.
    ///
    /// Not trusted for any decision. This file sits in the data directory, so
    /// anything running as the user can rewrite it, and every question that
    /// matters — which version, which security epoch, `exe` or `msi` — is
    /// re-derived from [`Self::manifest`] instead. Trusting the field here would
    /// have been a downgrade path: the artifact signature proves only that we
    /// signed those *bytes*, so pairing an old release's installer with a
    /// rewritten version high enough to clear the rollback floor would have got
    /// an old, signed Ember installed on demand.
    version: String,
    /// Also display-only, and re-derived from the manifest — see
    /// [`Self::version`].
    security_epoch: u64,
    /// Version we were running when we handed off, so a launch can tell
    /// "the installer never ran" from "it ran and this is the new build".
    from_version: String,
    /// `exe` or `msi`, display-only for the same reason as [`Self::version`].
    /// The file name on disk is derived from the *manifest's* version and URL,
    /// never read back from this marker, so a tampered marker cannot point us at
    /// an executable somewhere else.
    kind: String,
    /// Which platform entry of the manifest was staged. Untrusted, and used only
    /// to look that entry up: whatever it selects, the hash and signature acted
    /// on are the manifest's, and the version acted on is the one that same
    /// signed document declares.
    sha256: String,
    signature: String,
    /// The signed `latest.json` this update came from, verbatim, with its
    /// detached signature. Our own signing key over a document that pairs a
    /// version with each artifact's hash is the only thing here that binds
    /// "these bytes" to "this version" — a replayed older manifest is authentic
    /// but names its own older version, which the newer-than-running check then
    /// refuses.
    ///
    /// Defaulted so a marker written before this field existed still parses, and
    /// is then discarded by `verified_handoff_claim` with a log line that says why
    /// rather than one claiming the file is corrupt.
    #[serde(default)]
    manifest: String,
    #[serde(default)]
    manifest_signature: String,
    attempted_at: i64,
}

/// A hand-off that did not result in the new version running.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateHandoffReport {
    pub version: String,
    pub security_epoch: u64,
    pub attempted_at: i64,
    /// The saved installer is still present and still matches the hash and
    /// signature it was verified against, so it can be launched again.
    pub installer_ready: bool,
}

fn handoff_path(app: &AppHandle) -> Result<PathBuf> {
    Ok(crate::storage::paths::ensure_data_dir_with_app(app)
        .context("failed to resolve updater state directory")?
        .join(HANDOFF_FILE))
}

fn pending_dir(app: &AppHandle) -> Result<PathBuf> {
    Ok(crate::storage::paths::ensure_data_dir_with_app(app)
        .context("failed to resolve updater state directory")?
        .join(PENDING_DIR))
}

/// The installer's name on disk, built from values we control rather than from
/// anything the marker file says, so the path can only ever land inside
/// [`PENDING_DIR`].
fn installer_name(version: &str, kind: &str) -> String {
    let safe_version: String = version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_'))
        .collect();
    let safe_kind = if kind == "msi" { "msi" } else { "exe" };
    format!("Ember_{safe_version}_update.{safe_kind}")
}

/// `exe` unless the signed URL clearly names an MSI.
fn installer_kind(url: &Url) -> &'static str {
    if url.path().to_ascii_lowercase().ends_with(".msi") {
        "msi"
    } else {
        "exe"
    }
}

fn read_handoff(path: &Path) -> Result<Option<UpdateHandoff>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .context("update hand-off record is corrupt"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to read the update hand-off record"),
    }
}

/// Persist the verified installer and the record of handing it over.
///
/// Best-effort by design: the caller carries on installing if this fails, since
/// a missing safety net is not a reason to refuse an update the user asked for.
fn save_handoff(
    app: &AppHandle,
    platform: &SignedPlatform,
    version: &str,
    security_epoch: u64,
    manifest: &str,
    manifest_signature: &str,
    artifact: &[u8],
) -> Result<()> {
    let kind = installer_kind(&platform.url);
    let dir = pending_dir(app)?;
    std::fs::create_dir_all(&dir).context("failed to create the update staging directory")?;

    // Only ever one saved installer: whatever a previous attempt left behind is
    // either already installed or superseded by this one.
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }

    let path = dir.join(installer_name(version, kind));
    crate::security::atomic_write(&path, artifact, true)
        .context("failed to stage the verified installer")?;

    let record = UpdateHandoff {
        version: version.to_string(),
        security_epoch,
        from_version: app.package_info().version.to_string(),
        kind: kind.to_string(),
        sha256: platform.sha256.clone(),
        signature: platform.signature.clone(),
        manifest: manifest.to_string(),
        manifest_signature: manifest_signature.to_string(),
        attempted_at: chrono::Utc::now().timestamp(),
    };
    let bytes = serde_json::to_vec(&record).context("failed to serialize the hand-off record")?;
    crate::security::atomic_write(&handoff_path(app)?, &bytes, true)
        .context("failed to persist the hand-off record")
}

/// Forget a hand-off and delete the installer it refers to.
fn clear_handoff(app: &AppHandle) {
    if let Ok(path) = handoff_path(app) {
        let _ = std::fs::remove_file(path);
    }
    if let Ok(dir) = pending_dir(app) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// What a staged installer actually is, according to the signed document it came
/// from rather than the local record that points at it.
struct HandoffClaim {
    version: Version,
    security_epoch: u64,
    /// `exe` or `msi`, from the manifest's own URL for this artifact.
    kind: &'static str,
    /// The manifest's hash and signature for the artifact, which are what the
    /// staged bytes get checked against.
    sha256: String,
    signature: String,
}

/// Re-establish what the staged installer claims to be, from our own signature
/// over the manifest it came with.
///
/// Nothing in [`UpdateHandoff`] is trustworthy on its own: it is a JSON file in
/// the data directory, so anything running as the user can rewrite it. The
/// artifact signature does not close that gap either, because it attests to
/// *bytes* and says nothing about which version they are — so an old, genuinely
/// signed Ember installer paired with a rewritten `version` high enough to clear
/// the rollback floor would have been offered to the user and run.
///
/// The manifest is the missing half. It is signed as a whole with the same key,
/// and it pairs a version with each artifact's hash, so a hash that appears in it
/// can only be claimed as the version that document declares. Replaying a genuine
/// older manifest is possible and harmless: it names its own older version, which
/// the newer-than-running check then refuses.
///
/// Note which check carries that weight. The rollback floor is itself an
/// unauthenticated file in the same directory, so against an attacker who can
/// write there it is not a defence at all — "strictly newer than the running
/// build" is, because the running version is the binary's own. What remains is
/// that such an attacker can make Ember install some genuinely published release
/// newer than the one running, which is a great deal less than the any-signed-
/// installer-as-any-version they had before, and is bounded by what we ourselves
/// have released.
fn verified_handoff_claim(record: &UpdateHandoff) -> Result<HandoffClaim> {
    if record.manifest.is_empty() || record.manifest_signature.is_empty() {
        bail!("the staged update predates manifest binding and cannot be re-verified");
    }
    let config = embedded_updater_config()?;
    verify_minisign(
        record.manifest.as_bytes(),
        record.manifest_signature.as_bytes(),
        &config.public_key,
    )
    .context("the staged update's manifest is not signed by this build's updater key")?;
    claim_from_signed_manifest(
        &record.manifest,
        &record.sha256,
        &record.signature,
        &config.public_key,
    )
}

/// The claim a manifest supports, once its signature has already been checked.
///
/// Split from [`verified_handoff_claim`] so the step that matters — that the
/// version comes from the signed document and not from the marker beside it — can
/// be tested without the signing key.
fn claim_from_signed_manifest(
    manifest: &str,
    sha256: &str,
    signature: &str,
    public_key: &str,
) -> Result<HandoffClaim> {
    let raw: serde_json::Value =
        serde_json::from_str(manifest).context("the staged update's manifest is not JSON")?;
    let (manifest, _, version) = validate_manifest(raw, public_key)?;

    // Locate the artifact the marker points at. The marker chooses which entry,
    // but every value acted on afterwards comes from the entry itself, so the
    // worst it can do is select another platform's build of the same version.
    let platform = manifest
        .platforms
        .values()
        .find(|platform| platform.sha256 == sha256 && platform.signature == signature)
        .context("the staged installer is not an artifact of its own signed manifest")?;

    Ok(HandoffClaim {
        version,
        security_epoch: manifest.security_epoch,
        kind: installer_kind(&platform.url),
        sha256: platform.sha256.clone(),
        signature: platform.signature.clone(),
    })
}

/// The staged version, expressed as the rollback identity the anti-rollback
/// floor is compared against.
fn handoff_rollback_state(claim: &HandoffClaim) -> RollbackState {
    RollbackState {
        security_epoch: claim.security_epoch,
        highest_version: claim.version.to_string(),
    }
}

/// Whether the staged version is still allowed by the persisted security floor.
///
/// The install path refuses a verified artifact that has fallen below the floor,
/// and running the staged copy has to refuse it for the same reason: the bytes
/// being genuinely the bytes we verified says nothing about whether that version
/// is still one we are willing to install. A signed observation of a newer epoch
/// between the failed hand-off and now is exactly the case the floor exists for.
/// `None` when there is no floor on disk to compare against.
///
/// The distinction matters because the two answers deserve opposite treatment. A
/// staged build genuinely below a recorded floor is finished — delete it. A
/// *missing* floor file is not evidence of anything: it means the state file was
/// never written or has since been removed, which is exactly the ambiguous case
/// where destroying the staged bytes is the wrong move, and the same reason a
/// corrupt floor file is already left alone. `pending_meets_persisted_floor`
/// folds both into `false` because on the online path there is always another
/// download to fall back on; here there is not.
fn handoff_meets_floor(app: &AppHandle, claim: &HandoffClaim) -> Result<Option<bool>> {
    let path = state_path(app)?;
    if load_rollback_state(&path)?.is_none() {
        return Ok(None);
    }
    pending_meets_persisted_floor(&path, &handoff_rollback_state(claim)).map(Some)
}

/// Whether running the staged installer would move this machine forward.
///
/// The floor alone does not answer this. It tracks the highest version we have
/// *observed advertised*, which a manually installed build never touches — so
/// with a 1.5.3 installer staged and 1.5.4 since installed by hand, the floor
/// still reads 1.5.3, the staged copy sits exactly at it, and offering to run it
/// would silently downgrade the machine. Equality is the ordinary success case,
/// where the installer did run and this is the new build.
///
/// Decided by [`should_offer_update`], the same comparator the online path uses,
/// so the epoch keeps its meaning here. Comparing bare versions instead would
/// have withdrawn recovery from the one release that needs it most: an emergency
/// epoch bump exists precisely to authorize a *lower* version number, and a
/// version-only test reads that as a downgrade and deletes the staged installer.
fn handoff_is_an_upgrade(app: &AppHandle, claim: &HandoffClaim) -> bool {
    staged_claim_is_an_upgrade(
        claim.security_epoch,
        &claim.version,
        &app.package_info().version.to_string(),
    )
}

fn staged_claim_is_an_upgrade(staged_epoch: u64, staged: &Version, running: &str) -> bool {
    match Version::parse(running) {
        Ok(running) => should_offer_update(CURRENT_SECURITY_EPOCH, &running, staged_epoch, staged),
        // A running version we cannot parse is not a version we can compare
        // against, and guessing in the permissive direction is how downgrades
        // happen.
        Err(_) => false,
    }
}

/// Re-check the staged installer against the hash and signature it was
/// originally verified with, and return its path.
///
/// The bytes have been sitting on disk since the failed attempt, so they are
/// treated exactly like bytes off the network: nothing is executed on the
/// strength of having written it earlier.
fn verified_installer_path(app: &AppHandle, claim: &HandoffClaim) -> Result<PathBuf> {
    let path = pending_dir(app)?.join(installer_name(&claim.version.to_string(), claim.kind));
    let bytes = std::fs::read(&path).context("the staged installer is no longer present")?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != claim.sha256 {
        bail!("the staged installer no longer matches its signed hash");
    }
    let config = embedded_updater_config()?;
    verify_minisign(&bytes, claim.signature.as_bytes(), &config.public_key)?;
    Ok(path)
}

fn load_rollback_state(path: &Path) -> Result<Option<RollbackState>> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .context("updater rollback state is corrupt"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("failed to read updater rollback state"),
    }
}

fn save_rollback_state(path: &Path, state: &RollbackState) -> Result<()> {
    let bytes = serde_json::to_vec(state).context("failed to serialize updater rollback state")?;
    crate::security::atomic_write(path, &bytes, true)
        .context("failed to persist updater rollback state")
}

fn rollback_state_identity(state: &RollbackState) -> Result<(u64, Version)> {
    Ok((
        state.security_epoch,
        Version::parse(&state.highest_version).context("updater rollback state is corrupt")?,
    ))
}

fn persist_observed_floor(
    path: &Path,
    current_epoch: u64,
    current_version: &Version,
    observed_epoch: u64,
    observed_version: &Version,
) -> Result<RollbackState> {
    let stored = load_rollback_state(path)?;
    reject_rollback(
        current_epoch,
        current_version,
        stored.as_ref(),
        observed_epoch,
        observed_version,
    )?;
    let observed = observed_rollback_state(observed_epoch, observed_version);
    save_rollback_state(path, &observed)
        .map_err(|error| error.context(SignedObservationPersistenceFailed))?;
    Ok(observed)
}

fn pending_meets_persisted_floor(path: &Path, candidate: &RollbackState) -> Result<bool> {
    let Some(stored) = load_rollback_state(path)? else {
        // A checked update is inseparable from its durable observation floor.
        // Missing state must not silently make an old in-memory artifact valid.
        return Ok(false);
    };
    Ok(rollback_state_identity(candidate)? >= rollback_state_identity(&stored)?)
}

fn retain_only_pending_at_floor(pending: &mut Option<PendingUpdate>) -> Result<()> {
    let keep = match pending.as_ref() {
        Some(update) => {
            pending_meets_persisted_floor(&update.rollback_path, &update.candidate_state)?
        }
        None => true,
    };
    if !keep {
        pending.take();
    }
    Ok(())
}

fn matching_platform(manifest: &SignedManifest, update: &Update) -> Result<SignedPlatform> {
    let matches: Vec<&SignedPlatform> = manifest
        .platforms
        .values()
        .filter(|platform| {
            platform.url == update.download_url
                && platform.signature.trim() == update.signature.trim()
        })
        .collect();
    let first = matches.first().ok_or_else(|| {
        anyhow!("plugin-selected updater artifact was not in the signed manifest")
    })?;
    if matches.iter().any(|platform| {
        platform.sha256 != first.sha256
            || platform.size != first.size
            || platform.url != first.url
            || platform.signature.trim() != first.signature.trim()
    }) {
        bail!("duplicate signed updater targets disagree");
    }
    Ok((*first).clone())
}

async fn secure_check(app: &AppHandle) -> Result<Option<(UpdateInfo, PendingUpdate)>> {
    let config = embedded_updater_config()?;
    let signature_endpoint = signature_url(&config.endpoint)?;
    let manifest_response = match fetch_capped(
        &config.endpoint,
        MANIFEST_MAX_BYTES,
        METADATA_DEADLINE,
        "application/json",
        NetworkPolicy::PRODUCTION,
    )
    .await
    {
        Ok(response) => response,
        Err(error) if is_missing_updater_resource(&error) => {
            tracing::debug!(
                "Secure updater manifest missing at configured endpoint; treating as no update"
            );
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let signature_response = match fetch_capped(
        &signature_endpoint,
        SIGNATURE_MAX_BYTES,
        METADATA_DEADLINE,
        "application/octet-stream",
        NetworkPolicy::PRODUCTION,
    )
    .await
    {
        Ok(response) => response,
        Err(error) if is_missing_updater_resource(&error) => {
            tracing::warn!(
                "Secure updater signature missing at configured endpoint; refusing to treat as up to date"
            );
            return Err(UpdaterSignatureMissing.into());
        }
        Err(error) => return Err(error),
    };
    verify_minisign(
        &manifest_response.bytes,
        &signature_response.bytes,
        &config.public_key,
    )?;

    let raw_json: serde_json::Value = serde_json::from_slice(&manifest_response.bytes)
        .context("signed updater manifest is not JSON")?;
    let (manifest, verified_json, manifest_version) =
        validate_manifest(raw_json, &config.public_key)?;
    let current_version = app.package_info().version.clone();
    let rollback_path = state_path(app)?;
    let stored_floor = load_rollback_state(&rollback_path)?;
    if candidate_is_older_than_running_build_only(
        CURRENT_SECURITY_EPOCH,
        &current_version,
        stored_floor.as_ref(),
        manifest.security_epoch,
        &manifest_version,
    )? {
        // Nothing to offer, and nothing to ratchet: persisting here would lower
        // the observation floor. Returning early also skips the plugin's second
        // fetch, which could only produce the same older release.
        tracing::debug!(
            "Signed updater manifest advertises {} which is older than the running build; treating as no update",
            manifest.version
        );
        return Ok(None);
    }
    // Ratchet immediately after the signed document is fully parsed and
    // accepted. The plugin's deliberately independent second fetch is still
    // fallible; delaying this write until after it allowed an older pending
    // artifact to survive a failed re-fetch of a newer signed observation.
    let candidate_state = persist_observed_floor(
        &rollback_path,
        CURRENT_SECURITY_EPOCH,
        &current_version,
        manifest.security_epoch,
        &manifest_version,
    )?;

    // The plugin is still responsible for constructing the platform-specific
    // Update and installing it. It fetches only the already-vetted final URL,
    // with redirects/proxies disabled. Exact raw_json equality binds that
    // second fetch to the signed bytes and closes the double-fetch TOCTOU gap.
    //
    // Eligibility uses an epoch-aware comparator: the default plugin rule
    // (`release.version > current`) would ignore security-epoch bumps that
    // ship a lower version number.
    let final_host = manifest_response
        .final_url
        .host_str()
        .ok_or_else(|| anyhow!("vetted updater endpoint lost its host"))?
        .to_string();
    let final_addresses = manifest_response.final_addresses.clone();
    let offer_epoch = manifest.security_epoch;
    let offer_version = manifest_version.clone();
    let updater = app
        .updater_builder()
        .endpoints(vec![manifest_response.final_url.clone()])
        .context("failed to set updater endpoint")?
        .no_proxy()
        .timeout(METADATA_DEADLINE)
        .version_comparator(move |current, release| {
            release.version == offer_version
                && should_offer_update(
                    CURRENT_SECURITY_EPOCH,
                    &current,
                    offer_epoch,
                    &offer_version,
                )
        })
        .configure_client(move |builder| {
            builder
                .no_proxy()
                .redirect(RedirectPolicy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(READ_TIMEOUT)
                .resolve_to_addrs(&final_host, &final_addresses)
        })
        .build()
        .context("failed to build Tauri updater")?;
    let update = updater
        .check()
        .await
        .context("Tauri updater check failed")?;
    let pending_parts = if let Some(update) = update {
        if update.raw_json != verified_json {
            bail!("Tauri updater metadata differed from the signed manifest");
        }
        if update.version != manifest.version
            || update.current_version != current_version.to_string()
        {
            bail!("Tauri updater version differed from the signed manifest");
        }
        let platform = matching_platform(&manifest, &update)?;
        Some((update, platform))
    } else {
        None
    };

    let Some((update, platform)) = pending_parts else {
        return Ok(None);
    };

    let info = UpdateInfo {
        version: manifest.version,
        security_epoch: manifest.security_epoch,
        notes: manifest.notes,
        date: manifest.pub_date,
    };
    // Both were verified above: the manifest against its detached signature, the
    // signature against the embedded key. They are UTF-8 by construction — the
    // manifest parsed as JSON and `parse_signature` requires text.
    let manifest_text = String::from_utf8(manifest_response.bytes)
        .context("signed updater manifest is not UTF-8")?;
    let manifest_signature = String::from_utf8(signature_response.bytes)
        .context("signed updater signature is not UTF-8")?;
    Ok(Some((
        info.clone(),
        PendingUpdate {
            update,
            platform,
            rollback_path,
            candidate_state,
            info,
            manifest: manifest_text,
            manifest_signature,
        },
    )))
}

async fn download_artifact(
    platform: &SignedPlatform,
    public_key: &str,
    on_event: &Channel<UpdateProgress>,
) -> Result<Vec<u8>> {
    validate_url(&platform.url, NetworkPolicy::PRODUCTION)?;
    let expected_size = usize::try_from(platform.size)
        .context("signed updater artifact size does not fit this platform")?;
    let deadline = Instant::now() + ARTIFACT_DEADLINE;
    let (response, _, _) = send_with_redirects(
        &platform.url,
        NetworkPolicy::PRODUCTION,
        deadline,
        "application/octet-stream",
    )
    .await?;
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length != platform.size)
    {
        bail!("updater artifact Content-Length differed from signed size");
    }

    let _ = on_event.send(UpdateProgress::Started {
        content_length: platform.size,
    });
    let mut artifact = Vec::with_capacity(expected_size.min(16 * 1024 * 1024));
    let mut hasher = Sha256::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = timeout(remaining(deadline)?, stream.next())
        .await
        .context("updater artifact body timed out")?
    {
        let chunk = chunk.context("failed to read updater artifact")?;
        if artifact.len().saturating_add(chunk.len()) > expected_size {
            bail!("updater artifact exceeded its signed size");
        }
        hasher.update(&chunk);
        artifact.extend_from_slice(&chunk);
        let _ = on_event.send(UpdateProgress::Progress {
            chunk_length: chunk.len() as u64,
        });
    }
    if artifact.len() != expected_size {
        bail!("updater artifact was truncated");
    }
    let actual_hash = hex::encode(hasher.finalize());
    if actual_hash != platform.sha256 {
        bail!("updater artifact SHA-256 did not match signed metadata");
    }
    verify_minisign(&artifact, platform.signature.as_bytes(), public_key)?;
    let _ = on_event.send(UpdateProgress::Finished);
    Ok(artifact)
}

/// Which updater operation a failure is being reported for.
///
/// An enum rather than the log label it used to be, so the label and the
/// frontend error code cannot drift apart, and so every code stays a literal
/// at its `coded()` call site: `scripts/error-codes.test.mjs` only scans
/// construction sites, so a code threaded through a variable would slip past
/// the ratchet that exists to keep these translated.
#[derive(Clone, Copy)]
enum UpdaterOperation {
    Check,
    Install,
    /// Startup report of a hand-off that never produced the new version. The
    /// frontend discards a failure here (nothing to say is not an error), so
    /// this envelope is never displayed — it is coded anyway rather than
    /// leaving one operation able to reach the UI untranslated if that ever
    /// changes.
    HandoffCheck,
    InstallerLaunch,
}

/// Log the real cause and hand the UI a translatable, deliberately vague
/// envelope. The underlying error is not carried as context: what fails here
/// is signature/manifest/network internals the user cannot act on, and the
/// original message kept them to the log for that reason.
fn public_failure(operation: UpdaterOperation, error: anyhow::Error) -> String {
    let (label, envelope) = match operation {
        UpdaterOperation::Check => (
            "check",
            coded(
                "updater_check_failed",
                "Secure update check failed. Please try again later.",
            ),
        ),
        UpdaterOperation::Install => (
            "install",
            coded(
                "updater_install_failed",
                "Secure update install failed. Please try again later.",
            ),
        ),
        UpdaterOperation::HandoffCheck => (
            "hand-off check",
            coded(
                "updater_handoff_check_failed",
                "Secure update hand-off check failed. Please try again later.",
            ),
        ),
        UpdaterOperation::InstallerLaunch => (
            "installer launch",
            coded(
                "updater_launch_failed",
                "Secure update installer launch failed. Please try again later.",
            ),
        ),
    };
    tracing::warn!("Secure updater {label} failed: {error:#}");
    envelope
}

#[tauri::command]
pub async fn secure_updater_check(
    app: AppHandle,
    service: State<'_, UpdaterService>,
) -> Result<SecureUpdateCheckResult, String> {
    let _operation = service.operation.lock().await;
    match secure_check(&app).await {
        Ok(Some((info, pending))) => {
            *service.pending.lock().await = Some(pending);
            Ok(SecureUpdateCheckResult {
                update: Some(info),
                pending_retained: true,
                error: None,
                signature_missing: false,
            })
        }
        Ok(None) => {
            let mut pending = service.pending.lock().await;
            if let Err(error) = retain_only_pending_at_floor(&mut pending) {
                pending.take();
                return Err(public_failure(UpdaterOperation::Check, error));
            }
            Ok(SecureUpdateCheckResult {
                // Re-offer retained metadata so the UI can restore Install even
                // after a prior IPC failure cleared its local pending flag.
                update: pending.as_ref().map(|pending| pending.info.clone()),
                pending_retained: pending.is_some(),
                error: None,
                signature_missing: false,
            })
        }
        Err(error) => {
            let mut pending = service.pending.lock().await;
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<SignedObservationPersistenceFailed>()
                    .is_some()
            }) {
                // We accepted a newer signed document but could not durably
                // record it. Keeping any old artifact installable would fail
                // open across the exact persistence failure the ratchet is
                // intended to cover.
                pending.take();
            } else if let Err(state_error) = retain_only_pending_at_floor(&mut pending) {
                tracing::warn!(
                    "Secure updater could not validate pending state after failed check: {state_error:#}"
                );
                pending.take();
            }
            // Return structured retention state so the UI cannot keep offering
            // Install after native pending was cleared, and can restore it when
            // native still holds a verified artifact.
            let signature_missing = is_missing_updater_signature(&error);
            Ok(SecureUpdateCheckResult {
                update: pending.as_ref().map(|pending| pending.info.clone()),
                pending_retained: pending.is_some(),
                error: Some(public_failure(UpdaterOperation::Check, error)),
                signature_missing,
            })
        }
    }
}

#[tauri::command]
pub async fn secure_updater_install(
    app: AppHandle,
    service: State<'_, UpdaterService>,
    on_event: Channel<UpdateProgress>,
) -> Result<(), String> {
    let _operation = service.operation.lock().await;
    let mut pending = service.pending.lock().await;
    let Some(update) = pending.as_ref() else {
        return Err(coded(
            "updater_no_pending_update",
            "No verified update is ready to install.",
        ));
    };
    if !pending_meets_persisted_floor(&update.rollback_path, &update.candidate_state)
        .map_err(|error| public_failure(UpdaterOperation::Install, error))?
    {
        pending.take();
        return Err(coded(
            "updater_pending_below_floor",
            "The previously checked update is older than the signed security floor. Check for updates again.",
        ));
    }
    let config = embedded_updater_config()
        .map_err(|error| public_failure(UpdaterOperation::Install, error))?;
    let artifact = download_artifact(&update.platform, &config.public_key, &on_event)
        .await
        .map_err(|error| public_failure(UpdaterOperation::Install, error))?;
    // Record the attempt and keep the verified bytes before handing them over.
    // `install` does not come back on success, so this is the only chance to
    // leave behind anything that a later launch could act on. A failure here is
    // logged and ignored: losing the safety net is not a reason to refuse the
    // update itself.
    if let Err(error) = save_handoff(
        &app,
        &update.platform,
        &update.info.version,
        update.info.security_epoch,
        &update.manifest,
        &update.manifest_signature,
        &artifact,
    ) {
        tracing::warn!("Could not stage the update hand-off record: {error:#}");
    }
    // Re-read after the long download as well. Another process may have
    // observed a newer signed floor while this process was downloading.
    if !pending_meets_persisted_floor(&update.rollback_path, &update.candidate_state)
        .map_err(|error| public_failure(UpdaterOperation::Install, error))?
    {
        pending.take();
        return Err(coded(
            "updater_superseded_while_downloading",
            "A newer signed update was observed while downloading. Check for updates again.",
        ));
    }
    // `Update::install` never comes back on Windows: it hands the bundle to the
    // NSIS/MSI installer and then calls `std::process::exit(0)`. The plugin's
    // own `on_before_exit` hook is `AppHandle::cleanup_before_exit`, which only
    // clears tray icons/resource tables and hides windows — `RunEvent::Exit` is
    // never dispatched, so without this every installed update would abandon
    // the .part.met gap maps, nodes.dat, the known.met checkpoint that exists
    // precisely so AICH doesn't rehash from scratch, sources.met, server.met,
    // reputation and stats at their last periodic save, and would skip graceful
    // ed2k-server / rendezvous deregistration.
    //
    // Done here rather than by overriding `on_before_exit`, because that hook
    // runs synchronously on a runtime worker inside `install`: bridging back to
    // async from there means blocking that worker while another thread drives
    // the shutdown, and on a single-worker runtime that starves the very
    // network task we would be waiting on. Awaiting from the command yields the
    // worker instead. `run_graceful_shutdown` is internally bounded and safe to
    // run again from a later `RunEvent::Exit`; the outer timeout is the
    // backstop for a lock inside it that never becomes available.
    if timeout(
        crate::SHUTDOWN_WAIT + Duration::from_secs(15),
        crate::run_graceful_shutdown(&app, crate::SHUTDOWN_WAIT),
    )
    .await
    .is_err()
    {
        tracing::error!(
            "Graceful shutdown did not complete before the update install deadline; proceeding with a possibly truncated flush"
        );
    }

    if let Err(error) = update.update.install(&artifact) {
        tracing::warn!("Secure updater install failed: {error}");
        // Distinct from `public_failure`: the teardown above already stopped
        // Ember's network services, so this process is no longer transferring
        // even though the window is still up.
        return Err(coded(
            "updater_install_failed_services_stopped",
            "Secure update install failed. Ember stopped its network services for the update; restart Ember to resume transfers.",
        ));
    }
    pending.take();
    Ok(())
}

/// Whether the last hand-off to an installer failed to produce the new version.
///
/// Called on startup, and reports at most one thing: a staged installer for a
/// release strictly newer than the running build, which the UI can offer again.
///
/// Everything else returns `None`. A record that cannot be re-verified against
/// its signed manifest, one that is no longer an upgrade (the ordinary success
/// case — the installer ran and this is the new build), and one below the recorded
/// security floor are all cleaned up silently. A record whose floor cannot be read
/// is left alone deliberately: see [`handoff_meets_floor`].
///
/// The retention window is still judged from the marker's own `attempted_at`,
/// which is not authenticated — there is no signed timestamp to replace it with.
/// The only thing a rewritten one buys is keeping an offer alive that every other
/// check here already has to pass, or discarding it early, which the attacker
/// could do by deleting the file anyway.
#[tauri::command]
pub async fn secure_updater_handoff_status(
    app: AppHandle,
) -> Result<Option<UpdateHandoffReport>, String> {
    let path =
        handoff_path(&app).map_err(|error| public_failure(UpdaterOperation::HandoffCheck, error))?;
    let record = match read_handoff(&path) {
        Ok(Some(record)) => record,
        Ok(None) => return Ok(None),
        Err(error) => {
            // An unreadable marker is not worth surfacing, and keeping it would
            // make every launch retry the same parse.
            tracing::warn!("Discarding an unreadable update hand-off record: {error:#}");
            clear_handoff(&app);
            return Ok(None);
        }
    };

    let claim = match verified_handoff_claim(&record) {
        Ok(claim) => claim,
        Err(error) => {
            // Either the marker was tampered with or it refers to bytes its own
            // manifest does not contain. Nothing here can be offered, and keeping
            // it would make every launch repeat the same work.
            tracing::warn!("Discarding an unverifiable update hand-off record: {error:#}");
            clear_handoff(&app);
            return Ok(None);
        }
    };

    // Anything not strictly newer than what is running has nothing to offer:
    // equality is the ordinary success case, and older means the machine moved on
    // without us. Both are reasons to clean up rather than to prompt.
    if !handoff_is_an_upgrade(&app, &claim) {
        tracing::info!(
            "Clearing the staged installer for {}: {} is running",
            claim.version,
            app.package_info().version
        );
        clear_handoff(&app);
        return Ok(None);
    }

    let age = chrono::Utc::now()
        .timestamp()
        .saturating_sub(record.attempted_at);
    if !(0..=HANDOFF_MAX_AGE_SECS).contains(&age) {
        clear_handoff(&app);
        return Ok(None);
    }

    // A staged build that has fallen below the signed security floor can never
    // be run, so there is nothing to offer and no reason to keep its bytes. Say
    // nothing and let the ordinary check surface whatever superseded it.
    match handoff_meets_floor(&app, &claim) {
        Ok(Some(true)) => {}
        Ok(Some(false)) => {
            tracing::info!(
                "Discarding the staged installer for {}: it is below the signed security floor",
                claim.version
            );
            clear_handoff(&app);
            return Ok(None);
        }
        // No floor, or one we could not read: say nothing and keep the bytes. The
        // launch path refuses on the same evidence, so nothing can be run until a
        // check writes a floor again — at which point this offer becomes usable
        // rather than having been thrown away.
        Ok(None) => {
            tracing::warn!(
                "Not offering the staged installer for {}: no security floor is recorded yet",
                claim.version
            );
            return Ok(None);
        }
        Err(error) => {
            tracing::warn!(
                "Could not check the staged installer against the security floor: {error:#}"
            );
            return Ok(None);
        }
    }

    // Report the stall either way. Staged bytes that have since been quarantined
    // or truncated mean there is nothing to relaunch, but that is still the
    // explanation for why Ember closed itself and nothing happened — the notice
    // says so and points at checking for updates instead, which is a recovery the
    // user can actually carry out.
    let installer_ready = match verified_installer_path(&app, &claim) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!(
                "Staged installer for {} is unusable: {error:#}",
                claim.version
            );
            false
        }
    };
    tracing::warn!(
        "Update to {} was handed to an installer {age}s ago but {} is still running; \
         the installer did not complete (staged copy usable: {installer_ready})",
        claim.version,
        record.from_version,
    );
    Ok(Some(UpdateHandoffReport {
        version: claim.version.to_string(),
        security_epoch: claim.security_epoch,
        attempted_at: record.attempted_at,
        installer_ready,
    }))
}

/// Launch the staged installer again after a hand-off that never ran.
///
/// Deliberately interactive: no silent or passive flags. The first attempt was
/// the invisible one, and if something is going to refuse this binary the user
/// should be able to see it happen and answer whatever prompt appears.
#[tauri::command]
pub async fn secure_updater_run_saved_installer(app: AppHandle) -> Result<(), String> {
    let path = handoff_path(&app)
        .map_err(|error| public_failure(UpdaterOperation::InstallerLaunch, error))?;
    let Some(record) = read_handoff(&path)
        .map_err(|error| public_failure(UpdaterOperation::InstallerLaunch, error))?
    else {
        return Err(coded(
            "updater_no_staged_installer",
            "There is no staged installer to run.",
        ));
    };
    // Re-establish what this actually is before deciding anything about it. The
    // record's own fields are not evidence — see `verified_handoff_claim`.
    let claim = verified_handoff_claim(&record).map_err(|error| {
        tracing::warn!("Refusing to run the staged installer: {error:#}");
        clear_handoff(&app);
        coded(
            "updater_staged_unverified",
            "The staged installer could not be verified against its signed manifest. Check for updates again.",
        )
    })?;
    // Anti-rollback next, exactly as the install path does it. Verified bytes are
    // not the same question as a permitted version, and a permitted version is
    // not the same question as a newer one.
    if !handoff_is_an_upgrade(&app, &claim) {
        clear_handoff(&app);
        return Err(coded(
            "updater_staged_not_newer",
            "The staged update is not newer than the version already installed.",
        ));
    }
    match handoff_meets_floor(&app, &claim)
        .map_err(|error| public_failure(UpdaterOperation::InstallerLaunch, error))?
    {
        Some(true) => {}
        Some(false) => {
            clear_handoff(&app);
            return Err(coded(
                "updater_staged_below_floor",
                "The staged update is older than the signed security floor. Check for updates again.",
            ));
        }
        // Refuse, but keep the bytes: a floor we cannot read is not evidence of a
        // rollback. See `handoff_meets_floor`.
        None => {
            return Err(coded(
                "updater_no_security_floor",
                "Ember has no record of the current update security level yet. Check for updates first.",
            ));
        }
    }
    // A first pass before tearing the network stack down, so a staged copy that
    // has already gone does not cost the user their session for nothing. It is not
    // the check that authorises the launch.
    verified_installer_path(&app, &claim).map_err(|error| {
        tracing::warn!("Refusing to run the staged installer: {error:#}");
        coded(
            "updater_staged_installer_unusable",
            "The staged installer is missing or no longer matches its signature. Check for updates again.",
        )
    })?;

    // Same reasoning as the install path: the installer replaces files this
    // process has open, so flush and stop everything we own first.
    if timeout(
        crate::SHUTDOWN_WAIT + Duration::from_secs(15),
        crate::run_graceful_shutdown(&app, crate::SHUTDOWN_WAIT),
    )
    .await
    .is_err()
    {
        tracing::error!(
            "Graceful shutdown did not complete before the installer launch deadline; proceeding with a possibly truncated flush"
        );
    }

    // Re-verify here, with nothing between this and the spawn. Shutting down takes
    // seconds — long enough for anything running as the user to overwrite the file
    // in the window after a check — and this is the one path that then executes it.
    // Verifying before the flush and trusting it afterwards would make the
    // "nothing is executed on the strength of having written it earlier" rule
    // hold only for the first few seconds.
    //
    // No elevation is involved, and the spawn below could not produce it if it
    // were: `Command::spawn` is `CreateProcessW`, which never shows the UAC
    // consent dialog and simply fails with ERROR_ELEVATION_REQUIRED against a
    // binary whose manifest asks for admin. That is fine only because
    // `bundle.windows.nsis.installMode` is unset, so NSIS defaults to
    // `currentUser` and emits `RequestExecutionLevel user`. Setting it to
    // `perMachine` or `both` would break this path — and only this path, since
    // the updater plugin's own install uses `ShellExecuteW` — so that change has
    // to come with a switch to `ShellExecuteW` here. The MSI branch is unaffected
    // either way: `msiexec` elevates through the Windows Installer service.
    let installer = verified_installer_path(&app, &claim).map_err(|error| {
        tracing::warn!("Refusing to run the staged installer: {error:#}");
        coded(
            "updater_staged_installer_changed",
            "The staged installer changed while Ember was closing down. Check for updates again.",
        )
    })?;

    let spawned = if claim.kind == "msi" {
        // Absolute, because `CreateProcessW` searches this process's own directory
        // and the working directory before the system one, so a bare name is a
        // planted-binary hazard under the same local-write attacker this whole
        // path is being careful about.
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        std::process::Command::new(PathBuf::from(system_root).join(r"System32\msiexec.exe"))
            .arg("/i")
            .arg(&installer)
            .spawn()
    } else {
        std::process::Command::new(&installer).spawn()
    };

    match spawned {
        Ok(_) => {
            // The marker stays: only a launch that finds itself running the new
            // version clears it, so a second silent failure still reports.
            tracing::info!("Launched the staged installer for {}", claim.version);
            std::process::exit(0);
        }
        Err(error) => {
            tracing::warn!("Could not launch the staged installer: {error}");
            // The teardown above already stopped Ember's network services, so the
            // window is still up but nothing is transferring. Saying only where
            // the file is would send the user off to run it by hand from an app
            // that looks healthy and is not; the install path spells the same
            // thing out for the same reason.
            Err(coded(
                "updater_launch_failed_services_stopped",
                "Windows would not start the installer. It is saved in Ember's data folder under \"updates\" if you want to run it yourself. Ember stopped its network services for the update; restart Ember to resume transfers.",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    const TEST_PUBLIC_KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
    const TEST_SIGNATURE: &str = "untrusted comment: signature from minisign secret key
RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=
trusted comment: timestamp:1555779966\tfile:test
QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==";

    #[test]
    fn update_info_serializes_security_epoch_for_frontend() {
        let serialized = serde_json::to_value(UpdateInfo {
            version: "2.0.0".to_string(),
            security_epoch: 7,
            notes: Some("Security release".to_string()),
            date: Some("2026-07-25T00:00:00Z".to_string()),
        })
        .unwrap();

        assert_eq!(serialized["version"], "2.0.0");
        assert_eq!(serialized["securityEpoch"], 7);
        assert!(serialized.get("security_epoch").is_none());
    }

    async fn local_response(response: &'static str) -> Url {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await;
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        Url::parse(&format!("http://{address}/fixture")).unwrap()
    }

    #[test]
    fn signed_payload_verification_rejects_tampering() {
        verify_minisign(b"test", TEST_SIGNATURE.as_bytes(), TEST_PUBLIC_KEY).unwrap();
        assert!(verify_minisign(b"tampered", TEST_SIGNATURE.as_bytes(), TEST_PUBLIC_KEY).is_err());
    }

    /// A staged installer with the version its own signed manifest declares.
    ///
    /// At the running epoch, so the version is what decides comparisons here. A
    /// higher epoch would legitimately authorize a lower version, which is a
    /// different property and has its own case in
    /// `a_staged_installer_must_be_newer_than_the_running_build`.
    fn staged_manifest(version: &str, sha256: &str) -> String {
        format!(
            r#"{{"version":"{version}","security_epoch":{epoch},"platforms":{{"windows-x86_64":{{"target":"windows-x86_64","url":"https://example.com/Ember_{version}_x64-setup.exe","signature":{signature},"sha256":"{sha256}","size":4096}}}}}}"#,
            epoch = CURRENT_SECURITY_EPOCH,
            signature = serde_json::to_string(TEST_SIGNATURE).unwrap(),
        )
    }

    /// The hand-off marker is a JSON file in the data directory, so anything
    /// running as the user can rewrite it, and the artifact signature attests to
    /// bytes rather than to a version. Believing the marker's own `version` was
    /// therefore a downgrade path: pair an old release's genuinely signed
    /// installer with a version high enough to clear the rollback floor and Ember
    /// would offer to run it. The version has to come from the signed document
    /// that pairs it with that artifact's hash.
    #[test]
    fn a_rewritten_marker_cannot_promote_an_old_installer() {
        let sha256 = "a".repeat(64);
        let manifest = staged_manifest("1.4.0", &sha256);

        let claim = claim_from_signed_manifest(&manifest, &sha256, TEST_SIGNATURE, TEST_PUBLIC_KEY)
            .unwrap();
        assert_eq!(
            claim.version,
            Version::parse("1.4.0").unwrap(),
            "the version must come from the manifest, whatever the marker claims"
        );
        assert_eq!(claim.security_epoch, CURRENT_SECURITY_EPOCH);
        assert_eq!(claim.kind, "exe");

        // And with that version established, the checks downstream refuse it.
        assert!(!staged_claim_is_an_upgrade(
            claim.security_epoch,
            &claim.version,
            "1.5.3"
        ));

        // A marker naming a hash the manifest does not contain is refused here.
        // Note this is not what stops a *new* manifest being paired with an old
        // installer — for that the attacker would name a real entry of the new
        // manifest, and it is `verified_installer_path` hashing the bytes on disk
        // against that entry which refuses them.
        let elsewhere = "b".repeat(64);
        assert!(
            claim_from_signed_manifest(&manifest, &elsewhere, TEST_SIGNATURE, TEST_PUBLIC_KEY)
                .is_err(),
            "an artifact absent from its own manifest cannot be claimed"
        );
    }

    /// The floor tracks the highest version ever *advertised*, which a manually
    /// installed build never touches — so a staged 1.5.3 sits exactly at the floor
    /// on a machine already running 1.5.4, and offering it would downgrade.
    ///
    /// The epoch has to keep its meaning here too. An emergency epoch bump exists
    /// to authorize a *lower* version number, so a version-only comparison would
    /// read that release as a downgrade and delete the staged installer for the one
    /// update most worth recovering.
    #[test]
    fn a_staged_installer_must_be_newer_than_the_running_build() {
        let staged = Version::parse("1.5.3").unwrap();
        let epoch = CURRENT_SECURITY_EPOCH;
        assert!(staged_claim_is_an_upgrade(epoch, &staged, "1.5.2"));
        assert!(
            !staged_claim_is_an_upgrade(epoch, &staged, "1.5.3"),
            "equality is the success case: the installer ran"
        );
        assert!(
            !staged_claim_is_an_upgrade(epoch, &staged, "1.5.4"),
            "and older than what is installed must never be offered"
        );
        assert!(
            !staged_claim_is_an_upgrade(epoch, &staged, "not-a-version"),
            "an unparseable running version cannot be compared, so refuse"
        );
        assert!(
            staged_claim_is_an_upgrade(epoch + 1, &Version::parse("1.4.0").unwrap(), "1.5.3"),
            "an epoch bump authorizes a lower version, and recovery must honour it"
        );
    }

    #[test]
    fn rollback_state_rejects_older_signed_release() {
        let current = Version::parse("1.2.3").unwrap();
        let stored = RollbackState {
            security_epoch: 2,
            highest_version: "2.0.0".to_string(),
        };
        assert!(reject_rollback(
            1,
            &current,
            Some(&stored),
            2,
            &Version::parse("1.9.9").unwrap(),
        )
        .is_err());
        reject_rollback(
            1,
            &current,
            Some(&stored),
            3,
            &Version::parse("1.0.0").unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn candidate_older_than_running_build_is_not_a_rollback_attack() {
        let current = Version::parse("1.2.3").unwrap();
        let older = Version::parse("1.2.2").unwrap();

        // Yanked release / self-built binary, nothing observed yet: no update.
        assert!(candidate_is_older_than_running_build_only(1, &current, None, 1, &older).unwrap());
        // Same, with a persisted floor the candidate still satisfies.
        let below = observed_rollback_state(1, &Version::parse("1.2.0").unwrap());
        assert!(
            candidate_is_older_than_running_build_only(1, &current, Some(&below), 1, &older)
                .unwrap()
        );

        // Below a signed observation we already recorded: still a hard error.
        let above = observed_rollback_state(1, &Version::parse("2.0.0").unwrap());
        assert!(
            !candidate_is_older_than_running_build_only(1, &current, Some(&above), 1, &older)
                .unwrap()
        );
        assert!(reject_rollback(1, &current, Some(&above), 1, &older).is_err());

        // Equal, newer, and epoch-bumped candidates all stay on the normal path.
        for (epoch, version) in [(1, "1.2.3"), (1, "1.3.0"), (2, "1.0.0")] {
            assert!(!candidate_is_older_than_running_build_only(
                1,
                &current,
                None,
                epoch,
                &Version::parse(version).unwrap(),
            )
            .unwrap());
        }
    }

    #[test]
    fn epoch_aware_offer_allows_lower_version_on_epoch_bump() {
        let current = Version::parse("1.2.3").unwrap();
        assert!(should_offer_update(
            1,
            &current,
            3,
            &Version::parse("1.0.0").unwrap(),
        ));
        assert!(should_offer_update(
            1,
            &current,
            1,
            &Version::parse("1.2.4").unwrap(),
        ));
        assert!(!should_offer_update(
            1,
            &current,
            1,
            &Version::parse("1.2.3").unwrap(),
        ));
        assert!(!should_offer_update(
            1,
            &current,
            1,
            &Version::parse("1.2.2").unwrap(),
        ));
    }

    #[test]
    fn signed_observation_raises_persisted_floor() {
        let path = std::env::temp_dir().join(format!(
            "ember-updater-rollback-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let current = Version::parse("1.2.3").unwrap();
        let stored = RollbackState {
            security_epoch: 1,
            highest_version: current.to_string(),
        };
        save_rollback_state(&path, &stored).unwrap();

        let observed = Version::parse("1.5.0").unwrap();
        reject_rollback(1, &current, Some(&stored), 1, &observed).unwrap();
        let raised = observed_rollback_state(1, &observed);
        save_rollback_state(&path, &raised).unwrap();
        assert_eq!(load_rollback_state(&path).unwrap(), Some(raised.clone()));
        assert!(reject_rollback(
            1,
            &current,
            Some(&raised),
            1,
            &Version::parse("1.4.9").unwrap(),
        )
        .is_err());

        let up_to_date = observed_rollback_state(1, &current);
        assert_eq!(up_to_date.highest_version, "1.2.3");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn newer_signed_observation_invalidates_pending_after_plugin_fetch_failure() {
        let path = std::env::temp_dir().join(format!(
            "ember-updater-pending-floor-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let running = Version::parse("1.0.0").unwrap();
        let pending_v2 = observed_rollback_state(1, &Version::parse("2.0.0").unwrap());
        save_rollback_state(&path, &pending_v2).unwrap();
        assert!(pending_meets_persisted_floor(&path, &pending_v2).unwrap());

        // This is the exact state transition when the signed v3 fetch and
        // validation succeed but the plugin's independent metadata fetch then
        // fails: the observation is durable before that fallible fetch.
        persist_observed_floor(&path, 1, &running, 1, &Version::parse("3.0.0").unwrap()).unwrap();
        assert!(!pending_meets_persisted_floor(&path, &pending_v2).unwrap());
        assert_eq!(
            load_rollback_state(&path).unwrap().unwrap().highest_version,
            "3.0.0"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn transient_check_failure_retains_same_floor_pending() {
        let path = std::env::temp_dir().join(format!(
            "ember-updater-same-floor-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let pending = observed_rollback_state(2, &Version::parse("2.5.0").unwrap());
        save_rollback_state(&path, &pending).unwrap();
        assert!(pending_meets_persisted_floor(&path, &pending).unwrap());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_updater_resource_is_detectable_through_anyhow() {
        let error =
            anyhow::Error::new(UpdaterResourceMissing).context("failed to read updater signature");
        assert!(is_missing_updater_resource(&error));
        assert!(!is_missing_updater_resource(&anyhow!(
            "updater server returned HTTP 500"
        )));
    }

    #[test]
    fn verified_json_binding_rejects_mutated_manifest_document() {
        let verified = serde_json::json!({
            "version": "1.2.4",
            "security_epoch": 1,
            "notes": null,
            "platforms": {
                "windows-x86_64-nsis": {
                    "target": "windows-x86_64-nsis",
                    "url": "https://example.invalid/Ember_1.2.4_x64-setup.nsis.zip",
                    "signature": "sig",
                    "sha256": "a".repeat(64),
                    "size": 12
                }
            }
        });
        let mut tampered = verified.clone();
        tampered["notes"] = serde_json::json!("mutated after sign");
        // secure_check binds the plugin re-fetch with exact Value equality.
        assert_ne!(tampered, verified);
    }

    #[test]
    fn production_urls_reject_credentials_downgrades_and_special_ips() {
        for value in [
            "http://github.com/release",
            "https://user:pass@github.com/release",
            "https://127.0.0.1/release",
            "https://169.254.169.254/release",
            "https://[::1]/release",
        ] {
            assert!(
                validate_url(&Url::parse(value).unwrap(), NetworkPolicy::PRODUCTION).is_err(),
                "{value} should be rejected"
            );
        }
        validate_url(
            &Url::parse("https://github.com/untaimed18/Ember-P2P/releases/latest").unwrap(),
            NetworkPolicy::PRODUCTION,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn capped_fetch_rejects_oversized_local_fixture() {
        let url = local_response(
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n12345",
        )
        .await;
        let error = fetch_capped(
            &url,
            4,
            Duration::from_secs(5),
            "application/octet-stream",
            NetworkPolicy::local_fixture(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("size limit"));
    }

    #[tokio::test]
    async fn redirect_revalidation_rejects_special_use_destination() {
        let url = local_response(
            "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest.json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        let error = fetch_capped(
            &url,
            1024,
            Duration::from_secs(5),
            "application/json",
            NetworkPolicy::local_fixture(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("private or special-use"));
    }
}
