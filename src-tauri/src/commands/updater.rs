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

/// Manifest or signature asset is absent at the configured endpoint. Treated as
/// "no update available" rather than a hard check failure — common when a
/// release exists without the hardened `latest.json.sig` yet.
#[derive(Debug)]
struct UpdaterResourceMissing;

impl std::fmt::Display for UpdaterResourceMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("updater resource not found")
    }
}

impl std::error::Error for UpdaterResourceMissing {}

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
    /// Version the saved installer installs.
    version: String,
    security_epoch: u64,
    /// Version we were running when we handed off, so a launch can tell
    /// "the installer never ran" from "it ran and this is the new build".
    from_version: String,
    /// `exe` or `msi`. The file name on disk is derived from this and the
    /// version, never read back from the marker, so a tampered marker cannot
    /// point us at an executable somewhere else.
    kind: String,
    sha256: String,
    signature: String,
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

/// The staged version, expressed as the rollback identity the anti-rollback
/// floor is compared against.
fn handoff_rollback_state(record: &UpdateHandoff) -> RollbackState {
    RollbackState {
        security_epoch: record.security_epoch,
        highest_version: record.version.clone(),
    }
}

/// Whether the staged version is still allowed by the persisted security floor.
///
/// The install path refuses a verified artifact that has fallen below the floor,
/// and running the staged copy has to refuse it for the same reason: the bytes
/// being genuinely the bytes we verified says nothing about whether that version
/// is still one we are willing to install. A signed observation of a newer epoch
/// between the failed hand-off and now is exactly the case the floor exists for.
fn handoff_meets_floor(app: &AppHandle, record: &UpdateHandoff) -> Result<bool> {
    pending_meets_persisted_floor(&state_path(app)?, &handoff_rollback_state(record))
}

/// Re-check the staged installer against the hash and signature it was
/// originally verified with, and return its path.
///
/// The bytes have been sitting on disk since the failed attempt, so they are
/// treated exactly like bytes off the network: nothing is executed on the
/// strength of having written it earlier.
fn verified_installer_path(app: &AppHandle, record: &UpdateHandoff) -> Result<PathBuf> {
    let path = pending_dir(app)?.join(installer_name(&record.version, &record.kind));
    let bytes = std::fs::read(&path).context("the staged installer is no longer present")?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != record.sha256 {
        bail!("the staged installer no longer matches its signed hash");
    }
    let config = embedded_updater_config()?;
    verify_minisign(&bytes, record.signature.as_bytes(), &config.public_key)?;
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
            // Stock Tauri releases may publish latest.json without the hardened
            // latest.json.sig. Until that asset exists, there is no signed update
            // to offer — not a check failure.
            tracing::debug!(
                "Secure updater signature missing at configured endpoint; treating as no update"
            );
            return Ok(None);
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
    Ok(Some((
        info.clone(),
        PendingUpdate {
            update,
            platform,
            rollback_path,
            candidate_state,
            info,
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

fn public_failure(operation: &str, error: anyhow::Error) -> String {
    tracing::warn!("Secure updater {operation} failed: {error:#}");
    format!("Secure update {operation} failed. Please try again later.")
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
            })
        }
        Ok(None) => {
            let mut pending = service.pending.lock().await;
            if let Err(error) = retain_only_pending_at_floor(&mut pending) {
                pending.take();
                return Err(public_failure("check", error));
            }
            Ok(SecureUpdateCheckResult {
                // Re-offer retained metadata so the UI can restore Install even
                // after a prior IPC failure cleared its local pending flag.
                update: pending.as_ref().map(|pending| pending.info.clone()),
                pending_retained: pending.is_some(),
                error: None,
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
            Ok(SecureUpdateCheckResult {
                update: pending.as_ref().map(|pending| pending.info.clone()),
                pending_retained: pending.is_some(),
                error: Some(public_failure("check", error)),
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
        return Err("No verified update is ready to install.".to_string());
    };
    if !pending_meets_persisted_floor(&update.rollback_path, &update.candidate_state)
        .map_err(|error| public_failure("install", error))?
    {
        pending.take();
        return Err(
            "The previously checked update is older than the signed security floor. Check for updates again."
                .to_string(),
        );
    }
    let config = embedded_updater_config().map_err(|error| public_failure("install", error))?;
    let artifact = download_artifact(&update.platform, &config.public_key, &on_event)
        .await
        .map_err(|error| public_failure("install", error))?;
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
        &artifact,
    ) {
        tracing::warn!("Could not stage the update hand-off record: {error:#}");
    }
    // Re-read after the long download as well. Another process may have
    // observed a newer signed floor while this process was downloading.
    if !pending_meets_persisted_floor(&update.rollback_path, &update.candidate_state)
        .map_err(|error| public_failure("install", error))?
    {
        pending.take();
        return Err(
            "A newer signed update was observed while downloading. Check for updates again."
                .to_string(),
        );
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
        return Err(
            "Secure update install failed. Ember stopped its network services for the update; restart Ember to resume transfers."
                .to_string(),
        );
    }
    pending.take();
    Ok(())
}

/// Whether the last hand-off to an installer failed to produce the new version.
///
/// Called on startup. Three outcomes: no record at all, a record whose version
/// is the one now running (the update worked — clean it up and say nothing), or
/// a record for a version we are still not running, which is reported so the UI
/// can offer the staged installer again.
#[tauri::command]
pub async fn secure_updater_handoff_status(
    app: AppHandle,
) -> Result<Option<UpdateHandoffReport>, String> {
    let path = handoff_path(&app).map_err(|error| public_failure("hand-off check", error))?;
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

    if record.version == app.package_info().version.to_string() {
        tracing::info!(
            "Update to {} completed; clearing the staged installer",
            record.version
        );
        clear_handoff(&app);
        return Ok(None);
    }

    let age = chrono::Utc::now()
        .timestamp()
        .saturating_sub(record.attempted_at);
    if age > HANDOFF_MAX_AGE_SECS || age < 0 {
        clear_handoff(&app);
        return Ok(None);
    }

    // A staged build that has fallen below the signed security floor can never
    // be run, so there is nothing to offer and no reason to keep its bytes. Say
    // nothing and let the ordinary check surface whatever superseded it.
    match handoff_meets_floor(&app, &record) {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(
                "Discarding the staged installer for {}: it is below the signed security floor",
                record.version
            );
            clear_handoff(&app);
            return Ok(None);
        }
        Err(error) => {
            tracing::warn!("Could not check the staged installer against the security floor: {error:#}");
            clear_handoff(&app);
            return Ok(None);
        }
    }

    let installer_ready = match verified_installer_path(&app, &record) {
        Ok(_) => true,
        Err(error) => {
            tracing::warn!("Staged installer for {} is unusable: {error:#}", record.version);
            false
        }
    };
    tracing::warn!(
        "Update to {} was handed to an installer {age}s ago but {} is still running; \
         the installer did not complete (staged copy usable: {installer_ready})",
        record.version,
        record.from_version,
    );
    Ok(Some(UpdateHandoffReport {
        version: record.version,
        security_epoch: record.security_epoch,
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
    let path = handoff_path(&app).map_err(|error| public_failure("installer launch", error))?;
    let Some(record) = read_handoff(&path)
        .map_err(|error| public_failure("installer launch", error))?
    else {
        return Err("There is no staged installer to run.".to_string());
    };
    // Anti-rollback first, exactly as the install path does it. Verified bytes
    // are not the same question as a permitted version.
    if !handoff_meets_floor(&app, &record)
        .map_err(|error| public_failure("installer launch", error))?
    {
        clear_handoff(&app);
        return Err(
            "The staged update is older than the signed security floor. Check for updates again."
                .to_string(),
        );
    }
    let installer = verified_installer_path(&app, &record).map_err(|error| {
        tracing::warn!("Refusing to run the staged installer: {error:#}");
        "The staged installer is missing or no longer matches its signature. Check for updates again."
            .to_string()
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

    let spawned = if record.kind == "msi" {
        std::process::Command::new("msiexec")
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
            tracing::info!("Launched the staged installer for {}", record.version);
            std::process::exit(0);
        }
        Err(error) => {
            tracing::warn!("Could not launch the staged installer: {error}");
            Err("Windows would not start the installer. It is saved in Ember's data folder under \"updates\" if you want to run it yourself.".to_string())
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
        let error = anyhow::Error::new(UpdaterResourceMissing)
            .context("failed to read updater signature");
        assert!(is_missing_updater_resource(&error));
        assert!(!is_missing_updater_resource(&anyhow!("updater server returned HTTP 500")));
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
