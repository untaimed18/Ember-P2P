//! Ember's signed releases, fetched: the manifest an update check reads and
//! its signature, the installers, collection and notes it names, and sharing
//! every file of each new release (`release_share`). The desktop updater
//! (`commands::updater`) installs from these; emberd, which has no updater,
//! uses them to share releases.

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
use tokio::time::{timeout, Instant};
use url::{Host, Url};

use crate::host::AppHandle;
use crate::net_bind::lookup_host;

pub(crate) const MANIFEST_MAX_BYTES: usize = 512 * 1024;
pub(crate) const SIGNATURE_MAX_BYTES: usize = 16 * 1024;
pub(crate) const ARTIFACT_MAX_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_REDIRECTS: usize = 5;
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const METADATA_DEADLINE: Duration = Duration::from_secs(60);
pub(crate) const ARTIFACT_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Manifest asset is absent at the configured endpoint. Treated as
/// "no update available" rather than a hard check failure. A missing
/// `latest.json.sig` when the manifest exists is [`UpdaterSignatureMissing`].
#[derive(Debug)]
pub(crate) struct UpdaterResourceMissing;

impl std::fmt::Display for UpdaterResourceMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("updater resource not found")
    }
}

impl std::error::Error for UpdaterResourceMissing {}

pub(crate) fn is_missing_updater_resource(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<UpdaterResourceMissing>().is_some())
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SignedManifest {
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) notes: Option<String>,
    #[serde(default)]
    pub(crate) pub_date: Option<String>,
    pub(crate) security_epoch: u64,
    pub(crate) platforms: BTreeMap<String, SignedPlatform>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SignedPlatform {
    pub(crate) target: String,
    pub(crate) url: Url,
    pub(crate) signature: String,
    pub(crate) sha256: String,
    pub(crate) size: u64,
    /// The oldest glibc the artifact runs on (`"2.39"`), for a Linux package
    /// built on a newer distro than the last one. See [`choose_glibc_target`].
    #[serde(default)]
    pub(crate) min_glibc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Clone, Copy)]
pub(crate) struct NetworkPolicy {
    pub(crate) allow_http_loopback: bool,
    /// Go through the proxy the OS or environment names for the address
    /// ([`system_proxy_for`]). Off for test fixtures, which must not depend
    /// on the machine running them.
    pub(crate) system_proxy: bool,
}

impl NetworkPolicy {
    pub(crate) const PRODUCTION: Self = Self {
        allow_http_loopback: false,
        system_proxy: true,
    };

    #[cfg(test)]
    pub(crate) const fn local_fixture() -> Self {
        Self {
            allow_http_loopback: true,
            system_proxy: false,
        }
    }

    pub(crate) fn allows_ip(self, ip: IpAddr) -> bool {
        if self.allow_http_loopback && ip.is_loopback() {
            return true;
        }
        is_public_ip(ip)
    }
}

#[derive(Debug)]
pub(crate) struct FetchedBytes {
    pub(crate) bytes: Vec<u8>,
    pub(crate) final_url: Url,
    pub(crate) final_addresses: Vec<SocketAddr>,
}

pub(crate) struct EmbeddedUpdaterConfig {
    pub(crate) endpoint: Url,
    pub(crate) public_key: String,
}

#[derive(Deserialize)]
pub(crate) struct EmbeddedConfig {
    plugins: EmbeddedPlugins,
}

#[derive(Deserialize)]
pub(crate) struct EmbeddedPlugins {
    updater: EmbeddedUpdater,
}

#[derive(Deserialize)]
pub(crate) struct EmbeddedUpdater {
    pubkey: String,
    endpoints: Vec<Url>,
}

pub(crate) fn embedded_updater_config() -> Result<EmbeddedUpdaterConfig> {
    let config: EmbeddedConfig = serde_json::from_str(include_str!("../tauri.conf.json"))
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

pub(crate) fn signature_url(manifest_url: &Url) -> Result<Url> {
    let mut url = manifest_url.clone();
    let path = url.path();
    if path.is_empty() || path.ends_with('/') {
        bail!("updater manifest URL has no filename");
    }
    url.set_path(&format!("{path}.sig"));
    Ok(url)
}

pub(crate) fn decode_utf8_base64(input: &str, label: &str) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .with_context(|| format!("{label} is not valid base64"))?;
    String::from_utf8(bytes).with_context(|| format!("{label} is not UTF-8"))
}

pub(crate) fn parse_public_key(encoded: &str) -> Result<PublicKey> {
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

pub(crate) fn parse_signature(encoded: &[u8]) -> Result<Signature> {
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

pub(crate) fn verify_minisign(payload: &[u8], encoded_signature: &[u8], encoded_key: &str) -> Result<()> {
    let public_key = parse_public_key(encoded_key)?;
    let signature = parse_signature(encoded_signature)?;
    public_key
        .verify(payload, &signature, true)
        .context("minisign verification failed")
}

pub(crate) fn validate_manifest(
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
        if platform
            .min_glibc
            .as_deref()
            .is_some_and(|min| parse_glibc(min).is_none())
        {
            bail!("signed updater glibc requirement is invalid");
        }
        if target.ends_with(GLIBC_GATED_SUFFIX) && platform.min_glibc.is_none() {
            bail!("signed updater glibc-gated entry states no glibc requirement");
        }
        // Parse now so a malformed signed artifact signature is rejected at
        // check time, before the user downloads a potentially large bundle.
        parse_signature(platform.signature.as_bytes())?;
        parse_public_key(public_key)?;
    }

    Ok((manifest, value, version))
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

pub(crate) fn ipv4_in(ip: Ipv4Addr, base: [u8; 4], prefix: u8) -> bool {
    let ip = u32::from(ip);
    let base = u32::from(Ipv4Addr::from(base));
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    ip & mask == base & mask
}

pub(crate) fn is_public_ipv4(ip: Ipv4Addr) -> bool {
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

pub(crate) fn ipv6_in(ip: Ipv6Addr, base: [u16; 8], prefix: u8) -> bool {
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

pub(crate) fn is_public_ipv6(ip: Ipv6Addr) -> bool {
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

pub(crate) fn validate_url(url: &Url, policy: NetworkPolicy) -> Result<()> {
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

pub(crate) fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| UpdaterDeadlineExceeded.into())
}

/// The HTTP(S) proxy the OS or environment names for `url`, the way a browser
/// on this computer would reach it: `HTTPS_PROXY` and friends, or the Windows
/// and macOS proxy settings. Where GitHub is blocked, that proxy is often the
/// only way to it. Nothing here rests on the connection being direct: the
/// manifest is checked against the embedded key, and every installer against
/// its signature, whoever carried the bytes.
///
/// `Ok(None)` when there is no proxy for `url`, or only one this client cannot
/// speak (SOCKS).
pub(crate) fn system_proxy_for(url: &Url) -> Result<Option<reqwest::Proxy>> {
    let Ok(uri) = url.as_str().parse::<http::Uri>() else {
        return Ok(None);
    };
    let Some(intercept) = hyper_util::client::proxy::matcher::Matcher::from_system().intercept(&uri)
    else {
        return Ok(None);
    };
    let scheme = intercept.uri().scheme_str().unwrap_or("");
    if !matches!(scheme, "http" | "https") {
        tracing::warn!(
            "Ignoring the {scheme} system proxy for updates: only HTTP and HTTPS proxies are supported"
        );
        return Ok(None);
    }
    // The matcher takes an HTTP(S) proxy's `user:password@` out of its URI and
    // keeps it only as a ready-made Basic header; `raw_auth` is SOCKS-only. So
    // the header is what carries the credentials, or a proxy that needs them
    // answers 407 to every update check.
    let proxy = reqwest::Proxy::all(intercept.uri().to_string()).context("updater proxy is invalid")?;
    Ok(Some(match intercept.basic_auth() {
        Some(credentials) => proxy.custom_http_auth(credentials.clone()),
        None => proxy,
    }))
}

pub(crate) async fn client_for_url(
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
    let builder = crate::net_bind::http_client()?
        .user_agent(concat!("ember-secure-updater/", env!("CARGO_PKG_VERSION")))
        .redirect(RedirectPolicy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT);

    // Through a proxy the name is resolved there, so there is nothing to pin.
    let system_proxy = if policy.system_proxy { system_proxy_for(url)? } else { None };
    if let Some(proxy) = system_proxy {
        return Ok((
            builder
                .proxy(proxy)
                .build()
                .context("failed to build updater HTTP client")?,
            Vec::new(),
        ));
    }
    let mut builder = builder.no_proxy();

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

pub(crate) async fn send_with_redirects(
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

pub(crate) async fn fetch_capped(
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

/// Suffix of a Linux entry that states the glibc it needs
/// (`linux-x86_64-appimage-glibc`, `linux-x86_64-deb-glibc`).
///
/// Neither package carries glibc, so each one's glibc floor is the distro it
/// is built on. Moving a build to a newer distro would hand every install on
/// an older one a package that cannot start, and so one it cannot update its
/// way out of. So a build with a higher floor is published under the gated
/// entry, with `min_glibc`, and the plain `linux-{arch}-{installer}` entry
/// keeps one that runs wherever earlier releases did, if it is published at
/// all: an AppImage before 1.7.7 and a `.deb` before 1.8.0 read only the plain
/// entry and check no glibc. From 1.8.0 the AppImage is built on Ubuntu 24.04
/// and published under its gated entry alone; the `.deb` is still built on
/// 22.04 and published under the plain one.
pub(crate) const GLIBC_GATED_SUFFIX: &str = "-glibc";

/// `"2.39"` as `(2, 39)`: glibc names its releases by major and minor only.
pub(crate) fn parse_glibc(version: &str) -> Option<(u32, u32)> {
    let (major, minor) = version.split_once('.')?;
    let number = |part: &str| {
        (!part.is_empty() && part.len() <= 4 && part.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    Some((number(major)?, number(minor)?))
}

/// Progress sink for an artifact download: the frontend's channel for a manual
/// install, or nothing for one prepared in the background.
pub(crate) type ProgressSink<'a> = &'a (dyn Fn(UpdateProgress) + Sync);

/// The largest collection or notes file a release carries beside its
/// installers. Both are a few kilobytes.
pub(crate) const RELEASE_EXTRA_MAX_BYTES: usize = 1024 * 1024;

/// A release to share every file of, for [`seed_release`].
pub(crate) struct SeedJob {
    app: AppHandle,
    manifest: SignedManifest,
    public_key: String,
    folder: PathBuf,
}

/// Whether a seeding task runs, and the release it is to seed next. One task
/// at a time, and always the newest release a check saw: a check that lands
/// while a run is under way replaces what comes next rather than being lost.
pub(crate) fn seed_queue() -> &'static parking_lot::Mutex<(bool, Option<SeedJob>)> {
    static QUEUE: std::sync::OnceLock<parking_lot::Mutex<(bool, Option<SeedJob>)>> = std::sync::OnceLock::new();
    QUEUE.get_or_init(Default::default)
}

/// Share every file of the release `manifest` names, when the setting asks
/// for it (`release_share::seed_folder`). In the background: the check it
/// came from does not wait for some hundred megabytes.
pub(crate) fn spawn_seed(app: &AppHandle, manifest: &SignedManifest, public_key: &str) {
    let Some(folder) = crate::release_share::seed_folder() else {
        return;
    };
    {
        let mut queue = seed_queue().lock();
        queue.1 = Some(SeedJob {
            app: app.clone(),
            manifest: manifest.clone(),
            public_key: public_key.to_string(),
            folder,
        });
        if queue.0 {
            return;
        }
        queue.0 = true;
    }
    crate::host::async_runtime::spawn(async {
        // Only a panic reaches this with the task still marked running; an
        // ordinary end clears it under the lock, together with the check that
        // nothing is waiting, so no check can fall between the two.
        struct Running;
        impl Drop for Running {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    seed_queue().lock().0 = false;
                }
            }
        }
        let _running = Running;
        loop {
            let job = {
                let mut queue = seed_queue().lock();
                match queue.1.take() {
                    Some(job) => job,
                    None => {
                        queue.0 = false;
                        break;
                    }
                }
            };
            seed_release(&job).await;
        }
    });
}

/// Fetch every file of the release into its folder for sharing: each
/// installer checked exactly as an update is, against its signed size, hash
/// and signature, and the collection and notes against the signatures the
/// release workflow made for them. A file already there is checked the same
/// way, once a session, and fetched again if it fails. The previous release's
/// files go only once every installer of this one is in. Stops as soon as the
/// setting is turned off or points elsewhere.
pub(crate) async fn seed_release(job: &SeedJob) {
    let SeedJob { app, manifest, public_key, folder } = job;
    let still_wanted = || crate::release_share::seed_folder().as_deref() == Some(folder.as_path());
    let version = manifest.version.as_str();
    // A prerelease's files are named in a form `release_share` does not read
    // a version from, so it could neither prune nor clear them.
    if Version::parse(version).map_or(true, |parsed| !parsed.pre.is_empty() || !parsed.build.is_empty()) {
        return;
    }
    let mut wrote = 0usize;
    let mut installers_held = 0usize;
    let mut complete = true;
    let mut base: Option<Url> = None;
    let mut seen = std::collections::HashSet::new();
    for platform in manifest.platforms.values() {
        if !seen.insert(platform.url.clone()) {
            continue;
        }
        let Some(name) = crate::release_share::release_file_name(&platform.url, version) else {
            continue;
        };
        base.get_or_insert_with(|| platform.url.clone());
        let path = folder.join(&name);
        if holds_signed_artifact(&path, platform).await {
            installers_held += 1;
            continue;
        }
        if !still_wanted() {
            return;
        }
        let bytes = match download_artifact(platform, public_key, &|_| {}).await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!("Release sharing: could not fetch {name}: {error:#}");
                complete = false;
                continue;
            }
        };
        if keep_release_file(folder, &name, bytes, &platform.sha256).await {
            wrote += 1;
            installers_held += 1;
        } else if !still_wanted() {
            return;
        } else {
            complete = false;
        }
    }
    if let Some(base) = base {
        for name in [format!("Ember_{version}.emulecollection"), format!("Ember_{version}_release-notes.md")] {
            let path = folder.join(&name);
            if crate::release_share::checked_unchanged(&path, CHECKED_BY_RELEASE_SIGNATURE) {
                continue;
            }
            if !still_wanted() {
                return;
            }
            match fetch_signed_release_extra(&base, &name, public_key).await {
                Ok(SignedExtra::Verified(bytes)) => {
                    let unchanged = {
                        let (path, expected) = (path.clone(), bytes.clone());
                        tokio::task::spawn_blocking(move || std::fs::read(&path).is_ok_and(|held| held == expected))
                            .await
                            .unwrap_or(false)
                    };
                    if unchanged {
                        crate::release_share::note_checked(&path, CHECKED_BY_RELEASE_SIGNATURE);
                    } else if keep_release_file(folder, &name, bytes, CHECKED_BY_RELEASE_SIGNATURE).await {
                        wrote += 1;
                    }
                }
                // A release from before the workflow signed these.
                Ok(SignedExtra::Missing) => tracing::debug!("Release sharing: {version} has no signed {name}"),
                // What the release offers does not verify, so nothing of it is
                // shared from here, including a copy kept before.
                Ok(SignedExtra::BadSignature) => {
                    tracing::warn!("Release sharing: {name} does not match its release signature; not sharing it");
                    let (dir, stale) = (folder.clone(), name.clone());
                    if tokio::task::spawn_blocking(move || crate::release_share::remove(&dir, &stale))
                        .await
                        .unwrap_or(false)
                    {
                        wrote += 1;
                    }
                }
                Err(error) => tracing::warn!("Release sharing: could not fetch {name}: {error:#}"),
            }
        }
    }
    if !still_wanted() {
        return;
    }
    // A release none of whose installers is held here, its names unread or
    // every fetch failed, is no reason to let the previous one go.
    let pruned = if complete && installers_held > 0 {
        let (dir, keep) = (folder.clone(), version.to_string());
        tokio::task::spawn_blocking(move || crate::release_share::prune(&dir, &keep))
            .await
            .unwrap_or(0)
    } else {
        0
    };
    if wrote > 0 || pruned > 0 {
        tracing::info!("Release sharing: {wrote} file(s) of Ember {version} kept to share, {pruned} older removed");
        use crate::host::Manager;
        if let Some(watcher) = app.state::<crate::app_state::AppState>().shared_folder_watcher.clone() {
            watcher.queue_rescan_after(vec![folder.clone()], Duration::from_secs(2));
        }
    }
}

/// Whether `path` holds the signed artifact `platform` names: checked against
/// its size and SHA-256 once a session, and again whenever the file changes.
pub(crate) async fn holds_signed_artifact(path: &Path, platform: &SignedPlatform) -> bool {
    if crate::release_share::checked_unchanged(path, &platform.sha256) {
        return true;
    }
    let (file, size, sha256) = (path.to_path_buf(), platform.size, platform.sha256.clone());
    let holds = tokio::task::spawn_blocking(move || crate::release_share::holds(&file, size, &sha256))
        .await
        .unwrap_or(false);
    if holds {
        crate::release_share::note_checked(path, &platform.sha256);
    }
    holds
}

/// What a release's collection and notes are checked against: their
/// signature, verified by fetching it again once a session.
pub(crate) const CHECKED_BY_RELEASE_SIGNATURE: &str = "release signature";

/// Keep verified release bytes, recording them as checked against `against`,
/// while seeding still asks for `folder`. Whether they were kept.
pub(crate) async fn keep_release_file(folder: &Path, name: &str, bytes: Vec<u8>, against: &str) -> bool {
    let (dir, file) = (folder.to_path_buf(), name.to_string());
    let kept = tokio::task::spawn_blocking(move || {
        let still_wanted = || crate::release_share::seed_folder().as_deref() == Some(dir.as_path());
        crate::release_share::keep(&dir, &file, &bytes, still_wanted)
    });
    match kept.await {
        Ok(Ok(true)) => {
            crate::release_share::note_checked(&folder.join(name), against);
            true
        }
        Ok(Ok(false)) => false,
        Ok(Err(error)) => {
            tracing::warn!("Release sharing: could not keep {name}: {error}");
            false
        }
        Err(error) => {
            tracing::warn!("Release sharing: could not keep {name}: {error}");
            false
        }
    }
}

/// A file beside a release's installers, as [`fetch_signed_release_extra`]
/// found it.
pub(crate) enum SignedExtra {
    /// The release has no such file, or no signature for it.
    Missing,
    /// The bytes, verified under the updater key.
    Verified(Vec<u8>),
    /// There, but not what its signature signs.
    BadSignature,
}

/// `name`, beside the release's installers, checked against its `.sig` under
/// the updater key. A failure to reach either is an error; a mismatch is not.
pub(crate) async fn fetch_signed_release_extra(base: &Url, name: &str, public_key: &str) -> Result<SignedExtra> {
    let url = base.join(name).context("release file URL is invalid")?;
    let signature_url = base.join(&format!("{name}.sig")).context("release signature URL is invalid")?;
    for url in [&url, &signature_url] {
        validate_url(url, NetworkPolicy::PRODUCTION)?;
    }
    let fetch = |url: Url, cap: usize| async move {
        fetch_capped(&url, cap, METADATA_DEADLINE, "application/octet-stream", NetworkPolicy::PRODUCTION).await
    };
    let file = match fetch(url, RELEASE_EXTRA_MAX_BYTES).await {
        Ok(file) => file,
        Err(error) if is_missing_updater_resource(&error) => return Ok(SignedExtra::Missing),
        Err(error) => return Err(error),
    };
    let signature = match fetch(signature_url, SIGNATURE_MAX_BYTES).await {
        Ok(signature) => signature,
        Err(error) if is_missing_updater_resource(&error) => return Ok(SignedExtra::Missing),
        Err(error) => return Err(error),
    };
    Ok(match verify_minisign_for_file(&file.bytes, &signature.bytes, public_key, name) {
        Ok(()) => SignedExtra::Verified(file.bytes),
        Err(_) => SignedExtra::BadSignature,
    })
}

/// [`verify_minisign`], and the signature made for a file of this name. The
/// release workflow signs with `tauri signer`, whose trusted comment (signed
/// with the rest) names the file, and nothing else ties a collection or notes
/// file to its release: without it, an older release's signed collection
/// served under a newer name would verify.
pub(crate) fn verify_minisign_for_file(payload: &[u8], encoded_signature: &[u8], encoded_key: &str, name: &str) -> Result<()> {
    verify_minisign(payload, encoded_signature, encoded_key)?;
    let signature = parse_signature(encoded_signature)?;
    let signed_name = signature
        .trusted_comment()
        .split('\t')
        .find_map(|field| field.strip_prefix("file:"));
    if signed_name != Some(name) {
        bail!("signature was made for {signed_name:?}, not {name}");
    }
    Ok(())
}

pub(crate) async fn download_artifact(
    platform: &SignedPlatform,
    public_key: &str,
    on_event: ProgressSink<'_>,
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

    on_event(UpdateProgress::Started {
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
        on_event(UpdateProgress::Progress {
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
    on_event(UpdateProgress::Finished);
    Ok(artifact)
}

/// The overall deadline of an updater request ran out.
#[derive(Debug)]
pub(crate) struct UpdaterDeadlineExceeded;

impl std::fmt::Display for UpdaterDeadlineExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("updater request deadline exceeded")
    }
}

impl std::error::Error for UpdaterDeadlineExceeded {}

/// emberd: share the newest signed release while release sharing is on. It
/// has no updater, so this is the check the desktop app's updater makes for
/// it, with the manifest and its signature fetched and verified the same way.
#[cfg(feature = "server")]
pub(crate) async fn seed_newest_release(app: &AppHandle) {
    if crate::release_share::seed_folder().is_none() {
        return;
    }
    match newest_signed_release().await {
        Ok(Some((manifest, public_key))) => spawn_seed(app, &manifest, &public_key),
        Ok(None) => {}
        Err(error) => tracing::warn!("Release sharing: could not check for a new release: {error:#}"),
    }
}

/// Where emberd keeps the newest signed release it has accepted, as
/// `(security_epoch, version)`, as the desktop updater keeps its own floor.
#[cfg(feature = "server")]
const SEED_FLOOR_FILE: &str = "emberd-release-floor.json";

#[cfg(feature = "server")]
#[derive(Serialize, Deserialize)]
struct SeedFloor {
    security_epoch: u64,
    version: String,
}

/// Whether `candidate`, `(security_epoch, version)`, may be shared: not
/// below `floor`, the newest accepted before, in the updater's tuple order.
/// A manifest replayed from before, this run or after a restart, would
/// otherwise have the folder trade a newer release's files for an older one's.
#[cfg(feature = "server")]
fn seed_floor_admits(floor: Option<&(u64, Version)>, candidate: &(u64, Version)) -> bool {
    floor.is_none_or(|floor| candidate >= floor)
}

#[cfg(feature = "server")]
fn read_seed_floor(path: &Path) -> Result<Option<(u64, Version)>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("release sharing floor is unreadable"),
    };
    let floor: SeedFloor = serde_json::from_slice(&bytes).context("release sharing floor is corrupt")?;
    let version = Version::parse(&floor.version).context("release sharing floor is corrupt")?;
    Ok(Some((floor.security_epoch, version)))
}

/// The signed release the manifest names, unless it is older than this build
/// or below the floor ([`seed_floor_admits`]), which it then raises.
#[cfg(feature = "server")]
async fn newest_signed_release() -> Result<Option<(SignedManifest, String)>> {
    static FLOOR: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
    let config = embedded_updater_config()?;
    let manifest = match fetch_capped(
        &config.endpoint,
        MANIFEST_MAX_BYTES,
        METADATA_DEADLINE,
        "application/json",
        NetworkPolicy::PRODUCTION,
    )
    .await
    {
        Ok(response) => response,
        Err(error) if is_missing_updater_resource(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let signature = fetch_capped(
        &signature_url(&config.endpoint)?,
        SIGNATURE_MAX_BYTES,
        METADATA_DEADLINE,
        "application/octet-stream",
        NetworkPolicy::PRODUCTION,
    )
    .await?;
    verify_minisign(&manifest.bytes, &signature.bytes, &config.public_key)?;
    let raw: serde_json::Value =
        serde_json::from_slice(&manifest.bytes).context("signed updater manifest is not JSON")?;
    let (manifest, _, version) = validate_manifest(raw, &config.public_key)?;
    let running = Version::parse(env!("CARGO_PKG_VERSION"))?;
    if version < running {
        return Ok(None);
    }
    let candidate = (manifest.security_epoch, version);
    let path = crate::storage::paths::resolve_data_dir().join(SEED_FLOOR_FILE);
    let _held = FLOOR.lock();
    let floor = read_seed_floor(&path)?;
    if !seed_floor_admits(floor.as_ref(), &candidate) {
        tracing::warn!(
            "Release sharing: the signed manifest names {} (epoch {}), older than {} already shared from; not sharing it",
            candidate.1,
            candidate.0,
            floor
                .as_ref()
                .map_or_else(String::new, |(epoch, version)| format!("{version} (epoch {epoch})")),
        );
        return Ok(None);
    }
    if floor.as_ref() != Some(&candidate) {
        let record = SeedFloor { security_epoch: candidate.0, version: candidate.1.to_string() };
        crate::security::atomic_write(&path, &serde_json::to_vec(&record)?, true)
            .context("release sharing floor could not be saved")?;
    }
    Ok(Some((manifest, config.public_key)))
}

#[cfg(all(test, feature = "server"))]
mod seed_floor_tests {
    use super::*;

    /// A higher epoch outranks any version, and within one epoch an older
    /// version is refused: a replayed manifest cannot walk the folder back.
    #[test]
    fn the_release_floor_only_moves_forward() {
        let v = |text: &str| Version::parse(text).unwrap();
        let floor = (1, v("1.8.1"));
        assert!(seed_floor_admits(None, &(1, v("1.8.1"))));
        assert!(seed_floor_admits(Some(&floor), &(1, v("1.8.1"))), "the same release again");
        assert!(seed_floor_admits(Some(&floor), &(1, v("1.9.0"))));
        assert!(seed_floor_admits(Some(&floor), &(2, v("1.8.0"))), "an epoch bump may lower the version");
        assert!(!seed_floor_admits(Some(&floor), &(1, v("1.8.0"))));
        assert!(!seed_floor_admits(Some(&(2, v("1.8.0"))), &(1, v("1.9.0"))), "nor may a lower epoch");

        let path = std::env::temp_dir().join(format!("emberd-floor-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(read_seed_floor(&path).unwrap().is_none(), "none yet");
        std::fs::write(&path, br#"{"security_epoch":1,"version":"1.8.1"}"#).unwrap();
        assert_eq!(read_seed_floor(&path).unwrap(), Some(floor));
        std::fs::write(&path, b"not json").unwrap();
        assert!(read_seed_floor(&path).is_err(), "a corrupt floor stops sharing rather than resetting it");
        let _ = std::fs::remove_file(&path);
    }
}
