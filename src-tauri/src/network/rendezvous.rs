use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Hard byte cap on rendezvous responses. Payloads are always small JSON
/// blobs (at most a few dozen bytes today); 64 KiB leaves orders of
/// magnitude of headroom for future fields while still making us
/// resistant to a hostile server that streams megabytes at us.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

pub fn hashed_id(ember_hash: &[u8; 16]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ember_hash);
    hex::encode(hasher.finalize())
}

fn client() -> reqwest::Client {
    match reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .no_proxy()
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build rendezvous HTTP client with configured options: {e}, using default");
            reqwest::Client::new()
        }
    }
}

/// Read the response body with a hard byte cap. Protects against a hostile
/// or misbehaving rendezvous server that might otherwise stream megabytes of
/// JSON at us.
async fn read_bounded_bytes(resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len as usize > limit {
            return Err(format!(
                "rendezvous response too large: {len} bytes (max {limit})"
            ));
        }
    }
    let mut stream = resp.bytes_stream();
    use futures::StreamExt;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("rendezvous read failed: {e}"))?;
        if buf.len().saturating_add(chunk.len()) > limit {
            return Err(format!("rendezvous response exceeded {limit}-byte cap"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Register our presence with the rendezvous server.
/// If `external_ip` is provided, it is sent so the server stores our true
/// IPv4 address instead of the (possibly IPv6) connection address.
pub async fn register(base_url: &str, ember_hash: &[u8; 16], port: u16, external_ip: Option<Ipv4Addr>) -> Result<(), String> {
    let url = format!("{}/register", base_url.trim_end_matches('/'));
    let id = hashed_id(ember_hash);
    let mut body = serde_json::json!({ "id": id, "port": port });
    if let Some(ip) = external_ip {
        body["ip"] = serde_json::Value::String(ip.to_string());
    }
    let resp = client()
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("rendezvous register failed: {e}"))?;
    if resp.status().is_success() {
        // Don't leak the hashed friend ID or our public IP at `info!` level:
        // user-facing logs should not deanonymize the identity. Keep a terse
        // success message at info and the identifying bits at debug.
        info!("Rendezvous: registration succeeded on port {port}");
        debug!(
            "Rendezvous: registered {}… (ip={:?})",
            &id[..8],
            external_ip
        );
        Ok(())
    } else {
        let status = resp.status();
        Err(format!("rendezvous register returned {status}"))
    }
}

/// Look up a friend on the rendezvous server.
/// Returns `Some((ip, port))` if the friend is currently registered, `None` if not found.
pub async fn lookup(base_url: &str, friend_hash: &[u8; 16]) -> Result<Option<(Ipv4Addr, u16)>, String> {
    let id = hashed_id(friend_hash);
    let url = format!("{}/lookup/{}", base_url.trim_end_matches('/'), id);
    let resp = client()
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("rendezvous lookup failed: {e}"))?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        return Err(format!("rendezvous lookup returned {status}"));
    }
    let bytes = read_bounded_bytes(resp, MAX_RESPONSE_BYTES).await?;
    let body: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("rendezvous lookup bad body: {e}"))?;
    let ip_str = body["ip"].as_str().unwrap_or_default();
    let raw_port = body["port"].as_u64().unwrap_or_default();
    if raw_port == 0 || raw_port > u16::MAX as u64 {
        debug!(
            "Rendezvous: lookup for {}… returned invalid port: {}",
            &id[..8],
            raw_port
        );
        return Ok(None);
    }
    let port = raw_port as u16;
    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        if port > 0 {
            // Friend IP/port is effectively PII — keep it at debug rather than
            // info so it doesn't land in user-shared log bundles by default.
            debug!("Rendezvous: found {}… at {}:{}", &id[..8], ip, port);
            return Ok(Some((ip, port)));
        }
    }
    debug!(
        "Rendezvous: lookup for {}… returned unparseable data",
        &id[..8]
    );
    Ok(None)
}

/// Unregister our presence from the rendezvous server (graceful shutdown).
pub async fn unregister(base_url: &str, ember_hash: &[u8; 16]) -> Result<(), String> {
    let url = format!("{}/unregister", base_url.trim_end_matches('/'));
    let id = hashed_id(ember_hash);
    let resp = client()
        .delete(&url)
        .json(&serde_json::json!({ "id": id }))
        .send()
        .await
        .map_err(|e| format!("rendezvous unregister failed: {e}"))?;
    if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
        debug!("Rendezvous: unregistered {}…", &id[..8]);
        Ok(())
    } else {
        let status = resp.status();
        Err(format!("rendezvous unregister returned {status}"))
    }
}
