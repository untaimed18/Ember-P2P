use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::SigningKey;
use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, info};

use super::crypto::node_id_from_public_key;

/// Idle timeout for QUIC connections.
const IDLE_TIMEOUT_SECS: u64 = 120;

/// Keep-alive interval.
const KEEP_ALIVE_SECS: u64 = 15;

/// Concurrent stream limits. Ember uses one bidi stream per "request"; 64
/// is plenty for normal RPC and leaves headroom for DHT/relay bursts.
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 128;
const MAX_CONCURRENT_UNI_STREAMS: u32 = 128;

/// Per-stream and per-connection receive windows. Quinn defaults are
/// conservative (a few MiB) which caps single-stream throughput on
/// high-BDP links. 8 MiB / 64 MiB roughly matches Linux's auto-tuned
/// TCP receive window for a 100 ms RTT 100+ Mbps link.
const STREAM_RECEIVE_WINDOW_BYTES: u64 = 8 * 1024 * 1024;
const RECEIVE_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
const SEND_WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// UDP socket buffer sizes. The default OS buffer (often 208 KiB on Linux,
/// 64 KiB on Windows) starves QUIC of recv buffer at high throughput,
/// causing spurious packet drops that look like loss to the congestion
/// controller. 8 MiB recv / 2 MiB send is well-supported on all major OSes
/// (Windows clamps but tolerates), and matches what high-perf QUIC stacks
/// (mvfst, msquic) recommend.
const UDP_RECV_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const UDP_SEND_BUFFER_BYTES: usize = 2 * 1024 * 1024;

/// Builds an `rcgen::KeyPair` directly from an Ember node's real Ed25519
/// identity secret key, instead of generating a fresh throwaway key.
/// This is what lets the QUIC certificate's key be a real, verifiable
/// extension of the peer's identity (see [`extract_ember_ed25519_pubkey`]
/// and the verifiers below) rather than an arbitrary self-asserted label
/// with no cryptographic relationship to any specific node id.
fn ember_quic_keypair(secret_key: &[u8; 32]) -> anyhow::Result<rcgen::KeyPair> {
    let signing_key = SigningKey::from_bytes(secret_key);
    let pkcs8_doc = signing_key
        .to_pkcs8_der()
        .map_err(|e| anyhow::anyhow!("failed to PKCS8-encode Ed25519 identity key: {e}"))?;
    let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8_doc.as_bytes());
    Ok(rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &pkcs8_der,
        &rcgen::PKCS_ED25519,
    )?)
}

/// Generate a self-signed TLS certificate for QUIC, signed with the
/// node's *real* Ed25519 identity keypair (`secret_key`).
///
/// Earlier versions generated a fresh, random keypair here and merely
/// wrote the node id as a text label (`ember-{hex}`) into the cert's
/// SAN. That label was never cryptographically bound to the key
/// actually used in the TLS handshake — `rcgen::generate_simple_self_signed`
/// accepts *any* string as the SAN regardless of what key it signs
/// with, so any peer could mint a cert claiming to be any node id
/// (see `EmberCertVerifier`'s doc comment for the full writeup of why
/// that made per-peer pinning a no-op). Signing with the actual
/// identity key closes that gap: the verifiers below derive the
/// peer's node id from the certificate's real SubjectPublicKeyInfo —
/// the key TLS already proves the peer possesses via the handshake
/// signature — instead of trusting a self-asserted string.
///
/// Deterministic and cheap (no per-call randomness needed for the key
/// itself — Ed25519 signing is deterministic per RFC 8032), so callers
/// can regenerate this on demand from the stable identity key rather
/// than needing to cache/plumb the result through long-lived state.
pub fn generate_self_signed_cert(secret_key: &[u8; 32]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let key_pair = ember_quic_keypair(secret_key)?;
    let verifying_key = SigningKey::from_bytes(secret_key).verifying_key();
    let node_id = node_id_from_public_key(&verifying_key);
    // No longer load-bearing for security (see doc comment above), but
    // keeps the cert human-diagnosable and gives the verifiers a cheap
    // sanity label before they fall back to real SPKI extraction.
    let cn = format!("ember-{}", hex::encode(node_id));
    let cert = rcgen::CertificateParams::new(vec![cn])?.self_signed(&key_pair)?;
    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialized_der().to_vec();

    Ok((cert_der, key_der))
}

/// Build the shared `TransportConfig` used by both server- and
/// client-side endpoints. Centralising this means the client side
/// inherits the same window sizes / timeouts / stream limits as the
/// server, instead of running on Quinn defaults.
fn build_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
    transport.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
    // Fall back to a safe 30s idle timeout if the configured constant ever
    // overflows a VarInt, rather than panicking at endpoint setup.
    let idle_timeout = Duration::from_secs(IDLE_TIMEOUT_SECS)
        .try_into()
        .unwrap_or_else(|_| quinn::IdleTimeout::from(quinn::VarInt::from_u32(30_000)));
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_SECS)));
    transport.stream_receive_window(
        STREAM_RECEIVE_WINDOW_BYTES
            .try_into()
            .unwrap_or(quinn::VarInt::MAX),
    );
    transport.receive_window(
        RECEIVE_WINDOW_BYTES
            .try_into()
            .unwrap_or(quinn::VarInt::MAX),
    );
    transport.send_window(SEND_WINDOW_BYTES);
    Arc::new(transport)
}

/// Create the server-side QUIC endpoint configuration.
fn build_server_config(cert_der: &[u8], key_der: &[u8]) -> anyhow::Result<ServerConfig> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let supported_algs = provider.signature_verification_algorithms;
    // Require inbound peers to present a well-formed Ember cert and prove
    // possession of its key (handshake signature is verified). Symmetric to
    // the client-side EmberCertVerifier — closes the "accept any client"
    // gap. Node-identity auth still rests on the TCP Ed25519 PoP layer.
    let client_verifier = Arc::new(EmberClientCertVerifier { supported_algs });
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], key)?;
    tls_config.alpn_protocols = vec![b"ember/1".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));
    // Build a fresh `TransportConfig` and store via `Arc::new` so we
    // don't depend on `server_config.transport` having a unique strong
    // count at this exact point (the previous `Arc::get_mut(...).unwrap()`
    // would panic if a future quinn upgrade ever shared the default
    // transport Arc inside `with_crypto`).
    server_config.transport = build_transport_config();

    Ok(server_config)
}

/// Create the client-side QUIC configuration.
///
/// `expected_node_id` is the target peer's ember node id when known
/// at connect time, in which case the verifier pins the cert's real
/// SubjectPublicKeyInfo (not a self-asserted label) to that id — true
/// per-peer authentication, MITM-safe (see `EmberCertVerifier`). When
/// `None`, the verifier still requires the cert to be a well-formed
/// Ember self-signed Ed25519 cert (smoke-test only — no
/// authentication, but rejects external CAs / random certs an
/// on-path attacker might inject).
pub fn build_client_config(
    cert_der: &[u8],
    key_der: &[u8],
    expected_node_id: Option<[u8; 16]>,
) -> anyhow::Result<ClientConfig> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    // Capture the provider's signature-verification algorithms so the
    // verifier can *actually* check the TLS handshake signature against the
    // presented end-entity certificate's public key (see EmberCertVerifier).
    let supported_algs = provider.signature_verification_algorithms;
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EmberCertVerifier {
            expected_node_id,
            supported_algs,
        }))
        .with_client_auth_cert(vec![cert], key)?;
    tls_config.alpn_protocols = vec![b"ember/1".to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    // Mirror the server-side TransportConfig so outgoing connections
    // (download peers, hole-punch attempts, relay clients) get the same
    // generous windows and stream caps as inbound ones, instead of
    // running on whatever Quinn picked as a "safe" default.
    client_config.transport_config(build_transport_config());

    Ok(client_config)
}

/// Bind a UDP socket with explicit kernel buffer sizes. Returns the bound
/// `std::net::UdpSocket` ready to be handed to `Endpoint::new`. On
/// platforms where the requested buffer exceeds the system maximum, the
/// kernel silently clamps; we log a warning and continue rather than
/// failing the bind.
fn bind_tuned_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(addr)?;
    let s = socket2::SockRef::from(&socket);
    if let Err(e) = s.set_recv_buffer_size(UDP_RECV_BUFFER_BYTES) {
        debug!("UDP set_recv_buffer_size({UDP_RECV_BUFFER_BYTES}) failed: {e} (using OS default)");
    }
    if let Err(e) = s.set_send_buffer_size(UDP_SEND_BUFFER_BYTES) {
        debug!("UDP set_send_buffer_size({UDP_SEND_BUFFER_BYTES}) failed: {e} (using OS default)");
    }
    Ok(socket)
}

/// Parse a DER-encoded X.509 certificate and extract its real
/// SubjectPublicKeyInfo as a raw 32-byte Ed25519 public key.
///
/// Returns `None` if the certificate doesn't parse, or its SPKI isn't
/// an Ed25519 key (OID `1.3.101.112`) with the expected 32-byte
/// encoding. This walks the actual ASN.1 structure via `x509-cert`
/// (Certificate -> TBSCertificate -> SubjectPublicKeyInfo) rather than
/// pattern-matching bytes: a byte-search approach (as this function
/// used to be, searching for an `ember-{hex}` SAN marker) can be
/// fooled by a self-crafted certificate that plants a decoy match
/// earlier in the DER (e.g. inside an extension or the subject DN),
/// which would matter a lot here since the result feeds directly into
/// a security decision (`EmberCertVerifier`) rather than a diagnostic
/// label. A real structural parse has no such ambiguity: the SPKI is
/// whatever field is *structurally* in that position, full stop.
fn extract_ember_ed25519_pubkey(cert_der: &[u8]) -> Option<[u8; 32]> {
    use x509_cert::der::Decode;
    // RFC 8410 id-Ed25519, spelled against `x509-cert`'s own `const-oid`
    // rather than reused from `ed25519_dalek::pkcs8::ALGORITHM_OID`: the two
    // crates sit on different `const-oid` majors, so their `ObjectIdentifier`
    // types are not comparable even though the value is identical.
    const ID_ED25519: x509_cert::der::asn1::ObjectIdentifier =
        x509_cert::der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112");
    let cert = x509_cert::Certificate::from_der(cert_der).ok()?;
    let spki = cert.tbs_certificate().subject_public_key_info();
    if spki.algorithm.oid != ID_ED25519 {
        return None;
    }
    let raw = spki.subject_public_key.raw_bytes();
    <[u8; 32]>::try_from(raw).ok()
}

/// Derives an Ember node id from a certificate's real SubjectPublicKeyInfo,
/// i.e. the same key TLS already proved the presenting peer possesses
/// (via the handshake signature check in `verify_tls1{2,3}_signature`
/// below). This is the actual cryptographic binding: unlike a
/// self-asserted SAN string, a peer cannot claim a node id here without
/// also being able to complete a TLS handshake using that exact key.
fn cert_node_id(cert_der: &[u8]) -> Option<[u8; 16]> {
    let raw_pubkey = extract_ember_ed25519_pubkey(cert_der)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&raw_pubkey).ok()?;
    Some(node_id_from_public_key(&verifying_key))
}

/// Recover the authenticated Ember node id from Quinn's rustls peer identity.
/// The TLS handshake has already proved possession of this certificate key.
pub fn connection_node_id(connection: &quinn::Connection) -> Option<[u8; 16]> {
    let identity = connection.peer_identity()?;
    let certificates = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    certificates
        .first()
        .and_then(|cert| cert_node_id(cert.as_ref()))
}

/// Certificate verifier for QUIC connections to Ember peers.
///
/// Behaviour:
/// - If `expected_node_id` is `Some(nid)`, the cert's real
///   SubjectPublicKeyInfo (extracted via [`cert_node_id`], not a
///   self-asserted string) must hash to `nid`. Combined with the
///   handshake-signature check below — which proves the peer actually
///   holds the private key for that exact SPKI — this is a real
///   per-peer cryptographic pin: an attacker cannot substitute their
///   own cert, because doing so would require either breaking Ed25519
///   or finding a BLAKE3 preimage that hashes to `nid`, not merely
///   writing a different label into a self-signed cert. (An earlier
///   version of this verifier only compared a plaintext `ember-{hex}`
///   SAN string against `nid` — since `generate_self_signed_cert` used
///   to sign with a *fresh random* key regardless of what string was
///   requested, that check was purely self-asserted and gave zero
///   actual authentication; see `generate_self_signed_cert`'s doc
///   comment for the fix.)
/// - If `expected_node_id` is `None`, we still require the cert's SPKI
///   to parse as a well-formed Ed25519 key. This is a smoke check, not
///   authentication — but it does reject the all-too-easy "trust any
///   cert any CA ever issued" failure mode that the prior
///   `SkipServerVerification` allowed. Per-peer pinning replaces the
///   smoke path whenever the QUIC connect site knows its target's
///   `ember_node_id` ahead of time (broker/relay candidates discovered
///   via unauthenticated rendezvous/EPX channels often don't, so they
///   fall back to the smoke path).
///
/// In all cases the TLS handshake signature is verified against the
/// presented end-entity certificate's public key (see
/// `verify_tls1{2,3}_signature` below) using the active crypto provider's
/// algorithms — so the channel is cryptographically bound to a peer that
/// actually holds the cert's private key. For the unpinned smoke-check
/// path, that still doesn't prove the key belongs to a *specific*
/// node_id; the node_id↔key binding there is established out-of-band by
/// the eMule/Ember TCP layer's mutual Ed25519 proof-of-possession, on
/// which file-transfer integrity solely depends in that case.
#[derive(Debug)]
struct EmberCertVerifier {
    expected_node_id: Option<[u8; 16]>,
    /// Signature-verification algorithms from the active crypto provider.
    /// Used to verify the TLS handshake signature against the presented
    /// end-entity certificate's public key. Without this the handshake
    /// callbacks below would be rubber stamps and an on-path attacker could
    /// splice the connection with a cert it doesn't hold the key for.
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for EmberCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let Some(actual_node_id) = cert_node_id(end_entity.as_ref()) else {
            return Err(rustls::Error::General(
                "ember cert: SubjectPublicKeyInfo is not a well-formed Ed25519 key".into(),
            ));
        };
        if let Some(nid) = self.expected_node_id {
            if actual_node_id != nid {
                return Err(rustls::Error::General(format!(
                    "ember cert: pinned node_id mismatch (expected {}, got {})",
                    hex::encode(nid),
                    hex::encode(actual_node_id)
                )));
            }
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Server-side counterpart to [`EmberCertVerifier`]. Requires inbound QUIC
/// clients to present a well-formed Ember self-signed cert and proves they
/// hold its private key (the handshake signature is verified). This makes the
/// QUIC channel mutually key-authenticated instead of accepting any client.
/// As on the client side, binding a cert key to a specific node_id is the
/// job of the TCP Ed25519 proof-of-possession, not this verifier.
#[derive(Debug)]
struct EmberClientCertVerifier {
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::server::danger::ClientCertVerifier for EmberClientCertVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        if cert_node_id(end_entity.as_ref()).is_none() {
            return Err(rustls::Error::General(
                "ember client cert: SubjectPublicKeyInfo is not a well-formed Ed25519 key".into(),
            ));
        }
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Create a QUIC endpoint that can both accept incoming connections (relay server)
/// and make outgoing ones (hole-punch/relay client). Binds to `0.0.0.0:{bind_port}`
/// on UDP — this coexists with any TCP listener on the same port number, but
/// **does not** share a UDP socket with the eMule/Kad UDP listener. If the
/// caller has configured `tcp_port == udp_port`, the requested QUIC port will
/// already be in use; this function then walks a small range of fallback ports
/// (`bind_port+1..=+4`) before giving up. Use [`Endpoint::local_addr`] on the
/// returned endpoint to learn the *actual* bound port — callers that advertise
/// the QUIC port (e.g. rendezvous registration) must use that value, not the
/// originally-requested one.
pub fn build_server_client_endpoint(
    cert_der: &[u8],
    key_der: &[u8],
    bind_port: u16,
) -> anyhow::Result<Endpoint> {
    let server_config = build_server_config(cert_der, key_der)?;
    let client_config = build_client_config(cert_der, key_der, None)?;

    // Ordered: requested port first, then a few neighbours, then OS-assigned.
    // Don't include port 0 in the visible range to avoid hiding a typo'd
    // config behind silent OS-assignment — but still fall back to it if
    // every nearby port is busy, because losing QUIC entirely is worse
    // than running on an unpredictable port.
    let mut candidates: Vec<u16> = Vec::with_capacity(6);
    candidates.push(bind_port);
    for offset in 1..=4u16 {
        let p = bind_port.saturating_add(offset);
        if p != bind_port && p != 0 {
            candidates.push(p);
        }
    }
    candidates.push(0);

    let mut last_err: Option<anyhow::Error> = None;
    for &candidate in &candidates {
        let bind_addr: SocketAddr = format!("0.0.0.0:{candidate}").parse()?;
        let socket = match bind_tuned_udp(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(anyhow::Error::new(e).context(format!("bind {candidate}")));
                continue;
            }
        };
        match Endpoint::new(
            EndpointConfig::default(),
            Some(server_config.clone()),
            socket,
            Arc::new(quinn::TokioRuntime),
        ) {
            Ok(mut endpoint) => {
                endpoint.set_default_client_config(client_config.clone());
                let local = endpoint.local_addr()?;
                if candidate == bind_port {
                    info!("QUIC server+client endpoint bound on {local}");
                } else {
                    // Notable: the requested port collided (commonly because
                    // tcp_port == udp_port and the Kad UDP socket got there
                    // first). We're still up — but the advertised port has
                    // changed, so anything that exposes our QUIC reachability
                    // (rendezvous, friend presence, …) needs to read it back.
                    info!("QUIC requested port {bind_port} unavailable; bound on {local} instead",);
                }
                return Ok(endpoint);
            }
            Err(e) => {
                last_err = Some(anyhow::Error::new(e).context(format!("bind {candidate}")));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no QUIC bind candidates exhausted")))
}

/// Connect to a peer over an existing endpoint, optionally pinning the peer's
/// Ember node id into the TLS verifier.
///
/// `pin`, when `Some`, is `(our_cert_der, our_key_der, expected_peer_node_id)`:
/// `our_cert_der`/`our_key_der` are the DER bytes of *our own* client
/// certificate — normally freshly produced by
/// `generate_self_signed_cert(&our_ed25519_secret_key)`, since that's cheap
/// and deterministic — NOT the peer's. `expected_peer_node_id` is the only
/// part that identifies who we expect to reach. A per-connection client
/// config is then built whose verifier requires the *peer's* certificate to
/// carry a SubjectPublicKeyInfo that hashes to `expected_peer_node_id` (see
/// `EmberCertVerifier`) — true MITM-safe per-peer authentication. When `pin`
/// is `None`, the endpoint's default (unpinned smoke-test) client config is
/// used. `None` is the graceful fallback for broker/relay candidates
/// discovered via unauthenticated rendezvous/EPX, where the target's Ember node
/// id isn't known at QUIC-connect time — the KAD source record advertises the
/// peer's Noise public key, not its `ember_hash`, and the node↔key binding is
/// established out-of-band by the eMule/Ember TCP Ed25519 proof-of-possession.
/// Callers that *do* know the target node id pass `Some` to upgrade the
/// channel to authenticated pinning without any change to this transport
/// layer.
pub async fn connect_pinned(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    pin: Option<(&[u8], &[u8], [u8; 16])>,
) -> anyhow::Result<quinn::Connection> {
    let connecting = match pin {
        Some((cert_der, key_der, node_id)) => {
            let cfg = build_client_config(cert_der, key_der, Some(node_id))?;
            endpoint.connect_with(cfg, addr, server_name)?
        }
        None => endpoint.connect(addr, server_name)?,
    };
    Ok(connecting.await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn random_secret_key() -> [u8; 32] {
        SigningKey::generate(&mut OsRng).to_bytes()
    }

    fn node_id_for(secret_key: &[u8; 32]) -> [u8; 16] {
        node_id_from_public_key(&SigningKey::from_bytes(secret_key).verifying_key())
    }

    #[test]
    fn generate_cert_succeeds() {
        let secret_key = random_secret_key();
        let (cert, key) = generate_self_signed_cert(&secret_key).unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }

    #[test]
    fn cert_node_id_matches_the_signing_key_used() {
        // The core property C2's fix relies on: the node id recovered from
        // a cert is derived from the *actual signing key*, not a
        // separately-suppliable label.
        let secret_key = random_secret_key();
        let (cert_der, _key_der) = generate_self_signed_cert(&secret_key).unwrap();
        assert_eq!(cert_node_id(&cert_der), Some(node_id_for(&secret_key)));
    }

    #[test]
    fn cert_node_id_cannot_be_spoofed_by_a_different_key() {
        // An attacker holding a different keypair cannot make their own
        // cert extract to a victim's node id just by wanting it to — the
        // id is a one-way function of the real SPKI. This is exactly the
        // attack the old `ember-{hex}` SAN-string check was vulnerable
        // to: `generate_self_signed_cert` used to accept the label as a
        // free-standing parameter completely independent of which key it
        // signed with.
        let attacker_key = random_secret_key();
        let victim_key = random_secret_key();
        let (attacker_cert, _) = generate_self_signed_cert(&attacker_key).unwrap();
        assert_ne!(cert_node_id(&attacker_cert), Some(node_id_for(&victim_key)));
    }

    #[tokio::test]
    async fn connect_pinned_matches_and_rejects_node_id() {
        let server_key = random_secret_key();
        let client_key = random_secret_key();
        let server_node_id = node_id_for(&server_key);
        let (s_cert, s_key) = generate_self_signed_cert(&server_key).unwrap();
        let (c_cert, c_key) = generate_self_signed_cert(&client_key).unwrap();

        let server = build_server_client_endpoint(&s_cert, &s_key, 0).unwrap();
        let client = build_server_client_endpoint(&c_cert, &c_key, 0).unwrap();
        // The endpoint binds to 0.0.0.0:<port>; quinn refuses to *connect* to an
        // unspecified address, so dial the loopback with the OS-assigned port.
        let server_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            server.local_addr().unwrap().port(),
        );

        // Accept loop stays alive for both the matching and mismatched
        // connect attempts; aborted at the end of the test.
        let server_handle = tokio::spawn(async move {
            while let Some(incoming) = server.accept().await {
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                            if let Ok(data) = recv.read_to_end(64).await {
                                let _ = send.write_all(&data).await;
                                let _ = send.finish();
                            }
                        }
                        // Hold the connection open until the client closes it.
                        // Dropping `conn` here would emit CONNECTION_CLOSE that can
                        // race ahead of the echoed STREAM frame and surface as a
                        // spurious ConnectionLost on the client's read_to_end.
                        conn.closed().await;
                    }
                });
            }
        });

        // Correct pin → the verifier accepts the server cert (its real
        // SPKI hashes to `server_node_id`) and the round-trip succeeds.
        let conn = connect_pinned(
            &client,
            server_addr,
            "ember",
            Some((&c_cert, &c_key, server_node_id)),
        )
        .await
        .expect("pinned connect with correct node id should succeed");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(64).await.unwrap();
        assert_eq!(&echoed, b"ping");
        drop(conn);

        // Wrong pin → the verifier rejects the server cert (node-id mismatch)
        // and the handshake fails.
        let bad = connect_pinned(
            &client,
            server_addr,
            "ember",
            Some((&c_cert, &c_key, [0xFF; 16])),
        )
        .await;
        assert!(bad.is_err(), "pinned connect with wrong node id must fail");

        server_handle.abort();
    }
}
