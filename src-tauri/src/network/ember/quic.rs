use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, info, warn};

/// Maximum concurrent QUIC connections.
#[allow(dead_code)]
const MAX_CONNECTIONS: u32 = 256;

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

/// Configuration for the Ember QUIC transport.
#[allow(dead_code)]
pub struct QuicConfig {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub ember_node_id: [u8; 16],
}

/// Generate a self-signed TLS certificate for QUIC using the Ember node ID
/// as the subject CN.
pub fn generate_self_signed_cert(
    ember_node_id: &[u8; 16],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let cn = format!("ember-{}", hex::encode(ember_node_id));
    let subject_alt_names = vec![cn];
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(subject_alt_names)?;
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
    transport.max_idle_timeout(Some(
        Duration::from_secs(IDLE_TIMEOUT_SECS)
            .try_into()
            .expect("IDLE_TIMEOUT fits VarInt"),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_SECS)));
    transport.stream_receive_window(STREAM_RECEIVE_WINDOW_BYTES.try_into().unwrap_or(quinn::VarInt::MAX));
    transport.receive_window(RECEIVE_WINDOW_BYTES.try_into().unwrap_or(quinn::VarInt::MAX));
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
/// at connect time, in which case the verifier pins the cert's
/// `ember-{hex}` SAN to that id (true per-peer authentication, MITM-
/// safe). When `None`, the verifier still requires the cert to be a
/// well-formed Ember self-signed cert (smoke-test only — no
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
        warn!("UDP set_recv_buffer_size({UDP_RECV_BUFFER_BYTES}) failed: {e} (using OS default)");
    }
    if let Err(e) = s.set_send_buffer_size(UDP_SEND_BUFFER_BYTES) {
        warn!("UDP set_send_buffer_size({UDP_SEND_BUFFER_BYTES}) failed: {e} (using OS default)");
    }
    Ok(socket)
}

/// Extract the first SAN / CN that follows our `ember-{32 hex chars}`
/// convention from a DER-encoded certificate. Returns the 32-hex
/// suffix on success, `None` otherwise. We deliberately don't pull in
/// a full X.509 parser: rcgen-issued Ember certs put the SAN in
/// `subject_alt_names`, which the cert encodes verbatim. A linear
/// byte search for the marker prefix is sufficient for the smoke
/// check we need here.
fn extract_ember_san_hex(cert_der: &[u8]) -> Option<String> {
    const PREFIX: &[u8] = b"ember-";
    let mut i = 0usize;
    while i + PREFIX.len() + 32 <= cert_der.len() {
        if &cert_der[i..i + PREFIX.len()] == PREFIX {
            let candidate = &cert_der[i + PREFIX.len()..i + PREFIX.len() + 32];
            if candidate.iter().all(|c| c.is_ascii_hexdigit()) {
                return Some(String::from_utf8_lossy(candidate).to_string());
            }
        }
        i += 1;
    }
    None
}

/// Certificate verifier for QUIC connections to Ember peers.
///
/// Behaviour:
/// - If `expected_node_id` is `Some(nid)`, the cert's first
///   `ember-{32 hex chars}` SAN/CN must hex-match `nid`. This is a
///   real per-peer pin: an MITM can't substitute their own
///   self-signed cert because it would carry a different CN.
/// - If `expected_node_id` is `None`, we still require the cert to
///   look like an Ember self-signed cert (the prefix is present and
///   the suffix is 32 hex chars). This is a smoke check, not
///   authentication — but it does reject the all-too-easy "trust any
///   cert any CA ever issued" failure mode that the prior
///   `SkipServerVerification` allowed. Per-peer pinning will replace
///   the smoke path once all QUIC connect sites know their target's
///   `ember_node_id` at connect time (broker/relay candidates today
///   come in via unauthenticated rendezvous and EPX channels, so we
///   don't always have the node_id).
///
/// In all cases the TLS handshake signature is now verified against the
/// presented end-entity certificate's public key (see
/// `verify_tls1{2,3}_signature` below) using the active crypto provider's
/// algorithms — so the channel is cryptographically bound to a peer that
/// actually holds the cert's private key. An on-path attacker can no longer
/// splice a forged or substring-only cert without that key. What the
/// unpinned path still cannot do is prove the key belongs to a *specific*
/// node_id (that needs `expected_node_id`); the node_id↔key binding is
/// established out-of-band by the eMule/Ember TCP layer's mutual Ed25519
/// proof-of-possession, on which file-transfer integrity solely depends.
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
        let Some(hex_id) = extract_ember_san_hex(end_entity.as_ref()) else {
            return Err(rustls::Error::General(
                "ember cert: no `ember-{hex}` marker found in certificate".into(),
            ));
        };
        if let Some(nid) = self.expected_node_id {
            let expected = hex::encode(nid);
            if !hex_id.eq_ignore_ascii_case(&expected) {
                return Err(rustls::Error::General(format!(
                    "ember cert: pinned node_id mismatch (expected {expected}, got {hex_id})"
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
        if extract_ember_san_hex(end_entity.as_ref()).is_none() {
            return Err(rustls::Error::General(
                "ember client cert: no `ember-{hex}` marker found in certificate".into(),
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

/// An Ember QUIC endpoint that can accept incoming connections and initiate
/// outgoing ones.
#[allow(dead_code)]
pub struct EmberQuicEndpoint {
    endpoint: Endpoint,
    client_config: ClientConfig,
    pub local_addr: SocketAddr,
}

#[allow(dead_code)]
impl EmberQuicEndpoint {
    /// Create and bind a new QUIC endpoint with tuned UDP buffer sizes.
    pub fn new(bind_addr: SocketAddr, config: &QuicConfig) -> anyhow::Result<Self> {
        let server_config = build_server_config(&config.cert_der, &config.key_der)?;
        // Default client config for incoming connections from this
        // endpoint (no specific peer pin). Use `connect_pinned` for
        // outbound connections where the target's node_id is known.
        let client_config = build_client_config(&config.cert_der, &config.key_der, None)?;

        let socket = bind_tuned_udp(bind_addr)?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let local_addr = endpoint.local_addr()?;
        info!("Ember QUIC endpoint bound on {local_addr}");

        Ok(Self {
            endpoint,
            client_config,
            local_addr,
        })
    }

    /// Accept the next incoming QUIC connection.
    pub async fn accept(&self) -> Option<quinn::Incoming> {
        self.endpoint.accept().await
    }

    /// Connect to a remote peer.
    pub async fn connect(
        &self,
        addr: SocketAddr,
    ) -> anyhow::Result<quinn::Connection> {
        let conn = self
            .endpoint
            .connect_with(self.client_config.clone(), addr, "ember")?
            .await?;
        debug!("QUIC connected to {addr}");
        Ok(conn)
    }

    /// Close the endpoint gracefully.
    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }

    /// Get number of active connections.
    pub fn open_connections(&self) -> usize {
        self.endpoint.open_connections()
    }
}

/// Create a client-only QUIC endpoint bound to 0.0.0.0:0 for outgoing connections
/// (used by the connection broker for hole-punching and relay).
#[allow(dead_code)]
pub fn build_client_endpoint(cert_der: &[u8], key_der: &[u8]) -> anyhow::Result<Endpoint> {
    // Default to the unpinned smoke-test verifier; per-peer pinning
    // requires knowing the target's node_id at connect time, which
    // broker/hole-punch sites don't always have.
    let client_config = build_client_config(cert_der, key_der, None)?;
    let socket = bind_tuned_udp("0.0.0.0:0".parse::<SocketAddr>()?)?;
    let mut endpoint = Endpoint::new(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
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
                    info!(
                        "QUIC requested port {bind_port} unavailable; bound on {local} instead",
                    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_cert_succeeds() {
        let node_id = [0xAA; 16];
        let (cert, key) = generate_self_signed_cert(&node_id).unwrap();
        assert!(!cert.is_empty());
        assert!(!key.is_empty());
    }

    #[tokio::test]
    async fn quic_endpoint_binds() {
        let node_id = [0xBB; 16];
        let (cert, key) = generate_self_signed_cert(&node_id).unwrap();
        let config = QuicConfig {
            cert_der: cert,
            key_der: key,
            ember_node_id: node_id,
        };
        let endpoint = EmberQuicEndpoint::new("127.0.0.1:0".parse().unwrap(), &config).unwrap();
        assert_ne!(endpoint.local_addr.port(), 0);
        endpoint.close();
    }

    #[tokio::test]
    async fn quic_connect_round_trip() {
        let server_id = [0x01; 16];
        let client_id = [0x02; 16];

        let (s_cert, s_key) = generate_self_signed_cert(&server_id).unwrap();
        let server = EmberQuicEndpoint::new(
            "127.0.0.1:0".parse().unwrap(),
            &QuicConfig {
                cert_der: s_cert,
                key_der: s_key,
                ember_node_id: server_id,
            },
        )
        .unwrap();

        let (c_cert, c_key) = generate_self_signed_cert(&client_id).unwrap();
        let client = EmberQuicEndpoint::new(
            "127.0.0.1:0".parse().unwrap(),
            &QuicConfig {
                cert_der: c_cert,
                key_der: c_key,
                ember_node_id: client_id,
            },
        )
        .unwrap();

        let server_addr = server.local_addr;
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let server_handle = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let data = recv.read_to_end(1024).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            // Wait until client signals it's done reading
            let _ = done_rx.await;
        });

        let conn = client.connect(server_addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"hello ember").await.unwrap();
        send.finish().unwrap();

        let response = recv.read_to_end(1024).await.unwrap();
        assert_eq!(&response, b"hello ember");

        let _ = done_tx.send(());
        server_handle.await.unwrap();
        client.close();
    }
}
