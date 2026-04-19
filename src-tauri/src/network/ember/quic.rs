use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tracing::{debug, info};

/// Maximum concurrent QUIC connections.
#[allow(dead_code)]
const MAX_CONNECTIONS: u32 = 256;

/// Idle timeout for QUIC connections.
const IDLE_TIMEOUT_SECS: u64 = 120;

/// Keep-alive interval.
const KEEP_ALIVE_SECS: u64 = 15;

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

/// Create the server-side QUIC endpoint configuration.
fn build_server_config(cert_der: &[u8], key_der: &[u8]) -> anyhow::Result<ServerConfig> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls_config.alpn_protocols = vec![b"ember/1".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));
    // Build a fresh `TransportConfig`, populate it, then store via
    // `Arc::new` so we don't depend on `server_config.transport`
    // having a unique strong count at this exact point. The previous
    // `Arc::get_mut(...).unwrap()` would panic if a future quinn
    // upgrade ever shared the default transport Arc inside
    // `with_crypto`.
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(64u32.into());
    transport.max_concurrent_uni_streams(64u32.into());
    transport.max_idle_timeout(Some(Duration::from_secs(IDLE_TIMEOUT_SECS).try_into()?));
    transport.keep_alive_interval(Some(Duration::from_secs(KEEP_ALIVE_SECS)));
    server_config.transport = Arc::new(transport);

    Ok(server_config)
}

/// Create the client-side QUIC configuration.
pub fn build_client_config(cert_der: &[u8], key_der: &[u8]) -> anyhow::Result<ClientConfig> {
    let cert = CertificateDer::from(cert_der.to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.to_vec()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_client_auth_cert(vec![cert], key)?;
    tls_config.alpn_protocols = vec![b"ember/1".to_vec()];

    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    )))
}

/// Certificate verifier that accepts any server certificate (P2P trust model).
/// Peer authentication is done at the Ember protocol layer, not TLS PKI.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
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
    /// Create and bind a new QUIC endpoint.
    pub fn new(bind_addr: SocketAddr, config: &QuicConfig) -> anyhow::Result<Self> {
        let server_config = build_server_config(&config.cert_der, &config.key_der)?;
        let client_config = build_client_config(&config.cert_der, &config.key_der)?;

        let endpoint = Endpoint::server(server_config, bind_addr)?;
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
    let client_config = build_client_config(cert_der, key_der)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
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
    let client_config = build_client_config(cert_der, key_der)?;

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
        match Endpoint::server(server_config.clone(), bind_addr) {
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
