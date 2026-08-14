//! Ember-private secure friend stream.
//!
//! The outer carrier may be direct TCP, QUIC, or a WebSocket relay.  This
//! module deliberately knows nothing about that carrier: it performs a Noise
//! IK handshake over any split async byte stream and then exposes another
//! split byte stream carrying the original eD2K framing.  Stock eMule traffic
//! never enters this module.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::network::ember::crypto;

const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_DOMAIN: &[u8] = b"ember-secure-friend-stream-v2\0";

/// Private discriminator on the upload TCP stream.  Its first byte is not an
/// eD2K/eMule protocol marker.  The upload listener consumes it only when the
/// entire magic matches; all other first bytes continue through the existing
/// eMule parser/obfuscation negotiation.
// The first byte is NOT a value eMule cannot send: its
// `GetSemiRandomNotProtocolMarker()` (EncryptedStreamSocket.cpp) rejects only
// `OP_EDONKEYPROT`, `OP_PACKEDPROT` and `OP_EMULEPROT`, so a stock client opens
// roughly 1 in 253 obfuscated connections with `0x00`. Committing on this byte
// alone therefore misrouted those into the preamble reader and dropped them.
// `buffered_magic_matches` is what disambiguates; see its comment.
pub const PREAMBLE_MAGIC: [u8; 8] = [0, b'E', b'M', b'B', b'F', b'S', b'2', 0];
const ACK_MAGIC: [u8; 8] = [0, b'E', b'M', b'B', b'A', b'C', b'2', 0];
const PREAMBLE_LEN: usize = PREAMBLE_MAGIC.len() + 16 + 16 + 32;
const ACK_LEN: usize = ACK_MAGIC.len() + 1 + 32;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const RECORD_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_HANDSHAKE_MESSAGE: usize = 1024;
const MAX_NOISE_MESSAGE: usize = 65_535;
const NOISE_TAG_LEN: usize = 16;
const MAX_RECORD_PLAINTEXT: usize = MAX_NOISE_MESSAGE - NOISE_TAG_LEN;
const DUPLEX_CAPACITY: usize = 128 * 1024;

/// Stable bare error code understood by the UI in all supported locales.
pub const UPGRADE_REQUIRED_ERROR: &str = "SecureFriendV2Required";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurePeerIdentity {
    pub ember_hash: [u8; 16],
    pub ed25519_public_key: [u8; 32],
}

pub struct SecureStreamParts {
    pub reader: Box<dyn AsyncRead + Unpin + Send>,
    pub writer: Box<dyn AsyncWrite + Unpin + Send>,
    pub peer: SecurePeerIdentity,
}

pub fn is_preamble_first_byte(byte: u8) -> bool {
    byte == PREAMBLE_MAGIC[0]
}

/// Whether the bytes already buffered behind the discriminator are consistent
/// with the rest of [`PREAMBLE_MAGIC`].
///
/// The first byte cannot decide this on its own, because eMule's obfuscation
/// discriminator is allowed to be `0x00`. This peeks the buffer without
/// consuming, so a mismatch leaves the stream exactly as the eMule negotiator
/// expects to find it — no pushback and no change to the inbound path's types.
///
/// Both senders write their opening bytes in one go, so in practice the whole
/// prefix is already buffered and the answer is exact. When fewer bytes are
/// available (fragmented delivery) it accepts a prefix match rather than
/// rejecting, so a genuine Ember peer is never turned away; the residual
/// ambiguity is then one eMule connection whose random key part also begins
/// `EMBFS2`, which is not a case worth engineering for.
pub async fn buffered_magic_matches<R>(reader: &mut R) -> bool
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let expected = &PREAMBLE_MAGIC[1..];
    match reader.fill_buf().await {
        Ok(buffered) => {
            let comparable = buffered.len().min(expected.len());
            buffered[..comparable] == expected[..comparable]
        }
        // Let the secure path run and surface the I/O error itself rather than
        // silently handing a broken stream to the eMule negotiator.
        Err(_) => true,
    }
}

fn prologue(initiator: &[u8; 16], responder: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PROLOGUE_DOMAIN.len() + 32);
    out.extend_from_slice(PROLOGUE_DOMAIN);
    out.extend_from_slice(initiator);
    out.extend_from_slice(responder);
    out
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Explicit v2 protocol rejection (wrong magic / status).  UI maps this to the
/// "friend must upgrade Ember" copy — do **not** use for generic I/O or
/// timeouts, which would mislabel RST/timeout as an upgrade problem.
fn upgrade_required(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("{UPGRADE_REQUIRED_ERROR}: {message}")
}

/// Connectivity / crypto failure that is *not* an explicit "peer lacks v2"
/// rejection.  Callers must not treat these as [`UPGRADE_REQUIRED_ERROR`].
fn connect_failed(message: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("secure-stream connect failed: {message}")
}

async fn write_handshake_message<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    message: &[u8],
) -> io::Result<()> {
    if message.is_empty() || message.len() > MAX_HANDSHAKE_MESSAGE {
        return Err(invalid_data(
            "invalid secure-stream handshake message length",
        ));
    }
    writer.write_u16(message.len() as u16).await?;
    writer.write_all(message).await?;
    writer.flush().await
}

async fn read_handshake_message<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> io::Result<Vec<u8>> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let len = reader.read_u16().await? as usize;
        if len == 0 || len > MAX_HANDSHAKE_MESSAGE {
            return Err(invalid_data(
                "invalid secure-stream handshake message length",
            ));
        }
        let mut message = vec![0u8; len];
        reader.read_exact(&mut message).await?;
        Ok(message)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "secure-stream handshake timed out"))?
}

/// Initiate secure friend-stream v2.  The responder's Ed25519 public key is
/// returned in the private preamble acknowledgement, checked against the
/// expected Ember identity, converted to X25519, and then authenticated by
/// Noise IK.  This lets existing hash-only friend rows upgrade without a
/// trust-on-first-use key substitution: a replacement key would need the same
/// 128-bit BLAKE3 identity and its corresponding converted private scalar.
pub async fn initiate(
    mut raw_reader: Box<dyn AsyncRead + Unpin + Send>,
    mut raw_writer: Box<dyn AsyncWrite + Unpin + Send>,
    our_ember_hash: [u8; 16],
    expected_peer_hash: [u8; 16],
    our_ed25519_public_key: [u8; 32],
    our_ed25519_secret_key: [u8; 32],
) -> anyhow::Result<SecureStreamParts> {
    if !crypto::verify_ember_hash_binding(&our_ed25519_public_key, &our_ember_hash) {
        anyhow::bail!("local Ed25519 key does not match local Ember identity");
    }

    let mut preamble = Vec::with_capacity(PREAMBLE_LEN);
    preamble.extend_from_slice(&PREAMBLE_MAGIC);
    preamble.extend_from_slice(&our_ember_hash);
    preamble.extend_from_slice(&expected_peer_hash);
    preamble.extend_from_slice(&our_ed25519_public_key);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        raw_writer.write_all(&preamble).await?;
        raw_writer.flush().await
    })
    .await
    .map_err(|_| connect_failed("timed out writing the v2 preamble"))?
    .map_err(|e| connect_failed(format!("v2 preamble write failed: {e}")))?;

    let mut ack = [0u8; ACK_LEN];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, raw_reader.read_exact(&mut ack))
        .await
        .map_err(|_| connect_failed("timed out waiting for the v2 acknowledgement"))?
        .map_err(|e| connect_failed(format!("peer closed before the v2 acknowledgement: {e}")))?;
    // Only an explicit non-v2 / rejection ACK is upgrade-required.  A truncated
    // or garbage reply that still matches length is treated as protocol reject
    // when the magic/status do not match; I/O failures above stay generic.
    if ack[..ACK_MAGIC.len()] != ACK_MAGIC || ack[ACK_MAGIC.len()] != 0 {
        return Err(upgrade_required(
            "peer rejected or does not support secure friend-stream v2",
        ));
    }
    let peer_ed25519_public_key: [u8; 32] = ack[ACK_MAGIC.len() + 1..]
        .try_into()
        .map_err(|_| connect_failed("malformed v2 acknowledgement"))?;
    if !crypto::verify_ember_hash_binding(&peer_ed25519_public_key, &expected_peer_hash) {
        return Err(connect_failed(
            "responder public key does not match the expected friend identity",
        ));
    }

    let local_private = crypto::ed25519_seed_to_x25519_private(&our_ed25519_secret_key);
    let remote_public = crypto::ed25519_public_to_x25519(&peer_ed25519_public_key)
        .ok_or_else(|| connect_failed("responder has an invalid identity key"))?;
    let params: snow::params::NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid secure-stream Noise pattern: {e}"))?;
    let binding = prologue(&our_ember_hash, &expected_peer_hash);
    let mut handshake = snow::Builder::new(params)
        .local_private_key(&local_private)
        .remote_public_key(&remote_public)
        .prologue(&binding)
        .build_initiator()
        .map_err(|e| connect_failed(format!("could not initialize Noise IK: {e}")))?;

    let mut message_1 = [0u8; MAX_HANDSHAKE_MESSAGE];
    let message_1_len = handshake
        .write_message(&[], &mut message_1)
        .map_err(|e| connect_failed(format!("could not create Noise IK message 1: {e}")))?;
    write_handshake_message(&mut *raw_writer, &message_1[..message_1_len])
        .await
        .map_err(|e| connect_failed(format!("Noise IK message 1 failed: {e}")))?;

    let message_2 = read_handshake_message(&mut *raw_reader)
        .await
        .map_err(|e| connect_failed(format!("Noise IK message 2 failed: {e}")))?;
    let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
    handshake
        .read_message(&message_2, &mut payload)
        .map_err(|e| connect_failed(format!("Noise IK authentication failed: {e}")))?;

    let learned_remote = handshake
        .get_remote_static()
        .ok_or_else(|| connect_failed("Noise IK did not authenticate a responder static key"))?;
    if learned_remote != remote_public {
        return Err(connect_failed("Noise IK responder identity mismatch"));
    }
    let transport = handshake
        .into_transport_mode()
        .map_err(|e| connect_failed(format!("could not enter Noise transport mode: {e}")))?;

    Ok(spawn_record_layer(
        raw_reader,
        raw_writer,
        transport,
        SecurePeerIdentity {
            ember_hash: expected_peer_hash,
            ed25519_public_key: peer_ed25519_public_key,
        },
    ))
}

/// Accept a secure stream after the upload listener consumed its first byte.
/// The preamble's claimed Ed25519 key is checked against its Ember hash before
/// Noise, and the X25519 static learned from IK is checked against the standard
/// Ed25519 conversion after Noise.  Friend-list membership is intentionally a
/// higher-layer live check: an authenticated stranger may submit a secure
/// friend request, but cannot chat, browse, control uploads, or claim priority.
pub async fn accept_after_first(
    mut raw_reader: Box<dyn AsyncRead + Unpin + Send>,
    mut raw_writer: Box<dyn AsyncWrite + Unpin + Send>,
    first_byte: u8,
    our_ember_hash: [u8; 16],
    our_ed25519_public_key: [u8; 32],
    our_ed25519_secret_key: [u8; 32],
) -> anyhow::Result<SecureStreamParts> {
    let mut preamble = [0u8; PREAMBLE_LEN];
    preamble[0] = first_byte;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, raw_reader.read_exact(&mut preamble[1..]))
        .await
        .map_err(|_| anyhow::anyhow!("secure-stream preamble timed out"))??;
    if preamble[..PREAMBLE_MAGIC.len()] != PREAMBLE_MAGIC {
        anyhow::bail!("invalid secure-stream preamble");
    }

    let initiator_hash: [u8; 16] = preamble[PREAMBLE_MAGIC.len()..PREAMBLE_MAGIC.len() + 16]
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed initiator identity"))?;
    let responder_hash: [u8; 16] = preamble[PREAMBLE_MAGIC.len() + 16..PREAMBLE_MAGIC.len() + 32]
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed responder identity"))?;
    let initiator_ed25519_public_key: [u8; 32] =
        preamble[PREAMBLE_MAGIC.len() + 32..]
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed initiator public key"))?;

    if responder_hash != our_ember_hash {
        anyhow::bail!("secure-stream preamble targets a different Ember identity");
    }
    if !crypto::verify_ember_hash_binding(&initiator_ed25519_public_key, &initiator_hash) {
        anyhow::bail!("secure-stream initiator key does not match its Ember identity");
    }
    if !crypto::verify_ember_hash_binding(&our_ed25519_public_key, &our_ember_hash) {
        anyhow::bail!("local Ed25519 key does not match local Ember identity");
    }

    let mut ack = [0u8; ACK_LEN];
    ack[..ACK_MAGIC.len()].copy_from_slice(&ACK_MAGIC);
    ack[ACK_MAGIC.len()] = 0;
    ack[ACK_MAGIC.len() + 1..].copy_from_slice(&our_ed25519_public_key);
    raw_writer.write_all(&ack).await?;
    raw_writer.flush().await?;

    let local_private = crypto::ed25519_seed_to_x25519_private(&our_ed25519_secret_key);
    let expected_remote = crypto::ed25519_public_to_x25519(&initiator_ed25519_public_key)
        .ok_or_else(|| anyhow::anyhow!("initiator has an invalid identity key"))?;
    let params: snow::params::NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid secure-stream Noise pattern: {e}"))?;
    let binding = prologue(&initiator_hash, &our_ember_hash);
    let mut handshake = snow::Builder::new(params)
        .local_private_key(&local_private)
        .prologue(&binding)
        .build_responder()
        .map_err(|e| anyhow::anyhow!("could not initialize Noise IK responder: {e}"))?;

    let message_1 = read_handshake_message(&mut *raw_reader).await?;
    let mut payload = [0u8; MAX_HANDSHAKE_MESSAGE];
    handshake
        .read_message(&message_1, &mut payload)
        .map_err(|e| anyhow::anyhow!("Noise IK initiator authentication failed: {e}"))?;
    let learned_remote = handshake
        .get_remote_static()
        .ok_or_else(|| anyhow::anyhow!("Noise IK did not authenticate an initiator static key"))?;
    if learned_remote != expected_remote {
        anyhow::bail!("Noise IK initiator identity mismatch");
    }

    let mut message_2 = [0u8; MAX_HANDSHAKE_MESSAGE];
    let message_2_len = handshake
        .write_message(&[], &mut message_2)
        .map_err(|e| anyhow::anyhow!("could not create Noise IK message 2: {e}"))?;
    write_handshake_message(&mut *raw_writer, &message_2[..message_2_len]).await?;
    let transport = handshake
        .into_transport_mode()
        .map_err(|e| anyhow::anyhow!("could not enter Noise transport mode: {e}"))?;

    Ok(spawn_record_layer(
        raw_reader,
        raw_writer,
        transport,
        SecurePeerIdentity {
            ember_hash: initiator_hash,
            ed25519_public_key: initiator_ed25519_public_key,
        },
    ))
}

fn spawn_record_layer(
    mut raw_reader: Box<dyn AsyncRead + Unpin + Send>,
    mut raw_writer: Box<dyn AsyncWrite + Unpin + Send>,
    transport: snow::TransportState,
    peer: SecurePeerIdentity,
) -> SecureStreamParts {
    let transport = Arc::new(Mutex::new(transport));

    // Writes to `app_writer` are read by `plain_reader`, encrypted in bounded
    // chunks, and emitted as u16-length-prefixed Noise records.
    let (app_writer, mut plain_reader) = tokio::io::duplex(DUPLEX_CAPACITY);
    let write_transport = transport.clone();
    tokio::spawn(async move {
        let mut plaintext = vec![0u8; MAX_RECORD_PLAINTEXT];
        loop {
            let read = match plain_reader.read(&mut plaintext).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let mut ciphertext = vec![0u8; read + NOISE_TAG_LEN];
            let encrypted = {
                let mut state = write_transport.lock().await;
                match state.write_message(&plaintext[..read], &mut ciphertext) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!("secure-stream record encryption failed: {e}");
                        break;
                    }
                }
            };
            ciphertext.truncate(encrypted);
            let result = tokio::time::timeout(RECORD_TIMEOUT, async {
                raw_writer.write_u16(encrypted as u16).await?;
                raw_writer.write_all(&ciphertext).await?;
                raw_writer.flush().await
            })
            .await;
            if !matches!(result, Ok(Ok(()))) {
                break;
            }
        }
        let _ = raw_writer.shutdown().await;
    });

    // Decrypted bytes are written to `plain_writer` and read by `app_reader`.
    // The bounded duplex applies backpressure, so a peer cannot force
    // unbounded reassembly allocation.  Existing eD2K parsers retain their own
    // 512 KiB / 5 MiB whole-frame caps above this transparent byte stream.
    let (mut plain_writer, app_reader) = tokio::io::duplex(DUPLEX_CAPACITY);
    let read_transport = transport;
    tokio::spawn(async move {
        loop {
            let len = match tokio::time::timeout(RECORD_TIMEOUT, raw_reader.read_u16()).await {
                Ok(Ok(n)) => n as usize,
                _ => break,
            };
            if len <= NOISE_TAG_LEN || len > MAX_NOISE_MESSAGE {
                break;
            }
            let mut ciphertext = vec![0u8; len];
            if !matches!(
                tokio::time::timeout(RECORD_TIMEOUT, raw_reader.read_exact(&mut ciphertext)).await,
                Ok(Ok(_))
            ) {
                break;
            }
            let mut plaintext = vec![0u8; len - NOISE_TAG_LEN];
            let decrypted = {
                let mut state = read_transport.lock().await;
                match state.read_message(&ciphertext, &mut plaintext) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!(
                            "secure-stream record authentication/replay check failed: {e}"
                        );
                        break;
                    }
                }
            };
            if plain_writer
                .write_all(&plaintext[..decrypted])
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = plain_writer.shutdown().await;
    });

    SecureStreamParts {
        reader: Box::new(app_reader),
        writer: Box::new(app_writer),
        peer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn identity() -> (SigningKey, [u8; 16]) {
        let key = SigningKey::generate(&mut OsRng);
        let hash = crypto::node_id_from_public_key(&key.verifying_key());
        (key, hash)
    }

    async fn pair() -> (SecureStreamParts, SecureStreamParts) {
        let (alice_key, alice_hash) = identity();
        let (bob_key, bob_hash) = identity();
        let (alice_wire, bob_wire) = tokio::io::duplex(1024 * 1024);
        let (alice_r, alice_w) = tokio::io::split(alice_wire);
        let (mut bob_r, bob_w) = tokio::io::split(bob_wire);

        let responder = tokio::spawn(async move {
            let first = bob_r.read_u8().await.unwrap();
            accept_after_first(
                Box::new(bob_r),
                Box::new(bob_w),
                first,
                bob_hash,
                bob_key.verifying_key().to_bytes(),
                bob_key.to_bytes(),
            )
            .await
        });
        let initiator = initiate(
            Box::new(alice_r),
            Box::new(alice_w),
            alice_hash,
            bob_hash,
            alice_key.verifying_key().to_bytes(),
            alice_key.to_bytes(),
        )
        .await
        .unwrap();
        let responder = responder.await.unwrap().unwrap();
        (initiator, responder)
    }

    #[tokio::test]
    async fn mutual_identity_and_large_inner_frame_round_trip() {
        let (mut alice, mut bob) = pair().await;
        let data = vec![0xA5; 700 * 1024];
        let expected = data.clone();
        let write = tokio::spawn(async move {
            alice.writer.write_all(&data).await.unwrap();
            alice.writer.flush().await.unwrap();
        });
        let mut received = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(5), bob.reader.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        write.await.unwrap();
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn responder_identity_mismatch_fails_before_inner_stream() {
        let (alice_key, alice_hash) = identity();
        let (bob_key, bob_hash) = identity();
        let (_, wrong_hash) = identity();
        let (alice_wire, bob_wire) = tokio::io::duplex(8192);
        let (alice_r, alice_w) = tokio::io::split(alice_wire);
        let (mut bob_r, bob_w) = tokio::io::split(bob_wire);
        let responder = tokio::spawn(async move {
            let first = bob_r.read_u8().await.unwrap();
            accept_after_first(
                Box::new(bob_r),
                Box::new(bob_w),
                first,
                bob_hash,
                bob_key.verifying_key().to_bytes(),
                bob_key.to_bytes(),
            )
            .await
        });
        let result = initiate(
            Box::new(alice_r),
            Box::new(alice_w),
            alice_hash,
            wrong_hash,
            alice_key.verifying_key().to_bytes(),
            alice_key.to_bytes(),
        )
        .await;
        assert!(result.is_err());
        assert!(responder.await.unwrap().is_err());
    }

    #[test]
    fn reflected_and_replayed_noise_records_fail() {
        let (alice_key, alice_hash) = identity();
        let (bob_key, bob_hash) = identity();
        let alice_private = crypto::ed25519_seed_to_x25519_private(&alice_key.to_bytes());
        let bob_private = crypto::ed25519_seed_to_x25519_private(&bob_key.to_bytes());
        let bob_public =
            crypto::ed25519_public_to_x25519(&bob_key.verifying_key().to_bytes()).unwrap();
        let params: snow::params::NoiseParams = NOISE_PATTERN.parse().unwrap();
        let binding = prologue(&alice_hash, &bob_hash);
        let mut alice_hs = snow::Builder::new(params.clone())
            .local_private_key(&alice_private)
            .remote_public_key(&bob_public)
            .prologue(&binding)
            .build_initiator()
            .unwrap();
        let mut bob_hs = snow::Builder::new(params)
            .local_private_key(&bob_private)
            .prologue(&binding)
            .build_responder()
            .unwrap();
        let mut msg1 = [0u8; MAX_HANDSHAKE_MESSAGE];
        let n1 = alice_hs.write_message(&[], &mut msg1).unwrap();
        bob_hs.read_message(&msg1[..n1], &mut []).unwrap();
        let mut msg2 = [0u8; MAX_HANDSHAKE_MESSAGE];
        let n2 = bob_hs.write_message(&[], &mut msg2).unwrap();
        alice_hs.read_message(&msg2[..n2], &mut []).unwrap();
        let mut alice = alice_hs.into_transport_mode().unwrap();
        let mut bob = bob_hs.into_transport_mode().unwrap();

        let canary = b"INNER-ED2K-CANARY-OP_EMBER_CHAT_MSG";
        let mut ciphertext = vec![0u8; canary.len() + NOISE_TAG_LEN];
        let n = alice.write_message(canary, &mut ciphertext).unwrap();
        ciphertext.truncate(n);
        assert!(
            !ciphertext
                .windows(canary.len())
                .any(|window| window == canary),
            "a relay must not see inner eD2K canary bytes"
        );
        let mut plaintext = vec![0u8; canary.len()];
        assert_eq!(
            bob.read_message(&ciphertext, &mut plaintext).unwrap(),
            canary.len()
        );
        assert_eq!(plaintext, canary);
        assert!(
            bob.read_message(&ciphertext, &mut plaintext).is_err(),
            "ordered Noise nonce state must reject replay"
        );

        let mut reflected = vec![0u8; canary.len()];
        assert!(
            alice.read_message(&ciphertext, &mut reflected).is_err(),
            "directional Noise keys must reject reflection"
        );
    }

    #[test]
    fn private_preamble_cannot_collide_with_standard_emule_markers() {
        for marker in [0xE3u8, 0xC5, 0xD4] {
            assert!(!is_preamble_first_byte(marker));
        }
    }

    /// eMule's `GetSemiRandomNotProtocolMarker()` excludes only the three
    /// protocol opcodes, so `0x00` is a legal first byte for an ordinary
    /// obfuscated dial and the discriminator alone cannot decide. The buffered
    /// magic is what separates the two, and a mismatch must be reported without
    /// consuming anything so the eMule negotiator still sees an intact stream.
    #[tokio::test]
    async fn buffered_magic_rejects_an_emule_obfuscation_handshake() {
        // A plausible obfuscated request that happens to open with 0x00: random
        // key part, sync magic, method bytes, padding length.
        let emule_like = [0x00u8, 0x91, 0x2B, 0x77, 0x0C, 0x1D, 0xEF, 0x43, 0x00];
        let mut reader = tokio::io::BufReader::new(&emule_like[1..]);
        assert!(
            !buffered_magic_matches(&mut reader).await,
            "an eMule obfuscation handshake must not be taken for a friend preamble"
        );

        // Nothing was consumed, so the negotiator still gets every byte.
        use tokio::io::AsyncReadExt;
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).await.unwrap();
        assert_eq!(
            rest,
            &emule_like[1..],
            "the peek must leave the stream untouched"
        );
    }

    #[tokio::test]
    async fn buffered_magic_accepts_a_real_preamble() {
        let mut tail = PREAMBLE_MAGIC[1..].to_vec();
        tail.extend_from_slice(&[0xAA; 32]);
        let mut reader = tokio::io::BufReader::new(tail.as_slice());
        assert!(buffered_magic_matches(&mut reader).await);
    }

    /// Fragmented delivery must not turn a genuine Ember peer away: a prefix
    /// that matches as far as it goes is accepted.
    #[tokio::test]
    async fn buffered_magic_accepts_a_short_matching_prefix() {
        let partial = &PREAMBLE_MAGIC[1..3];
        let mut reader = tokio::io::BufReader::new(partial);
        assert!(buffered_magic_matches(&mut reader).await);
    }

    #[test]
    fn upgrade_required_error_string_is_stable_for_ui() {
        let err = upgrade_required("peer rejected or does not support secure friend-stream v2");
        let text = format!("{err}");
        assert!(text.starts_with(UPGRADE_REQUIRED_ERROR));
        assert!(!format!("{}", connect_failed("timed out")).contains(UPGRADE_REQUIRED_ERROR));
    }

    #[tokio::test]
    async fn non_v2_ack_maps_to_upgrade_required_not_generic_timeout() {
        let (alice_key, alice_hash) = identity();
        let (_, bob_hash) = identity();
        let (alice_wire, bob_wire) = tokio::io::duplex(8192);
        let (alice_r, alice_w) = tokio::io::split(alice_wire);
        let (mut bob_r, mut bob_w) = tokio::io::split(bob_wire);

        let responder = tokio::spawn(async move {
            let mut preamble = [0u8; PREAMBLE_LEN];
            bob_r.read_exact(&mut preamble).await.unwrap();
            // Explicit non-v2 acknowledgement (wrong magic).
            bob_w.write_all(&[0xE3; ACK_LEN]).await.unwrap();
            bob_w.flush().await.unwrap();
        });

        let err = initiate(
            Box::new(alice_r),
            Box::new(alice_w),
            alice_hash,
            bob_hash,
            alice_key.verifying_key().to_bytes(),
            alice_key.to_bytes(),
        )
        .await
        .err()
        .expect("non-v2 ACK must fail");
        let text = format!("{err}");
        assert!(
            text.contains(UPGRADE_REQUIRED_ERROR),
            "explicit protocol reject must be upgrade-required, got {text}"
        );
        let _ = responder.await;
    }

    #[tokio::test]
    async fn preamble_timeout_is_not_upgrade_required() {
        let (alice_key, alice_hash) = identity();
        let (_, bob_hash) = identity();
        let (alice_wire, _bob_wire) = tokio::io::duplex(8192);
        let (alice_r, alice_w) = tokio::io::split(alice_wire);
        // Drop the peer side so the ACK read fails as a closed connection /
        // timeout-class connect failure rather than an upgrade reject.
        drop(_bob_wire);

        let err = initiate(
            Box::new(alice_r),
            Box::new(alice_w),
            alice_hash,
            bob_hash,
            alice_key.verifying_key().to_bytes(),
            alice_key.to_bytes(),
        )
        .await
        .err()
        .expect("closed peer must fail");
        let text = format!("{err}");
        assert!(
            !text.contains(UPGRADE_REQUIRED_ERROR),
            "I/O failure must not be labeled upgrade-required, got {text}"
        );
    }
}
