use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::messages::*;
use super::upload::{EmberSessionMap, UploadEvent, UploadEventKind};
use crate::network::ember::crypto;

/// Lightweight TCP connection that performs Hello/EmuleInfo handshake and sends
/// an OP_EMBER_FRIEND_REQ, then disconnects. Returns the remote peer's
/// ember_hash if they respond with their own friend request (mutual confirm).
pub async fn connect_and_send_friend_request(
    addr: SocketAddr,
    our_user_hash: &[u8; 16],
    our_ember_hash: &[u8; 16],
    our_nickname: &str,
    our_client_id: u32,
    tcp_port: u16,
    udp_port: u16,
    obfuscate: bool,
    ed25519_pubkey: Option<[u8; 32]>,
    ed25519_secret_key: Option<[u8; 32]>,
) -> anyhow::Result<Option<[u8; 16]>> {
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TCP connect timeout"))??;
    let _ = stream.set_nodelay(true);

    let (raw_r, raw_w) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(raw_r);
    let mut writer = tokio::io::BufWriter::new(raw_w);

    let hello_options = HelloOptions {
        udp_port,
        kad_port: udp_port,
        supports_crypt_layer: obfuscate,
        requests_crypt_layer: obfuscate,
        requires_crypt_layer: false,
        supports_direct_udp_callback: false,
        supports_captcha: false,
        server_ip: 0,
        server_port: 0,
        kad_version: 0x09,
    };
    let hello_payload = build_hello_with_buddy_opts(
        our_user_hash,
        our_client_id,
        tcp_port,
        our_nickname,
        None,
        &hello_options,
    );
    write_packet(&mut writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload).await?;

    let (proto, opcode, data) = read_packet_with_timeout(&mut reader, 15)
        .await
        .context("waiting for HelloAnswer")?;
    if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
        anyhow::bail!("expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}");
    }
    let (_peer_user_hash, mut hello_caps) = parse_hello_answer(&data)
        .map_err(|e| {
            tracing::warn!("Failed to parse HelloAnswer from {addr}: {e}");
            e
        })?;

    let pk_ref = ed25519_pubkey.as_ref();
    let emule_payload = build_emule_info(udp_port, false, Some(our_ember_hash), pk_ref);
    write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

    let (proto, opcode, payload) = read_packet_with_timeout(&mut reader, 15)
        .await
        .context("waiting for EmuleInfo")?;

    if proto == OP_EMULEPROT && (opcode == OP_EMULEINFOANSWER || opcode == OP_EMULEINFO) {
        merge_caps(&mut hello_caps, parse_emule_info(&payload));
        if opcode == OP_EMULEINFO {
            let answer = build_emule_info(udp_port, false, Some(our_ember_hash), pk_ref);
            write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &answer).await?;
        }
    }

    if !hello_caps.is_ember {
        anyhow::bail!("remote peer is not an Ember client");
    }

    // Ember auth challenge-response if both sides support it
    if let (Some(peer_pk), Some(our_pk), Some(our_sk)) = (hello_caps.ember_pubkey, ed25519_pubkey, ed25519_secret_key) {
        perform_ember_auth(&mut reader, &mut writer, &our_pk, &our_sk, &peer_pk, hello_caps.ember_hash.as_ref(), addr).await?;
    }

    info!("Friend-connect handshake with {} complete, sending friend request", addr);
    write_packet(
        &mut writer,
        OP_EMULEPROT,
        OP_EMBER_FRIEND_REQ,
        our_nickname.as_bytes(),
    )
    .await?;

    // Read packets within a brief window looking for a reciprocal friend
    // request.  The remote may send EPX or other packets before the friend
    // request, so we drain up to a few packets instead of reading just one.
    let mut remote_ember_hash: Option<[u8; 16]> = None;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
    for _ in 0..5 {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, read_packet_inner(&mut reader)).await {
            Ok(Ok((p, o, _pl))) => {
                if p == OP_EMULEPROT && o == OP_EMBER_FRIEND_REQ {
                    if let Some(eh) = hello_caps.ember_hash {
                        info!("Received reciprocal friend request from {} (hash={})", addr, hex::encode(eh));
                        remote_ember_hash = Some(eh);
                    }
                    break;
                }
                debug!("Friend-connect to {}: skipping packet proto=0x{p:02X} op=0x{o:02X} while waiting for reciprocal", addr);
            }
            _ => break,
        }
    }

    Ok(remote_ember_hash)
}

/// Result from a successfully established friend session: the outbound sender
/// so the caller can immediately send packets before the loop consumes them.
pub struct FriendSessionHandle {
    pub outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
}

/// Establishes a persistent outbound friend session. Performs the full
/// Hello/EmuleInfo handshake, sends a friend request, then runs a
/// bidirectional select loop: reading incoming packets from the TCP stream
/// and writing outbound packets from the mpsc channel.
///
/// Incoming chat messages and browse responses are forwarded via the
/// `ul_event_tx` channel so the network loop can process them identically
/// to inbound (upload-side) friend packets.
///
/// The session automatically unregisters from `ember_sessions` on exit and
/// emits an `EmberFriendDisconnected` event.
pub async fn open_and_run_friend_session(
    addr: SocketAddr,
    our_user_hash: [u8; 16],
    our_ember_hash: [u8; 16],
    our_nickname: String,
    our_client_id: u32,
    tcp_port: u16,
    udp_port: u16,
    obfuscate: bool,
    ember_sessions: EmberSessionMap,
    ul_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    ed25519_pubkey: Option<[u8; 32]>,
    ed25519_secret_key: Option<[u8; 32]>,
) -> anyhow::Result<FriendSessionHandle> {
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TCP connect timeout"))??;
    let _ = stream.set_nodelay(true);

    let (raw_r, raw_w) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(raw_r);
    let mut writer = tokio::io::BufWriter::new(raw_w);

    let hello_options = HelloOptions {
        udp_port,
        kad_port: udp_port,
        supports_crypt_layer: obfuscate,
        requests_crypt_layer: obfuscate,
        requires_crypt_layer: false,
        supports_direct_udp_callback: false,
        supports_captcha: false,
        server_ip: 0,
        server_port: 0,
        kad_version: 0x09,
    };
    let hello_payload = build_hello_with_buddy_opts(
        &our_user_hash,
        our_client_id,
        tcp_port,
        &our_nickname,
        None,
        &hello_options,
    );
    write_packet(&mut writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload).await?;

    let (proto, opcode, data) = read_packet_with_timeout(&mut reader, 15)
        .await
        .context("waiting for HelloAnswer")?;
    if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
        anyhow::bail!("expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}");
    }
    let (_peer_user_hash, mut hello_caps) = parse_hello_answer(&data)
        .map_err(|e| {
            tracing::warn!("Failed to parse HelloAnswer from {addr}: {e}");
            e
        })?;

    let pk_ref = ed25519_pubkey.as_ref();
    let emule_payload = build_emule_info(udp_port, false, Some(&our_ember_hash), pk_ref);
    write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

    let (proto, opcode, payload) = read_packet_with_timeout(&mut reader, 15)
        .await
        .context("waiting for EmuleInfo")?;
    if proto == OP_EMULEPROT && (opcode == OP_EMULEINFOANSWER || opcode == OP_EMULEINFO) {
        merge_caps(&mut hello_caps, parse_emule_info(&payload));
        if opcode == OP_EMULEINFO {
            let answer = build_emule_info(udp_port, false, Some(&our_ember_hash), pk_ref);
            write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &answer).await?;
        }
    }

    if !hello_caps.is_ember {
        anyhow::bail!("remote peer is not an Ember client");
    }
    let peer_ember_hash = hello_caps.ember_hash
        .ok_or_else(|| anyhow::anyhow!("Ember peer has no ember_hash"))?;

    // Ember auth challenge-response if both sides support it
    if let (Some(peer_pk), Some(our_pk), Some(our_sk)) = (hello_caps.ember_pubkey, ed25519_pubkey, ed25519_secret_key) {
        perform_ember_auth(&mut reader, &mut writer, &our_pk, &our_sk, &peer_pk, Some(&peer_ember_hash), addr).await?;
    }

    let is_friend = friend_hashes.read().await.contains(&peer_ember_hash);
    if !is_friend {
        anyhow::bail!("remote peer {} is not in our friend list", hex::encode(peer_ember_hash));
    }

    write_packet(&mut writer, OP_EMULEPROT, OP_EMBER_FRIEND_REQ, our_nickname.as_bytes()).await?;

    info!("Friend session handshake with {} complete (hash={})", addr, hex::encode(peer_ember_hash));

    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    {
        let mut sessions = ember_sessions.write().await;
        if let Some(existing_tx) = sessions.get(&peer_ember_hash) {
            info!("Friend session for {} already exists, skipping duplicate", hex::encode(peer_ember_hash));
            return Ok(FriendSessionHandle { outbound_tx: existing_tx.clone() });
        }
        sessions.insert(peer_ember_hash, outbound_tx.clone());
    }

    let handle = FriendSessionHandle { outbound_tx };

    let session_ember_sessions = ember_sessions.clone();
    let session_ul_event_tx = ul_event_tx.clone();
    let session_friend_hashes = friend_hashes.clone();
    tokio::spawn(async move {
        const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(90);
        let mut last_activity = tokio::time::Instant::now();

        loop {
            let keepalive = tokio::time::sleep_until(last_activity + KEEPALIVE_INTERVAL);
            tokio::select! {
                result = read_packet_inner(&mut reader) => {
                    match result {
                        Ok((proto, opcode, payload)) => {
                            last_activity = tokio::time::Instant::now();
                            match (proto, opcode) {
                                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) => {
                                    if payload.len() <= 4096 {
                                        if let Ok(msg) = std::str::from_utf8(&payload) {
                                            let _ = session_ul_event_tx.send(UploadEvent {
                                                transfer_id: String::new(),
                                                kind: UploadEventKind::EmberChatMessage {
                                                    ember_hash: peer_ember_hash,
                                                    message: msg.to_string(),
                                                },
                                            }).await;
                                        }
                                    }
                                }
                                (OP_EMULEPROT, OP_EMBER_BROWSE_REQ) => {
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberBrowseRequest {
                                            ember_hash: peer_ember_hash,
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_BROWSE_RES) => {
                                    let entries = parse_browse_response(&payload);
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberBrowseResponse {
                                            ember_hash: peer_ember_hash,
                                            entries,
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) => {
                                    let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                                    info!("Received friend request on outbound session from {} (nick='{}')", addr, nick);
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberFriendRequest {
                                            ember_hash: peer_ember_hash,
                                            nickname: nick,
                                            peer_ip: addr.ip().to_string(),
                                            peer_port: addr.port(),
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_KEEPALIVE) => {}
                                _ => {
                                    debug!("Friend session ignoring proto=0x{proto:02X} op=0x{opcode:02X} from {addr}");
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Friend session read error from {addr}: {e}");
                            break;
                        }
                    }
                }
                Some(outbound_data) = outbound_rx.recv() => {
                    last_activity = tokio::time::Instant::now();
                    if writer.write_all(&outbound_data).await.is_err() {
                        debug!("Friend session write error to {addr}");
                        break;
                    }
                    if writer.flush().await.is_err() {
                        debug!("Friend session flush error to {addr}");
                        break;
                    }
                }
                _ = keepalive => {
                    if !session_friend_hashes.read().await.contains(&peer_ember_hash) {
                        info!("Friend {} removed, terminating outbound session", hex::encode(peer_ember_hash));
                        break;
                    }
                    if write_packet(&mut writer, OP_EMULEPROT, OP_EMBER_KEEPALIVE, &[]).await.is_err() {
                        debug!("Friend session keepalive to {addr} failed");
                        break;
                    }
                    last_activity = tokio::time::Instant::now();
                }
            }
        }

        {
            let mut sessions = session_ember_sessions.write().await;
            sessions.remove(&peer_ember_hash);
        }
        let _ = session_ul_event_tx.send(UploadEvent {
            transfer_id: String::new(),
            kind: UploadEventKind::EmberFriendDisconnected {
                ember_hash: peer_ember_hash,
            },
        }).await;
        info!("Friend session to {} ({}) ended", addr, hex::encode(peer_ember_hash));
    });

    Ok(handle)
}

use super::multi_source::parse_browse_response;

async fn write_packet<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_u8(protocol).await?;
    let pkt_len = (1 + payload.len()) as u32;
    writer.write_u32_le(pkt_len).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_packet_inner<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    let len = reader.read_u32_le().await?;
    if len == 0 || len > 5_000_000 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = (len - 1) as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok((protocol, opcode, payload))
}

async fn read_packet_with_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    timeout_secs: u64,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        read_packet_inner(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

/// Perform the Ember Ed25519 challenge-response authentication exchange.
///
/// Both sides send a 32-byte random nonce as `OP_EMBER_AUTH_CHALLENGE`, then
/// sign the received nonce with their Ed25519 key and send the signature as
/// `OP_EMBER_AUTH_RESPONSE` (32-byte pubkey + 64-byte signature).
///
/// Verification checks:
///   1. `BLAKE3(peer_pubkey)[0..16] == peer_ember_hash` (identity binding)
///   2. The signature over our nonce is valid under the peer's public key
async fn perform_ember_auth<R, W>(
    reader: &mut R,
    writer: &mut W,
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
    peer_pubkey: &[u8; 32],
    peer_ember_hash: Option<&[u8; 16]>,
    addr: SocketAddr,
) -> anyhow::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Verify peer pubkey matches their advertised ember_hash
    if let Some(expected_hash) = peer_ember_hash {
        let peer_vk = VerifyingKey::from_bytes(peer_pubkey)
            .map_err(|e| anyhow::anyhow!("invalid peer Ed25519 pubkey: {e}"))?;
        let derived_hash = crypto::node_id_from_public_key(&peer_vk);
        if derived_hash != *expected_hash {
            anyhow::bail!(
                "Ember auth: peer pubkey does not match ember_hash (derived={}, advertised={})",
                hex::encode(derived_hash), hex::encode(expected_hash)
            );
        }
    }

    // Generate and send our challenge nonce
    let mut our_nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut our_nonce);
    write_packet(writer, OP_EMULEPROT, OP_EMBER_AUTH_CHALLENGE, &our_nonce).await?;

    // Read peer's challenge nonce
    let (proto, opcode, peer_nonce_payload) = read_packet_with_timeout(reader, 10).await
        .map_err(|e| anyhow::anyhow!("Ember auth: failed to read challenge from {addr}: {e}"))?;
    if proto != OP_EMULEPROT || opcode != OP_EMBER_AUTH_CHALLENGE || peer_nonce_payload.len() != 32 {
        anyhow::bail!(
            "Ember auth: expected AUTH_CHALLENGE from {addr}, got proto=0x{proto:02X} op=0x{opcode:02X} len={}",
            peer_nonce_payload.len()
        );
    }

    // Sign the peer's nonce with our key and send response (pubkey + signature)
    let signing_key = SigningKey::from_bytes(our_secret_key);
    let signature = signing_key.sign(&peer_nonce_payload);
    let mut response = Vec::with_capacity(96);
    response.extend_from_slice(our_pubkey);
    response.extend_from_slice(&signature.to_bytes());
    write_packet(writer, OP_EMULEPROT, OP_EMBER_AUTH_RESPONSE, &response).await?;

    // Read peer's response (32-byte pubkey + 64-byte signature)
    let (proto, opcode, peer_response) = read_packet_with_timeout(reader, 10).await
        .map_err(|e| anyhow::anyhow!("Ember auth: failed to read response from {addr}: {e}"))?;
    if proto != OP_EMULEPROT || opcode != OP_EMBER_AUTH_RESPONSE || peer_response.len() != 96 {
        anyhow::bail!(
            "Ember auth: expected AUTH_RESPONSE from {addr}, got proto=0x{proto:02X} op=0x{opcode:02X} len={}",
            peer_response.len()
        );
    }

    let resp_pubkey: [u8; 32] = peer_response[..32].try_into().unwrap();
    if resp_pubkey != *peer_pubkey {
        anyhow::bail!("Ember auth: response pubkey doesn't match EmuleInfo pubkey from {addr}");
    }

    let peer_vk = VerifyingKey::from_bytes(peer_pubkey)
        .map_err(|e| anyhow::anyhow!("invalid peer Ed25519 pubkey: {e}"))?;
    let sig_bytes: [u8; 64] = peer_response[32..96].try_into().unwrap();
    let peer_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    peer_vk.verify(&our_nonce, &peer_sig)
        .map_err(|e| anyhow::anyhow!("Ember auth: signature verification failed for {addr}: {e}"))?;

    info!("Ember auth: verified peer {} at {}", hex::encode(&peer_pubkey[..8]), addr);
    Ok(())
}
